#!/usr/bin/env python

"""Create a package database for newest packages from conda-forge channel"""

import argparse
import asyncio
import bz2
import json
import os
import sys
import urllib.parse
from collections import defaultdict
from typing import Any

import aiofiles
import aiohttp
import msgpack
import zstandard
from packaging.version import parse as PV

try:
    from .utils import SCRIPT_DIR
except ImportError:
    from conda_tool.utils import SCRIPT_DIR


async def download_with_retry(
    session: aiohttp.ClientSession, url: str, max_retries: int = 3
) -> bytes:
    """下载数据并自动重试"""
    last_error = None
    for attempt in range(max_retries):
        try:
            async with session.get(url) as response:
                if response.status == 200:
                    return await response.read()
                else:
                    last_error = f"HTTP Error {response.status}"
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            last_error = str(e)

        if attempt < max_retries - 1:
            await asyncio.sleep(2**attempt)  # 指数退避

    raise RuntimeError(
        f"Failed to download {url} after {max_retries} attempts. Last error: {last_error}"
    )


async def save_repodata(arch: str, forge_url: str) -> dict[str, Any]:
    """异步获取 repodata.json 数据"""
    os.makedirs(f"{SCRIPT_DIR}/data/{arch}", exist_ok=True)
    data = {}
    if not forge_url.endswith("/"):
        forge_url += "/"
    url = urllib.parse.urljoin(forge_url, f"{arch}/repodata.json.bz2")

    print(f"Downloading {url} ...")
    try:
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=300)
        ) as session:
            compressed_data = await download_with_retry(session, url)
            print(f"Processing {url} ...")
            repodata = bz2.decompress(compressed_data)
            repodata = json.loads(repodata)

            # 合并 packages 和 packages.conda
            data.update(repodata.get("packages", {}))
            data.update(repodata.get("packages.conda", {}))
            # 保存压缩版本
            try:
                async with aiofiles.open(
                    f"{SCRIPT_DIR}/data/{arch}/data.zstd", "wb"
                ) as f:
                    cctx = zstandard.ZstdCompressor()
                    compressed = cctx.compress(msgpack.dumps(data))  # type: ignore
                    await f.write(compressed)
            except OSError as e:
                print(f"Error saving compressed data: {str(e)}", file=sys.stderr)
    except Exception as e:
        print(f"Error processing {url}: {str(e)}", file=sys.stderr)
        raise

    return data


async def process_package(
    pkg_db: defaultdict, pn: str, p: dict[str, Any], forge_url: str
) -> None:
    """处理单个包数据"""
    try:
        n = p["name"]
        v = p["version"]
        deps = p.get("depends", [])
        pkg_db[n].append(
            {
                "name": n,
                "version": v,
                "nv": f"{n}-{v}",
                "depends": deps,
                "md5": p["md5"],
                "build": p["build"],
                "subdir": p["subdir"],
                "timestamp": p.get("timestamp", 0),
                "url": f"{forge_url}/{p['subdir']}/{pn}",
            }
        )
    except KeyError as e:
        print(f"Invalid package data for {pn}, missing key: {str(e)}", file=sys.stderr)


async def save_single_package(package_name: str, package_data: list[dict]) -> None:
    """保存单个包数据到单独文件"""
    package_dir = f"{SCRIPT_DIR}/data/packages"
    os.makedirs(package_dir, exist_ok=True)
    file_path = f"{package_dir}/{package_name}.zstd"

    try:
        sorted(package_data, key=lambda x: PV(x["version"]))
    except Exception:
        sorted(package_data, key=lambda x: (x["version"], x["timestamp"], x["build"]))
    try:
        async with aiofiles.open(file_path, "wb") as f:
            cctx = zstandard.ZstdCompressor()
            compressed = cctx.compress(msgpack.dumps(package_data))  # type: ignore
            await f.write(compressed)
    except OSError as e:
        print(f"Error saving package {package_name}: {str(e)}", file=sys.stderr)


async def parse_repodata(data: dict[str, Any], forge_url: str) -> None:
    """异步转换 repodata 数据"""
    print("Extracting package database ...")
    pkg_db = defaultdict(list)

    # 并行处理包数据
    print("Extracting package database ...")
    tasks = []
    for pn, p in data.items():
        tasks.append(process_package(pkg_db, pn, p, forge_url))
    await asyncio.gather(*tasks)

    tasks = []
    for package_name, package_data in pkg_db.items():
        tasks.append(save_single_package(package_name, package_data))
    await asyncio.gather(*tasks)


async def load_existing_data(arch: str) -> dict[str, Any]:
    """加载现有的数据"""
    exist_data_fn = f"{SCRIPT_DIR}/data/{arch}/data.zstd"
    try:
        async with aiofiles.open(exist_data_fn, "rb") as f:
            dctx = zstandard.ZstdDecompressor()
            data = await f.read()
            return msgpack.loads(dctx.decompress(data))  # type: ignore
    except Exception as e:
        print(f"Error loading existing data for {arch}: {str(e)}", file=sys.stderr)
        return {}


def parse_args() -> argparse.Namespace:
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--arch",
        nargs=argparse.ONE_OR_MORE,
        dest="ARCHES",
        type=str,
        choices=[
            "emscripten-wasm32",
            "freebsd-64",
            "linux-32",
            "linux-64",
            "linux-aarch64",
            "linux-armv6l",
            "linux-armv7l",
            "linux-ppc64",
            "linux-ppc64le",
            "linux-riscv64",
            "linux-s390x",
            "noarch",
            "osx-64",
            "osx-arm64",
            "wasi-wasm32",
            "win-32",
            "win-64",
            "win-arm64",
            "zos-z",
        ],
        default=["noarch", "linux-64", "linux-aarch64"],
        help="Conda arch (default: %(default)s",
    )
    parser.add_argument(
        "--url",
        dest="CONDA_FORGE_URL",
        choices=[
            "https://conda.anaconda.org/conda-forge",
            "https://mirrors.nju.edu.cn/anaconda/cloud/conda-forge",
        ],
        default="https://mirrors.nju.edu.cn/anaconda/cloud/conda-forge",
        help="Conda forge url (default: %(default)s",
    )
    parser.add_argument(
        "-f",
        "--force_refresh",
        action="store_true",
        default=False,
        required=False,
        help="Whether to force refresh repodata",
    )
    parser.add_argument(
        "--max-concurrent",
        type=int,
        default=5,
        help="Maximum concurrent downloads (default: %(default)s)",
    )
    args = parser.parse_args()
    return args


async def process_arch(
    arch: str, args: argparse.Namespace, semaphore: asyncio.Semaphore
) -> dict[str, Any]:
    """处理单个架构的数据"""
    async with semaphore:
        if (
            os.path.exists(f"{SCRIPT_DIR}/data/{arch}/data.zstd")
            and not args.force_refresh
        ):
            print(f"Loading existing data for {arch}...")
            data = await load_existing_data(arch)
        else:
            print(f"Downloading fresh data for {arch}...")
            data = await save_repodata(arch, args.CONDA_FORGE_URL)

        return data


async def async_main() -> None:
    """异步主逻辑"""
    args = parse_args()
    data = {}
    semaphore = asyncio.Semaphore(args.max_concurrent)

    # 并行处理所有架构
    tasks = []
    for arch in args.ARCHES:
        tasks.append(process_arch(arch, args, semaphore))

    results = await asyncio.gather(*tasks, return_exceptions=True)

    # 检查并处理结果
    for arch, result in zip(args.ARCHES, results, strict=False):
        if isinstance(result, Exception):
            print(f"Error processing {arch}: {str(result)}", file=sys.stderr)
        else:
            data[arch] = result

    # 解析数据
    if data:
        await parse_repodata(
            {k: v for d in data.values() for k, v in d.items()},  # 合并所有架构的数据
            args.CONDA_FORGE_URL,
        )
    else:
        print("No valid data to process", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    """同步入口函数"""
    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        print("\nOperation cancelled by user", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Fatal error: {str(e)}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
