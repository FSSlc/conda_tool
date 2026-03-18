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
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from logging import getLogger
from typing import Any

import aiohttp
import msgpack
import zstandard
from packaging.version import InvalidVersion
from packaging.version import parse as PV

try:
    from .utils import SCRIPT_DIR, setup_logging
except ImportError:
    from conda_tool.utils import SCRIPT_DIR, setup_logging


logger = getLogger("conda_tool.makedb")


def _write_bytes(path: str, data: bytes) -> None:
    """Write bytes synchronously for reuse by the bounded thread pool."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


def _read_bytes(path: str) -> bytes:
    """Read bytes synchronously for reuse by the bounded thread pool."""
    with open(path, "rb") as f:
        return f.read()


async def run_file_io(
    file_executor: ThreadPoolExecutor, func: Any, *args: Any
) -> Any:
    """Run file I/O in the bounded thread pool."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(file_executor, partial(func, *args))


async def download_with_retry(
    session: aiohttp.ClientSession, url: str, max_retries: int = 3
) -> bytes:
    """Download data with automatic retry."""
    last_error = None
    for attempt in range(max_retries):
        try:
            async with session.get(url) as response:
                if response.status == 200:
                    return await response.read()
                last_error = f"HTTP Error {response.status}"
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            last_error = str(e)

        if attempt < max_retries - 1:
            await asyncio.sleep(2**attempt)  # Exponential backoff.

    raise RuntimeError(
        f"Failed to download {url} after {max_retries} attempts. Last error: {last_error}"
    )


async def save_repodata(
    arch: str,
    forge_url: str,
    file_semaphore: asyncio.Semaphore,
    file_executor: ThreadPoolExecutor,
) -> dict[str, Any]:
    """Fetch repodata.json asynchronously."""
    os.makedirs(f"{SCRIPT_DIR}/data/{arch}", exist_ok=True)
    data = {}
    if not forge_url.endswith("/"):
        forge_url += "/"
    url = urllib.parse.urljoin(forge_url, f"{arch}/repodata.json.bz2")

    logger.info(f"Downloading {url} ...")
    try:
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=300)
        ) as session:
            compressed_data = await download_with_retry(session, url)
            logger.info(f"Processing {url} ...")
            repodata = bz2.decompress(compressed_data)
            repodata = json.loads(repodata)

            # Merge packages and packages.conda.
            data.update(repodata.get("packages", {}))
            data.update(repodata.get("packages.conda", {}))
            # Save the compressed snapshot.
            try:
                cctx = zstandard.ZstdCompressor()
                compressed = cctx.compress(msgpack.dumps(data))  # type: ignore
                async with file_semaphore:
                    await run_file_io(
                        file_executor,
                        _write_bytes,
                        f"{SCRIPT_DIR}/data/{arch}/data.zstd",
                        compressed,
                    )
            except OSError as e:
                logger.error(f"Error saving compressed data: {str(e)}")
    except Exception as e:
        logger.error(f"Error processing {url}: {str(e)}")
        raise

    return data


async def process_package(
    pkg_db: defaultdict, pn: str, p: dict[str, Any], forge_url: str
) -> None:
    """Process a single package record."""
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
        logger.warning(f"Invalid package data for {pn}, missing key: {str(e)}")


async def save_single_package(
    package_name: str,
    package_data: list[dict],
    file_semaphore: asyncio.Semaphore,
    file_executor: ThreadPoolExecutor,
) -> None:
    """Save a single package's data to its own file."""
    package_dir = f"{SCRIPT_DIR}/data/packages"
    file_path = f"{package_dir}/{package_name}.zstd"

    try:
        # Reduce memory usage by sorting immediately without storing intermediates.
        package_data = sorted(
            package_data,
            key=lambda x: (PV(x["version"]), x["timestamp"], x["build"]),
            reverse=True,
        )
    except (InvalidVersion, TypeError):
        package_data = sorted(
            package_data,
            key=lambda x: (x["version"], x["timestamp"], x["build"]),
            reverse=True,
        )

    try:
        # Use a context-managed write path so files are closed promptly.
        cctx = zstandard.ZstdCompressor()
        compressed = cctx.compress(msgpack.dumps(package_data))  # type: ignore

        async with file_semaphore:
            await run_file_io(file_executor, _write_bytes, file_path, compressed)
    except OSError as e:
        logger.error(f"Error saving package {package_name}: {str(e)}")


def iter_repodata_items(
    data: dict[str, Any] | list[dict[str, Any]],
) -> Iterable[tuple[str, dict[str, Any]]]:
    """Iterate package records from one or more repodata mappings."""
    repodata_groups = [data] if isinstance(data, dict) else data
    for repodata in repodata_groups:
        yield from repodata.items()


async def parse_repodata(
    data: dict[str, Any] | list[dict[str, Any]],
    forge_url: str,
    semaphore: asyncio.Semaphore,
    file_semaphore: asyncio.Semaphore,
    file_executor: ThreadPoolExecutor,
) -> None:
    """Convert repodata into the local package database asynchronously."""
    logger.info("Extracting package database ...")
    pkg_db = defaultdict(list)

    # Process package records in parallel.
    logger.info("Processing packages ...")
    async def process_with_limit(pn: str, p: dict[str, Any]) -> None:
        async with semaphore:
            await process_package(pkg_db, pn, p, forge_url)

    package_items = list(iter_repodata_items(data))
    process_batch_size = 1000
    for index in range(0, len(package_items), process_batch_size):
        batch = package_items[index : index + process_batch_size]
        tasks = [process_with_limit(pn, p) for pn, p in batch]
        await asyncio.gather(*tasks)

    # Save packages in batches to avoid opening too many files at once.
    batch_size = 100  # Process 100 packages per batch.
    package_items = list(pkg_db.items())
    for i in range(0, len(package_items), batch_size):
        batch = package_items[i : i + batch_size]
        tasks = [
            save_single_package(
                package_name, package_data, file_semaphore, file_executor
            )
            for package_name, package_data in batch
        ]
        await asyncio.gather(*tasks)
        logger.info(
            f"Processed batch {i // batch_size + 1}/{(len(package_items) - 1) // batch_size + 1}"
        )


async def load_existing_data(
    arch: str,
    file_semaphore: asyncio.Semaphore,
    file_executor: ThreadPoolExecutor,
) -> dict[str, Any]:
    """Load an existing repodata snapshot."""
    exist_data_fn = f"{SCRIPT_DIR}/data/{arch}/data.zstd"
    try:
        async with file_semaphore:
            data = await run_file_io(file_executor, _read_bytes, exist_data_fn)
        dctx = zstandard.ZstdDecompressor()
        return msgpack.loads(dctx.decompress(data))  # type: ignore
    except Exception as e:
        logger.error(f"Error loading existing data for {arch}: {str(e)}")
        return {}


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
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
        help="Conda arch (default: %(default)s)",
    )
    parser.add_argument(
        "--url",
        dest="CONDA_FORGE_URL",
        choices=[
            "https://conda.anaconda.org/conda-forge",
            "https://mirrors.nju.edu.cn/anaconda/cloud/conda-forge",
        ],
        default="https://conda.anaconda.org/conda-forge",
        help="Conda forge url (default: %(default)s)",
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
        "--max",
        type=int,
        default=100,
        help="Maximum concurrent downloads (default: %(default)s)",
    )
    parser.add_argument(
        "--file-max",
        type=int,
        default=50,
        help="Maximum concurrent file operations (default: %(default)s)",
    )
    args = parser.parse_args()
    return args


async def process_arch(
    arch: str,
    args: argparse.Namespace,
    semaphore: asyncio.Semaphore,
    file_semaphore: asyncio.Semaphore,
    file_executor: ThreadPoolExecutor,
) -> dict[str, Any]:
    """Process repodata for a single architecture."""
    async with semaphore:
        if (
            os.path.exists(f"{SCRIPT_DIR}/data/{arch}/data.zstd")
            and not args.force_refresh
        ):
            logger.info(f"Loading existing data for {arch}...")
            data = await load_existing_data(arch, file_semaphore, file_executor)
        else:
            logger.info(f"Downloading fresh data for {arch}...")
            data = await save_repodata(
                arch, args.CONDA_FORGE_URL, file_semaphore, file_executor
            )

        return data


async def async_main() -> None:
    """Run the asynchronous main workflow."""
    args = parse_args()
    data = {}
    semaphore = asyncio.Semaphore(args.max)
    file_semaphore = asyncio.Semaphore(args.file_max)
    with ThreadPoolExecutor(max_workers=max(1, args.file_max)) as file_executor:
        # Process all architectures in parallel.
        tasks = []
        for arch in args.ARCHES:
            tasks.append(
                process_arch(arch, args, semaphore, file_semaphore, file_executor)
            )

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Check and collect results.
        for arch, result in zip(args.ARCHES, results, strict=False):
            if isinstance(result, Exception):
                logger.error(f"Error processing {arch}: {str(result)}")
            else:
                data[arch] = result

        # Parse the collected data.
        if data:
            await parse_repodata(
                list(data.values()),
                args.CONDA_FORGE_URL,
                semaphore,
                file_semaphore,
                file_executor,
            )
        else:
            logger.error("No valid data to process")
            sys.exit(1)


def main() -> None:
    """Run the synchronous entry point."""
    setup_logging(120)
    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        logger.warning("Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Fatal error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
