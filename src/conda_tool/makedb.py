#!/usr/bin/env python3

"""Create a package database for newest packages from conda-forge channel"""

import argparse
import bz2
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from typing import Any

from packaging.version import parse as PV

try:
    from .utils import SCRIPT_DIR
except ImportError:
    from utils import SCRIPT_DIR


def load_repodata(arches: list[str], forge_url: str) -> dict[str, Any]:
    """获取 repodata.json 数据"""
    data = {}
    for arch in arches:
        if not forge_url.endswith("/"):
            forge_url += "/"
        url = urllib.parse.urljoin(forge_url, f"{arch}/repodata.json.bz2")
        print(f"Connecting to {url} ...")
        try:
            with urllib.request.urlopen(url) as f:
                print(f"Loading {url} ...")
                repodata = bz2.decompress(f.read())
                print(f"Parsing {url} ...")
                repodata = json.loads(repodata)
                data.update(repodata["packages"])
                data.update(repodata["packages.conda"])
        except urllib.error.HTTPError as e:
            print(f"Error, download '{url}' failed, details: '{str(e)}'")
    if not os.path.exists(f"{SCRIPT_DIR}/data"):
        os.makedirs(f"{SCRIPT_DIR}/data")
    with open(f"{SCRIPT_DIR}/data/data.json", "w", encoding="utf8", newline="\n") as f:
        json.dump(data, f, ensure_ascii=False)
    return data


def parse_repodata(data: Any, out: str, forge_url: str) -> None:
    """转换 repodata 数据"""
    print("Extracting package database ...")
    pkg_db = defaultdict(list)
    for pn, p in data.items():
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
                "subdir": p['subdir'],
                "timestamp": p.get("timestamp", 0),
                "url": f"{forge_url}/{p['subdir']}/{pn}",
            }
        )
    for k, v in pkg_db.items():
        try:
            pkg_db[k] = sorted(v, key=lambda x: PV(x["version"]))
        except Exception:
            pkg_db[k] = sorted(
                v, key=lambda x: (x["version"], x["timestamp"], x["build"])
            )
    print(f"Writing package database to {out}")
    with open(out, "w", encoding="utf8", newline="\n") as f:
        json.dump(pkg_db, f, ensure_ascii=False)


def parse_args() -> argparse.Namespace:
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "-o",
        "--output",
        default=f"{SCRIPT_DIR}/data/pkgdb.json",
        help="Output package databse file (default: '%(default)s')",
    )
    parser.add_argument(
        "--arch",
        nargs=argparse.ONE_OR_MORE,
        dest="ARCHES",
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
        default=["noarch", "linux-64", "linux-aarch64", "win-64", "win-arm64"],
        help="Conda arch (default: %(default)s",
    )
    parser.add_argument(
        "--url",
        dest="CONDA_FORGE_URL",
        choices=[
            "https://conda.anaconda.org/conda-forge",
            "https://mirrors.nju.edu.cn/anaconda/cloud/conda-forge",
        ],
        default="https://conda.anaconda.org/conda-forge",
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
    args = parser.parse_args()
    return args


def main() -> None:
    """主要实现逻辑"""
    args = parse_args()
    exist_data_fn = f"{SCRIPT_DIR}/data/data.json"
    if os.path.exists(exist_data_fn):
        with open(exist_data_fn, encoding="utf8") as fin:
            data = json.load(fin)
    else:
        data = load_repodata(args.ARCHES, args.CONDA_FORGE_URL)
    parse_repodata(data, args.output, args.CONDA_FORGE_URL)


if __name__ == "__main__":
    main()
