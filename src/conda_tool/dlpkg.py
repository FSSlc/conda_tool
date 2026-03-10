#!/usr/bin/env python3

"""A tool to create a feedstock directly from a conda-forge package"""

import argparse
import os
import re
import shutil
import sys
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures.process import ProcessPoolExecutor
from logging import getLogger
from multiprocessing import Manager
from re import Match
from typing import Literal, TypedDict, cast

import msgpack
import ruamel.yaml
import zstandard
from colorama import Fore, Style
from packaging.version import parse as PV

try:
    from .utils import (
        SCRIPT_DIR,
        abs_path,
        extract_archive,
        get_choice,
        hash_files,
        setup_logging,
    )
except ImportError:
    from conda_tool.utils import (
        SCRIPT_DIR,
        abs_path,
        extract_archive,
        get_choice,
        hash_files,
        setup_logging,
    )


setup_logging(120)
logger = getLogger("conda_tool.dlpkg")

fn_is_simple = re.compile(r"^v?\d+([\-.]\d+)+(\.\w+)+$").match
url_p1 = re.compile(r"(^\s*-\s*)(.*)$")
url_p2 = re.compile(r"(^\s*-?\s*url:\s*)(.*)$")
url_p3 = re.compile(r"(^\s*-?\s*url:\s*)([^{]+)\{\{.*\}\}([^}]+)$")

HashType = Literal["md5", "sha1", "sha256"]
PackageUrl = str | list[str]


class PackageSpec(TypedDict):
    name: str
    version: str
    nv: str
    md5: str
    build: str
    subdir: str
    url: str
    timestamp: int


class SourceUrlSpec(TypedDict):
    url: PackageUrl
    hash_type: HashType | None
    hash: str | None
    fn: str | None


DownloadTask = tuple[SourceUrlSpec, str | None, str]
RecipePaths = tuple[str, str, str, str]
UrlBlock = list[int]


def url_basename(url: str) -> str:
    """获取名称"""
    return os.path.basename(urllib.parse.urlparse(url).path)


def parse_args() -> argparse.Namespace:
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "PKGNAME",
        help="Package name without any version and build strings.",
    )
    parser.add_argument(
        "-ub",
        "--upper_bound",
        default=None,
        help="Package version upper bound (default: highest)",
    )
    parser.add_argument(
        "--py",
        default="310",
        help="python version (default: %(default)s)",
    )
    parser.add_argument(
        "--subdir",
        default="linux-64",
        choices=["noarch", "linux-64", "linux-aarch64", "win-64", "win-arm64"],
        help="subdir for conda pkg",
    )
    parser.add_argument(
        "--ignore-py",
        action="store_true",
        help="ignore python version string",
    )
    parser.add_argument(
        "-i",
        "--interact",
        action="store_true",
        help="allow user choose which version to be download",
    )
    parser.add_argument(
        "--specs_dir",
        default=f"{os.path.join(SCRIPT_DIR, 'data', 'packages')}",
        help="Package database file (default: %(default)s)",
    )
    parser.add_argument(
        "--workdir",
        metavar="WORKDIR",
        default=f"{os.path.join(SCRIPT_DIR, 'workdir')}",
        help="Workdir for downloading (default: %(default)s)",
    )
    parser.add_argument(
        "--recipes-dir",
        metavar="DIR",
        default=f"{os.path.join(SCRIPT_DIR, 'recipes')}",
        help="Recipes directory (default: %(default)s)",
    )
    parser.add_argument(
        "--pkgs-dir",
        metavar="DIR",
        default=f"{os.path.join(SCRIPT_DIR, 'pkgs')}",
        help="Source packages directory (default: %(default)s)",
    )
    args = parser.parse_args()

    args.specs_dir = abs_path(args.specs_dir)
    args.workdir = abs_path(args.workdir)
    args.pkgs_dir = abs_path(args.pkgs_dir)
    args.recipes_dir = abs_path(args.recipes_dir)
    return args


class DownloadPkg:
    """从依赖数据中获取下载地址并下载源码、修改 meta.yaml"""

    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.workdir = self.args.workdir
        self.pkg_name = self.args.PKGNAME
        self.pkgs_dir = self.args.pkgs_dir
        self.recipes_dir = self.args.recipes_dir
        self.errors = Manager().list()

    def run(self) -> None:
        """主要实现逻辑"""

        pkg_spec = self.get_pkg_spec()
        self.create_feedstock(pkg_spec)

        if len(self.errors) > 0:
            logger.error(" Please check following error ".center(80, "-"))
            self.errors = list(set(self.errors))
            for error in self.errors:
                logger.error(error)
            logger.error("-" * 80)

    def get_pkg_spec(self) -> PackageSpec:
        """获取软件包的信息"""
        py = self.args.py
        ver = self.args.upper_bound

        spec_file = os.path.join(self.args.specs_dir, f"{self.pkg_name}.zstd")
        if not os.path.exists(spec_file):
            logger.error(
                f"{Fore.RED}oo Requested package {self.pkg_name}"
                + f" is not in database{Style.RESET_ALL}"
            )
            sys.exit(1)

        pkg_specs: list[PackageSpec] = []
        dctx = zstandard.ZstdDecompressor()
        with open(spec_file, "rb") as f:
            pkg_specs = cast(
                list[PackageSpec], msgpack.loads(dctx.decompress(f.read()))
            )

        if not pkg_specs:
            logger.error(
                f"{Fore.RED}oo Package {self.pkg_name} has no available specs in database"
                f"{Style.RESET_ALL}"
            )
            sys.exit(1)

        if py and (not self.args.ignore_py):
            filter_pkg_specs = [
                spec for spec in pkg_specs if py in str(spec.get("build", ""))
            ]
            if len(filter_pkg_specs) > 0:
                pkg_specs = list(filter_pkg_specs)
            else:
                logger.warning(
                    f"{Fore.YELLOW}>> No packages with {py} build string{Style.RESET_ALL}"
                )

        if self.args.subdir:
            filter_pkg_specs = [
                spec
                for spec in pkg_specs
                if self.args.subdir == spec["subdir"] or spec["subdir"] == "noarch"
            ]
            if len(filter_pkg_specs) > 0:
                pkg_specs = list(filter_pkg_specs)
            else:
                logger.warning(
                    f"{Fore.YELLOW}>> No packages with {self.args.subdir} found{Style.RESET_ALL}"
                )

        if self.args.interact and ver:
            pkg_specs = [p for p in reversed(pkg_specs) if PV(p["version"]) == PV(ver)]
            if len(pkg_specs) == 0:
                logger.error(
                    f"{Fore.RED}version {ver} of {self.pkg_name} "
                    f"is not found in the db{Style.RESET_ALL}"
                )
                sys.exit(1)
        pkg_specs.sort(key=lambda spec: f"{spec['timestamp']}-{spec['url']}")
        if self.args.interact:
            urls = [f"{spec['timestamp']}-{spec['url']}" for spec in pkg_specs]
            choice = get_choice(
                "Please choose a package to download",
                urls,
                default=len(urls) - 1,
            )
            if choice == -1:
                sys.exit(0)
            return pkg_specs[choice]

        if ver is None:
            pkg_spec = pkg_specs[-1]  # the newest version
            return pkg_spec

        pkg_spec = None
        for p in reversed(pkg_specs):
            if PV(p["version"]) <= PV(ver):
                pkg_spec = p
                break
        if pkg_spec is None:
            logger.error(
                f"{Fore.RED}version {ver} of {self.pkg_name} "
                f"is not found in the db{Style.RESET_ALL}"
            )
            sys.exit(1)
        return pkg_spec

    def create_feedstock(self, pkg_spec: PackageSpec) -> None:
        """创建 feestock"""
        pkg = pkg_spec["name"]
        logger.info(
            f"{Fore.GREEN}>> Creating feedstock for "
            + f"{pkg!r} {pkg_spec['version']}{Style.RESET_ALL}"
        )
        logger.info(
            f">> Downloading binary package {pkg_spec['nv']} from conda-forge channel ..."
        )
        out_fn = os.path.join(self.workdir, url_basename(pkg_spec["url"]))

        url_spec = SourceUrlSpec(
            url=pkg_spec["url"],
            hash_type="md5",
            hash=pkg_spec["md5"],
            fn=url_basename(pkg_spec["url"]),
        )
        self.download_file((url_spec, pkg, self.workdir))

        extract_dir = (
            os.path.basename(out_fn).replace(".tar.bz2", "").replace(".conda", "")
        )

        # pylint: disable-next=attribute-defined-outside-init
        self.extract_dir = os.path.normpath(os.path.join(self.workdir, extract_dir))

        self.unpack_conda_pkg(out_fn, self.extract_dir, pkg_spec)

        old_recipe, new_recipe, meta_yaml, meta_yaml_tpl = self.unpack_recipe(pkg_spec)

        url_specs = self.load_urls(meta_yaml)
        para_pairs = list(
            zip(
                url_specs,
                [pkg] * len(url_specs),
                [self.pkgs_dir] * len(url_specs),
                strict=True,
            )
        )

        with ProcessPoolExecutor(max_workers=os.cpu_count()) as pool:
            list(pool.map(self.download_file, para_pairs))

        logger.info(
            f"{Fore.GREEN}>> Replacing urls in {meta_yaml_tpl} ...{Style.RESET_ALL}"
        )
        self.replace_urls(meta_yaml_tpl, url_specs)
        if os.path.exists(os.path.join(old_recipe, "parent")):
            logger.info(f">> Created feedstock for {pkg!r} at {new_recipe}.")
        else:
            os.remove(meta_yaml)
            shutil.move(meta_yaml_tpl, meta_yaml)
            logger.info(
                f"{Fore.GREEN}>> Created feedstock for {pkg!r} "
                + f"at {new_recipe}.{Style.RESET_ALL}"
            )
        logger.warning(
            f"{Fore.YELLOW}!! Please be sure to check the recipe for necessary modifications."
        )
        logger.warning(
            f"!! Please check if all the following dependencies are built: {Style.RESET_ALL}"
        )

        deps = self.extract_reqs(os.path.join(new_recipe, "meta.yaml"))
        logger.info("-" * 80)
        logger.info(deps)
        logger.info("-" * 80)

    def download_file(self, para_pairs: DownloadTask) -> None:
        """下载文件"""
        url_spec, pkg, out_dir = para_pairs
        url = url_spec["url"]
        if url_spec.get("fn") is not None:
            fn = cast(str, url_spec.get("fn"))
        else:
            if isinstance(url, list):
                fn = url_basename(url[0])
            else:
                fn = url_basename(url)
        fn = f"{pkg}-{fn}" if pkg and fn_is_simple(fn) else fn
        url_spec.update({"fn": fn})
        full_fn = os.path.join(out_dir, fn)

        dl_urls = [url] if not isinstance(url, list) else list(url)
        dl_urls = [
            urllib.parse.urljoin("https://github.moeyy.xyz/", item)
            if "github" in item
            else item
            for item in dl_urls
        ]

        if os.path.exists(full_fn):
            hash_type = url_spec.get("hash_type")
            file_hash = url_spec.get("hash")
            if hash_type and file_hash:
                local_hash = hash_files([full_fn], hash_type)
                if local_hash == file_hash:
                    logger.info(
                        f"{Fore.YELLOW}oo {fn} exists, skip downloading.{Style.RESET_ALL}"
                    )
                    return
                os.unlink(full_fn)
                self.local_download(dl_urls, full_fn)
            else:
                logger.info(
                    f"{Fore.YELLOW}oo {fn} exists, skip downloading because no hash is available.{Style.RESET_ALL}"
                )
                return
        else:
            self.local_download(dl_urls, full_fn)

    def local_download(self, dl_urls: list[str], fn: str) -> None:
        """包装 download"""
        for url in dl_urls:
            res = self.download(url, fn)
            if isinstance(res, bool) and res is True:
                logger.info(f"oo File saved to {fn}{Style.RESET_ALL}")
                return
            # 重试一次
            logger.warning(
                f"{Fore.RED}oo Downloading error, retry once.{Style.RESET_ALL}"
            )
            res = self.download(url, fn)
            if isinstance(res, bool) and res is True:
                logger.info(f"oo File saved to {fn}{Style.RESET_ALL}")
                return
            if res is False:
                msg = (
                    f"{Fore.RED}oo Downloading error, "
                    f"Please download '{url}' by youself.{Style.RESET_ALL}"
                )
                self.errors.append(msg)
            else:
                self.errors.append(str(res))

    @staticmethod
    def download(url: str, fn: str) -> bool | Exception:
        """下载 url 到 fn"""
        try:
            chunk_size = 64 * 1024
            dest = os.path.dirname(fn)
            basefn = os.path.basename(fn)
            os.makedirs(dest, exist_ok=True)
            url_segs = urllib.parse.urlparse(url)
            netloc = url_segs.netloc
            with open(fn, "wb") as out:
                logger.info(f"{Fore.YELLOW}oo Connecting to {netloc}")
                with urllib.request.urlopen(url) as f:
                    logger.info(f"oo Downloading {basefn} from {url}")
                    logger.info(f"oo Downloading {basefn} to {dest}")
                    while True:
                        s = f.read(chunk_size)
                        if len(s) == 0:
                            break
                        out.write(s)
            return True
        except urllib.error.HTTPError:
            return False
        except Exception as e:
            return e

    def unpack_conda_pkg(
        self, out_fn: str, extract_dir: str, pkg_spec: PackageSpec
    ) -> None:
        """解压下载下来的 conda 包"""
        logger.info(f">> Unpacking {os.path.basename(out_fn)} to {extract_dir}...")
        shutil.rmtree(extract_dir, ignore_errors=True)
        os.makedirs(extract_dir, exist_ok=True)
        if ".conda" in out_fn:
            extract_archive(out_fn, extract_dir, "conda")
            info_out_fn = "info-" + url_basename(pkg_spec["url"]).replace(
                ".conda", ".tar.zst"
            )
            info_out_path = os.path.join(extract_dir, info_out_fn)
            extract_archive(info_out_path, extract_dir, fmt="zst")
        else:
            extract_archive(out_fn, extract_dir)

    def unpack_recipe(self, pkg_spec: PackageSpec) -> RecipePaths:
        """从下载的 conda 包中解压出 recipe"""
        old_recipe = os.path.normpath(os.path.join(self.extract_dir, "info", "recipe"))
        new_recipe = os.path.normpath(os.path.join(self.recipes_dir, pkg_spec["nv"]))
        os.makedirs(self.recipes_dir, exist_ok=True)
        if os.path.exists(new_recipe):
            shutil.rmtree(new_recipe)
        if os.path.exists(os.path.join(old_recipe, "parent")):
            logger.warning(
                f"{Fore.RED}!! {self.pkg_name} is a multi-output package, "
                f"correct its name{Style.RESET_ALL}"
            )
            real_recipe = os.path.join(old_recipe, "parent")
            shutil.copytree(real_recipe, new_recipe)
            meta_yaml = os.path.join(old_recipe, "meta.yaml")
            meta_yaml_tpl = os.path.join(new_recipe, "meta.yaml")
        else:
            logger.info(f">> Copying recipe to {new_recipe} ...")
            shutil.copytree(old_recipe, new_recipe)
            conda_build_cfg = os.path.join(new_recipe, "conda_build_config.yaml")
            meta_yaml = os.path.join(new_recipe, "meta.yaml")
            meta_yaml_tpl = os.path.join(new_recipe, "meta.yaml.template")
            if os.path.exists(conda_build_cfg):
                logger.info(f">> Removing redundant {conda_build_cfg} ...")
                os.remove(conda_build_cfg)
        logger.info(f">> Downloading packages to {self.pkgs_dir} ...")
        return old_recipe, new_recipe, meta_yaml, meta_yaml_tpl

    @staticmethod
    def load_urls(meta_yaml: str) -> list[SourceUrlSpec]:
        """从 meta.yaml 中获取可下载的所有 url 地址"""
        loader = ruamel.yaml.YAML()
        with open(meta_yaml, encoding="utf8") as f:
            meta = loader.load(f)
        result: list[SourceUrlSpec] = []
        if "source" not in meta:
            return []
        sources = meta["source"]
        if not isinstance(sources, list):
            sources = [sources]
        for item in sources:
            # 当前只支持下载 url 类型的来源
            if "url" not in item:
                logger.warning(
                    f"{Fore.YELLOW}Not supporting source type for {item}{Style.RESET_ALL}"
                )
                continue
            url = item["url"]
            hash_type: HashType | None = None
            file_hash = None
            for ht in ["md5", "sha1", "sha256"]:
                if ht in item:
                    hash_type = ht  # type: ignore
                    break
            if hash_type is not None:
                file_hash = item[hash_type]
            fn = item.get("fn", None)
            result.append(
                SourceUrlSpec(url=url, hash_type=hash_type, hash=file_hash, fn=fn)
            )
        return result

    def replace_urls(self, meta_yaml_tpl: str, url_specs: list[SourceUrlSpec]) -> None:
        """替换 meta.yaml 中 url 地址"""
        with open(meta_yaml_tpl, encoding="utf-8") as f:
            content = f.read().split("\n")
        url_blocks = self.get_url_block(content)
        if len(url_blocks) > 0:
            new_contents = self.get_new_contents(
                content, url_blocks, url_specs, meta_yaml_tpl
            )
            with open(meta_yaml_tpl, "w", encoding="utf8") as f:
                f.write("\n".join(new_contents))

    @staticmethod
    def get_url_block(content: list[str]) -> list[UrlBlock]:
        """获取 meta 中关于 url 的那些行的范围"""
        url_blocks = []
        for ln, line in enumerate(content):
            m = url_p2.match(line)
            if not m:
                continue
            if "://" in line:
                url_blocks.append([ln, ln + 1])
            else:
                cln = ln
                while cln + 1 < len(content):
                    next_line = content[cln + 1]
                    if not (next_line.strip() == "" or "://" in next_line):
                        break
                    cln += 1
                url_blocks.append([ln, cln + 1])
        return url_blocks

    def get_new_contents(
        self,
        content: list[str],
        url_blocks: list[UrlBlock],
        url_specs: list[SourceUrlSpec],
        meta_yaml_tpl: str,
    ) -> list[str]:
        """生成新的 meta.yaml 内容"""
        new_contents = content[0 : url_blocks[0][0]]
        for idx, block in enumerate(url_blocks):
            block_content = content[block[0] : block[1]]

            m, new_url, match_url_spec = self.get_new_url(block_content, url_specs)
            if match_url_spec is not None:
                fn = os.path.basename(urllib.parse.urlparse(new_url).path)
                if match_url_spec.get("fn") is not None:
                    fn = cast(str, match_url_spec.get("fn"))
                fn = str(fn)
                fn = f"{self.args.PKGNAME}-{fn}" if fn_is_simple(fn) else fn
                pkg_path = os.path.join(self.pkgs_dir, fn)
                pkg_path = os.path.relpath(pkg_path, os.path.dirname(meta_yaml_tpl))
                if len(block_content) == 1 and m is not None:
                    new_contents.append(m.group(1) + pkg_path)
                    # 原有的 source 加上注释
                    comment_block_content = "#" + block_content[0]
                    new_contents.append(comment_block_content)
                else:
                    new_contents.append(block_content[0] + " " + pkg_path)
                    # 原有的 source 加上注释
                    comment_block_content = ["#" + line for line in block_content]
                    new_contents.extend(comment_block_content)
            else:
                new_contents.extend(block_content)
            if idx != (len(url_blocks) - 1):
                # pylint: disable-next=unnecessary-list-index-lookup
                new_contents += content[url_blocks[idx][1] : url_blocks[idx + 1][0]]
        new_contents += content[url_blocks[-1][1] :]
        return new_contents

    @staticmethod
    def get_new_url(
        block_content: list[str], url_specs: list[SourceUrlSpec]
    ) -> tuple[Match[str] | None, str | None, SourceUrlSpec | None]:
        """得到新的 url 地址"""
        change_line = ""
        if len(block_content) == 1:
            change_line = block_content[0]
        else:
            for line in block_content:
                if "://" in line:
                    change_line = line
                    break
                continue
        if "{{" in change_line:
            if len(block_content) == 1:
                m = url_p3.match(change_line)
            else:
                m = url_p1.match(change_line)
            if m is None:
                return None, None, None
            new_url_pattern = re.escape(m.group(2)) + r".*" + re.escape(m.group(3))
        else:
            if len(block_content) == 1:
                m = url_p2.match(change_line)
            else:
                m = url_p1.match(change_line)
            if m is None:
                return None, None, None
            new_url_pattern = re.escape(m.group(2))

        new_url, match_url_spec = None, None

        for url_spec in url_specs:
            if new_url is None:
                url: list[str] | str = url_spec.get("url")
                if not isinstance(url, list):
                    urls = [url]
                else:
                    urls = url
                for u in urls:
                    if re.match(new_url_pattern, u):
                        new_url = u
                        match_url_spec = url_spec
                        break
        return m, new_url, match_url_spec

    @staticmethod
    def extract_reqs(meta_yaml: str) -> str:
        """从 meta.yaml 中找出所依赖的包列表"""
        with open(meta_yaml, encoding="utf-8") as f:
            content = f.read().split("\n")
        keys = ("host:", "run:", "build:", "run_constrained:")
        in_req = False
        result = []
        for line in content:
            line = line.strip()
            if not line:
                continue
            if not in_req:
                if not line.startswith("requirements:"):
                    continue
                in_req = True
                result.append(line)
            else:
                if line.startswith("#"):
                    continue
                if line.startswith("{"):
                    result.append(line)
                    continue
                if line.startswith("-"):
                    result.append(line)
                    continue
                if line.endswith(":") and line not in keys:
                    in_req = False
                    continue
                result.append(line)
        return "\n".join(result)


def main() -> None:
    """函数主流程"""
    args = parse_args()
    downloader = DownloadPkg(args)
    downloader.run()


if __name__ == "__main__":
    main()
