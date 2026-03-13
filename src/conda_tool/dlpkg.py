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
from typing import TypedDict, cast

import msgpack
import zstandard
from colorama import Fore, Style
from packaging.version import parse as PV

try:
    from .recipe import RecipeParser, SourceUrlSpec
    from .utils import (
        SCRIPT_DIR,
        abs_path,
        extract_archive,
        get_choice,
        hash_files,
        setup_logging,
    )
except ImportError:
    from conda_tool.recipe import RecipeParser, SourceUrlSpec
    from conda_tool.utils import (
        SCRIPT_DIR,
        abs_path,
        extract_archive,
        get_choice,
        hash_files,
        setup_logging,
    )


logger = getLogger("conda_tool.dlpkg")

fn_is_simple = re.compile(r"^v?\d+([\-.]\d+)+(\.\w+)+$").match


class PackageSpec(TypedDict):
    name: str
    version: str
    nv: str
    md5: str
    build: str
    subdir: str
    url: str
    timestamp: int


DownloadTask = tuple[SourceUrlSpec, str | None, str]
RecipePaths = tuple[str, str, str, str]


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

        deps = self.extract_reqs(meta_yaml)
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
            # multi-output: recipe 直接作为模板使用
            recipe_file, recipe_tpl = self._find_recipe_file(
                old_recipe, new_recipe, is_parent=True
            )
        else:
            logger.info(f">> Copying recipe to {new_recipe} ...")
            shutil.copytree(old_recipe, new_recipe)
            conda_build_cfg = os.path.join(new_recipe, "conda_build_config.yaml")
            if os.path.exists(conda_build_cfg):
                logger.info(f">> Removing redundant {conda_build_cfg} ...")
                os.remove(conda_build_cfg)
            recipe_file, recipe_tpl = self._find_recipe_file(
                new_recipe, new_recipe, is_parent=False
            )
        logger.info(f">> Downloading packages to {self.pkgs_dir} ...")
        return old_recipe, new_recipe, recipe_file, recipe_tpl

    @staticmethod
    def _find_recipe_file(
        source_dir: str, dest_dir: str, *, is_parent: bool
    ) -> tuple[str, str]:
        """在 recipe 目录中查找 recipe.yaml 或 meta.yaml，返回 (recipe_file, recipe_tpl)"""
        recipe_yaml = os.path.join(dest_dir, "recipe.yaml")
        meta_yaml = os.path.join(dest_dir, "meta.yaml")
        if os.path.exists(recipe_yaml):
            if is_parent:
                return os.path.join(source_dir, "recipe.yaml"), recipe_yaml
            return recipe_yaml, recipe_yaml + ".template"
        if is_parent:
            return os.path.join(source_dir, "meta.yaml"), meta_yaml
        return meta_yaml, meta_yaml + ".template"

    @staticmethod
    def load_urls(recipe_path: str) -> list[SourceUrlSpec]:
        """从 recipe (meta.yaml 或 recipe.yaml) 中获取可下载的所有 url 地址"""
        parser = RecipeParser(recipe_path)
        # RecipeParser.load_urls 返回的是 recipe.SourceUrlSpec，
        # 结构与 dlpkg.SourceUrlSpec 一致，直接转换
        return [
            SourceUrlSpec(
                url=spec["url"],
                hash_type=spec["hash_type"],
                hash=spec["hash"],
                fn=spec["fn"],
            )
            for spec in parser.load_urls()
        ]

    def replace_urls(self, recipe_tpl: str, url_specs: list[SourceUrlSpec]) -> None:
        """替换 recipe 中 url 地址（支持 meta.yaml 和 recipe.yaml）"""
        parser = RecipeParser(recipe_tpl)
        url_mapping: dict[int, str] = {}
        for idx, url_spec in enumerate(url_specs):
            fn = url_spec.get("fn")
            if fn is None:
                url = url_spec["url"]
                fn = url_basename(url[0] if isinstance(url, list) else url)
            fn = str(fn)
            fn = f"{self.args.PKGNAME}-{fn}" if fn_is_simple(fn) else fn
            pkg_path = os.path.join(self.pkgs_dir, fn)
            pkg_path = os.path.relpath(pkg_path, os.path.dirname(recipe_tpl))
            url_mapping[idx] = pkg_path

        new_content = parser.replace_source_urls(url_mapping)
        parser.save(recipe_tpl, new_content)

    @staticmethod
    def extract_reqs(recipe_path: str) -> str:
        """从 recipe (meta.yaml 或 recipe.yaml) 中找出所依赖的包列表"""
        parser = RecipeParser(recipe_path)
        return parser.extract_reqs()


def main() -> None:
    """函数主流程"""
    setup_logging(120)
    args = parse_args()
    downloader = DownloadPkg(args)
    downloader.run()


if __name__ == "__main__":
    main()
