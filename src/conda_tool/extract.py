#!/usr/bin/env python

"""A tool to extract conda packages from a conda constructor sh package."""

import argparse
import os
import shutil
import sys
from logging import getLogger
from typing import Any

try:
    from .utils import SCRIPT_DIR, abs_path, extract_large_tar, setup_logging
except ImportError:
    from conda_tool.utils import SCRIPT_DIR, abs_path, extract_large_tar, setup_logging


setup_logging(120)
logger = getLogger(__name__)

HEADER_PREFIXES = {
    b"# NAME:  ": "name",
    b"# VER:   ": "version",
    b"# PLAT:  ": "platform",
    b"# BYTES: ": "bytes",
    b"# LINES: ": "lines",
    b"# MD5:   ": "md5",
}


def parse_args() -> argparse.Namespace:
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description="conda sh 包解压工具")

    # 添加参数
    parser.add_argument("-s", "--source", required=True, help="sh 源文件路径")
    parser.add_argument(
        "-o",
        "--output",
        required=False,
        default=os.path.join(SCRIPT_DIR, "output"),
        help="目标目录路径",
    )
    parser.add_argument(
        "-c",
        "--clean",
        action="store_true",
        required=False,
        help="是否清理已存在的输出目录",
    )
    parser.add_argument(
        "-gr",
        "--generate_repo",
        action="store_true",
        required=False,
        help="是否按照 subdir 整理 conda 包",
    )
    parser.add_argument(
        "-k", "--keep_tar", action="store_true", required=False, help="是否删除压缩包"
    )

    # 解析参数
    args = parser.parse_args()

    # 获取参数值
    args.source = abs_path(args.source)
    args.output = abs_path(args.output)

    # 检查源文件是否存在
    if not os.path.isfile(args.source):
        logger.error(f"错误：源文件 '{args.source}' 不存在")
        sys.exit(1)

    if os.path.exists(args.output) and not os.path.isdir(args.output):
        logger.error(f"错误：目标路径 '{args.output}' 不是目录")
        sys.exit(1)

    if args.clean and os.path.isdir(args.output):
        shutil.rmtree(args.output)
        logger.info(f"已清理目标目录 '{args.output}'")

    if not os.path.exists(args.output):
        os.makedirs(args.output, exist_ok=True)
        logger.info(f"目标目录 '{args.output}' 已创建")

    logger.debug(f"sh 源文件路径 {args.source}")
    logger.debug(f"输出目录 {args.output}")

    return args


def _parse_boundary_value(line: bytes, boundary_name: bytes) -> int | None:
    """从 header 中解析 boundary 长度。"""
    if boundary_name not in line:
        return None

    try:
        return int(line.split()[-2])
    except (IndexError, ValueError) as exc:
        raise ValueError(f"无效的 {boundary_name.decode('utf-8')} 定义: {line!r}") from exc


def parse_sh(source_path: str, output_msg: bool = True) -> dict[str, Any]:
    """读取 sh 获取必要信息"""
    if output_msg:
        logger.info("解析 sh 文件信息")
    return_data = {
        "name": b"",
        "version": b"",
        "platform": b"",
        "bytes": b"",
        "lines": b"",
        "md5": b"",
        "old_mode": False,
        "script_data": b"",
        "conda_exec_data": b"",
        "pkgs_data": b"",
    }
    offset0, offset1, offset2 = 0, 0, 0
    with open(source_path, "rb") as fin:
        while True:
            line = fin.readline()
            if not line:
                raise ValueError(f"无效的 sh 文件，未找到 header 结束标记: {source_path}")

            for prefix, key in HEADER_PREFIXES.items():
                if line.startswith(prefix):
                    return_data[key] = line[len(prefix) :].strip()
                    if key in {"bytes", "lines"}:
                        return_data["old_mode"] = True
                    break

            boundary1 = _parse_boundary_value(line, b"boundary1=")
            if boundary1 is not None:
                offset1 = boundary1
            boundary2 = _parse_boundary_value(line, b"boundary2=")
            if boundary2 is not None:
                offset2 = boundary2

            if b"@@END_HEADER@@" == line.strip():
                offset0 = fin.tell()
                fin.seek(0)
                return_data["script_data"] = fin.read(offset0)
                break

        if return_data["old_mode"]:
            return_data["pkgs_data"] = fin.read()
        else:
            if offset1 <= 0 or offset2 <= 0:
                raise ValueError(
                    f"无效的 sh 文件，缺少 boundary 信息: {source_path}"
                )
            fin.seek(offset0)
            return_data["conda_exec_data"] = fin.read(offset1)
            return_data["pkgs_data"] = fin.read(offset2)

    if not return_data["pkgs_data"]:
        raise ValueError(f"未能从 sh 文件中提取 conda 包数据: {source_path}")

    if output_msg:
        logger.info("解析 sh 文件信息完毕")
    return return_data


class Extractor:
    """解压 conda constructor sh 包"""

    def __init__(self, args: argparse.Namespace) -> None:
        self.source_path = args.source
        self.output_dir = args.output
        self.keep_tar = args.keep_tar
        self.generate_repo = args.generate_repo

    def run(self) -> None:
        """执行具体的解压操作"""
        pkgs_dir = os.path.join(self.output_dir, "workdir", "pkgs")
        os.makedirs(pkgs_dir, exist_ok=True)

        sh_datas = parse_sh(self.source_path)
        old_mode = sh_datas["old_mode"]
        script_data = sh_datas["script_data"]
        conda_exec_data = sh_datas["conda_exec_data"]
        pkgs_data = sh_datas["pkgs_data"]

        self.extract_script(script_data)
        self.extract_conda_exec(old_mode, conda_exec_data)
        self.extract_payload(pkgs_data)
        self.extract_tar()

    def extract_script(self, script_data: bytes) -> None:
        """输出 sh 文件脚本内容"""
        logger.info("输出 sh 文件脚本内容")
        tpl_path = os.path.join(self.output_dir, "tpl.sh")
        with open(tpl_path, "wb") as fout:
            fout.write(script_data)
        logger.info("输出 sh 文件脚本内容完毕")

    def extract_conda_exec(self, old_mode: bool, conda_exec_data: bytes) -> None:
        """输出 sh 文件自带 conda 可执行程序"""
        if not old_mode:
            logger.info("输出 sh 文件自带 conda 可执行程序")
            conda_exec_path = os.path.join(self.output_dir, "_conda")
            with open(conda_exec_path, "wb") as fout:
                fout.write(conda_exec_data)
            logger.info("输出 sh 文件自带 conda 可执行程序完毕")

    def extract_payload(self, pkgs_data: bytes) -> None:
        """输出 sh 文件 conda 包"""
        logger.info("输出 sh 文件 conda 包")
        pkgs_path = os.path.join(self.output_dir, "pkgs.tar")
        with open(pkgs_path, "wb") as fout:
            fout.write(pkgs_data)
        logger.info("输出 sh 文件 conda 压缩包完毕")

    def extract_tar(self) -> None:
        """解压 sh 文件 conda 包"""
        logger.info("解压 sh 文件 conda 包")
        pkgs_path = os.path.join(self.output_dir, "pkgs.tar")
        pkgs_output_dir = os.path.join(self.output_dir, "workdir")
        conda_pkgs_dir = os.path.join(pkgs_output_dir, "pkgs")

        extract_large_tar(pkgs_path, pkgs_output_dir)

        if self.generate_repo:
            self.make_repo(conda_pkgs_dir, pkgs_output_dir)
        if not self.keep_tar:
            os.unlink(pkgs_path)
        logger.info("解压 sh 文件 conda 压缩包完毕")

    def make_repo(self, conda_pkgs_dir: str, pkgs_output_dir: str) -> None:
        """按照 conda channel 形式组织 conda 包"""
        preconda_dir = os.path.join(pkgs_output_dir, "preconda")
        urls_txt = os.path.join(conda_pkgs_dir, "urls.txt")
        should_cleanup_preconda = False

        if not os.path.exists(urls_txt):
            preconda_tar = os.path.join(pkgs_output_dir, "preconda.tar.bz2")
            if not os.path.exists(preconda_tar):
                raise FileNotFoundError(
                    f"未找到 urls.txt 或 preconda.tar.bz2: {pkgs_output_dir}"
                )

            os.makedirs(preconda_dir, exist_ok=True)
            # 使用 tarfile 模块以支持 filter 参数
            import tarfile
            with tarfile.open(preconda_tar, "r:bz2") as tar:
                if hasattr(tarfile, 'data_filter'):
                    # Python 3.12+ 支持 filter 参数
                    tar.extractall(preconda_dir, filter="data")
                else:
                    tar.extractall(preconda_dir)
            urls_txt = os.path.join(preconda_dir, "pkgs/urls.txt")
            should_cleanup_preconda = True

        if not os.path.exists(urls_txt):
            raise FileNotFoundError(f"未找到 urls.txt: {urls_txt}")

        subdir_pkgname_dict: dict[str, str] = {}
        with open(urls_txt, encoding="utf-8") as fin:
            for raw_line in fin:
                line = raw_line.strip()
                if not line:
                    continue

                try:
                    subdir, pkgname = line.rsplit("/", maxsplit=2)[-2:]
                except ValueError:
                    logger.warning(f"跳过无效的 urls 记录: {line}")
                    continue
                subdir_pkgname_dict[pkgname.strip()] = subdir.strip()

        if not subdir_pkgname_dict:
            raise ValueError(f"未从 urls.txt 中解析出任何 conda 包记录: {urls_txt}")

        for subdir in sorted(set(subdir_pkgname_dict.values())):
            os.makedirs(os.path.join(conda_pkgs_dir, subdir), exist_ok=True)

        conda_pkg_names = [
            name
            for name in os.listdir(conda_pkgs_dir)
            if name.endswith(".tar.bz2") or name.endswith(".conda")
        ]

        for conda_pkg in sorted(conda_pkg_names):
            subdir = subdir_pkgname_dict.get(conda_pkg)
            if not subdir:
                logger.warning(f"未找到包 {conda_pkg} 对应的 subdir，跳过整理")
                continue
            new_dir = os.path.join(conda_pkgs_dir, subdir)
            shutil.move(os.path.join(conda_pkgs_dir, conda_pkg), new_dir)

        if should_cleanup_preconda and os.path.exists(preconda_dir):
            shutil.rmtree(preconda_dir)


def main() -> None:
    """主函数"""
    args = parse_args()
    extractor = Extractor(args)
    extractor.run()


if __name__ == "__main__":
    main()
