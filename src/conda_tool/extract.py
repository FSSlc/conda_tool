#!/usr/bin/env python

"""A tool to extract conda packages from a conda constructor sh package."""

import argparse
import os
import shutil
import sys
from logging import getLogger

try:
    from .utils import SCRIPT_DIR, extract_large_tar, setup_logging
except ImportError:
    from conda_tool.utils import SCRIPT_DIR, extract_large_tar, setup_logging


setup_logging(120)
logger = getLogger(__name__)


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
    source_path = args.source
    if not os.path.isabs(source_path):
        source_path = os.path.abspath(os.path.join(SCRIPT_DIR, source_path))
    args.source = source_path

    output_dir = args.output
    if not os.path.isabs(output_dir):
        output_dir = os.path.abspath(os.path.join(SCRIPT_DIR, output_dir))
    args.output = output_dir

    # 检查源文件是否存在
    if not os.path.isfile(source_path):
        logger.fatal(f"错误：源文件 '{source_path}' 不存在")
        sys.exit(1)

    # 检查目标目录是否存在，如果不存在则创建
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        logger.info(f"目标目录 '{output_dir}' 已创建")
    if args.clean:
        shutil.rmtree(output_dir)
    logger.debug(f"sh 源文件路径 {source_path}")
    logger.debug(f"输出目录 {output_dir}")

    return args


class Extractor:
    """解压 conda constructor sh 包"""

    def __init__(self, args: argparse.Namespace) -> None:
        self.source_path = args.source
        self.output_dir = args.output
        self.keep_tar = args.keep_tar
        self.generate_repo = args.generate_repo

    def run(self) -> None:
        """执行具体的解压操作"""
        pkgs_dir = os.path.join(self.output_dir, "workdir/pkgs")
        os.makedirs(pkgs_dir, exist_ok=True)
        old_mode, script_data, conda_exec_data, pkgs_data = self.parse_sh()
        self.extract_script(script_data)
        self.extract_conda_exec(old_mode, conda_exec_data)
        self.extract_payload(pkgs_data)
        self.extract_tar()

    def parse_sh(self) -> tuple[bool, bytes, bytes, bytes]:
        """读取 sh 获取必要信息"""
        logger.info("解析 sh 文件信息")
        old_mode = False
        script_data, conda_exec_data, pkgs_data = b"", b"", b""
        offset0, offset1, offset2 = 0, 0, 0
        with open(self.source_path, "rb") as fin:
            while True:
                line = fin.readline()
                if b"LINES" in line:
                    old_mode = True
                if b"boundary1=" in line:
                    offset1 = int(line.split()[-2])
                if b"boundary2=" in line:
                    offset2 = int(line.split()[-2])
                if b"@@END_HEADER@@" == line.strip():
                    offset0 = fin.tell()
                    fin.seek(0)
                    script_data = fin.read(offset0)
                    break

            if old_mode:
                pkgs_data = fin.read()
            else:
                fin.seek(offset0)
                conda_exec_data = fin.read(offset1)
                pkgs_data = fin.read(offset2)
        logger.info("解析 sh 文件信息完毕")
        return old_mode, script_data, conda_exec_data, pkgs_data

    def extract_script(self, script_data):
        """输出 sh 文件脚本内容"""
        logger.info("输出 sh 文件脚本内容")
        tpl_path = os.path.join(self.output_dir, "tpl.sh")
        with open(tpl_path, "wb") as fout:
            fout.write(script_data)
        logger.info("输出 sh 文件脚本内容完毕")

    def extract_conda_exec(self, old_mode, conda_exec_data):
        """输出 sh 文件自带 conda 可执行程序"""
        if not old_mode:
            logger.info("输出 sh 文件自带 conda 可执行程序")
            conda_exec_path = os.path.join(self.output_dir, "_conda")
            with open(conda_exec_path, "wb") as fout:
                fout.write(conda_exec_data)
            logger.info("输出 sh 文件自带 conda 可执行程序完毕")

    def extract_payload(self, pkgs_data):
        """输出 sh 文件 conda 包"""
        logger.info("输出 sh 文件 conda 包")
        pkgs_path = os.path.join(self.output_dir, "pkgs.tar")
        with open(pkgs_path, "wb") as fout:
            fout.write(pkgs_data)
        logger.info("输出 sh 文件 conda 压缩包完毕")

    def extract_tar(self):
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

    def make_repo(self, conda_pkgs_dir, pkgs_output_dir):
        """按照 conda channel 形式组织 conda 包"""
        preconda_dir = os.path.join(pkgs_output_dir, "preconda")
        os.makedirs(preconda_dir, exist_ok=True)
        urls_txt = os.path.join(conda_pkgs_dir, "urls.txt")
        if not os.path.exists(urls_txt):
            shutil.unpack_archive(
                os.path.join(pkgs_output_dir, "preconda.tar.bz2"), preconda_dir, "bztar"
            )
            urls_txt = os.path.join(preconda_dir, "pkgs/urls.txt")
        subdir_pkgname_dict = {}
        with open(urls_txt, encoding="utf-8") as fout:
            urls = fout.readlines()
            for line in urls:
                subdir, pkgname = line.strip().split("/")[-2:]
                subdir_pkgname_dict[pkgname.strip()] = subdir.strip()
        subdirs = list(set(subdir_pkgname_dict.values()))
        for subdir in subdirs:
            os.makedirs(os.path.join(conda_pkgs_dir, subdir), exist_ok=True)
        conda_pkg_names = [
            name
            for name in os.listdir(conda_pkgs_dir)
            if name.endswith(".tar.bz2") or name.endswith(".conda")
        ]
        for conda_pkg in conda_pkg_names:
            if conda_pkg not in subdirs:
                new_dir = os.path.join(conda_pkgs_dir, subdir_pkgname_dict[conda_pkg])
                shutil.move(os.path.join(conda_pkgs_dir, conda_pkg), new_dir)
        if os.path.exists(preconda_dir):
            shutil.rmtree(preconda_dir)


def main() -> None:
    """主函数"""
    args = parse_args()
    extractor = Extractor(args)
    extractor.run()


if __name__ == "__main__":
    main()
