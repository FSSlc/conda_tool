#!/usr/bin/env python

"""A tool to extract conda packages from a conda constructor sh package."""

import argparse
from typing import Tuple
import os
import shutil
import sys
from logging import getLogger

from .utils import SCRIPT_DIR, setup_logging

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
        "-k", "--keep_tar", action="store_true", required=False, help="是否删除压缩包"
    )
    parser.add_argument(
        "-c", "--clean", action="store_true", required=False, help="是否清理输出目录"
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

    def run(self) -> None:
        """执行具体的解压操作"""
        pkgs_dir = os.path.join(self.output_dir, "workdir/pkgs")
        os.makedirs(pkgs_dir, exist_ok=True)

        old_mode, script_data, conda_exec_data, pkgs_data = self.parse_sh()

        logger.info("输出 sh 文件脚本内容")
        tpl_path = os.path.join(self.output_dir, "tpl.sh")
        with open(tpl_path, "wb") as fout:
            fout.write(script_data)
        logger.info("输出 sh 文件脚本内容完毕")

        if not old_mode:
            logger.info("输出 sh 文件自带 conda 可执行程序")
            conda_exec_path = os.path.join(self.output_dir, "_conda")
            with open(conda_exec_path, "wb") as fout:
                fout.write(conda_exec_data)
            logger.info("输出 sh 文件自带 conda 可执行程序完毕")

        logger.info("输出 sh 文件 conda 包")
        pkgs_path = os.path.join(self.output_dir, "pkgs.tar")
        pkgs_output_dir = os.path.join(self.output_dir, "workdir")
        with open(pkgs_path, "wb") as fout:
            fout.write(pkgs_data)
        logger.info("输出 sh 文件 conda 压缩包完毕")

        logger.info("解压 sh 文件 conda 包完毕")
        shutil.unpack_archive(pkgs_path, pkgs_output_dir, "tar")
        if not self.keep_tar:
            os.unlink(pkgs_path)
        logger.info("解压 sh 文件 conda 压缩包完毕")

    def parse_sh(self) -> Tuple[bool, bytes, bytes, bytes]:
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


def main() -> None:
    """主函数"""
    args = parse_args()
    extractor = Extractor(args)
    extractor.run()


if __name__ == "__main__":
    main()
