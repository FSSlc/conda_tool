#!/usr/bin/env python

import argparse
import os
import shutil
from logging import getLogger

from .utils import SCRIPT_DIR, setup_logging

setup_logging(120)
logger = getLogger(__name__)


def parse_args():
    logger.info("开始解析参数")
    # 创建 ArgumentParser 对象
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
        exit(1)

    # 检查目标目录是否存在，如果不存在则创建
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        logger.info(f"目标目录 '{output_dir}' 已创建")
    if args.clean:
        shutil.rmtree(output_dir)
    logger.debug(f"sh 源文件路径 {source_path}")
    logger.debug(f"输出目录 {output_dir}")

    logger.info("解析参数完毕")
    return args


class Extractor:
    def __init__(self, args):
        self.source_path = args.source
        self.output_dir = args.output
        self.keep_tar = args.keep_tar

    def run(self):
        pkgs_dir = os.path.join(self.output_dir, "workdir/pkgs")
        os.makedirs(pkgs_dir, exist_ok=True)

        logger.info("解析 sh 文件信息")
        old_mode = False
        script_data, conda_exec_data, pkgs_data = None, None, None
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


def main():
    args = parse_args()
    extractor = Extractor(args)
    extractor.run()


if __name__ == "__main__":
    main()
