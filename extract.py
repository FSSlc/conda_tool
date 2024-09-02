#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import logging
import os
import shutil

SCRIPT_DIR = os.path.dirname(__file__)


def setup_logging():
    log_path = os.path.join(SCRIPT_DIR, "extract.log")
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.FileHandler(log_path, mode="w"), logging.StreamHandler()],
    )


def parse_args():
    logging.info("开始解析参数")
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
        source_path = os.path.abspath(os.path.join(SCRIPT_DIR, output_dir))
    args.output = output_dir

    # 检查源文件是否存在
    if not os.path.isfile(source_path):
        logging.error(f"错误：源文件 '{source_path}' 不存在")
        return

    # 检查目标目录是否存在，如果不存在则创建
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        logging.info(f"目标目录 '{output_dir}' 已创建")
    if args.clean:
        shutil.rmtree(output_dir)
    logging.debug(f"sh 源文件路径 {source_path}")
    logging.debug(f"输出目录 {output_dir}")

    logging.info("解析参数完毕")
    return args


def extract(args):
    source_path = args.source
    output_dir = args.output

    pkgs_dir = os.path.join(output_dir, "workdir/pkgs")
    os.makedirs(pkgs_dir, exist_ok=True)

    logging.info("解析 sh 文件信息")
    old_mode = False
    script_data, conda_exec_data, pkgs_data = None, None, None
    offset0, offset1, offset2 = 0, 0, 0
    with open(source_path, "rb") as fin:
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
    logging.info("解析 sh 文件信息完毕")

    logging.info("输出 sh 文件脚本内容")
    tpl_path = os.path.join(output_dir, "tpl.sh")
    with open(tpl_path, "wb") as fout:
        fout.write(script_data)
    logging.info("输出 sh 文件脚本内容完毕")

    if not old_mode:
        logging.info("输出 sh 文件自带 conda 可执行程序")
        conda_exec_path = os.path.join(output_dir, "_conda")
        with open(conda_exec_path, "wb") as fout:
            fout.write(conda_exec_data)
        logging.info("输出 sh 文件自带 conda 可执行程序完毕")

    logging.info("输出 sh 文件 conda 包")
    pkgs_path = os.path.join(output_dir, "pkgs.tar")
    pkgs_output_dir = os.path.join(output_dir, "workdir")
    with open(pkgs_path, "wb") as fout:
        fout.write(pkgs_data)
    logging.info("输出 sh 文件 conda 压缩包完毕")

    logging.info("解压 sh 文件 conda 包完毕")
    shutil.unpack_archive(pkgs_path, pkgs_output_dir, "tar")
    if not args.keep_tar:
        os.unlink(pkgs_path)
    logging.info("解压 sh 文件 conda 压缩包完毕")


def main():
    setup_logging()
    args = parse_args()
    extract(args)


if __name__ == "__main__":
    main()
