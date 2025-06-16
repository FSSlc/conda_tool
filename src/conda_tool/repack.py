#!/usr/bin/env python

"""A tool to modify and repack conda constructor sh packages."""

import argparse
import os
import sys
import tarfile
import tempfile
from logging import getLogger

try:
    from .utils import abs_path, hash_files, setup_logging
except ImportError:
    from conda_tool.utils import abs_path, hash_files, setup_logging

setup_logging(120)
logger = getLogger(__name__)


def parse_args() -> argparse.Namespace:
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="Conda sh 包重打包工具")
    parser.add_argument("-s", "--source", required=True, help="sh 源文件路径")
    parser.add_argument("-c", "--config", required=True, help="修改规则文件路径")
    parser.add_argument("-o", "--output", required=False, help="保存修改后的 sh 包路径")
    args = parser.parse_args()

    args.source = abs_path(args.source)
    args.config = abs_path(args.config)
    args.output = abs_path(args.output)

    if not os.path.isfile(args.source):
        logger.error(f"Source sh package not found: {args.source}")
        sys.exit(1)
    if not os.path.isfile(args.config):
        logger.error(f"Config file not found: {args.config}")
        sys.exit(1)

    if not args.output:
        args.output = os.path.join(
            os.path.dirname(args.source) + "mod-" + os.path.basename(args.source)
        )

    if os.path.exists(args.output):
        logger.error(f"Output file already exists: {args.output}")
        sys.exit(1)

    return args


def extract_sh_package(source_sh: str, temp_dir: str) -> None:
    """Extract the sh package using extract.py"""
    import sys as sys_module

    from extract import main as extract_main

    original_argv = sys_module.argv
    try:
        sys_module.argv = ["extract.py", "-s", source_sh, "-o", temp_dir, "--clean"]
        extract_main()
    finally:
        sys_module.argv = original_argv


def modify_package_content(work_dir: str, config_path: str) -> None:
    """Modify the package content using modify.py"""
    import sys as sys_module

    from modify import main as modify_main

    original_argv = sys_module.argv
    try:
        sys_module.argv = [
            "modify.py",
            "-c",
            config_path,
            "-s",
            os.path.join(work_dir, "workdir", "pkgs"),
        ]
        modify_main()
    finally:
        sys_module.argv = original_argv


def repack_sh_package(original_sh: str, work_dir: str, output_path: str) -> None:
    """Repack the modified package into a new sh file"""
    from extract import parse_sh

    sh_datas = parse_sh(original_sh, False)
    old_mode = sh_datas["old_mode"]
    script_data = sh_datas["script_data"]
    conda_exec_data = sh_datas["conda_exec_data"]

    modified_tar = os.path.join(work_dir, "pkgs.tar")
    if os.path.exists(modified_tar):
        os.unlink(modified_tar)
    workdir_path = os.path.join(work_dir, "workdir")
    with tarfile.open(modified_tar, "w") as tar:
        for item in os.listdir(workdir_path):
            item_path = os.path.join(workdir_path, item)
            tar.add(item_path, arcname=item)

    with open(modified_tar, "rb") as f:
        pkgs_data = f.read()
    tmp_output_path = output_path + ".bak"
    with open(tmp_output_path, "wb") as f:
        f.write(script_data)
        if not old_mode:
            f.write(conda_exec_data)
        f.write(pkgs_data)
    os.chmod(tmp_output_path, 0o755)

    pkgs_tar_md5 = hash_files([modified_tar])
    sh_size_str = str(os.path.getsize(tmp_output_path)).rjust(12)

    sh_datas = parse_sh(tmp_output_path, False)
    script_data: bytes = sh_datas["script_data"]
    old_md5: bytes = sh_datas["md5"]
    old_bytes: bytes = sh_datas["bytes"]
    script_data = script_data.replace(old_md5, pkgs_tar_md5.encode("utf-8")).replace(
        old_bytes, sh_size_str.encode("utf-8")
    )

    with open(output_path, "wb") as f:
        f.write(script_data)
        if not old_mode:
            f.write(conda_exec_data)
        f.write(pkgs_data)
    os.chmod(output_path, 0o755)
    os.unlink(tmp_output_path)


def main() -> None:
    """Main function"""
    args = parse_args()

    # Create a temporary directory
    with tempfile.TemporaryDirectory(prefix="conda_repack_") as temp_dir:
        try:
            logger.info("Extracting source sh package...")
            extract_sh_package(args.source, temp_dir)

            logger.info("Modifying package content...")
            modify_package_content(temp_dir, args.config)

            logger.info("Repacking modified package...")
            repack_sh_package(args.source, temp_dir, args.output)

            logger.info(f"Successfully created modified package at: {args.output}")

        except Exception as e:
            logger.error(f"Error during repacking: {str(e)}")
            sys.exit(1)


if __name__ == "__main__":
    main()
