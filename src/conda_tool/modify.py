#!/usr/bin/env python

"""Mofdify a conda package according to a rule file."""

import argparse
import concurrent.futures
import json
import os
import queue
import shutil
import subprocess
import sys
import tarfile
import threading
from collections import defaultdict
from logging import getLogger
from typing import Any
from zipfile import ZIP_STORED, ZipFile

logger = getLogger(__name__)

try:
    import pathspec
except ImportError:
    logger.error("Error: 'pathspec' package is required. Please install it.")
    sys.exit(1)

try:
    from .utils import (
        NullWriter,
        abs_path,
        anonymize_tarinfo,
        compressor,
        extract_archive,
        get_filelist,
        hash_files,
        is_elf_file,
        setup_logging,
        tmp_chdir,
    )
except ImportError:
    from conda_tool.utils import (
        NullWriter,
        abs_path,
        anonymize_tarinfo,
        compressor,
        extract_archive,
        get_filelist,
        hash_files,
        is_elf_file,
        setup_logging,
        tmp_chdir,
    )

setup_logging(120)

CONDA_PACKAGE_FORMAT_VERSION = 2
MAX_WORKERS = min(32, (os.cpu_count() or 1) + 4)
CHUNK_SIZE = 8192 * 8
FILE_QUEUE_SIZE = 1000

EXAMPLE_DATA = {
    "conda": {
        "add": {"extract.py": "bin", "../src/conda_tool/*": "bin"},
        "mv": {"bin/conda": "bin/_conda"},
        "delete": ["etc/fish", "xonsh"],
    }
}


def parse_args() -> argparse.Namespace:
    """解析参数"""
    # 创建 ArgumentParser 对象
    parser = argparse.ArgumentParser(description="conda 包修改工具")

    # 添加参数
    parser.add_argument(
        "-oc", "--output_example_config", action="store_true", help="输出示例配置文件"
    )
    parser.add_argument("-c", "--config_path", help="配置文件路径")
    parser.add_argument("-s", "--pkg_path", help="待修改的 conda 包路径或目录")
    parser.add_argument(
        "-k",
        "--keep_origin",
        action="store_true",
        required=False,
        help="是否保留原有 conda 包",
    )

    # 解析参数
    args = parser.parse_args()
    if args.output_example_config:
        with open("config.json", "w", encoding="utf-8") as fout:
            json.dump(EXAMPLE_DATA, fout, indent=2, ensure_ascii=False)
        sys.exit(0)
    if not (args.config_path and args.pkg_path):
        logger.fatal("错误，-c 和 -s 参数必须同时提供")
        sys.exit(1)

    return args


class FileProcessor:
    """Handles concurrent file operations with memory efficiency"""

    def __init__(self):
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS)
        self.lock = threading.Lock()
        self.file_queue = queue.Queue(maxsize=FILE_QUEUE_SIZE)

    def process_files_concurrently(
        self, file_pairs: list[tuple[str, str]], operation: str
    ):
        """Process files concurrently with the specified operation"""
        futures = []
        for src, dst in file_pairs:
            futures.append(
                self.executor.submit(self._process_file, src, dst, operation)
            )

        # Wait for all operations to complete
        for future in concurrent.futures.as_completed(futures):
            try:
                future.result()
            except Exception as e:
                logger.error(f"File operation failed: {str(e)}")

    def _process_file(self, src: str, dst: str, operation: str):
        """Process a single file with proper error handling"""
        try:
            if operation == "copy":
                self._copy_file(src, dst)
            elif operation == "move":
                self._move_file(src, dst)
            elif operation == "delete":
                self._delete_file(src)
            elif operation == "strip":
                self._strip_file(src)
        except Exception as e:
            logger.error(f"Failed to {operation} {src}: {str(e)}")

    def _copy_file(self, src: str, dst: str):
        """Memory-efficient file copy"""
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        with open(src, "rb") as f_src, open(dst, "wb") as f_dst:
            while True:
                chunk = f_src.read(CHUNK_SIZE)
                if not chunk:
                    break
                f_dst.write(chunk)

    def _move_file(self, src: str, dst: str):
        """Move file with fallback to copy+delete"""
        try:
            shutil.move(src, dst)
        except OSError:
            # Cross-device move, fallback to copy+delete
            self._copy_file(src, dst)
            os.unlink(src)

    def _delete_file(self, path: str):
        """Delete file and empty parent directories"""
        if os.path.exists(path):
            os.unlink(path)
            # Clean up empty directories
            parent = os.path.dirname(path)
            while parent and len(os.listdir(parent)) == 0:
                os.rmdir(parent)
                parent = os.path.dirname(parent)

    def _strip_file(self, path: str):
        """Strip file"""
        is_elf = is_elf_file(path)
        if not is_elf:
            logger.warning("not a ELF file, ignore this file.")
        try:
            subprocess.run(
                ["strip", "--strip-debug", path],
                check=True,
                capture_output=True,
            )
        except subprocess.CalledProcessError as e:
            logger.error(f"Strip failed for {path}: {e.stderr.decode()}")

    def __del__(self):
        self.executor.shutdown(wait=True)


class Modify:
    """修改类的具体实现"""

    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.pkg_path, self.config_path = "", ""
        self.config: dict[str, Any] = {}
        self.file_processor = FileProcessor()

    def run(self) -> None:
        """具体实现逻辑"""
        # 1. 检查参数
        self.check_args()
        # 2. 读取配置
        logger.info("开始读取配置文件")
        with open(self.config_path, encoding="utf-8") as fin:
            self.config = json.load(fin)
        # 3. 获取配置信息并检测配置
        pkg_infos = self.get_pkg_infos()
        logger.info("读取配置文件完毕")

        logger.info("开始检查配置文件")
        filter_pkgs_infos = self.check_config(pkg_infos)
        logger.info("检查配置文件完毕")

        # 4. 修改文件并重新打包
        for pkg_info in filter_pkgs_infos:
            self.handle_one_package(pkg_info)
        logger.info("修改完毕")

    def check_args(self) -> None:
        """检验输入参数"""
        # 获取参数值
        logger.info("开始检查传入参数")
        config_path = abs_path(self.args.config_path)
        # 检查源文件是否存在
        if not os.path.isfile(config_path):
            logger.error(f"错误：配置文件 '{config_path}' 不存在")
            logger.info("检查传入参数完毕")
            sys.exit(1)
        self.config_path = config_path
        logger.debug(f"配置文件路径 {config_path}")

        pkg_path = abs_path(self.args.pkg_path)
        if not os.path.exists(pkg_path):
            logger.error(f"错误：conda 包路径或目录 {pkg_path}' 不存在")
            logger.info("检查传入参数完毕")
            sys.exit(1)
        self.pkg_path = pkg_path
        logger.debug(f"待处理的 conda 包或目录为 {pkg_path}")
        logger.info("检查传入参数完毕")

    def get_pkg_infos(self) -> list[dict[str, Any]]:
        """获取包的信息"""
        if os.path.isfile(self.pkg_path):
            pkg_paths = [self.pkg_path]
        else:
            pkg_paths = get_filelist(self.pkg_path, with_prefix=True)
            pkg_paths = [
                os.path.join(self.pkg_path, path)
                for path in pkg_paths
                if path.endswith(".tar.bz2") or path.endswith(".conda")
            ]

        pkg_infos = list(map(self.get_pkg_info, pkg_paths))
        return pkg_infos

    @staticmethod
    def get_pkg_info(pkg_path: str) -> dict[str, Any]:
        """获取 conda 包的元信息"""
        dirname = os.path.dirname(pkg_path)
        basename = os.path.basename(pkg_path)
        basename_no_suffix = basename.replace(".tar.bz2", "").replace(".conda", "")
        extract_path = os.path.join(dirname, basename_no_suffix)
        comps = basename_no_suffix.split("-")
        other, version, build_str = comps[:-2], comps[-2], comps[-1]
        name = "-".join(other)
        pkg_fmt = "tar.bz2" if ".tar.bz2" in pkg_path else "conda"
        binary_path = (
            os.path.join(extract_path, "pkg") if ".conda" in pkg_path else extract_path
        )
        info_path = os.path.join(extract_path, "info")
        real_info_path = (
            os.path.join(info_path, "info") if ".conda" in pkg_path else info_path
        )
        return {
            "path": pkg_path,
            "name": name,
            "name_no_suffix": basename_no_suffix,
            "version": version,
            "build_str": build_str,
            "format": pkg_fmt,
            "extract_path": extract_path,
            "binary_path": binary_path,
            "info_path": info_path,
            "real_info_path": real_info_path,
        }

    def check_config(self, pkgs_infos: list[Any]) -> list[Any]:
        """检查配置信息是否有误"""
        filter_pkgs_infos, errors = [], defaultdict(list)
        for pkg_name, rule in self.config.items():
            # 1. pkg_name check
            pkg_info = list(filter(lambda x: x.get("name") == pkg_name, pkgs_infos))
            if len(pkg_info) == 0:
                msg = f"Error, no package named '{pkg_name}' found in '{self.pkg_path}'"
                errors[pkg_name].append(msg)
            elif len(pkg_info) == 1:
                pkg_info = pkg_info[0]
                self.extract_pkg(pkg_info)

                # 2. rule check and transfer rule paths
                for rule_type in ["add", "mv"]:
                    if rule_type in rule:
                        new_expand_rules, errors = self.expand_rule(
                            rule, rule_type, errors, pkg_name, pkg_info
                        )
                        rule[rule_type] = new_expand_rules
                for rule_type in ["delete", "strip"]:
                    if rule_type in rule:
                        new_expand_files = self.expand_pattern_rule(
                            rule, rule_type, pkg_info
                        )
                        rule[rule_type] = new_expand_files
                pkg_info.update({"rule": rule})
                filter_pkgs_infos.append(pkg_info)
            else:
                msg = f"Error, more than one package named '{pkg_name}' found in '{self.pkg_path}', not handle them."
                errors[pkg_name].append(msg)

        if len(errors) > 0:
            for name, error in errors.items():
                logger.error(f"for package name '{name}', rule have following errors:")
                error_msgs = ["  " + err for err in error]
                for error_msg in error_msgs:
                    logger.error(error_msg)
            sys.exit(2)
        return filter_pkgs_infos

    def extract_pkg(self, pkg_info: Any) -> None:
        """解压 conda 包"""
        pkg_path = pkg_info["path"]
        extract_format = pkg_info["format"]
        extract_path = pkg_info["extract_path"]
        name_no_suffix = pkg_info["name_no_suffix"]
        if os.path.exists(extract_path):
            shutil.rmtree(extract_path)
        extract_archive(pkg_path, extract_path, extract_format)
        if extract_format == "conda":
            binary_path = pkg_info["binary_path"]
            info_path = pkg_info["info_path"]
            extract_archive(
                os.path.join(extract_path, f"pkg-{name_no_suffix}.tar.zst"),
                binary_path,
                "zst",
            )
            extract_archive(
                os.path.join(extract_path, f"info-{name_no_suffix}.tar.zst"),
                info_path,
                "zst",
            )

    def expand_rule(
        self,
        rule: dict[str, Any],
        rule_type: str,
        errors: defaultdict[Any, list[str]],
        pkg_name: str,
        pkg_info: dict[str, Any],
    ) -> tuple[dict[str, Any], defaultdict[Any, list[str]]]:
        """根据 rule_type 获取具体展开规则"""
        expand_rules = {}
        for k, v in rule[rule_type].items():
            src_path = k
            if rule_type == "add":
                src_dir = os.path.dirname(self.config_path)
            else:
                src_dir = pkg_info["binary_path"]
            if not os.path.isabs(k):
                src_path = os.path.abspath(os.path.normpath(os.path.join(src_dir, k)))
            if os.path.isfile(src_path):
                if not os.path.exists(src_path):
                    msg = f"Error, rule {rule_type} '{k}:{v}', {k} is not a valid exist path"
                    errors[pkg_name].append(msg)
                else:
                    if v.endswith("/"):
                        new_path = os.path.join(
                            pkg_info["binary_path"], v, os.path.basename(src_path)
                        )
                    else:
                        new_path = os.path.join(pkg_info["binary_path"], v)
                    expand_rules[src_path] = new_path
            elif os.path.isdir(src_path):
                if not os.path.exists(src_path):
                    msg = f"Error, rule {rule_type} '{k}:{v}', {k} is not a valid exist path"
                    errors[pkg_name].append(msg)
                else:
                    if not v.endswith("/"):
                        msg = (
                            f"Error, rule {rule_type} '{k}:{v}', {k} is a dir"
                            " then {v} must endswith '/'"
                        )
                        errors[pkg_name].append(msg)
                    else:
                        # 如果是目录，则将目录放到目标目录下
                        new_dir = os.path.join(pkg_info["binary_path"], v)
                        file_lists = get_filelist(src_path, with_prefix=True)
                        for file in file_lists:
                            expand_rules[file] = os.path.join(
                                new_dir,
                                src_path.strip("/").split("/")[-1],
                                os.path.relpath(file, start=src_path),
                            )
            else:
                # 通配符
                src_path_dirname = os.path.dirname(src_path)
                if not os.path.exists(src_path_dirname):
                    msg = f"Error, rule {rule_type} '{k}:{v}', {k} is not a valid exist path"
                    errors[pkg_name].append(msg)
                else:
                    file_lists = self.get_spec_match_files(
                        os.path.dirname(src_path),
                        pathspec.PathSpec.from_lines(
                            pathspec.patterns.gitwildmatch.GitWildMatchPattern,
                            [src_path],
                        ),
                    )
                    if len(file_lists) > 0:
                        if not v.endswith("/"):
                            msg = f"Error, rule {rule_type} '{k}:{v}', {v} must endswith '/'"
                            errors[pkg_name].append(msg)
                        else:
                            new_dir = os.path.join(pkg_info["binary_path"], v)
                            for file in file_lists:
                                expand_rules[file] = os.path.join(
                                    new_dir,
                                    os.path.relpath(file, start=src_path_dirname),
                                )
        return expand_rules, errors

    def expand_pattern_rule(
        self, rule: dict[str, Any], rule_type: str, pkg_info: dict[str, Any]
    ) -> list[str]:
        """转换匹配规则，用于 delete strip 规则"""
        rules = rule[rule_type]
        spec = pathspec.PathSpec.from_lines(
            pathspec.patterns.gitwildmatch.GitWildMatchPattern, rules
        )
        files = self.get_spec_match_files(
            pkg_info["binary_path"], spec, use_relative=True
        )
        return files

    @staticmethod
    def get_spec_match_files(
        basedir: str, spec: pathspec.PathSpec, use_relative: bool = False
    ) -> list[str]:
        """获取给定匹配规则的文件列表"""
        match_files = []
        for root, _, files in os.walk(basedir):
            for file in files:
                file_path = os.path.join(root, file)
                check_path = file_path
                if use_relative:
                    check_path = os.path.relpath(file_path, start=basedir)
                if spec.match_file(check_path):
                    match_files.append(file_path)
        return match_files

    def handle_one_package(self, pkg_info: dict[str, Any]) -> None:
        """处理一个 conda 包"""
        logger.info(f"开始处理 {pkg_info['path']}")
        rule = pkg_info["rule"]
        if "add" in rule:
            logger.info("  开始处理 add 规则")
            self.handle_add_rule(pkg_info)
            logger.info("  处理 add 规则完毕")
        if "mv" in rule:
            logger.info("  开始处理 mv 规则")
            self.handle_mv_rule(pkg_info)
            logger.info("  处理 mv 规则完毕")
        if "delete" in rule:
            logger.info("  开始处理 delete 规则")
            self.handle_delete_rule(pkg_info)
            logger.info("  处理 delete 规则完毕")
        if "strip" in rule:
            logger.info("  开始处理 strip 规则")
            self.handle_strip_rule(pkg_info)
            logger.info("  处理 strip 规则完毕")

        # 最后根据 paths.json 内容修改 files, has_prefix 文件
        _, paths_json_data = self.get_paths_json_data(pkg_info)
        files_list, has_prefix_list = [], []
        for info in paths_json_data["paths"]:
            files_list.append(info.get("_path"))
            if info.get("prefix_placeholder") is not None:
                has_prefix_list.append(
                    f"{info.get('prefix_placeholder')} {info.get('file_mode')} {info.get('_path')}"
                )

        files_path = os.path.join(pkg_info["real_info_path"], "files")
        with open(files_path, "w", encoding="utf-8") as fout:
            fout.write("\n".join(files_list))

        has_prefix_path = os.path.join(pkg_info["real_info_path"], "has_prefix")
        with open(has_prefix_path, "w", encoding="utf-8") as fout:
            fout.write("\n".join(has_prefix_list))

        # 重新打包
        extract_dir = pkg_info["extract_path"]
        dst_file = pkg_info["path"]
        logger.info(f"  重新打包 {dst_file} 开始")
        if self.args.keep_origin:
            dst_bk_file = dst_file + ".bk"
            shutil.move(dst_file, dst_bk_file)
        else:
            if os.path.exists(dst_file):
                os.unlink(dst_file)

        if pkg_info["format"] == "conda":
            self.pack_conda(dst_file, pkg_info)
        if pkg_info["format"] == "tar.bz2":
            self.pack_bz2(dst_file, pkg_info)
        shutil.rmtree(extract_dir)
        logger.info(f"处理 {pkg_info['path']} 完毕")

    def pack_conda(self, dst_file, pkg_info):
        """重新打包为 .conda 格式的包"""
        with ZipFile(dst_file, "w", compression=ZIP_STORED) as conda_file:
            conda_file.writestr(
                "metadata.json",
                json.dumps({"conda_pkg_format_version": CONDA_PACKAGE_FORMAT_VERSION}),
            )
            pkg_files = get_filelist(pkg_info["binary_path"], with_prefix=True)
            info_files = get_filelist(pkg_info["real_info_path"], with_prefix=True)
            components_files = (
                (f"pkg-{pkg_info['name_no_suffix']}.tar.zst", pkg_files),
                (
                    f"info-{pkg_info['name_no_suffix']}.tar.zst",
                    info_files,
                ),
            )
            # put the info last, for parity with updated transmute.
            for component, files in components_files:
                # If size is known, the decompressor may be able to allocate less memory.
                # The compressor will error if size is not correct.
                with tarfile.TarFile(fileobj=NullWriter(), mode="w") as sizer:  # type: ignore
                    for file in files:
                        arcname = ""
                        if "pkg" in component:
                            arcname = os.path.relpath(file, pkg_info["binary_path"])
                        if "info" in component:
                            arcname = os.path.relpath(file, pkg_info["info_path"])
                        sizer.add(file, filter=anonymize_tarinfo, arcname=arcname)

                with conda_file.open(
                    component, "w", force_zip64=True
                ) as component_file:
                    # only one stream_writer() per compressor() must be in use at a time
                    with (
                        compressor().stream_writer(
                            component_file,
                            size=sizer.fileobj.size,  # type: ignore
                            closefd=False,
                        ) as component_stream,
                        tarfile.TarFile(
                            fileobj=component_stream, mode="w"
                        ) as component_tar,
                    ):
                        for file in files:
                            arcname = ""
                            if "pkg" in component:
                                arcname = os.path.relpath(file, pkg_info["binary_path"])
                            if "info" in component:
                                arcname = os.path.relpath(file, pkg_info["info_path"])
                            component_tar.add(
                                file, filter=anonymize_tarinfo, arcname=arcname
                            )

    def pack_bz2(self, dst_file, pkg_info):
        """重新打包为 .tar.bz2 格式的包"""
        prefix = pkg_info["binary_path"]
        with tmp_chdir(prefix):
            files = get_filelist(prefix)
            with tarfile.open(dst_file, "w:bz2", encoding="utf-8") as t:
                for f in files:
                    t.add(f, filter=anonymize_tarinfo)

    def get_paths_json_data(self, pkg_info: dict[str, Any]) -> tuple[str, Any]:
        """从 paths.json 获取所有路径信息"""
        paths_json_path = os.path.join(pkg_info["real_info_path"], "paths.json")
        with open(paths_json_path, encoding="utf-8") as fin:
            paths_json_data = json.load(fin)
            return paths_json_path, paths_json_data

    def handle_add_rule(self, pkg_info: dict[str, Any]) -> None:
        """执行复制"""
        add_rule = pkg_info["rule"]["add"]
        new_data, file_pairs = [], []

        for old_path, new_path in add_rule.items():
            if not os.path.exists(old_path):
                logger.warning(f"Source file not found: {old_path}")
                continue
            if new_path.endswith("/"):
                os.makedirs(new_path, exist_ok=True)
                new_file_path = os.path.join(new_path, os.path.basename(old_path))
                new_file_rel_path = os.path.relpath(
                    new_file_path, pkg_info["binary_path"]
                )
            else:
                os.makedirs(os.path.dirname(new_path), exist_ok=True)
                new_file_path = new_path
                new_file_rel_path = os.path.relpath(new_path, pkg_info["binary_path"])

            file_pairs.append((old_path, new_file_path))
            new_data.append(
                {
                    "_path": new_file_rel_path,
                    "path_type": "hardlink",
                    "sha256": "",  # Will be updated after copy
                    "size_in_bytes": 0,
                }
            )

        # Process files concurrently
        self.file_processor.process_files_concurrently(file_pairs, "copy")

        # Update file metadata
        for i, (_, new_file_path) in enumerate(file_pairs):
            try:
                new_data[i]["sha256"] = hash_files([new_file_path])
                new_data[i]["size_in_bytes"] = os.path.getsize(new_file_path)
            except Exception as e:
                logger.error(f"Failed to update metadata for {new_file_path}: {str(e)}")
                continue

        # 修改 paths.json 文件
        paths_json_path, paths_json_data = self.get_paths_json_data(pkg_info)
        paths_json_data["paths"].extend(new_data)
        paths_json_data["paths"].sort(key=lambda x: x.get("_path"))
        with open(paths_json_path, "w", encoding="utf-8") as fout:
            fout.write(json.dumps(paths_json_data, indent=2, ensure_ascii=False))

    def handle_mv_rule(self, pkg_info: dict[str, Any]) -> None:
        """执行移动或改名"""
        mv_rule = pkg_info["rule"]["mv"]
        file_pairs = []
        path_updates = []

        for old_path, new_path in mv_rule.items():
            if new_path.endswith("/"):
                os.makedirs(new_path, exist_ok=True)
                new_file_path = os.path.join(new_path, os.path.basename(old_path))
                new_file_rel_path = os.path.relpath(
                    new_file_path, pkg_info["binary_path"]
                )
            else:
                os.makedirs(os.path.dirname(new_path), exist_ok=True)
                new_file_path = new_path
                new_file_rel_path = os.path.relpath(new_path, pkg_info["binary_path"])

            file_pairs.append((old_path, new_file_path))
            old_rel_path = os.path.relpath(old_path, pkg_info["binary_path"])
            path_updates.append((old_rel_path, new_file_rel_path))

        # Process files concurrently
        self.file_processor.process_files_concurrently(file_pairs, "move")

        # Update paths.json
        paths_json_path, paths_json_data = self.get_paths_json_data(pkg_info)
        for old_rel_path, new_rel_path in path_updates:
            for item in paths_json_data["paths"]:
                if item.get("_path") == old_rel_path:
                    item["_path"] = new_rel_path
                    break

            paths_json_data["paths"].sort(key=lambda x: x.get("_path"))
            with open(paths_json_path, "w", encoding="utf-8") as fout:
                fout.write(json.dumps(paths_json_data, indent=2, ensure_ascii=False))

    def handle_delete_rule(self, pkg_info: dict[str, Any]) -> None:
        """执行删除操作"""
        delete_rule = pkg_info["rule"]["delete"]

        files_to_delete = [
            os.path.join(pkg_info["binary_path"], delete_path)
            for delete_path in delete_rule
        ]

        # Process deletions concurrently
        self.file_processor.process_files_concurrently(
            [(f, "") for f in files_to_delete], "delete"
        )
        # Update paths.json
        delete_rel_paths = [
            os.path.relpath(delete_path, pkg_info["binary_path"])
            for delete_path in delete_rule
        ]

        paths_json_path, paths_json_data = self.get_paths_json_data(pkg_info)
        paths_json_data["paths"] = [
            item
            for item in paths_json_data["paths"]
            if item.get("_path") not in delete_rel_paths
        ]
        paths_json_data["paths"].sort(key=lambda x: x.get("_path"))
        with open(paths_json_path, "w", encoding="utf-8") as fout:
            json.dump(paths_json_data, fout, indent=2, ensure_ascii=False)

    def handle_strip_rule(self, pkg_info: dict[str, Any]) -> None:
        """执行压缩操作"""
        strip_rule = pkg_info["rule"]["strip"]
        for strip_path in strip_rule:
            strip_abs_path = os.path.join(pkg_info["binary_path"], strip_path)
            is_elf = is_elf_file(strip_abs_path)
            if not is_elf:
                logger.warning("not a ELF file, ignore this file.")
                continue
            try:
                subprocess.run(
                    ["strip", "--strip-debug", strip_abs_path],
                    check=True,
                    capture_output=True,
                )
            except subprocess.CalledProcessError as e:
                logger.error(f"Strip failed for {strip_abs_path}: {e.stderr.decode()}")
            # 修改 paths.json 文件
            strip_rel_path = os.path.relpath(strip_path, pkg_info["binary_path"])
            paths_json_path, paths_json_data = self.get_paths_json_data(pkg_info)
            new_paths_info = list(
                filter(
                    lambda x: x.get("_path") == strip_rel_path,
                    paths_json_data["paths"],
                )
            )[0]
            # 大小和 sha256 需要更新
            new_paths_info.update(
                {
                    "sha256": hash_files([strip_abs_path]),
                    "size_in_bytes": os.path.getsize(strip_abs_path),
                }
            )
            paths_json_data["paths"] = new_paths_info
            paths_json_data["paths"].sort(key=lambda x: x.get("_path"))
            with open(paths_json_path, "w", encoding="utf-8") as fout:
                fout.write(json.dumps(paths_json_data, indent=2, ensure_ascii=False))


def main() -> None:
    """主逻辑实现"""
    args = parse_args()
    instance = Modify(args)
    instance.run()


if __name__ == "__main__":
    main()
