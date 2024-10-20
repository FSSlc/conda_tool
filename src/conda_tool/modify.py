#!/usr/bin/env python

import argparse
import json
import os
import shutil
import sys
import tarfile
from collections import defaultdict
from logging import getLogger
from zipfile import ZIP_STORED, ZipFile

import pathspec

from .utils import (
    SCRIPT_DIR,
    NullWriter,
    anonymize_tarinfo,
    compressor,
    extract_archive,
    get_filelist,
    hash_files,
    setup_logging,
    tmp_chdir,
)

setup_logging(120)
logger = getLogger(__name__)

CONDA_PACKAGE_FORMAT_VERSION = 2

EXAMPLE_DATA = {
    "conda": {
        "add": {"extract.py": "bin"},
        "mv": {"bin/conda": "bin/_conda"},
        "delete": ["etc/fish", "xonsh"],
    }
}


def parse_args():
    logger.info("开始解析参数")
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
    try:
        args = parser.parse_args()
        if args.output_example_config:
            with open("config.json", "w") as fout:
                json.dump(EXAMPLE_DATA, fout, indent=2, ensure_ascii=False)
            exit(0)
        if not (args.config_path and args.pkg_path):
            logger.fatal("错误，-c 和 -s 参数必须同时提供")
            exit(1)
    finally:
        logger.info("解析参数完毕")
    return args


class Modify:
    def __init__(self, args):
        self.args = args
        self.pkg_path, self.config_path, self.config = None, None, None
        self.new_pkg_mode = False

    def check_args(self):
        # 获取参数值
        logger.info("开始检查传入参数")
        config_path = self.args.config_path
        if not os.path.isabs(config_path):
            config_path = os.path.abspath(os.path.join(SCRIPT_DIR, config_path))
        # 检查源文件是否存在
        if not os.path.isfile(config_path):
            logger.error(f"错误：配置文件 '{config_path}' 不存在")
            logger.info("检查传入参数完毕")
            sys.exit(1)
        self.config_path = config_path
        logger.debug(f"配置文件路径 {config_path}")

        pkg_path = self.args.pkg_path
        if not os.path.isabs(pkg_path):
            pkg_path = os.path.abspath(os.path.join(SCRIPT_DIR, pkg_path))
        if not os.path.exists(pkg_path):
            logger.error(f"错误：conda 包路径或目录 {pkg_path}' 不存在")
            logger.info("检查传入参数完毕")
            sys.exit(1)
        self.pkg_path = pkg_path
        logger.debug(f"待处理的 conda 包或目录为 {pkg_path}")
        logger.info("检查传入参数完毕")

    def run(self):
        # 1. 检查参数
        self.check_args()
        # 2. 读取配置
        logger.info("开始读取配置文件")
        with open(self.config_path) as fin:
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

    def get_pkg_infos(self):
        if os.path.isfile(self.pkg_path):
            pkg_paths = [self.pkg_path]
        else:
            pkg_paths = os.listdir(self.pkg_path)
            pkg_paths = [os.path.join(self.pkg_path, path) for path in pkg_paths]

        pkg_infos = list(map(self.get_pkg_info, pkg_paths))
        return pkg_infos

    @staticmethod
    def get_pkg_info(pkg_path):
        dirname = os.path.dirname(pkg_path)
        basename = os.path.basename(pkg_path)
        basename_no_suffix = basename.replace(".tar.bz2", "").replace(".conda", "")
        extract_path = os.path.join(dirname, basename_no_suffix)
        comps = basename_no_suffix.split("-")
        other, version, build_str = comps[:-2], comps[-2], comps[-1]
        name = "-".join(other)
        format = "tar.bz2" if ".tar.bz2" in pkg_path else "conda"
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
            "format": format,
            "extract_path": extract_path,
            "binary_path": binary_path,
            "info_path": info_path,
            "real_info_path": real_info_path,
        }

    def check_config(self, pkgs_infos):
        filter_pkgs_infos = []
        have_error, errors = False, defaultdict(list)
        for pkg_name, rule in self.config.items():
            # 1. pkg_name check
            pkg_info = list(filter(lambda x: x.get("name") == pkg_name, pkgs_infos))
            if len(pkg_info) == 0:
                have_error = True
                msg = f"Error, no package named '{pkg_name}' found in '{self.pkg_path}'"
                errors[pkg_name].append(msg)

            if len(pkg_info) == 1:
                pkg_info = pkg_info[0]
                self.extract_pkg(pkg_info)
                # 2. rule check and transfer rule paths
                if "add" in rule:
                    add_rule_paths = [
                        os.path.abspath(
                            os.path.normpath(
                                os.path.join(
                                    os.path.dirname(self.config_path), add_path
                                )
                            )
                        )
                        for add_path in rule["add"]
                    ]
                    new_add_rules = {}
                    for add_rule_path, add_path, new_path in zip(
                        add_rule_paths, rule["add"].keys(), rule["add"].values()
                    ):
                        if not os.path.exists(add_rule_path):
                            have_error = True
                            msg = f"Error, add rule '{add_path}' not exists."
                            errors[pkg_name].append(msg)
                        new_path = os.path.join(pkg_info["binary_path"], new_path)
                        if not os.path.isfile(new_path):
                            new_path = os.path.join(
                                new_path, os.path.basename(add_rule_path)
                            )
                        new_add_rules[add_rule_path] = new_path
                    rule["add"] = new_add_rules

                if "mv" in rule:
                    mv_rule_paths = [
                        os.path.abspath(
                            os.path.normpath(
                                os.path.join(pkg_info["binary_path"], mv_path)
                            )
                        )
                        for mv_path in rule["mv"]
                    ]
                    for mv_rule_path, mv_path, _ in zip(
                        mv_rule_paths, rule["mv"].keys(), rule["mv"].values()
                    ):
                        if not os.path.exists(mv_rule_path):
                            have_error = True
                            msg = f"Error, mv rule '{mv_path}' not exists."
                            errors[pkg_name].append(msg)

                if "delete" in rule:
                    delete_rules = rule["delete"]
                    delete_spec = pathspec.PathSpec.from_lines(
                        pathspec.patterns.GitWildMatchPattern, delete_rules
                    )
                    delete_files = self.get_deleted_files(
                        pkg_info["binary_path"], delete_spec
                    )
                    delete_files = [
                        os.path.relpath(file, pkg_info["binary_path"])
                        for file in delete_files
                    ]
                    rule["delete"] = delete_files
                pkg_info.update({"rule": rule})

        if have_error:
            for name, error in errors.items():
                logger.error(f"for package name '{name}', rule have following errors:")
                error_msgs = ["  " + err for err in error]
                for error_msg in error_msgs:
                    logger.error(error_msg)
            sys.exit(2)
        filter_pkgs_infos.append(pkg_info)
        return filter_pkgs_infos

    def handle_one_package(self, pkg_info):
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
        with open(files_path, "w") as fout:
            fout.write("\n".join(files_list))

        has_prefix_path = os.path.join(pkg_info["real_info_path"], "has_prefix")
        with open(has_prefix_path, "w") as fout:
            fout.write("\n".join(has_prefix_list))

        # 重新打包
        extract_dir = pkg_info["extract_path"]
        dst_file = pkg_info["path"]
        logger.info(f"  重新打包 {dst_file} 开始")
        if os.path.exists(dst_file):
            os.unlink(dst_file)

        if pkg_info["format"] == "conda":
            with ZipFile(dst_file, "w", compression=ZIP_STORED) as conda_file:
                pkg_metadata = {
                    "conda_pkg_format_version": CONDA_PACKAGE_FORMAT_VERSION
                }
                file_id = pkg_info["name_no_suffix"]
                conda_file.writestr("metadata.json", json.dumps(pkg_metadata))
                pkg_files = get_filelist(pkg_info["binary_path"], with_prefix=True)
                info_files = get_filelist(pkg_info["real_info_path"], with_prefix=True)
                components_files = (
                    (f"pkg-{file_id}.tar.zst", pkg_files),
                    (
                        f"info-{file_id}.tar.zst",
                        info_files,
                    ),
                )
                # put the info last, for parity with updated transmute.
                compress = compressor()
                for component, files in components_files:
                    # If size is known, the decompressor may be able to allocate less memory.
                    # The compressor will error if size is not correct.
                    with tarfile.TarFile(fileobj=NullWriter(), mode="w") as sizer:  # type: ignore
                        for file in files:
                            if "pkg" in component:
                                arcname = os.path.relpath(file, pkg_info["binary_path"])
                            if "info" in component:
                                arcname = os.path.relpath(file, pkg_info["info_path"])
                            sizer.add(file, filter=anonymize_tarinfo, arcname=arcname)
                    size = sizer.fileobj.size  # type: ignore

                    with conda_file.open(
                        component, "w", force_zip64=True
                    ) as component_file:
                        # only one stream_writer() per compressor() must be in use at a time
                        component_stream = compress.stream_writer(
                            component_file, size=size, closefd=False
                        )
                        component_tar = tarfile.TarFile(
                            fileobj=component_stream, mode="w"
                        )

                        for file in files:
                            if "pkg" in component:
                                arcname = os.path.relpath(file, pkg_info["binary_path"])
                            if "info" in component:
                                arcname = os.path.relpath(file, pkg_info["info_path"])
                            component_tar.add(
                                file, filter=anonymize_tarinfo, arcname=arcname
                            )
                        component_tar.close()
                        component_stream.close()
        if pkg_info["format"] == "tar.bz2":
            prefix = pkg_info["binary_path"]
            with tmp_chdir(prefix):
                files = get_filelist(prefix)
                with tarfile.open(dst_file, "w:bz2") as t:
                    for f in files:
                        t.add(f, filter=anonymize_tarinfo)
        shutil.rmtree(extract_dir)
        logger.info(f"处理 {pkg_info['path']} 完毕")

    def get_paths_json_data(self, pkg_info):
        paths_json_path = os.path.join(pkg_info["real_info_path"], "paths.json")
        with open(paths_json_path) as fin:
            paths_json_data = json.load(fin)
            return paths_json_path, paths_json_data

    def handle_add_rule(self, pkg_info):
        # 执行复制
        new_data = []
        add_rule = pkg_info["rule"]["add"]
        for old_path, new_path in add_rule.items():
            os.makedirs(os.path.dirname(new_path), exist_ok=True)
            shutil.copy(old_path, new_path)
            new_pkg_path = os.path.relpath(new_path, pkg_info["binary_path"])
            new_data.append(
                {
                    "_path": new_pkg_path,
                    "path_type": "hardlink",
                    "sha256": hash_files([new_path]),
                    "size_in_bytes": os.path.getsize(new_path),
                }
            )
        # 修改 paths.json 文件
        paths_json_path, paths_json_data = self.get_paths_json_data(pkg_info)
        paths_json_data["paths"].extend(new_data)
        paths_json_data["paths"].sort(key=lambda x: x.get("_path"))
        with open(paths_json_path, "w") as fout:
            fout.write(json.dumps(paths_json_data, indent=2, ensure_ascii=False))

    def handle_mv_rule(self, pkg_info):
        # 执行移动或改名
        mv_rule = pkg_info["rule"]["mv"]
        for old_path, new_path in mv_rule.items():
            old_abs_path = os.path.join(pkg_info["binary_path"], old_path)
            new_abs_path = os.path.join(pkg_info["binary_path"], new_path)
            os.makedirs(os.path.dirname(new_abs_path), exist_ok=True)
            shutil.move(old_abs_path, new_abs_path)
            # 修改 paths.json 文件
            paths_json_path, paths_json_data = self.get_paths_json_data(pkg_info)
            old_path_info = list(
                filter(lambda x: x.get("_path") == old_path, paths_json_data["paths"])
            )[0]
            old_path_info.update({"_path": new_path})
            paths_json_data["paths"].sort(key=lambda x: x.get("_path"))
            with open(paths_json_path, "w") as fout:
                fout.write(json.dumps(paths_json_data, indent=2, ensure_ascii=False))

    def handle_delete_rule(self, pkg_info):
        # 执行删除操作
        delete_rule = pkg_info["rule"]["delete"]
        for delete_path in delete_rule:
            delete_abs_path = os.path.join(pkg_info["binary_path"], delete_path)
            os.unlink(delete_abs_path)

            # 递归移除空目录
            to_remove_dir = os.path.dirname(delete_abs_path)
            while len(get_filelist(to_remove_dir)) == 0:
                os.rmdir(to_remove_dir)
                to_remove_dir = os.path.dirname(to_remove_dir)

            # 修改 paths.json 文件
            paths_json_path, paths_json_data = self.get_paths_json_data(pkg_info)
            new_paths_info = list(
                filter(
                    lambda x: x.get("_path") != delete_path, paths_json_data["paths"]
                )
            )
            paths_json_data["paths"] = new_paths_info
            paths_json_data["paths"].sort(key=lambda x: x.get("_path"))
            with open(paths_json_path, "w") as fout:
                fout.write(json.dumps(paths_json_data, indent=2, ensure_ascii=False))

    def extract_pkg(self, pkg_info):
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

    @staticmethod
    def get_deleted_files(basedir, spec: pathspec.PathSpec):
        delete_files = []
        for root, _, files in os.walk(basedir):
            for file in files:
                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, start=basedir)
                if spec.match_file(relative_path):
                    delete_files.append(file_path)
        return delete_files


def main():
    args = parse_args()
    instance = Modify(args)
    instance.run()


if __name__ == "__main__":
    main()
