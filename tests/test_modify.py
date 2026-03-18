"""Tests for modify."""

# pylint: disable=missing-function-docstring,missing-class-docstring,protected-access
# pylint: disable=too-few-public-methods,attribute-defined-outside-init
# pylint: disable=too-many-public-methods,use-implicit-booleaness-not-comparison

import argparse
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from collections import defaultdict
from pathlib import Path
from unittest import mock
from zipfile import ZipFile

import pathspec
import pytest

from conda_tool.modify import EXAMPLE_DATA, FileProcessor, Modify, main, parse_args
from conda_tool.utils import is_elf_file, setup_logging

setup_logging(120)


class TestParseArgs:
    def test_output_example_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            old_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                with mock.patch.object(sys, "argv", ["modify.py", "-oc"]):
                    with pytest.raises(SystemExit):
                        parse_args()
            finally:
                os.chdir(old_cwd)

            config_path = os.path.join(tmpdir, "config.json")
            assert os.path.isfile(config_path)
            with open(config_path, encoding="utf-8") as fin:
                assert json.load(fin) == EXAMPLE_DATA

    def test_missing_required_args(self) -> None:
        with mock.patch.object(sys, "argv", ["modify.py", "-c", "config.json"]):
            with pytest.raises(SystemExit):
                parse_args()

    def test_valid_args(self) -> None:
        with mock.patch.object(
            sys,
            "argv",
            ["modify.py", "-c", "config.json", "-s", "pkg.conda"],
        ):
            args = parse_args()

        assert args.config_path == "config.json"
        assert args.pkg_path == "pkg.conda"
        assert not args.keep_origin


class TestFileProcessor:
    def test_context_manager(self) -> None:
        with FileProcessor() as processor:
            assert processor.executor is not None

        with pytest.raises(RuntimeError):
            processor.executor.submit(lambda: None)

    def test_copy_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            src = os.path.join(tmpdir, "source.txt")
            dst = os.path.join(tmpdir, "sub", "dest.txt")
            Path(src).write_text("hello", encoding="utf-8")

            with FileProcessor() as processor:
                processor._copy_file(src, dst)

            assert os.path.isfile(dst)
            assert Path(dst).read_text(encoding="utf-8") == "hello"

    def test_move_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            src = os.path.join(tmpdir, "source.txt")
            dst = os.path.join(tmpdir, "sub", "dest.txt")
            Path(src).write_text("move-me", encoding="utf-8")

            with FileProcessor() as processor:
                processor._move_file(src, dst)

            assert not os.path.exists(src)
            assert os.path.isfile(dst)
            assert Path(dst).read_text(encoding="utf-8") == "move-me"

    def test_delete_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, "deleteme.txt")
            Path(file_path).write_text("x", encoding="utf-8")

            with FileProcessor() as processor:
                processor._delete_file(file_path)

            assert not os.path.exists(file_path)

    def test_delete_cleans_empty_dirs(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            nested = os.path.join(tmpdir, "a", "b", "c")
            os.makedirs(nested)
            file_path = os.path.join(nested, "deleteme.txt")
            Path(file_path).write_text("x", encoding="utf-8")

            with FileProcessor() as processor:
                processor._delete_file(file_path)

            assert not os.path.exists(file_path)
            assert not os.path.exists(nested)
            assert not os.path.exists(os.path.join(tmpdir, "a", "b"))

    def test_strip_non_elf_skips(self, capsys: pytest.CaptureFixture[str]) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, "text.txt")
            Path(file_path).write_text("not-elf", encoding="utf-8")

            with FileProcessor() as processor:
                processor._strip_file(file_path)

            captured = capsys.readouterr()
            combined = captured.out + captured.err
            assert "not a ELF file, ignore this file." in combined

    def test_process_files_concurrently(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            pairs = []
            for i in range(5):
                src = os.path.join(tmpdir, f"src-{i}.txt")
                dst = os.path.join(tmpdir, "out", f"dst-{i}.txt")
                Path(src).write_text(f"data-{i}", encoding="utf-8")
                pairs.append((src, dst))

            with FileProcessor() as processor:
                processor.process_files_concurrently(pairs, "copy")

            for i, (_, dst) in enumerate(pairs):
                assert os.path.isfile(dst)
                assert Path(dst).read_text(encoding="utf-8") == f"data-{i}"

    def test_process_files_concurrently_move(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            pairs = []
            for i in range(3):
                src = os.path.join(tmpdir, f"move-src-{i}.txt")
                dst = os.path.join(tmpdir, "moved", f"move-dst-{i}.txt")
                Path(src).write_text(f"move-data-{i}", encoding="utf-8")
                pairs.append((src, dst))

            with FileProcessor() as processor:
                processor.process_files_concurrently(pairs, "move")

            for i, (src, dst) in enumerate(pairs):
                assert not os.path.exists(src)
                assert os.path.isfile(dst)
                assert Path(dst).read_text(encoding="utf-8") == f"move-data-{i}"

    def test_process_file_routes_move(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            src = os.path.join(tmpdir, "from.txt")
            dst = os.path.join(tmpdir, "dest", "to.txt")
            Path(src).write_text("move-route", encoding="utf-8")

            with FileProcessor() as processor:
                processor._process_file(src, dst, "move")

            assert not os.path.exists(src)
            assert os.path.isfile(dst)
            assert Path(dst).read_text(encoding="utf-8") == "move-route"

    def test_process_file_routes_delete(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            src = os.path.join(tmpdir, "delete.txt")
            Path(src).write_text("delete-route", encoding="utf-8")

            with FileProcessor() as processor:
                processor._process_file(src, "", "delete")

            assert not os.path.exists(src)

    def test_process_files_concurrently_delete(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            files = []
            for i in range(3):
                path = os.path.join(tmpdir, "to-delete", f"delete-{i}.txt")
                os.makedirs(os.path.dirname(path), exist_ok=True)
                Path(path).write_text("x", encoding="utf-8")
                files.append(path)

            with FileProcessor() as processor:
                processor.process_files_concurrently([(f, "") for f in files], "delete")

            for path in files:
                assert not os.path.exists(path)

    def test_process_file_routes_strip(self, capsys: pytest.CaptureFixture[str]) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            src = os.path.join(tmpdir, "strip.txt")
            Path(src).write_text("not-elf", encoding="utf-8")

            with FileProcessor() as processor:
                processor._process_file(src, "", "strip")

            captured = capsys.readouterr()
            combined = captured.out + captured.err
            assert "not a ELF file, ignore this file." in combined

    def test_process_files_concurrently_logs_future_errors(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            src = os.path.join(tmpdir, "x.txt")
            dst = os.path.join(tmpdir, "y.txt")
            Path(src).write_text("x", encoding="utf-8")

            with FileProcessor() as processor:
                with (
                    mock.patch.object(
                        processor,
                        "_process_file",
                        side_effect=RuntimeError("future-boom"),
                    ),
                ):
                    processor.process_files_concurrently([(src, dst)], "copy")

            captured = capsys.readouterr()
            combined = captured.out + captured.err
            assert "File operation failed" in combined

    def test_process_file_logs_copy_errors(self, capsys: pytest.CaptureFixture[str]) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            missing_src = os.path.join(tmpdir, "missing.txt")
            dst = os.path.join(tmpdir, "dest", "x.txt")

            with FileProcessor() as processor:
                processor._process_file(missing_src, dst, "copy")

            captured = capsys.readouterr()
            combined = captured.out + captured.err
            assert "Failed to copy" in combined

    def test_strip_file_logs_called_process_error(self, capsys: pytest.CaptureFixture[str]) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "fake-bin")
            Path(path).write_bytes(b"\x7fELF")

            with FileProcessor() as processor:
                with (
                    mock.patch("conda_tool.modify.is_elf_file", return_value=True),
                    mock.patch(
                        "conda_tool.modify.subprocess.run",
                        side_effect=subprocess.CalledProcessError(
                            1,
                            ["strip", "--strip-debug", path],
                            stderr=b"strip-failed",
                        ),
                    ),
                ):
                    processor._strip_file(path)

            captured = capsys.readouterr()
            combined = captured.out + captured.err
            assert "Strip failed for" in combined


class TestGetPkgInfo:
    def test_conda_format(self) -> None:
        pkg_path = "/tmp/appdirs-1.4.4-pyh9f0ad1d_0.conda"
        info = Modify.get_pkg_info(pkg_path)
        assert info["format"] == "conda"
        assert info["name"] == "appdirs"
        assert info["version"] == "1.4.4"
        assert info["build_str"] == "pyh9f0ad1d_0"

    def test_tar_bz2_format(self) -> None:
        pkg_path = "/tmp/appdirs-1.4.4-pyh9f0ad1d_0.tar.bz2"
        info = Modify.get_pkg_info(pkg_path)
        assert info["format"] == "tar.bz2"
        assert info["name"] == "appdirs"
        assert info["version"] == "1.4.4"

    def test_hyphenated_package_name(self) -> None:
        pkg_path = "/tmp/python-dateutil-2.8.2-pyhd8ed1ab_0.conda"
        info = Modify.get_pkg_info(pkg_path)
        assert info["name"] == "python-dateutil"
        assert info["version"] == "2.8.2"
        assert info["build_str"] == "pyhd8ed1ab_0"


class TestModifyWithRealPackage:
    @classmethod
    def setup_class(cls) -> None:
        cls._cache_dir = tempfile.mkdtemp()
        candidate_urls = [
            "https://conda.anaconda.org/conda-forge/noarch/appdirs-1.4.4-pyh9f0ad1d_0.conda",
            "https://conda.anaconda.org/conda-forge/noarch/appdirs-1.4.4-pyhd8ed1ab_1.conda",
        ]

        last_exc = None
        for url in candidate_urls:
            pkg_filename = url.rsplit("/", 1)[-1]
            cached_pkg = os.path.join(cls._cache_dir, pkg_filename)
            try:
                urllib.request.urlretrieve(url, cached_pkg)
                cls._pkg_filename = pkg_filename
                cls._cached_pkg = cached_pkg
                return
            except Exception as exc:  # pragma: no cover - network-dependent fallback
                last_exc = exc

        pytest.skip(f"Unable to download fixture package: {last_exc}")

    @classmethod
    def teardown_class(cls) -> None:
        shutil.rmtree(cls._cache_dir, ignore_errors=True)

    def setup_method(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.pkg_path = os.path.join(self.tmpdir, self._pkg_filename)
        shutil.copy2(self._cached_pkg, self.pkg_path)
        self.config_path = os.path.join(self.tmpdir, "config.json")
        Path(self.config_path).write_text("{}", encoding="utf-8")
        args = argparse.Namespace(
            config_path=self.config_path,
            pkg_path=self.pkg_path,
            keep_origin=False,
        )
        self.modify = Modify(args)
        self.modify.config_path = self.config_path
        self.modify.pkg_path = self.pkg_path

    def teardown_method(self) -> None:
        self.modify.file_processor.shutdown()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _extract(self, pkg_path: str | None = None) -> dict:
        target = pkg_path or self.pkg_path
        pkg_info = self.modify.get_pkg_info(target)
        self.modify.extract_pkg(pkg_info)
        return pkg_info

    @staticmethod
    def _first_binary_file(pkg_info: dict, suffix: str | None = None) -> str:
        for root, _, files in os.walk(pkg_info["binary_path"]):
            for file in files:
                if suffix and not file.endswith(suffix):
                    continue
                return os.path.join(root, file)
        raise AssertionError("No matching file found in package binary path")

    def _pkg_name(self) -> str:
        return self.modify.get_pkg_info(self.pkg_path)["name"]

    def _make_tar_bz2_pkg(self) -> str:
        extracted = self._extract()
        tar_root = os.path.join(self.tmpdir, "tar_root")
        os.makedirs(tar_root, exist_ok=True)

        for root, _, files in os.walk(extracted["binary_path"]):
            for file in files:
                src = os.path.join(root, file)
                rel = os.path.relpath(src, extracted["binary_path"])
                dst = os.path.join(tar_root, rel)
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                shutil.copy2(src, dst)

        for root, _, files in os.walk(extracted["real_info_path"]):
            for file in files:
                src = os.path.join(root, file)
                rel = os.path.relpath(src, extracted["real_info_path"])
                dst = os.path.join(tar_root, "info", rel)
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                shutil.copy2(src, dst)

        bz2_path = os.path.join(self.tmpdir, f"{extracted['name_no_suffix']}.tar.bz2")
        with tarfile.open(bz2_path, "w:bz2", encoding="utf-8") as t:
            for root, _, files in os.walk(tar_root):
                for file in files:
                    full_path = os.path.join(root, file)
                    arcname = os.path.relpath(full_path, tar_root)
                    t.add(full_path, arcname=arcname)
        return bz2_path

    def test_extract_pkg(self) -> None:
        pkg_info = self.modify.get_pkg_info(self.pkg_path)
        self.modify.extract_pkg(pkg_info)
        assert os.path.isdir(pkg_info["binary_path"])
        assert os.path.isdir(pkg_info["info_path"])

    def test_check_args_valid(self) -> None:
        self.modify.check_args()
        assert self.modify.config_path == os.path.abspath(self.config_path)
        assert self.modify.pkg_path == os.path.abspath(self.pkg_path)

    def test_check_args_missing_config(self) -> None:
        args = argparse.Namespace(
            config_path=os.path.join(self.tmpdir, "missing.json"),
            pkg_path=self.pkg_path,
            keep_origin=False,
        )
        instance = Modify(args)
        with pytest.raises(SystemExit):
            instance.check_args()
        instance.file_processor.shutdown()

    def test_check_args_missing_pkg(self) -> None:
        args = argparse.Namespace(
            config_path=self.config_path,
            pkg_path=os.path.join(self.tmpdir, "missing.conda"),
            keep_origin=False,
        )
        instance = Modify(args)
        with pytest.raises(SystemExit):
            instance.check_args()
        instance.file_processor.shutdown()

    def test_get_pkg_infos_single_file(self) -> None:
        infos = self.modify.get_pkg_infos()
        assert len(infos) == 1
        assert infos[0]["path"] == self.pkg_path

    def test_get_pkg_infos_directory(self) -> None:
        pkg_dir = os.path.join(self.tmpdir, "pkgs")
        os.makedirs(pkg_dir)
        pkg_in_dir = os.path.join(pkg_dir, self._pkg_filename)
        shutil.copy2(self._cached_pkg, pkg_in_dir)
        self.modify.pkg_path = pkg_dir

        infos = self.modify.get_pkg_infos()
        assert len(infos) == 1
        assert infos[0]["path"] == pkg_in_dir

    def test_check_config_no_matching_pkg(self) -> None:
        infos = self.modify.get_pkg_infos()
        self.modify.config = {"definitely-wrong-name": {"delete": ["*.txt"]}}

        with pytest.raises(SystemExit):
            self.modify.check_config(infos)

    def test_run_full_pipeline(self, capsys: pytest.CaptureFixture[str]) -> None:
        add_name = "run-add.txt"
        add_src = os.path.join(self.tmpdir, add_name)
        Path(add_src).write_text("run-content", encoding="utf-8")

        config = {self._pkg_name(): {"add": {add_name: "bin/"}}}
        Path(self.config_path).write_text(
            json.dumps(config, ensure_ascii=False), encoding="utf-8"
        )


        self.modify.run()

        captured = capsys.readouterr()
        combined = captured.out + captured.err
        assert "开始读取配置文件" in combined
        assert "开始检查配置文件" in combined
        assert "修改完毕" in combined

        pkg_info = self.modify.get_pkg_info(self.pkg_path)
        self.modify.extract_pkg(pkg_info)
        assert (
            os.path.isfile(os.path.join(pkg_info["binary_path"], "bin", add_name))
        )

    def test_check_config_normal_path(self) -> None:
        infos = self.modify.get_pkg_infos()
        add_name = "normal-add.txt"
        add_src = os.path.join(self.tmpdir, add_name)
        Path(add_src).write_text("x", encoding="utf-8")

        self.modify.config = {self._pkg_name(): {"add": {add_name: "bin/"}}}
        filtered = self.modify.check_config(infos)

        assert len(filtered) == 1
        add_rule = filtered[0]["rule"]["add"]
        expected_src = os.path.abspath(add_src)
        expected_dst = os.path.join(filtered[0]["binary_path"], "bin/", add_name)
        assert expected_src in add_rule
        assert add_rule[expected_src] == expected_dst

    def test_check_config_duplicate_packages(self, capsys: pytest.CaptureFixture[str]) -> None:
        pkg_dir = os.path.join(self.tmpdir, "dup_pkgs")
        os.makedirs(pkg_dir)
        first_pkg = os.path.join(pkg_dir, self._pkg_filename)
        second_pkg = os.path.join(pkg_dir, "appdirs-9.9.9-fake_0.conda")
        shutil.copy2(self._cached_pkg, first_pkg)
        shutil.copy2(self._cached_pkg, second_pkg)

        self.modify.pkg_path = pkg_dir
        infos = self.modify.get_pkg_infos()
        self.modify.config = {"appdirs": {"delete": ["*.py"]}}


        with pytest.raises(SystemExit):
            self.modify.check_config(infos)

        captured = capsys.readouterr()
        combined = captured.out + captured.err
        assert "more than one package named 'appdirs'" in combined

    def test_expand_rule_add_file(self) -> None:
        pkg_info = self._extract()
        src_name = "expand-file.txt"
        src_path = os.path.join(self.tmpdir, src_name)
        Path(src_path).write_text("expand-file", encoding="utf-8")

        rule = {"add": {src_name: "target/"}}
        expanded, errors = self.modify.expand_rule(
            rule, "add", defaultdict(list), self._pkg_name(), pkg_info
        )

        assert len(errors) == 0
        assert len(expanded) == 1
        abs_src = os.path.abspath(src_path)
        assert abs_src in expanded
        assert expanded[abs_src] == os.path.join(
            pkg_info["binary_path"], "target/", src_name
        )

    def test_expand_rule_add_directory(self) -> None:
        pkg_info = self._extract()
        src_dir = os.path.join(self.tmpdir, "expand_dir")
        nested = os.path.join(src_dir, "sub")
        os.makedirs(nested)
        f1 = os.path.join(src_dir, "a.txt")
        f2 = os.path.join(nested, "b.txt")
        Path(f1).write_text("a", encoding="utf-8")
        Path(f2).write_text("b", encoding="utf-8")

        rule = {"add": {"expand_dir": "dest/"}}
        expanded, errors = self.modify.expand_rule(
            rule, "add", defaultdict(list), self._pkg_name(), pkg_info
        )

        assert len(errors) == 0
        assert len(expanded) == 2
        assert os.path.abspath(f1) in expanded
        assert os.path.abspath(f2) in expanded
        assert expanded[os.path.abspath(f1)] == os.path.join(
            pkg_info["binary_path"], "dest/", "expand_dir", "a.txt"
        )
        assert expanded[os.path.abspath(f2)] == os.path.join(
            pkg_info["binary_path"], "dest/", "expand_dir", "sub", "b.txt"
        )

    def test_expand_rule_add_wildcard(self) -> None:
        pkg_info = self._extract()
        wildcard_dir = os.path.join(self.tmpdir, "wild")
        os.makedirs(wildcard_dir)
        t1 = os.path.join(wildcard_dir, "one.txt")
        t2 = os.path.join(wildcard_dir, "two.txt")
        other = os.path.join(wildcard_dir, "skip.py")
        Path(t1).write_text("1", encoding="utf-8")
        Path(t2).write_text("2", encoding="utf-8")
        Path(other).write_text("3", encoding="utf-8")

        rule = {"add": {"wild/*.txt": "wild-dst/"}}
        expanded, errors = self.modify.expand_rule(
            rule, "add", defaultdict(list), self._pkg_name(), pkg_info
        )

        assert len(errors) == 0
        assert os.path.abspath(t1) in expanded
        assert os.path.abspath(t2) in expanded
        assert os.path.abspath(other) not in expanded

    def test_expand_rule_mv_file(self) -> None:
        pkg_info = self._extract()
        src_abs = self._first_binary_file(pkg_info)
        src_rel = os.path.relpath(src_abs, pkg_info["binary_path"])
        dst_rel = os.path.join("mv-target", os.path.basename(src_abs))
        rule = {"mv": {src_rel: dst_rel}}

        expanded, errors = self.modify.expand_rule(
            rule, "mv", defaultdict(list), self._pkg_name(), pkg_info
        )

        assert len(errors) == 0
        assert expanded[src_abs] == os.path.join(pkg_info["binary_path"], dst_rel)

    def test_expand_rule_dir_without_trailing_slash(self) -> None:
        pkg_info = self._extract()
        src_dir = os.path.join(self.tmpdir, "dir_no_slash")
        os.makedirs(src_dir)
        Path(os.path.join(src_dir, "x.txt")).write_text("x", encoding="utf-8")
        rule = {"add": {"dir_no_slash": "dest-no-slash"}}

        expanded, errors = self.modify.expand_rule(
            rule, "add", defaultdict(list), self._pkg_name(), pkg_info
        )

        assert expanded == {}
        assert any("must endswith '/'" in m for m in errors[self._pkg_name()])

    def test_expand_rule_nonexistent_path(self) -> None:
        pkg_info = self._extract()
        rule = {"add": {"missing_dir/*.txt": "dest/"}}

        expanded, errors = self.modify.expand_rule(
            rule, "add", defaultdict(list), self._pkg_name(), pkg_info
        )

        assert expanded == {}
        assert (
            any("is not a valid exist path" in m for m in errors[self._pkg_name()])
        )

    def test_expand_rule_wildcard_no_matching_files(self) -> None:
        pkg_info = self._extract()
        wildcard_dir = os.path.join(self.tmpdir, "wild-none")
        os.makedirs(wildcard_dir, exist_ok=True)
        Path(os.path.join(wildcard_dir, "keep.py")).write_text("x", encoding="utf-8")

        rule = {"add": {"wild-none/*.txt": "dest/"}}
        expanded, errors = self.modify.expand_rule(
            rule, "add", defaultdict(list), self._pkg_name(), pkg_info
        )

        assert expanded == {}
        assert len(errors) == 0

    def test_handle_add_rule_path_ending_slash(self) -> None:
        pkg_info = self._extract()
        src = os.path.join(self.tmpdir, "slash-add.txt")
        Path(src).write_text("slash", encoding="utf-8")
        dst_dir = os.path.join(pkg_info["binary_path"], "added-dir") + "/"

        pkg_info["rule"] = {"add": {src: dst_dir}}
        self.modify.handle_add_rule(pkg_info)

        new_file = os.path.join(pkg_info["binary_path"], "added-dir", "slash-add.txt")
        assert os.path.isfile(new_file)
        _, paths_data = self.modify.get_paths_json_data(pkg_info)
        assert (
            any(item["_path"] == "added-dir/slash-add.txt" for item in paths_data["paths"])
        )

    def test_handle_mv_rule_path_ending_slash(self) -> None:
        pkg_info = self._extract()
        old_path = self._first_binary_file(pkg_info)
        old_rel = os.path.relpath(old_path, pkg_info["binary_path"])
        dst_dir = os.path.join(pkg_info["binary_path"], "mv-dir") + "/"

        pkg_info["rule"] = {"mv": {old_path: dst_dir}}
        self.modify.handle_mv_rule(pkg_info)

        new_path = os.path.join(dst_dir, os.path.basename(old_path))
        new_rel = os.path.relpath(new_path, pkg_info["binary_path"])
        assert not os.path.exists(old_path)
        assert os.path.exists(new_path)
        _, paths_data = self.modify.get_paths_json_data(pkg_info)
        assert not any(item["_path"] == old_rel for item in paths_data["paths"])
        assert any(item["_path"] == new_rel for item in paths_data["paths"])

    def test_handle_add_rule(self) -> None:
        pkg_info = self._extract()
        source_file = os.path.join(self.tmpdir, "add.txt")
        Path(source_file).write_text("added", encoding="utf-8")
        added_abs_path = os.path.join(pkg_info["binary_path"], "bin", "add.txt")

        pkg_info["rule"] = {"add": {source_file: added_abs_path}}
        self.modify.handle_add_rule(pkg_info)

        assert os.path.isfile(added_abs_path)
        assert Path(added_abs_path).read_text(encoding="utf-8") == "added"

        _, paths_data = self.modify.get_paths_json_data(pkg_info)
        assert any(item["_path"] == "bin/add.txt" for item in paths_data["paths"])

    def test_handle_mv_rule(self) -> None:
        pkg_info = self._extract()
        old_path = self._first_binary_file(pkg_info)
        new_path = os.path.join(pkg_info["binary_path"], "moved", os.path.basename(old_path))

        pkg_info["rule"] = {"mv": {old_path: new_path}}
        self.modify.handle_mv_rule(pkg_info)

        assert not os.path.exists(old_path)
        assert os.path.isfile(new_path)

        old_rel = os.path.relpath(old_path, pkg_info["binary_path"])
        new_rel = os.path.relpath(new_path, pkg_info["binary_path"])
        _, paths_data = self.modify.get_paths_json_data(pkg_info)
        assert not any(item["_path"] == old_rel for item in paths_data["paths"])
        assert any(item["_path"] == new_rel for item in paths_data["paths"])

    def test_handle_delete_rule(self) -> None:
        pkg_info = self._extract()
        delete_path = self._first_binary_file(pkg_info)

        pkg_info["rule"] = {"delete": [delete_path]}
        self.modify.handle_delete_rule(pkg_info)

        assert not os.path.exists(delete_path)
        delete_rel = os.path.relpath(delete_path, pkg_info["binary_path"])
        _, paths_data = self.modify.get_paths_json_data(pkg_info)
        assert not any(item["_path"] == delete_rel for item in paths_data["paths"])

    def test_handle_strip_rule_non_elf(self, capsys: pytest.CaptureFixture[str]) -> None:
        pkg_info = self._extract()
        strip_target = self._first_binary_file(pkg_info, suffix=".py")
        if not strip_target:
            strip_target = self._first_binary_file(pkg_info)
        assert not is_elf_file(strip_target)

        pkg_info["rule"] = {"strip": [strip_target]}

        self.modify.handle_strip_rule(pkg_info)

        captured = capsys.readouterr()
        combined = captured.out + captured.err
        assert "not a ELF file, ignore this file." in combined

    def test_handle_one_package_add_and_repack(self) -> None:
        pkg_info = self._extract()
        source_file = os.path.join(self.tmpdir, "newfile.txt")
        Path(source_file).write_text("new-content", encoding="utf-8")
        added_abs_path = os.path.join(pkg_info["binary_path"], "added", "newfile.txt")

        pkg_info["rule"] = {"add": {source_file: added_abs_path}}
        self.modify.handle_one_package(pkg_info)

        with ZipFile(self.pkg_path) as zf:
            assert zf.testzip() is None
            assert "metadata.json" in zf.namelist()

        repacked_info = self._extract(self.pkg_path)
        assert (
            os.path.isfile(os.path.join(repacked_info["binary_path"], "added", "newfile.txt"))
        )

    def test_handle_one_package_delete_and_repack(self) -> None:
        pkg_info = self._extract()
        delete_path = self._first_binary_file(pkg_info)
        delete_rel = os.path.relpath(delete_path, pkg_info["binary_path"])

        pkg_info["rule"] = {"delete": [delete_path]}
        self.modify.handle_one_package(pkg_info)

        with ZipFile(self.pkg_path) as zf:
            assert zf.testzip() is None
            assert "metadata.json" in zf.namelist()

        repacked_info = self._extract(self.pkg_path)
        assert not (
            os.path.exists(os.path.join(repacked_info["binary_path"], delete_rel))
        )

    def test_handle_one_package_mv_and_repack(self) -> None:
        pkg_info = self._extract()
        old_path = self._first_binary_file(pkg_info)
        old_rel = os.path.relpath(old_path, pkg_info["binary_path"])
        new_rel = os.path.join("renamed", os.path.basename(old_path))
        new_path = os.path.join(pkg_info["binary_path"], new_rel)

        pkg_info["rule"] = {"mv": {old_path: new_path}}
        self.modify.handle_one_package(pkg_info)

        with ZipFile(self.pkg_path) as zf:
            assert zf.testzip() is None
            assert "metadata.json" in zf.namelist()

        repacked_info = self._extract(self.pkg_path)
        assert not (
            os.path.exists(os.path.join(repacked_info["binary_path"], old_rel))
        )
        assert os.path.exists(os.path.join(repacked_info["binary_path"], new_rel))

    def test_handle_one_package_keep_origin(self) -> None:
        pkg_info = self._extract()
        self.modify.args.keep_origin = True
        pkg_info["rule"] = {}

        self.modify.handle_one_package(pkg_info)

        assert os.path.isfile(self.pkg_path)
        assert os.path.isfile(self.pkg_path + ".bk")

    def test_get_paths_json_data(self) -> None:
        pkg_info = self._extract()
        path, data = self.modify.get_paths_json_data(pkg_info)
        assert path.endswith("paths.json")
        assert "paths" in data
        assert isinstance(data["paths"], list)
        assert len(data["paths"]) > 0

    def test_expand_pattern_rule(self) -> None:
        pkg_info = self._extract()
        rule = {"delete": ["**/*.py"]}
        files = self.modify.expand_pattern_rule(rule, "delete", pkg_info)
        assert len(files) > 0
        assert any(file.endswith(".py") for file in files)

    def test_get_spec_match_files(self) -> None:
        pkg_info = self._extract()
        spec = pathspec.PathSpec.from_lines(
            pathspec.patterns.gitwildmatch.GitWildMatchPattern,
            ["**/*.py"],
        )
        files = Modify.get_spec_match_files(pkg_info["binary_path"], spec, use_relative=True)
        assert len(files) > 0

    def test_pack_conda_produces_valid_zip(self) -> None:
        pkg_info = self._extract()
        out_file = os.path.join(self.tmpdir, "packed.conda")
        self.modify.pack_conda(out_file, pkg_info)

        assert os.path.isfile(out_file)
        with ZipFile(out_file) as zf:
            assert zf.testzip() is None
            assert "metadata.json" in zf.namelist()
            metadata = json.loads(zf.read("metadata.json").decode("utf-8"))
        assert "conda_pkg_format_version" in metadata

    def test_pack_bz2(self) -> None:
        bz2_path = self._make_tar_bz2_pkg()
        bz2_info = self.modify.get_pkg_info(bz2_path)
        self.modify.extract_pkg(bz2_info)

        out_file = os.path.join(self.tmpdir, "appdirs-1.4.4-repacked_0.tar.bz2")
        self.modify.pack_bz2(out_file, bz2_info)

        assert os.path.isfile(out_file)
        out_info = self.modify.get_pkg_info(out_file)
        self.modify.extract_pkg(out_info)
        assert os.path.isdir(out_info["real_info_path"])
        assert os.path.isfile(os.path.join(out_info["real_info_path"], "paths.json"))

    def test_handle_one_package_bz2_format(self) -> None:
        bz2_path = self._make_tar_bz2_pkg()
        args = argparse.Namespace(
            config_path=self.config_path,
            pkg_path=bz2_path,
            keep_origin=False,
        )
        bz2_modify = Modify(args)
        bz2_modify.config_path = self.config_path
        bz2_modify.pkg_path = bz2_path

        try:
            bz2_info = bz2_modify.get_pkg_info(bz2_path)
            bz2_modify.extract_pkg(bz2_info)
            source_file = os.path.join(self.tmpdir, "bz2-add.txt")
            Path(source_file).write_text("bz2-content", encoding="utf-8")
            added_abs_path = os.path.join(
                bz2_info["binary_path"], "added", "bz2-add.txt"
            )
            bz2_info["rule"] = {"add": {source_file: added_abs_path}}

            bz2_modify.handle_one_package(bz2_info)

            repacked_info = bz2_modify.get_pkg_info(bz2_path)
            bz2_modify.extract_pkg(repacked_info)
            assert (
                os.path.isfile(
                    os.path.join(repacked_info["binary_path"], "added", "bz2-add.txt")
                )
            )
        finally:
            bz2_modify.file_processor.shutdown()


class TestMain:
    def test_main_calls_setup_logging(self) -> None:
        fake_args = argparse.Namespace(config_path="a", pkg_path="b", keep_origin=False)

        with (
            mock.patch("conda_tool.modify.setup_logging") as mocked_setup_logging,
            mock.patch("conda_tool.modify.parse_args", return_value=fake_args),
            mock.patch("conda_tool.modify.Modify") as mocked_modify,
        ):
            main()

        mocked_setup_logging.assert_called_once_with(120)
        mocked_modify.assert_called_once_with(fake_args)
        mocked_modify.return_value.run.assert_called_once_with()
