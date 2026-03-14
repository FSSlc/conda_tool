import hashlib
import os
import sys
import tarfile
import tempfile
from pathlib import Path
from unittest import mock

import pytest

from conda_tool.repack import (
    extract_sh_package,
    main,
    modify_package_content,
    parse_args,
    repack_sh_package,
)
from conda_tool.utils import setup_logging

setup_logging(120)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_old_mode_sh(directory: str, *, name: str = "test.sh") -> str:
    """Create a minimal old-mode constructor .sh file with a valid tar payload."""
    sh_path = os.path.join(directory, name)

    # Build a small tar payload
    tar_path = os.path.join(directory, "_payload.tar")
    data_file = os.path.join(directory, "hello.txt")
    Path(data_file).write_text("hello-world", encoding="utf-8")
    with tarfile.open(tar_path, "w") as tar:
        tar.add(data_file, arcname="pkgs/hello.txt")
    with open(tar_path, "rb") as f:
        payload = f.read()

    payload_md5 = hashlib.md5(payload).hexdigest()

    bytes_placeholder = str(0).rjust(12)
    lines = [
        b"#!/bin/sh",
        b"# NAME:  testpkg",
        b"# VER:   1.0",
        b"# PLAT:  linux-64",
        b"# BYTES: " + bytes_placeholder.encode(),
        b"# LINES: 000000000010",
        b"# MD5:   " + payload_md5.encode(),
        b"@@END_HEADER@@",
    ]
    header = b"\n".join(lines) + b"\n"

    total_size = len(header) + len(payload)
    # Patch BYTES to reflect the total .sh size
    header = header.replace(
        b"# BYTES: " + bytes_placeholder.encode(),
        b"# BYTES: " + str(total_size).rjust(12).encode(),
    )

    with open(sh_path, "wb") as f:
        f.write(header)
        f.write(payload)
    os.chmod(sh_path, 0o755)

    # Cleanup temp tar
    os.unlink(tar_path)
    os.unlink(data_file)
    return sh_path


def _make_new_mode_sh(directory: str, *, name: str = "test.sh") -> str:
    """Create a minimal new-mode constructor .sh file (boundary1/boundary2)."""
    sh_path = os.path.join(directory, name)

    conda_exec = b"CONDA_EXEC_PLACEHOLDER"

    # Build a small tar payload
    tar_path = os.path.join(directory, "_payload.tar")
    data_file = os.path.join(directory, "hello.txt")
    Path(data_file).write_text("hello-world-new", encoding="utf-8")
    with tarfile.open(tar_path, "w") as tar:
        tar.add(data_file, arcname="pkgs/hello.txt")
    with open(tar_path, "rb") as f:
        payload = f.read()

    payload_md5 = hashlib.md5(payload).hexdigest()

    lines = [
        b"#!/bin/sh",
        b"# NAME:  testpkg",
        b"# VER:   2.0",
        b"# PLAT:  linux-64",
        b"# MD5:   " + payload_md5.encode(),
        b"boundary1=x " + str(len(conda_exec)).encode() + b" y",
        b"boundary2=x " + str(len(payload)).encode() + b" y",
        b"@@END_HEADER@@",
    ]
    header = b"\n".join(lines) + b"\n"

    with open(sh_path, "wb") as f:
        f.write(header)
        f.write(conda_exec)
        f.write(payload)
    os.chmod(sh_path, 0o755)

    os.unlink(tar_path)
    os.unlink(data_file)
    return sh_path


# ---------------------------------------------------------------------------
# parse_args tests
# ---------------------------------------------------------------------------

class TestParseArgs:
    def test_default_output_name(self) -> None:
        """Output defaults to mod-<source_basename> in the source's directory."""
        with tempfile.TemporaryDirectory() as tmp:
            source = _make_old_mode_sh(tmp, name="installer.sh")
            config = os.path.join(tmp, "rules.json")
            Path(config).write_text("{}", encoding="utf-8")

            with mock.patch.object(
                sys, "argv", ["repack.py", "-s", source, "-c", config]
            ):
                args = parse_args()

            assert os.path.basename(args.output) == "mod-installer.sh"
            assert os.path.dirname(args.output) == os.path.dirname(args.source)

    def test_explicit_output_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = _make_old_mode_sh(tmp, name="installer.sh")
            config = os.path.join(tmp, "rules.json")
            out = os.path.join(tmp, "custom-output.sh")
            Path(config).write_text("{}", encoding="utf-8")

            with mock.patch.object(
                sys,
                "argv",
                ["repack.py", "-s", source, "-c", config, "-o", out],
            ):
                args = parse_args()

            assert args.output == os.path.abspath(out)

    def test_missing_source_exits(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = os.path.join(tmp, "rules.json")
            Path(config).write_text("{}", encoding="utf-8")

            with mock.patch.object(
                sys,
                "argv",
                ["repack.py", "-s", "/no/such/file.sh", "-c", config],
            ):
                with pytest.raises(SystemExit):
                    parse_args()

    def test_missing_config_exits(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = _make_old_mode_sh(tmp)

            with mock.patch.object(
                sys,
                "argv",
                ["repack.py", "-s", source, "-c", "/no/such/config.json"],
            ):
                with pytest.raises(SystemExit):
                    parse_args()

    def test_output_already_exists_exits(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = _make_old_mode_sh(tmp)
            config = os.path.join(tmp, "rules.json")
            out = os.path.join(tmp, "existing.sh")
            Path(config).write_text("{}", encoding="utf-8")
            Path(out).write_text("occupied", encoding="utf-8")

            with mock.patch.object(
                sys,
                "argv",
                ["repack.py", "-s", source, "-c", config, "-o", out],
            ):
                with pytest.raises(SystemExit):
                    parse_args()

    def test_paths_are_resolved_to_absolute(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = _make_old_mode_sh(tmp)
            config = os.path.join(tmp, "rules.json")
            Path(config).write_text("{}", encoding="utf-8")

            with mock.patch.object(
                sys, "argv", ["repack.py", "-s", source, "-c", config]
            ):
                args = parse_args()

            assert os.path.isabs(args.source)
            assert os.path.isabs(args.config)
            assert os.path.isabs(args.output)


# ---------------------------------------------------------------------------
# extract_sh_package tests
# ---------------------------------------------------------------------------

class TestExtractShPackage:
    def test_extracts_old_mode_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = _make_old_mode_sh(tmp)
            out_dir = os.path.join(tmp, "extracted")
            os.makedirs(out_dir)

            extract_sh_package(source, out_dir)

            # The extract module should have produced a tpl.sh and workdir
            assert os.path.isfile(os.path.join(out_dir, "tpl.sh"))
            workdir = os.path.join(out_dir, "workdir")
            assert os.path.isdir(workdir)

    def test_extracts_new_mode_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = _make_new_mode_sh(tmp)
            out_dir = os.path.join(tmp, "extracted")
            os.makedirs(out_dir)

            extract_sh_package(source, out_dir)

            assert os.path.isfile(os.path.join(out_dir, "tpl.sh"))
            assert os.path.isfile(os.path.join(out_dir, "_conda"))
            workdir = os.path.join(out_dir, "workdir")
            assert os.path.isdir(workdir)

    def test_restores_sys_argv_on_success(self) -> None:
        original_argv = sys.argv[:]
        with tempfile.TemporaryDirectory() as tmp:
            source = _make_old_mode_sh(tmp)
            out_dir = os.path.join(tmp, "extracted")
            os.makedirs(out_dir)

            extract_sh_package(source, out_dir)

        assert sys.argv == original_argv

    def test_restores_sys_argv_on_failure(self) -> None:
        original_argv = sys.argv[:]
        with tempfile.TemporaryDirectory() as tmp:
            try:
                extract_sh_package("/nonexistent/file.sh", tmp)
            except (SystemExit, Exception):
                pass

        assert sys.argv == original_argv


# ---------------------------------------------------------------------------
# modify_package_content tests
# ---------------------------------------------------------------------------

class TestModifyPackageContent:
    def test_calls_modify_main_with_correct_argv(self) -> None:
        """Verify sys.argv is set up correctly and restored."""
        with tempfile.TemporaryDirectory() as tmp:
            work_dir = tmp
            config_path = os.path.join(tmp, "rules.json")
            Path(config_path).write_text("{}", encoding="utf-8")
            expected_pkg_path = os.path.join(work_dir, "workdir", "pkgs")
            os.makedirs(expected_pkg_path, exist_ok=True)

            captured_argv = []
            original_argv = sys.argv[:]

            with mock.patch("conda_tool.modify.main") as mocked:
                def capture_and_noop():
                    captured_argv.extend(sys.argv)

                mocked.side_effect = capture_and_noop
                modify_package_content(work_dir, config_path)

            assert sys.argv == original_argv
            assert captured_argv[0] == "modify.py"
            assert "-c" in captured_argv
            assert config_path in captured_argv
            assert "-s" in captured_argv
            assert expected_pkg_path in captured_argv

    def test_restores_sys_argv_on_failure(self) -> None:
        original_argv = sys.argv[:]
        with tempfile.TemporaryDirectory() as tmp:
            config_path = os.path.join(tmp, "rules.json")
            Path(config_path).write_text("{}", encoding="utf-8")

            with mock.patch("conda_tool.modify.main", side_effect=RuntimeError("boom")):
                try:
                    modify_package_content(tmp, config_path)
                except RuntimeError:
                    pass

        assert sys.argv == original_argv


# ---------------------------------------------------------------------------
# repack_sh_package tests
# ---------------------------------------------------------------------------

class TestRepackShPackage:
    def test_repack_old_mode_produces_valid_sh(self) -> None:
        """Extract an old-mode .sh then repack; verify the output is parseable."""
        from conda_tool.extract import parse_sh

        with tempfile.TemporaryDirectory() as tmp:
            source = _make_old_mode_sh(tmp)
            work_dir = os.path.join(tmp, "work")
            os.makedirs(work_dir)

            # Extract first
            extract_sh_package(source, work_dir)

            output = os.path.join(tmp, "repacked.sh")
            repack_sh_package(source, work_dir, output)

            assert os.path.isfile(output)
            assert os.access(output, os.X_OK)

            # The repacked file should be parseable
            sh_data = parse_sh(output, output_msg=False)
            assert sh_data["name"] == b"testpkg"
            assert sh_data["old_mode"] is True
            assert len(sh_data["pkgs_data"]) > 0

    def test_repack_new_mode_produces_valid_sh(self) -> None:
        from conda_tool.extract import parse_sh

        with tempfile.TemporaryDirectory() as tmp:
            source = _make_new_mode_sh(tmp)
            work_dir = os.path.join(tmp, "work")
            os.makedirs(work_dir)

            extract_sh_package(source, work_dir)

            output = os.path.join(tmp, "repacked.sh")
            repack_sh_package(source, work_dir, output)

            assert os.path.isfile(output)
            assert os.access(output, os.X_OK)

            sh_data = parse_sh(output, output_msg=False)
            assert sh_data["name"] == b"testpkg"
            assert sh_data["old_mode"] is False
            assert len(sh_data["pkgs_data"]) > 0
            assert len(sh_data["conda_exec_data"]) > 0

    def test_repack_updates_md5_in_header(self) -> None:
        """The repacked .sh should have an updated MD5 matching the new payload."""
        from conda_tool.extract import parse_sh

        with tempfile.TemporaryDirectory() as tmp:
            source = _make_old_mode_sh(tmp)
            work_dir = os.path.join(tmp, "work")
            os.makedirs(work_dir)

            extract_sh_package(source, work_dir)

            # Add a file to the workdir to change payload content
            extra = os.path.join(work_dir, "workdir", "extra.txt")
            Path(extra).write_text("extra-content", encoding="utf-8")

            output = os.path.join(tmp, "repacked.sh")
            repack_sh_package(source, work_dir, output)

            sh_data = parse_sh(output, output_msg=False)
            # MD5 in header should differ from original since payload changed
            original_data = parse_sh(source, output_msg=False)
            assert sh_data["md5"] != original_data["md5"]

    def test_repack_updates_bytes_in_header(self) -> None:
        """The BYTES field in the repacked header should match the file size."""
        from conda_tool.extract import parse_sh

        with tempfile.TemporaryDirectory() as tmp:
            source = _make_old_mode_sh(tmp)
            work_dir = os.path.join(tmp, "work")
            os.makedirs(work_dir)

            extract_sh_package(source, work_dir)

            output = os.path.join(tmp, "repacked.sh")
            repack_sh_package(source, work_dir, output)

            sh_data = parse_sh(output, output_msg=False)
            file_size = os.path.getsize(output)
            header_bytes = int(sh_data["bytes"].strip())
            assert header_bytes == file_size

    def test_repack_cleans_up_bak_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = _make_old_mode_sh(tmp)
            work_dir = os.path.join(tmp, "work")
            os.makedirs(work_dir)

            extract_sh_package(source, work_dir)

            output = os.path.join(tmp, "repacked.sh")
            repack_sh_package(source, work_dir, output)

            assert not os.path.exists(output + ".bak")

    def test_repack_payload_contains_workdir_content(self) -> None:
        """Verify the repacked payload tar includes workdir items."""
        from conda_tool.extract import parse_sh

        with tempfile.TemporaryDirectory() as tmp:
            source = _make_old_mode_sh(tmp)
            work_dir = os.path.join(tmp, "work")
            os.makedirs(work_dir)

            extract_sh_package(source, work_dir)

            output = os.path.join(tmp, "repacked.sh")
            repack_sh_package(source, work_dir, output)

            # Extract the payload from the repacked file
            sh_data = parse_sh(output, output_msg=False)
            payload_tar_path = os.path.join(tmp, "payload_check.tar")
            with open(payload_tar_path, "wb") as f:
                f.write(sh_data["pkgs_data"])

            with tarfile.open(payload_tar_path, "r") as tar:
                names = tar.getnames()
                # The workdir should have had pkgs/ with hello.txt
                assert any("pkgs" in n for n in names)


# ---------------------------------------------------------------------------
# main() tests
# ---------------------------------------------------------------------------

class TestMain:
    def test_main_calls_setup_logging(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = _make_old_mode_sh(tmp)
            config = os.path.join(tmp, "rules.json")
            Path(config).write_text("{}", encoding="utf-8")
            output = os.path.join(tmp, "out.sh")

            with (
                mock.patch(
                    "conda_tool.repack.setup_logging"
                ) as mocked_logging,
                mock.patch(
                    "conda_tool.repack.parse_args",
                    return_value=mock.MagicMock(
                        source=source, config=config, output=output
                    ),
                ),
                mock.patch("conda_tool.repack.extract_sh_package"),
                mock.patch("conda_tool.repack.modify_package_content"),
                mock.patch("conda_tool.repack.repack_sh_package"),
            ):
                main()

            mocked_logging.assert_called_once_with(120)

    def test_main_orchestrates_extract_modify_repack(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = _make_old_mode_sh(tmp)
            config = os.path.join(tmp, "rules.json")
            Path(config).write_text("{}", encoding="utf-8")
            output = os.path.join(tmp, "out.sh")

            fake_args = mock.MagicMock(
                source=source, config=config, output=output
            )
            call_order = []

            with (
                mock.patch("conda_tool.repack.setup_logging"),
                mock.patch("conda_tool.repack.parse_args", return_value=fake_args),
                mock.patch(
                    "conda_tool.repack.extract_sh_package",
                    side_effect=lambda *a: call_order.append("extract"),
                ) as mock_extract,
                mock.patch(
                    "conda_tool.repack.modify_package_content",
                    side_effect=lambda *a: call_order.append("modify"),
                ) as mock_modify,
                mock.patch(
                    "conda_tool.repack.repack_sh_package",
                    side_effect=lambda *a: call_order.append("repack"),
                ) as mock_repack,
            ):
                main()

            mock_extract.assert_called_once()
            mock_modify.assert_called_once()
            mock_repack.assert_called_once()
            assert call_order == ["extract", "modify", "repack"]

    def test_main_exits_on_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = _make_old_mode_sh(tmp)
            config = os.path.join(tmp, "rules.json")
            Path(config).write_text("{}", encoding="utf-8")
            output = os.path.join(tmp, "out.sh")

            fake_args = mock.MagicMock(
                source=source, config=config, output=output
            )

            with (
                mock.patch("conda_tool.repack.setup_logging"),
                mock.patch("conda_tool.repack.parse_args", return_value=fake_args),
                mock.patch(
                    "conda_tool.repack.extract_sh_package",
                    side_effect=RuntimeError("extraction failed"),
                ),
            ):
                with pytest.raises(SystemExit) as exc_info:
                    main()
                assert exc_info.value.code == 1


# ---------------------------------------------------------------------------
# End-to-end integration test
# ---------------------------------------------------------------------------

class TestEndToEnd:
    def test_full_repack_pipeline_old_mode(self) -> None:
        """Full pipeline: create .sh -> extract -> repack -> verify."""
        from conda_tool.extract import parse_sh

        with tempfile.TemporaryDirectory() as tmp:
            source = _make_old_mode_sh(tmp)
            work_dir = os.path.join(tmp, "work")
            os.makedirs(work_dir)

            # Step 1: Extract
            extract_sh_package(source, work_dir)

            # Step 2: Add new content to simulate a modification
            new_file = os.path.join(work_dir, "workdir", "pkgs", "added.txt")
            Path(new_file).write_text("new-content", encoding="utf-8")

            # Step 3: Repack
            output = os.path.join(tmp, "final.sh")
            repack_sh_package(source, work_dir, output)

            # Verify output
            assert os.path.isfile(output)
            sh_data = parse_sh(output, output_msg=False)

            # Extract the payload and verify new file is present
            payload_tar = os.path.join(tmp, "verify.tar")
            with open(payload_tar, "wb") as f:
                f.write(sh_data["pkgs_data"])
            with tarfile.open(payload_tar, "r") as tar:
                names = tar.getnames()
                assert any("added.txt" in n for n in names)

            # BYTES matches actual file size
            file_size = os.path.getsize(output)
            header_bytes = int(sh_data["bytes"].strip())
            assert header_bytes == file_size

    def test_full_repack_pipeline_new_mode(self) -> None:
        from conda_tool.extract import parse_sh

        with tempfile.TemporaryDirectory() as tmp:
            source = _make_new_mode_sh(tmp)
            work_dir = os.path.join(tmp, "work")
            os.makedirs(work_dir)

            extract_sh_package(source, work_dir)

            new_file = os.path.join(work_dir, "workdir", "pkgs", "added.txt")
            Path(new_file).write_text("new-content", encoding="utf-8")

            output = os.path.join(tmp, "final.sh")
            repack_sh_package(source, work_dir, output)

            assert os.path.isfile(output)
            sh_data = parse_sh(output, output_msg=False)
            assert sh_data["old_mode"] is False
            assert len(sh_data["conda_exec_data"]) > 0

            payload_tar = os.path.join(tmp, "verify.tar")
            with open(payload_tar, "wb") as f:
                f.write(sh_data["pkgs_data"])
            with tarfile.open(payload_tar, "r") as tar:
                names = tar.getnames()
                assert any("added.txt" in n for n in names)
