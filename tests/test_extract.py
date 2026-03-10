import os
import sys
import tarfile
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock

from conda_tool.extract import Extractor, parse_args, parse_sh


class ParseArgsTests(unittest.TestCase):
    def test_clean_recreates_output_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            source_path = tmp_path / "installer.sh"
            output_dir = tmp_path / "out"
            source_path.write_text("#!/bin/sh\n", encoding="utf-8")
            output_dir.mkdir()
            stale_file = output_dir / "stale.txt"
            stale_file.write_text("stale", encoding="utf-8")

            with mock.patch.object(
                sys,
                "argv",
                [
                    "extract.py",
                    "--source",
                    str(source_path),
                    "--output",
                    str(output_dir),
                    "--clean",
                ],
            ):
                args = parse_args()

            self.assertEqual(args.source, os.path.abspath(source_path))
            self.assertEqual(args.output, os.path.abspath(output_dir))
            self.assertTrue(output_dir.is_dir())
            self.assertFalse(stale_file.exists())

    def test_rejects_output_path_that_is_not_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            source_path = tmp_path / "installer.sh"
            output_file = tmp_path / "not_a_dir"
            source_path.write_text("#!/bin/sh\n", encoding="utf-8")
            output_file.write_text("x", encoding="utf-8")

            with mock.patch.object(
                sys,
                "argv",
                [
                    "extract.py",
                    "--source",
                    str(source_path),
                    "--output",
                    str(output_file),
                ],
            ):
                with self.assertRaises(SystemExit):
                    parse_args()


class ParseShTests(unittest.TestCase):
    def test_parse_old_mode_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source_path = Path(tmp) / "old.sh"
            payload = b"payload-old"
            content = (
                b"#!/bin/sh\n"
                b"# NAME:  demo\n"
                b"# VER:   1.0\n"
                b"# PLAT:  linux-64\n"
                b"# BYTES: 000000001234\n"
                b"# LINES: 000000000123\n"
                b"# MD5:   deadbeef\n"
                b"@@END_HEADER@@\n"
                + payload
            )
            source_path.write_bytes(content)

            sh_data = parse_sh(str(source_path), output_msg=False)

            self.assertTrue(sh_data["old_mode"])
            self.assertEqual(sh_data["name"], b"demo")
            self.assertEqual(sh_data["version"], b"1.0")
            self.assertEqual(sh_data["platform"], b"linux-64")
            self.assertEqual(sh_data["pkgs_data"], payload)
            self.assertEqual(sh_data["conda_exec_data"], b"")
            self.assertEqual(sh_data["script_data"], content[:-len(payload)])

    def test_parse_new_mode_payload_and_conda_exec(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source_path = Path(tmp) / "new.sh"
            conda_exec = b"abcde"
            payload = b"01234567"
            header = (
                b"#!/bin/sh\n"
                b"# NAME:  demo\n"
                b"# VER:   2.0\n"
                b"# PLAT:  linux-64\n"
                b"# MD5:   deadbeef\n"
                b"boundary1=x 5 y\n"
                b"boundary2=x 8 y\n"
                b"@@END_HEADER@@\n"
            )
            source_path.write_bytes(header + conda_exec + payload)

            sh_data = parse_sh(str(source_path), output_msg=False)

            self.assertFalse(sh_data["old_mode"])
            self.assertEqual(sh_data["conda_exec_data"], conda_exec)
            self.assertEqual(sh_data["pkgs_data"], payload)
            self.assertEqual(sh_data["script_data"], header)

    def test_parse_sh_requires_header_terminator(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source_path = Path(tmp) / "broken.sh"
            source_path.write_bytes(b"#!/bin/sh\n# NAME:  demo\n")

            with self.assertRaisesRegex(ValueError, "未找到 header 结束标记"):
                parse_sh(str(source_path), output_msg=False)

    def test_parse_sh_requires_boundaries_for_new_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source_path = Path(tmp) / "broken.sh"
            source_path.write_bytes(
                b"#!/bin/sh\n"
                b"# NAME:  demo\n"
                b"# VER:   2.0\n"
                b"# PLAT:  linux-64\n"
                b"# MD5:   deadbeef\n"
                b"@@END_HEADER@@\n"
                b"payload"
            )

            with self.assertRaisesRegex(ValueError, "缺少 boundary 信息"):
                parse_sh(str(source_path), output_msg=False)


class MakeRepoTests(unittest.TestCase):
    def make_extractor(self, output_dir: Path) -> Extractor:
        return Extractor(
            Namespace(
                source=str(output_dir / "installer.sh"),
                output=str(output_dir),
                keep_tar=True,
                generate_repo=True,
            )
        )

    def test_make_repo_organizes_packages_from_urls_txt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            pkgs_output_dir = tmp_path / "workdir"
            conda_pkgs_dir = pkgs_output_dir / "pkgs"
            conda_pkgs_dir.mkdir(parents=True)
            (conda_pkgs_dir / "urls.txt").write_text(
                "https://repo.anaconda.com/pkgs/main/linux-64/foo-1.0-0.tar.bz2\n"
                "https://repo.anaconda.com/pkgs/main/noarch/bar-1.0-0.conda\n",
                encoding="utf-8",
            )
            (conda_pkgs_dir / "foo-1.0-0.tar.bz2").write_bytes(b"foo")
            (conda_pkgs_dir / "bar-1.0-0.conda").write_bytes(b"bar")
            (conda_pkgs_dir / "unknown-1.0-0.conda").write_bytes(b"unknown")

            extractor = self.make_extractor(tmp_path)
            extractor.make_repo(str(conda_pkgs_dir), str(pkgs_output_dir))

            self.assertTrue(
                (conda_pkgs_dir / "linux-64" / "foo-1.0-0.tar.bz2").exists()
            )
            self.assertTrue((conda_pkgs_dir / "noarch" / "bar-1.0-0.conda").exists())
            self.assertTrue((conda_pkgs_dir / "unknown-1.0-0.conda").exists())

    def test_make_repo_extracts_preconda_tar_when_urls_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            pkgs_output_dir = tmp_path / "workdir"
            conda_pkgs_dir = pkgs_output_dir / "pkgs"
            conda_pkgs_dir.mkdir(parents=True)
            package_name = "foo-1.0-0.tar.bz2"
            (conda_pkgs_dir / package_name).write_bytes(b"foo")

            with tempfile.TemporaryDirectory() as tar_tmp:
                tar_tmp_path = Path(tar_tmp)
                preconda_root = tar_tmp_path / "preconda_src"
                urls_dir = preconda_root / "pkgs"
                urls_dir.mkdir(parents=True)
                (urls_dir / "urls.txt").write_text(
                    f"https://repo.anaconda.com/pkgs/main/linux-64/{package_name}\n",
                    encoding="utf-8",
                )
                with tarfile.open(pkgs_output_dir / "preconda.tar.bz2", "w:bz2") as tar:
                    tar.add(urls_dir, arcname="pkgs")

            extractor = self.make_extractor(tmp_path)
            extractor.make_repo(str(conda_pkgs_dir), str(pkgs_output_dir))

            self.assertTrue((conda_pkgs_dir / "linux-64" / package_name).exists())
            self.assertFalse((pkgs_output_dir / "preconda").exists())

    def test_make_repo_requires_metadata_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            pkgs_output_dir = tmp_path / "workdir"
            conda_pkgs_dir = pkgs_output_dir / "pkgs"
            conda_pkgs_dir.mkdir(parents=True)

            extractor = self.make_extractor(tmp_path)

            with self.assertRaisesRegex(FileNotFoundError, "urls.txt 或 preconda.tar.bz2"):
                extractor.make_repo(str(conda_pkgs_dir), str(pkgs_output_dir))


if __name__ == "__main__":
    unittest.main()
