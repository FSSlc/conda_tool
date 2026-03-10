import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from typing import get_type_hints
from unittest import mock

from conda_tool import dlpkg


class DownloadPkgTests(unittest.TestCase):
    def make_downloader(self, tmp_path: Path) -> dlpkg.DownloadPkg:
        manager_patcher = mock.patch.object(dlpkg, "Manager")
        mocked_manager = manager_patcher.start()
        self.addCleanup(manager_patcher.stop)
        mocked_manager.return_value.list.return_value = []

        args = Namespace(
            PKGNAME="demo",
            upper_bound=None,
            py="310",
            subdir="linux-64",
            ignore_py=False,
            interact=False,
            specs_dir=str(tmp_path / "specs"),
            workdir=str(tmp_path / "workdir"),
            recipes_dir=str(tmp_path / "recipes"),
            pkgs_dir=str(tmp_path / "pkgs"),
        )
        return dlpkg.DownloadPkg(args)

    def test_download_file_skips_existing_file_without_hash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            out_dir = tmp_path / "pkgs"
            out_dir.mkdir()
            existing_file = out_dir / "source.tar.gz"
            existing_file.write_bytes(b"existing")
            downloader = self.make_downloader(tmp_path)

            with mock.patch.object(downloader, "local_download") as mocked_download:
                downloader.download_file(
                    (
                        dlpkg.SourceUrlSpec(
                            url = "https://example.com/source.tar.gz",
                            fn = "source.tar.gz",
                            hash_type=None, hash=None
                        ),
                        None,
                        str(out_dir),
                    )
                )

            mocked_download.assert_not_called()
            self.assertEqual(existing_file.read_bytes(), b"existing")

    def test_get_url_block_handles_multiline_block_at_file_end(self) -> None:
        content = [
            "source:",
            "  url:",
            "    https://example.com/source.tar.gz",
            "",
        ]

        blocks = dlpkg.DownloadPkg.get_url_block(content)

        self.assertEqual(blocks, [[1, 4]])

    def test_get_new_contents_preserves_unmatched_url_block(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            downloader = self.make_downloader(tmp_path)
            content = [
                "package:",
                "source:",
                "  url: https://example.com/a.tar.gz",
                "",
                "about:",
                "source:",
                "  url: https://example.com/b.tar.gz",
                "",
            ]
            url_blocks = dlpkg.DownloadPkg.get_url_block(content)
            meta_yaml_tpl = str(tmp_path / "recipes" / "demo" / "meta.yaml.template")
            url_specs = [
                dlpkg.SourceUrlSpec(
                    url = "https://example.com/a.tar.gz",
                    hash_type = "md5",
                    hash= "hash-a",
                    fn = "a.tar.gz",
                )
            ]

            new_contents = downloader.get_new_contents(
                content, url_blocks, url_specs, meta_yaml_tpl
            )

            self.assertTrue(any("a.tar.gz" in line for line in new_contents))
            self.assertIn("about:", new_contents)
            self.assertIn("  url: https://example.com/b.tar.gz", new_contents)

    def test_core_methods_expose_precise_type_hints(self) -> None:
        get_pkg_spec_hints = get_type_hints(dlpkg.DownloadPkg.get_pkg_spec)
        download_file_hints = get_type_hints(dlpkg.DownloadPkg.download_file)
        unpack_recipe_hints = get_type_hints(dlpkg.DownloadPkg.unpack_recipe)

        self.assertIs(get_pkg_spec_hints["return"], dlpkg.PackageSpec)
        self.assertEqual(download_file_hints["para_pairs"], dlpkg.DownloadTask)
        self.assertEqual(unpack_recipe_hints["return"], dlpkg.RecipePaths)


if __name__ == "__main__":
    unittest.main()
