import os
import tempfile
from argparse import Namespace
from pathlib import Path
from typing import get_type_hints
from unittest import mock

from conda_tool import dlpkg


class DownloadPkgTests:
    def make_downloader(self, tmp_path: Path) -> dlpkg.DownloadPkg:
        mocked_manager = mock.Mock()
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
        with mock.patch.object(dlpkg, "Manager", mocked_manager):
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
            assert existing_file.read_bytes() == b"existing"

    def test_core_methods_expose_precise_type_hints(self) -> None:
        get_pkg_spec_hints = get_type_hints(dlpkg.DownloadPkg.get_pkg_spec)
        download_file_hints = get_type_hints(dlpkg.DownloadPkg.download_file)
        unpack_recipe_hints = get_type_hints(dlpkg.DownloadPkg.unpack_recipe)

        assert get_pkg_spec_hints["return"] is dlpkg.PackageSpec
        assert download_file_hints["para_pairs"] == dlpkg.DownloadTask
        assert unpack_recipe_hints["return"] == dlpkg.RecipePaths

    def test_load_urls_meta_yaml(self) -> None:
        content = """\
package:
  name: demo
  version: "1.0"

source:
  url: https://example.com/demo-1.0.tar.gz
  sha256: abc123
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "meta.yaml")
            Path(path).write_text(content, encoding="utf-8")
            urls = dlpkg.DownloadPkg.load_urls(path)

        assert len(urls) == 1
        assert urls[0]["url"] == "https://example.com/demo-1.0.tar.gz"
        assert urls[0]["hash_type"] == "sha256"
        assert urls[0]["hash"] == "abc123"

    def test_load_urls_meta_yaml_jinja2(self) -> None:
        content = """\
{% set version = "2.0" %}

package:
  name: curl
  version: {{ version }}

source:
  url: https://curl.haxx.se/download/curl-{{ version }}.tar.bz2
  sha256: deadbeef
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "meta.yaml")
            Path(path).write_text(content, encoding="utf-8")
            urls = dlpkg.DownloadPkg.load_urls(path)

        assert len(urls) == 1
        assert "{{ version }}" in urls[0]["url"]
        assert "curl.haxx.se" in urls[0]["url"]

    def test_load_urls_recipe_yaml(self) -> None:
        content = """\
context:
  version: "3.0"

package:
  name: pandas
  version: ${{ version }}

source:
  url: https://example.com/pandas-${{ version }}.tar.gz
  sha256: aabbcc
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "recipe.yaml")
            Path(path).write_text(content, encoding="utf-8")
            urls = dlpkg.DownloadPkg.load_urls(path)

        assert len(urls) == 1
        assert "${{ version }}" in urls[0]["url"]

    def test_replace_urls_meta_yaml(self) -> None:
        content = """\
package:
  name: demo
  version: "1.0"

source:
  url: https://example.com/demo-1.0.tar.gz
  sha256: abc123
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tpl_path = os.path.join(tmpdir, "meta.yaml.template")
            Path(tpl_path).write_text(content, encoding="utf-8")
            pkgs_dir = os.path.join(tmpdir, "pkgs")
            os.makedirs(pkgs_dir)

            tmp_path = Path(tmpdir)
            downloader = self.make_downloader(tmp_path)
            downloader.pkgs_dir = pkgs_dir

            url_specs = [
                dlpkg.SourceUrlSpec(
                    url="https://example.com/demo-1.0.tar.gz",
                    hash_type="sha256",
                    hash="abc123",
                    fn="demo-1.0.tar.gz",
                )
            ]
            downloader.replace_urls(tpl_path, url_specs)

            result = Path(tpl_path).read_text(encoding="utf-8")

        assert "demo-1.0.tar.gz" in result
        assert "original:" in result

    def test_replace_urls_recipe_yaml(self) -> None:
        content = """\
context:
  version: "3.0"

package:
  name: pandas
  version: ${{ version }}

source:
  url: https://example.com/pandas-${{ version }}.tar.gz
  sha256: aabbcc
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tpl_path = os.path.join(tmpdir, "recipe.yaml.template")
            Path(tpl_path).write_text(content, encoding="utf-8")
            pkgs_dir = os.path.join(tmpdir, "pkgs")
            os.makedirs(pkgs_dir)

            tmp_path = Path(tmpdir)
            downloader = self.make_downloader(tmp_path)
            downloader.pkgs_dir = pkgs_dir

            url_specs = [
                dlpkg.SourceUrlSpec(
                    url="https://example.com/pandas-3.0.tar.gz",
                    hash_type="sha256",
                    hash="aabbcc",
                    fn="pandas-3.0.tar.gz",
                )
            ]
            downloader.replace_urls(tpl_path, url_specs)

            result = Path(tpl_path).read_text(encoding="utf-8")

        assert "pandas-3.0.tar.gz" in result
        assert "${{ version }}" in result

    def test_extract_reqs_meta_yaml(self) -> None:
        content = """\
package:
  name: demo
  version: "1.0"

requirements:
  host:
    - python
  run:
    - python
    - numpy
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "meta.yaml")
            Path(path).write_text(content, encoding="utf-8")
            reqs = dlpkg.DownloadPkg.extract_reqs(path)

        assert "requirements" in reqs
        assert "python" in reqs
        assert "numpy" in reqs

    def test_extract_reqs_recipe_yaml(self) -> None:
        content = """\
context:
  version: "1.0"

package:
  name: demo
  version: ${{ version }}

requirements:
  host:
    - python
  run:
    - python
    - pandas
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "recipe.yaml")
            Path(path).write_text(content, encoding="utf-8")
            reqs = dlpkg.DownloadPkg.extract_reqs(path)

        assert "requirements" in reqs
        assert "pandas" in reqs

    def test_find_recipe_file_prefers_recipe_yaml(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(os.path.join(tmpdir, "meta.yaml")).write_text("x: 1", encoding="utf-8")
            Path(os.path.join(tmpdir, "recipe.yaml")).write_text("x: 1", encoding="utf-8")

            recipe_file, recipe_tpl = dlpkg.DownloadPkg._find_recipe_file(
                tmpdir, tmpdir, is_parent=False
            )

        assert recipe_file.endswith("recipe.yaml")
        assert recipe_tpl.endswith("recipe.yaml.template")

    def test_find_recipe_file_falls_back_to_meta_yaml(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(os.path.join(tmpdir, "meta.yaml")).write_text("x: 1", encoding="utf-8")

            recipe_file, recipe_tpl = dlpkg.DownloadPkg._find_recipe_file(
                tmpdir, tmpdir, is_parent=False
            )

        assert recipe_file.endswith("meta.yaml")
        assert recipe_tpl.endswith("meta.yaml.template")

    def test_find_recipe_file_parent_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            src = os.path.join(tmpdir, "src")
            dst = os.path.join(tmpdir, "dst")
            os.makedirs(src)
            os.makedirs(dst)
            Path(os.path.join(dst, "meta.yaml")).write_text("x: 1", encoding="utf-8")

            recipe_file, recipe_tpl = dlpkg.DownloadPkg._find_recipe_file(
                src, dst, is_parent=True
            )

        assert "src" in recipe_file
        assert "dst" in recipe_tpl

