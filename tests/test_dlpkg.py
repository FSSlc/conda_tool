import os
import tempfile
from argparse import Namespace
from pathlib import Path
from typing import get_type_hints
from unittest import mock

import aiohttp

from conda_tool import dlpkg


def make_args(tmp_path: Path, **overrides: object) -> Namespace:
    args = {
        "PKGNAME": "demo",
        "upper_bound": None,
        "py": "310",
        "subdir": "linux-64",
        "ignore_py": False,
        "interact": False,
        "specs_dir": str(tmp_path / "specs"),
        "spec_source": "auto",
        "prefix_dev_url": "https://prefix.dev",
        "prefix_dev_channel": "conda-forge",
        "prefix_dev_timeout": 30,
        "workdir": str(tmp_path / "workdir"),
        "recipes_dir": str(tmp_path / "recipes"),
        "pkgs_dir": str(tmp_path / "pkgs"),
    }
    args.update(overrides)
    return Namespace(**args)


def test_downloadpkg_init_uses_plain_error_list(tmp_path: Path) -> None:
    downloader = dlpkg.DownloadPkg(make_args(tmp_path))

    assert downloader.errors == []
    assert isinstance(downloader.errors, list)


def test_load_pkg_specs_uses_prefix_shards_when_available(tmp_path: Path) -> None:
    downloader = dlpkg.DownloadPkg(make_args(tmp_path, spec_source="auto"))
    remote_specs = [
        {
            "name": "demo",
            "version": "1.2.3",
            "nv": "demo-1.2.3",
            "md5": "abc",
            "build": "py310_0",
            "subdir": "linux-64",
            "url": "https://prefix.dev/conda-forge/linux-64/demo-1.2.3-py310_0.conda",
            "timestamp": 123,
        }
    ]

    with (
        mock.patch.object(
            downloader, "load_pkg_specs_from_prefix_shards", return_value=remote_specs
        ) as mocked_remote,
        mock.patch.object(
            downloader, "load_pkg_specs_from_local_db"
        ) as mocked_local,
    ):
        specs = downloader.load_pkg_specs()

    assert specs == remote_specs
    mocked_remote.assert_called_once_with()
    mocked_local.assert_not_called()


def test_load_pkg_specs_falls_back_to_local_on_shard_error(tmp_path: Path) -> None:
    downloader = dlpkg.DownloadPkg(make_args(tmp_path, spec_source="auto"))
    local_specs = [
        {
            "name": "demo",
            "version": "1.0.0",
            "nv": "demo-1.0.0",
            "md5": "def",
            "build": "0",
            "subdir": "linux-64",
            "url": "https://example.invalid/demo-1.0.0.conda",
            "timestamp": 1,
        }
    ]

    with (
        mock.patch.object(
            downloader,
            "load_pkg_specs_from_prefix_shards",
            side_effect=aiohttp.ClientError("network down"),
        ) as mocked_remote,
        mock.patch.object(
            downloader, "load_pkg_specs_from_local_db", return_value=local_specs
        ) as mocked_local,
    ):
        specs = downloader.load_pkg_specs()

    assert specs == local_specs
    mocked_remote.assert_called_once_with()
    mocked_local.assert_called_once_with()


def test_load_pkg_specs_from_prefix_shards_merges_subdir_and_noarch(
    tmp_path: Path,
) -> None:
    downloader = dlpkg.DownloadPkg(make_args(tmp_path, spec_source="prefix-shards"))

    with mock.patch.object(
        downloader,
        "_fetch_prefix_shard_specs",
        side_effect=[
            [
                {
                    "name": "demo",
                    "version": "2.0.0",
                    "nv": "demo-2.0.0",
                    "md5": "linux-md5",
                    "build": "py310_0",
                    "subdir": "linux-64",
                    "url": "https://prefix.dev/conda-forge/linux-64/demo-2.0.0-py310_0.conda",
                    "timestamp": 20,
                }
            ],
            [
                {
                    "name": "demo",
                    "version": "2.0.0",
                    "nv": "demo-2.0.0",
                    "md5": "noarch-md5",
                    "build": "0",
                    "subdir": "noarch",
                    "url": "https://prefix.dev/conda-forge/noarch/demo-2.0.0-0.conda",
                    "timestamp": 10,
                }
            ],
        ],
    ) as mocked_fetch:
        specs = downloader.load_pkg_specs_from_prefix_shards()

    assert [spec["subdir"] for spec in specs] == ["linux-64", "noarch"]
    assert mocked_fetch.call_args_list == [mock.call("linux-64"), mock.call("noarch")]


def test_fetch_prefix_shard_specs_parses_shard_payload(tmp_path: Path) -> None:
    downloader = dlpkg.DownloadPkg(make_args(tmp_path, spec_source="prefix-shards"))
    shard_index = {
        "info": {
            "base_url": "https://prefix.dev/conda-forge/linux-64/",
            "shards_base_url": "shards/",
        },
        "shards": {"demo": bytes.fromhex("de" * 32)},
    }
    shard_payload = {
        "packages": {
            "demo-1.2.3-0.tar.bz2": {
                "name": "demo",
                "version": "1.2.3",
                "build": "0",
                "subdir": "linux-64",
                "md5": bytes.fromhex("ab" * 16),
                "timestamp": 42,
            }
        },
        "packages.conda": {
            "demo-1.2.4-0.conda": {
                "name": "demo",
                "version": "1.2.4",
                "build": "0",
                "subdir": "linux-64",
                "md5": "cd" * 16,
                "timestamp": 50,
            }
        },
    }

    with (
        mock.patch.object(
            downloader, "_get_prefix_shard_index", return_value=shard_index
        ),
        mock.patch.object(
            downloader,
            "_read_url_bytes",
            return_value=b"ignored",
        ) as mocked_read,
        mock.patch.object(
            downloader,
            "_decode_msgpack_zstd",
            return_value=shard_payload,
        ),
    ):
        specs = downloader._fetch_prefix_shard_specs("linux-64")

    assert mocked_read.call_args[0][0].endswith(f"{'de' * 32}.msgpack.zst")
    assert specs[0]["md5"] == "ab" * 16
    assert specs[0]["url"].endswith("/demo-1.2.3-0.tar.bz2")
    assert specs[1]["timestamp"] == 50


def test_download_file_skips_existing_file_without_hash(tmp_path: Path) -> None:
    out_dir = tmp_path / "pkgs"
    out_dir.mkdir()
    existing_file = out_dir / "source.tar.gz"
    existing_file.write_bytes(b"existing")
    downloader = dlpkg.DownloadPkg(make_args(tmp_path))

    with mock.patch.object(downloader, "local_download") as mocked_download:
        downloader.download_file(
            (
                dlpkg.SourceUrlSpec(
                    url="https://example.com/source.tar.gz",
                    fn="source.tar.gz",
                    hash_type=None,
                    hash=None,
                ),
                None,
                str(out_dir),
            )
        )

    mocked_download.assert_not_called()
    assert existing_file.read_bytes() == b"existing"


def test_download_returns_false_for_not_found(tmp_path: Path) -> None:
    target = tmp_path / "missing.tar.gz"
    request_info = mock.Mock()
    exc = aiohttp.ClientResponseError(
        request_info=request_info,
        history=(),
        status=404,
        message="Not Found",
        headers=None,
    )

    with mock.patch.object(dlpkg.DownloadPkg, "_download_async", side_effect=exc):
        result = dlpkg.DownloadPkg.download(
            "https://example.com/missing.tar.gz", str(target)
        )

    assert result is False


def test_core_methods_expose_precise_type_hints() -> None:
    get_pkg_spec_hints = get_type_hints(dlpkg.DownloadPkg.get_pkg_spec)
    download_file_hints = get_type_hints(dlpkg.DownloadPkg.download_file)
    unpack_recipe_hints = get_type_hints(dlpkg.DownloadPkg.unpack_recipe)

    assert get_pkg_spec_hints["return"] is dlpkg.PackageSpec
    assert download_file_hints["para_pairs"] == dlpkg.DownloadTask
    assert unpack_recipe_hints["return"] == dlpkg.RecipePaths


def test_load_urls_meta_yaml() -> None:
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


def test_load_urls_meta_yaml_jinja2() -> None:
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


def test_replace_urls_meta_yaml() -> None:
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
        downloader = dlpkg.DownloadPkg(make_args(tmp_path))
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


def test_replace_urls_recipe_yaml() -> None:
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
        downloader = dlpkg.DownloadPkg(make_args(tmp_path))
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


def test_extract_reqs_meta_yaml() -> None:
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


def test_find_recipe_file_prefers_recipe_yaml() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        Path(os.path.join(tmpdir, "meta.yaml")).write_text("x: 1", encoding="utf-8")
        Path(os.path.join(tmpdir, "recipe.yaml")).write_text("x: 1", encoding="utf-8")

        recipe_file, recipe_tpl = dlpkg.DownloadPkg._find_recipe_file(
            tmpdir, tmpdir, is_parent=False
        )

    assert recipe_file.endswith("recipe.yaml")
    assert recipe_tpl.endswith("recipe.yaml")


def test_find_recipe_file_falls_back_to_meta_yaml() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        Path(os.path.join(tmpdir, "meta.yaml")).write_text("x: 1", encoding="utf-8")

        recipe_file, recipe_tpl = dlpkg.DownloadPkg._find_recipe_file(
            tmpdir, tmpdir, is_parent=False
        )

    assert recipe_file.endswith("meta.yaml")
    assert recipe_tpl.endswith("meta.yaml.template")


def test_find_recipe_file_parent_mode() -> None:
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
