"""Tests for utils."""

# pylint: disable=missing-function-docstring,missing-class-docstring
# pylint: disable=too-few-public-methods,import-outside-toplevel

import os
import tarfile
import tempfile

import pytest
import zstandard

from conda_tool.utils import (
    SCRIPT_DIR,
    ZSTD_COMPRESS_LEVEL,
    NullWriter,
    abs_path,
    anonymize_tarinfo,
    compressor,
    extract_archive,
    extract_large_tar,
    extract_zst,
    get_filelist,
    hash_files,
    is_elf_file,
    setup_logging,
    tmp_chdir,
)


class TestHashFiles:
    def test_md5_known_content(self, tmp_path):
        f = tmp_path / "a.txt"
        f.write_bytes(b"hello")
        result = hash_files([str(f)])
        assert result == "5d41402abc4b2a76b9719d911017c592"  # md5 of "hello"

    def test_sha256(self, tmp_path):
        f = tmp_path / "a.txt"
        f.write_bytes(b"hello")
        result = hash_files([str(f)], algorithm="sha256")
        assert len(result) == 64  # sha256 hex length

    def test_multiple_files(self, tmp_path):
        f1 = tmp_path / "a.txt"
        f2 = tmp_path / "b.txt"
        f1.write_bytes(b"hello")
        f2.write_bytes(b"world")
        result = hash_files([str(f1), str(f2)])
        assert isinstance(result, str)


class TestGetFilelist:
    def test_relative_paths(self, tmp_path):
        (tmp_path / "sub").mkdir()
        (tmp_path / "a.txt").write_text("a")
        (tmp_path / "sub" / "b.txt").write_text("b")
        result = get_filelist(str(tmp_path))
        assert "a.txt" in result
        assert os.path.join("sub", "b.txt") in result

    def test_absolute_paths(self, tmp_path):
        (tmp_path / "a.txt").write_text("a")
        result = get_filelist(str(tmp_path), with_prefix=True)
        assert all(os.path.isabs(p) for p in result)


class TestExtractZst:
    def test_extract_zst_roundtrip(self, tmp_path):
        # Create a tar.zst archive
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        (src_dir / "test.txt").write_text("content")

        archive = tmp_path / "test.tar.zst"
        with tempfile.TemporaryFile(suffix=".tar") as tmp_tar:
            with tarfile.open(fileobj=tmp_tar, mode="w") as tar:
                tar.add(str(src_dir / "test.txt"), arcname="test.txt")
            tmp_tar.seek(0)
            cctx = zstandard.ZstdCompressor()
            with open(str(archive), "wb") as out:
                cctx.copy_stream(tmp_tar, out)

        out_dir = tmp_path / "out"
        out_dir.mkdir()
        extract_zst(str(archive), str(out_dir))
        assert (out_dir / "test.txt").read_text() == "content"


class TestExtractArchive:
    def test_conda_zip_format(self, tmp_path):
        import zipfile

        archive = tmp_path / "test.conda"
        with zipfile.ZipFile(str(archive), "w") as zf:
            zf.writestr("metadata.json", '{"version": 1}')
        out = tmp_path / "out"
        out.mkdir()
        extract_archive(str(archive), str(out), "conda")
        assert (out / "metadata.json").exists()

    def test_tar_format(self, tmp_path):
        src = tmp_path / "data.txt"
        src.write_text("hello")
        archive = tmp_path / "test.tar"
        with tarfile.open(str(archive), "w") as tar:
            tar.add(str(src), arcname="data.txt")
        out = tmp_path / "out"
        out.mkdir()
        extract_archive(str(archive), str(out), "tar")
        assert (out / "data.txt").read_text() == "hello"

    def test_unknown_format_raises(self, tmp_path):
        with pytest.raises(ValueError, match="Unknown format"):
            extract_archive("fake.xyz", str(tmp_path), "xyz_unknown")


class TestExtractLargeTar:
    def test_normal_file_and_directory(self, tmp_path):
        archive = tmp_path / "test.tar"
        with tarfile.open(str(archive), "w") as tar:
            info = tarfile.TarInfo(name="dir")
            info.type = tarfile.DIRTYPE
            tar.addfile(info)
            data = b"file content"
            info = tarfile.TarInfo(name="dir/file.txt")
            info.size = len(data)
            from io import BytesIO

            tar.addfile(info, BytesIO(data))

        out = tmp_path / "out"
        extract_large_tar(str(archive), str(out))
        assert (out / "dir" / "file.txt").read_bytes() == b"file content"

    def test_skips_symlinks(self, tmp_path):
        archive = tmp_path / "test.tar"
        with tarfile.open(str(archive), "w") as tar:
            info = tarfile.TarInfo(name="link")
            info.type = tarfile.SYMTYPE
            info.linkname = "target"
            tar.addfile(info)
        out = tmp_path / "out"
        extract_large_tar(str(archive), str(out))
        assert not (out / "link").exists()

    def test_skips_path_traversal(self, tmp_path):
        archive = tmp_path / "test.tar"
        with tarfile.open(str(archive), "w") as tar:
            info = tarfile.TarInfo(name="../evil.txt")
            info.size = 4
            from io import BytesIO

            tar.addfile(info, BytesIO(b"evil"))
        out = tmp_path / "out"
        extract_large_tar(str(archive), str(out))
        assert not (out.parent / "evil.txt").exists()


class TestIsElfFile:
    def test_elf_file(self, tmp_path):
        f = tmp_path / "elf"
        f.write_bytes(b"\x7fELF" + b"\x00" * 100)
        assert is_elf_file(str(f)) is True

    def test_non_elf_file(self, tmp_path):
        f = tmp_path / "text"
        f.write_text("hello")
        assert is_elf_file(str(f)) is False

    def test_nonexistent_file(self):
        assert is_elf_file("/nonexistent/path") is False


class TestAbsPath:
    def test_relative_path(self):
        result = abs_path("relative/path")
        assert os.path.isabs(result)

    def test_absolute_path(self):
        result = abs_path("/absolute/path")
        assert result == "/absolute/path"


class TestTmpChdir:
    def test_changes_and_restores(self, tmp_path):
        original = os.getcwd()
        with tmp_chdir(str(tmp_path)):
            assert os.getcwd() == str(tmp_path)
        assert os.getcwd() == original


class TestAnonymizeTarinfo:
    def test_clears_user_info(self):
        info = tarfile.TarInfo(name="test")
        info.uid = 1000
        info.uname = "user"
        info.gid = 1000
        info.gname = "group"
        result = anonymize_tarinfo(info)
        assert result.uid == 0
        assert result.uname == ""
        assert result.gid == 0
        assert result.gname == ""


class TestNullWriter:
    def test_write_and_tell(self):
        w = NullWriter()
        assert w.tell() == 0
        n = w.write(b"hello")
        assert n == 5
        assert w.tell() == 5
        w.write(b"world")
        assert w.tell() == 10


class TestCompressor:
    def test_returns_compressor(self):
        c = compressor()
        assert isinstance(c, zstandard.ZstdCompressor)


class TestSetupLogging:
    def test_idempotent(self):
        import logging

        logger = logging.getLogger("conda_tool")
        setup_logging(120)
        count = len(logger.handlers)
        setup_logging(120)
        assert len(logger.handlers) == count


class TestConstants:
    def test_script_dir_is_absolute(self):
        assert os.path.isabs(SCRIPT_DIR)

    def test_zstd_level_is_int(self):
        assert isinstance(ZSTD_COMPRESS_LEVEL, int)
