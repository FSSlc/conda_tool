import contextlib
import hashlib
import logging
import os
import shutil
import tarfile
import tempfile

import zstandard

SCRIPT_DIR = os.path.dirname(__file__)
ZSTD_COMPRESS_LEVEL = 19
ZSTD_COMPRESS_THREADS = 1


def setup_logging(log_name):
    log_path = os.path.join(SCRIPT_DIR, log_name)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.FileHandler(log_path, mode="w"), logging.StreamHandler()],
    )


def extract_zst(archive, out_path):
    """extract .zst file"""

    if zstandard is None:
        raise ImportError("pip install zstandard")

    archive = os.path.abspath(archive)
    out_path = os.path.abspath(out_path)
    dctx = zstandard.ZstdDecompressor()

    with tempfile.TemporaryFile(suffix=".tar") as ofh:
        with open(archive, "rb") as ifh:
            dctx.copy_stream(ifh, ofh)
        ofh.seek(0)
        with tarfile.open(fileobj=ofh) as z:
            z.extractall(out_path)


def extract_archive(archive, out_path, format="zip"):
    if format == "zst":
        extract_zst(archive, out_path)
    elif format == "conda":
        shutil.unpack_archive(archive, out_path, format="zip")
    elif format in [
        "zip",
        "tar",
        "tar.gz",
        "tgz",
        "gztar",
        "bztar",
        "tar.bz2",
        "xztar",
        "tar.zx",
    ]:
        shutil.unpack_archive(archive, out_path)
    else:
        raise ValueError(f"Unknown format {format} to extract.")


def hash_files(paths, algorithm="md5"):
    h = hashlib.new(algorithm)
    for path in paths:
        with open(path, "rb") as fi:
            while True:
                chunk = fi.read(262144)
                if not chunk:
                    break
                h.update(chunk)
    return h.hexdigest()


def get_filelist(prefix, with_prefix=False):
    filelist = []
    for root, _, files in os.walk(prefix):
        for file in files:
            file_path = os.path.join(root, file)
            if with_prefix:
                filelist.append(file_path)
            else:
                relative_path = os.path.relpath(file_path, start=prefix)
                filelist.append(relative_path)
    return filelist


@contextlib.contextmanager
def tmp_chdir(dest):
    curdir = os.getcwd()
    try:
        os.chdir(dest)
        yield
    finally:
        os.chdir(curdir)


def anonymize_tarinfo(tarinfo):
    """
    Remove user id, name from tarinfo.
    """
    # also remove timestamps?
    tarinfo.uid = 0
    tarinfo.uname = ""
    tarinfo.gid = 0
    tarinfo.gname = ""
    return tarinfo


class NullWriter:
    """
    zstd uses less memory on extract if size is known.
    """

    def __init__(self):
        self.size = 0

    def write(self, bytes):
        self.size += len(bytes)
        return len(bytes)

    def tell(self):
        return self.size


def compressor():
    return zstandard.ZstdCompressor(
        level=ZSTD_COMPRESS_LEVEL, threads=ZSTD_COMPRESS_THREADS
    )
