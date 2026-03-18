"""Utils for module scripts"""

import contextlib
import gc
import hashlib
import logging
import os
import re
import shutil
import tarfile
import tempfile
import textwrap
from collections.abc import Sized
from logging import getLogger

import zstandard
from rich.console import Console
from rich.logging import RichHandler

logger = getLogger("conda_tool.utils")

SCRIPT_DIR = os.getcwd()
TEXT_WIDTH = 78
SEP_LINE = "-" * TEXT_WIDTH
ZSTD_COMPRESS_LEVEL = 19
ZSTD_COMPRESS_THREADS = 1


def setup_logging(terminal_width: int | None = None) -> None:
    """Configure logging output."""
    root_logger = logging.getLogger("conda_tool")
    if root_logger.handlers:
        root_logger.setLevel(logging.INFO)
        root_logger.propagate = False
        return

    console = Console(width=terminal_width) if terminal_width else None
    rich_handler = RichHandler(
        show_time=False,
        rich_tracebacks=True,
        tracebacks_show_locals=True,
        markup=True,
        show_path=False,
        console=console,
    )
    rich_handler.setFormatter(logging.Formatter("%(message)s"))
    root_logger.addHandler(rich_handler)

    root_logger.setLevel(logging.INFO)
    root_logger.propagate = False


def wrap_print(msg: str) -> None:
    """Print wrapped output."""
    print(textwrap.fill(msg, width=TEXT_WIDTH))


def wrap_input(msg: str) -> str:
    """Read wrapped input."""
    return input(textwrap.fill(msg, width=TEXT_WIDTH, drop_whitespace=False))


def get_choice(message: str, choices: list[str], default: int = 0) -> int:
    """Prompt the user for a single choice."""
    wrap_print(message + ":")
    for i, c in enumerate(choices):
        print(f"  [{i}] {c}")
    min_choice = 0
    max_choice = len(choices) - 1
    while True:
        choice = wrap_input(
            f"Please choose {min_choice}-{max_choice} (default: [{default}], -1 for exit): "
        )

        if not choice:
            print(SEP_LINE)
            return default
        if choice != "-1" and (not re.match(r"\d+", choice)):
            continue
        int_choice = int(choice)
        if int_choice < -1 or int_choice >= len(choices):
            continue
        print(SEP_LINE)
        return int_choice


def hash_files(paths: list[str], algorithm: str = "md5") -> str:
    """Compute a combined hash over multiple files."""
    h = hashlib.new(algorithm)
    for path in paths:
        with open(path, "rb") as fi:
            while True:
                chunk = fi.read(262144)
                if not chunk:
                    break
                h.update(chunk)
    return h.hexdigest()


def get_filelist(prefix: str, with_prefix: bool = False) -> list[str]:
    """Return a file list for the given directory."""
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


def extract_zst(archive: str, out_path: str) -> None:
    """extract .zst file"""

    archive = os.path.abspath(archive)
    out_path = os.path.abspath(out_path)
    dctx = zstandard.ZstdDecompressor()

    with tempfile.TemporaryFile(suffix=".tar") as ofh:
        with open(archive, "rb") as ifh:
            dctx.copy_stream(ifh, ofh)
        ofh.seek(0)
        with tarfile.open(fileobj=ofh) as z:
            if hasattr(tarfile, "data_filter"):
                # Python 3.12+ supports the filter argument.
                z.extractall(out_path, filter="data")
            else:
                z.extractall(out_path)


def extract_archive(archive: str, out_path: str, fmt: str = "zip") -> None:
    """Extract an archive."""
    if fmt == "zst":
        extract_zst(archive, out_path)
    elif fmt == "conda":
        shutil.unpack_archive(archive, out_path, format="zip")
    elif fmt in [
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
        if fmt.startswith("tar"):
            # Use custom tar extraction to handle symbolic links safely.
            with tarfile.open(archive, "r:*") as tar:
                for member in tar.getmembers():
                    try:
                        # Skip suspicious symbolic links.
                        if member.issym() and ".." in member.linkname:
                            continue
                        if hasattr(tarfile, "data_filter"):
                            # Python 3.12+ supports the filter argument.
                            tar.extract(
                                member, out_path, set_attrs=False, filter="data"
                            )
                        else:
                            tar.extract(member, out_path, set_attrs=False)
                    except OSError as e:
                        logger.warning(f"Failed to extract {member.name}: {e}")
                        continue
        else:
            shutil.unpack_archive(archive, out_path)
    else:
        raise ValueError(f"Unknown format {fmt} to extract.")


def extract_large_tar(  # pylint: disable=too-many-locals
    tar_path: str, extract_path: str, chunk_size: int = 8192, debug: bool = False
) -> None:
    """Extract large tar files efficiently."""
    try:
        os.makedirs(extract_path, exist_ok=True)

        with tarfile.open(tar_path, "r:*") as tar:
            # Load the member list once.
            members = tar.getmembers()
            total_files = len(members)

            for index, member in enumerate(members, 1):
                try:
                    # Guard against path traversal and symlink attacks.
                    member_name = member.name
                    if (
                        os.path.isabs(member_name)
                        or ".." in member_name.split(os.path.sep)
                        or member.issym()
                        or member.islnk()
                    ):
                        if debug:
                            logger.warning(f"跳过可疑条目 {member.name}")
                        continue

                    if debug:
                        logger.debug(
                            "进度：%03d/%03d (%06.2f%%) - %s",
                            index,
                            total_files,
                            (index / total_files) * 100,
                            member.name,
                        )

                    # Stream regular files to disk.
                    if member.isfile():
                        # Create the target directory tree first.
                        target_path = os.path.join(extract_path, member.name)
                        target_dir = os.path.dirname(target_path)
                        os.makedirs(target_dir, exist_ok=True)

                        # Extract the file in streaming mode.
                        source = tar.extractfile(member)
                        if source is not None:
                            with open(target_path, "wb") as target:
                                while True:
                                    chunk = source.read(chunk_size)
                                    if not chunk:
                                        break
                                    target.write(chunk)
                            source.close()
                    else:
                        # Directories can be extracted as-is.
                        if hasattr(tarfile, "data_filter"):
                            # Python 3.12+ supports the filter argument.
                            tar.extract(member, extract_path, filter="data")
                        else:
                            tar.extract(member, extract_path)
                    # Trigger periodic garbage collection.
                    if index % 100 == 0:
                        gc.collect()
                except (OSError, tarfile.TarError) as e:
                    logger.warning(f"解压文件 {member.name} 时出错：{e}")
                    continue
        if debug:
            logger.debug("解压完成！")

    except (tarfile.TarError, OSError) as e:
        logger.error(f"错误：{str(e)}")
        raise


@contextlib.contextmanager
def tmp_chdir(dest: str):
    """Temporarily change into a directory."""
    curdir = os.getcwd()
    try:
        os.chdir(dest)
        yield
    finally:
        os.chdir(curdir)


def anonymize_tarinfo(tarinfo: tarfile.TarInfo) -> tarfile.TarInfo:
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

    def __init__(self) -> None:
        self.size = 0

    def write(self, write_bytes: Sized) -> int:
        """Track the number of written bytes."""
        self.size += len(write_bytes)
        return len(write_bytes)

    def tell(self) -> int:
        """Return the current position."""
        return self.size


def compressor() -> zstandard.ZstdCompressor:
    """Create the shared zstd compressor configuration."""
    return zstandard.ZstdCompressor(
        level=ZSTD_COMPRESS_LEVEL, threads=ZSTD_COMPRESS_THREADS
    )


def is_elf_file(file_path: str) -> bool:
    """Determine whether a file is ELF by reading its header."""
    try:
        with open(file_path, "rb") as f:
            # Read the first four bytes.
            header = f.read(4)
            return header == b"\x7fELF"
    except OSError:
        return False


def abs_path(file_path: str) -> str:
    """Resolve a path relative to the current script directory."""
    if not os.path.isabs(file_path):
        file_path = os.path.abspath(os.path.join(SCRIPT_DIR, file_path))
    return file_path
