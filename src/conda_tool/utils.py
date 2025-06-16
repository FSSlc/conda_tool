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

import zstandard

SCRIPT_DIR = os.getcwd()
TEXT_WIDTH = 78
SEP_LINE = "-" * TEXT_WIDTH
ZSTD_COMPRESS_LEVEL = 19
ZSTD_COMPRESS_THREADS = 1


def setup_logging(terminal_width: int | None = None) -> None:
    """设置日志格式"""
    from rich.console import Console
    from rich.logging import RichHandler

    logger = logging.getLogger("conda_tool")
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
    logger.addHandler(rich_handler)

    logger.setLevel(logging.INFO)
    logger.propagate = False


def wrap_print(msg: str) -> None:
    """包裹输出信息"""
    print(textwrap.fill(msg, width=TEXT_WIDTH))


def wrap_input(msg: str) -> str:
    """包裹 input"""
    return input(textwrap.fill(msg, width=TEXT_WIDTH, drop_whitespace=False))


def get_choice(message: str, choices: list[str], default: int = 0) -> int:
    """获取用户单一选择"""
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
    """获取多个文件的一个 hash 值"""
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
    """获取文件列表"""
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
            z.extractall(out_path)


def extract_archive(archive: str, out_path: str, fmt: str = "zip") -> None:
    """解压压缩包"""
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
            # 自定义 tar 解压逻辑，处理符号链接
            with tarfile.open(archive, "r:*") as tar:
                for member in tar.getmembers():
                    try:
                        # 跳过可疑的符号链接
                        if member.issym() and ".." in member.linkname:
                            continue
                        tar.extract(member, out_path, set_attrs=False)
                    except OSError as e:
                        print(f"Warning: Failed to extract {member.name}: {str(e)}")
                        continue
        else:
            shutil.unpack_archive(archive, out_path)
    else:
        raise ValueError(f"Unknown format {fmt} to extract.")


def extract_large_tar(tar_path, extract_path, chunk_size=8192, debug=False):
    """高效解压大型 tar 文件的函数"""
    try:
        os.makedirs(extract_path, exist_ok=True)

        with tarfile.open(tar_path, "r:*") as tar:
            # 获取所有成员
            members = tar.getmembers()
            total_files = len(members)

            for index, member in enumerate(members, 1):
                try:
                    if debug:
                        print(
                            f"进度：{index:03d}/{total_files:03d} ({(index / total_files) * 100:06.2f}%)"
                            + f" - {member.name}"
                        )

                    # 如果是文件（不是目录）
                    if member.isfile():
                        # 创建目标文件的目录结构
                        target_path = os.path.join(extract_path, member.name)
                        target_dir = os.path.dirname(target_path)
                        os.makedirs(target_dir, exist_ok=True)

                        # 以流式方式提取文件
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
                        # 对于目录，直接创建
                        tar.extract(member, extract_path)
                    # 定期进行垃圾回收
                    if index % 100 == 0:
                        gc.collect()
                except Exception as e:
                    print(f"警告：解压文件 {member.name} 时出错：{str(e)}")
                    continue
        if debug:
            print("解压完成！")

    except Exception as e:
        print(f"错误：{str(e)}")


@contextlib.contextmanager
def tmp_chdir(dest: str):
    """进入临时目录"""
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
        """计算写的 bytes 数目"""
        self.size += len(write_bytes)
        return len(write_bytes)

    def tell(self) -> int:
        """返回当前位置"""
        return self.size


def compressor() -> zstandard.ZstdCompressor:
    """定义一个压缩器"""
    return zstandard.ZstdCompressor(
        level=ZSTD_COMPRESS_LEVEL, threads=ZSTD_COMPRESS_THREADS
    )


def is_elf_file(file_path: str) -> bool:
    """通过读取文件头判断是否为 ELF 文件"""
    try:
        with open(file_path, "rb") as f:
            # 读取前 4 个字节
            header = f.read(4)
            return header == b"\x7fELF"
    except OSError:
        return False


def abs_path(file_path: str) -> str:
    if not os.path.isabs(file_path):
        file_path = os.path.abspath(os.path.join(SCRIPT_DIR, file_path))
    return file_path


