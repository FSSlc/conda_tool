import asyncio
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

from conda_tool import makedb


class ParseRepodataTests(unittest.IsolatedAsyncioTestCase):
    async def test_save_single_package_writes_output_file(self) -> None:
        package_data = [
            {
                "name": "foo",
                "version": "1.0",
                "timestamp": 10,
                "build": "0",
            }
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            with mock.patch.object(makedb, "SCRIPT_DIR", tmpdir):
                with ThreadPoolExecutor(max_workers=1) as file_executor:
                    await makedb.save_single_package(
                        "foo",
                        package_data,
                        asyncio.Semaphore(1),
                        file_executor,
                    )

            assert Path(tmpdir, "data", "packages", "foo.zstd").exists()

    async def test_parse_repodata_groups_records_by_package_name(self) -> None:
        data = {
            "foo-1.0-0.tar.bz2": {
                "name": "foo",
                "version": "1.0",
                "depends": ["python >=3.10"],
                "md5": "md5-foo-1.0",
                "build": "0",
                "subdir": "linux-64",
                "timestamp": 10,
            },
            "foo-1.1-0.tar.bz2": {
                "name": "foo",
                "version": "1.1",
                "depends": ["python >=3.11"],
                "md5": "md5-foo-1.1",
                "build": "0",
                "subdir": "linux-64",
                "timestamp": 20,
            },
            "bar-2.0-0.conda": {
                "name": "bar",
                "version": "2.0",
                "depends": [],
                "md5": "md5-bar-2.0",
                "build": "py_0",
                "subdir": "noarch",
                "timestamp": 30,
            },
        }
        saved_packages: dict[str, list[dict]] = {}

        async def fake_save_single_package(
            package_name: str,
            package_data: list[dict],
            file_semaphore: asyncio.Semaphore,
            file_executor: ThreadPoolExecutor,
        ) -> None:
            saved_packages[package_name] = package_data

        with mock.patch.object(
            makedb, "save_single_package", side_effect=fake_save_single_package
        ) as mocked_save:
            with ThreadPoolExecutor(max_workers=2) as file_executor:
                await makedb.parse_repodata(
                    data,
                    "https://conda.anaconda.org/conda-forge",
                    asyncio.Semaphore(2),
                    asyncio.Semaphore(2),
                    file_executor,
                )

        assert mocked_save.await_count == 2
        assert set(saved_packages) == {"foo", "bar"}
        assert {item["version"] for item in saved_packages["foo"]} == {"1.0", "1.1"}
        assert (
            saved_packages["bar"][0]["url"]
            == "https://conda.anaconda.org/conda-forge/noarch/bar-2.0-0.conda"
        )

    async def test_parse_repodata_preserves_same_filename_from_multiple_arches(self) -> None:
        saved_packages: dict[str, list[dict]] = {}
        repodata_sets = [
            {
                "shared-1.0-0.tar.bz2": {
                    "name": "shared",
                    "version": "1.0",
                    "depends": [],
                    "md5": "md5-linux",
                    "build": "0",
                    "subdir": "linux-64",
                    "timestamp": 10,
                }
            },
            {
                "shared-1.0-0.tar.bz2": {
                    "name": "shared",
                    "version": "1.0",
                    "depends": [],
                    "md5": "md5-noarch",
                    "build": "0",
                    "subdir": "noarch",
                    "timestamp": 20,
                }
            },
        ]

        async def fake_save_single_package(
            package_name: str,
            package_data: list[dict],
            file_semaphore: asyncio.Semaphore,
            file_executor: ThreadPoolExecutor,
        ) -> None:
            saved_packages[package_name] = package_data

        with mock.patch.object(
            makedb, "save_single_package", side_effect=fake_save_single_package
        ):
            with ThreadPoolExecutor(max_workers=2) as file_executor:
                await makedb.parse_repodata(
                    repodata_sets,
                    "https://conda.anaconda.org/conda-forge",
                    asyncio.Semaphore(2),
                    asyncio.Semaphore(2),
                    file_executor,
                )

        assert len(saved_packages["shared"]) == 2
        assert {item["subdir"] for item in saved_packages["shared"]} == {
            "linux-64",
            "noarch",
        }


class LoggingTests:
    def test_module_logger_uses_conda_tool_namespace(self) -> None:
        assert makedb.logger.name == "conda_tool.makedb"
