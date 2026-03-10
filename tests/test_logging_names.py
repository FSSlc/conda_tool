import logging
import unittest

from conda_tool import dlpkg, extract, makedb, modify, repack
from conda_tool.utils import setup_logging


class LoggingNamespaceTests(unittest.TestCase):
    def test_module_loggers_use_conda_tool_namespace(self) -> None:
        self.assertEqual(extract.logger.name, "conda_tool.extract")
        self.assertEqual(repack.logger.name, "conda_tool.repack")
        self.assertEqual(dlpkg.logger.name, "conda_tool.dlpkg")
        self.assertEqual(modify.logger.name, "conda_tool.modify")
        self.assertEqual(makedb.logger.name, "conda_tool.makedb")

    def test_setup_logging_is_idempotent(self) -> None:
        logger = logging.getLogger("conda_tool")
        initial_count = len(logger.handlers)
        setup_logging(120)
        self.assertEqual(len(logger.handlers), initial_count)


if __name__ == "__main__":
    unittest.main()
