"""Tests for logger naming."""

# pylint: disable=missing-function-docstring,missing-class-docstring,no-name-in-module

import logging

from conda_tool import dlpkg, extract, makedb, modify, repack
from conda_tool.utils import setup_logging


class LoggingNamespaceTests:
    def test_module_loggers_use_conda_tool_namespace(self) -> None:
        assert extract.logger.name == "conda_tool.extract"
        assert repack.logger.name == "conda_tool.repack"
        assert dlpkg.logger.name == "conda_tool.dlpkg"
        assert modify.logger.name == "conda_tool.modify"
        assert makedb.logger.name == "conda_tool.makedb"

    def test_setup_logging_is_idempotent(self) -> None:
        logger = logging.getLogger("conda_tool")
        initial_count = len(logger.handlers)
        setup_logging(120)
        assert len(logger.handlers) == initial_count
