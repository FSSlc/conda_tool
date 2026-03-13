import sys
from unittest import mock

import pytest

from conda_tool.__main__ import TOOLS, main


class TestMain:
    def test_version_flag(self, capsys):
        with mock.patch.object(sys, "argv", ["conda-tool", "-V"]):
            main()
        captured = capsys.readouterr()
        assert "conda-tool" in captured.out
        assert "0.1.0" in captured.out

    def test_no_command_exits(self):
        with mock.patch.object(sys, "argv", ["conda-tool"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1

    def test_unknown_command_exits(self):
        with mock.patch.object(sys, "argv", ["conda-tool", "nonexistent"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 2

    def test_tools_dict_has_expected_keys(self):
        expected = {"makedb", "dlpkg", "extract", "modify", "repack"}
        assert set(TOOLS.keys()) == expected

    def test_valid_command_calls_module(self):
        fake_module = mock.MagicMock()
        with (
            mock.patch.object(sys, "argv", ["conda-tool", "extract", "--help"]),
            mock.patch("importlib.import_module", return_value=fake_module),
        ):
            main()
        fake_module.main.assert_called_once()

    def test_tool_system_exit_is_caught(self):
        fake_module = mock.MagicMock()
        fake_module.main.side_effect = SystemExit(0)
        with (
            mock.patch.object(sys, "argv", ["conda-tool", "extract"]),
            mock.patch("importlib.import_module", return_value=fake_module),
        ):
            # Should NOT raise
            main()

    def test_tool_exception_exits(self):
        fake_module = mock.MagicMock()
        fake_module.main.side_effect = RuntimeError("boom")
        with (
            mock.patch.object(sys, "argv", ["conda-tool", "modify"]),
            mock.patch("importlib.import_module", return_value=fake_module),
        ):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1
