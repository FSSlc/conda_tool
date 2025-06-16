#!/usr/bin/env python3
"""Conda Tool CLI with subcommand support."""

import argparse
import importlib
import sys

TOOLS: dict[str, str] = {
    "makedb": "Create package database from conda-forge",
    "dlpkg": "Download conda-forge package and create feedstock",
    "extract": "Extract conda constructor sh package",
    "modify": "Modify conda package contents",
    "repack": "Repack modified conda constructor sh package",
}


def forward_args(args: list[str]) -> list[str]:
    """正确处理带空格的参数引用"""
    return [arg if " " not in arg else f'"{arg}"' for arg in args]


def main():
    # 主解析器（禁用自动帮助生成，我们自己处理）
    main_parser = argparse.ArgumentParser(
        description="Conda Tool - A Swiss Army knife for conda packages", add_help=False
    )
    main_parser.add_argument(
        "-V", "--version", action="store_true", help="Show version and exit"
    )

    # 子命令解析器
    subparsers = main_parser.add_subparsers(title="available commands", dest="command")

    # 创建所有子命令（但不立即添加参数）
    subcommands = {}
    for tool, help_text in TOOLS.items():
        subcommands[tool] = subparsers.add_parser(
            tool,
            help=help_text,
            add_help=False,  # 各工具自己处理帮助
        )

    # 先解析出命令名称
    main_args, remaining = main_parser.parse_known_args()

    # 处理版本请求
    if main_args.version:
        print(f"conda-tool {importlib.import_module('conda_tool').__version__}")
        return

    # 检查是否指定了有效子命令
    if not main_args.command:
        main_parser.print_help()
        print("\nError: missing command")
        sys.exit(1)

    # 导入对应的工具模块
    try:
        tool_module = importlib.import_module(f"conda_tool.{main_args.command}")
    except ImportError:
        print(f"Error: unknown command '{main_args.command}'", file=sys.stderr)
        sys.exit(1)

    # 重建 sys.argv：工具名 + 剩余参数
    sys.argv = [f"{main_args.command}.py"] + remaining

    # 执行工具的主函数
    try:
        tool_module.main()
    except SystemExit:
        # 允许工具自己处理退出（如显示帮助信息后退出）
        pass
    except Exception as e:
        print(f"Error in {main_args.command}: {str(e)}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
