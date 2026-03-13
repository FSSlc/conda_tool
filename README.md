# conda_tool

Conda package and constructor installer toolkit / Conda 包与 constructor 安装包工具集。

## Overview / 概览

`conda_tool` is a pure Python (3.10+) CLI toolkit for:

- building local conda-forge package metadata databases,
- downloading package binaries and reconstructing feedstock-like recipe/source workspaces,
- extracting/modifying/repacking conda-constructor `.sh` installers.

`conda_tool` 是一个纯 Python（3.10+）命令行工具集，支持：

- 构建本地 conda-forge 包元数据库；
- 下载包二进制并重建类似 feedstock 的 recipe/源码工作区；
- 解包、修改、重打包 conda-constructor `.sh` 安装脚本。

## Commands / 命令

- `ct` (main dispatcher / 主入口)
- `ct_makedb`
- `ct_dlpkg`
- `ct_extract`
- `ct_modify`
- `ct_repack`

## Quick Start / 快速开始

```bash
pip install -e .
ct -V
ct makedb --help
```

## Documentation / 详细文档

### English

- [English README](./docs/README_EN.md)
- [Architecture Design (EN)](./docs/architecture_en.md)
- [Requirements Design (EN)](./docs/requirements_en.md)
- [Testing Guide (EN)](./docs/testing_en.md)
- [Deployment Guide (EN)](./docs/deployment_en.md)

### 中文

- [中文说明](./docs/README_ZH.md)
- [架构设计（中文）](./docs/architecture_zh.md)
- [需求设计（中文）](./docs/requirements_zh.md)
- [测试指南（中文）](./docs/testing_zh.md)
- [部署与使用指南（中文）](./docs/deployment_zh.md)
- [修改规则细节（中文）](./docs/modify_rule_details_zh.md)

## Tech Stack / 技术栈

- Python >= 3.10
- Runtime deps: `ruamel-yaml`, `colorama`, `packaging`, `pathspec`, `zstandard`, `rich`, `msgpack`, `aiofiles`, `aiohttp`
- Build: Hatch / hatchling
- Test: pytest, pytest-cov, coverage
- Lint: ruff, pylint

## License

MIT
