# conda_tool 文档（中文）

## 1. 项目概述

`conda_tool` 是一个纯 Python 的命令行工具集，用于处理：

- Conda 包元数据与二进制包
- 从 Conda 包提取 recipe 并构建本地 feedstock 工作流
- Conda-constructor `.sh` 安装包的解包、修改与重打包

该项目面向包工程和发布工程场景，便于快速检查、改写、重建 Conda 工件。

## 2. 核心特性

- **统一入口**：`ct` 作为主命令，支持子命令分发
- **独立可执行工具**：每个子工具都可单独调用（`ct_makedb`、`ct_dlpkg` 等）
- **异步元数据流水线**：`ct_makedb` 并发下载并转换 `repodata.json`
- **包到 feedstock 工作流**：`ct_dlpkg` 从二进制包提取 recipe 与源码 URL，并改写为本地路径
- **安装包提取能力**：`ct_extract` 支持多种 constructor shell 格式
- **规则驱动包修改**：`ct_modify` 支持 add/mv/delete/strip
- **端到端重打包**：`ct_repack` 串联 extract → modify → repack，并更新头部元数据

## 3. 命令列表

| 命令 | 说明 |
|---|---|
| `ct` | 主命令分发器 |
| `ct_makedb` | 从 conda-forge repodata 构建本地包数据库 |
| `ct_dlpkg` | 下载包、提取 recipe、拉取源码 |
| `ct_extract` | 解压 constructor `.sh` 安装包 |
| `ct_modify` | 基于规则修改 `.conda` / `.tar.bz2` 包 |
| `ct_repack` | 抽取 + 修改 + 重打包 constructor `.sh` |

## 4. 安装与快速开始

### 4.1 前置条件

- Python **3.10+**
- 建议使用虚拟环境

### 4.2 从源码安装

```bash
git clone https://github.com/FSSlc/conda_tool.git
cd conda_tool
python -m pip install -U pip
pip install -e .
```

### 4.3 安装验证

```bash
ct -V
ct makedb --help
ct_makedb --help
```

## 5. 使用指南

> 说明：`conda_tool.utils.SCRIPT_DIR` 使用 `os.getcwd()`。因此 `data/`、`workdir/`、`recipes/`、`pkgs/`、`output/` 等默认路径都相对于你执行命令时的当前目录。

---

### 5.1 `ct`（主入口）

```bash
ct [-V|--version] <command> [args...]
```

子命令：

- `makedb`
- `dlpkg`
- `extract`
- `modify`
- `repack`

示例：

```bash
ct makedb --arch noarch linux-64
```

---

### 5.2 `ct_makedb`

从 conda-forge 的 `repodata.json.bz2` 构建本地数据库。

```bash
ct_makedb [--arch ...] [--url ...] [-f|--force_refresh] [--max N] [--file-max N]
```

参数：

- `--arch`：一个或多个架构（默认：`noarch linux-64 linux-aarch64`）
- `--url`：conda-forge 官方地址或南大镜像
- `-f, --force_refresh`：强制刷新，不读取本地缓存
- `--max`：最大并发网络任务数（默认 `100`）
- `--file-max`：最大并发文件任务数（默认 `50`）

输出（位于当前工作目录）：

- `data/<arch>/data.zstd`：原始合并 repodata（msgpack + zstd）
- `data/packages/<pkgname>.zstd`：按包名拆分并排序的数据，便于快速查询

示例：

```bash
ct_makedb --arch noarch linux-64 --max 120 --file-max 80
```

---

### 5.3 `ct_dlpkg`

下载单个包二进制文件，提取 recipe，下载源码归档，并把 recipe 中 URL 替换为本地路径。

```bash
ct_dlpkg PKGNAME 
  [-ub|--upper_bound VERSION] [--py 310] [--subdir linux-64] [--ignore-py] [-i|--interact] 
  [--specs_dir PATH] [--workdir PATH] [--recipes-dir PATH] [--pkgs-dir PATH]
```

参数：

- `PKGNAME`：包名
- `-ub, --upper_bound`：允许的最大版本
- `--py`：Python 构建串筛选（默认 `310`）
- `--subdir`：目标子目录（`noarch`、`linux-64`、`linux-aarch64`、`win-64`、`win-arm64`）
- `--ignore-py`：忽略 Python 构建串筛选
- `-i, --interact`：交互选择候选版本
- `--specs_dir`：包数据库路径（默认 `data/packages`）
- `--workdir`：下载与解压临时目录
- `--recipes-dir`：recipe 输出目录
- `--pkgs-dir`：源码归档输出目录

示例：

```bash
ct_dlpkg numpy --subdir linux-64 --py 311 --recipes-dir ./recipes --pkgs-dir ./pkgs
```

---

### 5.4 `ct_extract`

将 conda-constructor shell 安装包解压为脚本、payload 及工作目录。

```bash
ct_extract -s SOURCE_SH [-o OUTPUT_DIR] [-c|--clean] [-gr|--generate_repo] [-k|--keep_tar]
```

参数：

- `-s, --source`：源 `.sh` 安装包（必填）
- `-o, --output`：输出目录（默认 `./output`）
- `-c, --clean`：解压前清理输出目录
- `-gr, --generate_repo`：按 subdir 组织提取出的 conda 包
- `-k, --keep_tar`：保留 `pkgs.tar`

示例：

```bash
ct_extract -s Miniforge3.sh -o ./out --clean --generate_repo
```

---

### 5.5 `ct_modify`

按 JSON 规则修改一个或多个 conda 包。

```bash
ct_modify -c RULE_FILE -s PKG_OR_DIR [-k|--keep_origin]
ct_modify -oc
```

参数：

- `-oc, --output_example_config`：输出示例 `config.json`
- `-c, --config_path`：规则文件路径
- `-s, --pkg_path`：待修改的包文件或目录
- `-k, --keep_origin`：保留原包（重命名为 `.bk`）

支持操作：

- `add`：向包内新增文件
- `mv`：包内移动/重命名
- `delete`：按 pathspec/gitwildmatch 规则删除
- `strip`：对匹配到的 ELF 文件执行 `strip --strip-debug`

示例：

```bash
ct_modify -oc
ct_modify -c ./rules.json -s ./workdir/pkgs
```

---

### 5.6 `ct_repack`

一键完成 constructor 安装包更新。

```bash
ct_repack -s SOURCE_SH -c RULE_FILE [-o OUTPUT_SH]
```

参数：

- `-s, --source`：原始 `.sh` 安装包
- `-c, --config`：修改规则文件
- `-o, --output`：输出路径（默认 `mod-<源文件名>`）

流程：

1. 解压安装包
2. 按规则修改其中的 conda 包
3. 重打包 payload
4. 更新 shell 头部中的 MD5 与大小字段

示例：

```bash
ct_repack -s ./Miniforge3.sh -c ./rules.json -o ./Miniforge3-mod.sh
```

## 6. 配置说明（Modify 规则文件）

规则文件是 JSON，顶层是“包名 -> 操作集合”的映射。

```json
{
  "conda": {
    "add": {
      "../local/my_tool": "bin/",
      "../patches/*.so": "lib/"
    },
    "mv": {
      "bin/conda": "bin/_conda"
    },
    "delete": [
      "etc/fish/**",
      "share/doc/**"
    ],
    "strip": [
      "bin/*",
      "lib/*.so*"
    ]
  }
}
```

编写建议：

- `add` 的源路径支持绝对路径或相对规则文件路径
- `mv/delete/strip` 针对解包后的包内容
- glob 匹配由 `pathspec` 实现（gitwildmatch 风格）

详细规则参考：

- [修改规则细节（中文）](./docs/modify_rule_details_zh.md)

## 7. 开发与质量保障

- 测试：`pytest -q`
- 覆盖率：`pytest --cov=src/conda_tool --cov-report=term-missing`
- Ruff：`ruff check .`
- Pylint：`pylint $(git ls-files '*.py')`

## 8. 相关文档

- [架构设计（English）](./architecture_en.md)
- [架构设计（中文）](./architecture_zh.md)
- [需求设计（English）](./requirements_en.md)
- [需求设计（中文）](./requirements_zh.md)
- [测试指南（English）](./testing_en.md)
- [测试指南（中文）](./testing_zh.md)
- [部署与使用（English）](./deployment_en.md)
- [部署与使用（中文）](./deployment_zh.md)

## 9. 许可证

MIT
