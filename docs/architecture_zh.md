# conda_tool 架构设计（中文）

## 1. 范围

本文档描述 `conda_tool` 的系统架构。该工具集覆盖以下能力：

- Conda 元数据索引构建（`makedb`）
- 基于二进制包还原 recipe/源码工作流（`dlpkg`）
- constructor 安装脚本提取（`extract`）
- 规则驱动包内容修改（`modify`）
- 安装包端到端重建（`repack`）

## 2. 总体架构

```text
                        +--------------------+
                        |   用户 / CI 任务    |
                        +---------+----------+
                                  |
                                  v
+---------------------------------------------------------------+
|                    CLI 层 (argparse)                          |
|   ct (__main__.py) -> 动态导入 -> makedb/dlpkg/...            |
+-----------------------------+---------------------------------+
                              |
                              v
+-----------------------------------------------------------------------+
|                    工具模块层 (src/conda_tool)                        |
|                                                                       |
|  makedb.py   dlpkg.py   extract.py   modify.py   repack.py            |
|      \          |           |            |          /                 |
|       \         |           |            |         /                  |
|        +--------+-----------+------------+--------+                   |
|                         utils.py + recipe.py                          |
+-----------------------------------------------------------------------+
                              |
                              v
+-----------------------------------------------------------------------+
|                    文件系统产物层（基于当前工作目录）                 |
| data/, data/packages/, workdir/, recipes/, pkgs/, output/, 临时目录   |
+-----------------------------------------------------------------------+
```

## 3. 入口与命令分发

`src/conda_tool/__main__.py`：

- 使用 `argparse` 定义子命令（`makedb`、`dlpkg`、`extract`、`modify`、`repack`）
- 使用 `importlib.import_module` 动态导入目标模块
- 通过重写 `sys.argv` 让各子工具自行处理参数
- 支持 `-V/--version`

`pyproject.toml` 中的 console scripts：

- `ct = conda_tool.__main__:main`
- `ct_makedb = conda_tool.makedb:main`
- `ct_dlpkg = conda_tool.dlpkg:main`
- `ct_extract = conda_tool.extract:main`
- `ct_modify = conda_tool.modify:main`
- `ct_repack = conda_tool.repack:main`

## 4. 模块职责

| 模块 | 职责 |
|---|---|
| `__main__.py` | 顶层命令分发 |
| `makedb.py` | 下载 repodata，合并包记录，构建压缩数据库 |
| `dlpkg.py` | 解析目标包规格，下载二进制包，提取 recipe，下载源码并改写 URL |
| `extract.py` | 解析 constructor `.sh` 格式并提取 payload |
| `modify.py` | 执行 add/mv/delete/strip 文件操作并重打包 conda 包 |
| `repack.py` | 编排 extract → modify → repack，并修补 `.sh` 头部校验信息 |
| `recipe.py` | 对 `meta.yaml` / `recipe.yaml` 执行模板安全的解析与改写 |
| `utils.py` | 日志、哈希、解压、文件列表、压缩等公共工具 |

## 5. 数据与执行流程

### 5.1 `makedb` → `dlpkg` 工作流

```text
ct_makedb
  |
  | 异步下载各架构 repodata.json.bz2
  v
合并 packages + packages.conda
  |
  | msgpack + zstd
  v
data/<arch>/data.zstd
  |
  | 按包名聚合 + 版本排序
  v
data/packages/<pkg>.zstd
  |
  +-------------------------------> ct_dlpkg <PKGNAME>
                                     |
                                     | 读取 <pkg>.zstd
                                     | 按 subdir/python/version/interact 筛选
                                     v
                                选中 package spec
                                     |
                                     | 下载二进制 .conda/.tar.bz2
                                     | 提取 info/recipe
                                     v
                                得到 recipe 与 source URL 列表
                                     |
                                     | 并行下载源码归档
                                     | 将 recipe URL 改写为本地相对路径
                                     v
                                本地 feedstock 风格目录 + 源码文件
```

实现要点：

- `makedb` 使用 `asyncio` + `aiohttp` + `aiofiles` + semaphore
- `dlpkg` 的源码下载使用 `ProcessPoolExecutor`
- 版本比较使用 `packaging.version`

### 5.2 `extract` → `modify` → `repack` 工作流

```text
ct_extract -s installer.sh
  |
  | parse_sh(): 读取头部与边界信息
  |  - old_mode: BYTES/LINES
  |  - new_mode: boundary1/boundary2
  v
提取脚本(tpl.sh)、可选 _conda、pkgs.tar
  |
  | 解包 pkgs.tar -> workdir/pkgs
  v
ct_modify -c rules.json -s workdir/pkgs
  |
  | 解包每个 .conda/.tar.bz2
  | 执行 add/mv/delete/strip
  | 更新 info/paths.json + files + has_prefix
  | 按原格式重打包
  v
修改后的 conda 包
  |
  +-----------------------------> ct_repack
                                   |
                                   | 程序内调用 extract + modify
                                   | 从 workdir 重建 pkgs.tar
                                   | 与脚本/conda执行段拼接
                                   | 修补头部 MD5 与大小字段
                                   v
                                 新的安装脚本 .sh
```

## 6. 关键设计决策

1. **基于当前目录的工作空间（`SCRIPT_DIR = os.getcwd()`）**
   - 便于临时运行和隔离产物。
   - 代价是用户需在正确目录下执行命令。

2. **双入口策略（`ct` + 独立命令）**
   - `ct` 适合发现与统一使用。
   - 独立命令更适合脚本/流水线。

3. **模板安全 recipe 解析**
   - `recipe.py` 先替换 `{{...}}` 与 `${{...}}` 为占位符，再进行 YAML 解析。
   - 避免引入完整模板求值引擎复杂度。

4. **按负载类型选择并发模型**
   - 网络 IO：`makedb` 用异步
   - 源码下载/隔离：`dlpkg` 用进程池
   - 文件操作：`modify` 用线程池

5. **按格式重打包**
   - 支持 `.conda`（zip + tar.zst 组件）
   - 支持 `.tar.bz2` 旧格式

## 7. 依赖关系图（逻辑）

```text
__main__
  ├── makedb ───┐
  ├── dlpkg  ───┼──> utils
  ├── extract ──┘
  ├── modify ─────> utils
  └── repack ─────> extract, modify, utils

dlpkg ───────────> recipe
```

外部依赖：

- 运行时：`ruamel-yaml`, `colorama`, `packaging`, `pathspec`, `zstandard`, `rich`, `msgpack`, `aiofiles`, `aiohttp`
- 开发测试：`pytest`, `pytest-cov`, `coverage`, `ruff`, `pylint`

## 8. 文件格式说明

### 8.1 本地数据库（`msgpack + zstd`）

- `data/<arch>/data.zstd`：压缩后的“包文件名 -> 元数据”映射
- `data/packages/<name>.zstd`：压缩后的包规格列表（按版本/时间戳/构建串排序）

常见字段：

- `name`, `version`, `nv`, `depends`, `md5`, `build`, `subdir`, `timestamp`, `url`

### 8.2 `.conda` 包格式

`.conda` 本质是 zip 容器，包含：

- `metadata.json`（`conda_pkg_format_version`）
- `pkg-<name-ver-build>.tar.zst`（实际文件内容）
- `info-<name-ver-build>.tar.zst`（元数据）

`modify.py` 会维护以下一致性文件：

- `info/paths.json`
- `info/files`
- `info/has_prefix`

### 8.3 constructor `.sh` 安装包格式

`extract.py` 支持两类头部模式：

- **旧模式**：`# BYTES:` / `# LINES:`
- **新模式**：`boundary1=` / `boundary2=`

可提取分段：

- 脚本段（`tpl.sh`）
- 可选内置 conda 可执行文件（`_conda`）
- 包载荷（`pkgs.tar`）

`repack.py` 会重新计算 payload 的 hash/size 并写回头部字段。

## 9. 可观测性与错误处理

- 日志统一通过 `rich.logging.RichHandler`
- 模块级 logger 命名（如 `conda_tool.makedb`）
- 参数校验与关键错误使用 `sys.exit()` 显式退出
- `utils.py` 中包含 tar 解压安全检查（路径穿越/链接处理）

## 10. 可扩展性

可扩展方向：

- 在 `__main__.py` 注册新子命令
- 扩展 modify 规则（如文本补丁、二进制差分）
- 增加更多镜像源或认证策略
- 增加结构化索引后端（如 sqlite/parquet）
