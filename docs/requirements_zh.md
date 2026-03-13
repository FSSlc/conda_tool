# conda_tool 需求设计（中文）

## 1. 简介

本文档定义 `conda_tool` 及各子工具的功能性与非功能性需求。

## 2. 功能需求

### 2.1 通用 CLI 需求

| ID | 需求 |
|---|---|
| FR-CLI-001 | 系统应提供顶层命令 `ct`，并包含 `makedb`、`dlpkg`、`extract`、`modify`、`repack` 子命令。 |
| FR-CLI-002 | 系统应提供独立命令别名（`ct_makedb`、`ct_dlpkg`、`ct_extract`、`ct_modify`、`ct_repack`）。 |
| FR-CLI-003 | `ct -V/--version` 应输出版本并退出。 |
| FR-CLI-004 | 缺少或无效命令时应以非零退出码退出，并输出明确错误信息。 |

### 2.2 `makedb` 需求

| ID | 需求 |
|---|---|
| FR-MDB-001 | 系统应从配置的 conda-forge 源下载一个或多个架构的 `repodata.json.bz2`。 |
| FR-MDB-002 | 系统应对临时网络错误提供重试机制。 |
| FR-MDB-003 | 系统应合并 repodata 中 `packages` 与 `packages.conda`。 |
| FR-MDB-004 | 系统应将每个架构的合并数据保存为 msgpack+zstd 压缩文件。 |
| FR-MDB-005 | 系统应生成按包名拆分的压缩索引，并按版本/时间戳/构建串排序。 |
| FR-MDB-006 | 系统应支持强制刷新与加载本地已有数据。 |
| FR-MDB-007 | 系统应支持可配置的网络并发与文件并发上限。 |

### 2.3 `dlpkg` 需求

| ID | 需求 |
|---|---|
| FR-DLP-001 | 系统应从本地 `data/packages/<pkg>.zstd` 读取包规格。 |
| FR-DLP-002 | 系统应支持按 Python 构建串、subdir、版本上限筛选候选项。 |
| FR-DLP-003 | 系统应支持交互式版本选择。 |
| FR-DLP-004 | 系统应下载选中的包二进制（`.conda` 或 `.tar.bz2`）。 |
| FR-DLP-005 | 系统应从包的 info 目录提取 recipe。 |
| FR-DLP-006 | 系统应同时支持 `meta.yaml` 与 `recipe.yaml`。 |
| FR-DLP-007 | 系统应提取 source URL 并并行下载源码归档。 |
| FR-DLP-008 | 系统应将 recipe 中 URL 改写为本地相对路径，并保留原 URL 注释。 |
| FR-DLP-009 | 系统应输出 requirements 片段，供后续人工构建依赖参考。 |

### 2.4 `extract` 需求

| ID | 需求 |
|---|---|
| FR-EXT-001 | 系统应解析 constructor `.sh` 头部并识别 payload 边界。 |
| FR-EXT-002 | 系统应支持旧模式（BYTES/LINES）和新模式（boundary1/boundary2）。 |
| FR-EXT-003 | 系统应将脚本段提取为 `tpl.sh`。 |
| FR-EXT-004 | 系统应在存在时提取内置 conda 可执行文件。 |
| FR-EXT-005 | 系统应提取 payload tar 并解包到 `workdir`。 |
| FR-EXT-006 | 系统应支持按 subdir 组织包仓库结构（`--generate_repo`）。 |
| FR-EXT-007 | 系统应支持清理输出目录及保留/删除 tar 的开关。 |

### 2.5 `modify` 需求

| ID | 需求 |
|---|---|
| FR-MOD-001 | 系统应接受以包名为键的 JSON 规则文件。 |
| FR-MOD-002 | 系统应支持 `add`、`mv`、`delete`、`strip` 四类操作。 |
| FR-MOD-003 | 系统应支持基于 glob/pathspec 的规则展开。 |
| FR-MOD-004 | 系统应支持处理单个包或包目录。 |
| FR-MOD-005 | 系统应完成解包、应用规则、并按原格式重新打包。 |
| FR-MOD-006 | 系统应维护并更新元数据文件（`paths.json`、`files`、`has_prefix`）一致性。 |
| FR-MOD-007 | 系统应支持保留原包（`--keep_origin`）。 |
| FR-MOD-008 | 系统应提供输出示例配置能力（`-oc`）。 |

### 2.6 `repack` 需求

| ID | 需求 |
|---|---|
| FR-RPK-001 | 系统应编排 constructor `.sh` 的 extract → modify → repack 全流程。 |
| FR-RPK-002 | 系统应创建临时工作目录并自动清理。 |
| FR-RPK-003 | 系统应从修改后的工作目录重建 `pkgs.tar`。 |
| FR-RPK-004 | 系统应生成新的安装脚本并保留可执行权限。 |
| FR-RPK-005 | 系统应更新脚本头部中的 payload MD5 与大小信息。 |
| FR-RPK-006 | 当输出路径已存在时，系统应报错退出（由用户更换输出路径）。 |

## 3. 非功能需求

### 3.1 性能

| ID | 需求 |
|---|---|
| NFR-PERF-001 | `makedb` 应使用异步 I/O 提升高延迟网络环境下吞吐。 |
| NFR-PERF-002 | `modify` 应使用并发文件处理提升批量操作效率。 |
| NFR-PERF-003 | `dlpkg` 应支持并行下载源码归档。 |
| NFR-PERF-004 | 压缩/解压应尽量使用流式或分块方式，控制内存占用。 |

### 3.2 可靠性

| ID | 需求 |
|---|---|
| NFR-REL-001 | 对于非法输入和不可恢复错误，应返回稳定的非零退出码。 |
| NFR-REL-002 | 网络下载应具备重试/退避策略。 |
| NFR-REL-003 | 压缩包解压（已实现处）应具备可疑条目防护。 |
| NFR-REL-004 | 关键失败路径应输出可操作的错误日志。 |

### 3.3 兼容性 / 平台

| ID | 需求 |
|---|---|
| NFR-COMP-001 | 运行时为 Python 3.10+（纯 Python 实现）。 |
| NFR-COMP-002 | 在依赖可用前提下，应可运行于 Linux/macOS/Windows。 |
| NFR-COMP-003 | 支持 `.conda` 与 `.tar.bz2` 两种包格式。 |

### 3.4 可维护性

| ID | 需求 |
|---|---|
| NFR-MNT-001 | 代码质量门禁应包含 `ruff` 与 `pylint`。 |
| NFR-MNT-002 | 自动化测试应使用 `pytest` 与 `pytest-cov`。 |
| NFR-MNT-003 | 模块职责应保持分离（分发、解析、转换、工具）。 |

## 4. 输入 / 输出规范

### 4.1 输入

| 工具 | 输入 |
|---|---|
| `ct_makedb` | 架构列表、镜像地址、并发参数 |
| `ct_dlpkg` | 包名、筛选参数、本地数据库路径、输出目录 |
| `ct_extract` | 源 `.sh`、输出目录、解压行为开关 |
| `ct_modify` | 规则 JSON、包文件/目录路径、保留原包开关 |
| `ct_repack` | 源 `.sh`、规则 JSON、输出 `.sh` 路径 |

### 4.2 输出

| 工具 | 输出 |
|---|---|
| `ct_makedb` | `data/<arch>/data.zstd`、`data/packages/<pkg>.zstd` |
| `ct_dlpkg` | 下载的二进制包、提取后的 recipe 目录、源码归档文件 |
| `ct_extract` | `tpl.sh`、可选 `_conda`、`workdir/`、可选 `pkgs.tar` |
| `ct_modify` | 修改后的 conda 包（可选 `.bk` 备份） |
| `ct_repack` | 修改后的 constructor 安装脚本 `.sh` |

## 5. 约束与假设

### 5.1 约束

- 项目应保持纯 Python 实现，并使用声明依赖。
- 默认工作空间与当前目录绑定（`os.getcwd()`）。
- `modify` 规则格式为 JSON，且以包名为键。
- constructor 脚本格式支持范围受 `extract.py` 当前解析逻辑限制。

### 5.2 假设

- 用户在可写目录执行命令。
- 远程 channel 可访问且返回合法 repodata。
- 输入包/安装脚本未损坏并符合预期格式。
- `strip` 操作依赖宿主系统工具链可用。

## 6. 验收标准（摘要）

- 所有 CLI 命令可显示帮助并正确校验必填参数。
- 关键端到端流程（`makedb -> dlpkg`、`extract -> modify -> repack`）在代表性样本上可成功执行。
- 包修改后元数据一致性文件得到正确更新。
- 支持版本 Python 环境下自动化测试通过。
