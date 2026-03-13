# conda_tool 部署与使用指南（中文）

## 1. 前置条件

- Python 3.10 及以上
- `pip`
- 可访问 conda-forge（或镜像）用于元数据和包下载
- 可选（涉及 strip 工作流时）：系统 `strip` 命令

建议：

- 使用虚拟环境（`venv` 或 conda env）
- 在独立工作目录运行命令（默认路径与当前目录绑定）

## 2. 安装方式

## 2.1 从 PyPI 安装（如已发布）

```bash
pip install conda_tool
```

## 2.2 从源码安装

```bash
git clone https://github.com/FSSlc/conda_tool.git
cd conda_tool
python -m pip install -U pip
pip install .
```

## 2.3 开发模式安装

```bash
git clone https://github.com/FSSlc/conda_tool.git
cd conda_tool
pip install -e .
```

## 2.4 安装开发/测试工具

```bash
pip install pytest pytest-cov coverage ruff pylint
```

## 3. 环境准备

隔离环境示例：

```bash
python -m venv .venv
source .venv/bin/activate   # Linux/macOS
# .venv\Scripts\activate   # Windows
pip install -U pip
pip install -e .
```

可选：初始化工作目录结构

```bash
mkdir -p data workdir recipes pkgs output
```

## 4. 典型使用流程

### 4.1 构建本地元数据库

```bash
ct_makedb --arch noarch linux-64 linux-aarch64
```

将生成：

- `data/<arch>/data.zstd`
- `data/packages/*.zstd`

### 4.2 下载单个包并创建本地 recipe 工作区

```bash
ct_dlpkg numpy --subdir linux-64 --py 311 --recipes-dir ./recipes --pkgs-dir ./pkgs
```

通常产出：

- `recipes/` 下的 recipe 目录
- `pkgs/` 下的源码压缩包

### 4.3 解包 constructor 安装脚本

```bash
ct_extract -s ./Miniforge3.sh -o ./output --clean --generate_repo
```

### 4.4 基于规则修改 conda 包

先生成示例规则并编辑：

```bash
ct_modify -oc
# 编辑 ./config.json
```

应用规则：

```bash
ct_modify -c ./config.json -s ./output/workdir/pkgs --keep_origin
```

### 4.5 重打包安装脚本

```bash
ct_repack -s ./Miniforge3.sh -c ./config.json -o ./Miniforge3-mod.sh
```

## 5. 构建与发布（维护者）

项目使用 **Hatchling** 作为构建后端（见 `pyproject.toml`）。

示例：

```bash
python -m pip install hatch
hatch build
```

产物通常位于 `dist/`。

## 6. 故障排查

### 6.1 `Requested package ... is not in database`

原因：

- `ct_dlpkg` 未找到 `data/packages/<pkg>.zstd`

处理：

- 先执行 `ct_makedb`
- 检查当前目录与 `--specs_dir` 参数

### 6.2 下载/网络失败

原因：

- 镜像不可达、网络抖动、防火墙限制

处理：

- `ct_makedb` 切换 `--url`
- 适当降低并发（`--max`、`--file-max`）

### 6.3 输出路径不符合预期

原因：

- 默认路径基于当前目录（`SCRIPT_DIR = os.getcwd()`）

处理：

- 在期望工作目录执行命令
- 显式传入路径参数（`--workdir`、`--recipes-dir`、`--pkgs-dir`、`-o`）

### 6.4 `ct_modify` 的 strip 相关错误

原因：

- 匹配到了非 ELF 文件，或系统缺少 `strip`

处理：

- 收窄 strip 规则
- 安装所需工具链（binutils 等）

### 6.5 `ct_repack` 提示输出文件已存在

处理：

- 更换 `-o` 输出路径
- 确认安全后删除旧文件

## 7. 运维建议

- 每个任务使用独立工作目录，避免产物互相污染。
- 在 CI 中显式指定输出路径，提升可复现性。
- 发布前执行 `pytest`、`ruff`、`pylint` 质量门禁。

## 8. 相关文档

- [README_ZH](./README_ZH.md)
- [架构设计](./architecture_zh.md)
- [需求设计](./requirements_zh.md)
- [测试指南](./testing_zh.md)
