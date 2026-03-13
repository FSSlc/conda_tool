# conda_tool 测试指南（中文）

## 1. 测试技术栈

`conda_tool` 使用：

- **测试框架**：`pytest`
- **覆盖率**：`pytest-cov`、`coverage`
- **代码检查**：`ruff`、`pylint`

相关配置位于 `pyproject.toml`：

- `tool.pytest.ini_options`
- `tool.coverage.run`
- `tool.coverage.report`

## 2. 测试目录结构

现有测试文件：

- `tests/test_main.py`
- `tests/test_makedb.py`
- `tests/test_dlpkg.py`
- `tests/test_extract.py`
- `tests/test_modify.py`
- `tests/test_recipe.py`
- `tests/test_utils.py`
- `tests/test_logging_names.py`

## 3. 如何运行测试

### 3.1 安装开发依赖

```bash
pip install -e .
pip install pytest pytest-cov coverage ruff pylint
# 或使用你环境支持的依赖组安装方式
```

### 3.2 运行全部测试

```bash
pytest -q
```

### 3.3 运行单个测试模块

```bash
pytest tests/test_modify.py -q
```

### 3.4 运行单个测试用例

```bash
pytest tests/test_dlpkg.py::DownloadPkgTests::test_load_urls_recipe_yaml -q
```

## 4. 覆盖率

### 4.1 终端覆盖率报告

```bash
pytest --cov=src/conda_tool --cov-report=term-missing
```

### 4.2 XML 覆盖率报告（CI 常用）

```bash
pytest --cov=src/conda_tool --cov-report=xml
```

覆盖率配置说明：

- 覆盖源：`conda_tool`
- 排除常见非运行路径（如 `if __name__ == '__main__'`）

## 5. 代码检查

### 5.1 Ruff

```bash
ruff check .
```

### 5.2 Pylint

```bash
pylint $(git ls-files '*.py')
```

仓库中包含 GitHub Actions 的 pylint 工作流，覆盖 Python 3.10/3.11/3.12。

## 6. 测试类别与重点

### 6.1 单元测试

- 参数解析（`parse_args`）
- 路径与文件操作
- 规则展开与元数据更新
- recipe 解析与替换逻辑

### 6.2 工作流测试（模块级集成）

- 各模块关键流程的端到端行为
- 解压与重打包场景
- 工具函数与主流程交互

### 6.3 回归测试

- 对历史缺陷修复添加明确测试
- 对 constructor 头部解析、规则匹配边界条件增加覆盖

## 7. 如何新增测试

1. 选择目标模块（如 `modify.py`）及对应测试文件（`tests/test_modify.py`）。
2. 遵循现有风格：
   - 使用 `pytest`
   - 使用 `tempfile.TemporaryDirectory()` / `tmp_path`
   - 使用 `unittest.mock` 隔离网络/进程/IO
3. 保证测试可重复：
   - 避免真实外网调用
   - 避免依赖宿主机特定状态
4. 同时覆盖成功路径与失败路径。
5. 提交前运行：
   - `pytest -q`
   - `pytest --cov=src/conda_tool --cov-report=term-missing`
   - `ruff check .`

## 8. 建议补充测试点

- `repack.py`：头部 MD5/size 修补正确性
- `extract.py`：错误 header/boundary 异常处理
- `makedb.py`：模拟 aiohttp 失败重试/退避逻辑
- `modify.py`：glob 与目录规则冲突、元数据一致性验证

## 9. CI 建议流程

推荐 CI 阶段：

1. 安装依赖
2. 执行 `ruff check .`
3. 执行 `pytest --cov=src/conda_tool --cov-report=xml`
4. 执行 `pylint $(git ls-files '*.py')`

可在 CI 中增加最低覆盖率阈值策略。
