# conda_tool Testing Guide (English)

## 1. Testing Stack

`conda_tool` uses:

- **Test runner**: `pytest`
- **Coverage**: `pytest-cov`, `coverage`
- **Linting**: `ruff`, `pylint`

Relevant config is in `pyproject.toml`:

- `tool.pytest.ini_options`
- `tool.coverage.run`
- `tool.coverage.report`

## 2. Test Layout

Current test files:

- `tests/test_main.py`
- `tests/test_makedb.py`
- `tests/test_dlpkg.py`
- `tests/test_extract.py`
- `tests/test_modify.py`
- `tests/test_recipe.py`
- `tests/test_utils.py`
- `tests/test_logging_names.py`

## 3. Running Tests

### 3.1 Install dev dependencies

```bash
pip install -e .
pip install pytest pytest-cov coverage ruff pylint
# or install from project dependency group if your workflow supports it
```

### 3.2 Run all tests

```bash
pytest -q
```

### 3.3 Run one test module

```bash
pytest tests/test_modify.py -q
```

### 3.4 Run specific test case

```bash
pytest tests/test_dlpkg.py::DownloadPkgTests::test_load_urls_recipe_yaml -q
```

## 4. Coverage

### 4.1 Terminal coverage report

```bash
pytest --cov=src/conda_tool --cov-report=term-missing
```

### 4.2 XML report (CI friendly)

```bash
pytest --cov=src/conda_tool --cov-report=xml
```

Coverage configuration notes:

- Coverage source target: `conda_tool`
- Excludes typical non-runtime lines (e.g., `if __name__ == '__main__'`)

## 5. Lint and Static Quality Checks

### 5.1 Ruff

```bash
ruff check .
```

### 5.2 Pylint

```bash
pylint $(git ls-files '*.py')
```

The repository includes GitHub Action workflow for pylint across Python 3.10/3.11/3.12.

## 6. Test Categories and Focus

### 6.1 Unit tests

- Argument parsing (`parse_args` behavior)
- Path and file handling
- Rule expansion and metadata updates
- Recipe parse/replace logic

### 6.2 Workflow tests (module-level integration)

- End-to-end behavior of key operations within each module
- Archive extraction/repacking scenarios
- Interactions between helper utilities and main tool logic

### 6.3 Regression tests

- Existing bugfixes should be covered by explicit tests
- Add tests for edge cases in constructor header parsing and rule matching

## 7. How to Add New Tests

1. Choose target module (e.g., `modify.py`) and corresponding test file (`tests/test_modify.py`).
2. Follow current style:
   - use `pytest`
   - use `tempfile.TemporaryDirectory()` / `tmp_path`
   - use `unittest.mock` for network/process/IO isolation
3. Prefer deterministic tests:
   - avoid external network calls
   - avoid dependency on host-specific state
4. Include both success and failure-path assertions.
5. Run:
   - `pytest -q`
   - `pytest --cov=src/conda_tool --cov-report=term-missing`
   - `ruff check .`

## 8. Suggested Test Additions

- `repack.py`: direct tests for header MD5/size patch correctness
- `extract.py`: malformed header boundary handling edge cases
- `makedb.py`: retry/backoff behavior with mocked aiohttp failures
- `modify.py`: mixed glob + directory rule conflicts and metadata consistency checks

## 9. CI Recommendations

Typical CI stages:

1. Install dependencies
2. Run `ruff check .`
3. Run `pytest --cov=src/conda_tool --cov-report=xml`
4. Run `pylint $(git ls-files '*.py')`

Optionally enforce minimum coverage threshold in CI policy.
