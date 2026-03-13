# conda_tool Architecture Design (English)

## 1. Scope

This document describes the architecture of `conda_tool`, a Python CLI toolkit for:

- Conda metadata indexing (`makedb`)
- Package-to-feedstock/source reconstruction (`dlpkg`)
- Constructor installer extraction (`extract`)
- Rule-driven package mutation (`modify`)
- End-to-end installer rebuild (`repack`)

## 2. High-Level Architecture

```text
                        +--------------------+
                        |   User / CI Job    |
                        +---------+----------+
                                  |
                                  v
+---------------------------------------------------------------+
|                    CLI Layer (argparse)                       |
|  ct (__main__.py) -> dynamic import -> makedb/dlpkg/...       |
+-----------------------------+---------------------------------+
                              |
                              v
+-----------------------------------------------------------------------+
|                         Tool Modules (src/conda_tool)                 |
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
|                     Filesystem Artifacts (cwd-based)                  |
| data/, data/packages/, workdir/, recipes/, pkgs/, output/, temp dirs |
+-----------------------------------------------------------------------+
```

## 3. Entry and Command Dispatch

`src/conda_tool/__main__.py`:

- Uses `argparse` with subcommands (`makedb`, `dlpkg`, `extract`, `modify`, `repack`)
- Dynamically imports target module with `importlib.import_module`
- Rewrites `sys.argv` so each sub-tool parses its own arguments
- Supports `-V/--version`

Console scripts (from `pyproject.toml`):

- `ct = conda_tool.__main__:main`
- `ct_makedb = conda_tool.makedb:main`
- `ct_dlpkg = conda_tool.dlpkg:main`
- `ct_extract = conda_tool.extract:main`
- `ct_modify = conda_tool.modify:main`
- `ct_repack = conda_tool.repack:main`

## 4. Module Responsibilities

| Module | Responsibility |
|---|---|
| `__main__.py` | Top-level command dispatcher |
| `makedb.py` | Download repodata, merge package records, build compressed per-package DB |
| `dlpkg.py` | Resolve target package spec, download binary, extract recipe, download source archives, rewrite source URLs |
| `extract.py` | Parse constructor `.sh` format and extract payload artifacts |
| `modify.py` | Apply add/mv/delete/strip file mutations and rebuild package archives |
| `repack.py` | Pipeline orchestration: extract → modify → repack `.sh`, header checksum/size patching |
| `recipe.py` | Parse/modify `meta.yaml` and `recipe.yaml` with template-safe placeholder substitution |
| `utils.py` | Shared utilities: logging, hashing, archive extraction, file listing, compression helpers |

## 5. Data/Execution Workflows

### 5.1 `makedb` → `dlpkg` Workflow

```text
ct_makedb
  |
  | async download repodata.json.bz2 (per arch)
  v
merge packages + packages.conda
  |
  | msgpack + zstd
  v
data/<arch>/data.zstd
  |
  | transform by package name + version sorting
  v
data/packages/<pkg>.zstd
  |
  +-------------------------------> ct_dlpkg <PKGNAME>
                                     |
                                     | read <pkg>.zstd
                                     | filter by subdir/python/version/interact
                                     v
                               selected package spec
                                     |
                                     | download binary .conda/.tar.bz2
                                     | extract info/recipe
                                     v
                               recipe output + source URL list
                                     |
                                     | parallel source archive downloads
                                     | rewrite recipe URLs to local relative paths
                                     v
                               local feedstock-like recipe + source files
```

Implementation highlights:

- `makedb` uses `asyncio`, `aiohttp`, `aiofiles`, semaphores
- `dlpkg` source downloads use `ProcessPoolExecutor`
- Version ordering uses `packaging.version`

### 5.2 `extract` → `modify` → `repack` Workflow

```text
ct_extract -s installer.sh
  |
  | parse_sh(): read header metadata + boundaries
  |  - old_mode: BYTES/LINES
  |  - new_mode: boundary1/boundary2
  v
extract script (tpl.sh), optional _conda, pkgs.tar
  |
  | unpack pkgs.tar -> workdir/pkgs
  v
ct_modify -c rules.json -s workdir/pkgs
  |
  | extract each .conda/.tar.bz2
  | apply add/mv/delete/strip
  | update info/paths.json + files + has_prefix
  | rebuild package format
  v
modified packages
  |
  +-----------------------------> ct_repack
                                   |
                                   | calls extract + modify programmatically
                                   | rebuild pkgs.tar from workdir
                                   | append to script/conda-exec sections
                                   | patch MD5 and size fields in header
                                   v
                                 new installer .sh
```

## 6. Key Design Decisions

1. **CWD-based workspace (`SCRIPT_DIR = os.getcwd()`)**
   - Keeps execution self-contained and portable for ad-hoc runs.
   - Tradeoff: users must run in intended directory to control artifact placement.

2. **Dual CLI strategy (`ct` + standalone tools)**
   - Improves UX for both discoverability (`ct`) and scripting (`ct_makedb`).

3. **Template-safe recipe parsing**
   - `recipe.py` masks `{{ ... }}` and `${{ ... }}` before YAML parse, then restores.
   - Avoids introducing hard dependency on full Jinja/rattler evaluators.

4. **Concurrency tuned by workload type**
   - Async I/O for network-heavy `makedb`
   - Process pool for source download/CPU isolation in `dlpkg`
   - Thread pool for file operations in `modify`

5. **Format-aware package rebuild**
   - Supports `.conda` (zip container + `pkg-*.tar.zst` + `info-*.tar.zst`)
   - Supports legacy `.tar.bz2`

## 7. Dependency Graph (Logical)

```text
__main__
  ├── makedb ───┐
  ├── dlpkg  ───┼──> utils
  ├── extract ──┘
  ├── modify ─────> utils
  └── repack ─────> extract, modify, utils

dlpkg ───────────> recipe
```

External libraries:

- Core runtime: `ruamel-yaml`, `colorama`, `packaging`, `pathspec`, `zstandard`, `rich`, `msgpack`, `aiofiles`, `aiohttp`
- Dev/test: `pytest`, `pytest-cov`, `coverage`, `ruff`, `pylint`

## 8. File Format Notes

### 8.1 Local DB (`msgpack + zstd`)

- `data/<arch>/data.zstd`: compressed map of package filename -> metadata
- `data/packages/<name>.zstd`: compressed list of package specs (sorted by version/timestamp/build)

Typical spec fields:

- `name`, `version`, `nv`, `depends`, `md5`, `build`, `subdir`, `timestamp`, `url`

### 8.2 `.conda` package format

`.conda` package is a zip container with:

- `metadata.json` (`conda_pkg_format_version`)
- `pkg-<name-ver-build>.tar.zst` (payload files)
- `info-<name-ver-build>.tar.zst` (metadata files)

`modify.py` updates metadata consistency:

- `info/paths.json`
- `info/files`
- `info/has_prefix`

### 8.3 Constructor `.sh` installer format

`extract.py` supports two header styles:

- **old mode**: uses `# BYTES:` / `# LINES:`
- **new mode**: uses `boundary1=` / `boundary2=` markers

Extracted sections:

- Script header/body (`tpl.sh`)
- Optional embedded conda executable (`_conda`)
- Package payload tar (`pkgs.tar`)

`repack.py` recalculates payload hash/size and patches them into header fields.

## 9. Observability and Error Handling

- Unified logging via `rich.logging.RichHandler`
- Per-module logger names (`conda_tool.makedb`, `conda_tool.modify`, etc.)
- Explicit `sys.exit()` on CLI validation/critical failures
- Safe extraction guards for tar entries and link handling in `utils.py`

## 10. Extensibility

Potential extension points:

- Add new subcommands by registering module in `__main__.py`
- Extend modify rule schema (e.g., text patching, binary diff)
- Add more channel mirrors or authentication strategies
- Introduce structured metadata index backends (sqlite/parquet)
