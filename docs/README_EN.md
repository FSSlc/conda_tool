# conda_tool Documentation (English)

## 1. Project Overview

`conda_tool` is a pure-Python CLI toolkit for working with:

- Conda package metadata and package binaries
- Conda feedstock recipe extraction workflows
- Conda-constructor `.sh` installer extraction, modification, and repacking

It is designed for package engineering and release tooling scenarios where you need to inspect, transform, and rebuild Conda artifacts quickly.

## 2. Core Features

- **Unified CLI**: `ct` as a single entry point with subcommands
- **Standalone CLIs**: each tool can run independently (`ct_makedb`, `ct_dlpkg`, etc.)
- **Async metadata pipeline**: `ct_makedb` downloads and transforms `repodata.json` concurrently
- **Package-to-feedstock workflow**: `ct_dlpkg` pulls recipe/source from package binaries and rewrites local source paths
- **Constructor installer extraction**: `ct_extract` supports multiple constructor shell formats
- **Rule-based package mutation**: `ct_modify` supports add/move/delete/strip operations via JSON rules
- **End-to-end installer repack**: `ct_repack` chains extract → modify → repack and updates header metadata

## 3. CLI Commands

| Command | Description |
|---|---|
| `ct` | Main command dispatcher |
| `ct_makedb` | Build local package database from conda-forge repodata |
| `ct_dlpkg` | Download package binary, extract recipe, fetch source files |
| `ct_extract` | Extract constructor `.sh` installer payload |
| `ct_modify` | Modify `.conda` / `.tar.bz2` packages by rule file |
| `ct_repack` | Extract + modify + repack constructor `.sh` installer |

## 4. Installation / Quick Start

### 4.1 Prerequisites

- Python **3.10+**
- Recommended: virtual environment

### 4.2 Install from source

```bash
git clone https://github.com/FSSlc/conda_tool.git
cd conda_tool
python -m pip install -U pip
pip install -e .
```

### 4.3 Verify installation

```bash
ct -V
ct makedb --help
ct_makedb --help
```

## 5. Usage Guide

> Note: `conda_tool.utils.SCRIPT_DIR` is `os.getcwd()`. Default paths such as `data/`, `workdir/`, `recipes/`, `pkgs/`, and `output/` are relative to the directory where you run commands.

---

### 5.1 `ct` (main dispatcher)

```bash
ct [-V|--version] <command> [args...]
```

Subcommands:

- `makedb`
- `dlpkg`
- `extract`
- `modify`
- `repack`

Example:

```bash
ct makedb --arch noarch linux-64
```

---

### 5.2 `ct_makedb`

Builds local package DB from conda-forge `repodata.json.bz2`.

```bash
ct_makedb [--arch ...] [--url ...] [-f|--force_refresh] [--max N] [--file-max N]
```

Arguments:

- `--arch`: one or more architectures (default: `noarch linux-64 linux-aarch64`)
- `--url`: conda-forge URL or Nanjing mirror
- `-f, --force_refresh`: force redownload instead of loading local cache
- `--max`: max concurrent network tasks (default: `100`)
- `--file-max`: max concurrent file operations (default: `50`)

Outputs (under current working directory):

- `data/<arch>/data.zstd`: raw merged repodata (msgpack + zstd)
- `data/packages/<pkgname>.zstd`: per-package sorted records for fast lookup

Example:

```bash
ct_makedb --arch noarch linux-64 --max 120 --file-max 80
```

---

### 5.3 `ct_dlpkg`

Downloads one package binary, extracts recipe, downloads source archives, rewrites recipe URL entries to local paths.

```bash
ct_dlpkg PKGNAME 
  [-ub|--upper_bound VERSION] [--py 310] [--subdir linux-64] [--ignore-py] [-i|--interact] 
  [--specs_dir PATH] [--workdir PATH] [--recipes-dir PATH] [--pkgs-dir PATH]
```

Arguments:

- `PKGNAME`: package name
- `-ub, --upper_bound`: max acceptable version
- `--py`: Python build selector string (default: `310`)
- `--subdir`: target subdir (`noarch`, `linux-64`, `linux-aarch64`, `win-64`, `win-arm64`)
- `--ignore-py`: ignore Python build string filtering
- `-i, --interact`: interactive selection from candidates
- `--specs_dir`: path to DB package specs (`data/packages` by default)
- `--workdir`: temporary package download/extract area
- `--recipes-dir`: output feedstock-like recipe directory
- `--pkgs-dir`: output source archives directory

Example:

```bash
ct_dlpkg numpy --subdir linux-64 --py 311 --recipes-dir ./recipes --pkgs-dir ./pkgs
```

---

### 5.4 `ct_extract`

Extracts a conda-constructor shell installer into script, payload archive, and package workspace.

```bash
ct_extract -s SOURCE_SH [-o OUTPUT_DIR] [-c|--clean] [-gr|--generate_repo] [-k|--keep_tar]
```

Arguments:

- `-s, --source`: source `.sh` installer (required)
- `-o, --output`: output directory (default: `./output`)
- `-c, --clean`: clean output directory before extraction
- `-gr, --generate_repo`: reorganize extracted packages by subdir
- `-k, --keep_tar`: keep extracted `pkgs.tar`

Example:

```bash
ct_extract -s Miniforge3.sh -o ./out --clean --generate_repo
```

---

### 5.5 `ct_modify`

Modifies one or multiple conda packages according to JSON rules.

```bash
ct_modify -c RULE_FILE -s PKG_OR_DIR [-k|--keep_origin]
ct_modify -oc
```

Arguments:

- `-oc, --output_example_config`: generate sample `config.json`
- `-c, --config_path`: rule file path
- `-s, --pkg_path`: target package file or directory
- `-k, --keep_origin`: keep original package (backup with `.bk`)

Supported operations in rule file:

- `add`: copy files into package
- `mv`: move/rename package files
- `delete`: remove files matched by pathspec/gitwildmatch
- `strip`: run `strip --strip-debug` for matched ELF files

Examples:

```bash
ct_modify -oc
ct_modify -c ./rules.json -s ./workdir/pkgs
```

---

### 5.6 `ct_repack`

One-shot constructor installer update workflow.

```bash
ct_repack -s SOURCE_SH -c RULE_FILE [-o OUTPUT_SH]
```

Arguments:

- `-s, --source`: original installer `.sh`
- `-c, --config`: modify rule file
- `-o, --output`: output installer path (default: `mod-<source_basename>`)

Behavior:

1. Extract installer
2. Modify contained conda packages via rule file
3. Repack installer payload
4. Update installer header MD5 and size fields

Example:

```bash
ct_repack -s ./Miniforge3.sh -c ./rules.json -o ./Miniforge3-mod.sh
```

## 6. Configuration (Modify Rule File)

Rule file is JSON mapping package name to operation sets.

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

Guidelines:

- `add` source paths can be absolute or rule-file-relative
- `mv/delete/strip` operate on extracted package content
- glob matching uses `pathspec` (gitwildmatch style)

See detailed explanation:

- [modify_rule_details_en.md](./modify_rule_details_en.md)

## 7. Development & QA

- Test: `pytest -q`
- Coverage: `pytest --cov=src/conda_tool --cov-report=term-missing`
- Lint (ruff): `ruff check .`
- Lint (pylint): `pylint $(git ls-files '*.py')`

## 8. Related Documents

- [Architecture (English)](./architecture_en.md)
- [Requirements (English)](./requirements_en.md)
- [Testing Guide (English)](./testing_en.md)
- [Deployment Guide (English)](./deployment_en.md)

## 9. License

MIT
