# conda_tool Deployment & Usage Guide (English)

## 1. Prerequisites

- Python 3.10 or newer
- `pip`
- Network access to conda-forge/mirror for metadata and package download
- Optional (for some strip workflows): system `strip` command

Recommended:

- Use virtual environments (`venv`, conda env, etc.)
- Run commands from a dedicated workspace directory because default data paths are based on current working directory

## 2. Installation Methods

## 2.1 Install from PyPI (if published)

```bash
pip install conda_tool
```

## 2.2 Install from source

```bash
git clone https://github.com/FSSlc/conda_tool.git
cd conda_tool
python -m pip install -U pip
pip install .
```

## 2.3 Development mode install

```bash
git clone https://github.com/FSSlc/conda_tool.git
cd conda_tool
pip install -e .
```

## 2.4 Install development/test tooling

```bash
pip install pytest pytest-cov coverage ruff pylint
```

## 3. Environment Setup

Create isolated environment example:

```bash
python -m venv .venv
source .venv/bin/activate   # Linux/macOS
# .venv\Scripts\activate   # Windows
pip install -U pip
pip install -e .
```

Optional workspace bootstrap:

```bash
mkdir -p data workdir recipes pkgs output
```

## 4. Typical Workflow Walkthrough

### 4.1 Build local metadata database

```bash
ct_makedb --arch noarch linux-64 linux-aarch64
```

This creates:

- `data/<arch>/data.zstd`
- `data/packages/*.zstd`

### 4.2 Download one package and create local recipe workspace

```bash
ct_dlpkg numpy --subdir linux-64 --py 311 --recipes-dir ./recipes --pkgs-dir ./pkgs
```

This typically produces:

- extracted recipe directory under `recipes/`
- source tarballs under `pkgs/`

### 4.3 Extract a constructor installer

```bash
ct_extract -s ./Miniforge3.sh -o ./output --clean --generate_repo
```

### 4.4 Modify packages with rule file

Generate sample rule and edit it:

```bash
ct_modify -oc
# edit ./config.json
```

Apply rules:

```bash
ct_modify -c ./config.json -s ./output/workdir/pkgs --keep_origin
```

### 4.5 Repack installer

```bash
ct_repack -s ./Miniforge3.sh -c ./config.json -o ./Miniforge3-mod.sh
```

## 5. Build and Packaging (Project Maintainers)

Project uses **Hatchling** build backend (defined in `pyproject.toml`).

Example build command:

```bash
python -m pip install hatch
hatch build
```

Artifacts are typically emitted to `dist/`.

## 6. Troubleshooting

### 6.1 `Requested package ... is not in database`

Cause:

- `ct_dlpkg` cannot find `data/packages/<pkg>.zstd`

Fix:

- Run `ct_makedb` first
- Verify current working directory and `--specs_dir`

### 6.2 Download/network failures

Cause:

- mirror unavailable, unstable network, firewall restrictions

Fix:

- switch to alternate `--url` in `ct_makedb`
- retry with lower concurrency (`--max`, `--file-max`)

### 6.3 Wrong output location

Cause:

- defaults are cwd-based (`SCRIPT_DIR = os.getcwd()`)

Fix:

- run commands in intended workspace
- pass explicit paths (`--workdir`, `--recipes-dir`, `--pkgs-dir`, `-o`)

### 6.4 `strip` related errors in `ct_modify`

Cause:

- non-ELF files matched, or `strip` tool unavailable

Fix:

- narrow strip patterns
- ensure required binutils/toolchain are installed

### 6.5 `ct_repack` says output file already exists

Fix:

- choose a new `-o` path
- remove old target file if safe

## 7. Operational Tips

- Keep one workspace per task to avoid mixing artifacts.
- For CI, prefer explicit output paths to ensure reproducibility.
- Add `pytest`, `ruff`, and `pylint` checks before packaging releases.

## 8. Related Docs

- [README_EN](./README_EN.md)
- [Architecture](./architecture_en.md)
- [Requirements](./requirements_en.md)
- [Testing](./testing_en.md)
