# conda_tool Requirements Design (English)

## 1. Introduction

This document defines functional and non-functional requirements for `conda_tool` and its sub-tools.

## 2. Functional Requirements

### 2.1 Common CLI Requirements

| ID | Requirement |
|---|---|
| FR-CLI-001 | System shall provide top-level command `ct` with subcommands `makedb`, `dlpkg`, `extract`, `modify`, `repack`. |
| FR-CLI-002 | System shall provide standalone command aliases (`ct_makedb`, `ct_dlpkg`, `ct_extract`, `ct_modify`, `ct_repack`). |
| FR-CLI-003 | `ct -V/--version` shall print package version and exit. |
| FR-CLI-004 | Invalid/missing command shall return non-zero exit code with clear message. |

### 2.2 `makedb` Requirements

| ID | Requirement |
|---|---|
| FR-MDB-001 | System shall download `repodata.json.bz2` for one or more architectures from configured conda-forge endpoint. |
| FR-MDB-002 | System shall support retry on transient network errors. |
| FR-MDB-003 | System shall merge `packages` and `packages.conda` entries from repodata. |
| FR-MDB-004 | System shall store per-arch merged data as msgpack + zstd compressed file. |
| FR-MDB-005 | System shall build per-package compressed index files sorted by version/timestamp/build. |
| FR-MDB-006 | System shall allow force refresh or loading existing local data. |
| FR-MDB-007 | System shall allow configurable network and file-operation concurrency limits. |

### 2.3 `dlpkg` Requirements

| ID | Requirement |
|---|---|
| FR-DLP-001 | System shall read package specs from local `data/packages/<pkg>.zstd`. |
| FR-DLP-002 | System shall support filtering candidates by Python build string, subdir, and upper version bound. |
| FR-DLP-003 | System shall support interactive package version selection mode. |
| FR-DLP-004 | System shall download selected package binary (`.conda` or `.tar.bz2`). |
| FR-DLP-005 | System shall extract recipe from package info directory. |
| FR-DLP-006 | System shall parse both `meta.yaml` and `recipe.yaml`. |
| FR-DLP-007 | System shall extract source URLs and download source archives in parallel. |
| FR-DLP-008 | System shall rewrite recipe source URLs to local relative paths and preserve original URL as comment. |
| FR-DLP-009 | System shall output dependency section for manual follow-up build planning. |

### 2.4 `extract` Requirements

| ID | Requirement |
|---|---|
| FR-EXT-001 | System shall parse constructor `.sh` headers and identify payload boundaries. |
| FR-EXT-002 | System shall support both old mode (BYTES/LINES) and new mode (boundary1/boundary2). |
| FR-EXT-003 | System shall extract script section to `tpl.sh`. |
| FR-EXT-004 | System shall extract embedded conda executable when present. |
| FR-EXT-005 | System shall extract payload tar and unpack to `workdir`. |
| FR-EXT-006 | System shall optionally reorganize package files into subdir repository layout (`--generate_repo`). |
| FR-EXT-007 | System shall support cleanup and keep/remove tar options. |

### 2.5 `modify` Requirements

| ID | Requirement |
|---|---|
| FR-MOD-001 | System shall accept JSON rule file keyed by package name. |
| FR-MOD-002 | System shall support `add`, `mv`, `delete`, and `strip` operations. |
| FR-MOD-003 | System shall support file glob/pathspec matching for rule expansion. |
| FR-MOD-004 | System shall support processing a single package file or a directory of packages. |
| FR-MOD-005 | System shall unpack package, apply file operations, and rebuild in original format. |
| FR-MOD-006 | System shall update package metadata files (`paths.json`, `files`, `has_prefix`) consistently. |
| FR-MOD-007 | System shall support preserving original package (`--keep_origin`). |
| FR-MOD-008 | System shall provide sample config output mode (`-oc`). |

### 2.6 `repack` Requirements

| ID | Requirement |
|---|---|
| FR-RPK-001 | System shall orchestrate extract → modify → repack workflow for constructor `.sh`. |
| FR-RPK-002 | System shall create temporary workspace and clean up automatically. |
| FR-RPK-003 | System shall rebuild `pkgs.tar` from modified package workspace. |
| FR-RPK-004 | System shall regenerate output installer and preserve executable permission. |
| FR-RPK-005 | System shall update payload MD5 and size metadata in shell header. |
| FR-RPK-006 | System shall fail if output path already exists unless user changes path. |

## 3. Non-Functional Requirements

### 3.1 Performance

| ID | Requirement |
|---|---|
| NFR-PERF-001 | `makedb` should leverage asynchronous I/O for high-latency network conditions. |
| NFR-PERF-002 | `modify` should use concurrent file processing for bulk file operations. |
| NFR-PERF-003 | `dlpkg` should support parallel source archive downloads. |
| NFR-PERF-004 | Compression/decompression should use streaming or chunking where practical to control memory usage. |

### 3.2 Reliability

| ID | Requirement |
|---|---|
| NFR-REL-001 | Tool shall provide deterministic non-zero exit codes for invalid inputs and unrecoverable errors. |
| NFR-REL-002 | Network download tasks shall include retry/backoff strategy for transient failures. |
| NFR-REL-003 | Archive extraction shall include safety checks against suspicious tar entries where implemented. |
| NFR-REL-004 | Critical operations should log actionable error messages. |

### 3.3 Compatibility / Platform

| ID | Requirement |
|---|---|
| NFR-COMP-001 | Runtime shall be Python 3.10+ (pure Python implementation). |
| NFR-COMP-002 | Tool should run on Linux/macOS/Windows where dependencies are available. |
| NFR-COMP-003 | Supported package formats shall include `.conda` and `.tar.bz2`. |

### 3.4 Maintainability

| ID | Requirement |
|---|---|
| NFR-MNT-001 | Code quality gates shall include `ruff` and `pylint`. |
| NFR-MNT-002 | Automated tests shall be implemented with `pytest` and `pytest-cov`. |
| NFR-MNT-003 | Module-level responsibilities shall remain separated (CLI dispatch, parsing, transform, utility). |

## 4. Input / Output Specifications

### 4.1 Inputs

| Tool | Input |
|---|---|
| `ct_makedb` | arch list, mirror URL, concurrency options |
| `ct_dlpkg` | package name, selection filters, local DB path, output directories |
| `ct_extract` | source `.sh`, output directory, extraction behavior flags |
| `ct_modify` | rule JSON path, package file/dir path, keep-origin flag |
| `ct_repack` | source `.sh`, rule JSON path, output `.sh` path |

### 4.2 Outputs

| Tool | Output |
|---|---|
| `ct_makedb` | `data/<arch>/data.zstd`, `data/packages/<pkg>.zstd` |
| `ct_dlpkg` | downloaded package binary, extracted recipe directory, source archive files |
| `ct_extract` | `tpl.sh`, optional `_conda`, `workdir/`, optional `pkgs.tar` |
| `ct_modify` | modified package archives (and optional `.bk` backup) |
| `ct_repack` | modified constructor installer `.sh` |

## 5. Constraints and Assumptions

### 5.1 Constraints

- Project must remain pure Python and compatible with declared dependencies.
- Default workspace behavior is tied to current working directory (`os.getcwd()`).
- Rule format for `modify` is JSON-based and package-name keyed.
- Constructor shell formats are limited to patterns currently parsed by `extract.py`.

### 5.2 Assumptions

- Users run commands in writable directories.
- Remote channel endpoints are reachable and provide valid repodata.
- Input packages/installers are not corrupted and conform to expected formats.
- `strip` command availability depends on host toolchain for strip-related operations.

## 6. Acceptance Criteria (Summary)

- All CLI commands display help and validate required arguments.
- End-to-end workflows (`makedb -> dlpkg`, `extract -> modify -> repack`) complete successfully on representative artifacts.
- Metadata consistency files are preserved/updated after package mutation.
- Unit and integration tests pass on supported Python versions.
