# Conda Package Modify Tool — Rule File Reference

Sometimes we need to modify the contents of a conda package, for example:

1. Add custom files into a conda package
2. Move files within a conda package to a different location
3. Delete certain files or directories from a conda package
4. Strip debug symbols from certain files to reduce size

The conda package modify tool (`ct_modify`) was developed to fulfill these needs.

To describe the desired modifications precisely, you write a **rule file**. The modify tool reads this file and executes the specified operations.

## Rule File Format

The rule file is a JSON file. Its top-level structure is a dictionary (object) where:

- **Keys** are the names of the packages to modify.
- **Values** are objects containing one or more of the four operation types.

Full example:

```json
{
  "conda": {
    "add": {
      "/xxx/conda_tool/dist/conda_tool-0.1.0-py3-none-any.whl": "bin/",
      "/xxx/conda_tool/.vscode/": "share/",
      "./src/conda_tool/*": "bin/"
    },
    "mv": {
      "bin/conda": "bin/_conda",
      "etc/fish": "share/"
    },
    "delete": ["etc/fish", "xonsh"],
    "strip": ["*.a", "*.so.*", "bin/*"]
  }
}
```

The four operation types are described in detail below.

### `add` Operation

The `add` rule is a key-value mapping where:

- **Key** — the source file or directory to add.
- **Value** — the destination path inside the conda package.

**Key rules:**

- Can be an **absolute path** or a **relative path**. Relative paths are resolved relative to the rule file's directory.
- Can be a **directory**. If the key ends with `/`, the corresponding value must also end with `/`, meaning the entire directory will be copied into the destination directory.
- Supports **glob patterns**. When using a glob, the value must end with `/`. For example, `../../src/conda_tool/*` copies all files under `conda_tool/` into the package's `bin/` directory.

**Value rules:**

- Must be a **relative path**, relative to the extracted conda package root.
- If the value represents a directory, it must end with `/`.

### `mv` Operation

The `mv` rule moves or renames files **within** the conda package. Both the key (source) and value (destination) are paths relative to the extracted package root.

The matching rules are similar to the `add` operation described above.

### `delete` Operation

The `delete` rule is a **list** of paths or patterns specifying files and directories to remove from the package.

Matching uses **gitwildmatch**-style patterns (similar to `.gitignore` rules), implemented via the [`pathspec`](https://pypi.org/project/pathspec/) library.

### `strip` Operation

The `strip` rule is a **list** of paths or patterns specifying ELF binary files to strip debug symbols from (using `strip --strip-debug`).

> **Note:** The strip feature is still being refined. Currently it only processes files identified as ELF binaries.

Matching uses **gitwildmatch**-style patterns (same as `delete`), implemented via the [`pathspec`](https://pypi.org/project/pathspec/) library.
