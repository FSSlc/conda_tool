# conda_tool

Conda Tool for download recipe, exctract constructor sh package, modify conda package.

Including following tools:

- `ct_makedb`: download `repodata.json` from conda-forge, then create a json data file.
- `ct_dlpkg`: using data file generated by `ct_makedb`, download given package name's recipe and source.
- `ct_extract`: extract conda constructor sh package to get conda packages.
- `ct_modify`: modify conda package with a given rule file, such as add files, remove files from a given conda package.
