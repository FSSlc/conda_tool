"""Tests for conda_tool.recipe — RecipeParser for meta.yaml and recipe.yaml."""

import os
import tempfile
from pathlib import Path

from conda_tool.recipe import RecipeFormat, RecipeParser

# ---------------------------------------------------------------------------
# Fixture helpers — raw recipe content strings
# ---------------------------------------------------------------------------

META_YAML_SIMPLE = """
package:
  name: demo
  version: "1.0.0"

source:
  url: https://example.com/demo-1.0.0.tar.gz
  sha256: abc123def456

requirements:
  host:
    - python
  run:
    - python
"""

META_YAML_JINJA2 = """
{% set version = "2.3.4" %}
{% set sha = "deadbeef" %}

package:
  name: curl
  version: {{ version }}

source:
  url: https://curl.haxx.se/download/curl-{{ version }}.tar.bz2
  sha256: {{ sha }}

requirements:
  host:
    - openssl
  run:
    - openssl
"""

META_YAML_MULTI_SOURCE = """
package:
  name: multi
  version: "1.0"

source:
  - url: https://example.com/a.tar.gz
    sha256: aaa111
  - url: https://example.com/b.tar.gz
    md5: bbb222
"""

META_YAML_MULTI_URL = """
package:
  name: zlib
  version: "1.3.1"

source:
  url:
    - https://zlib.net/zlib-1.3.1.tar.gz
    - https://mirror.example.com/zlib-1.3.1.tar.gz
  sha256: abc123
"""

META_YAML_NO_SOURCE = """
package:
  name: nosource
  version: "0.1"
"""

META_YAML_GIT_SOURCE = """
package:
  name: gitsrc
  version: "0.1"

source:
  git_url: https://github.com/example/repo.git
  git_rev: main
"""

RECIPE_YAML_SIMPLE = """
context:
  version: "3.0.1"

package:
  name: pandas
  version: ${{ version }}

source:
  url: https://github.com/pandas-dev/pandas/releases/download/v${{ version }}/pandas-${{ version }}.tar.gz
  sha256: deadbeef123

requirements:
  host:
    - python
    - numpy
  run:
    - python
    - numpy
"""

RECIPE_YAML_MULTI_SOURCE = """
context:
  version: "1.0"

package:
  name: multi
  version: ${{ version }}

source:
  - url: https://example.com/a-${{ version }}.tar.gz
    sha256: aaa
  - url: https://example.com/b-${{ version }}.tar.gz
    sha256: bbb
"""

RECIPE_YAML_SCHEMA_VERSION = """
schema_version: 1

context:
  version: "2.0"

package:
  name: modern
  version: ${{ version }}

source:
  url: https://example.com/modern-${{ version }}.tar.gz
  sha256: modern_hash
"""


def _write_recipe(tmpdir: str, filename: str, content: str) -> str:
    """Write recipe content to a temp file and return its path."""
    path = os.path.join(tmpdir, filename)
    Path(path).write_text(content, encoding="utf-8")
    return path


class TestRecipeFormat:
    def test_detect_format_meta_yaml(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_recipe(tmpdir, "meta.yaml", META_YAML_SIMPLE)
            parser = RecipeParser(path)
            assert parser.format == RecipeFormat.META_YAML

    def test_detect_format_recipe_yaml(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_recipe(tmpdir, "recipe.yaml", RECIPE_YAML_SIMPLE)
            parser = RecipeParser(path)
            assert parser.format == RecipeFormat.RECIPE_YAML

    def test_detect_format_template_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_recipe(tmpdir, "meta.yaml.template", META_YAML_SIMPLE)
            parser = RecipeParser(path)
            assert parser.format == RecipeFormat.META_YAML


class TestLoadUrls:
    def test_meta_yaml_single_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_recipe(tmpdir, "meta.yaml", META_YAML_SIMPLE)
            parser = RecipeParser(path)
            urls = parser.load_urls()

        assert len(urls) == 1
        assert urls[0]["url"] == "https://example.com/demo-1.0.0.tar.gz"
        assert urls[0]["hash_type"] == "sha256"
        assert urls[0]["hash"] == "abc123def456"
        assert urls[0]["fn"] is None

    def test_meta_yaml_jinja2_template(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_recipe(tmpdir, "meta.yaml", META_YAML_JINJA2)
            parser = RecipeParser(path)
            urls = parser.load_urls()

        assert len(urls) == 1
        url = urls[0]["url"]
        assert isinstance(url, str)
        assert "{{ version }}" in url
        assert "curl.haxx.se" in url

    def test_meta_yaml_multiple_sources(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_recipe(tmpdir, "meta.yaml", META_YAML_MULTI_SOURCE)
            parser = RecipeParser(path)
            urls = parser.load_urls()

        assert len(urls) == 2
        assert urls[0]["url"] == "https://example.com/a.tar.gz"
        assert urls[0]["hash_type"] == "sha256"
        assert urls[1]["url"] == "https://example.com/b.tar.gz"
        assert urls[1]["hash_type"] == "md5"

    def test_meta_yaml_multiple_urls_in_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_recipe(tmpdir, "meta.yaml", META_YAML_MULTI_URL)
            parser = RecipeParser(path)
            urls = parser.load_urls()

        assert len(urls) == 1
        url_list = urls[0]["url"]
        assert isinstance(url_list, list)
        assert len(url_list) == 2
        assert "zlib.net" in url_list[0]
        assert "mirror.example.com" in url_list[1]

    def test_no_source_section(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_recipe(tmpdir, "meta.yaml", META_YAML_NO_SOURCE)
            parser = RecipeParser(path)
            urls = parser.load_urls()

        assert urls == []

    def test_git_source_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_recipe(tmpdir, "meta.yaml", META_YAML_GIT_SOURCE)
            parser = RecipeParser(path)
            urls = parser.load_urls()

        assert urls == []

    def test_recipe_yaml_single_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_recipe(tmpdir, "recipe.yaml", RECIPE_YAML_SIMPLE)
            parser = RecipeParser(path)
            urls = parser.load_urls()

        assert len(urls) == 1
        url = urls[0]["url"]
        assert isinstance(url, str)
        assert "${{ version }}" in url
        assert "pandas" in url
        assert urls[0]["hash_type"] == "sha256"

    def test_recipe_yaml_with_context(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_recipe(tmpdir, "recipe.yaml", RECIPE_YAML_SIMPLE)
            parser = RecipeParser(path)

        assert parser.data is not None
        assert "context" in parser.data

    def test_recipe_yaml_multiple_sources(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_recipe(tmpdir, "recipe.yaml", RECIPE_YAML_MULTI_SOURCE)
            parser = RecipeParser(path)
            urls = parser.load_urls()

        assert len(urls) == 2
        assert "${{ version }}" in urls[0]["url"]
        assert "a-" in urls[0]["url"]
        assert "b-" in urls[1]["url"]

    def test_recipe_yaml_schema_version(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_recipe(tmpdir, "recipe.yaml", RECIPE_YAML_SCHEMA_VERSION)
            parser = RecipeParser(path)
            urls = parser.load_urls()

        assert len(urls) == 1
        assert "modern" in urls[0]["url"]


class TestReplaceSourceUrls:
    def test_replace_single_url(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_recipe(tmpdir, "meta.yaml", META_YAML_SIMPLE)
            parser = RecipeParser(path)
            result = parser.replace_source_urls({0: "../pkgs/demo-1.0.0.tar.gz"})

        assert "../pkgs/demo-1.0.0.tar.gz" in result
        assert "original:" in result
        assert "example.com" in result

    def test_replace_multiple_sources(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_recipe(tmpdir, "meta.yaml", META_YAML_MULTI_SOURCE)
            parser = RecipeParser(path)
            result = parser.replace_source_urls(
                {0: "../pkgs/a.tar.gz", 1: "../pkgs/b.tar.gz"}
            )

        assert "../pkgs/a.tar.gz" in result
        assert "../pkgs/b.tar.gz" in result
        assert "original: https://example.com/a.tar.gz" in result
        assert "original: https://example.com/b.tar.gz" in result

    def test_replace_preserves_jinja2(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_recipe(tmpdir, "meta.yaml", META_YAML_JINJA2)
            parser = RecipeParser(path)
            result = parser.replace_source_urls({0: "../pkgs/curl.tar.bz2"})

        assert "../pkgs/curl.tar.bz2" in result
        # Jinja2 set statements should be preserved
        assert "{% set version" in result
        # version reference in package section should be preserved
        assert "{{ version }}" in result

    def test_replace_preserves_dollar_jinja(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_recipe(tmpdir, "recipe.yaml", RECIPE_YAML_SIMPLE)
            parser = RecipeParser(path)
            result = parser.replace_source_urls({0: "../pkgs/pandas.tar.gz"})

        assert "../pkgs/pandas.tar.gz" in result
        # ${{ version }} in package section should be preserved
        assert "${{ version }}" in result
        # context block should still be there
        assert "context:" in result

    def test_replace_multiple_urls_list(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_recipe(tmpdir, "meta.yaml", META_YAML_MULTI_URL)
            parser = RecipeParser(path)
            result = parser.replace_source_urls({0: "../pkgs/zlib.tar.gz"})

        assert "../pkgs/zlib.tar.gz" in result
        assert "original:" in result
        assert "zlib.net" in result

    def test_replace_preserves_comments(self) -> None:
        content = """
package:
  name: demo
  version: "1.0"

source:
  url: https://example.com/demo.tar.gz  # download link
  sha256: abc123
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_recipe(tmpdir, "meta.yaml", content)
            parser = RecipeParser(path)
            result = parser.replace_source_urls({0: "../pkgs/demo.tar.gz"})

        assert "../pkgs/demo.tar.gz" in result

    def test_replace_no_source_returns_raw(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_recipe(tmpdir, "meta.yaml", META_YAML_NO_SOURCE)
            parser = RecipeParser(path)
            result = parser.replace_source_urls({0: "anything"})

        assert result == META_YAML_NO_SOURCE

    def test_replace_out_of_range_index_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_recipe(tmpdir, "meta.yaml", META_YAML_SIMPLE)
            parser = RecipeParser(path)
            result = parser.replace_source_urls({99: "../pkgs/nope.tar.gz"})

        # URL should remain unchanged
        assert "https://example.com/demo-1.0.0.tar.gz" in result


class TestSaveAndReload:
    def test_save_and_reload_meta_yaml(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_recipe(tmpdir, "meta.yaml", META_YAML_SIMPLE)
            parser = RecipeParser(path)
            result = parser.replace_source_urls({0: "../pkgs/demo.tar.gz"})

            out_path = os.path.join(tmpdir, "out.yaml")
            parser.save(out_path, result)

            parser2 = RecipeParser(out_path)
            urls = parser2.load_urls()

        assert len(urls) == 1
        assert urls[0]["url"] == "../pkgs/demo.tar.gz"

    def test_save_and_reload_recipe_yaml(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_recipe(tmpdir, "recipe.yaml", RECIPE_YAML_SIMPLE)
            parser = RecipeParser(path)
            result = parser.replace_source_urls({0: "../pkgs/pandas.tar.gz"})

            out_path = os.path.join(tmpdir, "recipe.yaml")
            parser.save(out_path, result)

            parser2 = RecipeParser(out_path)
            urls = parser2.load_urls()

        assert len(urls) == 1
        assert urls[0]["url"] == "../pkgs/pandas.tar.gz"

    def test_save_without_content_uses_data(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_recipe(tmpdir, "meta.yaml", META_YAML_SIMPLE)
            parser = RecipeParser(path)

            out_path = os.path.join(tmpdir, "out.yaml")
            parser.save(out_path)

            content = Path(out_path).read_text(encoding="utf-8")

        assert "demo" in content
        assert "1.0.0" in content


class TestExtractReqs:
    def test_extract_reqs_meta_yaml(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_recipe(tmpdir, "meta.yaml", META_YAML_SIMPLE)
            parser = RecipeParser(path)
            reqs = parser.extract_reqs()

        assert "requirements" in reqs
        assert "python" in reqs

    def test_extract_reqs_recipe_yaml(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_recipe(tmpdir, "recipe.yaml", RECIPE_YAML_SIMPLE)
            parser = RecipeParser(path)
            reqs = parser.extract_reqs()

        assert "requirements" in reqs
        assert "python" in reqs
        assert "numpy" in reqs

    def test_extract_reqs_no_requirements(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_recipe(tmpdir, "meta.yaml", META_YAML_NO_SOURCE)
            parser = RecipeParser(path)
            reqs = parser.extract_reqs()

        assert reqs == ""

    def test_extract_reqs_jinja2_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_recipe(tmpdir, "meta.yaml", META_YAML_JINJA2)
            parser = RecipeParser(path)
            reqs = parser.extract_reqs()

        assert "requirements" in reqs
        assert "openssl" in reqs


class TestRoundtrip:
    def test_roundtrip_meta_yaml_preserves_structure(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_recipe(tmpdir, "meta.yaml", META_YAML_JINJA2)
            parser = RecipeParser(path)
            result = parser.replace_source_urls({0: "../pkgs/curl.tar.bz2"})

        # Key structural elements should survive roundtrip
        assert "{% set version" in result
        assert "{% set sha" in result
        assert "package:" in result
        assert "source:" in result
        assert "requirements:" in result

    def test_roundtrip_recipe_yaml_preserves_structure(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_recipe(tmpdir, "recipe.yaml", RECIPE_YAML_SIMPLE)
            parser = RecipeParser(path)
            result = parser.replace_source_urls({0: "../pkgs/pandas.tar.gz"})

        assert "context:" in result
        assert "${{ version }}" in result
        assert "package:" in result
        assert "source:" in result
        assert "requirements:" in result

