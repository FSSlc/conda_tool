"""Conda recipe parser supporting both meta.yaml and recipe.yaml formats.

Handles Jinja2 templates ({{ }}) from conda-build meta.yaml and
rattler-build templates (${{ }}) from recipe.yaml by temporarily
replacing template expressions with safe placeholders before YAML parsing.
"""

import io
import re
from enum import Enum
from logging import getLogger
from typing import Literal, TypedDict

import ruamel.yaml

logger = getLogger("conda_tool.recipe")

HashType = Literal["md5", "sha1", "sha256"]
PackageUrl = str | list[str]


class RecipeFormat(Enum):
    """Supported recipe file formats."""

    META_YAML = "meta.yaml"
    RECIPE_YAML = "recipe.yaml"


class SourceUrlSpec(TypedDict):
    """Normalized source URL entry extracted from a recipe."""

    url: PackageUrl
    hash_type: HashType | None
    hash: str | None
    fn: str | None


class RecipeParser:
    """Parse conda recipes and support structured source URL rewriting.

    Supports both meta.yaml (conda-build, Jinja2 ``{{ }}``) and
    recipe.yaml (rattler-build, ``${{ }}``) formats.
    """

    # Match ${{ ... }} before {{ ... }} to avoid consuming the inner expression first.
    _TEMPLATE_EXPR_RE = re.compile(r"\$\{\{.*?\}\}|\{\{.*?\}\}")
    # Full-line Jinja2 control statements such as {% ... %}.
    _JINJA2_STMT_RE = re.compile(r"^(\s*)\{%.*?%\}\s*$", re.MULTILINE)
    # conda-build selector comments such as # [win].
    _SELECTOR_RE = re.compile(r"#\s*\[.*?\]\s*$", re.MULTILINE)

    def __init__(self, recipe_path: str) -> None:
        self.recipe_path = recipe_path
        self.format = self._detect_format()
        self._placeholders: dict[str, str] = {}
        self._counter = 0

        with open(recipe_path, encoding="utf-8") as f:
            self.raw_content = f.read()

        self._yaml = ruamel.yaml.YAML()
        self._yaml.indent(mapping=2, sequence=2, offset=2)
        self._yaml.preserve_quotes = True
        if self.format == RecipeFormat.META_YAML:
            sanitized = self._sanitize(self.raw_content)
            self.data = self._yaml.load(sanitized)
        else:
            self.data = self._yaml.load(self.raw_content)

    def _detect_format(self) -> RecipeFormat:
        if "recipe.yaml" in self.recipe_path:
            return RecipeFormat.RECIPE_YAML
        return RecipeFormat.META_YAML

    def _make_placeholder(self, match: re.Match) -> str:
        token = match.group(0)
        key = f"__RECIPE_PH_{self._counter}__"
        self._placeholders[key] = token
        self._counter += 1
        return key

    def _sanitize(self, content: str) -> str:
        """Replace template syntax with placeholders so the content becomes valid YAML."""
        # Convert Jinja2 syntax into placeholders so the YAML parser can read it.
        # Restore set statements to their original form when writing the file back.

        # Handle full-line Jinja2 statements first, especially set statements.
        lines = content.splitlines()
        temp_lines = []
        for line_idx, line in enumerate(lines):
            match = self._JINJA2_STMT_RE.match(line)
            if match:
                # This line is a full Jinja2 statement.
                token = match.group(0).strip()
                key = f"__JINJA2_STMT_{line_idx}__"
                # Store the original Jinja2 statement so restoration can preserve intent.
                self._placeholders[key] = token
                indent = match.group(1)
                # Replace Jinja2 statements with comments during YAML parsing.
                # Later restoration decides whether the comment marker should be removed.
                temp_lines.append(f"{indent}# {key}")
            else:
                temp_lines.append(line)

        # Replace ${{ }} and {{ }} expressions with placeholders.
        result = "\n".join(temp_lines)
        result = self._TEMPLATE_EXPR_RE.sub(self._make_placeholder, result)
        return result

    def _restore(self, content: str) -> str:
        """Restore placeholders back to the original template syntax."""
        # Restore expression placeholders first ({{ }} and ${{ }}).
        for key, value in sorted(
            self._placeholders.items(), key=lambda kv: -len(kv[0])
        ):
            # Handle placeholders for Jinja2 statements separately.
            if key.startswith("__JINJA2_STMT_"):
                # Detect whether this is a set statement.
                if "set " in value:
                    # Restore set statements as active syntax.
                    content = content.replace(f"# {key}", value)
                else:
                    # Keep control statements commented out.
                    content = content.replace(f"# {key}", f"# {value}")
            else:
                # Plain expression placeholders can be restored directly.
                content = content.replace(key, value)
        return content

    def load_urls(self) -> list[SourceUrlSpec]:
        """Extract all source URLs from the recipe."""
        if self.data is None:
            return []
        if self.format == RecipeFormat.META_YAML:
            if "source" not in self.data:
                return []
            sources = self.data["source"]
        else:
            if "recipe" not in self.data:
                return []
            if "source" not in self.data["recipe"]:
                return []
            sources = self.data["recipe"]["source"]
        if not isinstance(sources, list):
            sources = [sources]

        result: list[SourceUrlSpec] = []
        for item in sources:
            if not isinstance(item, dict) or "url" not in item:
                if isinstance(item, dict):
                    logger.warning(f"Not supporting source type for {item}")
                continue
            url = item["url"]
            # Restore placeholders for extraction without affecting later updates.
            # Any urllib.parse-specific handling should happen at the call site.
            final_url: PackageUrl
            if isinstance(url, str):
                final_url = self._restore(url)
            elif isinstance(url, list):
                final_url = [self._restore(str(u)) for u in item["url"]]
            else:
                # Preserve non-string values as-is.
                final_url = url

            hash_type: HashType | None = None
            file_hash = None
            for ht in ("sha256", "sha1", "md5"):
                if ht in item:
                    hash_type = ht  # type: ignore[assignment]
                    file_hash = str(item[ht])
                    break

            fn = item.get("fn", None)
            if fn is not None:
                fn = self._restore(str(fn))
            result.append(
                SourceUrlSpec(url=final_url, hash_type=hash_type, hash=file_hash, fn=fn)
            )
        return result

    def replace_source_urls(self, url_mapping: dict[int, str]) -> str:
        """Replace source URLs and return the updated file content.

        Args:
            url_mapping: Mapping of ``{source_index: new_local_path}``.
                Original URLs are preserved as comments.

        Returns:
            Updated file content with template syntax restored.
        """
        if self.data is None or "source" not in self.data:
            return self.raw_content

        sources = self.data["source"]
        is_single = not isinstance(sources, list)
        if is_single:
            sources = [sources]

        for idx, new_path in url_mapping.items():
            if idx >= len(sources):
                continue
            source = sources[idx]
            if not isinstance(source, dict) or "url" not in source:
                continue

            old_url = source["url"]
            # Build comment text from the restored original URL.
            if isinstance(old_url, list):
                comment = " | ".join(self._restore(str(u)) for u in old_url)
            else:
                comment = self._restore(str(old_url))

            # Replace the URL and annotate it with the original value.
            source["url"] = new_path
            # Only ruamel.yaml comment-aware nodes support end-of-line comments.
            if hasattr(sources[idx], "yaml_add_eol_comment"):
                sources[idx].yaml_add_eol_comment(f"original: {comment}", "url")
            else:
                # Fall back silently when comment support is unavailable.
                pass

        stream = io.StringIO()
        self._yaml.dump(self.data, stream)
        result = stream.getvalue()
        return self._restore(result)

    def save(self, output_path: str, content: str | None = None) -> None:
        """Save the updated recipe file."""
        if content is None:
            stream = io.StringIO()
            self._yaml.dump(self.data, stream)
            content = self._restore(stream.getvalue())
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)

    def extract_reqs(self) -> str:
        """Extract the requirements section from the parsed recipe data."""
        if self.data is None :
            return ""
        if self.format == RecipeFormat.META_YAML:
            if "requirements" not in self.data:
                return ""
            reqs = self.data["requirements"]
        else:
            if "recipe" not in self.data:
                return ""
            if "requirements" not in self.data["recipe"]:
                return ""
            reqs = self.data["recipe"]["requirements"]
        stream = io.StringIO()
        yaml = ruamel.yaml.YAML()
        yaml.indent(mapping=2, sequence=2, offset=2)
        yaml.dump({"requirements": reqs}, stream)
        return self._restore(stream.getvalue().strip())
