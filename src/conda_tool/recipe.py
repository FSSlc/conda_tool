"""Conda recipe parser supporting both meta.yaml and recipe.yaml formats.

Handles Jinja2 templates ({{ }}) from conda-build meta.yaml and
rattler-build templates (${{ }}) from recipe.yaml by temporarily
replacing template expressions with safe placeholders before YAML parsing.
"""

import io
import os
import re
from enum import Enum
from logging import getLogger
from typing import Literal, TypedDict

import ruamel.yaml

logger = getLogger("conda_tool.recipe")

HashType = Literal["md5", "sha1", "sha256"]
PackageUrl = str | list[str]


class RecipeFormat(Enum):
    META_YAML = "meta.yaml"
    RECIPE_YAML = "recipe.yaml"


class SourceUrlSpec(TypedDict):
    url: PackageUrl
    hash_type: HashType | None
    hash: str | None
    fn: str | None


class RecipeParser:
    """解析 conda recipe 并支持结构化修改 source URL。

    同时支持 meta.yaml (conda-build, Jinja2 ``{{ }}``) 和
    recipe.yaml (rattler-build, ``${{ }}``) 两种格式。
    """

    # ${{ ... }} 必须在 {{ ... }} 之前匹配，避免内层被先吃掉
    _TEMPLATE_EXPR_RE = re.compile(r"\$\{\{.*?\}\}|\{\{.*?\}\}")
    # {% ... %} Jinja2 控制语句（整行）
    _JINJA2_STMT_RE = re.compile(r"^(\s*)\{%.*?%\}\s*$", re.MULTILINE)
    # conda-build selector 注释, 如 # [win]
    _SELECTOR_RE = re.compile(r"#\s*\[.*?\]\s*$", re.MULTILINE)

    def __init__(self, recipe_path: str) -> None:
        self.recipe_path = recipe_path
        self.format = self._detect_format()
        self._placeholders: dict[str, str] = {}
        self._counter = 0

        with open(recipe_path, encoding="utf-8") as f:
            self.raw_content = f.read()

        sanitized = self._sanitize(self.raw_content)
        self._yaml = ruamel.yaml.YAML()
        self._yaml.preserve_quotes = True
        self.data = self._yaml.load(sanitized)

    def _detect_format(self) -> RecipeFormat:
        basename = os.path.basename(self.recipe_path)
        if basename == "recipe.yaml":
            return RecipeFormat.RECIPE_YAML
        return RecipeFormat.META_YAML

    def _make_placeholder(self, match: re.Match) -> str:
        token = match.group(0)
        key = f"__RECIPE_PH_{self._counter}__"
        self._placeholders[key] = token
        self._counter += 1
        return key

    def _comment_stmt(self, match: re.Match) -> str:
        """将 {% %} 控制语句行转为 YAML 注释，同时保留原始文本为占位符"""
        token = match.group(0)
        indent = match.group(1)
        key = f"__RECIPE_PH_{self._counter}__"
        self._placeholders[key] = token.strip()
        self._counter += 1
        return f"{indent}# {key}"

    def _sanitize(self, content: str) -> str:
        """将模板语法替换为占位符，使内容成为合法 YAML"""
        # 先处理 {% %} 语句行（整行变注释）
        result = self._JINJA2_STMT_RE.sub(self._comment_stmt, content)
        # 再处理 ${{ }} 和 {{ }} 表达式
        result = self._TEMPLATE_EXPR_RE.sub(self._make_placeholder, result)
        return result

    def _restore(self, content: str) -> str:
        """将占位符还原为原始模板语法"""
        for key, value in sorted(
            self._placeholders.items(), key=lambda kv: -len(kv[0])
        ):
            content = content.replace(key, value)
        return content

    def load_urls(self) -> list[SourceUrlSpec]:
        """从 recipe 中提取所有 source URL"""
        if self.data is None or "source" not in self.data:
            return []
        sources = self.data["source"]
        if not isinstance(sources, list):
            sources = [sources]

        result: list[SourceUrlSpec] = []
        for item in sources:
            if not isinstance(item, dict) or "url" not in item:
                if isinstance(item, dict):
                    logger.warning(f"Not supporting source type for {item}")
                continue
            url = item["url"]
            # 还原 URL 中的占位符
            if isinstance(url, str):
                url = self._restore(url)
            elif isinstance(url, list):
                url = [self._restore(str(u)) for u in url]

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
                SourceUrlSpec(url=url, hash_type=hash_type, hash=file_hash, fn=fn)
            )
        return result

    def replace_source_urls(self, url_mapping: dict[int, str]) -> str:
        """替换 source URL 并返回修改后的完整文件内容。

        Args:
            url_mapping: ``{source_index: new_local_path}`` 映射。
                         原有 URL 会被注释保留。

        Returns:
            修改后的文件内容字符串（已还原模板语法）。
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
            # 构造注释文本（还原占位符以显示原始 URL）
            if isinstance(old_url, list):
                comment = " | ".join(self._restore(str(u)) for u in old_url)
            else:
                comment = self._restore(str(old_url))

            source["url"] = new_path
            source.yaml_add_eol_comment(f"original: {comment}", "url")

        stream = io.StringIO()
        self._yaml.dump(self.data, stream)
        result = stream.getvalue()
        return self._restore(result)

    def save(self, output_path: str, content: str | None = None) -> None:
        """保存修改后的 recipe 文件"""
        if content is None:
            stream = io.StringIO()
            self._yaml.dump(self.data, stream)
            content = self._restore(stream.getvalue())
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)

    def extract_reqs(self) -> str:
        """从 recipe 数据结构中提取 requirements 段"""
        if self.data is None or "requirements" not in self.data:
            return ""
        reqs = self.data["requirements"]
        stream = io.StringIO()
        yaml = ruamel.yaml.YAML()
        yaml.dump({"requirements": reqs}, stream)
        return self._restore(stream.getvalue().strip())
