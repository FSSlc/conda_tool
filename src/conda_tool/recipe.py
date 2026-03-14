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
    # conda-build selector 注释，如 # [win]
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
        """将模板语法替换为占位符，使内容成为合法 YAML"""
        # 为了使 YAML 解析器能够解析文件，我们需要将所有 Jinja2 语法转为占位符
        # 但之后在输出时，要将 set 语句恢复为正常格式

        # 首先处理整行的 Jinja2 语句（可能要特别处理 set 语句）
        lines = content.splitlines()
        temp_lines = []
        for line_idx, line in enumerate(lines):
            match = self._JINJA2_STMT_RE.match(line)
            if match:
                # 这是一整行的 Jinja2 语句
                token = match.group(0).strip()
                key = f"__JINJA2_STMT_{line_idx}__"
                # 存储原始的 Jinja2 语句，以便在输出时决定如何恢复
                self._placeholders[key] = token
                indent = match.group(1)
                # 在 YAML 解析阶段，将所有 Jinja2 语句替换为注释，以确保 YAML 解析成功
                # 稍后在恢复时，我们会根据语句类型决定是否取消注释
                temp_lines.append(f"{indent}# {key}")
            else:
                temp_lines.append(line)

        # 对于 ${{ }} 和 {{ }} 表达式，替换为占位符
        result = "\n".join(temp_lines)
        result = self._TEMPLATE_EXPR_RE.sub(self._make_placeholder, result)
        return result

    def _restore(self, content: str) -> str:
        """将占位符还原为原始模板语法"""
        # 先替换表达式占位符（{{ }} 和 ${{ }}）
        for key, value in sorted(
            self._placeholders.items(), key=lambda kv: -len(kv[0])
        ):
            # 如果是一个 Jinja2 语句的占位符
            if key.startswith("__JINJA2_STMT_"):
                # 识别是否是 set 语句
                if "set " in value:
                    # 是 set 语句，恢复为正常格式
                    content = content.replace(f"# {key}", value)
                else:
                    # 是控制语句，保持为注释格式
                    content = content.replace(f"# {key}", f"# {value}")
            else:
                # 普通表达式占位符，直接替换
                content = content.replace(key, value)
        return content

    def load_urls(self) -> list[SourceUrlSpec]:
        """从 recipe 中提取所有 source URL"""
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
            # 为了提取 URL 而不影响后续使用，我们先还原
            # 但在返回 URL 之前，需要确保 urllib.parse 可以处理它
            final_url: PackageUrl
            if isinstance(url, str):
                # 如果需要处理 urllib.parse 中的问题，应该在使用 URL 时再处理
                final_url = self._restore(url)
            elif isinstance(url, list):
                final_url = [self._restore(str(u)) for u in item["url"]]
            else:
                # 对于其他类型，直接使用原始值
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

            # 为新路径添加注释并替换 URL
            source["url"] = new_path
            # 为了确保字典对象支持注释功能，我们重新获取它
            if hasattr(sources[idx], "yaml_add_eol_comment"):
                sources[idx].yaml_add_eol_comment(f"original: {comment}", "url")
            else:
                # 如果对象不支持注释功能，则保留原始 URL 的注释信息
                pass

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
