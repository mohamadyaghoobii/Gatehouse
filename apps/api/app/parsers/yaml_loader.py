from __future__ import annotations

import re
from typing import Any

import yaml


class LineDict(dict):
    """A dict that remembers the source line of the mapping and of each key."""

    line: int | None = None
    key_lines: dict[Any, int]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.key_lines = {}


class LineList(list):
    line: int | None = None
    item_lines: list[int]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.item_lines = []


class _LineLoader(yaml.SafeLoader):
    pass


def _construct_mapping(loader: _LineLoader, node: yaml.MappingNode) -> LineDict:
    loader.flatten_mapping(node)
    mapping = LineDict()
    mapping.line = node.start_mark.line + 1
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=True)
        value = loader.construct_object(value_node, deep=True)
        mapping[key] = value
        try:
            mapping.key_lines[key] = key_node.start_mark.line + 1
        except TypeError:
            pass
    return mapping


def _construct_sequence(loader: _LineLoader, node: yaml.SequenceNode) -> LineList:
    seq = LineList()
    seq.line = node.start_mark.line + 1
    for child in node.value:
        seq.append(loader.construct_object(child, deep=True))
        seq.item_lines.append(child.start_mark.line + 1)
    return seq


_LineLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)
_LineLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_SEQUENCE_TAG, _construct_sequence)


def _restrict_bool_resolvers() -> None:
    """Keep only true/false as booleans so GitHub's `on:` key is not parsed as True."""
    strict = re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$", re.X)
    _LineLoader.add_implicit_resolver("tag:yaml.org,2002:bool", strict, list("tTfF"))
    for first_char, mappings in list(_LineLoader.yaml_implicit_resolvers.items()):
        _LineLoader.yaml_implicit_resolvers[first_char] = [
            (tag, regexp)
            for tag, regexp in mappings
            if tag != "tag:yaml.org,2002:bool" or regexp is strict
        ]


_restrict_bool_resolvers()


def load_yaml_with_lines(content: str) -> Any:
    """Parse YAML, annotating mappings and sequences with source line numbers."""
    try:
        return yaml.load(content, Loader=_LineLoader)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        location = f" near line {mark.line + 1}" if mark else ""
        raise ValueError(f"The pipeline is not valid YAML{location}.") from exc


def line_of(container: Any, key: Any = None, default: int | None = None) -> int | None:
    if key is not None and isinstance(container, LineDict):
        return container.key_lines.get(key, getattr(container, "line", default))
    return getattr(container, "line", default)
