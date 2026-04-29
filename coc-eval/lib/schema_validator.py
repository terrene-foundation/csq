"""Lightweight JSON Schema (subset) validator — stdlib-only.

Originally extracted from `suite_validator.py` (H1) and extended in H4 to
support per-field `pattern` (regex), multi-type arrays (e.g.
`["string", "null"]`), `number`, and `null` types — all needed by the
JSONL v1.0.0 schema for nullable fields and run_id regex validation.

Subset supported:
- type: string | integer | number | boolean | null | object | array
       (and arrays of those for union types).
- required, properties, additionalProperties (defaults to `True`,
  forward-compat per ADR-G).
- items, minItems.
- minLength, pattern (regex via Python `re.fullmatch`).
- enum (any JSON-comparable value).

$ref support (H4): intra-document refs of the form `#/definitions/Foo`
resolve against the top-level schema. External `$ref` URIs are NOT
supported — they would require fetching, which the stdlib-only
constraint forbids. The root schema is threaded through recursive calls
so refs always resolve against the document root, not a sub-tree.

NOT supported (deliberate omissions for stdlib parity):
- External $ref URIs, $defs (use `definitions` instead), allOf, oneOf,
  anyOf, not, dependentRequired, etc.
- Date-time format keywords (validate via custom predicates if needed).
- Numeric ranges (minimum, maximum) — add when a schema needs them.

Polymorphism (e.g. records that have EITHER `score.criteria` OR
`score.tiers`) is handled at the caller level rather than via `oneOf`.
JSONL v1.0.0 makes both fields independently optional with
`additionalProperties: true`, matching the parallel-arrays decision in
`06-jsonl-schema-v1.md` §"Score shape: parallel arrays".
"""

from __future__ import annotations

import re
from typing import Any


class SchemaValidationError(ValueError):
    """Raised when a value fails schema validation."""


_TYPE_PREDICATES: dict[str, Any] = {
    "string": lambda v: isinstance(v, str),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    "boolean": lambda v: isinstance(v, bool),
    "null": lambda v: v is None,
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
}


def _check_type(value: Any, schema_type: Any, path: str) -> None:
    """Validate `value` against the `type` keyword.

    `schema_type` may be a string ("string", "object", ...) or a list of
    strings (a JSON-Schema "union" type). At least one must match.
    """
    if schema_type is None:
        return
    types = schema_type if isinstance(schema_type, list) else [schema_type]
    for t in types:
        pred = _TYPE_PREDICATES.get(t)
        if pred is None:
            raise SchemaValidationError(
                f"{path or '<root>'}: unknown schema type {t!r}"
            )
        if pred(value):
            return
    got = type(value).__name__ if value is not None else "null"
    raise SchemaValidationError(
        f"{path or '<root>'}: expected {schema_type!r}, got {got}"
    )


def _resolve_ref(ref: str, root_schema: dict[str, Any]) -> dict[str, Any]:
    """Resolve a `#/definitions/Foo`-style ref against the root schema.

    Only intra-document refs (`#/...`) are supported.
    """
    if not ref.startswith("#/"):
        raise SchemaValidationError(f"unsupported $ref form (no #/-prefix): {ref!r}")
    parts = ref[2:].split("/")
    cursor: Any = root_schema
    for part in parts:
        if not isinstance(cursor, dict) or part not in cursor:
            raise SchemaValidationError(f"$ref target not found in root: {ref!r}")
        cursor = cursor[part]
    if not isinstance(cursor, dict):
        raise SchemaValidationError(
            f"$ref target is not a schema object: {ref!r} -> {type(cursor).__name__}"
        )
    return cursor


# Cap schema-traversal recursion depth as a DoS guard (H4 review M4).
# A schema that lands on disk in a `coc-eval/schemas/` directory has the
# same threat model as a JSONL file in `results/` — anyone with FS write
# access can plant a cyclic schema and exhaust the validator's stack.
# The legitimate v1.0.0 schema's deepest nesting is ~5; 64 leaves ample
# headroom for forward-compat sub-schemas while stopping a runaway loop.
_MAX_SCHEMA_DEPTH: int = 64


def validate_against_schema(
    value: Any,
    schema: dict[str, Any],
    path: str = "",
    root_schema: dict[str, Any] | None = None,
    _depth: int = 0,
) -> None:
    """Recursive validator for the supported subset.

    Raises `SchemaValidationError` on the first violation found, with a
    JSON-pointer-style `path` to make debugging large schemas easier.
    Forward-compat: unknown object keys are accepted unless the schema
    explicitly sets `additionalProperties: false`.

    Args:
        value: JSON-decoded value to validate.
        schema: Schema sub-tree (may itself contain `$ref` for jump-to-root).
        path: JSON-pointer-style path used in error messages.
        root_schema: Top-level schema for `$ref` resolution. Defaults to
            `schema` on the first call; subsequent recursive calls thread it
            through so refs always resolve against the document root.
        _depth: Recursion depth (private). Capped at `_MAX_SCHEMA_DEPTH`
            so a cyclic `$ref` (`A.$ref -> B`, `B.$ref -> A`) cannot DoS
            the validator. Hit-cap raises `SchemaValidationError`.
    """
    if root_schema is None:
        root_schema = schema
    if _depth > _MAX_SCHEMA_DEPTH:
        raise SchemaValidationError(
            f"{path or '<root>'}: schema recursion depth exceeded "
            f"{_MAX_SCHEMA_DEPTH} — possible cyclic $ref"
        )

    # `$ref` short-circuits all other keywords at this scope (draft-07).
    ref = schema.get("$ref")
    if isinstance(ref, str):
        resolved = _resolve_ref(ref, root_schema)
        validate_against_schema(value, resolved, path, root_schema, _depth + 1)
        return

    schema_type = schema.get("type")
    _check_type(value, schema_type, path)

    # Object validation runs even when type is unspecified, as long as
    # value is a dict and the schema declares object-keywords.
    if isinstance(value, dict) and (
        "required" in schema
        or "properties" in schema
        or "additionalProperties" in schema
    ):
        required = schema.get("required", [])
        for key in required:
            if key not in value:
                raise SchemaValidationError(
                    f"{path or '<root>'}: missing required key {key!r}"
                )
        properties = schema.get("properties", {})
        additional_allowed = schema.get("additionalProperties", True)
        for key, subval in value.items():
            sub_path = f"{path}.{key}" if path else key
            if key in properties:
                validate_against_schema(
                    subval,
                    properties[key],
                    sub_path,
                    root_schema,
                    _depth + 1,
                )
            elif not additional_allowed:
                raise SchemaValidationError(f"{sub_path}: unexpected property")

    if isinstance(value, list) and "items" in schema:
        min_items = schema.get("minItems")
        if min_items is not None and len(value) < min_items:
            raise SchemaValidationError(
                f"{path}: minItems {min_items}, got {len(value)}"
            )
        items_schema = schema["items"]
        for idx, item in enumerate(value):
            validate_against_schema(
                item,
                items_schema,
                f"{path}[{idx}]",
                root_schema,
                _depth + 1,
            )

    if isinstance(value, str):
        min_length = schema.get("minLength")
        if min_length is not None and len(value) < min_length:
            raise SchemaValidationError(
                f"{path}: minLength {min_length}, got {len(value)}"
            )
        pattern = schema.get("pattern")
        if pattern is not None:
            try:
                if not re.fullmatch(pattern, value):
                    raise SchemaValidationError(
                        f"{path}: value does not match pattern {pattern!r}"
                    )
            except re.error as e:
                raise SchemaValidationError(
                    f"{path}: invalid regex pattern {pattern!r}: {e}"
                ) from e

    enum_values = schema.get("enum")
    if enum_values is not None and value not in enum_values:
        raise SchemaValidationError(
            f"{path}: value {value!r} not in enum {enum_values}"
        )
