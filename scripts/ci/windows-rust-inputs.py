#!/usr/bin/env python3
"""Conservative static Rust file-input census for Windows relevance.

Bounded grammar: Rust comments/strings/groups, cfg(unix) item scopes, includes,
fs read aliases, local path bindings, manifest anchors, concat! and join/parent.
Configured static walker roots protect directory prefixes. Unanchored runtime,
temporary and user paths are OUT OF SCOPE and inventoried, not analyzed by rustc.
Exact OUT_DIR include concatenations are inventoried as build-generated inputs.
Unresolved static-looking repository inputs remain UNDETERMINED.
"""
import argparse
from collections import Counter
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import re
import tomllib


def lex(text):
    tokens, i, line = [], 0, 1
    raw_re = re.compile(r'(?:br|r)(#*)"')
    quote_re = re.compile(r'(?:b)?"')
    char_re = re.compile(r"(?:b)?'(?:\\.|[^'\\\n])'")
    word_re = re.compile(r"[A-Za-z_][A-Za-z_0-9]*|::|->|=>|.", re.S)
    while i < len(text):
        start, at = i, line
        if text[i].isspace():
            i += 1
        elif text.startswith("//", i):
            end = text.find("\n", i)
            i = len(text) if end < 0 else end
        elif text.startswith("/*", i):
            i, depth = i + 2, 1
            while depth and i < len(text):
                if text.startswith("/*", i): depth, i = depth + 1, i + 2
                elif text.startswith("*/", i): depth, i = depth - 1, i + 2
                else: i += 1
            if depth: raise ValueError("unterminated block comment")
        else:
            raw = raw_re.match(text, i)
            quoted = quote_re.match(text, i)
            char = char_re.match(text, i)
            if raw:
                body = raw.end(); end = text.find('"' + raw[1], body)
                if end < 0: raise ValueError("unterminated raw string")
                tokens.append((text[body:end], at, "string")); i = end + 1 + len(raw[1])
            elif quoted:
                body = quoted.end(); end = body
                while end < len(text):
                    if text[end] == "\\": end += 2
                    elif text[end] == '"': break
                    else: end += 1
                if end >= len(text): raise ValueError("unterminated string")
                try: value = json.loads('"' + text[body:end] + '"')
                except ValueError: value = None
                tokens.append((value, at, "string")); i = end + 1
            elif char:
                i = char.end()
            else:
                word = word_re.match(text, i)[0]
                tokens.append((word, at, "code")); i += len(word)
        line += text[start:i].count("\n")
    return tokens


def groups(tokens):
    pairs, stack = {}, []
    for i, (value, _, kind) in enumerate(tokens):
        if kind != "code": continue
        if value in ("(", "[", "{"): stack.append((value, i))
        elif value in (")", "]", "}"):
            if not stack or stack[-1][0] != {")": "(", "]": "[", "}": "{"}[value]:
                raise ValueError("unbalanced Rust delimiter")
            _, j = stack.pop(); pairs[j] = i; pairs[i] = j
    if stack: raise ValueError("unclosed Rust delimiter")
    return pairs


def split_args(tokens):
    pairs, args, start, i = groups(tokens), [], 0, 0
    while i < len(tokens):
        if tokens[i][2] == "code" and tokens[i][0] in ("(", "[", "{"): i = pairs[i] + 1; continue
        if tokens[i][0] == ",": args.append(tokens[start:i]); start = i + 1
        i += 1
    if start < len(tokens): args.append(tokens[start:])
    return args


def generated_out_dir_suffix(tokens):
    """Recognize only concat!(env!("OUT_DIR"), <literal>), without reading env."""
    shape = [(t[0], t[2]) for t in tokens]
    if (len(shape) == 11 and shape[:9] == [
            ("concat", "code"), ("!", "code"), ("(", "code"),
            ("env", "code"), ("!", "code"), ("(", "code"),
            ("OUT_DIR", "string"), (")", "code"), (",", "code")] and
            shape[9][1] == "string" and isinstance(shape[9][0], str) and
            shape[10] == (")", "code")):
        suffix = shape[9][0]
        if (suffix.startswith("/") and ".." not in suffix.split("/") and
                not any(char in suffix for char in ("\\", "\x00", ":"))):
            return suffix
    return None


def cfg_false(tokens):
    """Prove exclusion on Windows; unknown feature predicates stay included."""
    words = [t[0] for t in tokens]
    if words == ["unix"]: return True
    if len(words) >= 3 and words[:2] == ["target_os", "="]:
        return tokens[2][2] == "string" and words[2] != "windows"
    if len(words) > 3 and words[0] in ("all", "any", "not") and words[1] == "(":
        args = split_args(tokens[2:-1])
        if words[0] == "all": return any(cfg_false(a) for a in args)
        if words[0] == "any": return bool(args) and all(cfg_false(a) for a in args)
        if words[0] == "not": return args == [[("windows", tokens[2][1], "code")]]
    return False


def excluded_ranges(tokens, pairs):
    excluded = []
    for i, token in enumerate(tokens):
        if token[0] != "#": continue
        j = i + 1
        inner = j < len(tokens) and tokens[j][0] == "!"
        if inner: j += 1
        if j not in pairs or tokens[j][0] != "[": continue
        end = pairs[j]; attr = tokens[j + 1:end]
        if len(attr) < 4 or attr[0][0] != "cfg" or not cfg_false(attr[2:-1]): continue
        if inner: excluded.append((0, len(tokens))); continue
        k = end + 1
        while k < len(tokens) and tokens[k][0] not in ("{", ";"): k += 1
        if k >= len(tokens): raise ValueError("cfg item boundary unresolved")
        excluded.append((i, pairs[k] if tokens[k][0] == "{" else k))
    return excluded


def resolve_expr(tokens, bindings, manifest, cwd=None):
    tokens = list(tokens)
    while tokens and tokens[0][0] == "&": tokens.pop(0)
    if not tokens: return None
    pairs = groups(tokens); value, i = None, 0
    if tokens[0][2] == "string": value, i = tokens[0][0], 1
    elif tokens[0][0] == "(" and pairs[0] == len(tokens) - 1:
        return resolve_expr(tokens[1:-1], bindings, manifest, cwd)
    else:
        while i < len(tokens) and tokens[i][0] not in ("(", "!", ".", "?"): i += 1
        name = "".join(str(t[0]) for t in tokens[:i])
        if i == 1 and name in bindings: value = bindings[name]
        elif i < len(tokens) and tokens[i][0] == "!": i += 1
        if i < len(tokens) and tokens[i][0] == "(":
            end = pairs[i]; args = split_args(tokens[i + 1:end])
            if name in ("env", "option_env", "std::env::var", "std::env::var_os") and args and args[0][0][0] == "CARGO_MANIFEST_DIR":
                value = str(manifest)
            elif name == "std::env::current_dir": value = str(cwd) if cwd else None
            elif name + "()" in bindings: value = bindings[name + "()"]
            elif name == "concat":
                values = [resolve_expr(a, bindings, manifest, cwd) for a in args]
                value = "".join(values) if all(v is not None for v in values) else None
            elif name.endswith(("manifest_dir", "Path::new", "PathBuf::from")) and args:
                value = resolve_expr(args[0], bindings, manifest, cwd)
            i = end + 1
    while i < len(tokens):
        if tokens[i][0] == "?": i += 1; continue
        if i + 2 >= len(tokens) or tokens[i][0] != "." or tokens[i + 2][0] != "(": return None
        method, end = tokens[i + 1][0], pairs[i + 2]
        args = tokens[i + 3:end]
        if method == "join":
            right = resolve_expr(args, bindings, manifest, cwd)
            value = str(Path(value) / right) if value is not None and right is not None else None
        elif method == "parent": value = str(Path(value).parent) if value is not None else None
        elif method not in ("unwrap", "expect", "to_path_buf", "to_owned", "as_path", "ok", "as_ref"):
            value = None
        i = end + 1
    return value


def file_census(source, root):
    manifest = source.parent
    while manifest != root and not (manifest / "Cargo.toml").is_file(): manifest = manifest.parent
    tokens = lex(source.read_text()); pairs = groups(tokens)
    excluded = excluded_ranges(tokens, pairs)
    modules = [(tokens[i + 1][0], any(a <= i <= b for a, b in excluded))
               for i, t in enumerate(tokens[:-2]) if t[0] == "mod" and
               tokens[i + 2][0] == ";"]
    namespaces, readers, bindings, scopes = {"fs"}, set(), {}, []
    macros = {"include_str", "include_bytes"}
    for i, token in enumerate(tokens):
        if token[0] != "use": continue
        end = next((j for j in range(i + 1, len(tokens)) if tokens[j][0] == ";"), i)
        words = [t[0] for t in tokens[i:end]]
        for j, word in enumerate(words):
            if word in macros and words[j + 1:j + 2] == ["as"]: macros.add(words[j + 2])
        if "fs" not in words: continue
        if "*" in words: readers.update({"read", "read_to_string", "read_dir", "read_link"})
        for j, word in enumerate(words):
            if word == "fs" and words[j + 1:j + 2] == ["as"]: namespaces.add(words[j + 2])
            if word == "self" and words[j + 1:j + 2] == ["as"]: namespaces.add(words[j + 2])
            if isinstance(word, str) and word.startswith("read"):
                readers.add(words[j + 2] if words[j + 1:j + 2] == ["as"] else word)
    rows, root_arrays, loop_roots, prefixes, pending_roots, handled_roots = [], {}, {}, set(), set(), set()
    static_names, anchored_values, function_ends, configured_names, for_bindings, used_arrays = set(), set(), {}, set(), {}, set()
    cwd = manifest if "tests" in source.relative_to(manifest).parts else None
    def static_hint(expr):
        explicit = any(t[0] == "CARGO_MANIFEST_DIR" or (t[2] == "code" and t[0] in ("concat", "include_str", "include_bytes")) for t in expr)
        try: expr_groups = groups(expr)
        except ValueError: return explicit
        at = 0
        while at + 2 < len(expr):
            if expr[at][2] == "code" and expr[at][0] in ("(", "[", "{"):
                at = expr_groups[at] + 1; continue
            if [t[0] for t in expr[at:at + 3]] == [".", "join", "("]:
                base = resolve_expr(expr[:at], bindings, manifest, cwd)
                return explicit or (base is not None and (not Path(base).is_absolute() or Path(base).is_relative_to(root))) or bool(expr[:at] and expr[0][0] in static_names)
            at += 1
        direct_literal = bool(expr) and expr[0][2] == "string" and isinstance(expr[0][0], str) and "\n" not in expr[0][0] and not Path(expr[0][0]).is_absolute() and ("/" in expr[0][0] or Path(expr[0][0]).suffix in {".md", ".json", ".toml", ".rs", ".sql"})
        constructor = any(t[0] in ("format", "Path", "PathBuf") for t in expr[:5])
        return direct_literal or any(t[0] == "CARGO_MANIFEST_DIR" or t[0] in static_names or
                   (t[2] == "code" and t[0] in ("concat", "include_str", "include_bytes")) or
                   (constructor and t[2] == "string" and isinstance(t[0], str) and
                    t[0].startswith(("../", "./", "docs/", "specs/", ".claude/"))) for t in expr)
    def protect(base, values):
        for value in values:
            path = Path(os.path.normpath(str(Path(base) / value)))
            prefixes.add(path.relative_to(root).as_posix())
    for i, (word, line, kind) in enumerate(tokens):
        if kind != "code": continue
        if word == "fn" and i + 3 < len(tokens) and tokens[i + 2][0] == "(" and pairs[i + 2] == i + 3:
            body = i + 4
            while body < len(tokens) and tokens[body][0] not in ("{", ";"): body += 1
            if body < len(tokens) and tokens[body][0] == "{": function_ends[pairs[body]] = (tokens[i + 1][0], body)
        if word == "{":
            scopes.append((dict(bindings), set(static_names), set(configured_names), dict(loop_roots)))
            if i in for_bindings:
                variable, array_name = for_bindings[i]
                if array_name in root_arrays: loop_roots[variable] = array_name; used_arrays.add(array_name)
                else: loop_roots.pop(variable, None)
        elif word == "}" and scopes:
            summary = None
            if i in function_ends:
                name, start = function_ends[i]; tail = start + 1; cursor = tail
                while cursor < i:
                    if tokens[cursor][0] == ";" and tokens[cursor][2] == "code": tail = cursor + 1
                    cursor = pairs[cursor] + 1 if tokens[cursor][2] == "code" and tokens[cursor][0] in ("(", "[", "{") else cursor + 1
                try: summary = resolve_expr(tokens[tail:i], bindings, manifest, cwd)
                except (ValueError, IndexError): pass
            bindings, static_names, configured_names, loop_roots = scopes.pop()
            if summary is not None:
                bindings[name + "()"] = summary
                if Path(summary).is_absolute(): anchored_values.add(summary)
        if word == "for" and i + 3 < len(tokens) and tokens[i + 2][0] == "in":
            body = i + 4
            while body < len(tokens) and tokens[body][0] != "{": body += 1
            if body < len(tokens): for_bindings[body] = (tokens[i + 1][0], tokens[i + 3][0])
        if word in ("let", "const", "static"):
            j = i + 1
            if j < len(tokens) and tokens[j][0] == "mut": j += 1
            name = tokens[j][0] if j < len(tokens) else None
            k = j + 1
            while k < len(tokens) and tokens[k][0] not in ("=", ";", "{"):
                k = pairs[k] + 1 if tokens[k][0] in ("[", "(") else k + 1
            if k < len(tokens) and tokens[k][0] == "=":
                end = k + 1
                while end < len(tokens) and not (tokens[end][2] == "code" and tokens[end][0] == ";"):
                    end = pairs[end] + 1 if tokens[end][2] == "code" and tokens[end][0] in ("(", "[", "{") else end + 1
                expr = tokens[k + 1:end]
                try: bindings[name] = resolve_expr(expr, bindings, manifest, cwd)
                except (ValueError, IndexError, TypeError): bindings[name] = None
                if static_hint(expr): static_names.add(name)
                else: static_names.discard(name)
                if any(t[0] in configured_names for t in expr): configured_names.add(name)
                else: configured_names.discard(name)
                alias = [t[0] for t in expr]
                if isinstance(name, str) and not any(a <= i <= b for a, b in excluded):
                    array = expr[1:] if expr and expr[0][0] == "&" else expr
                    try: values = split_args(array[1:-1]) if array and array[0][0] == "[" and groups(array).get(0) == len(array) - 1 else []
                    except ValueError: values = []
                    if values or name.endswith("ROOTS"):
                        root_arrays[name] = [a[0][0] for a in values] if values and all(len(a) == 1 and a[0][2] == "string" and a[0][0] for a in values) else None
                for at in range(len(expr) - 4):
                    if [t[0] for t in expr[at:at + 3]] == [".", "join", "("] and expr[at + 3][0] in loop_roots:
                        array_name = loop_roots[expr[at + 3][0]]
                        try: base = resolve_expr(expr[:at], bindings, manifest, cwd)
                        except (ValueError, IndexError): base = None
                        if base and root_arrays[array_name]:
                            protect(base, root_arrays[array_name]); handled_roots.add(array_name); configured_names.add(name)
                        else: pending_roots.add(array_name)
                if len(alias) >= 3 and alias[-2] == "::" and alias[-3] in namespaces and str(alias[-1]).startswith("read"):
                    readers.add(name)
        macro = word in macros and tokens[i + 1:i + 2] and tokens[i + 1][0] == "!"
        read = (isinstance(word, str) and word.startswith("read") and i > 1 and
                tokens[i - 1][0] == "::" and tokens[i - 2][0] in namespaces) or word in readers
        if not macro and not read: continue
        j = i + (2 if macro else 1)
        if j >= len(tokens) or tokens[j][0] != "(": continue
        args = split_args(tokens[j + 1:pairs[j]])
        if not args: raise ValueError("reader without an argument")
        unix = any(start <= i <= end for start, end in excluded)
        value = resolve_expr(args[0], bindings, manifest, cwd)
        row = {"source": source.relative_to(root).as_posix(), "line": line,
               "reader": word, "unix_only": unix, "path": None,
               "argument_sha256": hashlib.sha256(json.dumps([(t[0], t[2]) for t in args[0]]).encode()).hexdigest()}
        suffix = generated_out_dir_suffix(args[0]) if macro else None
        if suffix is not None:
            row.update(state="generated_out_dir", suffix=suffix)
        elif value is None:
            row["state"] = "configured" if any(t[0] in configured_names for t in args[0]) else "unresolved" if macro or static_hint(args[0]) or (args[0][0][2] == "string" and args[0][0][0] is None) else "runtime"
        else:
            target = Path(value)
            if not target.is_absolute(): target = (source.parent if macro else manifest) / target
            # Input identity is the tracked path, even when it is a symlink.
            target = Path(os.path.normpath(str(target)))
            try:
                row["path"] = target.relative_to(root).as_posix(); row["state"] = "static"
                if word == "read_dir" and not unix: prefixes.add(row["path"])
            except ValueError: row["state"] = "external" if Path(value).is_absolute() else "unresolved"
        rows.append(row)
    for name in pending_roots - handled_roots:
        if root_arrays[name] and anchored_values:
            for base in anchored_values: protect(base, root_arrays[name])
        elif name.endswith("ROOTS"):
            rows.append({"source": source.relative_to(root).as_posix(), "line": 0, "reader": "configured-walker",
                         "unix_only": False, "path": None, "state": "unresolved", "reason": "static walker root unresolved: " + name})
    return rows, modules, prefixes


def scan(root):
    root = Path(root).resolve()
    (root / "Cargo.toml").resolve().relative_to(root)
    manifest_bytes = (root / "Cargo.toml").read_bytes()
    members = tomllib.loads(manifest_bytes.decode("utf-8")).get("workspace", {}).get("members", ["."])
    if not isinstance(members, list) or not members or not all(isinstance(m, str) for m in members):
        raise ValueError("workspace members must be a literal path list")
    files = sorted({p for member in members for crate in root.glob(member)
                    for p in crate.rglob("*.rs") if "target" not in p.relative_to(root).parts})
    census, errors, module_refs, source_hashes, prefixes = [], [], {}, {}, set()
    for source in files:
        try:
            source.resolve().relative_to(root)
            if source.is_symlink(): raise ValueError("Rust source symlink requires explicit scope")
            before = source.read_bytes(); source_hashes[source.relative_to(root).as_posix()] = hashlib.sha256(before).hexdigest()
            rows, modules, file_prefixes = file_census(source, root); census.extend(rows); prefixes.update(file_prefixes)
            if source.read_bytes() != before: raise ValueError("Rust source changed during scan")
            directory = source.parent if source.stem in ("lib", "main", "mod") else source.parent / source.stem
            for module, unix in modules:
                for candidate in [directory / (module + ".rs"), directory / module / "mod.rs"]:
                    if candidate.is_file(): module_refs.setdefault(candidate.relative_to(root).as_posix(), []).append(unix)
        except (ValueError, OSError, IndexError, TypeError) as error:
            errors.append({"source": source.relative_to(root).as_posix(), "reason": type(error).__name__})
    # External cfg-gated modules are retained in the census, with their scope.
    for row in census:
        if module_refs.get(row["source"]) and all(module_refs[row["source"]]): row["unix_only"] = True
    for name, digest in source_hashes.items():
        if hashlib.sha256((root / name).read_bytes()).hexdigest() != digest:
            errors.append({"source": name, "reason": "source changed after census"})
    if (root / "Cargo.toml").read_bytes() != manifest_bytes:
        errors.append({"source": "Cargo.toml", "reason": "workspace changed during census"})
    active = [row for row in census if not row["unix_only"]]
    return {"paths": sorted({row["path"] for row in active if row["state"] == "static"}),
            "prefixes": sorted(prefixes), "runtime_inventory": [
                {key: row[key] for key in ("source", "line", "reader", "argument_sha256")} |
                {"classification": "out-of-scope-unanchored-runtime"} for row in active if row["state"] == "runtime"],
            "generated_inputs": [
                {key: row[key] for key in ("source", "line", "reader", "argument_sha256", "suffix")} |
                {"classification": "generated_out_dir"} for row in active if row["state"] == "generated_out_dir"],
            "unresolved": errors + [row for row in active if row["state"] == "unresolved"],
            "census": census, "rust_files": len(files), "source_hashes": source_hashes}


def guard(root, detector):
    """Exercise the real detector with each derived input; unresolved is rc2."""
    result = scan(root)
    if result["unresolved"]: return 2, result
    event = {"number": 1, "pull_request": {"number": 1,
             "head": {"sha": "a" * 40}, "base": {"sha": "b" * 40}}}
    metadata = dict(event["pull_request"], changed_files=1)
    probes = result["paths"] + [("" if p == "." else p + "/") + "__windows_input_probe__.md" for p in result["prefixes"]]
    for path in probes:
        def fetch(endpoint):
            return ([{"filename": path, "status": "modified"}]
                    if "/files?" in endpoint else metadata)
        decision = detector.decide("pull_request", event, "fixture/repo", fetch,
                                   checkout_inputs=lambda: (probes, result["paths"], result["prefixes"]))
        if decision[1] == "UNDETERMINED": return 2, result
        if not decision[0]: return 1, result
    return 0, result


def runtime_snapshot(result):
    sources = {row["source"] for row in result["runtime_inventory"] + result["generated_inputs"]}
    return {"schema": 1, "scope": "Unanchored runtime/temp/user reads are outside bounded static-input analysis; OUT_DIR includes are build-generated inputs.",
            "generator_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "source_hashes": {name: digest for name, digest in result["source_hashes"].items() if name in sources},
            "reads": result["runtime_inventory"], "generated_inputs": result["generated_inputs"]}


def inventory_keys(rows):
    # Lines and source hashes bind the recorded observation, but line movement
    # alone does not create a new runtime/generated consumer or require a census rewrite.
    return Counter((r["source"], r["reader"], r["argument_sha256"], r["classification"], r.get("suffix")) for r in rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=Path(__file__).resolve().parents[2])
    parser.add_argument("--guard", action="store_true", help="verify the actual detector cannot skip derived inputs")
    parser.add_argument("--write-census", action="store_true", help="explicitly update the committed runtime/generated inventory")
    parser.add_argument("--check-census", action="store_true", help="check runtime/generated consumer identities, ignoring line movement")
    parser.add_argument("--quiet", action="store_true", help="print counts instead of the full census")
    args = parser.parse_args()
    try:
        if args.guard:
            path = Path(args.root) / "scripts/ci/windows-rust-changes.py"
            spec = importlib.util.spec_from_file_location("input_detector_guard", path)
            detector = importlib.util.module_from_spec(spec); spec.loader.exec_module(detector)
            code, result = guard(args.root, detector)
        else:
            result = scan(args.root); code = 2 if result["unresolved"] else 0
        census_path = Path(args.root) / "scripts/ci/windows-rust-runtime-census.json"
        if args.write_census:
            if result["unresolved"]: raise ValueError("cannot update census with unresolved static inputs")
            census_path.write_text(json.dumps(runtime_snapshot(result), indent=2) + "\n")
        if args.check_census:
            saved = json.loads(census_path.read_text())
            if saved.get("schema") != 1: raise ValueError("unsupported runtime census schema")
            if (inventory_keys(saved["reads"]) != inventory_keys(result["runtime_inventory"]) or
                    "generated_inputs" not in saved or
                    inventory_keys(saved["generated_inputs"]) != inventory_keys(result["generated_inputs"])):
                code = 1
                result["census_update_required"] = "Run --write-census explicitly after inspecting runtime/generated consumer changes."
        shown = {"paths": len(result["paths"]), "prefixes": len(result["prefixes"]), "unresolved": len(result["unresolved"]),
                 "runtime_reads": len(result["runtime_inventory"]), "generated_inputs": len(result["generated_inputs"]),
                 "rust_files": result["rust_files"], "exit": code} if args.quiet else result
        print(json.dumps(shown, indent=2))
        return code
    except Exception as error:
        print(json.dumps({"unresolved": [{"reason": type(error).__name__}]})); return 2


if __name__ == "__main__":
    raise SystemExit(main())
