#!/usr/bin/env python3
"""csq Conformance Walk (CW) — deterministic oracle over csq's real delivery axis.

Walks SOURCE -> DELIVERED -> LIVE for the surfaces csq actually exposes, with a
MACHINE-DERIVED denominator, coverage reported SEPARATELY from pass-rate, and the
discrete verdict taxonomy Pass | Fail | Blocked | Retest | Skipped | Not-Run.

The delivery gap this instruments: a `#[tauri::command]` can exist in source, compile,
and pass every cargo test, while never reaching `generate_handler!` — so the renderer's
`invoke()` fails at runtime with "command not found". Source-only checks are blind to it.

Adapters (each degrades to Not-Run rather than faking a Pass):
  A1 ipc-registration  SOURCE->DELIVERED  every #[tauri::command] reaches generate_handler!
  A2 ipc-invoke        DELIVERED->LIVE    every frontend invoke("x") resolves to a handler
  A3 capability-grants DELIVERED          no un-narrowed `<plugin>:default` bundles
  A4 cli-surface       LIVE               every clap subcommand answers --help (needs --live)

Exit 0 = no Fail rows. Exit 1 = >=1 Fail. Exit 2 = the walk could not run (never a pass).

Origin: csq adoption of kailash-coc-rs `conformance-walk` (template v2.24.0), 2026-08-04.
Upstream's adapter family is the kailash SDK `cw_core` engine, which csq does not vendor;
this is csq's own adapter set over csq's own surfaces.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

VERDICTS = ("Pass", "Fail", "Blocked", "Retest", "Skipped", "Not-Run")


@dataclass
class Record:
    """One CW record. `expectation` is FROZEN before `observed` is read."""

    adapter: str
    unit: str
    expectation: str
    verdict: str
    observed: str = ""

    def __post_init__(self) -> None:
        if self.verdict not in VERDICTS:
            raise ValueError(f"verdict {self.verdict!r} outside the discrete taxonomy")


@dataclass
class Adapter:
    name: str
    family: str  # SOURCE | DELIVERED | LIVE
    records: list[Record] = field(default_factory=list)
    blocked_reason: str = ""


# ── source helpers ────────────────────────────────────────────────────────────

_ATTR_LINE = re.compile(r"^\s*#!?\[[^\n]*\]\s*$", re.M)


def _strip_attr_lines(text: str) -> str:
    """Blank out whole-line attributes so their `]` cannot terminate a bracket scan.

    A naive non-greedy `generate_handler!\\[(.*?)\\]` stops at the `]` of an inner
    `#[cfg(feature = "enterprise")]`, silently truncating the registration list and
    reporting every entry below it as unregistered. Measured on csq 2026-08-04: that
    bug produced 6 false FAILs. Attributes are blanked (not deleted) to keep offsets.
    """
    return _ATTR_LINE.sub(lambda m: " " * len(m.group(0)), text)


def _bracket_span(text: str, open_idx: int) -> str:
    """Return the content of the `[...]` whose `[` sits at open_idx, depth-aware."""
    depth, i = 0, open_idx
    while i < len(text):
        if text[i] == "[":
            depth += 1
        elif text[i] == "]":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1 : i]
        i += 1
    raise ValueError("unterminated generate_handler! bracket")


def _rs_files(root: Path, sub: str) -> list[Path]:
    return sorted(p for p in (root / sub).rglob("*.rs") if "/target/" not in str(p))


# ── A1: every #[tauri::command] reaches generate_handler! ─────────────────────

_DECL = re.compile(
    r"#\[tauri::command[^\]]*\]\s*(?:#\[[^\]]*\]\s*)*"
    r"(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([a-z0-9_]+)"
)


def collect_declared(root: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for p in _rs_files(root, "csq/src/desktop"):
        # NOT _strip_attr_lines here: that helper blanks whole-line attributes,
        # which would erase the `#[tauri::command]` marker this regex anchors on.
        for m in _DECL.finditer(p.read_text(errors="replace")):
            out.setdefault(m.group(1), str(p.relative_to(root)))
    return out


def collect_registered(root: Path) -> set[str]:
    reg: set[str] = set()
    for p in _rs_files(root, "csq/src/desktop"):
        raw = p.read_text(errors="replace")
        clean = _strip_attr_lines(raw)
        for m in re.finditer(r"generate_handler!\s*\[", clean):
            body = _bracket_span(clean, m.end() - 1)
            for path in re.findall(r"([A-Za-z0-9_:]+)\s*(?:,|$)", body):
                leaf = path.split("::")[-1]
                if leaf and leaf.islower():
                    reg.add(leaf)
    return reg


def load_waivers(root: Path) -> dict[str, dict[str, str]]:
    """Deliberate, authority-backed waivers. A waived unit is Skipped, never Pass.

    It stays IN the denominator: the Record is appended to `a.records` like any
    other, and `emit()` counts `len(a.records)`. Waiving therefore lowers the
    numerator and can never be a route to 100%.
    """
    p = root / "scripts/conformance-walk-waivers.json"
    if not p.exists():
        return {}
    raw = json.loads(p.read_text())
    return {k: v for k, v in raw.items() if not k.startswith("_")}


def adapter_ipc_registration(root: Path) -> Adapter:
    a = Adapter("ipc-registration", "SOURCE->DELIVERED")
    declared, registered = collect_declared(root), collect_registered(root)
    if not declared:
        a.blocked_reason = (
            "no #[tauri::command] declarations found under csq/src/desktop"
        )
        return a
    waived = load_waivers(root).get(a.name, {})
    for name in sorted(declared):
        ok = name in registered
        if not ok and name in waived:
            verdict, observed = "Skipped", f"waived: {waived[name]}"
        else:
            verdict = "Pass" if ok else "Fail"
            observed = f"{declared[name]}; registered={ok}"
        a.records.append(
            Record(
                a.name,
                name,
                "declared #[tauri::command] is reachable from the renderer "
                "(present in a generate_handler! list)",
                verdict,
                observed,
            )
        )
    return a


# ── A2: every frontend invoke("x") resolves to a registered handler ───────────

_INVOKE = re.compile(r"""invoke\s*(?:<[^>]*>)?\s*\(\s*["'`]([a-z0-9_]+)["'`]""")


def adapter_ipc_invoke(root: Path) -> Adapter:
    a = Adapter("ipc-invoke", "DELIVERED->LIVE")
    ui = root / "csq/ui/src"
    if not ui.is_dir():
        a.blocked_reason = f"frontend source tree absent at {ui.relative_to(root)}"
        return a
    sites: dict[str, str] = {}
    for p in sorted(list(ui.rglob("*.ts")) + list(ui.rglob("*.svelte"))):
        for m in _INVOKE.finditer(p.read_text(errors="replace")):
            sites.setdefault(m.group(1), str(p.relative_to(root)))
    if not sites:
        a.blocked_reason = "no invoke() call sites found in the frontend tree"
        return a
    registered = collect_registered(root)
    for name in sorted(sites):
        ok = name in registered
        a.records.append(
            Record(
                a.name,
                name,
                "renderer-invoked command name resolves to a registered handler",
                "Pass" if ok else "Fail",
                f"{sites[name]}; registered={ok}",
            )
        )
    return a


# ── A3: capability grants are narrowed (tauri-commands.md § Permission Grant Shape) ──


def adapter_capability_grants(root: Path) -> Adapter:
    a = Adapter("capability-grants", "DELIVERED")
    caps = sorted((root / "csq").rglob("capabilities/*.json"))
    if not caps:
        a.blocked_reason = "no capabilities/*.json found under csq/"
        return a
    for p in caps:
        try:
            perms = json.loads(p.read_text()).get("permissions", [])
        except json.JSONDecodeError as e:
            a.records.append(
                Record(
                    a.name,
                    str(p.relative_to(root)),
                    "capability file parses as JSON",
                    "Fail",
                    f"JSONDecodeError: {e}",
                )
            )
            continue
        names = [q if isinstance(q, str) else q.get("identifier", "") for q in perms]
        wide = [
            n for n in names if n.endswith(":default") and not n.startswith("core:")
        ]
        a.records.append(
            Record(
                a.name,
                str(p.relative_to(root)),
                "every non-core grant is a specific sub-permission, not a "
                "`<plugin>:default` bundle (tauri-commands.md)",
                "Pass" if not wide else "Fail",
                (
                    f"wide bundles: {wide}"
                    if wide
                    else f"{len(names)} grants, all narrowed"
                ),
            )
        )
    return a


# ── A4: LIVE — every clap subcommand answers --help on the built binary ───────


def adapter_cli_surface(root: Path, binary: str | None) -> Adapter:
    a = Adapter("cli-surface", "LIVE")
    if not binary:
        a.blocked_reason = (
            "no --live <binary> supplied; LIVE family not walked this run"
        )
        return a
    bin_path = Path(binary).expanduser()
    if not bin_path.exists():
        a.blocked_reason = f"binary {bin_path} does not exist"
        return a
    try:
        top = subprocess.run(
            [str(bin_path), "--help"], capture_output=True, text=True, timeout=30
        )
    except (OSError, subprocess.SubprocessError) as e:
        a.blocked_reason = f"{bin_path} --help did not run: {e}"
        return a
    if top.returncode != 0:
        a.blocked_reason = f"{bin_path} --help exited {top.returncode}"
        return a
    subs, in_cmds = [], False
    for line in top.stdout.splitlines():
        if re.match(r"^\s*(Commands|SUBCOMMANDS):", line):
            in_cmds = True
            continue
        if in_cmds:
            if re.match(r"^\S", line) and line.strip().endswith(":"):
                break
            m = re.match(r"^\s{2,}([a-z][a-z0-9-]*)(?:\s|$)", line)
            if m and m.group(1) != "help":
                subs.append(m.group(1))
    if not subs:
        a.blocked_reason = "could not enumerate subcommands from --help output"
        return a
    for sub in sorted(set(subs)):
        try:
            r = subprocess.run(
                [str(bin_path), sub, "--help"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            verdict = "Pass" if r.returncode == 0 else "Fail"
            observed = f"exit {r.returncode}"
        except subprocess.TimeoutExpired:
            verdict, observed = "Retest", "timed out after 30s"
        except (OSError, subprocess.SubprocessError) as e:
            verdict, observed = "Blocked", f"could not invoke: {e}"
        a.records.append(
            Record(
                a.name,
                f"csq {sub}",
                "advertised subcommand answers `--help` with exit 0",
                verdict,
                observed,
            )
        )
    return a


# ── report ────────────────────────────────────────────────────────────────────


def emit(adapters: list[Adapter], as_json: bool) -> int:
    if as_json:
        print(
            json.dumps(
                {
                    "adapters": [
                        {
                            "name": a.name,
                            "family": a.family,
                            "blocked_reason": a.blocked_reason,
                            "records": [r.__dict__ for r in a.records],
                        }
                        for a in adapters
                    ]
                },
                indent=2,
            )
        )
    fails = sum(1 for a in adapters for r in a.records if r.verdict == "Fail")
    if as_json:
        return 1 if fails else 0

    print("# csq Conformance Walk\n")
    print("## Coverage + frontier (denominator machine-derived; NOT pass-rate)\n")
    print("| adapter | family | enumerated | measured | verdict |")
    print("| --- | --- | --- | --- | --- |")
    total_units = 0
    for a in adapters:
        n = len(a.records)
        total_units += n
        state = "walked" if n else f"NOT-RUN — {a.blocked_reason}"
        print(f"| {a.name} | {a.family} | {n} | {n} | {state} |")
    print(
        f"\nTotal units enumerated: {total_units}. "
        f"Adapters not run: {sum(1 for a in adapters if not a.records)} "
        "(reported, never counted as Pass).\n"
    )

    print("## Pass-rate (measured units only)\n")
    print("| adapter | " + " | ".join(VERDICTS) + " |")
    print("| --- |" + " --- |" * len(VERDICTS))
    for a in adapters:
        if not a.records:
            continue
        counts = [str(sum(1 for r in a.records if r.verdict == v)) for v in VERDICTS]
        print(f"| {a.name} | " + " | ".join(counts) + " |")

    bad = [
        r
        for a in adapters
        for r in a.records
        if r.verdict in ("Fail", "Blocked", "Retest")
    ]
    print("\n## Structural findings -> the CI gate\n")
    if not bad:
        print("None. Every measured unit passed its frozen expectation.")
    else:
        for r in bad:
            print(
                f"- **[{r.verdict}] {r.adapter} / `{r.unit}`** — expected: "
                f"{r.expectation}. Observed: {r.observed}"
            )
    print(f"\nExit: {1 if fails else 0} ({fails} Fail rows).")
    return 1 if fails else 0


def main() -> int:
    ap = argparse.ArgumentParser(description="csq Conformance Walk")
    ap.add_argument("--root", default=".", help="repo root (default: cwd)")
    ap.add_argument(
        "--live",
        metavar="BINARY",
        help="path to a built csq binary; enables the LIVE family",
    )
    ap.add_argument("--json", action="store_true", help="emit machine-readable records")
    ap.add_argument(
        "--adapter", action="append", help="run only the named adapter (repeatable)"
    )
    args = ap.parse_args()

    root = Path(args.root).resolve()
    if not (root / "Cargo.toml").exists():
        print(
            f"FATAL: {root} is not the csq workspace root (no Cargo.toml).",
            file=sys.stderr,
        )
        return 2

    build = [
        ("ipc-registration", lambda: adapter_ipc_registration(root)),
        ("ipc-invoke", lambda: adapter_ipc_invoke(root)),
        ("capability-grants", lambda: adapter_capability_grants(root)),
        ("cli-surface", lambda: adapter_cli_surface(root, args.live)),
    ]
    if args.adapter:
        build = [(n, f) for n, f in build if n in args.adapter]
        if not build:
            print(f"FATAL: no adapter matched {args.adapter}", file=sys.stderr)
            return 2
    return emit([f() for _, f in build], args.json)


if __name__ == "__main__":
    sys.exit(main())
