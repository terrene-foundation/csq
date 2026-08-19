#!/usr/bin/env python3
"""Ratchet on the renderer's effective granted IPC surface.

`csq/capabilities/default.json` narrows every plugin grant to leaf permissions
except one: `core:default`. That bundle's membership is defined UPSTREAM, in
Tauri's own ACL manifests, and it is regenerated into
`csq/gen/schemas/acl-manifests.json` as a mechanical side effect of a `tauri`
version bump. So a Tauri MINOR bump can add commands to the renderer's
reachable surface with no csq file changing, no permission line moving in
review, and CI green.

That is not hypothetical. The 2.10.3 -> 2.11.5 bump added four:
    core:app:default    += allow-supports-multiple-windows
    core:tray:default   += allow-set-icon-with-as-template
    core:window:default += allow-activity-name, allow-scene-identifier
It took a security review plus a hand-written JSON parse to notice, because
`acl-manifests.json` is a single-line blob in which the string `core:app:default`
never literally appears -- every grep-shaped check is structurally blind to it.

This gate expands csq's ACTUAL grants through the manifests to a set of leaf
permission IDENTIFIERS, and fails when that set changes without the snapshot
being updated deliberately. (An identifier is not a command: a manifest lists the
commands an identifier unlocks separately, under `commands.allow`. In Tauri's core
manifests the mapping is 1:1 today, but the ratchet is over identifiers.)
`tauri-commands.md` treats the renderer as adversarial; this makes the adversary's
granted surface a reviewed constant instead of an upstream side effect.

A reference the manifests cannot resolve is the one way this could degrade
quietly, so it never passes unremarked: an unexpandable `:default` bundle is fatal
at exit 2, and every other unresolved key is recorded in the snapshot so that its
own movement trips the ratchet. See `expand()`.

Exit 0 = surface unchanged. Exit 1 = surface changed (review, then --update).
Exit 2 = the gate could not run (missing/corrupt/unexpandable input, or any
unhandled error during expansion) -- never silently clean, and never exit 1, which
would send the operator to re-run `--update` on an input that cannot be evaluated.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import NoReturn

REPO_ROOT = Path(__file__).resolve().parent.parent
CAPABILITIES = REPO_ROOT / "csq" / "capabilities" / "default.json"
MANIFESTS = REPO_ROOT / "csq" / "gen" / "schemas" / "acl-manifests.json"
SNAPSHOT = REPO_ROOT / "scripts" / "acl-granted-surface.snapshot.json"


def die(msg: str) -> NoReturn:
    """Fail LOUDLY at exit 2. A gate that cannot run is not a gate that passed."""
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(2)


def load_json(path: Path) -> dict:
    if not path.exists():
        die(f"{path.relative_to(REPO_ROOT)} not found -- cannot evaluate the grant surface.")
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError as e:
        die(f"{path.relative_to(REPO_ROOT)} is not valid JSON: {e}")


def split_ref(ref: str, current_plugin: str) -> tuple[str, str]:
    """Resolve a permission reference to (plugin, name).

    References are either qualified (`core:app:default`, `opener:allow-open-url`)
    or bare (`allow-version`), the latter being relative to the plugin whose
    manifest we are currently expanding.
    """
    if ":" not in ref:
        return current_plugin, ref
    plugin, _, name = ref.rpartition(":")
    return plugin, name


def expand(
    ref: str, manifests: dict, current_plugin: str, seen: set[str], unresolved: set[str]
) -> set[str]:
    """Expand one permission reference into its set of leaf permissions.

    A reference expands if it names a plugin's `default_permission` or one of its
    `permission_sets`; otherwise it is a leaf. `seen` breaks cycles -- upstream
    manifests are generated, and a cycle there must not hang the gate.

    `unresolved` collects every key whose plugin is absent from the manifests; see
    the unknown-plugin branch below for why that set is carried into the snapshot.
    """
    plugin, name = split_ref(ref, current_plugin)
    key = f"{plugin}:{name}"
    if key in seen:
        return set()
    seen.add(key)

    entry = manifests.get(plugin)
    if entry is None:
        # An unknown plugin key is AMBIGUOUS: the reference is either a genuine
        # leaf permission, or a BUNDLE whose members we can no longer see. Reading
        # a bundle as a leaf collapses its entire subtree into one opaque token, so
        # a command later added under it leaves the leaf set unchanged and the gate
        # exits 0 while the surface widened. That degradation is silent by
        # construction, and an upstream manifest key-naming restructure (say,
        # `core:app:default` becoming `app:default`) is exactly the mechanical
        # change this gate exists to survive.
        #
        # BOTH remedies the review offered are applied, because they cover
        # different halves of the ambiguity and neither is sufficient alone:
        #
        #   (a) A `:default` reference is a bundle BY CONSTRUCTION -- Tauri's
        #       manifests define `default` only as a `default_permission` block.
        #       An unknown plugin there is unambiguously an unexpandable bundle,
        #       so we die at exit 2 rather than under-report.
        #   (b) Every other unknown key MIGHT be a legitimate leaf, so dying would
        #       be a false positive. Instead it is recorded in the snapshot, which
        #       makes the unresolved set itself part of the ratchet: if a key
        #       appears, disappears, or is renamed, the comparison trips at exit 1
        #       and an operator reads it, rather than the subtree silently
        #       evaporating.
        if name == "default":
            die(
                f"permission reference {ref!r} resolves to bundle {key!r}, but plugin "
                f"{plugin!r} is absent from {MANIFESTS.name}. Its members cannot be "
                f"expanded, so the granted surface would be UNDER-reported and this gate "
                f"would pass while widening. Re-derive the reference against the current "
                f"manifests -- do not ignore it."
            )
        unresolved.add(key)
        return {key}

    if name == "default":
        members = entry.get("default_permission", {}).get("permissions", [])
        out: set[str] = set()
        for m in members:
            out |= expand(m, manifests, plugin, seen, unresolved)
        return out

    pset = entry.get("permission_sets", {}).get(name)
    if pset:
        out = set()
        for m in pset.get("permissions", []):
            out |= expand(m, manifests, plugin, seen, unresolved)
        return out

    return {key}


def compute_surface() -> dict[str, list[str]]:
    caps = load_json(CAPABILITIES)
    manifests = load_json(MANIFESTS)

    grants = caps.get("permissions")
    if not grants:
        die("capabilities/default.json declares no permissions -- refusing to record an empty surface.")

    leaves: set[str] = set()
    unresolved: set[str] = set()
    for g in grants:
        if not isinstance(g, str):
            die(f"non-string permission grant {g!r}; object-form scoped grants are not yet handled by this gate.")
        plugin, _ = split_ref(g, "")
        leaves |= expand(g, manifests, plugin, set(), unresolved)

    if not leaves:
        die("expanded grant surface is empty -- the manifests or capabilities file is malformed.")

    return {
        "granted": sorted(grants),
        "effective_leaf_permissions": sorted(leaves),
        "unresolved_references": sorted(unresolved),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument(
        "--update",
        action="store_true",
        help="Rewrite the snapshot. Use ONLY after reviewing each added permission "
        "against tauri-commands.md MUST-3 (no credentials in return types).",
    )
    args = ap.parse_args()

    # Any unhandled exception inside expansion (a top-level JSON array where a
    # mapping is expected, an unexpected member shape) would otherwise propagate
    # as Python's default exit 1 -- which is this gate's "surface CHANGED" code.
    # The operator would be told to review a diff and re-run `--update`, which
    # crashes identically. A gate that cannot run must say so at exit 2.
    # `die()` raises SystemExit, which is not an Exception, so its own exit 2
    # paths pass straight through this handler.
    try:
        current = compute_surface()
    except Exception as e:  # noqa: BLE001 -- deliberate: any crash is a failed gate
        die(f"could not evaluate the grant surface: {type(e).__name__}: {e}")

    if args.update:
        SNAPSHOT.write_text(json.dumps(current, indent=2) + "\n")
        print(f"Snapshot updated: {len(current['effective_leaf_permissions'])} effective leaf permissions.")
        return 0

    if not SNAPSHOT.exists():
        die(f"{SNAPSHOT.relative_to(REPO_ROOT)} not found. Create it with --update after reviewing the surface.")

    recorded = load_json(SNAPSHOT)
    old = set(recorded.get("effective_leaf_permissions", []))
    new = set(current["effective_leaf_permissions"])

    if not old:
        die("recorded snapshot has an empty permission set -- refusing to compare against nothing.")

    added, removed = sorted(new - old), sorted(old - new)
    grants_changed = recorded.get("granted", []) != current["granted"]
    # Part (b) of the unknown-plugin remedy in `expand()`: a key that could not be
    # resolved against the manifests is opaque, so any movement in that set is a
    # reviewable event rather than something the leaf diff can be trusted to show.
    old_unresolved = sorted(recorded.get("unresolved_references", []))
    unresolved_changed = old_unresolved != current["unresolved_references"]

    if not added and not removed and not grants_changed and not unresolved_changed:
        print(f"ACL GRANT SURFACE UNCHANGED — {len(new)} effective leaf permissions.")
        return 0

    print("ACL GRANT SURFACE CHANGED — the renderer's granted permission surface moved.\n")
    if unresolved_changed:
        print("  references that could not be expanded against the manifests changed:")
        for r in sorted(set(current["unresolved_references"]) - set(old_unresolved)):
            print(f"      + {r}")
        for r in sorted(set(old_unresolved) - set(current["unresolved_references"])):
            print(f"      - {r}")
        print("    (an unresolved key hides whatever sits beneath it — resolve it, do not record it blind.)")
        print()
    if grants_changed:
        print("  csq/capabilities/default.json grants changed:")
        for g in sorted(set(current["granted"]) - set(recorded.get("granted", []))):
            print(f"      + {g}")
        for g in sorted(set(recorded.get("granted", [])) - set(current["granted"])):
            print(f"      - {g}")
        print()
    for p in added:
        print(f"      + {p}")
    for p in removed:
        print(f"      - {p}")

    print(
        "\nEach ADDED entry is a permission IDENTIFIER newly inside csq's granted\n"
        "surface. A permission is not identical to a command — a manifest models the\n"
        "commands it unlocks separately, under `commands.allow` — though in Tauri's\n"
        "core manifests the mapping is 1:1 today. Audit the commands each added\n"
        "identifier admits, not the identifier's name alone.\n"
        "If csq's capabilities file did not change, this arrived from an upstream\n"
        "Tauri bump regenerating csq/gen/schemas/acl-manifests.json.\n\n"
        "Required before accepting:\n"
        "  1. Audit each added command against tauri-commands.md MUST-3\n"
        "     (no credentials, tokens, or keys in return types) and MUST NOT 1.\n"
        "  2. Name every addition in the PR body so it is reviewed, not silent.\n"
        "  3. Re-run with --update to move the ratchet deliberately.\n"
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
