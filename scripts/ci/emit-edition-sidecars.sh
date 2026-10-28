#!/usr/bin/env bash
# Trusted build claim, not bundled-content proof or signed provenance.
# Run from the matching release-oracle revision AFTER final signing/packaging.
# Usage: emit-edition-sidecars.sh <raw-binary> <final-artifact> [...]
# Reads bytes only; never executes the raw binary. No caller-supplied edition.
set -uo pipefail
[ "$#" -ge 2 ] || { echo 'UNDETERMINED: raw binary and final artifacts required' >&2; exit 2; }
raw="$1"; shift
[ -f "$raw" ] && [ ! -L "$raw" ] || { echo 'UNDETERMINED: raw binary unavailable' >&2; exit 2; }
matches="$(mktemp)" || exit 2
trap 'rm -f "$matches"' EXIT
LC_ALL=C grep -a -o -E '[0-9]+\.[0-9]+\.[0-9]+ \((community|enterprise)\)' "$raw" > "$matches"
scan_rc=$?
if [ "$scan_rc" -ne 0 ]; then echo 'UNDETERMINED: raw scan failed' >&2; exit 2; fi
eds="$(cat "$matches")" || exit 2
case "$eds" in
  *' (enterprise)'*) edition=enterprise ;;
  *' (community)'*) edition=community ;;
  *) echo 'UNDETERMINED: raw edition literal unavailable' >&2; exit 2 ;;
esac
command -v python3 >/dev/null 2>&1 || exit 2
python3 - "$edition" "$@" <<'PYCLAIM'
import hashlib, json, pathlib, sys
try:
    edition = sys.argv[1]
    claims = []
    for name in sys.argv[2:]:
        artifact = pathlib.Path(name)
        sidecar = pathlib.Path(name + '.edition')
        if (not artifact.is_file() or artifact.is_symlink() or sidecar.is_symlink()
                or artifact.suffix in ('.sig', '.sha256', '.edition')):
            raise ValueError(f'not a final regular bundle: {artifact}')
        digest = hashlib.sha256()
        with artifact.open('rb') as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                digest.update(chunk)
        claims.append((sidecar, {'format_version': 1, 'edition': edition,
                      'artifact_sha256': digest.hexdigest()}))
    for sidecar, claim in claims:
        sidecar.write_text(json.dumps(claim, sort_keys=True) + '\n')
    print(f'wrote {len(claims)} artifact-bound edition claim(s)')
except (OSError, ValueError) as error:
    print('UNDETERMINED: ' + str(error), file=sys.stderr)
    sys.exit(2)
PYCLAIM
