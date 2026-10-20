# Synthetic instrument control, never a replacement for a product hook.
# Use an absolute interpreter; no helper search path or inherited user state.
mode=$1
root=$2
[ "$HOME" = "$root/home" ] || exit 91
[ "$CSQ_BASE_DIR" = "$root/base" ] || exit 92
[ "$CLAUDE_CONFIG_DIR" = "$root/config" ] || exit 93
[ "$PWD" = "$root/cwd" ] || exit 94
[ "$PATH" = "$root/empty-path" ] || exit 95
[ -z "${ANTHROPIC_API_KEY+x}" ] || exit 96
IFS= read -r payload || exit 97
[ "$payload" = 'payload' ] || exit 98
[ -f seed.txt ] && IFS= read -r seed < seed.txt || exit 99
[ "$seed" = 'frozen' ] || exit 100
# Independent arm roots: the second arm must not see the first arm's write.
[ ! -e arm-created.txt ] || exit 101
printf '%s\n' 'fixture effect' > arm-created.txt
[ ! -e "$0.mutation" ] || exit 103
printf '%s\n' 'private source effect' > "$0.mutation"
case "$mode" in
  allow) printf '%s\n' '{"decision":"allow","context":[],"rewrite":null}' ;;
  deny) printf '%s\n' '{"decision":"deny","context":[],"rewrite":null}' ;;
  malformed) printf '%s\n' '{"decision":' ;;
  duplicate) printf '%s\n' '{"decision":"deny","decision":"allow","context":[],"rewrite":null}' ;;
  duplicate-rewrite) printf '%s\n' '{"decision":"allow","context":[],"rewrite":{"a":1,"a":2}}' ;;
  rewrite) printf '%s\n' '{"decision":"allow","context":[],"rewrite":{"a":2}}' ;;
  unknown) printf '%s\n' '{"decision":"mystery","context":[],"rewrite":null}' ;;
  stderr) printf '%s\n' 'diagnostic' >&2; printf '%s\n' '{"decision":"allow","context":[],"rewrite":null}' ;;
  flood) while :; do printf '%s' '0123456789012345678901234567890123456789'; done ;;
  hang) while :; do :; done ;;
  inherited-pipe) (while :; do :; done) & printf '%s\n' '{"decision":"allow","context":[],"rewrite":null}' ;;
  *) exit 102 ;;
esac
