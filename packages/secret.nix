# `secret <command> …` — the primary, discoverable interface to the macOS
# login-Keychain secret store, in the modern noun-verb CLI shape (git/docker/op
# style). Verbs:
#   secret set   <KEY> [VALUE]  store/rotate (hidden prompt if no VALUE)
#   secret get   <KEY>          print one value on demand (lazy read)
#   secret rm    <KEY>          delete + unregister
#   secret ls                   list every registered KEY (from the index; `list` also accepted)
#   secret adopt <KEY>          register a Keychain item added outside this CLI
#   secret load                 reload secrets into the CURRENT shell — SHELL-FUNCTION ONLY
#   secret <KEY>                shorthand for `secret get <KEY>`
#
# The index (`__set_secret_index__`) is SINGLE-WRITER: only this CLI's set/rm
# maintain it. An item created out-of-band (Keychain Access GUI, raw `security
# add-generic-password`) therefore EXISTS — `get` still finds it by direct
# lookup — but is invisible to `ls` AND to the shell loader's export loop
# (`secret load` iterates the same index, so it cannot help either). `get`
# warns on such unindexed hits, and `adopt` re-registers the item through the
# managed set path — which also puts this CLI on the item's ACL, silencing the
# per-read auth prompt GUI-created items carry.
#
# `set-secret` / `remove-secret` remain as thin back-compat aliases. The MUTATING
# verbs (set/rm/adopt) forward to `set-secret` so the Keychain/index logic lives
# in ONE place; get/list are simple reads done here. macOS-ONLY (the Keychain is
# macOS-only). A companion shell FUNCTION the home-manager module wraps this so
# set/rm/adopt/load also update the CURRENT shell's environment — a bare binary
# cannot mutate its parent's env, and `load` is therefore function-only.
{
  writeShellApplication,
  set-secret,
}:
writeShellApplication {
  name = "secret";
  runtimeInputs = [ set-secret ];
  text = ''
    security=/usr/bin/security
    account="$(/usr/bin/id -un)"
    index_service="__set_secret_index__"

    # Optional non-default keychain (positional trailing arg to `security`),
    # mirroring set-secret — lets tests run against a throwaway keychain.
    kc=()
    if [ -n "''${SET_SECRET_KEYCHAIN:-}" ]; then
      kc=("$SET_SECRET_KEYCHAIN")
    fi

    # Usage via printf (not a heredoc): a heredoc terminator inside a Nix
    # indented string is fragile under formatter reindentation.
    usage() {
      printf '%s\n' \
        "usage: secret <command> [args]" \
        "  secret set   <KEY> [VALUE]  store/rotate a secret (hidden prompt if no VALUE)" \
        "  secret get   <KEY>          print a secret's value (lazy read)" \
        "  secret rm    <KEY>          delete a secret and unregister it" \
        "  secret ls                   list every registered secret name (alias: list)" \
        "  secret adopt <KEY>          register a Keychain item added outside this CLI" \
        "  secret load                 reload secrets into the current shell (shell function only)" \
        "  secret <KEY>                shorthand for 'secret get <KEY>'" \
        "aliases: set-secret == 'secret set'  -  remove-secret == 'secret rm'" >&2
    }

    # True iff KEY is registered in the space-separated index item.
    indexed() {
      index="$("$security" find-generic-password -a "$account" -s "$index_service" -w "''${kc[@]}" 2>/dev/null || true)"
      case " $index " in
        *" $1 "*) return 0 ;;
        *) return 1 ;;
      esac
    }

    # Print KEY's value (stdout stays the bare value, as before). If the item
    # exists but is NOT in the index — added out-of-band — warn on stderr: it
    # will not show in `secret ls` and the shell loader (and `secret load`,
    # which walks the same index) will never export it.
    do_get() {
      if value="$("$security" find-generic-password -a "$account" -s "$1" -w "''${kc[@]}" 2>/dev/null)"; then
        printf '%s\n' "$value"
        if ! indexed "$1"; then
          printf '%s\n' \
            "secret: warning: '$1' exists in the Keychain but is not in the index" \
            "  (added outside this CLI, e.g. via Keychain Access?). It will not appear" \
            "  in 'secret ls', and the shell loader / 'secret load' will not export" \
            "  it. Fix: secret adopt $1" >&2
        fi
      else
        rc=$?
        return "$rc"
      fi
    }

    cmd="''${1:-}"
    case "$cmd" in
      -h | --help)
        usage
        exit 0
        ;;
      "")
        usage
        exit 1
        ;;
      set)
        shift
        exec set-secret "$@"
        ;;
      rm | remove | unset)
        shift
        if [ -z "''${1:-}" ]; then
          echo "secret: rm needs <KEY>. usage: secret rm <KEY>" >&2
          exit 1
        fi
        exec set-secret --remove "$1"
        ;;
      get)
        shift
        if [ -z "''${1:-}" ]; then
          echo "secret: get needs <KEY>. usage: secret get <KEY>" >&2
          exit 1
        fi
        do_get "$1"
        ;;
      adopt)
        shift
        if [ -z "''${1:-}" ]; then
          echo "secret: adopt needs <KEY>. usage: secret adopt <KEY>" >&2
          exit 1
        fi
        if ! value="$("$security" find-generic-password -a "$account" -s "$1" -w "''${kc[@]}" 2>/dev/null)"; then
          echo "secret: adopt: no Keychain item named '$1' (account $account) to adopt." >&2
          exit 1
        fi
        if indexed "$1"; then
          echo "secret: adopt: $1 is already registered; nothing to do."
          exit 0
        fi
        # Re-set through the managed path: registers KEY in the index and
        # re-writes the item so this CLI lands on its ACL (GUI-created items
        # otherwise prompt on every read). The value is fed via stdin —
        # set-secret's hidden-prompt path — so it never appears in argv/ps.
        printf '%s\n' "$value" | set-secret "$1"
        ;;
      ls | list)
        # Print each registered KEY on its own line. Peel the space-separated
        # index with POSIX parameter expansion (no unquoted word-split, so the
        # linter stays happy under writeShellApplication's `set -euo pipefail`).
        index="$("$security" find-generic-password -a "$account" -s "$index_service" -w "''${kc[@]}" 2>/dev/null || true)"
        rest="$index"
        while [ -n "$rest" ]; do
          k="''${rest%% *}"
          rest="''${rest#"$k"}"
          rest="''${rest# }"
          [ -n "$k" ] && echo "$k"
        done
        ;;
      load)
        echo "secret load: only works via the shell function (it must mutate the current shell)." >&2
        echo "  Open a new shell, or run: source ~/.config/secrets/loader.sh" >&2
        exit 1
        ;;
      *)
        # Bare `secret KEY` — treat an unknown first word as a get target. (A
        # secret literally named after a verb needs the explicit `secret get <verb>`.)
        do_get "$cmd"
        ;;
    esac
  '';
}
