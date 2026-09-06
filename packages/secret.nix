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
        "  secret set [--env E|--no-export] <SERVICE> [VALUE]   store/rotate (hidden prompt if no VALUE)" \
        "  secret get   <SERVICE|ENV>  print a secret's value (lazy read)" \
        "  secret rm    <SERVICE>      delete a secret and unregister it" \
        "  secret ls [--long]          list registered secrets (alias: list)" \
        "  secret adopt <SERVICE>      register a Keychain item added outside this CLI" \
        "  secret load                 reload secrets into the current shell (shell function only)" \
        "  secret <SERVICE|ENV>        shorthand for 'secret get'" \
        "" \
        "SERVICE is the canonical id, conventionally <tool>:<host>:<kind>" \
        "(e.g. glab:gitlab.com:token). ENV is the shell variable it is exported" \
        "as; a secret with no ENV binding is stored but never made ambient." \
        "aliases: set-secret == 'secret set'  -  remove-secret == 'secret rm'" >&2
    }

    read_index() {
      "$security" find-generic-password -a "$account" -s "$index_service" -w "''${kc[@]}" 2>/dev/null || true
    }

    # Index token halves — see THE INDEX GRAMMAR in packages/set-secret.nix,
    # which is the canonical definition. Split on the FIRST '='; a bare token
    # (no '=') is the legacy self-binding form, where ENV == SERVICE.
    tok_env() { case "$1" in *=*) printf '%s' "''${1%%=*}" ;; *) printf '%s' "$1" ;; esac; }
    tok_service() { case "$1" in *=*) printf '%s' "''${1#*=}" ;; *) printf '%s' "$1" ;; esac; }

    # True iff SERVICE is registered in the index.
    indexed() {
      rest="$(read_index)"
      while [ -n "$rest" ]; do
        t="''${rest%% *}"
        rest="''${rest#"$t"}"
        rest="''${rest# }"
        [ -n "$t" ] || continue
        [ "$(tok_service "$t")" = "$1" ] && return 0
      done
      return 1
    }

    # Resolve a user-supplied name to its SERVICE: prefer an exact SERVICE
    # match, then fall back to an ENV match. That fallback is what keeps
    # `secret get GITLAB_TOKEN` working after the item itself has been renamed
    # to glab:gitlab.com:token — consumers migrate on their own schedule.
    resolve() {
      rest="$(read_index)"
      while [ -n "$rest" ]; do
        t="''${rest%% *}"
        rest="''${rest#"$t"}"
        rest="''${rest# }"
        [ -n "$t" ] || continue
        [ "$(tok_service "$t")" = "$1" ] && { printf '%s' "$1"; return 0; }
      done
      rest="$(read_index)"
      while [ -n "$rest" ]; do
        t="''${rest%% *}"
        rest="''${rest#"$t"}"
        rest="''${rest# }"
        [ -n "$t" ] || continue
        e="$(tok_env "$t")"
        if [ -n "$e" ] && [ "$e" = "$1" ]; then
          printf '%s' "$(tok_service "$t")"
          return 0
        fi
      done
      # Unregistered: try it verbatim, so an out-of-band item is still readable.
      printf '%s' "$1"
      return 0
    }

    # Print KEY's value (stdout stays the bare value, as before). If the item
    # exists but is NOT in the index — added out-of-band — warn on stderr: it
    # will not show in `secret ls` and the shell loader (and `secret load`,
    # which walks the same index) will never export it.
    do_get() {
      svc="$(resolve "$1")"
      if value="$("$security" find-generic-password -a "$account" -s "$svc" -w "''${kc[@]}" 2>/dev/null)"; then
        printf '%s\n' "$value"
        if ! indexed "$svc"; then
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
        # Print each registered SERVICE on its own line; --long adds the ENV it
        # is exported as ("-" when it is deliberately not exported). Peel the
        # space-separated index with POSIX parameter expansion (no unquoted
        # word-split, so the linter stays happy under writeShellApplication's
        # `set -euo pipefail`).
        shift
        long=0
        [ "''${1:-}" = "--long" ] || [ "''${1:-}" = "-l" ] && long=1
        rest="$(read_index)"
        [ "$long" -eq 1 ] && printf '%-34s %s\n' "SERVICE" "ENV"
        while [ -n "$rest" ]; do
          k="''${rest%% *}"
          rest="''${rest#"$k"}"
          rest="''${rest# }"
          [ -n "$k" ] || continue
          if [ "$long" -eq 1 ]; then
            e="$(tok_env "$k")"
            printf '%-34s %s\n' "$(tok_service "$k")" "''${e:--}"
          else
            tok_service "$k"
            printf '\n'
          fi
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
