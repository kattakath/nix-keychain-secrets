# `secret <command> …` — the primary, discoverable interface to the macOS
# login-Keychain secret store, in the modern noun-verb CLI shape (git/docker/op
# style). Verbs:
#   secret set   <KEY> [VALUE]  store/rotate (hidden prompt if no VALUE)
#   secret reveal <KEY>         PRINT one value (the only printing verb)
#   secret rm    <KEY>          delete + unregister
#   secret ls                   list every registered KEY (from the index; `list` also accepted)
#   secret adopt <KEY>          register a Keychain item added outside this CLI
#   secret load                 reload secrets into the CURRENT shell — SHELL-FUNCTION ONLY
#   (no bare `secret <KEY>`, and no `get` — printing is opt-in)
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
  pb-conceal,
}:
writeShellApplication {
  name = "secret";
  runtimeInputs = [
    set-secret
    pb-conceal
  ];
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
        "  secret reveal <SERVICE|ENV>  PRINT the value to stdout (last resort)" \
        "  secret rm    <SERVICE>      delete a secret and unregister it" \
        "  secret ls [--long]          list registered secrets (alias: list)" \
        "  secret exec  [ENV=]SERVICE... -- CMD   run CMD with the secrets in its env" \
        "  secret copy  <SERVICE|ENV>  to the clipboard, concealed + auto-cleared" \
        "  secret fp    <SERVICE|ENV>  identity of a secret, without its value" \
        "  secret bind   <SERVICE> <ENV>  export SERVICE as \$ENV in every shell" \
        "  secret unbind <SERVICE>        stop exporting it; readable only via 'secret get'" \
        "  secret adopt <SERVICE>      register a Keychain item added outside this CLI" \
        "  secret load                 reload secrets into the current shell (shell function only)" \
        "" \
        "There is no bare 'secret <KEY>' and no 'get': printing is opt-in." \
        "Prefer copy (to you), exec (to a command), fp (to verify)." \
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
    # `secret reveal GITLAB_TOKEN` working after the item itself has been renamed
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

    # Rewrite ONLY the index token for SERVICE, leaving the secret value
    # untouched. Without this, changing a binding meant re-running `set-secret`,
    # which needs the value again — so flipping a credential to on-demand would
    # have required reading it out and passing it back in, for a change that
    # concerns the index alone.
    rebind() { # rebind <SERVICE> <ENV|"">
      if ! indexed "$1"; then
        echo "secret: '$1' is not registered; nothing to rebind (see 'secret ls')." >&2
        return 1
      fi
      if [ -n "$2" ] && ! printf '%s' "$2" | grep -qE '^[A-Za-z_][A-Za-z0-9_]*$'; then
        echo "secret: invalid ENV '$2' (must match [A-Za-z_][A-Za-z0-9_]*)" >&2
        return 1
      fi
      if [ -n "$2" ]; then new_tok="$2=$1"; else new_tok="=$1"; fi
      out=""
      rest="$(read_index)"
      while [ -n "$rest" ]; do
        t="''${rest%% *}"
        rest="''${rest#"$t"}"
        rest="''${rest# }"
        [ -n "$t" ] || continue
        [ "$(tok_service "$t")" = "$1" ] && t="$new_tok"
        if [ -n "$out" ]; then out="$out $t"; else out="$t"; fi
      done
      "$security" add-generic-password -U -a "$account" -s "$index_service" -w "$out" "''${kc[@]}"
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

    # The ENV a SERVICE is bound to, or empty. `|| true` + trailing `true`:
    # a loop whose last iteration fails its test leaves the subshell non-zero,
    # which under `set -e` kills the caller with no message.
    bound_env() {
      rest="$(read_index)"
      while [ -n "$rest" ]; do
        t="''${rest%% *}"
        rest="''${rest#"$t"}"
        rest="''${rest# }"
        [ -n "$t" ] || continue
        if [ "$(tok_service "$t")" = "$1" ]; then
          tok_env "$t"
          return 0
        fi
      done
      return 0
    }

    cmd="''${1:-}"
    case "$cmd" in
      exec)
        # `secret exec [ENV=]SERVICE... -- CMD [ARGS]` — put the values in the
        # CHILD's environment and exec. The value never crosses stdout, so it
        # cannot land in a log or an agent transcript. This is the egress meant
        # for machines. Borrowed from `envchain NS CMD`, `chamber exec` and
        # `op run`, which all solve exactly this.
        #
        # The ENV=SERVICE argument form is the index grammar (see
        # set-secret.nix), so a name reads the same here as it does in the
        # store. A bare SERVICE uses whatever ENV the index binds it to; an
        # unbound one must be spelled ENV=SERVICE, because there is nothing to
        # infer and guessing a variable name would silently authenticate
        # nothing.
        shift
        specs=()
        while [ "$#" -gt 0 ]; do
          if [ "$1" = "--" ]; then
            shift
            break
          fi
          specs+=("$1")
          shift
        done
        if [ "''${#specs[@]}" -eq 0 ] || [ "$#" -eq 0 ]; then
          echo "secret: usage: secret exec [ENV=]SERVICE... -- CMD [ARGS]" >&2
          exit 1
        fi
        for spec in "''${specs[@]}"; do
          case "$spec" in
            *=*)
              e="''${spec%%=*}"
              svc="''${spec#*=}"
              ;;
            *)
              svc="$(resolve "$spec")"
              e="$(bound_env "$svc")"
              if [ -z "$e" ]; then
                echo "secret: '$spec' has no env binding; spell it ENV=$svc" >&2
                exit 1
              fi
              ;;
          esac
          if ! v="$("$security" find-generic-password -a "$account" -s "$svc" -w "''${kc[@]}" 2>/dev/null)"; then
            echo "secret: exec: no Keychain item '$svc'" >&2
            exit 1
          fi
          export "$e=$v"
          v=""
        done
        exec "$@"
        ;;
      copy | clip | -c)
        # The HUMAN handoff: put the value on the pasteboard and print only a
        # status line, so it never crosses stdout into a log or a transcript.
        #
        # NOT pbcopy — see packages/pb-conceal.nix for why pbcopy structurally
        # cannot do this, what the two pasteboard markers are, and the residual
        # risk that remains. This verb owns only the Keychain read and the
        # timeout default; the pasteboard mechanics are entirely over there.
        shift
        if [ -z "''${1:-}" ]; then
          echo "secret: copy needs <SERVICE|ENV>. usage: secret copy <SERVICE>" >&2
          exit 1
        fi
        svc="$(resolve "$1")"
        if ! v="$("$security" find-generic-password -a "$account" -s "$svc" -w "''${kc[@]}" 2>/dev/null)"; then
          echo "secret: copy: no Keychain item '$svc'" >&2
          exit 1
        fi
        clip_time="''${SECRET_CLIP_TIME:-45}"
        # The pasteboard mechanics live in pb-conceal, which knows nothing about
        # the Keychain and takes any value on stdin. Keeping them in a separate
        # binary is what makes this a seam rather than a tangle: if a second
        # consumer ever appears, extracting it is a file move, not a rewrite.
        # Value goes over the PIPE, never argv.
        if ! printf '%s' "$v" | pb-conceal --clear "$clip_time" >/dev/null; then
          v=""
          echo "secret: copy: pasteboard write failed" >&2
          exit 1
        fi
        v=""
        echo "secret: $svc copied — concealed, host-only, clears in ''${clip_time}s."
        ;;
      fp | fingerprint)
        # Identity of a secret, never its value — the question an agent actually
        # needs answered ("did the rotation land?", "is this the same value?").
        #
        # mdat comes free: `security find-generic-password` WITHOUT -w/-g prints
        # the item's metadata and no value at all. Same answer GitHub's
        # `updated_at` and `fly secrets list` give.
        #
        # The digest is HMAC-SHA256 under a machine-local random salt, truncated
        # to 12 base64 chars (~72 bits). The salt is the load-bearing part: a
        # bare truncated hash of a low-entropy secret is dictionary-attackable.
        # Same reasoning as HIBP's k-anonymity range API. Format mirrors
        # `ssh-add -l`. NOT an interop format — the salt is local, so nobody
        # else can reproduce these digests, and that is deliberate.
        shift
        if [ -z "''${1:-}" ]; then
          echo "secret: fp needs <SERVICE|ENV>. usage: secret fp <SERVICE>" >&2
          exit 1
        fi
        svc="$(resolve "$1")"
        if ! v="$("$security" find-generic-password -a "$account" -s "$svc" -w "''${kc[@]}" 2>/dev/null)"; then
          echo "secret: fp: no Keychain item '$svc'" >&2
          exit 1
        fi
        salt_service="__secret_fp_salt__"
        if ! salt="$("$security" find-generic-password -a "$account" -s "$salt_service" -w "''${kc[@]}" 2>/dev/null)"; then
          salt="$(/usr/bin/openssl rand -base64 32)"
          "$security" add-generic-password -U -a "$account" -s "$salt_service" -w "$salt" "''${kc[@]}"
        fi
        digest="$(printf '%s' "$v" | /usr/bin/openssl dgst -sha256 -hmac "$salt" -binary | /usr/bin/openssl base64 -A | cut -c1-12)"
        # Metadata WITHOUT -w/-g: prints attributes, never the value. The mdat
        # line looks like:  "mdat"<timedate>=0x...  "20260906182027Z"
        # security(1) renders the trailing NUL of the timedate blob literally as
        # the four characters \000 — strip it rather than shipping it in output.
        mdat="$("$security" find-generic-password -a "$account" -s "$svc" "''${kc[@]}" 2>&1 |
          awk -F'"' '/"mdat"/ { print $(NF - 1) }' | head -1)"
        mdat="''${mdat%%\\000}"
        printf '%-34s sha256:%s  len=%s  mdat=%s\n' "$svc" "$digest" "''${#v}" "''${mdat:-unknown}"
        v=""
        salt=""
        ;;
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
      reveal)
        # The ONE verb that prints a secret to stdout. Named so it is loud,
        # greppable and easy to deny in a PreToolUse hook — the point is not
        # that printing is forbidden, but that it can never happen by accident
        # or by habit. copy/exec/fp cover every routine case without printing.
        shift
        if [ -z "''${1:-}" ]; then
          echo "secret: reveal needs <SERVICE|ENV>. usage: secret reveal <SERVICE>" >&2
          exit 1
        fi
        do_get "$1"
        ;;
      get)
        # Deliberately removed rather than aliased. An alias would keep every
        # old habit and every old script silently printing, which is the thing
        # this rename exists to stop. Fail loudly and name the alternatives.
        shift
        echo "secret: 'get' is gone — it printed secrets into logs and transcripts." >&2
        printf '%s\n' \
          "  to hand one to yourself:   secret copy ''${1:-<SERVICE>}" \
          "  to give one to a command:  secret exec ''${1:-<SERVICE>} -- CMD" \
          "  to check it is the right:  secret fp ''${1:-<SERVICE>}" \
          "  to actually print it:      secret reveal ''${1:-<SERVICE>}" >&2
        exit 1
        ;;
      bind)
        shift
        if [ -z "''${1:-}" ] || [ -z "''${2:-}" ]; then
          echo "secret: bind needs <SERVICE> <ENV>. usage: secret bind <SERVICE> <ENV>" >&2
          exit 1
        fi
        rebind "$1" "$2" || exit 1
        echo "secret: $1 -> \$$2 (exported in every NEW shell; 'secret load' to apply here)"
        ;;
      unbind)
        shift
        if [ -z "''${1:-}" ]; then
          echo "secret: unbind needs <SERVICE>. usage: secret unbind <SERVICE>" >&2
          exit 1
        fi
        # `|| true` + a trailing `true`: this runs under writeShellApplication's
        # `set -e`, and a loop whose LAST iteration fails its test leaves the
        # subshell non-zero, which killed the whole command with no message.
        was="$(
          rest="$(read_index)"
          while [ -n "$rest" ]; do
            t="''${rest%% *}"
            rest="''${rest#"$t"}"
            rest="''${rest# }"
            [ -n "$t" ] || continue
            if [ "$(tok_service "$t")" = "$1" ]; then
              tok_env "$t"
              break
            fi
          done
          true
        )" || true
        rebind "$1" "" || exit 1
        if [ -n "$was" ]; then
          echo "secret: $1 no longer exported (was \$$was). Reach it with: secret copy $1 | secret exec | secret fp"
          echo "  NOTE: still set in ALREADY-RUNNING shells. 'unset $was' here, or open a new shell." >&2
        else
          echo "secret: $1 was already unbound; nothing to do."
        fi
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
        # A bare `secret KEY` used to print. That made the most accident-prone
        # thing also the shortest thing to type, so it is gone too: an unknown
        # word is now an error, not a silent disclosure.
        echo "secret: unknown command '$cmd'." >&2
        printf '%s\n' \
          "  did you mean:  secret copy $cmd   |   secret exec $cmd -- CMD" \
          "                 secret fp $cmd     |   secret reveal $cmd" >&2
        exit 1
        ;;
    esac
  '';
}
