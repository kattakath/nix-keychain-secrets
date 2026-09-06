# `set-secret <SERVICE> [VALUE]` — store a secret in the macOS login Keychain
# (encrypted at rest) and register it so every shell exports it. The inverse is
# `set-secret --remove <SERVICE>` (delete the item + unregister from the index).
# macOS-ONLY:
# the Keychain is the single source of truth — nothing secret (not even the key
# NAMES) is ever written to disk in plaintext.
#
# A companion shell FUNCTION the home-manager module wraps this binary so a
# `set-secret KEY VALUE` at the prompt ALSO exports the value into the CURRENT
# shell immediately; new login shells load every registered secret via the
# export loop in that same module. Run bare (`nix run .#set-secret`) it only
# persists — a child process cannot mutate its parent shell's environment.
#
# Managed items (login Keychain, account = `id -un`):
#   service = <SERVICE>             -> the secret value
#   service = __set_secret_index__  -> space-separated INDEX, read by the loader
#
# ===========================================================================
# THE INDEX GRAMMAR — canonical definition. The loader
# (modules/keychain-secrets.nix) and `secret` (packages/secret.nix) both parse
# this; all three MUST agree or the store silently mis-reads.
#
#   index := token (" " token)*
#   token := ENV "=" SERVICE    exported into every shell as $ENV
#          |     "=" SERVICE    stored, NEVER exported (on-demand only)
#          |         SERVICE    legacy self-binding: exported as $SERVICE
#
#   SERVICE := [A-Za-z_][A-Za-z0-9_.:-]*   (may contain ':' and '.')
#   ENV     := [A-Za-z_][A-Za-z0-9_]*      (must be a shell identifier)
#
# Split ENV/SERVICE on the FIRST '=' (''${tok%%=*} / ''${tok#*=}), so a SERVICE
# may itself contain '='. Tokens never contain a space, and the index must stay
# newline-free: `security -w` returns any value containing a newline as HEX,
# which would corrupt it.
#
# WHY the separate ENV binding. Before this, the Keychain service name WAS the
# env var name, so the store could hold exactly one credential per provider —
# you could not keep, say, a full-scope and a read-only gitlab.com token side by
# side, because both wanted to be $GITLAB_TOKEN. Naming items
# `<tool>:<host>:<kind>` (the convention GitLab's own CLI uses in this very
# keychain — `glab:gitlab.com:token`, `:job_token`, `:oauth2_refresh_token`)
# makes per-audience, per-privilege credentials expressible, and the ENV column
# is what re-attaches them to consumers that still read an env var.
#
# The second thing it buys: a token with NO env binding is stored but never
# ambient. That is a per-secret answer to this module's own security caveat
# (secrets readable via `env` by any process in the tree, AI agents included) —
# high-privilege credentials can now be read only on demand, by the one wrapper
# that needs them.
#
# Prior art for the shape: 1Password's `op://vault/item/field` + `op run
# --env-file` is the same split (hierarchical id, explicit env binding), as is
# `pass`'s directory tree. This is that pattern on the one store macOS gives a
# shell.
# ===========================================================================
#
# Testing / advanced: export SET_SECRET_KEYCHAIN=/path/to.keychain to target a
# keychain other than the default login one.
{
  writeShellApplication,
  coreutils,
  gnugrep,
}:
writeShellApplication {
  name = "set-secret";
  runtimeInputs = [
    coreutils
    gnugrep
  ];
  text = ''
    security=/usr/bin/security
    account="$(id -un)"
    index_service="__set_secret_index__"

    # Optional non-default keychain (positional trailing arg to `security`).
    kc=()
    if [ -n "''${SET_SECRET_KEYCHAIN:-}" ]; then
      kc=("$SET_SECRET_KEYCHAIN")
    fi

    usage() {
      printf '%s\n' \
        "usage: set-secret [--env ENV | --no-export] <SERVICE> [VALUE]" \
        "       set-secret --remove <SERVICE>   (aliases: -r)" \
        "  Stores the value under SERVICE in the macOS login Keychain (encrypted" \
        "  at rest) and registers it so every shell exports it as \$ENV." \
        "" \
        "  SERVICE  [A-Za-z_][A-Za-z0-9_.:-]*  e.g. glab:gitlab.com:token" \
        "  --env    bind to this env var instead of SERVICE" \
        "  --no-export  store it, but never make it ambient (on-demand only)" \
        "" \
        "  ENV defaults to SERVICE when SERVICE is a valid shell identifier," \
        "  and to none otherwise — so a ':'-shaped name is opt-in to export." \
        "  Omit VALUE for a hidden prompt." >&2
    }

    valid_service() { printf '%s' "$1" | grep -qE '^[A-Za-z_][A-Za-z0-9_.:-]*$'; }
    valid_env() { printf '%s' "$1" | grep -qE '^[A-Za-z_][A-Za-z0-9_]*$'; }

    # Emit the SERVICE half of an index token (see THE INDEX GRAMMAR above).
    tok_service() { case "$1" in *=*) printf '%s' "''${1#*=}" ;; *) printf '%s' "$1" ;; esac; }

    read_index() {
      "$security" find-generic-password -a "$account" -s "$index_service" -w "''${kc[@]}" 2>/dev/null || true
    }

    if [ "''${1:-}" = "-h" ] || [ "''${1:-}" = "--help" ]; then
      usage
      exit 0
    fi

    # --remove/-r <SERVICE>: delete the Keychain item (idempotent — ignore "not
    # found") AND unregister it from the index, rebuilding the space-separated
    # list without the token whose SERVICE half matches. The inverse of the add
    # path; fixes index/Keychain drift.
    if [ "''${1:-}" = "--remove" ] || [ "''${1:-}" = "-r" ]; then
      key="''${2:-}"
      if [ -z "$key" ]; then
        echo "set-secret: --remove needs <SERVICE>. usage: set-secret --remove <SERVICE>" >&2
        exit 1
      fi
      if ! valid_service "$key"; then
        echo "set-secret: invalid SERVICE '$key' (must match [A-Za-z_][A-Za-z0-9_.:-]*)" >&2
        exit 1
      fi
      "$security" delete-generic-password -a "$account" -s "$key" "''${kc[@]}" >/dev/null 2>&1 || true
      index="$(read_index)"
      new_index=""
      rest="$index"
      while [ -n "$rest" ]; do
        k="''${rest%% *}"
        rest="''${rest#"$k"}"
        rest="''${rest# }"
        [ -n "$k" ] || continue
        [ "$(tok_service "$k")" = "$key" ] && continue
        if [ -n "$new_index" ]; then new_index="$new_index $k"; else new_index="$k"; fi
      done
      "$security" add-generic-password -U -a "$account" -s "$index_service" -w "$new_index" "''${kc[@]}"
      echo "set-secret: removed $key (Keychain item deleted if present; unregistered from index)."
      exit 0
    fi

    # --env ENV / --no-export must precede SERVICE.
    env_name=""
    env_set=0
    while true; do
      case "''${1:-}" in
        --env)
          env_name="''${2:-}"
          env_set=1
          if [ -z "$env_name" ]; then
            echo "set-secret: --env needs a name." >&2
            exit 1
          fi
          shift 2
          ;;
        --no-export)
          env_name=""
          env_set=1
          shift
          ;;
        *) break ;;
      esac
    done

    key="''${1:-}"
    if [ -z "$key" ]; then
      echo "set-secret: missing <SERVICE>. usage: set-secret [--env ENV] <SERVICE> [VALUE]" >&2
      exit 1
    fi
    if ! valid_service "$key"; then
      echo "set-secret: invalid SERVICE '$key' (must match [A-Za-z_][A-Za-z0-9_.:-]*)" >&2
      exit 1
    fi

    # Default binding: SERVICE itself when it is a usable shell identifier
    # (keeps every pre-existing FLAT_NAME working untouched), otherwise none —
    # so a ':'-shaped name never becomes ambient by accident.
    if [ "$env_set" -eq 0 ]; then
      if valid_env "$key"; then env_name="$key"; else env_name=""; fi
    fi
    if [ -n "$env_name" ] && ! valid_env "$env_name"; then
      echo "set-secret: invalid ENV '$env_name' (must match [A-Za-z_][A-Za-z0-9_]*)" >&2
      exit 1
    fi

    if [ "$#" -ge 2 ]; then
      value="$2"
    else
      # No value on the command line: read it hidden so it never hits history/ps.
      printf 'Value for %s: ' "$key" >&2
      IFS= read -rs value
      printf '\n' >&2
      if [ -z "$value" ]; then
        echo "set-secret: empty value; nothing stored." >&2
        exit 1
      fi
    fi

    # Store the secret encrypted. -U updates the item in place if it exists.
    "$security" add-generic-password -U -a "$account" -s "$key" -w "$value" "''${kc[@]}"

    # Register in the index, replacing any existing token for this SERVICE so a
    # re-set can CHANGE the binding. A legacy bare token is rewritten to the
    # explicit ENV=SERVICE form on its next set.
    if [ -n "$env_name" ]; then token="$env_name=$key"; else token="=$key"; fi
    index="$(read_index)"
    new_index=""
    rest="$index"
    while [ -n "$rest" ]; do
      k="''${rest%% *}"
      rest="''${rest#"$k"}"
      rest="''${rest# }"
      [ -n "$k" ] || continue
      [ "$(tok_service "$k")" = "$key" ] && continue
      if [ -n "$new_index" ]; then new_index="$new_index $k"; else new_index="$k"; fi
    done
    if [ -n "$new_index" ]; then new_index="$new_index $token"; else new_index="$token"; fi
    if [ "$new_index" != "$index" ]; then
      "$security" add-generic-password -U -a "$account" -s "$index_service" -w "$new_index" "''${kc[@]}"
    fi

    # Verify the value round-trips back out of the Keychain, then show only the
    # first few characters as proof (never the whole secret).
    got="$("$security" find-generic-password -a "$account" -s "$key" -w "''${kc[@]}" 2>/dev/null || true)"
    if [ "$got" != "$value" ]; then
      echo "set-secret: WARNING — $key did not round-trip out of the Keychain." >&2
      exit 1
    fi
    if [ -n "$env_name" ]; then
      echo "set-secret: stored $key -> \$$env_name (value starts with ''${got:0:4}…)."
    else
      echo "set-secret: stored $key (NOT exported; read with 'secret get $key') (value starts with ''${got:0:4}…)."
    fi
  '';
}
