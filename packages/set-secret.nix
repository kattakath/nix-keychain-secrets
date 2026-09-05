# `set-secret <KEY> [VALUE]` — store a secret in the macOS login Keychain
# (encrypted at rest) and register it so every shell exports it. The inverse is
# `set-secret --remove <KEY>` (delete the item + unregister from the index).
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
#   service = <KEY>                 -> the secret value
#   service = __set_secret_index__  -> space-separated list of managed KEYs,
#                                      read by the login export loop
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

    if [ "''${1:-}" = "-h" ] || [ "''${1:-}" = "--help" ]; then
      echo "usage: set-secret <KEY> [VALUE]"
      echo "       set-secret --remove <KEY>   (aliases: -r)"
      echo "  Stores KEY=VALUE in the macOS login Keychain (encrypted at rest) and"
      echo "  registers KEY so every shell exports it. Omit VALUE for a hidden"
      echo "  prompt. --remove deletes the Keychain item (if any) and unregisters"
      echo "  KEY from the index. Use the set-secret shell function to also apply"
      echo "  the change (export / unset) to the current shell immediately."
      exit 0
    fi

    # --remove/-r <KEY>: delete the Keychain item (idempotent — ignore "not
    # found") AND unregister KEY from the index, rebuilding the space-separated
    # list without it. The inverse of the add path; fixes index/Keychain drift.
    if [ "''${1:-}" = "--remove" ] || [ "''${1:-}" = "-r" ]; then
      key="''${2:-}"
      if [ -z "$key" ]; then
        echo "set-secret: --remove needs <KEY>. usage: set-secret --remove <KEY>" >&2
        exit 1
      fi
      if ! printf '%s' "$key" | grep -qE '^[A-Za-z_][A-Za-z0-9_]*$'; then
        echo "set-secret: invalid KEY '$key' (must match [A-Za-z_][A-Za-z0-9_]*)" >&2
        exit 1
      fi
      "$security" delete-generic-password -a "$account" -s "$key" "''${kc[@]}" >/dev/null 2>&1 || true
      index="$("$security" find-generic-password -a "$account" -s "$index_service" -w "''${kc[@]}" 2>/dev/null || true)"
      new_index=""
      rest="$index"
      while [ -n "$rest" ]; do
        k="''${rest%% *}"
        rest="''${rest#"$k"}"
        rest="''${rest# }"
        [ -n "$k" ] || continue
        [ "$k" = "$key" ] && continue
        if [ -n "$new_index" ]; then new_index="$new_index $k"; else new_index="$k"; fi
      done
      "$security" add-generic-password -U -a "$account" -s "$index_service" -w "$new_index" "''${kc[@]}"
      echo "set-secret: removed $key (Keychain item deleted if present; unregistered from index)."
      exit 0
    fi

    key="''${1:-}"
    if [ -z "$key" ]; then
      echo "set-secret: missing <KEY>. usage: set-secret <KEY> [VALUE]" >&2
      exit 1
    fi
    if ! printf '%s' "$key" | grep -qE '^[A-Za-z_][A-Za-z0-9_]*$'; then
      echo "set-secret: invalid KEY '$key' (must match [A-Za-z_][A-Za-z0-9_]*)" >&2
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

    # Register KEY in the in-Keychain index if not already there. SPACE-separated
    # (not newline): `security -w` returns any value containing a newline as HEX,
    # which would corrupt the index. KEYs match [A-Za-z0-9_]+ so they never
    # contain a space — the login loop splits on spaces via POSIX parameter
    # expansion (portable across zsh/bash).
    index="$("$security" find-generic-password -a "$account" -s "$index_service" -w "''${kc[@]}" 2>/dev/null || true)"
    case " $index " in
      *" $key "*) : ;; # already registered
      *)
        if [ -n "$index" ]; then index="$index $key"; else index="$key"; fi
        "$security" add-generic-password -U -a "$account" -s "$index_service" -w "$index" "''${kc[@]}"
        ;;
    esac

    # Verify the value round-trips back out of the Keychain, then show only the
    # first few characters as proof (never the whole secret).
    got="$("$security" find-generic-password -a "$account" -s "$key" -w "''${kc[@]}" 2>/dev/null || true)"
    if [ "$got" != "$value" ]; then
      echo "set-secret: WARNING — $key did not round-trip out of the Keychain." >&2
      exit 1
    fi
    echo "set-secret: stored $key in the login Keychain (value starts with ''${got:0:4}…)."
  '';
}
