# home-manager module: programs.keychainSecrets
#
# A macOS login-Keychain secret store exposed as a noun-verb CLI plus a loader
# that exports your registered secrets into EVERY shell — login, non-login,
# interactive or not (including the bash an AI coding agent spawns for its tools).
# Nothing secret (not even the key NAMES) is written to the Nix store or to git.
#
# macOS-ONLY: the config is gated on stdenv.isDarwin, so enabling it on a Linux
# host is a clean no-op (safe for mixed nix-darwin + NixOS fleets).
#
# SECURITY MODEL — read this before enabling: this deliberately makes secrets
# AMBIENT in every shell, so any process in the tree (including an AI agent) can
# read them via `env`. That's the point for laptop/dev API keys, and the wrong
# model for high-value secrets — use sops-nix/agenix/1Password for those.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.programs.keychainSecrets;
  setSecret = pkgs.callPackage ../packages/set-secret.nix { };
  removeSecret = pkgs.callPackage ../packages/remove-secret.nix { set-secret = setSecret; };
  secretCmd = pkgs.callPackage ../packages/secret.nix { set-secret = setSecret; };
  loaderPath = "${config.home.homeDirectory}/${cfg.loaderRelPath}";

  # The loader.sh body: a one-time-per-process-tree Keychain load + the
  # set-secret/remove-secret/secret shell functions (which also mutate the
  # current shell, something a bare binary cannot do).
  loaderBody = ''
        # -- one-time-per-tree Keychain load ------------------------------------
        if [ -z "''${__SECRETS_KEYCHAIN_LOADED:-}" ]; then
          __ss_dbg() {
            if [ -n "''${SECRETS_DEBUG:-}" ]; then printf 'secrets: %s
    ' "$1" >&2; fi
            return 0
          }
          __ss_account="$(/usr/bin/id -un)"
          # Capture the index read's exit code: rc != 0 means the index item is
          # UNREADABLE (Keychain locked, or nothing registered yet) — distinct from a
          # readable-but-empty index. Only a readable index sets the sentinel.
          __ss_index="$(/usr/bin/security find-generic-password -a "$__ss_account" -s __set_secret_index__ -w 2>/dev/null)"
          __ss_rc=$?
          if [ "$__ss_rc" -ne 0 ]; then
            __ss_dbg "index unreadable (rc=$__ss_rc): Keychain locked or no secrets registered; NOT caching — a later shell will retry"
          else
            __ss_loaded=0
            __ss_failed=0
            # Peel the SPACE-separated index one token at a time with POSIX parameter
            # expansion — identical in zsh and bash (a `for k in $index` would NOT
            # word-split in zsh). No subshell, so exports land in THIS shell.
            __ss_rest="$__ss_index"
            while [ -n "$__ss_rest" ]; do
              __ss_k="''${__ss_rest%% *}" # first token
              __ss_rest="''${__ss_rest#"$__ss_k"}" # drop it
              __ss_rest="''${__ss_rest# }" # trim one leading space
              [ -n "$__ss_k" ] || continue
              if __ss_v="$(/usr/bin/security find-generic-password -a "$__ss_account" -s "$__ss_k" -w 2>/dev/null)"; then
                export "$__ss_k=$__ss_v"
                __ss_loaded=$((__ss_loaded + 1))
                __ss_dbg "loaded $__ss_k (len=''${#__ss_v})"
              else
                __ss_failed=$((__ss_failed + 1))
                __ss_dbg "MISSING $__ss_k (listed in index but not found in Keychain)"
              fi
            done
            # Sentinel = "index consulted, every listed secret attempted". Set on a
            # readable index even if empty (nothing to load is a valid loaded state)
            # and EXPORTED so descendants skip this whole block.
            #
            # CAVEAT (by design): the sentinel is per-secret-set, not per-secret. If a
            # child shell drops a single var (`unset FOO`, or is spawned with
            # `env -u FOO`), this loader will NOT restore it — the inherited sentinel
            # short-circuits the whole block. To get FOO back, either open a shell
            # without the sentinel, or force a reload in place:
            #   unset __SECRETS_KEYCHAIN_LOADED && source ~/.config/secrets/loader.sh
            # (a fresh login shell / new process tree always reloads from scratch).
            export __SECRETS_KEYCHAIN_LOADED=1
            # Non-interactive bash's only startup hook is $BASH_ENV — propagate it so
            # bash descendants of this (possibly zsh) shell also self-load / short-circuit.
            export BASH_ENV="${loaderPath}"
            __ss_dbg "done: $__ss_loaded loaded, $__ss_failed missing (sentinel set)"
            unset __ss_loaded __ss_failed
          fi
          unset __ss_account __ss_index __ss_rc __ss_rest __ss_k __ss_v
          unset -f __ss_dbg 2>/dev/null || true
        fi

        # -- interactive helpers (defined always; touch the Keychain only if called) --
        # Persist to (or remove from) the Keychain, then apply the change to THIS
        # shell right away (a bare binary can't mutate its parent's env): an add
        # re-exports the value, a --remove unsets it here too.
        set-secret() {
          command set-secret "$@" || return
          case "''${1:-}" in
            --remove | -r)
              case "''${2:-}" in
                [A-Za-z_]*) unset "$2" 2>/dev/null || true ;;
              esac
              ;;
            [A-Za-z_]*)
              export "$1=$(/usr/bin/security find-generic-password -a "$(/usr/bin/id -un)" -s "$1" -w 2>/dev/null)"
              ;;
          esac
        }
        # Inverse of set-secret: delete + unregister, and unset it from THIS shell.
        # Delegates to the set-secret function so the --remove/unset path is shared.
        remove-secret() {
          set-secret --remove "$@"
        }
        # Primary noun-verb interface: `secret <set|get|rm|ls|adopt|load|KEY>`. The
        # mutating verbs update THIS shell (set/adopt→export, rm→unset) by delegating
        # to the set-secret/remove-secret functions above (adopt runs in the binary,
        # then exports here); `load` re-reads the whole store into the current shell
        # (the fix for a manually-unset var — see the sentinel caveat above);
        # get/ls/help fall through to the `secret` binary. A bare `secret KEY` is
        # shorthand for `secret get KEY`.
        secret() {
          case "''${1:-}" in
            set)
              shift
              set-secret "$@"
              ;;
            rm | remove | unset)
              shift
              remove-secret "$@"
              ;;
            adopt)
              shift
              command secret adopt "$@" || return
              # A newly-adopted secret goes live in THIS shell too, like `secret set`.
              case "''${1:-}" in
                [A-Za-z_]*)
                  export "$1=$(/usr/bin/security find-generic-password -a "$(/usr/bin/id -un)" -s "$1" -w 2>/dev/null)"
                  ;;
              esac
              ;;
            load)
              unset __SECRETS_KEYCHAIN_LOADED
              [ -r "${loaderPath}" ] && . "${loaderPath}" || true
              ;;
            get | ls | list | -h | --help | "")
              command secret "$@"
              ;;
            *)
              command secret get "$1"
              ;;
          esac
        }
  '';

  sourceLoader = ''[ -r "${loaderPath}" ] && . "${loaderPath}" || true'';
in
{
  options.programs.keychainSecrets = {
    enable = lib.mkEnableOption "macOS login-Keychain secret store + every-shell loader (secret/set-secret/remove-secret)";
    loaderRelPath = lib.mkOption {
      type = lib.types.str;
      default = ".config/secrets/loader.sh";
      description = "Path of the generated loader script, relative to the home directory.";
    };
  };

  # macOS-only: a clean no-op on Linux hosts.
  config = lib.mkIf (cfg.enable && pkgs.stdenv.isDarwin) {
    home.packages = [
      secretCmd
      setSecret
      removeSecret
    ];

    # The loader file (a REAL file so $BASH_ENV can name it).
    home.file.${cfg.loaderRelPath}.text = loaderBody;

    # Non-interactive bash's only startup hook.
    home.sessionVariables.BASH_ENV = loaderPath;

    # Per-shell source lines. Harmless if a given shell module is not enabled
    # (the option value is just ignored). zsh via .zshenv (EVERY zsh); bash via
    # .bash_profile (login) + .bashrc (interactive non-login); non-interactive
    # non-login bash via $BASH_ENV above.
    programs.zsh.envExtra = lib.mkAfter sourceLoader;
    programs.bash.profileExtra = lib.mkAfter sourceLoader;
    programs.bash.bashrcExtra = lib.mkAfter sourceLoader;
  };
}
