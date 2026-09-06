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
#
# PRIOR ART DECLINED — why this isn't just envchain. `pkgs.envchain` IS in this
# repo's pinned nixpkgs (pkgs/by-name/en/envchain/package.nix:41, "Set environment
# variables with macOS keychain or D-Bus secret service"), and it is the obvious
# off-the-shelf answer. It does not fit the requirement stated above, for reasons
# read off its own source (envchain.c:53-61 usage, execvp at :294):
#   * WRAPPER-SCOPED, not ambient. envchain's only exec form is
#     `envchain NAMESPACE CMD [ARG ...]` — it execs ONE child with the vars set.
#     Its usage lists set / exec / list / unset and no ambient or eval mode. The
#     requirement here is EVERY shell, including the non-interactive bash an agent
#     spawns per tool call, which nobody gets to wrap.
#   * No cross-shell load state. The readable-index sentinel below exists so a
#     LOCKED Keychain retries in a later shell instead of caching an empty load —
#     state that only makes sense for an ambient loader, so wrapping envchain in a
#     shell hook would still leave all of this to write.
#   * `maintainers = [ ]` in nixpkgs (package.nix:45), upstream pinned at v1.1.0.
# Also grepped the pinned home-manager for an upstream option: no `envchain`
# anywhere in home-manager/modules, and `programs.keychain` is a name lookalike —
# the funtoo ssh-agent/gpg-agent wrapper (modules/programs/keychain.nix:28, keys
# default `id_rsa`), unrelated to the macOS Keychain.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.programs.keychainSecrets;
  setSecret = pkgs.callPackage ../packages/set-secret.nix { };
  # The pasteboard half `secret copy` pipes to. Installed alongside the CLI so
  # it is usable on its own with any value on stdin, not only via the Keychain.
  pbConceal = pkgs.callPackage ../packages/pb-conceal.nix { };
  removeSecret = pkgs.callPackage ../packages/remove-secret.nix { set-secret = setSecret; };
  secretCmd = pkgs.callPackage ../packages/secret.nix {
    set-secret = setSecret;
    pb-conceal = pbConceal;
  };
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
          # Honour SET_SECRET_KEYCHAIN like `secret` and `set-secret` do. Without
          # this the loader was the ONE component that always read the login
          # keychain, so a test that sourced it silently operated on real
          # secrets while believing it was isolated — which is exactly how a
          # live value ends up echoed into a log. Not a privilege boundary:
          # anything able to set this variable can already read the environment
          # it would be loading into.
          __ss_kc=""
          if [ -n "''${SET_SECRET_KEYCHAIN:-}" ]; then __ss_kc="$SET_SECRET_KEYCHAIN"; fi
          # Capture the index read's exit code: rc != 0 means the index item is
          # UNREADABLE (Keychain locked, or nothing registered yet) — distinct from a
          # readable-but-empty index. Only a readable index sets the sentinel.
          __ss_index="$(/usr/bin/security find-generic-password -a "$__ss_account" -s __set_secret_index__ -w ''${__ss_kc:+"$__ss_kc"} 2>/dev/null)"
          __ss_rc=$?
          if [ "$__ss_rc" -ne 0 ]; then
            __ss_dbg "index unreadable (rc=$__ss_rc): Keychain locked or no secrets registered; NOT caching — a later shell will retry"
          else
            __ss_loaded=0
            __ss_failed=0
            __ss_skipped=0
            # Peel the SPACE-separated index one token at a time with POSIX parameter
            # expansion — identical in zsh and bash (a `for k in $index` would NOT
            # word-split in zsh). No subshell, so exports land in THIS shell.
            __ss_rest="$__ss_index"
            while [ -n "$__ss_rest" ]; do
              __ss_k="''${__ss_rest%% *}" # first token
              __ss_rest="''${__ss_rest#"$__ss_k"}" # drop it
              __ss_rest="''${__ss_rest# }" # trim one leading space
              [ -n "$__ss_k" ] || continue
              # Split ENV=SERVICE on the FIRST '=' — see THE INDEX GRAMMAR in
              # packages/set-secret.nix, which is the canonical definition. A
              # bare token (no '=') is the legacy self-binding form.
              case "$__ss_k" in
                *=*)
                  __ss_e="''${__ss_k%%=*}"
                  __ss_s="''${__ss_k#*=}"
                  ;;
                *)
                  __ss_e="$__ss_k"
                  __ss_s="$__ss_k"
                  ;;
              esac
              # No ENV half: stored deliberately WITHOUT an env binding, so it
              # must never become ambient. Read it on demand with `secret get`.
              if [ -z "$__ss_e" ]; then
                __ss_skipped=$((__ss_skipped + 1))
                __ss_dbg "not exported: $__ss_s (no env binding; on-demand only)"
                continue
              fi
              if __ss_v="$(/usr/bin/security find-generic-password -a "$__ss_account" -s "$__ss_s" -w ''${__ss_kc:+"$__ss_kc"} 2>/dev/null)"; then
                export "$__ss_e=$__ss_v"
                __ss_loaded=$((__ss_loaded + 1))
                __ss_dbg "loaded $__ss_s -> \$$__ss_e (len=''${#__ss_v})"
              else
                __ss_failed=$((__ss_failed + 1))
                __ss_dbg "MISSING $__ss_s (listed in index but not found in Keychain)"
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
            __ss_dbg "done: $__ss_loaded loaded, $__ss_skipped not-exported, $__ss_failed missing (sentinel set)"
            unset __ss_loaded __ss_failed __ss_skipped
          fi
          unset __ss_account __ss_kc __ss_index __ss_rc __ss_rest __ss_k __ss_v __ss_e __ss_s
          unset -f __ss_dbg 2>/dev/null || true
        fi

        # -- interactive helpers (defined always; touch the Keychain only if called) --
        # Resolve SERVICE -> its ENV binding via the index, then export (or, for
        # an unbound secret, do nothing — that is the point of leaving it
        # unbound). Shared by set-secret/adopt so one grammar reader serves both.
        # Prints the bound name on stdout so callers can unset it later.
        __secrets_bound_env() {
          __sbe_idx="$(/usr/bin/security find-generic-password -a "$(/usr/bin/id -un)" -s __set_secret_index__ -w ''${SET_SECRET_KEYCHAIN:+"$SET_SECRET_KEYCHAIN"} 2>/dev/null || true)"
          __sbe_rest="$__sbe_idx"
          while [ -n "$__sbe_rest" ]; do
            __sbe_t="''${__sbe_rest%% *}"
            __sbe_rest="''${__sbe_rest#"$__sbe_t"}"
            __sbe_rest="''${__sbe_rest# }"
            [ -n "$__sbe_t" ] || continue
            case "$__sbe_t" in
              *=*)
                __sbe_e="''${__sbe_t%%=*}"
                __sbe_s="''${__sbe_t#*=}"
                ;;
              *)
                __sbe_e="$__sbe_t"
                __sbe_s="$__sbe_t"
                ;;
            esac
            if [ "$__sbe_s" = "$1" ]; then
              printf '%s' "$__sbe_e"
              unset __sbe_idx __sbe_rest __sbe_t __sbe_e __sbe_s
              return 0
            fi
          done
          unset __sbe_idx __sbe_rest __sbe_t __sbe_e __sbe_s
          return 1
        }
        __secrets_export() {
          __se_env="$(__secrets_bound_env "$1" || true)"
          if [ -n "$__se_env" ]; then
            export "$__se_env=$(/usr/bin/security find-generic-password -a "$(/usr/bin/id -un)" -s "$1" -w ''${SET_SECRET_KEYCHAIN:+"$SET_SECRET_KEYCHAIN"} 2>/dev/null)"
          fi
          unset __se_env
        }
        # Strip leading `--env NAME` / `--no-export` flags and echo the SERVICE.
        __secrets_service_arg() {
          while [ "$#" -gt 0 ]; do
            case "$1" in
              --env)
                shift 2 || return 1
                ;;
              --no-export)
                shift
                ;;
              *)
                printf '%s' "$1"
                return 0
                ;;
            esac
          done
          return 1
        }
        # Persist to (or remove from) the Keychain, then apply the change to THIS
        # shell right away (a bare binary can't mutate its parent's env): an add
        # re-exports the value, a --remove unsets it here too.
        set-secret() {
          # Capture the binding BEFORE a removal — afterwards the index no longer
          # says which env var this secret was exported as.
          __ss_fn_pre=""
          case "''${1:-}" in
            --remove | -r) __ss_fn_pre="$(__secrets_bound_env "''${2:-}" || true)" ;;
          esac
          command set-secret "$@" || {
            unset __ss_fn_pre
            return 1
          }
          case "''${1:-}" in
            --remove | -r)
              [ -n "$__ss_fn_pre" ] && unset "$__ss_fn_pre" 2>/dev/null
              ;;
            *)
              __ss_fn_svc="$(__secrets_service_arg "$@" || true)"
              [ -n "$__ss_fn_svc" ] && __secrets_export "$__ss_fn_svc"
              unset __ss_fn_svc
              ;;
          esac
          unset __ss_fn_pre
          return 0
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
        # (no bare-KEY shorthand any more — printing is opt-in.)
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
              # A newly-adopted secret goes live in THIS shell too, like `secret set`
              # — but only if the index actually binds it to an env var.
              [ -n "''${1:-}" ] && __secrets_export "$1"
              ;;
            load)
              unset __SECRETS_KEYCHAIN_LOADED
              [ -r "${loaderPath}" ] && . "${loaderPath}" || true
              ;;
            bind | unbind)
              # MUST be listed explicitly. Anything not matched here falls to the
              # `*)` arm below and is treated as a KEY to get — so a missing verb
              # becomes `secret get unbind`, which exits 44 (security(1): item not
              # found) and reads as a bug in the binary rather than a gap here.
              # Capture the binding BEFORE the call; afterwards the index no
              # longer says what it was.
              __ss_verb="$1"
              __ss_pre="$(__secrets_bound_env "''${2:-}" || true)"
              command secret "$@" || {
                unset __ss_verb __ss_pre
                return 1
              }
              case "$__ss_verb" in
                unbind) [ -n "$__ss_pre" ] && unset "$__ss_pre" 2>/dev/null ;;
                bind) __secrets_export "''${2:-}" ;;
              esac
              unset __ss_verb __ss_pre
              ;;
            reveal | get | copy | clip | -c | exec | fp | fingerprint | ls | list | -h | --help | "")
              # Every verb the binary knows MUST be listed. Anything missing
              # falls to `*)` below, which used to mean "treat it as a KEY and
              # print it" — a missing verb silently became a disclosure.
              command secret "$@"
              ;;
            *)
              # No longer "print it". The binary refuses unknown words and
              # names the alternatives; just pass it through and let it say so.
              command secret "$@"
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
      pbConceal
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
