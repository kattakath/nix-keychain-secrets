#!/usr/bin/env bash
# Functional test for THE INDEX GRAMMAR (packages/set-secret.nix).
#
# NOT a `nix flake check` derivation, and it cannot become one: the Nix build
# sandbox has no login session and no Keychain, so every assertion here would
# fail there for reasons unrelated to the code. Run it by hand, or from a CI
# step that executes outside the sandbox on a real macOS session.
#
#   nix develop -c ./tests/grammar.sh
#   LOADER=/nix/store/…-hm_.configsecretsloader.sh ./tests/grammar.sh
#
# Every Keychain call is redirected to a THROWAWAY keychain via
# SET_SECRET_KEYCHAIN, which all three components honour. The login keychain is
# never read or written.
#
# ONE RULE, learned the expensive way: never echo a value that could have come
# from the real store. Assert on booleans and lengths. If isolation ever breaks,
# a boolean assertion fails loudly; an echoed value becomes a disclosure in
# whatever log is capturing the run.
set -uo pipefail

KC="$HOME/Library/Keychains/zz-kcs-test.keychain-db"
# The loader under test. Defaults to the ACTIVATED one, which is a Nix store
# symlink and therefore lags an unactivated working tree — point LOADER at a
# freshly built hm_.configsecretsloader.sh to test uncommitted changes.
LOADER="${LOADER:-$HOME/.config/secrets/loader.sh}"
export SET_SECRET_KEYCHAIN="$KC"

# Drop the shell FUNCTIONS the loader defines. $BASH_ENV points every
# non-interactive bash at the ACTIVATED loader, so this script starts with
# `secret`/`set-secret` already shadowed by the wrappers from whatever
# generation is live — not the binaries under test. A verb the old wrapper
# does not know (`unbind`) fell through its `*)` arm to `secret get unbind`,
# which exits 44 (security(1): "item could not be found") and looks like a bug
# in the new code rather than the wrong code being run.
unset -f secret set-secret remove-secret 2>/dev/null || true

command -v set-secret >/dev/null || { echo "set-secret not on PATH (nix develop?)" >&2; exit 1; }

security delete-keychain "$KC" >/dev/null 2>&1 || true
security create-keychain -p testpw "$KC"
security unlock-keychain -p testpw "$KC"
trap 'security delete-keychain "$KC" >/dev/null 2>&1 || true' EXIT

pass=0
fail=0
ck() { # ck <label> <expected> <actual>
  if [ "$2" = "$3" ]; then
    printf '  ok   %s\n' "$1"
    pass=$((pass + 1))
  else
    printf '  FAIL %s\n       want: %s\n       got:  %s\n' "$1" "$2" "$3"
    fail=$((fail + 1))
  fi
}
probe() { env -i HOME="$HOME" SET_SECRET_KEYCHAIN="$KC" bash -c "source '$LOADER' 2>/dev/null
$1" 2>/dev/null; }

echo "== 1. legacy flat name still self-binds =="
set-secret OPENAI_API_KEY sk-legacy >/dev/null
ck "get by flat name" "sk-legacy" "$(secret get OPENAI_API_KEY)"
ck "index token is ENV=SERVICE" "OPENAI_API_KEY=OPENAI_API_KEY" \
  "$(security find-generic-password -a "$(id -un)" -s __set_secret_index__ -w "$KC")"

echo "== 2. tool:host:kind with an explicit --env =="
set-secret --env GITLAB_TOKEN glab:gitlab.com:token glpat-aaa >/dev/null
ck "get by SERVICE" "glpat-aaa" "$(secret get glab:gitlab.com:token)"
ck "get by ENV (back-compat after rename)" "glpat-aaa" "$(secret get GITLAB_TOKEN)"

echo "== 3. same host, second credential, different privilege =="
set-secret --no-export vast:gitlab.com:read_repository glpat-ro >/dev/null
ck "second gitlab token coexists" "glpat-ro" "$(secret get vast:gitlab.com:read_repository)"
ck "first one is untouched" "glpat-aaa" "$(secret get glab:gitlab.com:token)"

echo "== 4. ls / ls --long =="
ck "ls prints SERVICE ids" \
  "OPENAI_API_KEY glab:gitlab.com:token vast:gitlab.com:read_repository" \
  "$(secret ls | tr '\n' ' ' | sed 's/ $//')"
secret ls --long

echo "== 5. THE POINT: an unbound secret is never ambient =="
ck "loader honours SET_SECRET_KEYCHAIN (isolation holds)" "yes" \
  "$(probe '[ "${GITLAB_TOKEN:-}" = glpat-aaa ] && echo yes || echo no')"
ck "bound secret IS exported" "set" \
  "$(probe '[ -n "${GITLAB_TOKEN:-}" ] && echo set || echo unset')"
ck "UNBOUND secret is NOT exported under any name" "0" \
  "$(probe 'env | grep -c glpat-ro || true')"

echo "== 6. re-set can CHANGE the binding =="
set-secret --no-export glab:gitlab.com:token glpat-aaa >/dev/null
ck "binding removed, value kept" "glpat-aaa" "$(secret get glab:gitlab.com:token)"
ck "ENV lookup no longer resolves" "" "$(secret get GITLAB_TOKEN 2>/dev/null)"

echo "== 6b. bind/unbind change the binding WITHOUT the value =="
# Asserts on the INDEX, not via the loader: test 5 already proves the loader
# honours the binding, and the index is the thing bind/unbind actually edit.
idx() { security find-generic-password -a "$(id -un)" -s __set_secret_index__ -w "$KC"; }
set-secret --env TMP_TOKEN app:example.com:api ex-val >/dev/null
case " $(idx) " in *" TMP_TOKEN=app:example.com:api "*) r=yes ;; *) r=no ;; esac
ck "bound: index carries ENV=SERVICE" "yes" "$r"
secret unbind app:example.com:api >/dev/null
ck "unbind: value survives untouched" "ex-val" "$(secret get app:example.com:api)"
case " $(idx) " in *" =app:example.com:api "*) r=yes ;; *) r=no ;; esac
ck "unbind: index token has no ENV half" "yes" "$r"
secret bind app:example.com:api TMP_TOKEN >/dev/null
case " $(idx) " in *" TMP_TOKEN=app:example.com:api "*) r=yes ;; *) r=no ;; esac
ck "re-bind restores the ENV half" "yes" "$r"
secret unbind not-registered:x:y >/dev/null 2>&1
ck "unbind on an unregistered SERVICE exits 1" "1" "$?"
# The SHELL FUNCTION must pass every verb through. A verb missing from its
# case arm falls to `*)` -> `secret get <verb>` -> exit 44, which looks like a
# binary bug. Shipped exactly that for bind/unbind once; assert it here.
fnwrap="$(sed -n '/^ *secret() {/,/^ *}$/p' "$LOADER")"
for v in set get rm ls adopt load bind unbind; do
  case "$fnwrap" in
    *"$v"*) r=yes ;;
    *) r=no ;;
  esac
  ck "shell function handles '$v'" "yes" "$r"
done
set-secret --remove app:example.com:api >/dev/null

echo "== 7. remove by SERVICE =="
set-secret --remove vast:gitlab.com:read_repository >/dev/null
ck "gone from index" "OPENAI_API_KEY glab:gitlab.com:token" \
  "$(secret ls | tr '\n' ' ' | sed 's/ $//')"
ck "item deleted" "" "$(secret get vast:gitlab.com:read_repository 2>/dev/null)"

echo "== 8. invalid names rejected =="
set-secret --env 'bad-env' svc:x:y v >/dev/null 2>&1
ck "bad ENV rejected" "1" "$?"
set-secret 'has space' v >/dev/null 2>&1
ck "bad SERVICE rejected" "1" "$?"

printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
