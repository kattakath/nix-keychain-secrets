# nix-keychain-secrets

[![CI](https://github.com/ismailkattakath/nix-keychain-secrets/actions/workflows/ci.yml/badge.svg)](https://github.com/ismailkattakath/nix-keychain-secrets/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![Built with Nix](https://img.shields.io/badge/built%20with-Nix-5277C3.svg?logo=nixos&logoColor=white)](https://nixos.org)

**Your API keys in every shell — from the macOS login Keychain, not a dotfile.**

A tiny noun-verb CLI (`secret set/get/rm/ls`) backed by the macOS login Keychain,
plus a home-manager loader that exports your registered secrets into **every**
shell — login, non-login, interactive or not, **including the bash an AI coding
agent spawns for its tools**. Nothing secret (not even the key *names*) is ever
written to the Nix store or to git. No age/GPG key, no `.sops.yaml`, no
subscription.

> Status: early / beta. macOS-only. Used daily in a personal nix-darwin setup.

## Why this exists

The usual "secrets in my shell" tricks break for **non-login shells**: a plain
`export FOO=…` in `.zshrc`/`.bash_profile` never reaches `zsh -c` from a
Makefile, a VS Code task, a launchd job, or **an AI agent's Bash tool** — so those
processes silently get *zero* secrets. This wires all four shell entry points
(`.zshenv`, `.bash_profile`, `.bashrc`, and non-interactive bash's only hook,
`$BASH_ENV`) to a single loader that reads the Keychain **once per process tree**
(a `__SECRETS_KEYCHAIN_LOADED` sentinel; ~470 ms paid once at the root) and
exports each value to every descendant.

## Prerequisites

- **macOS** — the store is the macOS login Keychain (`/usr/bin/security`). The module is a clean no-op on Linux.
- **Nix** with flakes enabled (`experimental-features = nix-command flakes`).
- **[home-manager](https://github.com/nix-community/home-manager)** — the module plugs into `programs.zsh`/`programs.bash`, so enable those for full every-shell coverage.

## Install (flake + home-manager)

```nix
{
  inputs.keychain-secrets.url = "github:ismailkattakath/nix-keychain-secrets";

  # in your home-manager modules:
  #   keychain-secrets.homeManagerModules.default
  # then:
  #   programs.keychainSecrets.enable = true;   # macOS-only; no-op on Linux
}
```

Needs `programs.zsh.enable` / `programs.bash.enable` for the respective shell
coverage. The three CLIs are added to `home.packages` automatically.

## Usage

```sh
secret set OPENAI_API_KEY          # hidden prompt (or: secret set KEY value)
secret get OPENAI_API_KEY          # print one value on demand
secret OPENAI_API_KEY              # shorthand for `secret get`
secret ls                          # list registered names (never values)
secret rm  OPENAI_API_KEY          # delete + unregister
secret adopt SOME_KEY              # register an item added outside the CLI
secret load                        # re-load into the CURRENT shell
```
`set-secret` / `remove-secret` remain as back-compat aliases. `set`/`rm`/`load`
also update your *current* shell (a bare binary can't touch its parent's env, so
those run as a shell function from the loader).

## How it works

- **Store:** macOS login Keychain (`security` generic passwords), account = `id -un`.
- **Index:** one Keychain item (`__set_secret_index__`) holds the space-separated
  list of managed key names — so `ls`/`load` know what to export. The index is
  **single-writer**: only `secret set`/`rm` maintain it, so an item added
  out-of-band (Keychain Access GUI, raw `security add-generic-password`) is
  found by `secret get` (which warns) but is invisible to `ls` and the loader
  until you run `secret adopt <KEY>` — which registers it and, as a bonus,
  rewrites the item so the CLI is on its ACL (no more per-read auth prompts).
- **Loader:** `~/.config/secrets/loader.sh`, sourced by every shell; loads once
  per tree via an exported sentinel; `SECRETS_DEBUG=1` reports names/lengths/exit
  codes (never values).
- **Nothing on disk/git:** only the loader *script* and the key *names* index live
  outside the Keychain; values never leave it except into process memory.

## ⚠️ Security model — read this

This deliberately makes your secrets **ambient in every shell**. That means **any
process in the tree — including a compromised dependency or the AI agent
itself — can read them via `env`.** That is the correct trade-off for *laptop /
dev API keys* whose whole point is to be present for your tools. It is **not** a
model for high-value secrets, servers, or shared machines.

- Values rest only in the Keychain (encrypted at rest) and in process memory.
- First `security` read may trigger a Keychain ACL prompt — allow it once.
- Onboarding a new Mac still needs `secret set …` (or a Keychain restore); a
  rebuild provisions the *loader*, not the secret *values*.

## When to use something else

| You want… | Use |
|---|---|
| Git-encrypted, multi-machine, or server secrets | [sops-nix](https://github.com/Mic92/sops-nix) / [agenix](https://github.com/ryantm/agenix) |
| Just-in-time, short-lived, team-shared secrets | [1Password CLI](https://developer.1password.com/docs/cli/) (`op run`) |
| Secrets only inside `nix develop` | [agenix-shell](https://github.com/aciceri/agenix-shell) |
| Per-project (not global) env | [direnv](https://direnv.net/) |
| **Global laptop API keys in *every* shell, incl. agent bash, no crypto ceremony** | **this** |

## Used in production

See it wired into a real fleet in **[kattakath/nix-config](https://github.com/kattakath/nix-config)** — [`modules/shared/home.nix`](https://github.com/kattakath/nix-config/blob/main/modules/shared/home.nix) imports `homeManagerModules.default` and sets `programs.keychainSecrets.enable = true` on the macOS host.

## License

MIT © Ismail Kattakath
