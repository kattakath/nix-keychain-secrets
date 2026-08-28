{
  description = "macOS login-Keychain secret store as a noun-verb CLI (secret set/get/rm/ls) + a home-manager loader that exports your secrets into EVERY shell, including non-login / AI-agent bash via $BASH_ENV. Nothing in the Nix store or git.";

  inputs = {
    flake-parts.url = "github:hercules-ci/flake-parts";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    home-manager.url = "github:nix-community/home-manager";
    home-manager.inputs.nixpkgs.follows = "nixpkgs";
  };

  nixConfig = {
    extra-substituters = [ "https://kattakath.cachix.org" ];
    extra-trusted-public-keys = [
      "kattakath.cachix.org-1:y/w6wnb4ZArdlbfWJ82c81uCXeYgG/sGDUYCszavmEw="
    ];
  };

  outputs =
    inputs@{
      self,
      flake-parts,
      home-manager,
      ...
    }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      # formatter runs on all 3; the CLI/module itself is macOS-only (every app
      # shells out to /usr/bin/security), gated per-system below.
      systems = [
        "aarch64-darwin"
        "x86_64-linux"
        "aarch64-linux"
      ];

      flake = {
        # The reusable home-manager module (system-agnostic; no-op off macOS).
        homeManagerModules.keychainSecrets = ./modules/keychain-secrets.nix;
        homeManagerModules.default = self.homeManagerModules.keychainSecrets;
      };

      perSystem =
        { pkgs, system, ... }:
        {
          formatter = pkgs.nixfmt-rfc-style;

          # The CLIs, also runnable directly (macOS-only).
          packages = pkgs.lib.optionalAttrs (system == "aarch64-darwin") (
            let
              set-secret = pkgs.callPackage ./packages/set-secret.nix { };
            in
            {
              inherit set-secret;
              secret = pkgs.callPackage ./packages/secret.nix { inherit set-secret; };
              remove-secret = pkgs.callPackage ./packages/remove-secret.nix { inherit set-secret; };
              default = pkgs.callPackage ./packages/secret.nix { inherit set-secret; };
            }
          );

          apps = pkgs.lib.optionalAttrs (system == "aarch64-darwin") (
            pkgs.lib.genAttrs
              [
                "secret"
                "set-secret"
                "remove-secret"
              ]
              (name: {
                type = "app";
                program = "${self.packages.${system}.${name}}/bin/${name}";
              })
            // {
              default = {
                type = "app";
                program = "${self.packages.${system}.secret}/bin/secret";
              };
            }
          );

          # Eval check: the module wires BASH_ENV + emits a loader carrying the
          # one-time-per-tree sentinel (macOS home-manager config).
          checks = pkgs.lib.optionalAttrs (system == "aarch64-darwin") (
            let
              hm = home-manager.lib.homeManagerConfiguration {
                inherit pkgs;
                modules = [
                  self.homeManagerModules.default
                  {
                    home.username = "tester";
                    home.homeDirectory = "/Users/tester";
                    home.stateVersion = "24.05";
                    programs.keychainSecrets.enable = true;
                  }
                ];
              };
              loader = hm.config.home.file.".config/secrets/loader.sh".source;
            in
            {
              module-evaluates = pkgs.runCommand "keychain-secrets-eval" { } ''
                test "${hm.config.home.sessionVariables.BASH_ENV}" = "/Users/tester/.config/secrets/loader.sh"
                grep -q "__SECRETS_KEYCHAIN_LOADED" ${loader}
                grep -q "secret()" ${loader}
                echo ok > "$out"
              '';
              inherit (self.packages.${system}) secret set-secret remove-secret;
            }
          );
        };
    };
}
