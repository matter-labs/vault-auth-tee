{
  description = "vault auth plugin for remote attestation of TEEs";

  inputs = {
    nixsgx-flake.url = "github:matter-labs/nixsgx";
    nixpkgs.follows = "nixsgx-flake/nixpkgs";
    flake-utils.url = "github:numtide/flake-utils?tag=v1.0.0";
  };

  outputs = { self, nixpkgs, flake-utils, nixsgx-flake }:
    flake-utils.lib.eachSystem [ "x86_64-linux" ] (system:
      let
        pkgs = import nixpkgs {
          inherit system; overlays = [
          nixsgx-flake.overlays.default
          overlays
        ];
          config.allowUnfree = true;
        };
        vault-auth-tee = pkgs.callPackage ./packages/vault-auth-tee.nix { };
        container-vault-auth-tee = pkgs.callPackage ./packages/container-vault-auth-tee.nix { };
        overlays = final: prev: { vat = { inherit vault-auth-tee; }; };
      in
      {
        formatter = pkgs.nixpkgs-fmt;

        inherit overlays;

        packages = {
          inherit vault-auth-tee;
          inherit container-vault-auth-tee;
          default = vault-auth-tee;
        };

        devShells = {
          default = pkgs.mkShell {
            inputsFrom = [ vault-auth-tee ];
          };
        };
      });
}
