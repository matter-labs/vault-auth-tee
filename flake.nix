{
  description = "vault auth plugin for remote attestation of TEEs";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-23.11";

    nixsgx-flake = {
      url = "github:matter-labs/nixsgx";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    snowfall-lib = {
      url = "github:snowfallorg/lib?rev=92803a029b5314d4436a8d9311d8707b71d9f0b6";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = inputs:
    inputs.snowfall-lib.mkFlake {
      inherit inputs;
      src = ./.;

      package-namespace = "vat";

      overlays = with inputs; [
        nixsgx-flake.overlays.default
      ];

      alias = {
        packages = {
          default = "vault-auth-tee";
        };
        shells = {
          default = "vault-auth-tee";
        };
      };

      outputs-builder = channels: {
        formatter = channels.nixpkgs.nixpkgs-fmt;
      };
    };
}
