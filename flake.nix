{
  description = "vault auth plugin for remote attestation of TEEs";

  inputs = {
    nixsgx-flake.url = "github:matter-labs/nixsgx";
    nixpkgs.follows = "nixsgx-flake/nixpkgs";
    snowfall-lib.follows = "nixsgx-flake/snowfall-lib";
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
