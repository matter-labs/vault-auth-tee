{
  description = "vault auth plugin for remote attestation of TEEs";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-23.11";

    nix-filter.url = "github:numtide/nix-filter";

    nixsgx-flake = {
      url = "github:matter-labs/nixsgx";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, nixsgx-flake, nix-filter, ... }:
    let
      system = "x86_64-linux";
      filter = nix-filter.lib;
      pkgs = import nixpkgs { inherit system; overlays = [ nixsgx-flake.overlays.default ]; };
      bin = pkgs.buildGoModule {
        buildInputs = with pkgs; [
          nixsgx.sgx-sdk
          nixsgx.sgx-dcap
          nixsgx.sgx-dcap.quote_verify
        ];

        name = "vault-auth-tee";
        src = filter {
          root = ./.;
          include = [
            ./go.mod
            ./go.sum
            "cmd"
            "test-fixtures"
            (filter.matchExt "go")
          ];
        };

        vendorHash = "sha256-t59C0yzJzFAXNXYOFbta2g5CYlkfvlukq42cxCwLaGY=";
      };

      dockerImage = pkgs.dockerTools.buildLayeredImage {
        name = "vault-auth-tee";
        tag = "test";

        config.Entrypoint = [ "/bin/sh" ];

        contents = pkgs.buildEnv {
          name = "image-root";

          paths = with pkgs.dockerTools; [
            bin
            pkgs.vault
            usrBinEnv
            binSh
            caCertificates
            fakeNss
          ];
          pathsToLink = [ "/bin" "/etc" ];
        };
      };
    in
    with pkgs; {
      formatter.x86_64-linux = nixpkgs.legacyPackages.x86_64-linux.nixpkgs-fmt;
      packages.x86_64-linux = {
        inherit bin dockerImage;
        default = bin;
      };
      devShells.x86_64-linux.default = mkShell {
        inputsFrom = [ bin ];
        nativeBuildInputs = with pkgs; [ dive go_1_21 ];
      };
    };
}
