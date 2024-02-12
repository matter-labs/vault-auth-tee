{
  description = "vault auth plugin for remote attestation of TEEs";

  inputs = {
    # for libsgx-dcap-quote-verify
    nixpkgs.url = "github:nixos/nixpkgs/nixos-23.11";

    nixsgx-flake = {
      url = "github:matter-labs/nixsgx";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    gitignore = {
      url = "github:hercules-ci/gitignore.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, gitignore, nixsgx-flake, ... }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; overlays = [ nixsgx-flake.overlays.default ]; };
      bin = pkgs.buildGoModule {
          buildInputs = with pkgs; [
            nixsgx.sgx-sdk
            nixsgx.sgx-dcap
            nixsgx.sgx-dcap.quote_verify
          ];

        CGO_CFLAGS =
          "-I${pkgs.nixsgx.sgx-dcap}/include -I${pkgs.nixsgx.sgx-sdk}/include";
        LDFLAGS = "-L${pkgs.nixsgx.sgx-dcap}/lib";

        name = "vault-auth-tee";
        src = gitignore.lib.gitignoreSource ./.;
        vendorHash = "sha256-lhc4Fs+jGVYnd3vUWWXpebuBsPz6vbr1bCGwdyIPeKU=";
      };
      dockerImage = pkgs.dockerTools.buildImage {
        name = "vault-auth-tee";
        tag = "latest";
        copyToRoot = [
          bin
          # pkgs.vault
        ];
        #config = { Cmd = [ "${bin}/bin/vault" ]; };
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
        buildInputs = with pkgs; [ dive go_1_19 gotools mypkgs.sgx-sdk mypkgs.libsgx-dcap-quote-verify ];
      };
    };
}
