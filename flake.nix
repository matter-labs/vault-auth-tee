{
  description = "vault auth plugin for remote attestation of TEEs";

  inputs = {
    # for libsgx-dcap-quote-verify
    nixpkgs.url = "github:nixos/nixpkgs/nixos-23.05";
    mynixpkgs.url =
      "github:haraldh/nixpkgs/intel-dcap-openssl";
    gitignore = {
      url = "github:hercules-ci/gitignore.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, gitignore, mynixpkgs, ... }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
      mypkgs = import mynixpkgs { inherit system; };
      bin = pkgs.buildGoModule {
        buildInputs = with mypkgs; [ sgx-sdk libsgx-dcap-quote-verify ];

        CGO_CFLAGS =
          "-I${mypkgs.libsgx-dcap-quote-verify.dev}/include -I${mypkgs.sgx-sdk}/include";
        LDFLAGS = "-L${mypkgs.libsgx-dcap-quote-verify.dev}/lib";

        name = "vault-auth-tee";
        src = gitignore.lib.gitignoreSource ./.;
        vendorSha256 = "sha256-aRflg1OJKPXJifDoitRLT+MQLVpRH4NzsHb+OsT0Iqw=";
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
