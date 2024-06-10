{ lib
, pkgs
, ...
}:

pkgs.buildGoModule {
  buildInputs = with pkgs; [
    nixsgx.sgx-sdk
    nixsgx.sgx-dcap
    nixsgx.sgx-dcap.quote_verify
  ];

  outputs = [ "out" "sha" ];

  name = "vault-auth-tee";
  src = with lib.fileset; toSource {
    root = ./..;
    fileset = unions [
      ../go.mod
      ../go.sum
      ../cmd
      ../test-fixtures
      (fileFilter (file: file.hasExt "go") ./..)
    ];
  };

  postFixup = ''
    mkdir -p $sha/share
    sha256sum $out/bin/vault-auth-tee | (read a _; echo $a) > $sha/share/vault-auth-tee.sha256
  '';

  vendorHash = "sha256-XbzUzR5YAxMmDvC9KStqT97v5j6Md7oL2BtkM9N5XTc=";
}
