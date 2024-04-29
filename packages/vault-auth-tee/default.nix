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
    root = ./../..;
    fileset = unions [
      ../../go.mod
      ../../go.sum
      ../../cmd
      ../../test-fixtures
      (fileFilter (file: file.hasExt "go") ./../..)
    ];
  };

  postFixup = ''
    mkdir -p $sha/share
    sha256sum $out/bin/vault-auth-tee | (read a _; echo $a) > $sha/share/vault-auth-tee.sha256
  '';

  vendorHash = "sha256-RmOyKVU+WOFUaC9nLsr0l+BnGpt0nEes3Su4IY0mOk0=";
}
