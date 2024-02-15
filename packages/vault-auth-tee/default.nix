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

  vendorHash = "sha256-t59C0yzJzFAXNXYOFbta2g5CYlkfvlukq42cxCwLaGY=";
}
