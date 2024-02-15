{ lib
, pkgs
, ...
}:
pkgs.mkShell {
  inputsFrom = [ pkgs.vat.vault-auth-tee ];
}
