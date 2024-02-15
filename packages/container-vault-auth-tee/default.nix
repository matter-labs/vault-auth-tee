{ pkgs
, vat
, vault
, ...
}:
pkgs.dockerTools.buildLayeredImage {
  name = "vault-auth-tee";
  tag = "test";

  config.Entrypoint = [ "/bin/sh" ];

  contents = pkgs.buildEnv {
    name = "image-root";

    paths = with pkgs.dockerTools; [
      vat.vault-auth-tee
      vault
      usrBinEnv
      binSh
      caCertificates
      fakeNss
    ];
    pathsToLink = [ "/bin" "/etc" ];
  };
}
