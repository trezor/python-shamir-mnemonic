{ pkgs ? import ./nixpkgs.nix {} }:

with pkgs;

let
in
{
  py314 = stdenv.mkDerivation rec {
    name = "python314-with-poetry";

    buildInputs = [
      cacert
      git
      gnumake
      openssh
      python314
      poetry
    ];
  };

  py313 = stdenv.mkDerivation rec {
    name = "python313-with-poetry";

    buildInputs = [
      cacert
      git
      gnumake
      openssh
      python313
      poetry
    ];
  };

  py312 = stdenv.mkDerivation rec {
    name = "python312-with-poetry";

    buildInputs = [
      cacert
      git
      gnumake
      openssh
      python312
      poetry
    ];
  };
 
  py311 = stdenv.mkDerivation rec {
    name = "python311-with-poetry";

    buildInputs = [
      cacert
      git
      gnumake
      openssh
      python311
      poetry
    ];
  };

  py310 = stdenv.mkDerivation rec {
    name = "python310-with-poetry";

    buildInputs = [
      cacert
      git
      gnumake
      openssh
      python310
      poetry
    ];
  };
}
