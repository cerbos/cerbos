{
  description = "Tools for running the Cerbos E2E tests";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        # `helmfile apply` requires the `helm diff` plugin.
        helm = pkgs.wrapHelm pkgs.kubernetes-helm {
          plugins = [ pkgs.kubernetes-helmPlugins.helm-diff ];
        };
      in
      {
        devShells.default = pkgs.mkShell {
          packages = [
            pkgs.go_1_27
            pkgs.gotestsum
            pkgs.kind
            pkgs.kubectl
            helm
            pkgs.helmfile
            pkgs.stern
            pkgs.telepresence2
          ];
        };
      });
}
