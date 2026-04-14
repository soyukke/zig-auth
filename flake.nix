{
  description = "Zig authentication system on Cloudflare Workers";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
    zig-overlay.url = "github:mitchellh/zig-overlay";
    zig-overlay.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, zig-overlay }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f system);
    in
    {
      devShells = forAllSystems (system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ zig-overlay.overlays.default ];
          };
          zig = pkgs.zigpkgs."0.15.2";
        in
        {
          default = pkgs.mkShell {
            buildInputs = [
              zig
              pkgs.zls
              pkgs.nodejs_20
              pkgs.just
              pkgs.gitleaks
            ];
            shellHook = ''
              export ZIG_LOCAL_CACHE_DIR="$PWD/.zig-cache"
              export ZIG_GLOBAL_CACHE_DIR="$HOME/.cache/zig"
            '';
          };
        }
      );
    };
}
