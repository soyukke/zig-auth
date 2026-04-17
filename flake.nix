{
  description = "Zig authentication system on Cloudflare Workers";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f system);
      zig_binaries = {
        x86_64-linux = {
          url = "https://ziglang.org/download/0.16.0/zig-x86_64-linux-0.16.0.tar.xz";
          hash = "sha256-cOSWZKdDdLSLUebz/fv0N/Y5XUJQkFBYi9SavlK6PQA=";
        };
        aarch64-linux = {
          url = "https://ziglang.org/download/0.16.0/zig-aarch64-linux-0.16.0.tar.xz";
          hash = "sha256-6ksJv7IuxvbGzqxXq2PvtrRuF6sI0h9p86SLOOFTTxc=";
        };
        x86_64-darwin = {
          url = "https://ziglang.org/download/0.16.0/zig-x86_64-macos-0.16.0.tar.xz";
          hash = "sha256-A4dVftGHe8ai4YAsg5GVO63bp2CBh2MBxSL1KXe1K6c=";
        };
        aarch64-darwin = {
          url = "https://ziglang.org/download/0.16.0/zig-aarch64-macos-0.16.0.tar.xz";
          hash = "sha256-sj1w3qqHm1wtSG7TMW9+qlPoSs9vycx0feFSRQ1AFIk=";
        };
      };
    in
    {
      devShells = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          zig_info = zig_binaries.${system};
          zig = pkgs.runCommand "zig-0.16.0" {
            src = pkgs.fetchurl {
              url = zig_info.url;
              hash = zig_info.hash;
            };
          } ''
            mkdir -p "$out"
            tar -xf "$src" --strip-components=1 -C "$out"
            mkdir -p "$out/bin"
            cat > "$out/bin/zig" <<EOF
            #!/bin/sh
            exec "$out/zig" "\$@"
            EOF
            chmod +x "$out/bin/zig"
          '';
        in
        {
          default = pkgs.mkShell {
            buildInputs = [
              zig
              pkgs.nodejs_20
              pkgs.pnpm
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
