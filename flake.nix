{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }: let
    system = "x86_64-linux";
    pkgs = import nixpkgs { inherit system; };
    pnpm = pkgs.pnpm_9;
    nodejs = pkgs.nodejs_22;

    gateway = pkgs.rustPlatform.buildRustPackage {
      pname = "onecli-gateway";
      version = "0.1.0";
      src = ./apps/gateway;
      cargoLock.lockFile = ./apps/gateway/Cargo.lock;
    };

    # Pre-fetch pnpm dependencies (fixed-output derivation).
    # To compute the hash: run `nix build .#web` with an empty hash,
    # nix will print the expected hash in the error message.
    pnpmDeps = pnpm.fetchDeps {
      pname = "onecli-web-deps";
      version = "0.1.0";
      src = ./.;
      hash = "";  # Replace with actual hash from `nix build .#web`
      fetcherVersion = 3;
    };

    web = pkgs.stdenv.mkDerivation {
      pname = "onecli-web";
      version = "0.1.0";
      src = ./.;

      nativeBuildInputs = [
        nodejs
        pnpm.configHook
      ];

      inherit pnpmDeps;

      env = {
        NEXT_TELEMETRY_DISABLED = "1";
        # Dummy DATABASE_URL prevents PGlite from initializing during build
        DATABASE_URL = "postgresql://build:build@localhost/build";
      };

      buildPhase = ''
        runHook preBuild
        pnpm --filter @onecli/db generate
        pnpm build --filter=@onecli/web
        runHook postBuild
      '';

      installPhase = ''
        runHook preInstall
        mkdir -p $out

        # Next.js standalone output
        cp -r apps/web/.next/standalone/* $out/
        cp -r apps/web/.next/static $out/apps/web/.next/static
        if [ -d apps/web/public ]; then
          cp -r apps/web/public $out/apps/web/public
        fi

        # Prisma migrations and init script for PGlite mode
        mkdir -p $out/packages/db
        cp -r packages/db/prisma $out/packages/db/prisma
        if [ -d packages/db/scripts ]; then
          cp -r packages/db/scripts $out/packages/db/scripts
        fi

        runHook postInstall
      '';
    };

    # Entrypoint script that runs both gateway and web dashboard
    entrypoint = pkgs.writeShellScriptBin "onecli" ''
      set -euo pipefail
      DATA_DIR="''${ONECLI_DATA_DIR:-$HOME/.onecli}"
      mkdir -p "$DATA_DIR"

      # Generate gateway-API shared secret if missing
      GATEWAY_SECRET_FILE="$DATA_DIR/gateway-secret"
      if [ ! -f "$GATEWAY_SECRET_FILE" ] || [ ! -s "$GATEWAY_SECRET_FILE" ]; then
        head -c 32 /dev/urandom | od -A n -t x1 | tr -d ' \n' > "$GATEWAY_SECRET_FILE"
        chmod 600 "$GATEWAY_SECRET_FILE"
      fi

      # Generate secret encryption key if missing
      SECRET_KEY_FILE="$DATA_DIR/secret-encryption-key"
      if [ ! -f "$SECRET_KEY_FILE" ] || [ ! -s "$SECRET_KEY_FILE" ]; then
        head -c 32 /dev/urandom | ${pkgs.coreutils}/bin/base64 > "$SECRET_KEY_FILE"
        chmod 600 "$SECRET_KEY_FILE"
      fi
      export SECRET_ENCRYPTION_KEY="$(cat "$SECRET_KEY_FILE")"

      # PGlite data — symlink so Next.js resolves ./data/pglite relative to server.js
      PGLITE_LINK="${web}/apps/web/data"
      if [ ! -e "$PGLITE_LINK" ]; then
        # standalone output is read-only; set DATABASE_URL to point PGlite at our data dir
        true
      fi

      # Runtime config
      printf '{"authMode":"local","oauthConfigured":false}\n' > "$DATA_DIR/runtime-config.json"

      export GATEWAY_PORT="''${GATEWAY_PORT:-10255}"
      export PORT="''${PORT:-10254}"
      export NODE_ENV="production"
      export AUTH_TRUST_HOST="true"
      export NEXTAUTH_URL="http://localhost:$PORT"

      # Start gateway in background
      ${gateway}/bin/onecli-gateway \
        --port "$GATEWAY_PORT" \
        --data-dir "$DATA_DIR" \
        --gateway-secret-file "$GATEWAY_SECRET_FILE" &
      GATEWAY_PID=$!

      cleanup() {
        kill "$GATEWAY_PID" 2>/dev/null
        wait "$GATEWAY_PID" 2>/dev/null
      }
      trap cleanup EXIT TERM INT

      # Start Next.js web dashboard (foreground)
      exec ${nodejs}/bin/node ${web}/apps/web/server.js
    '';

    # Gateway-only runner (works without web dashboard build)
    gateway-runner = pkgs.writeShellScriptBin "onecli-gateway" ''
      DATA_DIR="''${ONECLI_DATA_DIR:-$HOME/.onecli}"
      mkdir -p "$DATA_DIR"

      GATEWAY_SECRET_FILE="$DATA_DIR/gateway-secret"
      if [ ! -f "$GATEWAY_SECRET_FILE" ] || [ ! -s "$GATEWAY_SECRET_FILE" ]; then
        head -c 32 /dev/urandom | od -A n -t x1 | tr -d ' \n' > "$GATEWAY_SECRET_FILE"
        chmod 600 "$GATEWAY_SECRET_FILE"
      fi

      exec ${gateway}/bin/onecli-gateway \
        --port "''${GATEWAY_PORT:-10255}" \
        --data-dir "$DATA_DIR" \
        --gateway-secret-file "$GATEWAY_SECRET_FILE" \
        "$@"
    '';

  in {
    packages.${system} = {
      inherit gateway web;
      gateway-runner = gateway-runner;
      default = entrypoint;
    };

    # NixOS module for systemd service
    nixosModules.default = { config, lib, pkgs, ... }:
    let
      cfg = config.services.onecli;
    in {
      options.services.onecli = {
        enable = lib.mkEnableOption "onecli credential proxy";

        gatewayPort = lib.mkOption {
          type = lib.types.port;
          default = 10255;
          description = "Port for the MITM gateway";
        };

        webPort = lib.mkOption {
          type = lib.types.port;
          default = 10254;
          description = "Port for the web dashboard";
        };

        dataDir = lib.mkOption {
          type = lib.types.str;
          default = "/var/lib/onecli";
          description = "Directory for persistent state (CA certs, secrets, PGlite DB)";
        };

        package = lib.mkPackageOption self.packages.${system} "default" {};

        openFirewall = lib.mkOption {
          type = lib.types.bool;
          default = false;
          description = "Open firewall ports for gateway and web dashboard";
        };
      };

      config = lib.mkIf cfg.enable {
        systemd.services.onecli = {
          description = "OneCLI credential proxy (gateway + web dashboard)";
          after = [ "network.target" ];
          wantedBy = [ "multi-user.target" ];

          environment = {
            ONECLI_DATA_DIR = cfg.dataDir;
            GATEWAY_PORT = toString cfg.gatewayPort;
            PORT = toString cfg.webPort;
            NODE_ENV = "production";
          };

          serviceConfig = {
            Type = "simple";
            ExecStart = "${cfg.package}/bin/onecli";
            StateDirectory = "onecli";
            DynamicUser = true;
            Restart = "on-failure";
            RestartSec = 5;

            # Hardening
            NoNewPrivileges = true;
            ProtectSystem = "strict";
            ProtectHome = true;
            ReadWritePaths = [ cfg.dataDir ];
            PrivateTmp = true;
          };
        };

        networking.firewall = lib.mkIf cfg.openFirewall {
          allowedTCPPorts = [ cfg.gatewayPort cfg.webPort ];
        };
      };
    };

    devShells.${system}.default = pkgs.mkShell {
      buildInputs = [
        gateway
        nodejs
        pnpm
      ];
    };
  };
}
