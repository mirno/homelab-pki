{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = [
    pkgs.go             # Go programming language
    pkgs.gotests        # Generate unit tests for Go
    pkgs.richgo         # Rich data structure rendering for Go
    pkgs.lefthook       # Git hooks manager
    pkgs.go-task           # Taskfile (task runner)

    # Additional Go tools
    pkgs.lefthook
    pkgs.golangci-lint  # Linter for Go code
    pkgs.delve          # Debugger for Go
    pkgs.gotools        # Miscellaneous Go tools

    pkgs.gosec

    pkgs.docker

    # cert tools
    pkgs.step-cli
    pkgs.step-ca # local certificate authority alternative providing ACME server
    # pkgs.certbot # outdated, v3 is released but not supported by nix. Please use: https://eff-certbot.readthedocs.io/en/stable/install.html#snap-recommended  # ACME client that can obtain certs and extensibly update server configurations
    pkgs.openssl

    pkgs.jq

    # DNS
    pkgs.dnsmasq
    pkgs.dig
    pkgs.nmap
    pkgs.cfssl
    pkgs.coredns
    # pkgs.nginx
    

    # experimental
    pkgs.bat
  ];
}

