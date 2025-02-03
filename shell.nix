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
  ];
}

