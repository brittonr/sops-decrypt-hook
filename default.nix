# Default entry point for non-flake usage
{ pkgs ? import <nixpkgs> {} }:

let
  # Import all test suites
  allTests = import ./tests-all.nix { inherit pkgs; };
  
  # Import the consolidated implementation
  sopsDecryptHook = import ./sops-decrypt-hook.nix { inherit (pkgs) lib pkgs; };
  
in {
  # Main implementation
  inherit sopsDecryptHook;
  
  # Recommended for use
  mkSopsDecryptHook = sopsDecryptHook;
  
  # All tests
  tests = allTests;
  
  # Quick commands
  test = allTests.all;
  testQuick = allTests.quickTest;
  testSecurity = allTests.securityValidation;
  testUnit = allTests.allUnitTests;
  testIntegration = allTests.allIntegrationTests;
  testEdge = allTests.edgeCaseTests;
  testPerf = allTests.performanceTest;
  
  # Shell with everything
  shell = pkgs.mkShell {
    buildInputs = with pkgs; [
      sops
      age
      jq
      yq
    ];
    
    shellHook = ''
      echo "SOPS Decrypt Hook Development Shell"
      echo ""
      echo "Run tests with:"
      echo "  nix-build -A test           # All tests"
      echo "  nix-build -A testQuick      # Quick smoke test"
      echo "  nix-build -A testSecurity   # Security validation"
      echo "  nix-build -A testUnit       # Unit tests"
      echo "  nix-build -A testIntegration # Integration tests"
    '';
  };
}