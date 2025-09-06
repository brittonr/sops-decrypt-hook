# Unit tests using nix-unit framework
# Run with: nix run github:nix-community/nix-unit -- --flake .#tests-unit
{ lib ? (import <nixpkgs> {}).lib
, mkHook ? import ./sops-decrypt-hook.nix
}:

let
  # Use the implementations passed as parameters
  originalHook = mkHook;
  secureHook = mkHook;
  
  # Test helper to extract the shell script from the hook
  getShellScript = hook: sopsFiles: 
    (hook { inherit sopsFiles; }).shellHook;
  
  # Helper to check if a string contains another string
  contains = needle: haystack:
    builtins.match ".*${lib.escapeRegex needle}.*" haystack != null;

in {
  # Test that the function returns the expected structure
  test_hook_structure = {
    expr = builtins.typeOf (originalHook { sopsFiles = [ "/test.env" ]; }).shellHook;
    expected = "string";
  };
  
  # Test that multiple files are handled
  test_multiple_files = {
    expr = let
      hook = originalHook { 
        sopsFiles = [ "/file1.env" "/file2.env" "/file3.env" ]; 
      };
    in
      # Check that all files appear in the script
      contains "/file1.env" hook.shellHook &&
      contains "/file2.env" hook.shellHook &&
      contains "/file3.env" hook.shellHook;
    expected = true;
  };
  
  # Test that the original implementation uses the buggy cut command
  test_original_has_bug = {
    expr = let
      script = getShellScript originalHook [ "/test.env" ];
    in
      # Original uses: cut -d '=' -f 2 (without the -)
      contains "cut -d '=' -f 2)" script &&
      !contains "cut -d '=' -f 2-" script;
    expected = true;
  };
  
  # Test that secure implementation has the fix
  test_secure_has_fix = {
    expr = let
      script = getShellScript secureHook [ "/test.env" ];
    in
      # Secure uses: cut -d '=' -f 2- (with the -)
      contains "cut -d '=' -f 2-" script;
    expected = true;
  };
  
  # Test that secure implementation has protected variables
  test_secure_has_protected_vars = {
    expr = let
      script = getShellScript secureHook [ "/test.env" ];
    in
      contains "PROTECTED_VARS=" script &&
      contains "PATH HOME USER SHELL" script;
    expected = true;
  };
  
  # Test that original doesn't quote variables (security issue)
  test_original_unquoted_key = {
    expr = let
      script = getShellScript originalHook [ "/test.env" ];
    in
      # Original has: export $key="$value" (unquoted $key)
      contains "export \$key=" script;
    expected = true;
  };
  
  # Test that secure implementation quotes properly
  test_secure_quoted_properly = {
    expr = let
      script = getShellScript secureHook [ "/test.env" ];
    in
      # Secure uses: declare -x "$key"="$value" (quoted)
      contains "declare -x \"\$key\"=\"\$value\"" script;
    expected = true;
  };
  
  # Test that original doesn't quote the sops file path
  test_original_unquoted_path = {
    expr = let
      script = getShellScript originalHook [ "/test.env" ];
    in
      # Original has: sops --decrypt $sopsFile (unquoted)
      contains "sops --decrypt \$sopsFile)" script;
    expected = true;
  };
  
  # Test that secure quotes the file path
  test_secure_quoted_path = {
    expr = let
      script = getShellScript secureHook [ "/test.env" ];
    in
      # Secure has: sops --decrypt "$sopsFile" (quoted)
      contains "sops --decrypt \"\$sopsFile\"" script;
    expected = true;
  };
  
  # Test that secure has error handling
  test_secure_has_error_handling = {
    expr = let
      script = getShellScript secureHook [ "/test.env" ];
    in
      contains "ERROR: Failed to decrypt" script &&
      contains "WARNING: SOPS file not found" script;
    expected = true;
  };
  
  # Test that original lacks error handling
  test_original_no_error_handling = {
    expr = let
      script = getShellScript originalHook [ "/test.env" ];
    in
      !contains "ERROR:" script && !contains "WARNING:" script;
    expected = true;
  };
  
  # Test path traversal protection in secure
  test_secure_path_traversal_protection = {
    expr = let
      script = getShellScript secureHook [ "/test.env" ];
    in
      contains "Potential path traversal detected" script;
    expected = true;
  };
  
  # Test file size limit in secure
  test_secure_file_size_limit = {
    expr = let
      script = getShellScript secureHook [ "/test.env" ];
    in
      contains "SOPS file too large" script &&
      contains "10485760" script; # 10MB limit
    expected = true;
  };
  
  # Test JSON format support
  test_json_format_support = {
    expr = let
      hook = mkHook { 
        sopsFiles = [];
        fileConfigs = [{ path = "/test.json"; format = "json"; }];
      };
      script = hook.shellHook;
    in
      contains "jq" script && 
      contains "paths(scalars)" script &&
      contains "getpath" script;
    expected = true;
  };
  
  # Test JSON format requires jq
  test_json_requires_jq = {
    expr = let
      hook = mkHook { 
        sopsFiles = [];
        fileConfigs = [{ path = "/test.json"; format = "json"; }];
      };
      script = hook.shellHook;
    in
      contains "jq required for JSON format" script;
    expected = true;
  };
  
  # Test empty string handling
  test_empty_files_list = {
    expr = builtins.typeOf (originalHook { sopsFiles = []; }).shellHook;
    expected = "string";
  };
  
  # Test dangerous variable detection in secure
  test_secure_dangerous_vars = {
    expr = let
      script = getShellScript secureHook [ "/test.env" ];
    in
      contains "DANGEROUS_VARS=" script &&
      contains "LD_PRELOAD" script &&
      contains "BASH_ENV" script;
    expected = true;
  };
  
  # Test that secure validates variable names
  test_secure_validates_var_names = {
    expr = let
      script = getShellScript secureHook [ "/test.env" ];
    in
      contains "validate_var_name" script &&
      contains "^[A-Za-z_][A-Za-z0-9_]*\$" script;
    expected = true;
  };
  
  # Test command injection protection in secure
  test_secure_command_injection_protection = {
    expr = let
      script = getShellScript secureHook [ "/test.env" ];
    in
      contains "potential command injection" script ||
      contains "Potentially dangerous value" script;
    expected = true;
  };
  
  # Test that secure has proper cleanup
  test_secure_has_cleanup = {
    expr = let
      script = getShellScript secureHook [ "/test.env" ];
    in
      contains "trap" script &&
      contains "rm -f \$temp_file" script;
    expected = true;
  };
  
  # Test line counting in secure
  test_secure_counts_lines = {
    expr = let
      script = getShellScript secureHook [ "/test.env" ];
    in
      contains "line_count=" script &&
      contains "export_count=" script &&
      contains "skip_count=" script;
    expected = true;
  };
  
  # Test toString conversion of file paths
  test_tostring_conversion = {
    expr = let
      script = getShellScript originalHook [ ./test.env ];
    in
      # Should convert path to string
      builtins.isString script;
    expected = true;
  };
}