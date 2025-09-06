# Consolidated sops-decrypt-hook with security hardening and optional advanced features
let
  lib = (import <nixpkgs> {}).lib;
  pkgs = import <nixpkgs> {};
  sops = pkgs.sops;
  # Security configuration
  defaultProtectedVars = [
    "PATH" "HOME" "USER" "SHELL" "LD_LIBRARY_PATH" "LD_PRELOAD" 
    "SHELLOPTS" "IFS" "PS1" "PS2" "PS3" "PS4"
  ];
  
  dangerousVars = [
    "LD_AUDIT" "LD_DEBUG" "LD_BIND_NOW" "LD_TRACE_LOADED_OBJECTS"
    "DYLD_LIBRARY_PATH" "DYLD_INSERT_LIBRARIES" "DYLD_PRINT_TO_FILE"
    "BASH_ENV" "ENV" "PROMPT_COMMAND" "PERL5LIB" "PYTHONPATH" "NODE_PATH"
  ];

  # Main hook generator with optional configuration
  mkSopsDecryptHook = { 
    sopsFiles,
    # Security options (enabled by default)
    protectedVars ? defaultProtectedVars ++ dangerousVars,
    validatePaths ? true,
    validateKeys ? true,
    maxFileSize ? 10485760,  # 10MB default
    
    # Behavior options
    failOnError ? false,
    verbose ? false,
    allowOverwrite ? false,
    
    # Advanced options (opt-in)
    globalPrefix ? "",
    fileConfigs ? [],  # List of { path, format ? "dotenv", prefix ? "", filter ? null, required ? true }
    keyTransform ? "none",  # "uppercase", "lowercase", or "none"
  }@args:
  let
    # Normalize file inputs
    normalizedFiles = 
      if fileConfigs != []
      then fileConfigs
      else map (f: { path = f; format = "dotenv"; prefix = ""; filter = null; required = true; }) 
               (if builtins.isList sopsFiles then sopsFiles else [sopsFiles]);
    
    # Generate format-specific parsers
    generateParser = format: {
      dotenv = ''
        while IFS= read -r line || [ -n "$line" ]; do
          [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
          
          if [[ "$line" =~ ^([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]]; then
            key="''${BASH_REMATCH[1]}"
            value="''${BASH_REMATCH[2]}"
            value="''${value#\"}"
            value="''${value%\"}"
            value="''${value#\'}"
            value="''${value%\'}"
            process_key_value "$key" "$value"
          fi
        done
      '';
      
      json = ''
        if command -v ${pkgs.jq}/bin/jq >/dev/null 2>&1; then
          # Flatten nested JSON objects with underscore separator
          ${pkgs.jq}/bin/jq -r '
            paths(scalars) as $p | 
            "\($p | join("_"))\t\(getpath($p) | tostring)"
          ' | \
          while IFS=$'\t' read -r key value; do
            process_key_value "$key" "$value"
          done
        else
          echo "ERROR: jq required for JSON format but not available" >&2
          return 1
        fi
      '';
      
      yaml = ''
        while IFS= read -r line; do
          if [[ "$line" =~ ^([A-Za-z_][A-Za-z0-9_]*):\ *(.*)$ ]]; then
            key="''${BASH_REMATCH[1]}"
            value="''${BASH_REMATCH[2]}"
            process_key_value "$key" "$value"
          fi
        done
      '';
      
      ini = ''
        current_section=""
        while IFS= read -r line; do
          if [[ "$line" =~ ^\[([^\]]+)\]$ ]]; then
            current_section="''${BASH_REMATCH[1]}_"
          elif [[ "$line" =~ ^([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]]; then
            key="''${current_section}''${BASH_REMATCH[1]}"
            value="''${BASH_REMATCH[2]}"
            process_key_value "$key" "$value"
          fi
        done
      '';
    }.${format} or ''
      echo "ERROR: Unsupported format: ${format}" >&2
      return 1
    '';
    
    # Key transformation logic
    transformKey = 
      if keyTransform == "uppercase" then ''key="''${key^^}"''
      else if keyTransform == "lowercase" then ''key="''${key,,}"''
      else "";
  in
  {
    shellHook = ''
      # SOPS Decrypt Hook
      ${lib.optionalString verbose "echo '=== SOPS Decrypt Hook Starting ===' >&2"}
      
      # Protected variables list
      PROTECTED_VARS="${lib.concatStringsSep " " protectedVars}"
      
      # Validation function for variable names
      validate_var_name() {
        local name="$1"
        
        ${lib.optionalString validateKeys ''
          if ! echo "$name" | grep -qE '^[A-Za-z_][A-Za-z0-9_]*$'; then
            echo "WARNING: Invalid variable name: $name" >&2
            return 1
          fi
        ''}
        
        for protected in $PROTECTED_VARS; do
          if [ "$name" = "$protected" ]; then
            echo "WARNING: Skipping protected variable: $name" >&2
            return 1
          fi
        done
        
        ${lib.optionalString (!allowOverwrite) ''
          if [ -n "''${!name+x}" ]; then
            echo "WARNING: Variable $name already exists, skipping" >&2
            return 1
          fi
        ''}
        
        return 0
      }
      
      # Process each SOPS file
      ${lib.concatMapStringsSep "\n" (fileConfig: ''
        (
          sopsFile="${fileConfig.path}"
          fileFormat="${fileConfig.format or "dotenv"}"
          filePrefix="${globalPrefix}${fileConfig.prefix or ""}"
          fileFilter="${if fileConfig.filter or null == null then "" else fileConfig.filter}"
          fileRequired="${toString (fileConfig.required or true)}"
          
          ${lib.optionalString verbose ''echo "Processing: $sopsFile (format: $fileFormat)" >&2''}
          
          # Path validation
          ${lib.optionalString validatePaths ''
            if echo "$sopsFile" | grep -qE '(^|/)\.\.(/|$)'; then
              echo "ERROR: Potential path traversal detected in: $sopsFile" >&2
              ${if failOnError then "exit 1" else "true"}
            fi
          ''}
          
          # Check file existence
          if [ ! -f "$sopsFile" ]; then
            if [ "$fileRequired" = "true" ]; then
              echo "ERROR: Required SOPS file not found: $sopsFile" >&2
              ${if failOnError then "exit 1" else "true"}
            else
              ${lib.optionalString verbose ''echo "Optional file not found: $sopsFile" >&2''}
            fi
            true  # Continue to next file
          else
            # Check file size
            ${lib.optionalString (maxFileSize > 0) ''
              file_size=$(stat -c%s "$sopsFile" 2>/dev/null || stat -f%z "$sopsFile" 2>/dev/null || echo 0)
              if [ "$file_size" -gt ${toString maxFileSize} ]; then
                echo "ERROR: SOPS file too large (>10MB): $sopsFile" >&2
                ${if failOnError then "exit 1" else "true"}
              fi
            ''}
            
            # Process key-value pairs
            process_key_value() {
              local key="$1"
              local value="$2"
              
              # Apply prefix
              key="$filePrefix$key"
              
              # Apply key transformation
              ${transformKey}
              
              # Apply filter if specified
              if [ -n "$fileFilter" ]; then
                if ! echo "$key" | grep -qE "$fileFilter"; then
                  return
                fi
              fi
              
              # Validate and export
              if validate_var_name "$key"; then
                # Check for command injection patterns
                if echo "$value" | grep -qE '[$`\\]|\$\(|\{\{|<\('; then
                  ${lib.optionalString verbose ''echo "WARNING: Sanitizing value for $key" >&2''}
                  value=$(printf '%q' "$value")
                fi
                
                # Export the variable
                if declare -x "$key"="$value" 2>/dev/null; then
                  ${lib.optionalString verbose ''echo "  Exported: $key" >&2''}
                else
                  echo "ERROR: Failed to export variable: $key" >&2
                fi
              fi
            }
            
            # Create temp file for secure processing
            temp_file=$(mktemp) || {
              echo "ERROR: Failed to create temporary file" >&2
              ${if failOnError then "exit 1" else "true"}
            }
            
            # Ensure cleanup
            trap "rm -f $temp_file" EXIT INT TERM
            
            # Decrypt file
            if ${sops}/bin/sops --decrypt "$sopsFile" > "$temp_file" 2>/dev/null; then
              # Parse based on format
              ${generateParser (fileConfig.format or "dotenv")} < "$temp_file"
            else
              echo "ERROR: Failed to decrypt $sopsFile" >&2
              rm -f "$temp_file"
              ${if failOnError then "exit 1" else "true"}
            fi
            
            # Cleanup
            rm -f "$temp_file"
            trap - EXIT INT TERM
          fi
        )
      '') normalizedFiles}
      
      ${lib.optionalString verbose "echo '=== SOPS Decrypt Hook Complete ===' >&2"}
    '';
  };

  # Simple wrapper for basic use cases (backwards compatible)
  mkSimpleHook = sopsFiles: mkSopsDecryptHook { inherit sopsFiles; };

in
  # For simple use: just pass a list of files
  # For advanced use: call mkSopsDecryptHook with full config
  args:
    if builtins.isList args
    then mkSimpleHook args
    else if builtins.isString args
    then mkSimpleHook [args]
    else if args ? sopsFiles
    then mkSopsDecryptHook args
    else throw "Invalid arguments to sops-decrypt-hook: expected list of files or configuration set"