# sops-decrypt-hook

A Nix shell hook for automatically decrypting SOPS-encrypted files and exporting their contents as environment variables.

## Features

- **Secure**: Built-in protection against command injection and path traversal
- **Fast**: Efficient decryption and parsing
- **Flexible**: Supports multiple file formats (dotenv, JSON)
- **Protected**: System variables (PATH, HOME) are never overwritten by default
- **Tested**: Comprehensive test suite with real SOPS encryption

## Overview

This project provides a Nix function that creates shell hooks for decrypting SOPS-encrypted files in development environments. The implementation includes built-in security hardening with configurable options.

## Quick Start

```nix
# flake.nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    sops-decrypt-hook.url = "github:brittonr/sops-decrypt-hook";
  };

  outputs = { self, nixpkgs, sops-decrypt-hook, ... }:
    let
      system = "x86_64-linux";  # or "aarch64-darwin" for M1 Macs
      pkgs = nixpkgs.legacyPackages.${system};
    in {
      devShells.${system}.default = pkgs.mkShell {
        buildInputs = [ pkgs.sops pkgs.jq ];  # jq needed for JSON format
        shellHook = (sops-decrypt-hook.lib.mkSopsDecryptHook {
          sopsFiles = [ ./secrets.enc.env ];
        }).shellHook;
      };
    };
}
```

## Configuration Options

The `mkSopsDecryptHook` function accepts the following options:

### Required
- `sopsFiles`: List of SOPS-encrypted files to decrypt

### Security Options (enabled by default)
- `protectedVars`: List of environment variables that cannot be overwritten (default: system variables)
- `validatePaths`: Validate file paths for security (default: `true`)
- `validateKeys`: Validate variable names (default: `true`)
- `maxFileSize`: Maximum file size in bytes (default: 10MB)

### Behavior Options
- `failOnError`: Exit if decryption fails (default: `false`)
- `verbose`: Show detailed output (default: `false`)
- `allowOverwrite`: Allow overwriting existing environment variables (default: `false`)
- `globalPrefix`: Add prefix to all exported variables (default: `""`)

### Example with Options

```nix
shellHook = (sops-decrypt-hook.lib.mkSopsDecryptHook {
  sopsFiles = [ ./secrets.enc.env ./database.enc.env ];
  failOnError = true;
  verbose = true;
  globalPrefix = "APP_";
}).shellHook;
```

## File Formats

The hook supports multiple file formats:

### Dotenv Format (.env)
```bash
# Create secrets.env
API_KEY=secret123
DATABASE_URL=postgresql://localhost/mydb
# Comments are supported
EMPTY_VALUE=
QUOTED="value with spaces"

# Encrypt with SOPS
sops -e secrets.env > secrets.enc.env
```

### JSON Format (.json)
```json
{
  "api_key": "secret123",
  "database": {
    "host": "localhost",
    "port": 5432,
    "credentials": {
      "user": "admin",
      "password": "secret"
    }
  }
}
```

```bash
# Encrypt with SOPS
sops -e secrets.json > secrets.enc.json
```

Nested JSON objects are automatically flattened with underscore separators:
- `api_key` → `api_key`
- `database.host` → `database_host`
- `database.credentials.user` → `database_credentials_user`

Note: Use the `keyTransform` option to convert to uppercase if needed.

### Using Different Formats

```nix
shellHook = (sops-decrypt-hook.lib.mkSopsDecryptHook {
  sopsFiles = [];  # Use fileConfigs instead for format specification
  fileConfigs = [
    { path = ./secrets.enc.env; format = "dotenv"; }
    { path = ./config.enc.json; format = "json"; prefix = "APP_"; }
  ];
}).shellHook;
```

**Note:** JSON format requires `jq` to be available in your shell environment.

## Testing

The project includes comprehensive tests implemented as Nix derivations.

```bash
# Run all checks
nix flake check

# Run specific test category
nix build .#checks.x86_64-linux.security
nix build .#checks.x86_64-linux.quick
nix build .#checks.x86_64-linux.unitTests

# Run nix-unit tests
nix run .#test-nix-unit

# Run all tests
nix run .#test-all
```

### Test Categories

- **Quick Tests**: Fast smoke tests for basic functionality
- **Security Tests**: Validates security protections
- **Unit Tests**: Mock SOPS tests for functionality
- **Integration Tests**: Real SOPS encryption tests with age keys
- **Edge Cases**: Special characters, injection attempts
- **Performance**: Performance benchmarks

## Development Shells

```bash
# Default development environment
nix develop

# With sops-nix integration
nix develop .#withSopsNix

# Testing environment
nix develop .#testing
```

## NixOS Module Usage

```nix
{
  imports = [ sops-decrypt-hook.nixosModules.default ];
  
  services.sopsDecryptHook = {
    enable = true;
    files = [ /etc/secrets/app.env ];
    services = [ "myapp" "database" ];
  };
}
```

## Home Manager Module Usage

```nix
{
  imports = [ sops-decrypt-hook.homeManagerModules.default ];
  
  programs.sopsDecryptHook = {
    enable = true;
    files = [ ~/.secrets/personal.env ];
    shells = [ "bash" "zsh" ];
  };
}
```

## Common Issues and Solutions

### Issue: Values with equals signs are truncated

**Symptom:** `DATABASE_URL=postgresql://user:pass@localhost/db` becomes just `postgresql://user`

**Solution:** The current implementation properly handles `cut -d '=' -f 2-` to preserve values with equals signs.

### Issue: PATH or HOME variables are overwritten

**Symptom:** Shell becomes unusable after loading secrets

**Solution:** System variables are protected by default. Use `protectedVars` option to customize the list.

### Issue: Silent failures

**Symptom:** Secrets aren't loaded but no error is shown

**Solution:** Use `verbose: true` and `failOnError: true` options for debugging.

## Best Practices

1. **Validate SOPS files** before adding to your devShell
2. **Use appropriate failure modes**:
   - `failOnError: true` for CI/CD pipelines
   - `failOnError: false` for development (default)
3. **Use prefixes** to namespace variables: `globalPrefix = "MYAPP_"`
4. **Regular testing** - Run the test suite after updates
5. **Keep secrets files small** - Default max size is 10MB

## Security Features

The implementation includes built-in protection against:

- Command injection via malicious variable names or values
- Path traversal attacks
- Overwriting critical system variables
- Loading of suspiciously large files
- Invalid variable names that could cause shell issues

Protected variables by default include:
- System paths: `PATH`, `LD_LIBRARY_PATH`
- Shell variables: `HOME`, `USER`, `SHELL`, `IFS`
- Security-sensitive: `LD_PRELOAD`, `BASH_ENV`, `PYTHONPATH`

## Contributing

Please ensure all contributions:
1. Pass the security tests
2. Include appropriate documentation
3. Follow Nix best practices
4. Are properly tested

## License

MIT

## Security

If you discover a security vulnerability, please report it via GitHub Security Advisories.