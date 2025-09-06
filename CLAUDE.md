# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Nix shell hook utility for automatically decrypting SOPS-encrypted files and exporting their key-value pairs as environment variables in Nix development shells.

## Architecture

The project consists of a single Nix function in `sops-decrypt-hook.nix` that:
1. Accepts a list of SOPS-encrypted files as input
2. Returns a shell hook that decrypts each file using the `sops` command
3. Parses the decrypted content for key=value pairs
4. Exports those pairs as environment variables in the shell

## Key Implementation Details

- **sops-decrypt-hook.nix:1-16**: Main function that generates a shell hook
  - Takes `sopsFiles` as input parameter
  - Iterates through each file and decrypts using `sops --decrypt`
  - Parses lines matching the pattern `KEY=VALUE` using regex
  - Exports each key-value pair as an environment variable

## Dependencies

- Requires `sops` to be available in the environment for decryption
- Designed to be used within Nix development shells

## Testing Considerations

When modifying the shell hook:
- Ensure proper handling of malformed key-value pairs
- Test with multiple SOPS files
- Verify that environment variables are correctly exported
- Check behavior when SOPS files don't exist or can't be decrypted