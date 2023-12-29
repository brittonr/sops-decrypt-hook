## Introduction

This GitHub repository contains the `sops-decrypt-hook.nix` file, which is designed to be used as a shell hook in Nix development environments. This hook simplifies the process of decrypting a configuration file encrypted using [SOPS (Secrets OPerationS)](https://github.com/mozilla/sops) and adding its contents as environment variables within a dev shell.

## Usage

To use the `sops-decrypt-hook.nix` file in your Nix development environment, follow these steps:

1. Clone this GitHub repository to your local machine:

   ```bash
   git clone https://github.com/yourusername/your-repo.git
   ```
Navigate to the directory where you cloned the repository:
bash
Copy code
cd your-repo
Edit the flake.nix file to specify the sopsFile variable with the path to your encrypted configuration file:
```nix
shellHook = (import ./sops-decrypt-hook.nix { sopsFile = "/path/to/your/config.sops.yaml"; }).shellHook;
```
Save the flake.nix file.
Build your Nix development environment using the following command:
```bash
nix develop
```
The sops-decrypt-hook.nix script will be executed as a shell hook during the environment setup, decrypting the specified configuration file and adding its contents as environment variables within the dev shell.

How It Works

The sops-decrypt-hook.nix script performs the following actions:

- It checks if the specified sopsFile exists.
- If the file exists, it reads each line of the decrypted file and extracts key-value pairs in the format KEY: VALUE.
- It sets environment variables in the dev shell using these key-value pairs, making them accessible for use in your development environment.
