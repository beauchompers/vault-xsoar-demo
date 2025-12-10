# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a single-file bash script (`vault-xsoar.sh`) that provides an all-in-one tool for installing, configuring, and managing HashiCorp Vault integrated with Cortex XSOAR for credential management. Target platform is Ubuntu 24.04 LTS.

## Running the Script

```bash
# Install Vault and configure for XSOAR (requires root)
sudo ./vault-xsoar.sh install

# Common commands (after installation, tool is available as vault-xsoar)
vault-xsoar status          # Show Vault status
vault-xsoar list            # List all credentials
vault-xsoar get <path>      # Get credential (e.g., active-directory/svc_xsoar)
vault-xsoar add <path>      # Add new credential (interactive or with args)
vault-xsoar rotate <path>   # Rotate credential password
vault-xsoar test            # Run integration tests
vault-xsoar xsoar-info      # Show XSOAR integration config
```

## Code Structure

The script is organized into sections marked by comment blocks:
- **Configuration**: Global variables, colors, paths (lines 1-32)
- **Utility Functions**: Logging, root check, vault status helpers, password generation (lines 59-136)
- **Commands**: Each `cmd_*` function implements a CLI command:
  - `cmd_install`: Full Vault installation, initialization, and XSOAR policy setup
  - `cmd_unseal`, `cmd_status`, `cmd_test`: Vault management
  - `cmd_list`, `cmd_get`, `cmd_add`, `cmd_rotate`, `cmd_delete`: Credential CRUD operations
  - `cmd_xsoar_info`: XSOAR integration details
- **Main**: Command dispatch via case statement (lines 882-911)

## Key Paths and Configuration

- Vault config: `/etc/vault.d/vault.hcl`
- Vault data: `/opt/vault/data`
- Vault logs: `/var/log/vault`
- Credentials stored under KV v1 engine at path `credentials/`
- Environment file: `/root/vault-env.sh` (contains VAULT_ADDR, VAULT_TOKEN, VAULT_UNSEAL_KEY)
- XSOAR tokens: `/root/xsoar-tokens.txt`

## Environment Variables

- `VAULT_ADDR`: Vault server address (default: http://127.0.0.1:8200)
- `VAULT_TOKEN`: Authentication token
- `VAULT_UNSEAL_KEY`: Key for unsealing Vault
- `DEBUG=1`: Enable debug logging
