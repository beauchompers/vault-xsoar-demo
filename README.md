# Vault XSOAR

An all-in-one tool for installing, configuring, and managing HashiCorp Vault integrated with Cortex XSOAR for credential management.

## Features

- **One-command Vault installation** on Ubuntu 24.04 LTS
- **TLS enabled by default** with auto-generated certificates
- **Interactive TUI menu** using [gum](https://github.com/charmbracelet/gum) for arrow-key navigation
- **Credential management**: list, get, add, rotate, delete
- **Bulk import** credentials from JSON files
- **XSOAR integration** with pre-configured policies and tokens
- **Password generation** with complexity requirements

## Quick Start

```bash
# Install Vault with demo credentials
sudo ./vault-xsoar.sh install

# Or install with your own credentials
sudo CREDENTIALS_FILE=./my-credentials.json ./vault-xsoar.sh install

# Launch interactive menu
./vault-xsoar.sh

# Or use CLI commands directly
./vault-xsoar.sh list
./vault-xsoar.sh get svc_xsoar
```

## Installation

### Prerequisites

- Ubuntu 24.04 LTS (or compatible)
- Root/sudo access for installation
- `curl`, `jq` (installed automatically)

### Install Vault

```bash
# Clone or download the script
chmod +x vault-xsoar.sh

# Run installation (creates demo credentials by default)
sudo ./vault-xsoar.sh install
```

After installation:
- Vault UI: https://127.0.0.1:8200/ui (TLS enabled by default)
- Root token and unseal key saved to `/root/vault-env.sh`
- XSOAR tokens saved to `/root/xsoar-tokens.txt`
- TLS certificates in `/etc/vault.d/tls/`

## Usage

### Interactive Mode

Run without arguments to launch the interactive menu (requires `gum`):

```bash
./vault-xsoar.sh
```

Menu structure:
- **Status & Info**: Vault status, run tests, XSOAR integration info
- **Credential Management**: Browse, get, add, rotate, delete credentials
- **Vault Operations**: Unseal, install

### CLI Commands

```bash
# Vault Management
./vault-xsoar.sh install              # Install and configure Vault
./vault-xsoar.sh uninstall            # Completely remove Vault and all data
./vault-xsoar.sh unseal               # Unseal Vault after restart
./vault-xsoar.sh status               # Show Vault status
./vault-xsoar.sh test                 # Run integration tests

# Credential Management
./vault-xsoar.sh list                 # List all credentials
./vault-xsoar.sh get <name>           # Get credential details
./vault-xsoar.sh get <name> json      # Get as JSON
./vault-xsoar.sh add <name>           # Add credential (interactive)
./vault-xsoar.sh add <name> <u> <p>   # Add credential with values
./vault-xsoar.sh rotate <name>        # Rotate password
./vault-xsoar.sh rotate <name> 24     # Rotate with 24-char password
./vault-xsoar.sh delete <name>        # Delete credential
./vault-xsoar.sh import <file>        # Import from JSON file

# Info
./vault-xsoar.sh xsoar-info           # Show XSOAR integration details
./vault-xsoar.sh help                 # Show help
./vault-xsoar.sh version              # Show version
```

### Importing Credentials

Create a JSON file with your credentials:

```json
{
  "credentials": [
    {
      "path": "svc_account",
      "data": {
        "username": "svc_user",
        "password": "SecureP@ss123!",
        "domain": "corp.local",
        "description": "Service Account"
      }
    },
    {
      "path": "my_api",
      "data": {
        "api_key": "key-12345",
        "api_secret": "secret-67890",
        "endpoint": "https://api.example.com"
      }
    }
  ]
}
```

Import during installation or after:

```bash
# During installation
sudo CREDENTIALS_FILE=./credentials.json ./vault-xsoar.sh install

# After installation
./vault-xsoar.sh import credentials.json
```

See [credentials.json.example](credentials.json.example) for a complete example.

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `VAULT_ADDR` | Vault server address | `https://127.0.0.1:8200` |
| `VAULT_TOKEN` | Authentication token | (from install) |
| `VAULT_TLS_ENABLED` | Enable TLS with self-signed certs | `true` |
| `CREDENTIALS_FILE` | JSON file for initial credentials | (uses demo data) |
| `DEBUG` | Enable debug output | `0` |

## XSOAR Integration

After installation, two tokens are created:

- **Read-Only Token**: For fetching credentials (`xsoar-credentials` policy)
- **Rotation Token**: For credential management (`xsoar-rotation` policy)

View integration details:

```bash
./vault-xsoar.sh xsoar-info
```

XSOAR commands:
```
!hashicorp-list-secrets
!hashicorp-get-secret path=svc_xsoar
```

## TLS Configuration

TLS is **enabled by default** with auto-generated self-signed certificates:

```bash
# Install with TLS (default)
sudo ./vault-xsoar.sh install

# Install without TLS (not recommended for production)
sudo VAULT_TLS_ENABLED=false ./vault-xsoar.sh install
```

Certificate locations:
- CA certificate: `/etc/vault.d/tls/ca.crt`
- Server certificate: `/etc/vault.d/tls/vault.crt`
- Server key: `/etc/vault.d/tls/vault.key`

The CA certificate is automatically added to the system trust store. For XSOAR integration, either:
- Import the CA certificate as a trusted CA in XSOAR
- Set "Verify SSL" to false in the XSOAR Vault integration settings

## Security Notes

- TLS is enabled by default with self-signed certificates
- Unseal key and root token are stored in `/root/` with `600` permissions
- Never commit `credentials.json` files (added to `.gitignore`)
- Rotate the root token after initial setup in production
- For production, consider using certificates from a trusted CA

## Requirements

- **OS**: Ubuntu 24.04 LTS
- **Dependencies**: `curl`, `jq`, `gnupg` (installed automatically)
- **Optional**: `gum` for interactive menu (can be installed via the script)

## License

MIT
