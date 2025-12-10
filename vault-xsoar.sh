#!/bin/bash
#===============================================================================
#  HashiCorp Vault + Cortex XSOAR Integration Tool
#  All-in-one: Install, Configure, Manage Credentials, Rotate
#  Target: Ubuntu 24.04 LTS
#===============================================================================

set -e

VERSION="1.0.0"
SCRIPT_NAME=$(basename "$0")

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
GRAY='\033[0;90m'
NC='\033[0m'
BOLD='\033[1m'

# Configuration
VAULT_VERSION="1.15.4"
VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
VAULT_CONFIG_DIR="/etc/vault.d"
VAULT_DATA_DIR="/opt/vault/data"
VAULT_LOG_DIR="/var/log/vault"
CREDENTIALS_PATH="credentials"

#===============================================================================
# ASCII Art Logo
#===============================================================================
show_logo() {
    echo -e "${CYAN}"
    cat << 'EOF'
 ██╗   ██╗ █████╗ ██╗   ██╗██╗  ████████╗    ██╗  ██╗███████╗ ██████╗  █████╗ ██████╗ 
 ██║   ██║██╔══██╗██║   ██║██║  ╚══██╔══╝    ╚██╗██╔╝██╔════╝██╔═══██╗██╔══██╗██╔══██╗
 ██║   ██║███████║██║   ██║██║     ██║        ╚███╔╝ ███████╗██║   ██║███████║██████╔╝
 ╚██╗ ██╔╝██╔══██║██║   ██║██║     ██║        ██╔██╗ ╚════██║██║   ██║██╔══██║██╔══██╗
  ╚████╔╝ ██║  ██║╚██████╔╝███████╗██║       ██╔╝ ██╗███████║╚██████╔╝██║  ██║██║  ██║
   ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝       ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
EOF
    echo -e "${NC}"
    echo -e "${GRAY}═══════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}       HashiCorp Vault + Cortex XSOAR Credential Management Tool v${VERSION}${NC}"
    echo -e "${GRAY}═══════════════════════════════════════════════════════════════════════════════${NC}"
    echo ""
}

show_mini_logo() {
    echo -e "${CYAN}╔═══════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}  ${WHITE}⚡ VAULT ${MAGENTA}✕${NC} ${WHITE}XSOAR${NC}  ${GRAY}Credential Manager${NC}  ${CYAN}║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════╝${NC}"
}

#===============================================================================
# Logging Functions
#===============================================================================
log_info()    { echo -e "${BLUE}[ℹ]${NC} $1"; }
log_success() { echo -e "${GREEN}[✔]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[⚠]${NC} $1"; }
log_error()   { echo -e "${RED}[✖]${NC} $1"; }
log_step()    { echo -e "${MAGENTA}[➤]${NC} $1"; }
log_debug()   { [[ "${DEBUG:-0}" == "1" ]] && echo -e "${GRAY}[D]${NC} $1"; }

spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    while ps -p $pid > /dev/null 2>&1; do
        for i in $(seq 0 9); do
            echo -ne "\r${CYAN}[${spinstr:$i:1}]${NC} $2"
            sleep $delay
        done
    done
    echo -ne "\r"
}

#===============================================================================
# Utility Functions
#===============================================================================
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This command requires root privileges. Use: sudo $SCRIPT_NAME $*"
        exit 1
    fi
}

load_vault_env() {
    if [[ -f /root/vault-env.sh ]]; then
        source /root/vault-env.sh
    fi
    export VAULT_ADDR="${VAULT_ADDR}"
}

check_vault_running() {
    if ! systemctl is-active --quiet vault 2>/dev/null; then
        log_error "Vault service is not running. Start with: sudo systemctl start vault"
        return 1
    fi
    return 0
}

check_vault_unsealed() {
    local status=$(vault status -format=json 2>/dev/null | jq -r '.sealed' 2>/dev/null)
    if [[ "${status}" == "true" ]]; then
        log_error "Vault is sealed. Unseal with: $SCRIPT_NAME unseal"
        return 1
    fi
    return 0
}

check_vault_ready() {
    check_vault_running && check_vault_unsealed
}

generate_password() {
    local length=${1:-20}
    local password=""
    
    # Ensure complexity requirements
    while true; do
        password=$(openssl rand -base64 48 | tr -dc 'a-zA-Z0-9!@#$%^&*' | head -c ${length})
        
        # Check complexity
        [[ "$password" =~ [A-Z] ]] && \
        [[ "$password" =~ [a-z] ]] && \
        [[ "$password" =~ [0-9] ]] && \
        [[ "$password" =~ [!@#\$%^\&\*] ]] && break
    done
    
    echo "$password"
}

#===============================================================================
# INSTALL Command
#===============================================================================
cmd_install() {
    check_root
    show_logo
    
    echo -e "${WHITE}${BOLD}Starting Vault Installation for XSOAR Integration${NC}"
    echo ""
    
    # Pre-flight
    log_step "Running pre-flight checks..."
    if ! grep -q "Ubuntu" /etc/os-release 2>/dev/null; then
        log_warn "This script is optimized for Ubuntu. Proceeding anyway..."
    fi
    log_success "Pre-flight checks passed"
    
    # Install Vault
    log_step "Installing HashiCorp Vault..."
    apt-get update -qq
    apt-get install -y -qq gnupg software-properties-common curl jq > /dev/null
    
    curl -fsSL https://apt.releases.hashicorp.com/gpg | gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg 2>/dev/null
    echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/hashicorp.list > /dev/null
    apt-get update -qq
    apt-get install -y -qq vault > /dev/null
    
    log_success "Vault $(vault --version | head -1) installed"
    
    # Configure
    log_step "Configuring Vault server..."
    mkdir -p ${VAULT_CONFIG_DIR} ${VAULT_DATA_DIR} ${VAULT_LOG_DIR}
    id -u vault &>/dev/null || useradd --system --home ${VAULT_CONFIG_DIR} --shell /bin/false vault
    chown -R vault:vault ${VAULT_DATA_DIR} ${VAULT_LOG_DIR}
    
    cat > ${VAULT_CONFIG_DIR}/vault.hcl << 'VAULTCONF'
# Vault Server Configuration - XSOAR Demo
listener "tcp" {
  address       = "0.0.0.0:8200"
  tls_disable   = true  # Enable TLS in production!
}

storage "file" {
  path = "/opt/vault/data"
}

api_addr     = "http://0.0.0.0:8200"
cluster_addr = "https://0.0.0.0:8201"
ui           = true
log_level    = "info"
log_file     = "/var/log/vault/vault.log"
disable_mlock = true
VAULTCONF

    # Systemd service
    cat > /etc/systemd/system/vault.service << 'SYSTEMD'
[Unit]
Description=HashiCorp Vault
Documentation=https://www.vaultproject.io/docs/
Requires=network-online.target
After=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=3

[Service]
User=vault
Group=vault
ProtectSystem=full
ProtectHome=read-only
PrivateTmp=yes
PrivateDevices=yes
SecureBits=keep-caps
AmbientCapabilities=CAP_IPC_LOCK
NoNewPrivileges=yes
ExecStart=/usr/bin/vault server -config=/etc/vault.d/vault.hcl
ExecReload=/bin/kill --signal HUP $MAINPID
KillMode=process
KillSignal=SIGINT
Restart=on-failure
RestartSec=5
TimeoutStopSec=30
LimitNOFILE=65536
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
SYSTEMD

    systemctl daemon-reload
    log_success "Vault configured"
    
    # Start and Initialize
    log_step "Starting Vault service..."
    systemctl enable vault > /dev/null 2>&1
    systemctl start vault
    sleep 3
    log_success "Vault service started"
    
    export VAULT_ADDR="http://127.0.0.1:8200"
    
    if vault status 2>/dev/null | grep -q "Initialized.*true"; then
        log_warn "Vault already initialized"
    else
        log_step "Initializing Vault..."
        INIT_OUTPUT=$(vault operator init -key-shares=1 -key-threshold=1 -format=json)
        
        UNSEAL_KEY=$(echo "${INIT_OUTPUT}" | jq -r '.unseal_keys_b64[0]')
        ROOT_TOKEN=$(echo "${INIT_OUTPUT}" | jq -r '.root_token')
        
        echo "${INIT_OUTPUT}" > /root/vault-init-keys.json
        chmod 600 /root/vault-init-keys.json
        
        cat > /root/vault-env.sh << EOF
export VAULT_ADDR="http://127.0.0.1:8200"
export VAULT_TOKEN="${ROOT_TOKEN}"
export VAULT_UNSEAL_KEY="${UNSEAL_KEY}"
EOF
        chmod 600 /root/vault-env.sh
        
        vault operator unseal "${UNSEAL_KEY}" > /dev/null
        log_success "Vault initialized and unsealed"
        
        export VAULT_TOKEN="${ROOT_TOKEN}"
    fi
    
    source /root/vault-env.sh
    
    # Configure secrets engine
    log_step "Configuring secrets engine..."
    vault secrets enable -path=${CREDENTIALS_PATH} -version=1 kv 2>/dev/null || true
    log_success "KV secrets engine enabled at '${CREDENTIALS_PATH}/'"
    
    # Create demo credentials
    log_step "Creating demo credentials..."
    
    vault kv put ${CREDENTIALS_PATH}/active-directory/svc_xsoar \
        username="svc_xsoar" \
        password="DemoP@ssw0rd123!" \
        domain="demo.local" \
        description="XSOAR Service Account" \
        last_rotated="$(date -u +%Y-%m-%dT%H:%M:%SZ)" > /dev/null
    
    vault kv put ${CREDENTIALS_PATH}/active-directory/admin \
        username="admin_xsoar" \
        password="AdminP@ss456!" \
        domain="demo.local" \
        description="AD Admin Account" > /dev/null
    
    vault kv put ${CREDENTIALS_PATH}/api-keys/threatintel \
        api_key="TI-KEY-demo-12345-abcdef" \
        api_secret="TI-SECRET-67890-ghijkl" \
        endpoint="https://api.threatintel.demo/v1" > /dev/null
    
    vault kv put ${CREDENTIALS_PATH}/database/splunk \
        username="splunk_user" \
        password="SplunkP@ss789!" \
        host="splunk.demo.local" \
        port="8089" > /dev/null
    
    vault kv put ${CREDENTIALS_PATH}/email/smtp \
        username="xsoar-notify@demo.local" \
        password="EmailP@ss321!" \
        server="smtp.demo.local" \
        port="587" > /dev/null
    
    log_success "Demo credentials created"
    
    # Create XSOAR policies
    log_step "Creating XSOAR access policies..."
    
    cat > /tmp/xsoar-policy.hcl << 'POLICY'
path "credentials/*" { capabilities = ["read", "list"] }
path "auth/token/renew-self" { capabilities = ["update"] }
path "auth/token/lookup-self" { capabilities = ["read"] }
POLICY
    vault policy write xsoar-credentials /tmp/xsoar-policy.hcl > /dev/null
    
    cat > /tmp/xsoar-rotate-policy.hcl << 'POLICY'
path "credentials/*" { capabilities = ["create", "read", "update", "list", "delete"] }
path "auth/token/renew-self" { capabilities = ["update"] }
path "auth/token/lookup-self" { capabilities = ["read"] }
POLICY
    vault policy write xsoar-rotation /tmp/xsoar-rotate-policy.hcl > /dev/null
    rm /tmp/xsoar-policy.hcl /tmp/xsoar-rotate-policy.hcl
    
    # Create tokens
    XSOAR_TOKEN=$(vault token create -policy="xsoar-credentials" -ttl="768h" -display-name="xsoar-engine" -format=json | jq -r '.auth.client_token')
    ROTATION_TOKEN=$(vault token create -policy="xsoar-rotation" -ttl="768h" -display-name="xsoar-rotation" -format=json | jq -r '.auth.client_token')
    
    cat > /root/xsoar-tokens.txt << EOF
════════════════════════════════════════════════════════════════════
 XSOAR VAULT INTEGRATION TOKENS
════════════════════════════════════════════════════════════════════

 Read-Only Token (for fetching credentials):
 ${XSOAR_TOKEN}

 Rotation Token (for credential management):
 ${ROTATION_TOKEN}

 Vault Address: ${VAULT_ADDR}

════════════════════════════════════════════════════════════════════
 XSOAR INTEGRATION SETTINGS
════════════════════════════════════════════════════════════════════
 Server URL:        ${VAULT_ADDR}
 Auth Method:       Token
 API Version:       v1
 Engine Type:       KV Version 1
 Path:              ${CREDENTIALS_PATH}

════════════════════════════════════════════════════════════════════
EOF
    chmod 600 /root/xsoar-tokens.txt
    log_success "XSOAR policies and tokens created"
    
    # Copy script to system
    log_step "Installing management tool..."
    cp "$0" /usr/local/bin/vault-xsoar
    chmod +x /usr/local/bin/vault-xsoar
    log_success "Tool installed to /usr/local/bin/vault-xsoar"
    
    # Print summary
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}${BOLD}                    ✔ INSTALLATION COMPLETE${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${WHITE}Vault UI:${NC}          ${CYAN}${VAULT_ADDR}/ui${NC}"
    echo ""
    echo -e "${WHITE}Root Token:${NC}        ${YELLOW}${ROOT_TOKEN}${NC}"
    echo -e "${WHITE}Unseal Key:${NC}        ${YELLOW}${UNSEAL_KEY}${NC}"
    echo ""
    echo -e "${WHITE}XSOAR Read Token:${NC}  ${YELLOW}${XSOAR_TOKEN}${NC}"
    echo -e "${WHITE}XSOAR Write Token:${NC} ${YELLOW}${ROTATION_TOKEN}${NC}"
    echo ""
    echo -e "${GRAY}Tokens saved to: /root/xsoar-tokens.txt${NC}"
    echo -e "${GRAY}Environment:      source /root/vault-env.sh${NC}"
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}Quick Commands:${NC}"
    echo -e "  ${CYAN}vault-xsoar list${NC}                    - List all credentials"
    echo -e "  ${CYAN}vault-xsoar get <path>${NC}              - Get a credential"
    echo -e "  ${CYAN}vault-xsoar rotate <path>${NC}           - Rotate a credential"
    echo -e "  ${CYAN}vault-xsoar add <path> <user> <pass>${NC} - Add new credential"
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════════════════════${NC}"
}

#===============================================================================
# UNSEAL Command
#===============================================================================
cmd_unseal() {
    show_mini_logo
    load_vault_env
    
    if [[ -z "${VAULT_UNSEAL_KEY}" ]]; then
        log_error "Unseal key not found. Check /root/vault-env.sh"
        exit 1
    fi
    
    log_step "Unsealing Vault..."
    vault operator unseal "${VAULT_UNSEAL_KEY}" > /dev/null
    log_success "Vault unsealed"
}

#===============================================================================
# STATUS Command
#===============================================================================
cmd_status() {
    show_mini_logo
    load_vault_env
    echo ""
    
    # Service status
    if systemctl is-active --quiet vault 2>/dev/null; then
        echo -e "${GREEN}●${NC} Vault Service: ${GREEN}Running${NC}"
    else
        echo -e "${RED}●${NC} Vault Service: ${RED}Stopped${NC}"
        return
    fi
    
    # Seal status
    local sealed=$(vault status -format=json 2>/dev/null | jq -r '.sealed')
    if [[ "${sealed}" == "false" ]]; then
        echo -e "${GREEN}●${NC} Seal Status:   ${GREEN}Unsealed${NC}"
    else
        echo -e "${YELLOW}●${NC} Seal Status:   ${YELLOW}Sealed${NC}"
        return
    fi
    
    # Connection info
    echo -e "${BLUE}●${NC} Address:       ${VAULT_ADDR}"
    
    # Credentials count
    echo ""
    echo -e "${WHITE}${BOLD}Stored Credentials:${NC}"
    
    local paths=("active-directory" "api-keys" "database" "email")
    for p in "${paths[@]}"; do
        local count=$(vault kv list -format=json ${CREDENTIALS_PATH}/${p} 2>/dev/null | jq -r 'length' 2>/dev/null || echo "0")
        printf "  %-20s %s\n" "${p}/" "${count} entries"
    done
    echo ""
}

#===============================================================================
# LIST Command
#===============================================================================
cmd_list() {
    load_vault_env
    check_vault_ready || exit 1
    
    show_mini_logo
    echo ""
    
    local path=${1:-""}
    local full_path="${CREDENTIALS_PATH}/${path}"
    
    echo -e "${WHITE}${BOLD}📂 Credentials at: ${CYAN}${full_path}/${NC}"
    echo -e "${GRAY}─────────────────────────────────────────${NC}"
    
    local items=$(vault kv list -format=json ${full_path} 2>/dev/null)
    
    if [[ -z "${items}" ]] || [[ "${items}" == "null" ]]; then
        log_warn "No credentials found at this path"
        return
    fi
    
    echo "${items}" | jq -r '.[]' | while read -r item; do
        if [[ "${item}" == */ ]]; then
            echo -e "  ${BLUE}📁${NC} ${item}"
        else
            echo -e "  ${GREEN}🔑${NC} ${item}"
        fi
    done
    echo ""
}

#===============================================================================
# GET Command
#===============================================================================
cmd_get() {
    load_vault_env
    check_vault_ready || exit 1
    
    local path=$1
    local format=${2:-"table"}
    
    if [[ -z "${path}" ]]; then
        log_error "Usage: $SCRIPT_NAME get <path> [json]"
        echo "  Example: $SCRIPT_NAME get active-directory/svc_xsoar"
        exit 1
    fi
    
    show_mini_logo
    echo ""
    
    local full_path="${CREDENTIALS_PATH}/${path}"
    local data=$(vault kv get -format=json ${full_path} 2>/dev/null)
    
    if [[ -z "${data}" ]]; then
        log_error "Credential not found: ${path}"
        exit 1
    fi
    
    if [[ "${format}" == "json" ]]; then
        echo "${data}" | jq '.data'
    else
        echo -e "${WHITE}${BOLD}🔐 Credential: ${CYAN}${path}${NC}"
        echo -e "${GRAY}─────────────────────────────────────────${NC}"
        
        echo "${data}" | jq -r '.data | to_entries | .[] | "  \(.key): \(.value)"' | while read -r line; do
            local key=$(echo "$line" | cut -d: -f1 | xargs)
            local value=$(echo "$line" | cut -d: -f2- | xargs)
            
            if [[ "${key}" == *"password"* ]] || [[ "${key}" == *"secret"* ]] || [[ "${key}" == *"token"* ]]; then
                printf "  ${WHITE}%-18s${NC} ${YELLOW}%s${NC}\n" "${key}:" "${value}"
            else
                printf "  ${WHITE}%-18s${NC} %s\n" "${key}:" "${value}"
            fi
        done
        echo ""
    fi
}

#===============================================================================
# ADD Command
#===============================================================================
cmd_add() {
    load_vault_env
    check_vault_ready || exit 1
    
    local path=$1
    local username=$2
    local password=$3
    
    show_mini_logo
    echo ""
    
    if [[ -z "${path}" ]]; then
        log_error "Usage: $SCRIPT_NAME add <path> [username] [password]"
        echo ""
        echo "  Examples:"
        echo "    $SCRIPT_NAME add active-directory/new-svc myuser mypass"
        echo "    $SCRIPT_NAME add api-keys/newapi  # Interactive mode"
        exit 1
    fi
    
    local full_path="${CREDENTIALS_PATH}/${path}"
    
    # Interactive mode if username not provided
    if [[ -z "${username}" ]]; then
        echo -e "${WHITE}${BOLD}➕ Add New Credential: ${CYAN}${path}${NC}"
        echo -e "${GRAY}─────────────────────────────────────────${NC}"
        
        read -p "  Username: " username
        read -sp "  Password (blank to generate): " password
        echo ""
        
        if [[ -z "${password}" ]]; then
            password=$(generate_password 20)
            echo -e "  ${GREEN}Generated:${NC} ${YELLOW}${password}${NC}"
        fi
        
        read -p "  Description: " description
        
        local extra_fields=""
        while true; do
            read -p "  Add field (name=value, blank to finish): " field
            [[ -z "${field}" ]] && break
            extra_fields="${extra_fields} ${field}"
        done
    fi
    
    local timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    
    log_step "Creating credential..."
    
    if [[ -n "${description}" ]]; then
        vault kv put ${full_path} \
            username="${username}" \
            password="${password}" \
            description="${description}" \
            created_at="${timestamp}" \
            last_rotated="${timestamp}" \
            ${extra_fields} > /dev/null
    else
        vault kv put ${full_path} \
            username="${username}" \
            password="${password}" \
            created_at="${timestamp}" \
            last_rotated="${timestamp}" > /dev/null
    fi
    
    log_success "Credential created: ${path}"
    echo ""
}

#===============================================================================
# ROTATE Command
#===============================================================================
cmd_rotate() {
    load_vault_env
    check_vault_ready || exit 1
    
    local path=$1
    local length=${2:-20}
    
    if [[ -z "${path}" ]]; then
        log_error "Usage: $SCRIPT_NAME rotate <path> [password_length]"
        echo "  Example: $SCRIPT_NAME rotate active-directory/svc_xsoar 24"
        exit 1
    fi
    
    show_mini_logo
    echo ""
    
    local full_path="${CREDENTIALS_PATH}/${path}"
    local timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    
    echo -e "${WHITE}${BOLD}🔄 Rotating Credential: ${CYAN}${path}${NC}"
    echo -e "${GRAY}─────────────────────────────────────────${NC}"
    
    # Get current
    log_step "Fetching current credential..."
    local current=$(vault kv get -format=json ${full_path} 2>/dev/null)
    
    if [[ -z "${current}" ]]; then
        log_error "Credential not found: ${path}"
        exit 1
    fi
    
    local current_data=$(echo "${current}" | jq '.data')
    local current_password=$(echo "${current_data}" | jq -r '.password')
    local username=$(echo "${current_data}" | jq -r '.username // "unknown"')
    local prev_rotation=$(echo "${current_data}" | jq -r '.last_rotated // "never"')
    
    echo -e "  ${WHITE}Username:${NC}          ${username}"
    echo -e "  ${WHITE}Last Rotation:${NC}     ${prev_rotation}"
    
    # Generate new password
    log_step "Generating new password..."
    local new_password=$(generate_password ${length})
    
    # Update
    local updated_data=$(echo "${current_data}" | jq \
        --arg new_pwd "${new_password}" \
        --arg old_pwd "${current_password}" \
        --arg ts "${timestamp}" \
        --arg prev_ts "${prev_rotation}" \
        '.password = $new_pwd | 
         .previous_password = $old_pwd |
         .last_rotated = $ts |
         .previous_rotation = $prev_ts |
         .rotation_count = ((.rotation_count // 0) + 1)')
    
    log_step "Updating credential in Vault..."
    echo "${updated_data}" | vault kv put ${full_path} - > /dev/null
    
    echo ""
    log_success "Credential rotated successfully!"
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}${BOLD}  New Password:${NC} ${YELLOW}${new_password}${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${GRAY}⚠ Remember to update the target system with the new password!${NC}"
    echo ""
    
    # Output JSON for XSOAR if requested
    if [[ "${3}" == "--json" ]]; then
        jq -n \
            --arg path "${path}" \
            --arg username "${username}" \
            --arg password "${new_password}" \
            --arg timestamp "${timestamp}" \
            '{success: true, path: $path, username: $username, new_password: $password, rotated_at: $timestamp}'
    fi
}

#===============================================================================
# DELETE Command
#===============================================================================
cmd_delete() {
    load_vault_env
    check_vault_ready || exit 1
    
    local path=$1
    
    if [[ -z "${path}" ]]; then
        log_error "Usage: $SCRIPT_NAME delete <path>"
        exit 1
    fi
    
    show_mini_logo
    echo ""
    
    local full_path="${CREDENTIALS_PATH}/${path}"
    
    echo -e "${WHITE}${BOLD}🗑️  Delete Credential: ${CYAN}${path}${NC}"
    echo -e "${GRAY}─────────────────────────────────────────${NC}"
    
    read -p "Are you sure you want to delete this credential? [y/N] " confirm
    
    if [[ "${confirm}" != "y" ]] && [[ "${confirm}" != "Y" ]]; then
        log_warn "Cancelled"
        exit 0
    fi
    
    vault kv delete ${full_path} > /dev/null
    log_success "Credential deleted: ${path}"
    echo ""
}

#===============================================================================
# TEST Command
#===============================================================================
cmd_test() {
    load_vault_env
    
    show_mini_logo
    echo ""
    echo -e "${WHITE}${BOLD}🧪 Running Integration Tests${NC}"
    echo -e "${GRAY}─────────────────────────────────────────${NC}"
    echo ""
    
    local passed=0
    local failed=0
    
    # Test 1: Connectivity
    echo -n "  [1/5] Vault connectivity........... "
    if curl -s "${VAULT_ADDR}/v1/sys/health" > /dev/null 2>&1; then
        echo -e "${GREEN}PASS${NC}"
        ((passed++))
    else
        echo -e "${RED}FAIL${NC}"
        ((failed++))
    fi
    
    # Test 2: Service running
    echo -n "  [2/5] Vault service................ "
    if systemctl is-active --quiet vault 2>/dev/null; then
        echo -e "${GREEN}PASS${NC}"
        ((passed++))
    else
        echo -e "${RED}FAIL${NC}"
        ((failed++))
    fi
    
    # Test 3: Unsealed
    echo -n "  [3/5] Vault unsealed............... "
    local sealed=$(vault status -format=json 2>/dev/null | jq -r '.sealed' 2>/dev/null)
    if [[ "${sealed}" == "false" ]]; then
        echo -e "${GREEN}PASS${NC}"
        ((passed++))
    else
        echo -e "${YELLOW}SEALED${NC}"
        ((failed++))
    fi
    
    # Test 4: Authentication
    echo -n "  [4/5] Authentication............... "
    if vault token lookup > /dev/null 2>&1; then
        echo -e "${GREEN}PASS${NC}"
        ((passed++))
    else
        echo -e "${RED}FAIL${NC}"
        ((failed++))
    fi
    
    # Test 5: Read credentials
    echo -n "  [5/5] Read credentials............. "
    if vault kv get ${CREDENTIALS_PATH}/active-directory/svc_xsoar > /dev/null 2>&1; then
        echo -e "${GREEN}PASS${NC}"
        ((passed++))
    else
        echo -e "${RED}FAIL${NC}"
        ((failed++))
    fi
    
    echo ""
    echo -e "${GRAY}─────────────────────────────────────────${NC}"
    
    if [[ ${failed} -eq 0 ]]; then
        echo -e "${GREEN}${BOLD}  ✔ All tests passed! (${passed}/5)${NC}"
        echo ""
        echo -e "${WHITE}  Ready for XSOAR integration.${NC}"
    else
        echo -e "${RED}${BOLD}  ✖ Some tests failed (${passed}/5 passed)${NC}"
    fi
    echo ""
}

#===============================================================================
# XSOAR-INFO Command
#===============================================================================
cmd_xsoar_info() {
    load_vault_env
    
    show_mini_logo
    echo ""
    echo -e "${WHITE}${BOLD}📋 XSOAR Integration Configuration${NC}"
    echo -e "${GRAY}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    if [[ -f /root/xsoar-tokens.txt ]]; then
        cat /root/xsoar-tokens.txt
    else
        echo -e "${WHITE}Server URL:${NC}        ${VAULT_ADDR}"
        echo -e "${WHITE}Auth Method:${NC}       Token"
        echo -e "${WHITE}API Version:${NC}       v1"
        echo -e "${WHITE}Engine Path:${NC}       ${CREDENTIALS_PATH}"
        echo ""
        log_warn "Token file not found. Run 'install' to generate tokens."
    fi
    
    echo ""
    echo -e "${WHITE}${BOLD}XSOAR Commands:${NC}"
    echo -e "${GRAY}─────────────────────────────────────────${NC}"
    echo "  !hashicorp-list-secrets"
    echo "  !hashicorp-get-secret path=active-directory/svc_xsoar"
    echo "  !hashicorp-list-secrets path=active-directory"
    echo ""
}

#===============================================================================
# HELP Command
#===============================================================================
cmd_help() {
    show_logo
    
    echo -e "${WHITE}${BOLD}USAGE${NC}"
    echo -e "  ${CYAN}$SCRIPT_NAME${NC} <command> [options]"
    echo ""
    
    echo -e "${WHITE}${BOLD}INSTALLATION${NC}"
    echo -e "  ${GREEN}install${NC}              Install and configure Vault for XSOAR"
    echo -e "  ${GREEN}unseal${NC}               Unseal Vault after restart"
    echo -e "  ${GREEN}status${NC}               Show Vault status and summary"
    echo -e "  ${GREEN}test${NC}                 Run integration tests"
    echo ""
    
    echo -e "${WHITE}${BOLD}CREDENTIAL MANAGEMENT${NC}"
    echo -e "  ${GREEN}list${NC} [path]          List credentials"
    echo -e "  ${GREEN}get${NC} <path> [json]    Get credential details"
    echo -e "  ${GREEN}add${NC} <path> [u] [p]   Add new credential"
    echo -e "  ${GREEN}rotate${NC} <path> [len]  Rotate credential password"
    echo -e "  ${GREEN}delete${NC} <path>        Delete credential"
    echo ""
    
    echo -e "${WHITE}${BOLD}XSOAR INTEGRATION${NC}"
    echo -e "  ${GREEN}xsoar-info${NC}           Show XSOAR integration details"
    echo ""
    
    echo -e "${WHITE}${BOLD}EXAMPLES${NC}"
    echo -e "  ${GRAY}# Install Vault${NC}"
    echo -e "  sudo $SCRIPT_NAME install"
    echo ""
    echo -e "  ${GRAY}# List all credentials${NC}"
    echo -e "  $SCRIPT_NAME list"
    echo -e "  $SCRIPT_NAME list active-directory"
    echo ""
    echo -e "  ${GRAY}# Get a credential${NC}"
    echo -e "  $SCRIPT_NAME get active-directory/svc_xsoar"
    echo -e "  $SCRIPT_NAME get api-keys/threatintel json"
    echo ""
    echo -e "  ${GRAY}# Add new credential${NC}"
    echo -e "  $SCRIPT_NAME add active-directory/new-svc admin SecureP@ss123"
    echo -e "  $SCRIPT_NAME add api-keys/newapi  ${GRAY}# Interactive mode${NC}"
    echo ""
    echo -e "  ${GRAY}# Rotate password${NC}"
    echo -e "  $SCRIPT_NAME rotate active-directory/svc_xsoar"
    echo -e "  $SCRIPT_NAME rotate active-directory/svc_xsoar 24  ${GRAY}# 24 char password${NC}"
    echo ""
    
    echo -e "${WHITE}${BOLD}ENVIRONMENT VARIABLES${NC}"
    echo -e "  ${CYAN}VAULT_ADDR${NC}           Vault server address"
    echo -e "  ${CYAN}VAULT_TOKEN${NC}          Authentication token"
    echo ""
}

#===============================================================================
# Main Entry Point
#===============================================================================
main() {
    local command=${1:-help}
    shift 2>/dev/null || true
    
    case "${command}" in
        install)     cmd_install "$@" ;;
        unseal)      cmd_unseal "$@" ;;
        status)      cmd_status "$@" ;;
        test)        cmd_test "$@" ;;
        list|ls)     cmd_list "$@" ;;
        get|show)    cmd_get "$@" ;;
        add|create)  cmd_add "$@" ;;
        rotate)      cmd_rotate "$@" ;;
        delete|rm)   cmd_delete "$@" ;;
        xsoar-info)  cmd_xsoar_info "$@" ;;
        help|--help|-h) cmd_help ;;
        version|--version|-v) 
            show_mini_logo
            echo -e "  Version: ${VERSION}"
            echo ""
            ;;
        *)
            log_error "Unknown command: ${command}"
            echo "Run '$SCRIPT_NAME help' for usage."
            exit 1
            ;;
    esac
}

main "$@"
