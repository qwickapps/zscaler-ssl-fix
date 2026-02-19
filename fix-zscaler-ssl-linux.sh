#!/bin/bash
# ============================================================================
# fix-zscaler-ssl-linux.sh v2.0
#
# Fixes "self signed certificate in certificate chain" errors caused by
# Zscaler (or similar corporate SSL inspection proxies) on Linux.
#
# Supports: Ubuntu/Debian, RHEL/Fedora/CentOS, Arch, and generic Linux.
# Covers:   Node.js, Bun, Claude Code, Python, Git, npm, yarn, curl,
#           AWS CLI, Docker, VS Code, and system CA trust store.
#
# Usage:  chmod +x fix-zscaler-ssl-linux.sh && ./fix-zscaler-ssl-linux.sh
# Repo:   https://github.com/AskRaaj/zscaler-ssl-fix
# ============================================================================

set -euo pipefail

CERT_DIR="$HOME/.zscaler-certs"
ZSCALER_CERT="$CERT_DIR/zscaler-root-ca.pem"
COMBINED_BUNDLE="$CERT_DIR/ca-bundle-with-zscaler.pem"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'

log_ok()   { echo -e "  ${GREEN}✓${NC} $1"; }
log_warn() { echo -e "  ${YELLOW}⚠${NC}  $1"; }
log_fail() { echo -e "  ${RED}✗${NC} $1"; }
log_info() { echo -e "  ${BLUE}ℹ${NC} $1"; }
section()  { echo -e "\n${BOLD}$1${NC}"; }

# Detect distro family
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        case "$ID" in
            ubuntu|debian|linuxmint|pop) echo "debian" ;;
            rhel|centos|fedora|rocky|alma|ol) echo "rhel" ;;
            arch|manjaro|endeavouros) echo "arch" ;;
            *) echo "unknown" ;;
        esac
    elif [ -f /etc/debian_version ]; then
        echo "debian"
    elif [ -f /etc/redhat-release ]; then
        echo "rhel"
    else
        echo "unknown"
    fi
}

DISTRO=$(detect_distro)
DISTRO_NAME="Linux"
[ -f /etc/os-release ] && . /etc/os-release && DISTRO_NAME="${PRETTY_NAME:-Linux}"

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║     Zscaler SSL Certificate Fix for Linux  (v2.0)      ║"
echo "║                                                        ║"
echo "║  Fixes: Node.js · Bun · Claude Code · Python · Git     ║"
echo "║         npm · yarn · curl · AWS CLI · VS Code · more   ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
log_info "Detected: $DISTRO_NAME ($DISTRO family)"

# =========================================================================
# PHASE 1: Extract Zscaler Root CA
# =========================================================================
section "Phase 1: Extracting Zscaler Root CA"

mkdir -p "$CERT_DIR"
ZSCALER_FOUND=false

# Method 1: Check if cert is already in system trust store
for SEARCH_DIR in \
    /usr/local/share/ca-certificates \
    /etc/pki/ca-trust/source/anchors \
    /usr/share/pki/trust/anchors \
    /etc/ca-certificates/trust-source/anchors; do
    if [ -d "$SEARCH_DIR" ]; then
        FOUND_FILE=$(find "$SEARCH_DIR" -iname "*zscaler*" -print -quit 2>/dev/null || true)
        if [ -n "$FOUND_FILE" ]; then
            cp "$FOUND_FILE" "$ZSCALER_CERT"
            log_ok "Found Zscaler cert in system store: $FOUND_FILE"
            ZSCALER_FOUND=true
            break
        fi
    fi
done

# Method 2: Check common IT drop locations
if [ "$ZSCALER_FOUND" = false ]; then
    for LOC in /tmp/zscaler*.pem /tmp/zscaler*.crt /opt/zscaler/cert*.pem \
               "$HOME/zscaler"*.pem "$HOME/zscaler"*.crt "$HOME/Downloads/zscaler"*.pem; do
        for F in $LOC; do
            if [ -f "$F" ]; then
                cp "$F" "$ZSCALER_CERT"
                log_ok "Found Zscaler cert at: $F"
                ZSCALER_FOUND=true
                break 2
            fi
        done
    done
fi

# Method 3: Extract from live TLS handshake
if [ "$ZSCALER_FOUND" = false ]; then
    log_warn "Not found locally — trying live TLS extraction..."
    LAST_CERT=$(echo | openssl s_client -connect api.anthropic.com:443 -showcerts 2>/dev/null | awk '
        /BEGIN CERTIFICATE/ { cert="" ; collecting=1 }
        collecting { cert = cert $0 "\n" }
        /END CERTIFICATE/ { last = cert; collecting=0 }
        END { printf "%s", last }
    ')
    if [ -n "$LAST_CERT" ]; then
        echo "$LAST_CERT" > "$ZSCALER_CERT"
        SUBJECT=$(echo "$LAST_CERT" | openssl x509 -noout -subject 2>/dev/null || echo "unknown")
        if echo "$SUBJECT" | grep -iq zscaler; then
            log_ok "Extracted Zscaler cert from TLS handshake"
            ZSCALER_FOUND=true
        else
            log_warn "Root cert found: $SUBJECT"
            read -p "  Use this cert? (y/n): " CONFIRM
            [[ "$CONFIRM" =~ ^[yY] ]] && ZSCALER_FOUND=true || { log_fail "Aborted."; exit 1; }
        fi
    fi
fi

if [ "$ZSCALER_FOUND" = false ]; then
    log_fail "Could not find Zscaler certificate."
    echo "  Please obtain it from your IT team and save to: $ZSCALER_CERT"
    exit 1
fi

echo ""
openssl x509 -in "$ZSCALER_CERT" -noout -subject -issuer -dates 2>/dev/null | sed 's/^/  /'

# =========================================================================
# PHASE 2: Install to system trust store + create combined bundle
# =========================================================================
section "Phase 2: Installing to system trust store"

NEED_SUDO=false

case "$DISTRO" in
    debian)
        DEST="/usr/local/share/ca-certificates/zscaler-root-ca.crt"
        if [ ! -f "$DEST" ] || ! diff -q "$ZSCALER_CERT" "$DEST" &>/dev/null; then
            log_info "Installing to system CA store (requires sudo)..."
            sudo cp "$ZSCALER_CERT" "$DEST"
            sudo update-ca-certificates
            log_ok "System trust store updated (update-ca-certificates)"
        else
            log_ok "Already in system trust store"
        fi
        ;;
    rhel)
        DEST="/etc/pki/ca-trust/source/anchors/zscaler-root-ca.pem"
        if [ ! -f "$DEST" ] || ! diff -q "$ZSCALER_CERT" "$DEST" &>/dev/null; then
            log_info "Installing to system CA store (requires sudo)..."
            sudo cp "$ZSCALER_CERT" "$DEST"
            sudo update-ca-trust extract
            log_ok "System trust store updated (update-ca-trust)"
        else
            log_ok "Already in system trust store"
        fi
        ;;
    arch)
        DEST="/etc/ca-certificates/trust-source/anchors/zscaler-root-ca.crt"
        if [ ! -f "$DEST" ] || ! diff -q "$ZSCALER_CERT" "$DEST" &>/dev/null; then
            log_info "Installing to system CA store (requires sudo)..."
            sudo cp "$ZSCALER_CERT" "$DEST"
            sudo trust extract-compat
            log_ok "System trust store updated (trust extract-compat)"
        else
            log_ok "Already in system trust store"
        fi
        ;;
    *)
        log_warn "Unknown distro — skipping system trust store install"
        log_info "Manually install: sudo cp $ZSCALER_CERT /usr/local/share/ca-certificates/ && sudo update-ca-certificates"
        ;;
esac

section "Phase 2b: Creating combined CA bundle"

SYSTEM_CA=""
for CA_PATH in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt \
    /etc/ssl/ca-bundle.pem /etc/ssl/cert.pem; do
    [ -f "$CA_PATH" ] && { SYSTEM_CA="$CA_PATH"; break; }
done

if [ -n "$SYSTEM_CA" ]; then
    cat "$SYSTEM_CA" "$ZSCALER_CERT" > "$COMBINED_BUNDLE"
    log_ok "Combined bundle created"
    log_info "System CAs from: $SYSTEM_CA"
else
    cp "$ZSCALER_CERT" "$COMBINED_BUNDLE"
    log_warn "System CA bundle not found — using Zscaler cert only"
fi

# =========================================================================
# PHASE 3: Configure tools
# =========================================================================
section "Phase 3: Configuring tools"

echo ""
echo -e "  ${BOLD}── CLI Tools ──${NC}"

command -v git &>/dev/null && { git config --global http.sslCAInfo "$COMBINED_BUNDLE" 2>/dev/null; log_ok "Git"; } || log_warn "Git — not found"
command -v npm &>/dev/null && { npm config set cafile "$COMBINED_BUNDLE" 2>/dev/null; log_ok "npm"; } || log_warn "npm — not found"

if command -v yarn &>/dev/null; then
    if yarn --version 2>/dev/null | grep -q "^1\."; then
        yarn config set cafile "$COMBINED_BUNDLE" 2>/dev/null
    else
        yarn config set httpsCaFilePath "$COMBINED_BUNDLE" 2>/dev/null
    fi
    log_ok "yarn"
fi

command -v pip3 &>/dev/null && { pip3 config set global.cert "$COMBINED_BUNDLE" 2>/dev/null; log_ok "pip"; } || log_warn "pip — not found"
command -v conda &>/dev/null && { conda config --set ssl_verify "$COMBINED_BUNDLE" 2>/dev/null; log_ok "conda"; } || log_warn "conda — not found"

echo ""
echo -e "  ${BOLD}── Claude Code ──${NC}"

CLAUDE_SETTINGS="$HOME/.claude/settings.json"
mkdir -p "$HOME/.claude"
python3 - "$CLAUDE_SETTINGS" "$COMBINED_BUNDLE" << 'PYEOF'
import json, sys
path, cert = sys.argv[1], sys.argv[2]
try:
    with open(path) as f: settings = json.load(f)
except: settings = {}
settings.setdefault("env", {})
settings["env"]["NODE_EXTRA_CA_CERTS"] = cert
settings["env"]["SSL_CERT_FILE"] = cert
settings["env"]["NODE_USE_SYSTEM_CA"] = "1"
with open(path, "w") as f: json.dump(settings, f, indent=2)
PYEOF
log_ok "Claude Code CLI (~/.claude/settings.json)"

# VS Code (Linux paths)
VSCODE_SETTINGS="$HOME/.config/Code/User/settings.json"
if [ -f "$VSCODE_SETTINGS" ]; then
    python3 - "$VSCODE_SETTINGS" "$COMBINED_BUNDLE" << 'PYEOF'
import json, sys
path, cert = sys.argv[1], sys.argv[2]
try:
    with open(path) as f: settings = json.load(f)
except: settings = {}
for key in ["claude-dev.environmentVariables", "ClaudeCode.environmentVariables"]:
    settings.setdefault(key, {})
    if isinstance(settings[key], dict):
        settings[key]["NODE_EXTRA_CA_CERTS"] = cert
        settings[key]["SSL_CERT_FILE"] = cert
        settings[key]["NODE_USE_SYSTEM_CA"] = "1"
with open(path, "w") as f: json.dump(settings, f, indent=2)
PYEOF
    log_ok "VS Code — Claude Code extension"
else
    log_warn "VS Code settings not found, skipping"
fi

echo ""
echo -e "  ${BOLD}── Docker ──${NC}"
if command -v docker &>/dev/null; then
    log_info "Mount in containers: -v $COMBINED_BUNDLE:/etc/ssl/certs/ca-certificates.crt:ro"
    log_info "Or in Dockerfile:"
    echo "         COPY zscaler-root-ca.pem /usr/local/share/ca-certificates/zscaler.crt"
    echo "         RUN update-ca-certificates"
else
    log_warn "Docker — not found"
fi

# =========================================================================
# PHASE 4: Shell environment variables
# =========================================================================
section "Phase 4: Setting environment variables"

SHELL_NAME=$(basename "$SHELL")
case "$SHELL_NAME" in
    zsh)  PROFILE="$HOME/.zshrc" ;;
    bash) PROFILE="$HOME/.bashrc" ;;
    *)    PROFILE="$HOME/.profile" ;;
esac

ENV_BLOCK='
# === Zscaler SSL Certificate Fix (v2.0) ===
# Node.js
export NODE_EXTRA_CA_CERTS="'"$COMBINED_BUNDLE"'"
# Bun runtime (Claude Code v2.1.17+)
export NODE_USE_SYSTEM_CA=1
# Python
export SSL_CERT_FILE="'"$COMBINED_BUNDLE"'"
export REQUESTS_CA_BUNDLE="'"$COMBINED_BUNDLE"'"
# curl / AWS
export CURL_CA_BUNDLE="'"$COMBINED_BUNDLE"'"
export AWS_CA_BUNDLE="'"$COMBINED_BUNDLE"'"
# === End Zscaler Fix ==='

if grep -q "Zscaler SSL Certificate Fix" "$PROFILE" 2>/dev/null; then
    sed -i '/# === Zscaler SSL Certificate Fix/,/# === End Zscaler Fix ===/d' "$PROFILE"
fi
echo "$ENV_BLOCK" >> "$PROFILE"
log_ok "Updated $PROFILE"

# Also add to .profile for login shells if using bash
if [ "$SHELL_NAME" = "bash" ] && [ -f "$HOME/.profile" ]; then
    if ! grep -q "Zscaler SSL Certificate Fix" "$HOME/.profile" 2>/dev/null; then
        echo "$ENV_BLOCK" >> "$HOME/.profile"
        log_ok "Updated ~/.profile (login shells)"
    fi
fi

# Export for current session
export NODE_EXTRA_CA_CERTS="$COMBINED_BUNDLE" SSL_CERT_FILE="$COMBINED_BUNDLE"
export REQUESTS_CA_BUNDLE="$COMBINED_BUNDLE" CURL_CA_BUNDLE="$COMBINED_BUNDLE"
export AWS_CA_BUNDLE="$COMBINED_BUNDLE" NODE_USE_SYSTEM_CA=1

# =========================================================================
# PHASE 5: Verification
# =========================================================================
section "Phase 5: Verification"
echo ""

PASS=0; FAIL=0

VERIFY=$(openssl s_client -connect api.anthropic.com:443 -CAfile "$COMBINED_BUNDLE" < /dev/null 2>&1 | grep "Verify return code" || true)
echo "$VERIFY" | grep -q "0 (ok)" && { log_ok "OpenSSL ✓"; ((PASS++)); } || { log_fail "OpenSSL: $VERIFY"; ((FAIL++)); }

if command -v curl &>/dev/null; then
    HTTP=$(curl -s -o /dev/null -w "%{http_code}" --cacert "$COMBINED_BUNDLE" https://api.anthropic.com 2>/dev/null || echo "000")
    [ "$HTTP" != "000" ] && { log_ok "curl (HTTP $HTTP) ✓"; ((PASS++)); } || { log_fail "curl failed"; ((FAIL++)); }
fi

if command -v node &>/dev/null; then
    NR=$(NODE_EXTRA_CA_CERTS="$COMBINED_BUNDLE" node -e "fetch('https://api.anthropic.com').then(r=>console.log('HTTP '+r.status)).catch(e=>console.log('FAIL:'+e.code))" 2>/dev/null || echo "FAIL")
    echo "$NR" | grep -q "HTTP" && { log_ok "Node.js ($NR) ✓"; ((PASS++)); } || { log_fail "Node.js: $NR"; ((FAIL++)); }
fi

if command -v python3 &>/dev/null; then
    PR=$(SSL_CERT_FILE="$COMBINED_BUNDLE" python3 -c "
import urllib.request,ssl
r=urllib.request.urlopen('https://api.anthropic.com',context=ssl.create_default_context(cafile='$COMBINED_BUNDLE'))
print('HTTP',r.status)" 2>/dev/null || echo "FAIL")
    echo "$PR" | grep -q "HTTP" && { log_ok "Python ($PR) ✓"; ((PASS++)); } || { log_fail "Python"; ((FAIL++)); }
fi

if command -v bun &>/dev/null; then
    BR=$(NODE_USE_SYSTEM_CA=1 bun -e "fetch('https://api.anthropic.com').then(r=>console.log('HTTP '+r.status)).catch(e=>console.log('FAIL:'+e.code))" 2>/dev/null || echo "FAIL")
    echo "$BR" | grep -q "HTTP" && { log_ok "Bun ($BR) ✓"; ((PASS++)); } || { log_fail "Bun: $BR"; ((FAIL++)); }
fi

TOTAL=$((PASS + FAIL))
echo ""
echo "╔══════════════════════════════════════════════════════════╗"
[ "$FAIL" -eq 0 ] && echo -e "║  ${GREEN}ALL DONE — $PASS/$TOTAL checks passed${NC}                         ║" \
                   || echo -e "║  ${YELLOW}DONE — $PASS/$TOTAL passed, $FAIL failed${NC}                          ║"
echo "╠══════════════════════════════════════════════════════════╣"
echo -e "║  ${YELLOW}Next steps:${NC}                                            ║"
echo "║    1. source $PROFILE                                  ║"
echo "║    2. Restart VS Code / Claude Desktop                 ║"
echo "║    3. claude /login                                    ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
