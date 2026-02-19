#!/bin/bash
# ============================================================================
# fix-zscaler-ssl-macos.sh v2.0
#
# Fixes "self signed certificate in certificate chain" errors caused by
# Zscaler (or similar corporate SSL inspection proxies) on macOS.
#
# Covers: Node.js, Bun, Claude Code, Python, Git, npm, yarn, curl, AWS CLI,
#         Docker, VS Code extensions, and GUI apps.
#
# Usage:  chmod +x fix-zscaler-ssl-macos.sh && ./fix-zscaler-ssl-macos.sh
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

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║     Zscaler SSL Certificate Fix for macOS  (v2.0)      ║"
echo "║                                                        ║"
echo "║  Fixes: Node.js · Bun · Claude Code · Python · Git     ║"
echo "║         npm · yarn · curl · AWS CLI · VS Code · more   ║"
echo "╚══════════════════════════════════════════════════════════╝"

# =========================================================================
# PHASE 1: Extract Zscaler Root CA
# =========================================================================
section "Phase 1: Extracting Zscaler Root CA"

mkdir -p "$CERT_DIR"
ZSCALER_FOUND=false

# Method 1: Search macOS Keychain
for CERT_NAME in \
    "Zscaler Root CA" \
    "ZscalerRootCertificate-2048-SHA256" \
    "Zscaler Intermediate Root CA" \
    "Zscaler"; do
    for KEYCHAIN in \
        /Library/Keychains/System.keychain \
        ~/Library/Keychains/login.keychain-db \
        /System/Library/Keychains/SystemRootCertificates.keychain; do
        if [ -f "$KEYCHAIN" ] && \
           security find-certificate -c "$CERT_NAME" -a "$KEYCHAIN" > /dev/null 2>&1; then
            security find-certificate -c "$CERT_NAME" -a -p "$KEYCHAIN" > "$ZSCALER_CERT"
            log_ok "Found '${CERT_NAME}' in $(basename "$KEYCHAIN")"
            ZSCALER_FOUND=true
            break 2
        fi
    done
done

# Method 2: Extract from live TLS handshake
if [ "$ZSCALER_FOUND" = false ]; then
    log_warn "Not found in Keychain — trying live TLS extraction..."
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
    echo "  Export manually from Keychain Access → Save to: $ZSCALER_CERT"
    exit 1
fi

echo ""
openssl x509 -in "$ZSCALER_CERT" -noout -subject -issuer -dates 2>/dev/null | sed 's/^/  /'

# =========================================================================
# PHASE 2: Create combined CA bundle
# =========================================================================
section "Phase 2: Creating combined CA bundle"

SYSTEM_CA=""
for CA_PATH in /etc/ssl/cert.pem /usr/local/etc/openssl@3/cert.pem \
    /opt/homebrew/etc/openssl@3/cert.pem /usr/local/etc/openssl/cert.pem \
    /opt/homebrew/etc/openssl/cert.pem; do
    [ -f "$CA_PATH" ] && { SYSTEM_CA="$CA_PATH"; break; }
done

if [ -n "$SYSTEM_CA" ]; then
    cat "$SYSTEM_CA" "$ZSCALER_CERT" > "$COMBINED_BUNDLE"
    log_ok "Combined bundle created (system + Zscaler)"
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

# VS Code
VSCODE_SETTINGS="$HOME/Library/Application Support/Code/User/settings.json"
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

# =========================================================================
# PHASE 4: Shell environment variables
# =========================================================================
section "Phase 4: Setting environment variables"

SHELL_NAME=$(basename "$SHELL")
case "$SHELL_NAME" in
    zsh)  PROFILE="$HOME/.zshrc" ;;
    bash) PROFILE="$HOME/.bash_profile" ;;
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
# curl / AWS / Homebrew
export CURL_CA_BUNDLE="'"$COMBINED_BUNDLE"'"
export AWS_CA_BUNDLE="'"$COMBINED_BUNDLE"'"
export HOMEBREW_CA_CERTIFICATES="'"$COMBINED_BUNDLE"'"
# === End Zscaler Fix ==='

# Replace old block if present
if grep -q "Zscaler SSL Certificate Fix" "$PROFILE" 2>/dev/null; then
    sed -i '' '/# === Zscaler SSL Certificate Fix/,/# === End Zscaler Fix ===/d' "$PROFILE"
fi
echo "$ENV_BLOCK" >> "$PROFILE"
log_ok "Updated $PROFILE"

# GUI apps
echo ""
echo -e "  ${BOLD}── GUI apps (launchctl) ──${NC}"
for VAR in NODE_EXTRA_CA_CERTS SSL_CERT_FILE REQUESTS_CA_BUNDLE CURL_CA_BUNDLE AWS_CA_BUNDLE; do
    launchctl setenv "$VAR" "$COMBINED_BUNDLE" 2>/dev/null && log_ok "launchctl $VAR" || log_warn "launchctl $VAR"
done
launchctl setenv NODE_USE_SYSTEM_CA 1 2>/dev/null && log_ok "launchctl NODE_USE_SYSTEM_CA" || true

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
echo "║    1. source ~/${SHELL_NAME}rc                                  ║"
echo "║    2. Restart VS Code / Claude Desktop                 ║"
echo "║    3. claude /login                                    ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
