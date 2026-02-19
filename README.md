# 🔐 Zscaler SSL Certificate Fix

**One script to fix `SELF_SIGNED_CERT_IN_CHAIN` errors across all dev tools — on macOS, Linux, and Windows.**

If you work behind Zscaler (or any corporate SSL-inspecting proxy) and you've hit certificate errors in Node.js, Python, Claude Code, Git, npm, curl, or AWS CLI — this repo fixes all of them in a single run.

---

## Quick Start

### macOS
```bash
curl -fsSL https://raw.githubusercontent.com/AskRaaj/zscaler-ssl-fix/main/scripts/fix-zscaler-ssl-macos.sh -o fix.sh
chmod +x fix.sh && ./fix.sh
```

### Linux (Ubuntu/Debian, RHEL/Fedora, Arch)
```bash
curl -fsSL https://raw.githubusercontent.com/AskRaaj/zscaler-ssl-fix/main/scripts/fix-zscaler-ssl-linux.sh -o fix.sh
chmod +x fix.sh && ./fix.sh
```

### Windows (PowerShell)
```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/AskRaaj/zscaler-ssl-fix/main/scripts/fix-zscaler-ssl-windows.ps1" -OutFile fix.ps1
powershell -ExecutionPolicy Bypass -File fix.ps1
```

---

## What It Fixes

| Error Message | Affected Tools |
|---|---|
| `SELF_SIGNED_CERT_IN_CHAIN` | Node.js, npm, Claude Code, Git |
| `UNABLE_TO_GET_ISSUER_CERT_LOCALLY` | Bun, Claude Code, VS Code extensions |
| `unable to get local issuer certificate` | curl, Python requests, AWS CLI |
| `SSL: CERTIFICATE_VERIFY_FAILED` | Python, pip, conda |
| `OAuth error: self signed certificate` | Claude Code `/login` |

---

## What It Does

Each script runs through 5 phases:

### Phase 1: Extract the Zscaler Root CA
- **macOS**: Searches Keychain Access (System, login, SystemRootCertificates)
- **Linux**: Searches `/usr/local/share/ca-certificates`, `/etc/pki/ca-trust/source/anchors`, and common file locations
- **Windows**: Searches the Windows Certificate Store (LocalMachine\Root, CurrentUser\Root)
- **All**: Falls back to extracting from a live TLS handshake via `openssl s_client`

### Phase 2: Create Combined CA Bundle
Concatenates your system's default CA certificates with the Zscaler root cert, so both public CAs and your corporate CA are trusted simultaneously.

### Phase 3: Configure Developer Tools
| Tool | Configuration |
|---|---|
| Git | `git config --global http.sslCAInfo` |
| npm | `npm config set cafile` |
| yarn | `yarn config set httpsCaFilePath` (v2+) or `cafile` (v1) |
| pip | `pip config set global.cert` |
| conda | `conda config --set ssl_verify` |
| Claude Code | `~/.claude/settings.json` → `env` block |
| VS Code | `settings.json` → `ClaudeCode.environmentVariables` |

### Phase 4: Set Environment Variables
| Variable | Runtime |
|---|---|
| `NODE_EXTRA_CA_CERTS` | Node.js |
| `NODE_USE_SYSTEM_CA=1` | **Bun / Claude Code** (the critical one) |
| `SSL_CERT_FILE` | Python, OpenSSL |
| `REQUESTS_CA_BUNDLE` | Python `requests` |
| `CURL_CA_BUNDLE` | curl |
| `AWS_CA_BUNDLE` | AWS CLI / SDK |
| `HOMEBREW_CA_CERTIFICATES` | Homebrew (macOS) |

On macOS, also sets via `launchctl` for GUI apps (Claude Desktop, VS Code from Dock).  
On Windows, sets as persistent User environment variables.

### Phase 5: Verify
Runs connectivity tests against `api.anthropic.com` using OpenSSL, curl, Node.js, Python, and Bun.

---

## Why Standard Fixes Don't Work for Claude Code

This is the key insight that most guides miss.

Starting with **v2.1.17**, Claude Code switched from a standard Node.js build to a native binary compiled with the **Bun runtime**. Bun has its own TLS stack that doesn't reliably respect `NODE_EXTRA_CA_CERTS`. This means you can have:

- ✅ OpenSSL verification passing  
- ✅ `curl` working perfectly  
- ✅ Node.js `fetch()` succeeding  
- ❌ **Claude Code still failing**

### The Fix

```bash
export NODE_USE_SYSTEM_CA=1
```

This tells the Bun runtime to load certificates from your **OS trust store** (macOS Keychain / Windows Certificate Store / Linux system CAs) instead of its bundled certificates. Combined with `NODE_EXTRA_CA_CERTS` for standard Node.js, this covers both runtimes.

This is an actively tracked issue across multiple GitHub issues:
- [#25084](https://github.com/anthropics/claude-code/issues/25084) — SELF_SIGNED_CERT_IN_CHAIN in VS Code extension
- [#25977](https://github.com/anthropics/claude-code/issues/25977) — WebFetch SSL error behind Zscaler (Bun ignores NODE_EXTRA_CA_CERTS)
- [#24470](https://github.com/anthropics/claude-code/issues/24470) — Self-signed certificate in Cowork
- [#22559](https://github.com/anthropics/claude-code/issues/22559) — Desktop app doesn't forward NODE_EXTRA_CA_CERTS to CLI

---

## Why This Happens

When your company uses Zscaler for SSL inspection, it acts as a man-in-the-middle for all HTTPS traffic:

```
Your app → Zscaler proxy → api.anthropic.com
```

Zscaler decrypts traffic, inspects it, re-encrypts it with **its own root certificate**. Your browser trusts this because IT installed Zscaler's CA into your system trust store. But developer tools use their own bundled CA stores and don't recognize Zscaler's certificate.

---

## What NOT to Do

❌ **`NODE_TLS_REJECT_UNAUTHORIZED=0`** — Disables ALL certificate validation. Opens you to real MITM attacks.

❌ **`verify=False` in Python** — Same problem at the application level.

❌ **Assume one env var covers everything** — Node.js ignores `SSL_CERT_FILE`. Python ignores `NODE_EXTRA_CA_CERTS`. Bun may ignore both. You need all of them.

---

## Works With Other Proxies Too

The same approach works for any SSL-inspecting proxy:
- **Netskope**
- **Palo Alto GlobalProtect**
- **Fortinet FortiGate**
- **Blue Coat / Symantec**
- **McAfee Web Gateway**

Just substitute the root CA certificate.

---

## Troubleshooting

**Script ran fine but Claude Code still fails?**  
Restart your terminal AND the Claude Desktop app. GUI apps won't pick up env vars until relaunched.

**Permission denied on Keychain (macOS)?**  
Export manually from Keychain Access, or run with `sudo`.

**Different cert name?**  
Open your cert manager, search for your proxy name, and export manually to `~/.zscaler-certs/zscaler-root-ca.pem`.

**WSL users?**  
Copy the cert into WSL and run the Linux script. The Windows cert store is not accessible from WSL by default.

---

## File Structure

```
zscaler-ssl-fix/
├── README.md
├── LICENSE
└── scripts/
    ├── fix-zscaler-ssl-macos.sh       # macOS (bash)
    ├── fix-zscaler-ssl-linux.sh        # Linux (bash)
    └── fix-zscaler-ssl-windows.ps1     # Windows (PowerShell)
```

---

## Contributing

PRs welcome! Particularly for:
- Additional proxy vendors
- Package managers (pnpm, bun install, cargo, etc.)
- CI/CD environments (GitHub Actions, GitLab CI behind corporate proxy)

---

## License

MIT — see [LICENSE](LICENSE)

---

*Created by [Raajkumar Subramaniam.](https://linkedin.com/in/raajkumar) · Founder of [QwickApps](https://qwickapps.com) · Former Senior SWE at Google · AI/ML solutions & cybersecurity training for U.S. government teams.*
