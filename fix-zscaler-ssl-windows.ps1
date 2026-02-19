# ============================================================================
# fix-zscaler-ssl-windows.ps1 v2.0
#
# Fixes "self signed certificate in certificate chain" errors caused by
# Zscaler (or similar corporate SSL inspection proxies) on Windows.
#
# Covers: Node.js, Bun, Claude Code, Python, Git, npm, yarn, curl, AWS CLI,
#         WSL, VS Code extensions.
#
# Usage:  Right-click → Run with PowerShell (or run as Admin for system-wide)
#         powershell -ExecutionPolicy Bypass -File fix-zscaler-ssl-windows.ps1
#
# Repo:   https://github.com/AskRaaj/zscaler-ssl-fix
# ============================================================================

$ErrorActionPreference = "Continue"

$CertDir = "$env:USERPROFILE\.zscaler-certs"
$ZscalerCert = "$CertDir\zscaler-root-ca.pem"
$CombinedBundle = "$CertDir\ca-bundle-with-zscaler.pem"

function Write-Ok   { param($msg) Write-Host "  ✓ $msg" -ForegroundColor Green }
function Write-Warn { param($msg) Write-Host "  ⚠  $msg" -ForegroundColor Yellow }
function Write-Fail { param($msg) Write-Host "  ✗ $msg" -ForegroundColor Red }
function Write-Info { param($msg) Write-Host "  ℹ $msg" -ForegroundColor Cyan }
function Write-Section { param($msg) Write-Host "`n$msg" -ForegroundColor White -BackgroundColor DarkGray }

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║    Zscaler SSL Certificate Fix for Windows  (v2.0)     ║" -ForegroundColor Cyan
Write-Host "║                                                        ║" -ForegroundColor Cyan
Write-Host "║  Fixes: Node.js · Bun · Claude Code · Python · Git     ║" -ForegroundColor Cyan
Write-Host "║         npm · yarn · curl · AWS CLI · VS Code · WSL    ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

# =========================================================================
# PHASE 1: Extract Zscaler Root CA from Windows Certificate Store
# =========================================================================
Write-Section " Phase 1: Extracting Zscaler Root CA"

if (-not (Test-Path $CertDir)) { New-Item -ItemType Directory -Path $CertDir -Force | Out-Null }

$ZscalerFound = $false

# Search Windows cert stores for Zscaler
$SearchNames = @("Zscaler Root CA", "ZscalerRootCertificate-2048-SHA256",
                 "Zscaler Intermediate Root CA", "Zscaler")
$StoreLocations = @("LocalMachine", "CurrentUser")
$StoreNames = @("Root", "CA", "AuthRoot")

foreach ($StoreLoc in $StoreLocations) {
    foreach ($StoreName in $StoreNames) {
        try {
            $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($StoreName, $StoreLoc)
            $store.Open("ReadOnly")
            foreach ($SearchName in $SearchNames) {
                $certs = $store.Certificates | Where-Object {
                    $_.Subject -like "*$SearchName*" -or
                    $_.Issuer -like "*$SearchName*" -or
                    $_.FriendlyName -like "*$SearchName*"
                }
                if ($certs -and $certs.Count -gt 0) {
                    $cert = $certs[0]
                    # Export as PEM
                    $base64 = [Convert]::ToBase64String($cert.RawData, "InsertLineBreaks")
                    $pem = "-----BEGIN CERTIFICATE-----`n$base64`n-----END CERTIFICATE-----"
                    $pem | Out-File -FilePath $ZscalerCert -Encoding ASCII -NoNewline
                    Write-Ok "Found '$($cert.Subject)' in $StoreLoc\$StoreName"
                    $ZscalerFound = $true
                    $store.Close()
                    break
                }
            }
            $store.Close()
            if ($ZscalerFound) { break }
        } catch {
            # Skip stores we can't access
        }
    }
    if ($ZscalerFound) { break }
}

# Method 2: Try live TLS extraction
if (-not $ZscalerFound) {
    Write-Warn "Not found in cert stores — trying live TLS extraction..."
    try {
        $output = echo "" | openssl s_client -connect api.anthropic.com:443 -showcerts 2>&1
        # Extract last cert in chain (the root)
        $certs = [regex]::Matches($output, "-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----")
        if ($certs.Count -gt 0) {
            $lastCert = $certs[$certs.Count - 1].Value
            $lastCert | Out-File -FilePath $ZscalerCert -Encoding ASCII -NoNewline
            $subject = echo $lastCert | openssl x509 -noout -subject 2>&1
            if ($subject -match "(?i)zscaler") {
                Write-Ok "Extracted Zscaler cert from TLS handshake"
                $ZscalerFound = $true
            } else {
                Write-Warn "Root cert found: $subject"
                $confirm = Read-Host "  Use this cert? (y/n)"
                if ($confirm -match "^[yY]") { $ZscalerFound = $true }
            }
        }
    } catch {
        Write-Warn "OpenSSL not available for TLS extraction"
    }
}

# Method 3: Try certutil export
if (-not $ZscalerFound) {
    Write-Info "Trying certutil export..."
    try {
        $tempCer = "$CertDir\temp-zscaler.cer"
        foreach ($SearchName in $SearchNames) {
            $result = certutil -store Root "$SearchName" $tempCer 2>&1
            if (Test-Path $tempCer) {
                certutil -encode $tempCer $ZscalerCert 2>&1 | Out-Null
                Remove-Item $tempCer -Force
                Write-Ok "Exported via certutil"
                $ZscalerFound = $true
                break
            }
        }
    } catch {}
}

if (-not $ZscalerFound) {
    Write-Fail "Could not find Zscaler certificate."
    Write-Host ""
    Write-Host "  Manual steps:" -ForegroundColor Yellow
    Write-Host "    1. Open Edge → Settings → Privacy → Security → Manage Certificates"
    Write-Host "    2. Go to 'Trusted Root Certification Authorities'"
    Write-Host "    3. Find 'Zscaler Root CA' → Export → Base-64 encoded X.509 (.CER)"
    Write-Host "    4. Save to: $ZscalerCert"
    Write-Host "    5. Re-run this script"
    exit 1
}

Write-Host ""
try { openssl x509 -in $ZscalerCert -noout -subject -issuer -dates 2>&1 | ForEach-Object { Write-Host "  $_" } } catch {}

# =========================================================================
# PHASE 2: Create combined CA bundle
# =========================================================================
Write-Section " Phase 2: Creating combined CA bundle"

# Get Mozilla CA bundle (node ships one, or download)
$SystemCA = $null
$NodeCAPath = "$env:APPDATA\npm\node_modules\ca-certificates\ca-bundle.crt"
$GitCAPath = (git config --global http.sslCAInfo 2>$null)

# Try to find existing CA bundle
$CAPaths = @(
    $NodeCAPath,
    $GitCAPath,
    "C:\Program Files\Git\mingw64\etc\ssl\certs\ca-bundle.crt",
    "C:\Program Files\Git\mingw64\ssl\certs\ca-bundle.crt",
    "C:\msys64\etc\ssl\certs\ca-bundle.crt"
)

foreach ($p in $CAPaths) {
    if ($p -and (Test-Path $p)) {
        $SystemCA = $p
        break
    }
}

if ($SystemCA) {
    $systemContent = Get-Content $SystemCA -Raw
    $zscalerContent = Get-Content $ZscalerCert -Raw
    "$systemContent`n$zscalerContent" | Out-File -FilePath $CombinedBundle -Encoding ASCII -NoNewline
    Write-Ok "Combined bundle created"
    Write-Info "System CAs from: $SystemCA"
} else {
    Copy-Item $ZscalerCert $CombinedBundle
    Write-Warn "No system CA bundle found — using Zscaler cert only"
    Write-Info "Install Git for Windows to get a full CA bundle"
}

# =========================================================================
# PHASE 3: Configure tools
# =========================================================================
Write-Section " Phase 3: Configuring tools"

Write-Host ""
Write-Host "  ── CLI Tools ──" -ForegroundColor White

# Git
if (Get-Command git -ErrorAction SilentlyContinue) {
    git config --global http.sslCAInfo $CombinedBundle
    Write-Ok "Git"
} else { Write-Warn "Git — not found" }

# npm
if (Get-Command npm -ErrorAction SilentlyContinue) {
    npm config set cafile $CombinedBundle 2>&1 | Out-Null
    Write-Ok "npm"
} else { Write-Warn "npm — not found" }

# yarn
if (Get-Command yarn -ErrorAction SilentlyContinue) {
    $yarnVer = yarn --version 2>&1
    if ($yarnVer -match "^1\.") {
        yarn config set cafile $CombinedBundle 2>&1 | Out-Null
    } else {
        yarn config set httpsCaFilePath $CombinedBundle 2>&1 | Out-Null
    }
    Write-Ok "yarn"
}

# pip
if (Get-Command pip -ErrorAction SilentlyContinue) {
    pip config set global.cert $CombinedBundle 2>&1 | Out-Null
    Write-Ok "pip"
} elseif (Get-Command pip3 -ErrorAction SilentlyContinue) {
    pip3 config set global.cert $CombinedBundle 2>&1 | Out-Null
    Write-Ok "pip3"
} else { Write-Warn "pip — not found" }

Write-Host ""
Write-Host "  ── Claude Code ──" -ForegroundColor White

# Claude Code settings.json
$ClaudeDir = "$env:USERPROFILE\.claude"
$ClaudeSettings = "$ClaudeDir\settings.json"
if (-not (Test-Path $ClaudeDir)) { New-Item -ItemType Directory -Path $ClaudeDir -Force | Out-Null }

$settings = @{}
if (Test-Path $ClaudeSettings) {
    try { $settings = Get-Content $ClaudeSettings -Raw | ConvertFrom-Json -AsHashtable } catch { $settings = @{} }
}
if (-not $settings.ContainsKey("env")) { $settings["env"] = @{} }
$settings["env"]["NODE_EXTRA_CA_CERTS"] = $CombinedBundle
$settings["env"]["SSL_CERT_FILE"] = $CombinedBundle
$settings["env"]["NODE_USE_SYSTEM_CA"] = "1"
$settings | ConvertTo-Json -Depth 5 | Out-File -FilePath $ClaudeSettings -Encoding UTF8
Write-Ok "Claude Code CLI (~\.claude\settings.json)"

# VS Code settings
$VSCodeSettings = "$env:APPDATA\Code\User\settings.json"
if (Test-Path $VSCodeSettings) {
    try {
        $vsSettings = Get-Content $VSCodeSettings -Raw | ConvertFrom-Json -AsHashtable
    } catch { $vsSettings = @{} }

    foreach ($key in @("claude-dev.environmentVariables", "ClaudeCode.environmentVariables")) {
        if (-not $vsSettings.ContainsKey($key)) { $vsSettings[$key] = @{} }
        $vsSettings[$key]["NODE_EXTRA_CA_CERTS"] = $CombinedBundle
        $vsSettings[$key]["SSL_CERT_FILE"] = $CombinedBundle
        $vsSettings[$key]["NODE_USE_SYSTEM_CA"] = "1"
    }
    $vsSettings | ConvertTo-Json -Depth 5 | Out-File -FilePath $VSCodeSettings -Encoding UTF8
    Write-Ok "VS Code — Claude Code extension"
} else {
    Write-Warn "VS Code settings not found, skipping"
}

# =========================================================================
# PHASE 4: Environment variables (User-level persistent)
# =========================================================================
Write-Section " Phase 4: Setting environment variables"

$EnvVars = @{
    "NODE_EXTRA_CA_CERTS"  = $CombinedBundle    # Node.js
    "NODE_USE_SYSTEM_CA"   = "1"                # Bun / Claude Code
    "SSL_CERT_FILE"        = $CombinedBundle    # Python / OpenSSL
    "REQUESTS_CA_BUNDLE"   = $CombinedBundle    # Python requests
    "CURL_CA_BUNDLE"       = $CombinedBundle    # curl
    "AWS_CA_BUNDLE"        = $CombinedBundle    # AWS CLI
}

foreach ($name in $EnvVars.Keys) {
    $val = $EnvVars[$name]
    # Set for current session
    [System.Environment]::SetEnvironmentVariable($name, $val, "Process")
    # Set persistently for current user
    [System.Environment]::SetEnvironmentVariable($name, $val, "User")
    Write-Ok "$name (User + Process)"
}

Write-Host ""
Write-Info "To set system-wide (all users), re-run as Administrator"

# WSL hint
Write-Host ""
Write-Host "  ── WSL ──" -ForegroundColor White
Write-Info "If using WSL, copy the cert and run the Linux script:"
Write-Host "         cp '$($ZscalerCert -replace '\\','/')' /mnt/c/... → WSL"
Write-Host "         Then run: ./fix-zscaler-ssl-linux.sh"

# =========================================================================
# PHASE 5: Verification
# =========================================================================
Write-Section " Phase 5: Verification"
Write-Host ""

$Pass = 0; $Fail = 0

# Test: curl
if (Get-Command curl.exe -ErrorAction SilentlyContinue) {
    $httpCode = curl.exe -s -o NUL -w "%{http_code}" --cacert $CombinedBundle https://api.anthropic.com 2>&1
    if ($httpCode -ne "000" -and $httpCode) {
        Write-Ok "curl (HTTP $httpCode) ✓"
        $Pass++
    } else {
        Write-Fail "curl failed"
        $Fail++
    }
}

# Test: Node.js
if (Get-Command node -ErrorAction SilentlyContinue) {
    $env:NODE_EXTRA_CA_CERTS = $CombinedBundle
    $nr = node -e "fetch('https://api.anthropic.com').then(r=>console.log('HTTP '+r.status)).catch(e=>console.log('FAIL:'+e.code))" 2>&1
    if ($nr -match "HTTP") {
        Write-Ok "Node.js ($nr) ✓"
        $Pass++
    } else {
        Write-Fail "Node.js: $nr"
        $Fail++
    }
}

# Test: Python
$pythonCmd = if (Get-Command python3 -ErrorAction SilentlyContinue) { "python3" }
             elseif (Get-Command python -ErrorAction SilentlyContinue) { "python" }
             else { $null }
if ($pythonCmd) {
    $env:SSL_CERT_FILE = $CombinedBundle
    $pr = & $pythonCmd -c "
import urllib.request,ssl
try:
    r=urllib.request.urlopen('https://api.anthropic.com',context=ssl.create_default_context(cafile=r'$CombinedBundle'))
    print('HTTP',r.status)
except Exception as e:
    print('FAIL:',e)
" 2>&1
    if ("$pr" -match "HTTP") {
        Write-Ok "Python ($pr) ✓"
        $Pass++
    } else {
        Write-Fail "Python: $pr"
        $Fail++
    }
}

$Total = $Pass + $Fail
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
if ($Fail -eq 0) {
    Write-Host "║  ALL DONE — $Pass/$Total checks passed                         ║" -ForegroundColor Green
} else {
    Write-Host "║  DONE — $Pass/$Total passed, $Fail failed                          ║" -ForegroundColor Yellow
}
Write-Host "╠══════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
Write-Host "║  Next steps:                                            ║" -ForegroundColor Yellow
Write-Host "║    1. Restart your terminal                             ║" -ForegroundColor White
Write-Host "║    2. Restart VS Code / Claude Desktop                  ║" -ForegroundColor White
Write-Host "║    3. claude /login                                     ║" -ForegroundColor White
Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
