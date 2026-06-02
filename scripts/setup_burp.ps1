<#
.SYNOPSIS
    Download Burp Suite + the PortSwigger MCP Server extension into ./tools/burp
    so the keyless local MCP endpoint is available for VENOM engagements.

.DESCRIPTION
    No API key is involved. The MCP Server extension runs inside Burp on this
    machine and exposes a loopback SSE endpoint (default 127.0.0.1:9876/sse).

    This script:
      1. Verifies a Java runtime is present (Burp needs Java 17+).
      2. Downloads the Burp Suite Community jar (override with -Version / -Edition).
      3. Downloads the MCP Server extension jar (latest GitHub release, or -McpUrl).
      4. Writes a Burp user-config JSON that auto-loads the extension.

    Use -Check to verify what is already installed without downloading.

.EXAMPLE
    pwsh scripts/setup_burp.ps1
    pwsh scripts/setup_burp.ps1 -Version 2025.5.6 -Edition community
    pwsh scripts/setup_burp.ps1 -Check
#>
[CmdletBinding()]
param(
    [string]$ToolsDir = "$PSScriptRoot\..\tools\burp",
    [ValidateSet("community", "pro")]
    [string]$Edition = "community",
    [string]$Version = $env:BURP_VERSION,                 # e.g. 2025.5.6; blank => "latest"
    [string]$McpUrl  = $env:BURP_MCP_EXT_URL,             # explicit extension jar URL (optional)
    [int]$McpPort    = 9876,
    [switch]$Check
)

$ErrorActionPreference = "Stop"
$ToolsDir = (New-Item -ItemType Directory -Force -Path $ToolsDir).FullName
$BurpJar  = Join-Path $ToolsDir "burpsuite_$Edition.jar"
$McpJar   = Join-Path $ToolsDir "burp-mcp-server.jar"
$CfgFile  = Join-Path $ToolsDir "venom-burp-config.json"

function Test-Java {
    $java = Get-Command java -ErrorAction SilentlyContinue
    if (-not $java) {
        Write-Warning "Java not found. Install a JRE/JDK 17+ (e.g. https://adoptium.net) and re-run."
        return $false
    }
    Write-Host "  Java: $($java.Source)"
    return $true
}

if ($Check) {
    Write-Host "Burp MCP install check ($ToolsDir):"
    [void](Test-Java)
    Write-Host ("  Burp jar      : " + $(if (Test-Path $BurpJar) { "present" } else { "MISSING" }))
    Write-Host ("  MCP extension : " + $(if (Test-Path $McpJar)  { "present" } else { "MISSING" }))
    Write-Host ("  User config   : " + $(if (Test-Path $CfgFile) { "present" } else { "MISSING" }))
    return
}

Write-Host "== VENOM :: Burp + MCP setup ==" -ForegroundColor Cyan
[void](Test-Java)

# --- 1. Burp Suite jar ------------------------------------------------------
if (Test-Path $BurpJar) {
    Write-Host "  Burp jar already present: $BurpJar"
} else {
    $ver = if ([string]::IsNullOrWhiteSpace($Version)) { "latest" } else { $Version }
    $url = "https://portswigger.net/burp/releases/download?product=$Edition&version=$ver&type=Jar"
    Write-Host "  Downloading Burp $Edition ($ver)..."
    try {
        Invoke-WebRequest -Uri $url -OutFile $BurpJar -UseBasicParsing
        Write-Host "  -> $BurpJar"
    } catch {
        Write-Warning ("Burp download failed: {0}" -f $_.Exception.Message)
        Write-Warning "Pick a specific version from https://portswigger.net/burp/releases and re-run with -Version <x>."
    }
}

# --- 2. MCP Server extension jar -------------------------------------------
if (Test-Path $McpJar) {
    Write-Host "  MCP extension already present: $McpJar"
} else {
    if ([string]::IsNullOrWhiteSpace($McpUrl)) {
        Write-Host "  Resolving latest MCP Server extension release from GitHub..."
        try {
            $rel = Invoke-RestMethod -UseBasicParsing `
                -Uri "https://api.github.com/repos/PortSwigger/mcp-server/releases/latest" `
                -Headers @{ "User-Agent" = "venom-setup" }
            $asset = $rel.assets | Where-Object { $_.name -like "*.jar" } | Select-Object -First 1
            $McpUrl = $asset.browser_download_url
        } catch {
            Write-Warning ("Could not query GitHub releases: {0}" -f $_.Exception.Message)
        }
    }
    if ($McpUrl) {
        Write-Host "  Downloading MCP extension: $McpUrl"
        Invoke-WebRequest -Uri $McpUrl -OutFile $McpJar -UseBasicParsing
        Write-Host "  -> $McpJar"
    } else {
        Write-Warning "No MCP extension URL. Install 'MCP Server' from Burp's BApp Store, or set -McpUrl."
    }
}

# --- 3. Burp user-config that auto-loads the extension ----------------------
$cfg = @{
    user_options = @{
        extender = @{
            extensions = @(
                @{ type = "java"; name = "MCP Server"; errors_to = "ui"; output_to = "ui";
                   loaded = $true; extension_file = $McpJar }
            )
        }
    }
}
$cfg | ConvertTo-Json -Depth 8 | Set-Content -Path $CfgFile -Encoding utf8
Write-Host "  Wrote Burp user-config: $CfgFile"

Write-Host ""
Write-Host "Done. Next:" -ForegroundColor Green
Write-Host "  1) pwsh scripts/run_burp_mcp.ps1        # launches Burp with the extension"
Write-Host "  2) In .env set: BURP_MCP_ENABLED=true   (BURP_MCP_URL=http://127.0.0.1:$McpPort/sse)"
Write-Host "  3) venom burp --status                 # verify connectivity"
