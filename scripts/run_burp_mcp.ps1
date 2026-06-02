<#
.SYNOPSIS
    Launch Burp Suite with the MCP Server extension loaded, exposing the keyless
    local MCP SSE endpoint for VENOM.

.EXAMPLE
    pwsh scripts/run_burp_mcp.ps1
    pwsh scripts/run_burp_mcp.ps1 -Headless     # attempt headless (needs a display server)
#>
[CmdletBinding()]
param(
    [string]$ToolsDir = "$PSScriptRoot\..\tools\burp",
    [ValidateSet("community", "pro")]
    [string]$Edition = "community",
    [switch]$Headless
)

$ErrorActionPreference = "Stop"
$BurpJar = Join-Path $ToolsDir "burpsuite_$Edition.jar"
$CfgFile = Join-Path $ToolsDir "venom-burp-config.json"

if (-not (Get-Command java -ErrorAction SilentlyContinue)) {
    throw "Java not found. Install JRE/JDK 17+ then re-run."
}
if (-not (Test-Path $BurpJar)) {
    throw "Burp jar missing. Run scripts/setup_burp.ps1 first."
}

$javaArgs = @("-jar", $BurpJar)
if (Test-Path $CfgFile) { $javaArgs += @("--user-config-file=$CfgFile") }
if ($Headless) {
    # Community has no official headless mode; this only works behind a virtual
    # display (e.g. xvfb on Linux). On Windows, run without -Headless.
    $env:JAVA_TOOL_OPTIONS = "-Djava.awt.headless=true"
}

Write-Host "Launching Burp ($Edition) with MCP extension..." -ForegroundColor Cyan
Write-Host "  java $($javaArgs -join ' ')"
Write-Host "  MCP SSE endpoint will be at: http://127.0.0.1:9876/sse"
& java @javaArgs
