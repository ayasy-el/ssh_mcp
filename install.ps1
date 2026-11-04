# ==============================================================================
# SSH-MCP 1-Line Installer for Windows (PowerShell)
# Usage:
#   irm https://raw.githubusercontent.com/ayasy-el/ssh-mcp/main/install.ps1 | iex
# ==============================================================================

$ErrorActionPreference = "Stop"

$Repo = if ($env:REPO) { $env:REPO } else { "ayasy-el/ssh-mcp" }
$BinaryName = "ssh-mcp.exe"
$Asset = "ssh-mcp-windows-x86_64.zip"

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "             SSH-MCP Server Installer for Windows               " -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

# 1. Determine target directory
$InstallDir = Join-Path $HOME ".local\bin"
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

# 2. Download latest release
$DownloadUrl = "https://github.com/$Repo/releases/latest/download/$Asset"
$TempZip = Join-Path $env:TEMP $Asset
$TempExtract = Join-Path $env:TEMP "ssh-mcp-extract"

Write-Host "Downloading: $DownloadUrl ..." -ForegroundColor Yellow
Invoke-WebRequest -Uri $DownloadUrl -OutFile $TempZip -UseBasicParsing

# 3. Extract and install
if (Test-Path $TempExtract) {
    Remove-Item -Recurse -Force $TempExtract
}
Expand-Archive -Path $TempZip -DestinationPath $TempExtract -Force

$SourceBin = Join-Path $TempExtract $BinaryName
$TargetBin = Join-Path $InstallDir $BinaryName
Copy-Item -Path $SourceBin -Destination $TargetBin -Force

# Clean temporary files
Remove-Item -Force $TempZip -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force $TempExtract -ErrorAction SilentlyContinue

Write-Host "[OK] Installed binary to: $TargetBin" -ForegroundColor Green

# 4. Check User PATH
$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($UserPath -notlike "*$InstallDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$UserPath;$InstallDir", "User")
    $env:Path = "$env:Path;$InstallDir"
    Write-Host "[OK] Added $InstallDir to your User PATH environment variable." -ForegroundColor Green
}

# 5. Configure Pi Agent automatically (Zero-Noise: on-demand dynamic MCP registration)
Write-Host "Configuring Pi Coding Agent integrations..." -ForegroundColor Cyan
try {
    & $TargetBin --install-pi | Out-Null
    Write-Host "[OK] Installed /ssh slash command & SSH skill into Pi Coding Agent" -ForegroundColor Green
    Write-Host "[OK] Zero-noise mode enabled (no startup warnings when ssh-mcp is inactive)" -ForegroundColor Green
} catch {}

Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host " Installation Complete! You're ready to use ssh-mcp.            " -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Quick Start:" -ForegroundColor Yellow
Write-Host "  1. Run in PowerShell:         ssh-mcp"
Write-Host "  2. Run without approval:      ssh-mcp --no-approval"
Write-Host "  3. Inside Pi Coding Agent:    Type /ssh"
Write-Host ""
