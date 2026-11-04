#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# SSH-MCP 1-Line Installer for Linux & macOS
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/ayasy-el/ssh_mcp/main/install.sh | bash
# ==============================================================================

REPO="${REPO:-ayasy-el/ssh_mcp}"
BINARY_NAME="ssh-mcp"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m' # No Color

echo -e "${CYAN}${BOLD}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║          SSH-MCP Server Installer for Linux & macOS           ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# 1. Detect OS
OS_RAW="$(uname -s)"
case "${OS_RAW}" in
    Linux*)     OS="linux";;
    Darwin*)    OS="macos";;
    *)
        echo -e "${RED}Error: Unsupported operating system: ${OS_RAW}${NC}"
        echo "For Windows, run install.ps1 in PowerShell instead."
        exit 1
        ;;
esac

# 2. Detect Architecture
ARCH_RAW="$(uname -m)"
case "${ARCH_RAW}" in
    x86_64|amd64)   ARCH="x86_64";;
    aarch64|arm64)
        if [ "${OS}" = "macos" ]; then
            ARCH="arm64"
        else
            ARCH="aarch64"
        fi
        ;;
    *)
        echo -e "${RED}Error: Unsupported processor architecture: ${ARCH_RAW}${NC}"
        exit 1
        ;;
esac

ASSET_NAME="ssh-mcp-${OS}-${ARCH}.tar.gz"
echo -e "Detected Platform: ${BOLD}${OS} (${ARCH})${NC}"

# 3. Determine installation directory
if [ -w "/usr/local/bin" ] && [ "${EUID:-$(id -u)}" -eq 0 ]; then
    INSTALL_DIR="/usr/local/bin"
else
    INSTALL_DIR="${HOME}/.local/bin"
fi
mkdir -p "${INSTALL_DIR}"

# 4. Fetch latest release URL
DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/${ASSET_NAME}"
echo -e "Downloading latest release: ${CYAN}${DOWNLOAD_URL}${NC} ..."

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

if command -v curl >/dev/null 2>&1; then
    curl -fsSL "${DOWNLOAD_URL}" -o "${TMP_DIR}/${ASSET_NAME}"
elif command -v wget >/dev/null 2>&1; then
    wget -qO "${TMP_DIR}/${ASSET_NAME}" "${DOWNLOAD_URL}"
else
    echo -e "${RED}Error: Neither curl nor wget was found. Please install one.${NC}"
    exit 1
fi

# 5. Extract and install binary
tar -xzf "${TMP_DIR}/${ASSET_NAME}" -C "${TMP_DIR}"
chmod +x "${TMP_DIR}/${BINARY_NAME}"
mv "${TMP_DIR}/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"

echo -e "${GREEN}✔ Installed binary to: ${BOLD}${INSTALL_DIR}/${BINARY_NAME}${NC}"

# 6. Verify PATH
if [[ ":$PATH:" != *":${INSTALL_DIR}:"* ]]; then
    echo -e "${YELLOW}Notice: ${INSTALL_DIR} is not in your current PATH.${NC}"
    echo "Add this to your ~/.bashrc or ~/.zshrc:"
    echo -e "  ${BOLD}export PATH=\"${INSTALL_DIR}:\$PATH\"${NC}"
fi

# 7. Auto-configure Pi Coding Agent (Zero-Noise: on-demand dynamic MCP registration)
echo ""
echo -e "${CYAN}Setting up integrations...${NC}"
if "${INSTALL_DIR}/${BINARY_NAME}" --install-pi >/dev/null 2>&1; then
    echo -e "${GREEN}✔ Installed /ssh slash command & SSH skill into Pi Coding Agent (~/.agents/skills/ssh/SKILL.md)${NC}"
    echo -e "${GREEN}✔ Configured zero-noise dynamic integration (no startup warnings when ssh-mcp is inactive)${NC}"
fi

# 8. Success Banner
echo ""
echo -e "${GREEN}${BOLD}================================================================${NC}"
echo -e "${GREEN}${BOLD} Installation Complete! You're ready to use ssh-mcp.${NC}"
echo -e "${GREEN}${BOLD}================================================================${NC}"
echo ""
echo "🚀 Quick Start:"
echo -e "   1. Run in terminal:          ${BOLD}ssh-mcp${NC}"
echo -e "   2. Run without approval:     ${BOLD}ssh-mcp --no-approval${NC}"
echo -e "   3. Inside Pi Coding Agent:   Type ${BOLD}/ssh${NC} for interactive controls"
echo ""
