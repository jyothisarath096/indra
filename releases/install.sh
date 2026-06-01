#!/bin/bash
set -e

# INDRA Node Installer
# Usage: curl -sSf https://indraprotocol.com/install.sh | bash

INDRA_VERSION="0.1.0-testnet"
GITHUB_RAW="https://raw.githubusercontent.com/jyothisarath096/indra/main/releases"
INSTALL_DIR="$HOME/.indra"
DATA_DIR="$HOME/.indra/data"
BIN_DIR="$HOME/.indra/bin"

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║         INDRA Node Installer              ║"
echo "║         v${INDRA_VERSION}                 ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# Detect OS and architecture
OS=$(uname -s)
ARCH=$(uname -m)

if [ "$OS" = "Linux" ] && [ "$ARCH" = "x86_64" ]; then
    PLATFORM="linux-x86_64"
elif [ "$OS" = "Linux" ] && [ "$ARCH" = "aarch64" ]; then
    PLATFORM="linux-arm64"
elif [ "$OS" = "Darwin" ] && [ "$ARCH" = "arm64" ]; then
    PLATFORM="macos-arm64"
else
    echo "ERROR: Unsupported platform: $OS $ARCH"
    echo "Supported: Linux x86_64, Linux arm64, macOS arm64"
    exit 1
fi

echo "✓ Detected platform: $PLATFORM"

# Check disk space (need at least 2 GB)
AVAILABLE=$(df -k "$HOME" | awk 'NR==2 {print $4}')
AVAILABLE_GB=$((AVAILABLE / 1024 / 1024))
if [ "$AVAILABLE_GB" -lt 2 ]; then
    echo "ERROR: Insufficient disk space. Need at least 2 GB, have ${AVAILABLE_GB} GB"
    exit 1
fi
echo "✓ Disk space: ${AVAILABLE_GB} GB available"

# Create directories
mkdir -p "$BIN_DIR" "$DATA_DIR"
echo "✓ Created directories: $INSTALL_DIR"

# Download binaries
echo ""
echo "Downloading INDRA node binary..."
curl -sSf "$GITHUB_RAW/$PLATFORM/indra-node" -o "$BIN_DIR/indra-node"
chmod +x "$BIN_DIR/indra-node"

echo "Downloading INDRA keygen..."
curl -sSf "$GITHUB_RAW/$PLATFORM/indra-keygen" -o "$BIN_DIR/indra-keygen"
chmod +x "$BIN_DIR/indra-keygen"

echo "Downloading genesis.toml..."
curl -sSf "$GITHUB_RAW/genesis.toml" -o "$DATA_DIR/genesis.toml"

echo "✓ Downloaded all files"

# Add to PATH
SHELL_RC=""
if [ -f "$HOME/.zshrc" ]; then
    SHELL_RC="$HOME/.zshrc"
elif [ -f "$HOME/.bashrc" ]; then
    SHELL_RC="$HOME/.bashrc"
fi

if [ -n "$SHELL_RC" ]; then
    if ! grep -q "indra/bin" "$SHELL_RC"; then
        echo "" >> "$SHELL_RC"
        echo "# INDRA" >> "$SHELL_RC"
        echo "export PATH=\"\$HOME/.indra/bin:\$PATH\"" >> "$SHELL_RC"
    fi
fi
export PATH="$BIN_DIR:$PATH"

echo ""
echo "══════════════════════════════════════════"
echo "  INDRA installed successfully!"
echo "══════════════════════════════════════════"
echo ""

# Check if keys already exist
if [ -f "$DATA_DIR/keys.json" ]; then
    echo "  ✓ Keys found: $DATA_DIR/keys.json"
    echo "    (using existing validator identity)"
else
    echo "  Generating your validator keypair..."
    echo ""
    echo "  Enter your validator display name (e.g. your name or city):"
    read -p "  Name: " VALIDATOR_NAME
    "$BIN_DIR/indra-keygen" --name "$VALIDATOR_NAME" --output "$DATA_DIR/keys.json"
    echo ""
    echo "  ⚠️  IMPORTANT: Write down your 24-word"
    echo "  recovery phrase shown above."
    echo "  It is the ONLY way to recover your validator."
fi

echo ""
echo "══════════════════════════════════════════"
echo "  To start your node:"
echo ""
echo "  indra-node \\"
echo "    --data-dir ~/.indra/data \\"
echo "    --genesis ~/.indra/data/genesis.toml \\"
echo "    --keys ~/.indra/data/keys.json"
echo ""
echo "  Or as a background service:"
echo "  indra-node --data-dir ~/.indra/data \\"
echo "    --genesis ~/.indra/data/genesis.toml \\"
echo "    --keys ~/.indra/data/keys.json &"
echo ""
echo "  Dashboard (once running):"
echo "  http://localhost:8545"
echo "══════════════════════════════════════════"
echo ""

# Ask if they want to start now
read -p "Start the node now? [y/N] " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Starting INDRA node..."
    exec "$BIN_DIR/indra-node" \
        --data-dir "$DATA_DIR" \
        --genesis "$DATA_DIR/genesis.toml" \
        --keys "$DATA_DIR/keys.json"
fi
