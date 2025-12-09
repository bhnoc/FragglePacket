#!/bin/bash
set -e

cd "$(dirname "$0")"

echo "=============================================="
echo " FragglePacket - Setup"
echo "=============================================="
echo ""

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    OS=$(uname -s)
fi

echo "Detected OS: $OS"
echo ""

# Install system dependencies
install_deps() {
    echo "[1/4] Installing system dependencies..."
    
    case $OS in
        ubuntu|debian|pop)
            sudo apt-get update -qq
            sudo apt-get install -y -qq \
                build-essential \
                pkg-config \
                libssl-dev \
                curl \
                iputils-tracepath \
                traceroute \
                tcpdump \
                net-tools
            ;;
        fedora|rhel|centos|rocky|alma)
            sudo dnf install -y \
                gcc \
                make \
                pkg-config \
                openssl-devel \
                curl \
                traceroute \
                tcpdump \
                net-tools
            ;;
        arch|manjaro)
            sudo pacman -S --noconfirm \
                base-devel \
                openssl \
                curl \
                traceroute \
                tcpdump \
                net-tools
            ;;
        Darwin)
            # macOS
            if command -v brew &> /dev/null; then
                brew install openssl curl
            else
                echo "Install Homebrew first: https://brew.sh"
                exit 1
            fi
            ;;
        *)
            echo "Unknown OS: $OS"
            echo "Please manually install: build-essential, pkg-config, libssl-dev, curl, traceroute, tcpdump"
            ;;
    esac
    echo "  Done."
}

# Install Rust
install_rust() {
    echo "[2/4] Checking Rust installation..."
    
    if command -v cargo &> /dev/null; then
        RUST_VERSION=$(rustc --version)
        echo "  Found: $RUST_VERSION"
    else
        echo "  Rust not found. Installing..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source "$HOME/.cargo/env"
        echo "  Installed: $(rustc --version)"
    fi
    
    export PATH="$HOME/.cargo/bin:$PATH"
}

# Build the tool
build_tool() {
    echo "[3/4] Building..."
    
    cargo build --release 2>&1 | grep -E "(Compiling mtu|Finished|error)" || true
    
    if [ -f "./target/release/fraggle-packet" ] && [ -f "./target/release/fraggle-packet-tui" ]; then
        echo "  Build successful (CLI + TUI)."
    else
        echo "  Build FAILED!"
        cargo build --release
        exit 1
    fi
}

# Verify capabilities
verify_setup() {
    echo "[4/4] Verifying setup..."
    
    BINARY="./target/release/fraggle-packet"
    TUI_BINARY="./target/release/fraggle-packet-tui"
    
    # Check binaries exist
    if [ ! -f "$BINARY" ]; then
        echo "  ERROR: CLI binary not found"
        exit 1
    fi
    echo "  CLI Binary: OK"
    
    if [ ! -f "$TUI_BINARY" ]; then
        echo "  WARNING: TUI binary not found"
    else
        echo "  TUI Binary: OK"
    fi
    
    # Check tracepath
    if command -v tracepath &> /dev/null; then
        echo "  tracepath: OK"
    else
        echo "  tracepath: NOT FOUND (per-hop MTU disabled)"
    fi
    
    # Check tcpdump (for future MSS capture)
    if command -v tcpdump &> /dev/null; then
        echo "  tcpdump: OK"
    else
        echo "  tcpdump: NOT FOUND (MSS capture disabled)"
    fi
    
    # Check if we can use raw sockets
    if sudo -n true 2>/dev/null; then
        echo "  sudo: OK (passwordless)"
    else
        echo "  sudo: Will prompt for password"
    fi
    
    # Check targets file
    if [ -f "targets.txt" ]; then
        TARGET_COUNT=$(grep -v '^#' targets.txt | grep -v '^$' | wc -l)
        echo "  targets.txt: $TARGET_COUNT targets"
    else
        echo "  targets.txt: NOT FOUND (using defaults)"
    fi
}

# Main
install_deps
install_rust
build_tool
verify_setup

echo ""
echo "=============================================="
echo " Setup Complete!"
echo "=============================================="
echo ""
echo "Run: ./start.sh"
echo ""

