#!/bin/bash
set -e

cd "$(dirname "$0")"

BINARY="./target/release/fraggle-packet"
DESKTOP_BINARY="./target/release/fraggle-desktop"

# Rebuild release binaries when the Rust sources or manifests are newer.  The
# launcher previously checked only for existence, which could silently run an
# old GUI after source changes.
is_stale() {
    local binary="$1"

    [ ! -x "$binary" ] && return 0
    find Cargo.toml Cargo.lock main.rs src -type f -newer "$binary" -print -quit 2>/dev/null | grep -q .
}

build_release() {
    local target="$1"

    if ! command -v cargo >/dev/null 2>&1; then
        echo "FragglePacket needs to be rebuilt, but cargo is not installed."
        echo "Run ./setup.sh first."
        exit 1
    fi

    echo "FragglePacket sources changed; rebuilding $target..."
    cargo build --release --bin "$target"
}

if is_stale "$BINARY"; then
    build_release fraggle-packet
fi

# Only require the GUI toolchain for launch modes that use the desktop app.
# CLI and TUI commands remain usable on hosts without desktop dependencies.
case "${1:-}" in
    ""|-d|--desktop)
        if is_stale "$DESKTOP_BINARY"; then
            build_release fraggle-desktop
        fi
        ;;
esac

# Parse arguments
case "${1:-}" in
    -t|--tui)
        echo ""
        echo "=============================================="
        echo " FragglePacket - Terminal UI"
        echo "=============================================="
        echo ""
        echo "Launching interactive TUI..."
        echo ""
        echo "All tests work without root."
        echo "Note: ICMP MTU uses Linux-specific flags (use TCP MTU on macOS)."
        echo ""
        echo "TUI Controls: [T]=Tests [H]=HTTPS [F]=Fuzzing [?]=Help [q]=Quit"
        echo ""
        exec "$BINARY" tui
        ;;
    -d|--desktop)
        if [ ! -f "$DESKTOP_BINARY" ]; then
            echo "Desktop GUI not built. Run ./setup.sh first."
            echo ""
            echo "Desktop GUI requires additional dependencies:"
            echo "  Ubuntu/Debian: libgtk-3-dev libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev"
            echo "  macOS:         included with system"
            exit 1
        fi
        echo ""
        echo "=============================================="
        echo " FragglePacket - Desktop GUI"
        echo "=============================================="
        echo ""
        echo "Launching Desktop GUI..."
        echo ""
        echo "Most tests work without root. The app detects missing privileges"
        echo "and shows disabled features in a banner at the top."
        echo ""
        echo "For raw-socket features (PCAP replay, active PMTU probe, capture)"
        echo "relaunch with sudo, or grant caps one time:"
        echo "  sudo setcap cap_net_raw,cap_net_admin+eip $DESKTOP_BINARY"
        echo ""
        exec "$DESKTOP_BINARY"
        ;;
    -1|--quick)
        shift
        TARGET="${1:-8.8.8.8}"
        echo "Quick ICMP test to $TARGET..."
        "$BINARY" quick "$TARGET"
        ;;
    -2|--diagnose)
        shift
        TARGET="${1:-github.com}"
        echo "Full diagnostic for $TARGET..."
        "$BINARY" diagnose "$TARGET"
        ;;
    -3|--multi)
        shift
        TARGETS="${1:-8.8.8.8,1.1.1.1,github.com}"
        echo "Multi-target comparison: $TARGETS..."
        "$BINARY" multi "$TARGETS"
        ;;
    -4|--vpn)
        shift
        VPNTYPE="${1:-zscaler}"
        echo "VPN MTU calculator for $VPNTYPE..."
        "$BINARY" vpn "$VPNTYPE"
        ;;
    -5|--tcp)
        shift
        TARGET="${1:-github.com:443}"
        echo "TCP-only test to $TARGET..."
        "$BINARY" tcp "$TARGET"
        ;;
    -6|--test)
        shift
        CATEGORY="${1:-dns}"
        TARGET="${2:-github.com}"
        echo "Running $CATEGORY test on $TARGET..."
        "$BINARY" test --categories "$CATEGORY" "$TARGET"
        ;;
    -7|--test-all)
        shift
        TARGET="${1:-github.com}"
        echo "Running ALL tests on $TARGET..."
        "$BINARY" test --categories all "$TARGET"
        ;;
    -8|--https)
        shift
        TARGET="${1:-github.com}"
        echo "HTTPS stage-by-stage test on $TARGET..."
        "$BINARY" https "$TARGET"
        ;;
    -9|--list-vpn)
        "$BINARY" vpn list
        ;;
    -10|--kitchen-sink)
        echo "Running comprehensive MTU analysis..."
        "$BINARY" kitchen-sink
        ;;
    -11|--json)
        TIMESTAMP=$(date +%Y%m%d_%H%M%S)
        mkdir -p reports
        OUTFILE="reports/mtu-report-${TIMESTAMP}.json"
        echo "Running comprehensive analysis with JSON output..."
        "$BINARY" kitchen-sink --json --output "$OUTFILE"
        echo ""
        echo "Report saved to: $OUTFILE"
        ;;
    -f|--fuzz)
        shift
        MODE="${1:-all}"
        OUTPUT="${2:-reports/fuzz_output.pcap}"
        echo "Running fuzzing mode: $MODE..."
        "$BINARY" fuzz --mode "$MODE" --output "$OUTPUT"
        ;;
    -h|--help)
        cat << 'EOF'
============================================
 FragglePacket - Network Diagnostics Suite
============================================

Usage: ./start.sh [OPTION] [ARGS]

Default (no args): Launch Desktop GUI

Interface Options:
  (no args)                      Launch Desktop GUI (Dioxus)
  -d, --desktop                  Launch Desktop GUI (Dioxus)
  -t, --tui                      Launch terminal UI (TUI)

CLI Options:
  -1, --quick [TARGET]           Quick ICMP test (default: 8.8.8.8)
  -2, --diagnose [TARGET]        Full diagnostic (default: github.com)
  -3, --multi [TARGETS]          Multi-target comparison (comma-separated)
  -4, --vpn [TYPE]               VPN/SASE MTU calculator (default: zscaler)
  -5, --tcp [HOST:PORT]          TCP-only test (default: github.com:443)
  -6, --test [CATEGORY] [TARGET] Run specific test category
  -7, --test-all [TARGET]        Run ALL 11 test categories
  -8, --https [TARGET]           HTTPS stage-by-stage analysis
  -9, --list-vpn                 List available VPN types
  -10, --kitchen-sink            Comprehensive MTU analysis
  -11, --json                    Comprehensive + JSON report
  -f, --fuzz [MODE] [OUTPUT]     Run packet fuzzing
  -h, --help                     Show this help

Test Categories (for -6):
  dns, mtu, https, tcp-health, rtt, packet-loss, path-analysis, ipv6, application, fuzzing

TUI Keybindings:
  [T]     - Open Test Panel (11 test categories)
  [1-0]   - Select test category (1=DNS, 2=MTU, etc.)
  [Enter] - Run selected test (smart: single/all targets)
  [A]     - Run ALL tests on current target
  [H]     - HTTPS Panel (stage-by-stage testing)
  [F]     - Fuzzing Panel
  [c]     - Collapse/expand detail panels
  [?]     - Help screen

Examples:
  ./start.sh                              # Launch Desktop GUI (default)
  ./start.sh --tui                        # Launch TUI
  ./start.sh -1                           # Quick ICMP to 8.8.8.8
  ./start.sh -2 example.com               # Full diagnostic
  ./start.sh -6 dns github.com            # Run DNS tests only
  ./start.sh -7 cloudflare.com            # Run ALL 11 tests
  ./start.sh -8 github.com                # HTTPS stage analysis
  ./start.sh -f tcp-options reports/tcp.pcap  # Fuzz TCP options

Note: Most tests work without root. ICMP MTU uses Linux-specific ping flags.
      Raw-socket features (replay, active probe, capture) need sudo or setcap.
EOF
        ;;
    "")
        if [ ! -f "$DESKTOP_BINARY" ]; then
            echo "Desktop GUI not built. Falling back to TUI."
            echo "Run ./setup.sh to build the Desktop GUI."
            echo ""
            exec "$BINARY" tui
        fi
        echo ""
        echo "=============================================="
        echo " FragglePacket - Desktop GUI"
        echo "=============================================="
        echo ""
        echo "Launching Desktop GUI..."
        echo ""
        echo "The app detects missing privileges and shows disabled"
        echo "features in a banner at the top. For raw-socket features"
        echo "relaunch with sudo or grant caps one time:"
        echo "  sudo setcap cap_net_raw,cap_net_admin+eip $DESKTOP_BINARY"
        echo ""
        exec "$DESKTOP_BINARY"
        ;;
    *)
        echo "Unknown option: $1"
        echo "Use -h or --help for usage information"
        exit 1
        ;;
esac
