#!/bin/bash
set -e

cd "$(dirname "$0")"

BINARY="./target/release/fraggle-packet"

# Check if built
if [ ! -f "$BINARY" ]; then
    echo "FragglePacket not built. Run ./setup.sh first."
    exit 1
fi

# Parse arguments
case "${1:-}" in
    -1|--quick)
        shift
        TARGET="${1:-8.8.8.8}"
        echo "Quick ICMP test to $TARGET..."
        sudo "$BINARY" quick "$TARGET"
        ;;
    -2|--diagnose)
        shift
        TARGET="${1:-github.com}"
        echo "Full diagnostic for $TARGET..."
        sudo "$BINARY" diagnose "$TARGET"
        ;;
    -3|--multi)
        shift
        TARGETS="${1:-8.8.8.8,1.1.1.1,github.com}"
        echo "Multi-target comparison: $TARGETS..."
        sudo "$BINARY" multi "$TARGETS"
        ;;
    -4|--vpn)
        shift
        VPNTYPE="${1:-zscaler}"
        echo "VPN MTU calculator for $VPNTYPE..."
        sudo "$BINARY" vpn "$VPNTYPE"
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
        "$BINARY" test --category "$CATEGORY" "$TARGET"
        ;;
    -7|--test-all)
        shift
        TARGET="${1:-github.com}"
        echo "Running ALL tests on $TARGET..."
        "$BINARY" test --all "$TARGET"
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
        sudo "$BINARY" kitchen-sink
        ;;
    -11|--json)
        TIMESTAMP=$(date +%Y%m%d_%H%M%S)
        mkdir -p reports
        OUTFILE="reports/mtu-report-${TIMESTAMP}.json"
        echo "Running comprehensive analysis with JSON output..."
        sudo "$BINARY" kitchen-sink --json --output "$OUTFILE"
        echo ""
        echo "Report saved to: $OUTFILE"
        ;;
    -f|--fuzz)
        shift
        MODE="${1:-all}"
        OUTPUT="${2:-reports/fuzz_output.pcap}"
        echo "Running fuzzing mode: $MODE..."
        sudo "$BINARY" fuzz --mode "$MODE" --output "$OUTPUT"
        ;;
    -h|--help)
        cat << 'EOF'
============================================
 FragglePacket - Network Diagnostics Suite
============================================

Usage: ./start.sh [OPTION] [ARGS]

Default (no args): Launch interactive TUI

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
  ./start.sh                              # Launch TUI (default)
  ./start.sh -1                           # Quick ICMP to 8.8.8.8
  ./start.sh -2 example.com               # Full diagnostic
  ./start.sh -6 dns github.com            # Run DNS tests only
  ./start.sh -7 cloudflare.com            # Run ALL 11 tests
  ./start.sh -8 github.com                # HTTPS stage analysis
  ./start.sh -f tcp-options reports/tcp.pcap  # Fuzz TCP options

Note: Most tests require sudo for ICMP/raw socket access.
      TUI will show warnings if not run as root.
EOF
        ;;
    "")
        # Default: Launch TUI
        echo ""
        echo "=============================================="
        echo " FragglePacket - Network Diagnostics Suite"
        echo "=============================================="
        echo ""
        echo "Launching interactive TUI..."
        echo ""
        if [ "$EUID" -ne 0 ]; then
            echo "⚠️  Not running as root. Some features require sudo:"
            echo "   • ICMP MTU testing (ping-based)"
            echo "   • Raw socket tests"
            echo "   • tracepath (press 't' in detail view)"
            echo "   • Packet fuzzing"
            echo ""
            echo "For full features: sudo ./start.sh"
            echo ""
        fi
        echo "TUI Controls: [T]=Tests [H]=HTTPS [F]=Fuzzing [?]=Help [q]=Quit"
        echo ""
        exec "$BINARY" tui
        ;;
    *)
        echo "Unknown option: $1"
        echo "Use -h or --help for usage information"
        exit 1
        ;;
esac
