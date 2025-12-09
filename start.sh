#!/bin/bash
set -e

cd "$(dirname "$0")"

BINARY="./target/release/fraggle-packet"
TUI_BINARY="./target/release/fraggle-packet-tui"

# Check if built
if [ ! -f "$BINARY" ] || [ ! -f "$TUI_BINARY" ]; then
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
    -6|--list-vpn)
        "$BINARY" vpn list
        ;;
    -7|--kitchen-sink)
        echo "Running comprehensive MTU analysis..."
        sudo "$BINARY" kitchen-sink
        ;;
    -8|--json)
        TIMESTAMP=$(date +%Y%m%d_%H%M%S)
        mkdir -p reports
        OUTFILE="reports/mtu-report-${TIMESTAMP}.json"
        echo "Running comprehensive analysis with JSON output..."
        sudo "$BINARY" kitchen-sink --json --output "$OUTFILE"
        echo ""
        echo "Report saved to: $OUTFILE"
        ;;
    -h|--help)
        cat << 'EOF'
============================================
 FragglePacket
============================================

Usage: ./start.sh [OPTION] [TARGET]

Default (no args): Launch interactive TUI

CLI Options:
  -1, --quick [TARGET]        Quick ICMP test (default: 8.8.8.8)
  -2, --diagnose [TARGET]     Full diagnostic (default: github.com)
  -3, --multi [TARGETS]       Multi-target comparison (comma-separated)
  -4, --vpn [TYPE]            VPN/SASE MTU calculator (default: zscaler)
  -5, --tcp [HOST:PORT]       TCP-only test (default: github.com:443)
  -6, --list-vpn              List available VPN types
  -7, --kitchen-sink          Comprehensive MTU analysis
  -8, --json                  Comprehensive + JSON report
  -h, --help                  Show this help

Examples:
  ./start.sh                       # Launch TUI (default)
  ./start.sh -1                    # Quick ICMP to 8.8.8.8
  ./start.sh -1 1.1.1.1            # Quick ICMP to custom target
  ./start.sh -2 example.com        # Full diagnostic
  ./start.sh -3 "8.8.8.8,1.1.1.1"  # Compare multiple targets
  ./start.sh -4 wireguard          # VPN calculator

Note: Most tests require sudo for ICMP access.
      TUI will show a warning if not run as root.
EOF
        ;;
    "")
        # Default: Launch TUI
        echo ""
        echo "=============================================="
        echo " FragglePacket"
        echo "=============================================="
        echo ""
        echo "Launching interactive TUI..."
        echo ""
        if [ "$EUID" -ne 0 ]; then
            echo "⚠️  Not running as root. Some features require sudo:"
            echo "   • ICMP MTU testing"
            echo "   • tracepath (press 't' in detail view)"
            echo ""
            echo "For full features: sudo ./start.sh"
            echo ""
        fi
        exec "$TUI_BINARY"
        ;;
    *)
        echo "Unknown option: $1"
        echo "Use -h or --help for usage information"
        exit 1
        ;;
esac
