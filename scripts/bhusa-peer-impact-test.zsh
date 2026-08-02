#!/bin/zsh

# BHUSA peer-impact test
#
# Recommended 1:many experiment:
#   Laptop A: MODE=load ./scripts/bhusa-peer-impact-test.zsh
#   Laptop B: MODE=observe ./scripts/bhusa-peer-impact-test.zsh
# Then swap A/B and repeat. If both laptops use MODE=load, assign different
# XMission port pairs because an iperf3 listener normally serves one test at a
# time (for example, 5201/5202 and a separately verified pair).

set -u

MODE="${MODE:-load}"
IFACE="${IFACE:-en0}"
SERVER="${SERVER:-speedtest.xmission.com}"
UPLOAD_PORT="${UPLOAD_PORT:-5201}"
DOWNLOAD_PORT="${DOWNLOAD_PORT:-5202}"
RATE="${RATE:-350M}"
PACKET_SIZE="${PACKET_SIZE:-1472}"
TCP_PARALLEL="${TCP_PARALLEL:-4}"
TCP_RATE_PER_STREAM="${TCP_RATE_PER_STREAM:-87.5M}"
TCP_BLOCK_SIZE="${TCP_BLOCK_SIZE:-128K}"
DIRECTIONAL_SECONDS="${DIRECTIONAL_SECONDS:-7}"
SIMULTANEOUS_SECONDS="${SIMULTANEOUS_SECONDS:-12}"
OMIT_SECONDS="${OMIT_SECONDS:-1}"
PING_INTERVAL="${PING_INTERVAL:-0.2}"
IDLE_PING_COUNT="${IDLE_PING_COUNT:-25}"
LOADED_PING_COUNT="${LOADED_PING_COUNT:-65}"
OBSERVER_PING_COUNT="${OBSERVER_PING_COUNT:-750}"
START_EPOCH="${START_EPOCH:-}"
LABEL="${LABEL:-$(scutil --get ComputerName 2>/dev/null || hostname -s)}"

for required_command in iperf3 ping ipconfig python3; do
    if ! command -v "$required_command" >/dev/null 2>&1; then
        print -u2 "ERROR: required command not found: $required_command"
        exit 1
    fi
done

if [[ "$MODE" != "load" && "$MODE" != "observe" ]]; then
    print -u2 "ERROR: MODE must be load or observe"
    exit 1
fi

LOCAL_IP=$(ipconfig getifaddr "$IFACE")
GATEWAY=$(ipconfig getoption "$IFACE" router)

if [[ -z "$LOCAL_IP" || -z "$GATEWAY" ]]; then
    print -u2 "ERROR: could not resolve an IP address and gateway for $IFACE"
    exit 1
fi

RESULTS=$(mktemp -d "/tmp/bhusa-peer-impact-${MODE}.XXXXXX")

wait_for_start() {
    if [[ -z "$START_EPOCH" ]]; then
        return
    fi
    if [[ "$START_EPOCH" != <-> ]]; then
        print -u2 "ERROR: START_EPOCH must be Unix epoch seconds"
        exit 1
    fi
    while (( $(date +%s) < START_EPOCH )); do
        sleep 0.1
    done
}

write_metadata() {
    {
        print "label=$LABEL"
        print "mode=$MODE"
        print "started_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        print "interface=$IFACE"
        print "local_ip=$LOCAL_IP"
        print "gateway=$GATEWAY"
        print "server=$SERVER"
        print "upload_port=$UPLOAD_PORT"
        print "download_port=$DOWNLOAD_PORT"
        print "rate=$RATE"
        print "packet_size=$PACKET_SIZE"
        print "tcp_aggregate_target=350M"
        print "tcp_parallel=$TCP_PARALLEL"
        print "tcp_rate_per_stream=$TCP_RATE_PER_STREAM"
        print "tcp_block_size=$TCP_BLOCK_SIZE"
    } > "$RESULTS/metadata.txt"
}

mark_phase() {
    local phase="$1"
    printf '%s\t%s\t%s\n' "$(date +%s)" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$phase" \
        >> "$RESULTS/timeline.tsv"
}

run_observer() {
    print "Observer is monitoring the Wi-Fi gateway only; it will generate no iperf load."
    print "Observer duration: approximately $((OBSERVER_PING_COUNT * 2 / 10)) seconds"
    mark_phase "observer_start"
    ping --apple-time -b "$IFACE" -n -i "$PING_INTERVAL" -c "$OBSERVER_PING_COUNT" "$GATEWAY" \
        > "$RESULTS/gateway-observer.txt" \
        2> "$RESULTS/gateway-observer.stderr"
    local ping_rc=$?
    mark_phase "observer_end"
    python3 - "$RESULTS/gateway-observer.txt" <<'PY'
import re
import sys
from pathlib import Path

text = Path(sys.argv[1]).read_text(errors="replace")
latency = re.search(
    r"(?:round-trip|rtt) min/avg/max/(?:stddev|mdev) = "
    r"([0-9.]+)/([0-9.]+)/([0-9.]+)/([0-9.]+) ms",
    text,
)
loss = re.search(r"([0-9.]+)% packet loss", text)
if latency:
    minimum, average, maximum, deviation = latency.groups()
    print(f"Gateway observer: {average} ms average, {maximum} ms maximum, "
          f"{loss.group(1) if loss else 'unknown'}% loss")
else:
    print("Gateway observer: results unavailable")
PY
    print "Raw evidence: $RESULTS"
    return "$ping_rc"
}

run_udp_simultaneous() {
    local run_id="$1"
    ping --apple-time -b "$IFACE" -n -i "$PING_INTERVAL" -c "$LOADED_PING_COUNT" "$GATEWAY" \
        > "$RESULTS/udp-gateway-loaded-${run_id}.txt" \
        2> "$RESULTS/udp-gateway-loaded-${run_id}.stderr" &
    local ping_pid=$!

    iperf3 -c "$SERVER" -p "$UPLOAD_PORT" -4 -B "$LOCAL_IP%$IFACE" \
        -u -b "$RATE" -l "$PACKET_SIZE" -t "$SIMULTANEOUS_SECONDS" \
        -O "$OMIT_SECONDS" -J \
        > "$RESULTS/udp-sim-upload-${run_id}.json" \
        2> "$RESULTS/udp-sim-upload-${run_id}.stderr" &
    local upload_pid=$!

    iperf3 -c "$SERVER" -p "$DOWNLOAD_PORT" -4 -B "$LOCAL_IP%$IFACE" \
        -u -b "$RATE" -l "$PACKET_SIZE" -t "$SIMULTANEOUS_SECONDS" \
        -O "$OMIT_SECONDS" -R -J \
        > "$RESULTS/udp-sim-download-${run_id}.json" \
        2> "$RESULTS/udp-sim-download-${run_id}.stderr" &
    local download_pid=$!

    wait "$upload_pid"
    local upload_rc=$?
    wait "$download_pid"
    local download_rc=$?
    wait "$ping_pid"
    local ping_rc=$?

    if (( upload_rc != 0 || download_rc != 0 || ping_rc != 0 )); then
        print -u2 "ERROR: UDP simultaneous run $run_id failed (upload=$upload_rc download=$download_rc ping=$ping_rc)"
        return 1
    fi
}

run_tcp_simultaneous() {
    local run_id="$1"
    ping --apple-time -b "$IFACE" -n -i "$PING_INTERVAL" -c "$LOADED_PING_COUNT" "$GATEWAY" \
        > "$RESULTS/tcp-gateway-loaded-${run_id}.txt" \
        2> "$RESULTS/tcp-gateway-loaded-${run_id}.stderr" &
    local ping_pid=$!

    iperf3 -c "$SERVER" -p "$UPLOAD_PORT" -4 -B "$LOCAL_IP%$IFACE" \
        -b "$TCP_RATE_PER_STREAM" -P "$TCP_PARALLEL" -l "$TCP_BLOCK_SIZE" \
        -t "$SIMULTANEOUS_SECONDS" -O "$OMIT_SECONDS" -J \
        > "$RESULTS/tcp-sim-upload-${run_id}.json" \
        2> "$RESULTS/tcp-sim-upload-${run_id}.stderr" &
    local upload_pid=$!

    iperf3 -c "$SERVER" -p "$DOWNLOAD_PORT" -4 -B "$LOCAL_IP%$IFACE" \
        -b "$TCP_RATE_PER_STREAM" -P "$TCP_PARALLEL" -l "$TCP_BLOCK_SIZE" \
        -t "$SIMULTANEOUS_SECONDS" -O "$OMIT_SECONDS" -R -J \
        > "$RESULTS/tcp-sim-download-${run_id}.json" \
        2> "$RESULTS/tcp-sim-download-${run_id}.stderr" &
    local download_pid=$!

    wait "$upload_pid"
    local upload_rc=$?
    wait "$download_pid"
    local download_rc=$?
    wait "$ping_pid"
    local ping_rc=$?

    if (( upload_rc != 0 || download_rc != 0 || ping_rc != 0 )); then
        print -u2 "ERROR: TCP simultaneous run $run_id failed (upload=$upload_rc download=$download_rc ping=$ping_rc)"
        return 1
    fi
}

print_summary() {
    python3 - "$RESULTS" <<'PY'
import json
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])

def iperf_udp(filename):
    data = json.loads((path / filename).read_text())
    if data.get("error"):
        raise RuntimeError(data["error"])
    received = data["end"]["sum_received"]
    return (
        received["bits_per_second"] / 1e6,
        received.get("lost_percent", 0),
        received.get("lost_packets", 0),
    )

def iperf_tcp(filename):
    data = json.loads((path / filename).read_text())
    if data.get("error"):
        raise RuntimeError(data["error"])
    received = data["end"]["sum_received"]
    sent = data["end"].get("sum_sent", {})
    return received["bits_per_second"] / 1e6, sent.get("retransmits", 0)

def gateway(filename):
    text = (path / filename).read_text(errors="replace")
    latency = re.search(
        r"(?:round-trip|rtt) min/avg/max/(?:stddev|mdev) = "
        r"([0-9.]+)/([0-9.]+)/([0-9.]+)/([0-9.]+) ms",
        text,
    )
    loss = re.search(r"([0-9.]+)% packet loss", text)
    if not latency:
        return None
    values = tuple(map(float, latency.groups()))
    return values, float(loss.group(1)) if loss else 0

def udp_transfer(value):
    mbps, loss, lost = value
    if lost == 0:
        return f"{mbps:.1f} Mbps, zero loss"
    return f"{mbps:.1f} Mbps, {lost:,} packets lost ({loss:.3f}%)"

def tcp_transfer(value):
    mbps, retransmits = value
    return f"{mbps:.1f} Mbps, {retransmits:,} retransmissions"

def latency_text(value, idle=False):
    if not value:
        return "Unavailable"
    samples, loss = value
    if idle:
        return f"Idle average {samples[1]:.1f} ms, {loss:g}% loss"
    return (f"{samples[1]:.1f} ms average, {samples[2]:.1f} ms maximum, "
            f"{loss:g}% loss")

def table(title, rows):
    headers = ["Test", "Upload", "Download", "Gateway latency"]
    widths = [max(len(headers[i]), *(len(row[i]) for row in rows)) for i in range(4)]
    separator = "  ".join("-" * width for width in widths)
    def line(values):
        return "  ".join(values[i].ljust(widths[i]) for i in range(4))
    return "\n".join([title, line(headers), separator, *(line(row) for row in rows)])

udp_rows = [[
    "Directional controls",
    udp_transfer(iperf_udp("udp-upload-only.json")),
    udp_transfer(iperf_udp("udp-download-only.json")),
    latency_text(gateway("udp-gateway-idle.txt"), idle=True),
]]
for run_id in (1, 2):
    udp_rows.append([
        f"Simultaneous run {run_id}",
        udp_transfer(iperf_udp(f"udp-sim-upload-{run_id}.json")),
        udp_transfer(iperf_udp(f"udp-sim-download-{run_id}.json")),
        latency_text(gateway(f"udp-gateway-loaded-{run_id}.txt")),
    ])

tcp_rows = [[
    "Directional controls",
    tcp_transfer(iperf_tcp("tcp-upload-only.json")),
    tcp_transfer(iperf_tcp("tcp-download-only.json")),
    latency_text(gateway("tcp-gateway-idle.txt"), idle=True),
]]
for run_id in (1, 2):
    tcp_rows.append([
        f"Simultaneous run {run_id}",
        tcp_transfer(iperf_tcp(f"tcp-sim-upload-{run_id}.json")),
        tcp_transfer(iperf_tcp(f"tcp-sim-download-{run_id}.json")),
        latency_text(gateway(f"tcp-gateway-loaded-{run_id}.txt")),
    ])

summary = table("UDP — 350 Mbps per direction", udp_rows)
summary += "\n\n" + table("TCP — 350 Mbps target per direction, 4 streams", tcp_rows)
print(summary)
(path / "summary.txt").write_text(summary + "\n")
PY
}

write_metadata
print "BHUSA peer-impact test"
print "  Label:      $LABEL"
print "  Mode:       $MODE"
print "  Interface:  $IFACE ($LOCAL_IP)"
print "  Gateway:    $GATEWAY"
print "  Server:     $SERVER"
print "  Evidence:   $RESULTS"
[[ -n "$START_EPOCH" ]] && print "  Start epoch: $START_EPOCH"

wait_for_start
print "Started UTC: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"

if [[ "$MODE" == "observe" ]]; then
    run_observer
    exit $?
fi

mark_phase "udp_upload_control_start"
iperf3 -c "$SERVER" -p "$UPLOAD_PORT" -4 -B "$LOCAL_IP%$IFACE" \
    -u -b "$RATE" -l "$PACKET_SIZE" -t "$DIRECTIONAL_SECONDS" \
    -O "$OMIT_SECONDS" -J \
    > "$RESULTS/udp-upload-only.json" 2> "$RESULTS/udp-upload-only.stderr" || exit $?

sleep 3

mark_phase "udp_download_control_start"
iperf3 -c "$SERVER" -p "$DOWNLOAD_PORT" -4 -B "$LOCAL_IP%$IFACE" \
    -u -b "$RATE" -l "$PACKET_SIZE" -t "$DIRECTIONAL_SECONDS" \
    -O "$OMIT_SECONDS" -R -J \
    > "$RESULTS/udp-download-only.json" 2> "$RESULTS/udp-download-only.stderr" || exit $?

sleep 3
mark_phase "udp_gateway_idle_start"
ping --apple-time -b "$IFACE" -n -i "$PING_INTERVAL" -c "$IDLE_PING_COUNT" "$GATEWAY" \
    > "$RESULTS/udp-gateway-idle.txt" 2> "$RESULTS/udp-gateway-idle.stderr" || exit $?

sleep 2
mark_phase "udp_simultaneous_1_start"
run_udp_simultaneous 1 || exit $?
sleep 3
mark_phase "udp_simultaneous_2_start"
run_udp_simultaneous 2 || exit $?

sleep 5

mark_phase "tcp_upload_control_start"
iperf3 -c "$SERVER" -p "$UPLOAD_PORT" -4 -B "$LOCAL_IP%$IFACE" \
    -b "$TCP_RATE_PER_STREAM" -P "$TCP_PARALLEL" -l "$TCP_BLOCK_SIZE" \
    -t "$DIRECTIONAL_SECONDS" -O "$OMIT_SECONDS" -J \
    > "$RESULTS/tcp-upload-only.json" 2> "$RESULTS/tcp-upload-only.stderr" || exit $?

sleep 3

mark_phase "tcp_download_control_start"
iperf3 -c "$SERVER" -p "$DOWNLOAD_PORT" -4 -B "$LOCAL_IP%$IFACE" \
    -b "$TCP_RATE_PER_STREAM" -P "$TCP_PARALLEL" -l "$TCP_BLOCK_SIZE" \
    -t "$DIRECTIONAL_SECONDS" -O "$OMIT_SECONDS" -R -J \
    > "$RESULTS/tcp-download-only.json" 2> "$RESULTS/tcp-download-only.stderr" || exit $?

sleep 3
mark_phase "tcp_gateway_idle_start"
ping --apple-time -b "$IFACE" -n -i "$PING_INTERVAL" -c "$IDLE_PING_COUNT" "$GATEWAY" \
    > "$RESULTS/tcp-gateway-idle.txt" 2> "$RESULTS/tcp-gateway-idle.stderr" || exit $?

sleep 2
mark_phase "tcp_simultaneous_1_start"
run_tcp_simultaneous 1 || exit $?
sleep 3
mark_phase "tcp_simultaneous_2_start"
run_tcp_simultaneous 2 || exit $?
mark_phase "load_suite_end"

print
print_summary
print
print "Raw evidence: $RESULTS"
