#!/usr/bin/env python3
"""Canary in the coalmine — peer-impact companion monitor.

Calibrates on quiet gateway pings, then enters TEST MODE and runs the same
UDP→TCP matrix as fragglepacket's bhusa-peer-impact-test.zsh so results can be
compared side-by-side. UDP and TCP are scored/reported separately so the
mid-suite transport switch cannot skew a single baseline.
"""

from __future__ import annotations

import argparse
import curses
import json
import math
import os
import random
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Deque, Optional, Tuple


# ── Defaults aligned with fragglepacket/scripts/bhusa-peer-impact-test.zsh ──
DEFAULT_IFACE = "en0"
# No baked-in lab server — require --server / SERVER (or --protoevidence).
DEFAULT_UPLOAD_PORT = 5201
DEFAULT_DOWNLOAD_PORT = 5202
DEFAULT_RATE = "350M"
HOST_RE = re.compile(
    r"^(?:"
    r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)"  # IPv4
    r"|(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*)"  # hostname
    r")$"
)
IFACE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{0,31}$")
RATE_RE = re.compile(r"^\d+(?:\.\d+)?[KkMmGg]?$")
DEFAULT_PACKET_SIZE = 1472
DEFAULT_TCP_PARALLEL = 4
DEFAULT_TCP_RATE_PER_STREAM = "87.5M"
DEFAULT_TCP_BLOCK_SIZE = "128K"
DEFAULT_DIRECTIONAL_SECONDS = 7
DEFAULT_SIMULTANEOUS_SECONDS = 12
DEFAULT_OMIT_SECONDS = 1
DEFAULT_PING_INTERVAL = 0.2
DEFAULT_IDLE_PING_COUNT = 25
DEFAULT_LOADED_PING_COUNT = 65
DEFAULT_CALIBRATE_SECONDS = 60
DEFAULT_HISTORY = 72
TREND_SECONDS = 5.0  # ping average window for up/flat/down trend
TREND_FLAT_ABS_MS = 1.0  # treat as flat if |Δ| ≤ this…
TREND_FLAT_FRAC = 0.05   # …or ≤ 5% of prior window avg

CAGE = [
    "   ╒════════════╕   ",
    "   ││  .--.  <)││   ",
    "   ││ ( o> )   ││   ",
    "   ││ /)  (\\   ││   ",
    '   ││ ""  ""   ││   ',
    "   ││   ||     ││   ",
    "   ││  _||_    ││   ",
    "   ││ //  \\\\   ││   ",
    "   ╘════╤═══════╛   ",
    "        │           ",
    "       ═╧═          ",
]

# Compact "this is fine" dog — shown under the bird when the mine is on fire.
THIS_IS_FINE = [
    r"   \,,,,_     ~~",
    r"    | o o|   ~~~",
    r"    |  = |  ~~~~",
    r"    |    |   ~~ ",
    r"   /|____|\     ",
    r"  THIS IS FINE  ",
]

FINE_LAT_MS = 50.0
FINE_LOSS_PCT = 10.0
FINE_THRUPUT_MBPS = 50.0

QUIPS = {
    "calibrating": [
        "Learning the quiet…",
        "Sniffing the air…",
        "Calibrating my feathers…",
        "What does normal even feel like?",
    ],
    "armed": [
        "Calibrated. Waiting on you…",
        "Hit ENTER to run the suite with your companion.",
        "Perched. Not probing. Your call.",
    ],
    "test": [
        "Test mode. Eyes open.",
        "Matching his matrix. Chirp.",
        "UDP first. TCP later. Don't mix the coal.",
        "Running alongside the other canary…",
        "If the cage rattles, we write it down.",
    ],
    "nominal": [
        "All quiet in the mine.",
        "Chirp. Still breathing.",
        "The canary approves.",
        "Nominal is my middle name.",
    ],
    "warning": [
        "Something's in the air…",
        "Is that… bufferbloat?",
        "Latency's getting spicy.",
        "Someone's chewing the pipe.",
    ],
    "alert": [
        "CHIRP CHIRP — GET OUT",
        "COAL DUST! Latency spike!",
        "I'm not dramatic, you're saturated.",
        "Evacuate the mine shaft!",
    ],
    "report": [
        "Suite done. Compare notes with the other bird.",
        "Report filed. Still watching the shaft.",
        "Tables look familiar, don't they?",
    ],
}


@dataclass
class Sample:
    t: float
    value: float
    extra: float = 0.0  # loss% (UDP) or retransmits (TCP)
    proto: str = "udp"  # udp | tcp


@dataclass
class PingBaseline:
    ready: bool = False
    ping_ms: float = 0.0
    samples: int = 0


@dataclass
class LossRun:
    label: str
    lost: int
    loss_pct: float
    t: float = field(default_factory=time.time)


@dataclass
class Config:
    iface: str = DEFAULT_IFACE
    server: str = ""  # required at runtime via --server / SERVER
    upload_port: int = DEFAULT_UPLOAD_PORT
    download_port: int = DEFAULT_DOWNLOAD_PORT
    ping_target: str = ""  # defaults to iface gateway
    rate: str = DEFAULT_RATE
    packet_size: int = DEFAULT_PACKET_SIZE
    tcp_parallel: int = DEFAULT_TCP_PARALLEL
    tcp_rate_per_stream: str = DEFAULT_TCP_RATE_PER_STREAM
    tcp_block_size: str = DEFAULT_TCP_BLOCK_SIZE
    directional_seconds: int = DEFAULT_DIRECTIONAL_SECONDS
    simultaneous_seconds: int = DEFAULT_SIMULTANEOUS_SECONDS
    omit_seconds: int = DEFAULT_OMIT_SECONDS
    ping_interval: float = DEFAULT_PING_INTERVAL
    idle_ping_count: int = DEFAULT_IDLE_PING_COUNT
    loaded_ping_count: int = DEFAULT_LOADED_PING_COUNT
    calibrate_seconds: float = DEFAULT_CALIBRATE_SECONDS


@dataclass
class State:
    cfg: Config = field(default_factory=Config)
    started: float = field(default_factory=time.time)
    # lifecycle: calibrating → armed → test → report
    mode: str = "calibrating"
    status: str = "calibrating"
    protocol: str = "—"  # udp | tcp | —
    suite_step: str = "waiting"
    round_id: int = 0
    local_ip: str = ""
    gateway: str = ""
    results_dir: Optional[Path] = None
    summary_text: str = ""
    ping_hist: Deque[Sample] = field(default_factory=lambda: deque(maxlen=DEFAULT_HISTORY))
    ping_avg_hist: Deque[Sample] = field(default_factory=lambda: deque(maxlen=DEFAULT_HISTORY))
    # Separate histories so UDP↔TCP switch cannot skew one chart/baseline
    udp_up_hist: Deque[Sample] = field(default_factory=lambda: deque(maxlen=DEFAULT_HISTORY))
    udp_down_hist: Deque[Sample] = field(default_factory=lambda: deque(maxlen=DEFAULT_HISTORY))
    tcp_up_hist: Deque[Sample] = field(default_factory=lambda: deque(maxlen=DEFAULT_HISTORY))
    tcp_down_hist: Deque[Sample] = field(default_factory=lambda: deque(maxlen=DEFAULT_HISTORY))
    last_ping_ms: Optional[float] = None
    last_ping_avg_5s: Optional[float] = None
    ping_trend: str = "flat"  # up | flat | down
    last_up_mbps: Optional[float] = None
    last_up_extra: Optional[float] = None
    last_down_mbps: Optional[float] = None
    last_down_extra: Optional[float] = None
    last_iperf_label: str = "—"
    fine_dog: bool = False  # sticky: once the room is on fire, dog stays
    fine_reason: str = ""
    loss_runs: Deque[LossRun] = field(default_factory=lambda: deque(maxlen=16))
    total_packets_lost: int = 0
    baseline: PingBaseline = field(default_factory=PingBaseline)
    quip: str = "Waking up…"
    quip_until: float = 0.0
    events: Deque[str] = field(default_factory=lambda: deque(maxlen=10))
    errors: Deque[str] = field(default_factory=lambda: deque(maxlen=4))
    stop: threading.Event = field(default_factory=threading.Event)
    suite_go: threading.Event = field(default_factory=threading.Event)
    lock: threading.Lock = field(default_factory=threading.Lock)
    task: str = "perching…"
    task_phase: str = "init"
    task_started: float = field(default_factory=time.time)
    task_ends_at: Optional[float] = None
    ping_count: int = 0
    probe_count: int = 0


def validate_iface(iface: str) -> str:
    if not IFACE_RE.fullmatch(iface):
        raise ValueError(f"invalid interface name: {iface!r}")
    return iface


def validate_host(host: str, *, what: str = "host") -> str:
    host = host.strip()
    if not host or not HOST_RE.fullmatch(host):
        raise ValueError(f"invalid {what}: {host!r} (IPv4 or hostname required)")
    return host


def validate_port(port: int, *, what: str = "port") -> int:
    if not isinstance(port, int) or isinstance(port, bool) or not (1 <= port <= 65535):
        raise ValueError(f"invalid {what}: {port!r} (need 1–65535)")
    return port


def validate_rate(rate: str, *, what: str = "rate") -> str:
    rate = rate.strip()
    if not RATE_RE.fullmatch(rate):
        raise ValueError(f"invalid {what}: {rate!r} (examples: 100M, 87.5M, 500K)")
    return rate


def resolve_net(iface: str) -> tuple[str, str]:
    iface = validate_iface(iface)
    ip = subprocess.check_output(["ipconfig", "getifaddr", iface], text=True).strip()
    gw = subprocess.check_output(["ipconfig", "getoption", iface, "router"], text=True).strip()
    if not ip:
        raise RuntimeError(f"no IPv4 address on {iface}")
    if not gw:
        raise RuntimeError(f"no gateway/router on {iface}")
    return ip, validate_host(gw, what="gateway")


def bind_host(local_ip: str, iface: str) -> str:
    return f"{local_ip}%{iface}"


def parse_ping_line(line: str) -> Optional[float]:
    m = re.search(r"time[=<]([0-9.]+)\s*ms", line)
    return float(m.group(1)) if m else None


def _avg_in_window(hist: Deque[Sample], now: float, start_ago: float, end_ago: float) -> Optional[float]:
    """Mean of samples with timestamps in [now-start_ago, now-end_ago]."""
    lo_t = now - start_ago
    hi_t = now - end_ago
    vals = [s.value for s in hist if lo_t <= s.t <= hi_t]
    if not vals:
        return None
    return sum(vals) / len(vals)


def update_ping_trend(state: State, now: Optional[float] = None) -> None:
    """Compare the latest 5s ping average to the prior 5s window → up/flat/down."""
    now = now if now is not None else time.time()
    current = _avg_in_window(state.ping_hist, now, TREND_SECONDS, 0.0)
    previous = _avg_in_window(state.ping_hist, now, TREND_SECONDS * 2, TREND_SECONDS)
    state.last_ping_avg_5s = current
    if current is not None:
        state.ping_avg_hist.append(Sample(now, current))
    if current is None or previous is None or previous <= 0:
        state.ping_trend = "flat"
        return
    delta = current - previous
    if abs(delta) <= max(TREND_FLAT_ABS_MS, previous * TREND_FLAT_FRAC):
        state.ping_trend = "flat"
    elif delta > 0:
        state.ping_trend = "up"
    else:
        state.ping_trend = "down"


def parse_ping_loss_pct(text: str) -> Optional[float]:
    m = re.search(r"([0-9.]+)% packet loss", text)
    return float(m.group(1)) if m else None


def record_loss(state: State, label: str, lost: int, loss_pct: float) -> None:
    """Append a per-run loss result and bump the cumulative counter."""
    entry = LossRun(label=label, lost=max(0, int(lost)), loss_pct=float(loss_pct))
    state.loss_runs.appendleft(entry)
    state.total_packets_lost += entry.lost
    add_event(
        state,
        f"LOSS {label}: {entry.lost:,} pkts ({entry.loss_pct:.3f}%)  "
        f"total {state.total_packets_lost:,}",
    )


def sparkline(values: list[float], width: int, height: int = 8) -> Tuple[list[str], float, float]:
    blocks = " ▁▂▃▄▅▆▇█"
    if width < 8:
        width = 8
    if not values:
        empty = [" " * width for _ in range(height)]
        empty[-1] = "·" * width
        return empty, 0.0, 1.0

    data = values[-width:]
    if len(data) < width:
        data = [float("nan")] * (width - len(data)) + data

    finite = [v for v in data if not math.isnan(v)]
    if not finite:
        return [" " * width for _ in range(height)], 0.0, 1.0

    lo = min(finite)
    hi = max(finite)
    if hi <= lo:
        hi = lo + 1.0

    grid = [[" " for _ in range(width)] for _ in range(height)]
    for x, v in enumerate(data):
        if math.isnan(v):
            continue
        norm = (v - lo) / (hi - lo)
        level = norm * height
        full = int(level)
        frac = level - full
        for y in range(full):
            if y < height:
                grid[height - 1 - y][x] = "█"
        if full < height:
            idx = min(len(blocks) - 1, int(frac * (len(blocks) - 1)))
            if idx > 0:
                grid[height - 1 - full][x] = blocks[idx]

    return ["".join(r) for r in grid], lo, hi


def fmt_age(seconds: float) -> str:
    s = int(seconds)
    m, s = divmod(s, 60)
    h, m = divmod(m, 60)
    if h:
        return f"{h}h{m:02d}m"
    return f"{m}m{s:02d}s"


def add_event(state: State, msg: str) -> None:
    stamp = datetime.now().strftime("%H:%M:%S")
    state.events.appendleft(f"{stamp}  {msg}")


def set_task(
    state: State,
    task: str,
    phase: str,
    ends_at: Optional[float] = None,
) -> None:
    state.task = task
    state.task_phase = phase
    state.task_started = time.time()
    state.task_ends_at = ends_at


def mark_phase(results: Path, phase: str) -> None:
    line = f"{int(time.time())}\t{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}\t{phase}\n"
    with (results / "timeline.tsv").open("a") as fh:
        fh.write(line)


def maybe_quip(state: State, force: bool = False) -> None:
    now = time.time()
    if not force and now < state.quip_until:
        return
    key = state.status if state.status in QUIPS else state.mode
    bucket = QUIPS.get(key, QUIPS["nominal"])
    state.quip = random.choice(bucket)
    linger = {
        "calibrating": 8,
        "armed": 10,
        "test": 10,
        "nominal": 14,
        "warning": 9,
        "alert": 5,
        "report": 12,
    }.get(state.status, 12)
    state.quip_until = now + linger + random.uniform(0, 4)


def update_fine_dog(state: State, *, udp_loss: Optional[float] = None) -> None:
    """Summon the dog when latency, loss, or throughput crosses the 'fine' line."""
    reasons: list[str] = []
    if state.last_ping_ms is not None and state.last_ping_ms > FINE_LAT_MS:
        reasons.append(f"latency {state.last_ping_ms:.0f}ms")
    loss = udp_loss
    if loss is None and state.protocol == "udp":
        candidates = [x for x in (state.last_up_extra, state.last_down_extra) if x is not None]
        loss = max(candidates) if candidates else None
    if loss is not None and loss > FINE_LOSS_PCT:
        reasons.append(f"loss {loss:.1f}%")
    for label, mbps in (("↑", state.last_up_mbps), ("↓", state.last_down_mbps)):
        if mbps is not None and mbps < FINE_THRUPUT_MBPS:
            reasons.append(f"{label}{mbps:.0f}Mbps")
    if not reasons:
        return
    state.fine_dog = True
    state.fine_reason = ", ".join(reasons[:3])


def evaluate_ping(state: State) -> None:
    """Ping-only health vs calibration baseline. Never mixes UDP/TCP throughput."""
    if state.mode == "calibrating":
        age = time.time() - state.started
        pings = [s.value for s in state.ping_hist]
        if age >= state.cfg.calibrate_seconds and len(pings) >= 20:
            state.baseline.ping_ms = sum(pings) / len(pings)
            state.baseline.samples = len(pings)
            state.baseline.ready = True
            state.mode = "armed"
            state.status = "armed"
            state.suite_step = "press-enter"
            set_task(
                state,
                "CALIBRATION COMPLETE — metrics paused. Press ENTER to start suite "
                "(runs simultaneously with companion)",
                "armed",
            )
            add_event(
                state,
                f"CALIBRATION COMPLETE — ping baseline {state.baseline.ping_ms:.1f}ms "
                f"(n={state.baseline.samples}) — PRESS ENTER to run with companion",
            )
            maybe_quip(state, force=True)
        else:
            state.status = "calibrating"
        return

    if state.mode in ("armed", "report"):
        state.status = state.mode
        return

    if not state.baseline.ready or state.baseline.ping_ms <= 0:
        return

    # During active suite, only ping drives live alert color
    score = 0
    reasons: list[str] = []
    if state.last_ping_ms is not None:
        ratio = state.last_ping_ms / state.baseline.ping_ms
        if state.last_ping_ms > max(80.0, state.baseline.ping_ms * 4) or ratio >= 4:
            score = 2
            reasons.append(f"ping {state.last_ping_ms:.0f}ms")
        elif state.last_ping_ms > max(40.0, state.baseline.ping_ms * 2.2) or ratio >= 2.2:
            score = 1
            reasons.append(f"ping {state.last_ping_ms:.0f}ms")

    recent = [s.value for s in list(state.ping_hist)[-12:]]
    if recent:
        avg = sum(recent) / len(recent)
        if avg > max(60.0, state.baseline.ping_ms * 3):
            score = max(score, 2)
        elif avg > max(30.0, state.baseline.ping_ms * 1.8):
            score = max(score, 1)

    new = {0: "test", 1: "warning", 2: "alert"}[score]
    if state.mode == "test" and score == 0:
        new = "test"
    if new != state.status:
        state.status = new
        if reasons:
            add_event(state, f"{new.upper()}: {', '.join(reasons[:3])}")
        maybe_quip(state, force=True)


def format_ticker(snap: dict, now: float, width: int, scroll: int) -> str:
    task = snap["task"]
    phase = snap["task_phase"]
    ends = snap["task_ends_at"]
    started = snap["task_started"]
    elapsed = max(0.0, now - started)
    eta = f"  │  eta {max(0.0, ends - now):4.1f}s" if ends is not None else f"  │  t+{elapsed:4.1f}s"
    ping_bit = ""
    if snap["last_ping"] is not None:
        ping_bit = f"  │  ping #{snap['ping_count']} {snap['last_ping']:.1f}ms"

    mode_bit = f"  │  {snap['mode'].upper()}"
    if snap["mode"] == "calibrating":
        age = now - snap["started_at"]
        mode_bit += f" {min(age, snap['calibrate_for']):.0f}/{snap['calibrate_for']:.0f}s"
    elif snap["mode"] == "armed":
        mode_bit += " · PRESS ENTER → RUN SUITE WITH COMPANION"
    elif snap["protocol"] != "—":
        mode_bit += f"/{snap['protocol'].upper()} · {snap['suite_step']}"

    prefix = {
        "init": "INIT",
        "ping": "PING",
        "calibrate": "CAL",
        "armed": "ARM",
        "udp": "UDP",
        "tcp": "TCP",
        "gap": "WAIT",
        "report": "RPT",
        "error": "ERR",
        "iperf-up": "↑",
        "iperf-down": "↓",
        "sim": "SIM",
        "idle": "IDLE",
    }.get(phase, phase.upper()[:6])

    full = f"▶ {prefix}  {task}{eta}{ping_bit}{mode_bit}   ·   Ctrl+C/q quit   ·   "
    if len(full) <= width:
        return full.ljust(width)[:width]
    offset = scroll % len(full)
    return (full[offset:] + full[:offset])[:width]


# ── iperf / ping runners (peer-impact parity) ───────────────────────────────

def run_iperf_udp(
    cfg: Config,
    local_ip: str,
    reverse: bool,
    seconds: int,
    out_json: Path,
    out_err: Path,
) -> tuple[float, float, int]:
    port = cfg.download_port if reverse else cfg.upload_port
    cmd = [
        "iperf3", "-c", cfg.server, "-p", str(port), "-4",
        "-B", bind_host(local_ip, cfg.iface),
        "-u", "-b", cfg.rate, "-l", str(cfg.packet_size),
        "-t", str(seconds), "-O", str(cfg.omit_seconds), "-J",
    ]
    if reverse:
        cmd.append("-R")
    with out_json.open("w") as stdout, out_err.open("w") as stderr:
        proc = subprocess.run(cmd, stdout=stdout, stderr=stderr, timeout=seconds + 30)
    raw = out_json.read_text().strip()
    if not raw:
        err_lines = out_err.read_text().strip().splitlines()
        raise RuntimeError(err_lines[-1] if err_lines else f"iperf3 udp failed rc={proc.returncode}")
    data = json.loads(raw)
    if data.get("error"):
        raise RuntimeError(data["error"])
    if proc.returncode != 0:
        err_lines = out_err.read_text().strip().splitlines()
        raise RuntimeError(err_lines[-1] if err_lines else f"iperf3 udp failed rc={proc.returncode}")
    received = data["end"]["sum_received"]
    return (
        received["bits_per_second"] / 1e6,
        float(received.get("lost_percent") or 0.0),
        int(received.get("lost_packets") or 0),
    )


def run_iperf_tcp(
    cfg: Config,
    local_ip: str,
    reverse: bool,
    seconds: int,
    out_json: Path,
    out_err: Path,
) -> tuple[float, int]:
    port = cfg.download_port if reverse else cfg.upload_port
    cmd = [
        "iperf3", "-c", cfg.server, "-p", str(port), "-4",
        "-B", bind_host(local_ip, cfg.iface),
        "-b", cfg.tcp_rate_per_stream, "-P", str(cfg.tcp_parallel),
        "-l", cfg.tcp_block_size,
        "-t", str(seconds), "-O", str(cfg.omit_seconds), "-J",
    ]
    if reverse:
        cmd.append("-R")
    with out_json.open("w") as stdout, out_err.open("w") as stderr:
        proc = subprocess.run(cmd, stdout=stdout, stderr=stderr, timeout=seconds + 30)
    raw = out_json.read_text().strip()
    if not raw:
        err_lines = out_err.read_text().strip().splitlines()
        raise RuntimeError(err_lines[-1] if err_lines else f"iperf3 tcp failed rc={proc.returncode}")
    data = json.loads(raw)
    if data.get("error"):
        raise RuntimeError(data["error"])
    if proc.returncode != 0:
        err_lines = out_err.read_text().strip().splitlines()
        raise RuntimeError(err_lines[-1] if err_lines else f"iperf3 tcp failed rc={proc.returncode}")
    received = data["end"]["sum_received"]
    sent = data["end"].get("sum_sent", {})
    return received["bits_per_second"] / 1e6, int(sent.get("retransmits") or 0)


def run_gateway_ping(
    cfg: Config,
    gateway: str,
    count: int,
    out_txt: Path,
    out_err: Path,
) -> Optional[float]:
    """Run a counted gateway ping. Returns packet-loss percent when parseable."""
    cmd = [
        "ping", "--apple-time", "-b", cfg.iface, "-n",
        "-i", str(cfg.ping_interval), "-c", str(count), gateway,
    ]
    with out_txt.open("w") as stdout, out_err.open("w") as stderr:
        proc = subprocess.run(cmd, stdout=stdout, stderr=stderr, timeout=count * cfg.ping_interval + 30)
    text = out_txt.read_text(errors="replace")
    if proc.returncode != 0 and not text.strip():
        raise RuntimeError(f"ping failed rc={proc.returncode}")
    return parse_ping_loss_pct(text)


def interruptible_sleep(state: State, seconds: float, task: str) -> bool:
    """Sleep in slices; return True if stop requested."""
    ends = time.time() + seconds
    while not state.stop.is_set():
        remain = ends - time.time()
        if remain <= 0:
            return False
        with state.lock:
            set_task(state, task + f" ({remain:.1f}s)", "gap", ends_at=ends)
        if state.stop.wait(min(0.5, remain)):
            return True
    return True


# ── peer-impact summary (format parity) ─────────────────────────────────────

def build_summary(results: Path, rate: str, tcp_parallel: int) -> str:
    def iperf_udp(filename: str):
        data = json.loads((results / filename).read_text())
        if data.get("error"):
            raise RuntimeError(data["error"])
        received = data["end"]["sum_received"]
        return (
            received["bits_per_second"] / 1e6,
            received.get("lost_percent", 0),
            received.get("lost_packets", 0),
        )

    def iperf_tcp(filename: str):
        data = json.loads((results / filename).read_text())
        if data.get("error"):
            raise RuntimeError(data["error"])
        received = data["end"]["sum_received"]
        sent = data["end"].get("sum_sent", {})
        return received["bits_per_second"] / 1e6, sent.get("retransmits", 0)

    def gateway(filename: str):
        text = (results / filename).read_text(errors="replace")
        latency = re.search(
            r"(?:round-trip|rtt) min/avg/max/(?:stddev|mdev) = "
            r"([0-9.]+)/([0-9.]+)/([0-9.]+)/([0-9.]+) ms",
            text,
        )
        loss = re.search(r"([0-9.]+)% packet loss", text)
        if not latency:
            return None
        values = tuple(map(float, latency.groups()))
        return values, float(loss.group(1)) if loss else 0.0

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
        return (
            f"{samples[1]:.1f} ms average, {samples[2]:.1f} ms maximum, "
            f"{loss:g}% loss"
        )

    def table(title, rows):
        headers = ["Test", "Upload", "Download", "Gateway latency"]
        widths = [max(len(headers[i]), *(len(row[i]) for row in rows)) for i in range(4)]

        def line(values):
            return "  ".join(values[i].ljust(widths[i]) for i in range(4))

        separator = "  ".join("-" * width for width in widths)
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

    header = "CANARY peer-impact companion report\n"
    summary = header
    summary += table(f"UDP — {rate} per direction", udp_rows)
    summary += "\n\n"
    summary += table(
        f"TCP — {rate} target per direction, {tcp_parallel} streams",
        tcp_rows,
    )
    return summary


# ── workers ─────────────────────────────────────────────────────────────────

def ping_worker(state: State) -> None:
    cfg = state.cfg
    target = cfg.ping_target or state.gateway
    cmd = [
        "ping", "--apple-time", "-b", cfg.iface, "-n",
        "-i", str(cfg.ping_interval), target,
    ]
    with state.lock:
        set_task(state, f"calibration ping stream → {target}", "calibrate")
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
        )
    except Exception as exc:  # noqa: BLE001
        with state.lock:
            state.errors.appendleft(f"ping failed: {exc}")
            set_task(state, f"ping failed: {exc}", "error")
        return

    assert proc.stdout is not None
    try:
        for line in proc.stdout:
            if state.stop.is_set():
                break
            ms = parse_ping_line(line)
            if ms is None:
                continue
            with state.lock:
                state.last_ping_ms = ms
                state.ping_count += 1
                state.ping_hist.append(Sample(time.time(), ms))
                update_ping_trend(state)
                evaluate_ping(state)
                if state.mode in ("test", "report"):
                    update_fine_dog(state)
                if state.mode == "calibrating":
                    age = time.time() - state.started
                    set_task(
                        state,
                        f"calibrating RTT → {target} "
                        f"(last {ms:.2f}ms, n={state.ping_count}, "
                        f"{min(age, cfg.calibrate_seconds):.0f}/{cfg.calibrate_seconds:.0f}s)",
                        "calibrate",
                    )
                elif state.mode == "armed":
                    set_task(
                        state,
                        "metrics paused after calibration — Press ENTER to start suite "
                        f"alongside companion (ping still watching {target}: {ms:.2f}ms)",
                        "armed",
                    )
    finally:
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()


def handle_enter(state: State) -> None:
    """Single gate: armed → kick suite_go so canary runs with the companion."""
    with state.lock:
        if state.mode == "armed":
            state.mode = "test"
            state.status = "test"
            state.suite_step = "starting"
            set_task(
                state,
                "ENTER received — starting peer-impact suite NOW (simultaneous with companion)",
                "test",
            )
            add_event(state, "GO — running suite alongside companion")
            maybe_quip(state, force=True)
            state.suite_go.set()


def run_udp_simultaneous(state: State, results: Path, run_id: int) -> None:
    cfg = state.cfg
    ends = time.time() + cfg.simultaneous_seconds + 2
    with state.lock:
        state.suite_step = f"udp-sim-{run_id}"
        set_task(
            state,
            f"UDP simultaneous run {run_id}: ↑{cfg.upload_port} + ↓{cfg.download_port} "
            f"@ {cfg.rate} for {cfg.simultaneous_seconds}s + loaded gateway ping",
            "sim",
            ends_at=ends,
        )

    ping_out = results / f"udp-gateway-loaded-{run_id}.txt"
    ping_err = results / f"udp-gateway-loaded-{run_id}.stderr"
    up_json = results / f"udp-sim-upload-{run_id}.json"
    up_err = results / f"udp-sim-upload-{run_id}.stderr"
    down_json = results / f"udp-sim-download-{run_id}.json"
    down_err = results / f"udp-sim-download-{run_id}.stderr"

    ping_target = cfg.ping_target or state.gateway
    ping_proc = subprocess.Popen(
        [
            "ping", "--apple-time", "-b", cfg.iface, "-n",
            "-i", str(cfg.ping_interval), "-c", str(cfg.loaded_ping_count),
            ping_target,
        ],
        stdout=ping_out.open("w"),
        stderr=ping_err.open("w"),
    )

    def up():
        return run_iperf_udp(cfg, state.local_ip, False, cfg.simultaneous_seconds, up_json, up_err)

    def down():
        return run_iperf_udp(cfg, state.local_ip, True, cfg.simultaneous_seconds, down_json, down_err)

    up_result: list = []
    down_result: list = []
    up_exc: list = []
    down_exc: list = []

    def wrap(fn, bucket, err_bucket):
        try:
            bucket.append(fn())
        except Exception as exc:  # noqa: BLE001
            err_bucket.append(exc)

    t_up = threading.Thread(target=wrap, args=(up, up_result, up_exc))
    t_down = threading.Thread(target=wrap, args=(down, down_result, down_exc))
    t_up.start()
    t_down.start()
    t_up.join()
    t_down.join()
    ping_proc.wait(timeout=cfg.loaded_ping_count * cfg.ping_interval + 30)
    gw_loss = parse_ping_loss_pct(ping_out.read_text(errors="replace"))

    if up_exc:
        raise up_exc[0]
    if down_exc:
        raise down_exc[0]

    mbps_u, loss_u, lost_u = up_result[0]
    mbps_d, loss_d, lost_d = down_result[0]
    with state.lock:
        state.probe_count += 2
        state.last_up_mbps, state.last_up_extra = mbps_u, loss_u
        state.last_down_mbps, state.last_down_extra = mbps_d, loss_d
        state.udp_up_hist.append(Sample(time.time(), mbps_u, loss_u, "udp"))
        state.udp_down_hist.append(Sample(time.time(), mbps_d, loss_d, "udp"))
        state.last_iperf_label = (
            f"UDP sim{run_id} ↑{mbps_u:.1f} ({lost_u} lost) ↓{mbps_d:.1f} ({lost_d} lost)"
        )
        add_event(state, state.last_iperf_label)
        record_loss(state, f"UDP sim{run_id} ↑", lost_u, loss_u)
        record_loss(state, f"UDP sim{run_id} ↓", lost_d, loss_d)
        if gw_loss is not None:
            lost_gw = int(round(cfg.loaded_ping_count * gw_loss / 100.0))
            record_loss(state, f"UDP sim{run_id} gw", lost_gw, gw_loss)
        update_fine_dog(state, udp_loss=max(loss_u, loss_d))


def run_tcp_simultaneous(state: State, results: Path, run_id: int) -> None:
    cfg = state.cfg
    ends = time.time() + cfg.simultaneous_seconds + 2
    with state.lock:
        state.suite_step = f"tcp-sim-{run_id}"
        set_task(
            state,
            f"TCP simultaneous run {run_id}: ↑{cfg.upload_port} + ↓{cfg.download_port} "
            f"{cfg.tcp_parallel}×{cfg.tcp_rate_per_stream} for {cfg.simultaneous_seconds}s",
            "sim",
            ends_at=ends,
        )

    ping_out = results / f"tcp-gateway-loaded-{run_id}.txt"
    ping_err = results / f"tcp-gateway-loaded-{run_id}.stderr"
    up_json = results / f"tcp-sim-upload-{run_id}.json"
    up_err = results / f"tcp-sim-upload-{run_id}.stderr"
    down_json = results / f"tcp-sim-download-{run_id}.json"
    down_err = results / f"tcp-sim-download-{run_id}.stderr"

    ping_target = cfg.ping_target or state.gateway
    ping_proc = subprocess.Popen(
        [
            "ping", "--apple-time", "-b", cfg.iface, "-n",
            "-i", str(cfg.ping_interval), "-c", str(cfg.loaded_ping_count),
            ping_target,
        ],
        stdout=ping_out.open("w"),
        stderr=ping_err.open("w"),
    )

    up_result: list = []
    down_result: list = []
    up_exc: list = []
    down_exc: list = []

    def wrap(fn, bucket, err_bucket):
        try:
            bucket.append(fn())
        except Exception as exc:  # noqa: BLE001
            err_bucket.append(exc)

    t_up = threading.Thread(
        target=wrap,
        args=(
            lambda: run_iperf_tcp(
                cfg, state.local_ip, False, cfg.simultaneous_seconds, up_json, up_err
            ),
            up_result,
            up_exc,
        ),
    )
    t_down = threading.Thread(
        target=wrap,
        args=(
            lambda: run_iperf_tcp(
                cfg, state.local_ip, True, cfg.simultaneous_seconds, down_json, down_err
            ),
            down_result,
            down_exc,
        ),
    )
    t_up.start()
    t_down.start()
    t_up.join()
    t_down.join()
    ping_proc.wait(timeout=cfg.loaded_ping_count * cfg.ping_interval + 30)
    gw_loss = parse_ping_loss_pct(ping_out.read_text(errors="replace"))

    if up_exc:
        raise up_exc[0]
    if down_exc:
        raise down_exc[0]

    mbps_u, ret_u = up_result[0]
    mbps_d, ret_d = down_result[0]
    with state.lock:
        state.probe_count += 2
        state.last_up_mbps, state.last_up_extra = mbps_u, float(ret_u)
        state.last_down_mbps, state.last_down_extra = mbps_d, float(ret_d)
        state.tcp_up_hist.append(Sample(time.time(), mbps_u, float(ret_u), "tcp"))
        state.tcp_down_hist.append(Sample(time.time(), mbps_d, float(ret_d), "tcp"))
        state.last_iperf_label = (
            f"TCP sim{run_id} ↑{mbps_u:.1f} ({ret_u} rexmit) ↓{mbps_d:.1f} ({ret_d} rexmit)"
        )
        add_event(state, state.last_iperf_label)
        if gw_loss is not None:
            lost_gw = int(round(cfg.loaded_ping_count * gw_loss / 100.0))
            record_loss(state, f"TCP sim{run_id} gw", lost_gw, gw_loss)
        update_fine_dog(state)


def run_peer_impact_suite(state: State) -> Path:
    """One full UDP→TCP matrix matching bhusa-peer-impact-test.zsh (load mode)."""
    cfg = state.cfg
    with state.lock:
        state.round_id += 1
        rid = state.round_id
        state.mode = "test"
        state.status = "test"
        state.protocol = "udp"
    results = Path(tempfile.mkdtemp(prefix=f"bhusa-canary-r{rid}."))
    with state.lock:
        state.results_dir = results
        add_event(state, f"TEST MODE round {rid} → {results}")
        maybe_quip(state, force=True)

    meta = results / "metadata.txt"
    meta.write_text(
        "\n".join([
            "label=canary",
            "mode=load",
            f"started_utc={datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
            f"interface={cfg.iface}",
            f"local_ip={state.local_ip}",
            f"gateway={state.gateway}",
            f"ping_target={cfg.ping_target or state.gateway}",
            f"server={cfg.server}",
            f"upload_port={cfg.upload_port}",
            f"download_port={cfg.download_port}",
            f"rate={cfg.rate}",
            f"packet_size={cfg.packet_size}",
            "tcp_aggregate_target=350M",
            f"tcp_parallel={cfg.tcp_parallel}",
            f"tcp_rate_per_stream={cfg.tcp_rate_per_stream}",
            f"tcp_block_size={cfg.tcp_block_size}",
            "companion=canary",
            "",
        ])
    )

    # ── UDP block (do not compare later TCP numbers against these) ──────────
    with state.lock:
        state.protocol = "udp"
        state.suite_step = "udp-upload-control"
        set_task(
            state,
            f"UDP upload-only control → {cfg.server}:{cfg.upload_port} "
            f"-u -b {cfg.rate} -t {cfg.directional_seconds}",
            "udp",
            ends_at=time.time() + cfg.directional_seconds + 2,
        )
    mark_phase(results, "udp_upload_control_start")
    mbps, loss, lost = run_iperf_udp(
        cfg, state.local_ip, False, cfg.directional_seconds,
        results / "udp-upload-only.json", results / "udp-upload-only.stderr",
    )
    with state.lock:
        state.probe_count += 1
        state.last_up_mbps, state.last_up_extra = mbps, loss
        state.udp_up_hist.append(Sample(time.time(), mbps, loss, "udp"))
        state.last_iperf_label = f"UDP ↑ {mbps:.1f} Mbps, {lost} lost ({loss:.3f}%)"
        add_event(state, state.last_iperf_label)
        record_loss(state, "UDP ↑ control", lost, loss)
        update_fine_dog(state, udp_loss=loss)

    if interruptible_sleep(state, 3, "UDP inter-test gap"):
        return results

    with state.lock:
        state.suite_step = "udp-download-control"
        set_task(
            state,
            f"UDP download-only control → {cfg.server}:{cfg.download_port} -R "
            f"-u -b {cfg.rate} -t {cfg.directional_seconds}",
            "udp",
            ends_at=time.time() + cfg.directional_seconds + 2,
        )
    mark_phase(results, "udp_download_control_start")
    mbps, loss, lost = run_iperf_udp(
        cfg, state.local_ip, True, cfg.directional_seconds,
        results / "udp-download-only.json", results / "udp-download-only.stderr",
    )
    with state.lock:
        state.probe_count += 1
        state.last_down_mbps, state.last_down_extra = mbps, loss
        state.udp_down_hist.append(Sample(time.time(), mbps, loss, "udp"))
        state.last_iperf_label = f"UDP ↓ {mbps:.1f} Mbps, {lost} lost ({loss:.3f}%)"
        add_event(state, state.last_iperf_label)
        record_loss(state, "UDP ↓ control", lost, loss)
        update_fine_dog(state, udp_loss=loss)

    if interruptible_sleep(state, 3, "UDP inter-test gap"):
        return results

    with state.lock:
        state.suite_step = "udp-gateway-idle"
        set_task(
            state,
            f"UDP-phase idle ping ×{cfg.idle_ping_count} → {cfg.ping_target or state.gateway}",
            "idle",
            ends_at=time.time() + cfg.idle_ping_count * cfg.ping_interval + 2,
        )
    mark_phase(results, "udp_gateway_idle_start")
    gw_loss = run_gateway_ping(
        cfg, cfg.ping_target or state.gateway, cfg.idle_ping_count,
        results / "udp-gateway-idle.txt", results / "udp-gateway-idle.stderr",
    )
    if gw_loss is not None:
        with state.lock:
            lost_gw = int(round(cfg.idle_ping_count * gw_loss / 100.0))
            record_loss(state, "UDP gw idle", lost_gw, gw_loss)

    if interruptible_sleep(state, 2, "UDP pre-sim gap"):
        return results

    mark_phase(results, "udp_simultaneous_1_start")
    run_udp_simultaneous(state, results, 1)
    if interruptible_sleep(state, 3, "UDP between simultaneous runs"):
        return results
    mark_phase(results, "udp_simultaneous_2_start")
    run_udp_simultaneous(state, results, 2)

    if interruptible_sleep(state, 5, "transport switch gap — starting fresh TCP baseline (not mixed with UDP)"):
        return results

    # ── TCP block (fresh controls; never folded into UDP baselines) ─────────
    with state.lock:
        state.protocol = "tcp"
        state.suite_step = "tcp-upload-control"
        state.last_up_mbps = None
        state.last_down_mbps = None
        state.last_up_extra = None
        state.last_down_extra = None
        add_event(state, "PROTOCOL SWITCH → TCP (UDP results sealed)")
        set_task(
            state,
            f"TCP upload-only control → {cfg.server}:{cfg.upload_port} "
            f"-P {cfg.tcp_parallel} -b {cfg.tcp_rate_per_stream} "
            f"-t {cfg.directional_seconds}",
            "tcp",
            ends_at=time.time() + cfg.directional_seconds + 2,
        )
    mark_phase(results, "tcp_upload_control_start")
    mbps, rexmit = run_iperf_tcp(
        cfg, state.local_ip, False, cfg.directional_seconds,
        results / "tcp-upload-only.json", results / "tcp-upload-only.stderr",
    )
    with state.lock:
        state.probe_count += 1
        state.last_up_mbps, state.last_up_extra = mbps, float(rexmit)
        state.tcp_up_hist.append(Sample(time.time(), mbps, float(rexmit), "tcp"))
        state.last_iperf_label = f"TCP ↑ {mbps:.1f} Mbps, {rexmit} retransmissions"
        add_event(state, state.last_iperf_label)
        update_fine_dog(state)

    if interruptible_sleep(state, 3, "TCP inter-test gap"):
        return results

    with state.lock:
        state.suite_step = "tcp-download-control"
        set_task(
            state,
            f"TCP download-only control → {cfg.server}:{cfg.download_port} -R "
            f"-P {cfg.tcp_parallel} -b {cfg.tcp_rate_per_stream}",
            "tcp",
            ends_at=time.time() + cfg.directional_seconds + 2,
        )
    mark_phase(results, "tcp_download_control_start")
    mbps, rexmit = run_iperf_tcp(
        cfg, state.local_ip, True, cfg.directional_seconds,
        results / "tcp-download-only.json", results / "tcp-download-only.stderr",
    )
    with state.lock:
        state.probe_count += 1
        state.last_down_mbps, state.last_down_extra = mbps, float(rexmit)
        state.tcp_down_hist.append(Sample(time.time(), mbps, float(rexmit), "tcp"))
        state.last_iperf_label = f"TCP ↓ {mbps:.1f} Mbps, {rexmit} retransmissions"
        add_event(state, state.last_iperf_label)
        update_fine_dog(state)

    if interruptible_sleep(state, 3, "TCP inter-test gap"):
        return results

    with state.lock:
        state.suite_step = "tcp-gateway-idle"
        set_task(
            state,
            f"TCP-phase idle ping ×{cfg.idle_ping_count} → {cfg.ping_target or state.gateway}",
            "idle",
            ends_at=time.time() + cfg.idle_ping_count * cfg.ping_interval + 2,
        )
    mark_phase(results, "tcp_gateway_idle_start")
    gw_loss = run_gateway_ping(
        cfg, cfg.ping_target or state.gateway, cfg.idle_ping_count,
        results / "tcp-gateway-idle.txt", results / "tcp-gateway-idle.stderr",
    )
    if gw_loss is not None:
        with state.lock:
            lost_gw = int(round(cfg.idle_ping_count * gw_loss / 100.0))
            record_loss(state, "TCP gw idle", lost_gw, gw_loss)

    if interruptible_sleep(state, 2, "TCP pre-sim gap"):
        return results

    mark_phase(results, "tcp_simultaneous_1_start")
    run_tcp_simultaneous(state, results, 1)
    if interruptible_sleep(state, 3, "TCP between simultaneous runs"):
        return results
    mark_phase(results, "tcp_simultaneous_2_start")
    run_tcp_simultaneous(state, results, 2)
    mark_phase(results, "load_suite_end")

    summary = build_summary(results, cfg.rate, cfg.tcp_parallel)
    (results / "summary.txt").write_text(summary + "\n")
    with state.lock:
        state.summary_text = summary
        state.mode = "report"
        state.status = "report"
        state.suite_step = "complete"
        state.protocol = "—"
        update_fine_dog(state)
        set_task(
            state,
            f"SUITE COMPLETE — results on screen + {results}/summary.txt  (q to quit)",
            "report",
        )
        add_event(state, f"REPORT ready: {results}/summary.txt")
        add_event(state, "RESULTS displayed below — scroll terminal taller if clipped")
        maybe_quip(state, force=True)
    return results


def suite_worker(state: State) -> None:
    # Wait for ENTER after calibration (suite_go), then run with the companion.
    while not state.stop.is_set() and not state.suite_go.is_set():
        state.stop.wait(0.25)
    if state.stop.is_set():
        return
    try:
        results = run_peer_impact_suite(state)
        with state.lock:
            set_task(
                state,
                f"RESULTS READY — see log panel / {results}/summary.txt  (q or Ctrl+C to quit)",
                "report",
            )
            add_event(state, "Suite finished — displaying peer-impact results")
    except Exception as exc:  # noqa: BLE001
        with state.lock:
            state.errors.appendleft(str(exc)[:100])
            state.mode = "report"
            state.status = "report"
            set_task(state, f"suite error: {exc}", "error")
            add_event(state, f"suite error: {exc}")
    # Hold on report until user quits
    while not state.stop.is_set():
        state.stop.wait(0.5)


# ── TUI ─────────────────────────────────────────────────────────────────────

def status_color(status: str) -> int:
    return {
        "calibrating": 6,
        "armed": 3,
        "test": 4,
        "nominal": 2,
        "warning": 3,
        "alert": 1,
        "report": 5,
    }.get(status, 7)


def safe_addstr(win, y: int, x: int, text: str, attr: int = 0) -> None:
    try:
        h, w = win.getmaxyx()
        if y < 0 or y >= h or x >= w:
            return
        win.addnstr(y, x, text, max(0, w - x - 1), attr)
    except curses.error:
        pass


def draw_boxed(win, title: str, color: int) -> None:
    try:
        h, w = win.getmaxyx()
        win.attron(curses.color_pair(color))
        win.border()
        win.attroff(curses.color_pair(color))
        label = f" {title} "
        win.addstr(0, max(1, (w - len(label)) // 2), label[: w - 2], curses.color_pair(color) | curses.A_BOLD)
    except curses.error:
        pass


def render_panel_graph(win, title, values, unit, current, baseline, color) -> None:
    win.erase()
    h, w = win.getmaxyx()
    draw_boxed(win, title, color)
    if h < 6 or w < 12:
        win.noutrefresh()
        return
    rows, lo, hi = sparkline(values, max(8, w - 4), max(3, h - 5))
    for i, row in enumerate(rows):
        safe_addstr(win, 1 + i, 2, row, curses.color_pair(color))
    cur_s = f"{current:.1f}{unit}" if current is not None else "—"
    base_s = f"{baseline:.1f}{unit}" if baseline is not None else "—"
    safe_addstr(win, h - 3, 2, f"now {cur_s}   base {base_s}", curses.A_DIM)
    safe_addstr(win, h - 2, 2, f"range {lo:.1f} – {hi:.1f} {unit}", curses.A_DIM)
    win.noutrefresh()


def render_trend_panel(win, avg_5s: Optional[float], trend: str, avg_hist: list) -> None:
    """5-second average sparkline + big colored trend arrow."""
    win.erase()
    h, w = win.getmaxyx()
    color, arrow, label = {
        "up": (1, "▲", "RISING"),
        "down": (2, "▼", "FALLING"),
        "flat": (3, "▶", "STEADY"),
    }.get(trend, (3, "▶", "STEADY"))
    draw_boxed(win, "5s AVG TREND", color)
    if h < 5 or w < 12:
        win.noutrefresh()
        return

    # Leave room on the right for the arrow glyph column.
    arrow_col_w = 6
    chart_w = max(6, w - 4 - arrow_col_w)
    chart_h = max(2, h - 4)
    rows, lo, hi = sparkline([s.value for s in avg_hist], chart_w, chart_h)
    for i, row in enumerate(rows):
        safe_addstr(win, 1 + i, 2, row, curses.color_pair(color))

    # Big arrow on the right side of the panel
    ax = max(2, w - arrow_col_w)
    ay = max(1, (h - 3) // 2)
    safe_addstr(win, ay, ax, f" {arrow} ", curses.color_pair(color) | curses.A_BOLD)
    if ay + 1 < h - 2:
        safe_addstr(win, ay + 1, ax, label[: arrow_col_w - 1], curses.color_pair(color) | curses.A_BOLD)

    avg_s = f"{avg_5s:.1f}ms" if avg_5s is not None else "—"
    safe_addstr(win, h - 2, 2, f"5s avg {avg_s}  {lo:.1f}–{hi:.1f}"[: w - 4], curses.A_DIM)
    win.noutrefresh()


def ui_loop(stdscr, state: State) -> None:
    curses.curs_set(0)
    curses.start_color()
    curses.use_default_colors()
    for i, fg in enumerate(
        [
            curses.COLOR_RED,
            curses.COLOR_GREEN,
            curses.COLOR_YELLOW,
            curses.COLOR_BLUE,
            curses.COLOR_MAGENTA,
            curses.COLOR_CYAN,
            curses.COLOR_WHITE,
        ],
        start=1,
    ):
        curses.init_pair(i, fg, -1)

    stdscr.nodelay(True)
    stdscr.timeout(1000)
    last_quip_roll = 0.0
    scroll = 0
    started_at = state.started
    panels: dict = {}

    while not state.stop.is_set():
        now = time.time()
        with state.lock:
            evaluate_ping(state)
            if now - last_quip_roll > 1.0:
                maybe_quip(state)
                last_quip_roll = now
            proto = state.protocol
            if proto == "tcp":
                up_hist = list(state.tcp_up_hist)
                down_hist = list(state.tcp_down_hist)
                extra_unit = "rexmit"
            else:
                # During calibrate / udp / report: show UDP hist (never blend TCP in)
                up_hist = list(state.udp_up_hist)
                down_hist = list(state.udp_down_hist)
                extra_unit = "loss%"
            snap = {
                "mode": state.mode,
                "status": state.status,
                "protocol": state.protocol,
                "suite_step": state.suite_step,
                "quip": state.quip,
                "ping": list(state.ping_hist),
                "ping_avg": list(state.ping_avg_hist),
                "up": up_hist,
                "down": down_hist,
                "extra_unit": extra_unit,
                "last_ping": state.last_ping_ms,
                "last_ping_avg_5s": state.last_ping_avg_5s,
                "ping_trend": state.ping_trend,
                "last_up": state.last_up_mbps,
                "last_up_extra": state.last_up_extra,
                "last_down": state.last_down_mbps,
                "last_down_extra": state.last_down_extra,
                "iperf_label": state.last_iperf_label,
                "baseline": state.baseline,
                "events": list(state.events),
                "errors": list(state.errors),
                "loss_runs": list(state.loss_runs),
                "total_packets_lost": state.total_packets_lost,
                "gateway": state.gateway,
                "ping_target": state.cfg.ping_target or state.gateway,
                "local_ip": state.local_ip,
                "task": state.task,
                "task_phase": state.task_phase,
                "task_started": state.task_started,
                "task_ends_at": state.task_ends_at,
                "ping_count": state.ping_count,
                "probe_count": state.probe_count,
                "calibrate_for": state.cfg.calibrate_seconds,
                "started_at": started_at,
                "results_dir": str(state.results_dir) if state.results_dir else "",
                "summary_lines": state.summary_text.splitlines() if state.summary_text else [],
                "round_id": state.round_id,
                "server": state.cfg.server,
                "rate": state.cfg.rate,
                "fine_dog": state.fine_dog,
                "fine_reason": state.fine_reason,
            }

        try:
            h, w = stdscr.getmaxyx()
            if h < 24 or w < 80:
                stdscr.erase()
                safe_addstr(stdscr, 0, 0, "Need a bigger terminal (≥80×24). Ctrl+C to quit.")
                stdscr.refresh()
                ch = stdscr.getch()
                if ch in (3, ord("q")):
                    state.stop.set()
                elif ch in (10, 13, curses.KEY_ENTER):
                    handle_enter(state)
                continue

            ticker_h = 3
            left_w = 28
            report_mode = snap["mode"] == "report" and bool(snap["summary_lines"])
            # In report mode, give almost the whole screen to the results tables.
            # During suite, leave room for the per-run packet-loss counter.
            if report_mode:
                bot_h = max(14, h - ticker_h - 14)
            elif snap["loss_runs"]:
                bot_h = max(10, min(14, 4 + len(snap["loss_runs"])))
            else:
                bot_h = 8
            mid_w = (w - left_w) // 2
            right_w = w - left_w - mid_w
            top_h = max(4, h - bot_h - ticker_h)
            ping_h = max(2, top_h // 2)
            trend_h = max(2, top_h - ping_h)
            if ping_h + trend_h > top_h:
                ping_h = top_h // 2
                trend_h = top_h - ping_h
            layout_key = (h, w, top_h, bot_h, ticker_h, left_w, mid_w, right_w, report_mode, ping_h)

            if panels.get("key") != layout_key:
                stdscr.erase()
                stdscr.refresh()
                panels = {
                    "key": layout_key,
                    "left": curses.newwin(top_h, left_w, 0, 0),
                    "mid_ping": curses.newwin(ping_h, mid_w, 0, left_w),
                    "mid_trend": curses.newwin(trend_h, mid_w, ping_h, left_w),
                    "right": curses.newwin(top_h, right_w, 0, left_w + mid_w),
                    "bottom": curses.newwin(bot_h, w, top_h, 0),
                    "ticker": curses.newwin(ticker_h, w, top_h + bot_h, 0),
                }

            left = panels["left"]
            mid_ping = panels["mid_ping"]
            mid_trend = panels["mid_trend"]
            right = panels["right"]
            bottom = panels["bottom"]
            ticker = panels["ticker"]
            sc = status_color(snap["status"])
            dog_color = 1 if snap["fine_dog"] else sc

            # Left: cage (+ this-is-fine dog when thresholds trip)
            left.erase()
            mode_title = {
                "calibrating": "CANARY · CAL",
                "armed": "CANARY · ARM",
                "test": "CANARY · TEST",
                "report": "CANARY · RPT",
            }.get(snap["mode"], "CANARY")
            draw_boxed(left, mode_title, dog_color if snap["fine_dog"] else sc)
            art_top = 2
            for i, line in enumerate(CAGE):
                if art_top + i >= top_h - 8:
                    break
                safe_addstr(
                    left, art_top + i, 2, line[: left_w - 4],
                    curses.color_pair(dog_color if snap["fine_dog"] else sc),
                )

            next_y = art_top + len(CAGE) + 1
            if snap["fine_dog"]:
                for i, line in enumerate(THIS_IS_FINE):
                    if next_y + i >= top_h - 5:
                        break
                    safe_addstr(
                        left, next_y + i, 2, line[: left_w - 4],
                        curses.color_pair(1) | curses.A_BOLD,
                    )
                next_y += len(THIS_IS_FINE) + 1
                if snap["fine_reason"] and next_y < top_h - 4:
                    safe_addstr(
                        left, next_y, 2, snap["fine_reason"][: left_w - 4],
                        curses.color_pair(1),
                    )
                    next_y += 2

            bubble_y = next_y
            wrap_w = left_w - 6
            words = snap["quip"].split()
            lines: list[str] = []
            cur = ""
            for word in words:
                trial = f"{cur} {word}".strip()
                if len(trial) <= wrap_w:
                    cur = trial
                else:
                    if cur:
                        lines.append(cur)
                    cur = word
            if cur:
                lines.append(cur)
            lines = lines[:3]
            if bubble_y + 4 < top_h - 4:
                safe_addstr(left, bubble_y, 3, "╭" + "─" * (wrap_w + 2) + "╮", curses.A_DIM)
                for i, line in enumerate(lines):
                    safe_addstr(left, bubble_y + 1 + i, 3, "│ " + line.ljust(wrap_w) + " │")
                safe_addstr(left, bubble_y + 1 + len(lines), 3, "╰" + "─" * (wrap_w + 2) + "╯", curses.A_DIM)

            safe_addstr(
                left, top_h - 4, 2,
                f"{snap['status'].upper():<12}",
                curses.color_pair(sc) | curses.A_BOLD,
            )
            mode_attr = curses.A_BOLD if snap["mode"] in ("armed", "test") else curses.A_DIM
            safe_addstr(left, top_h - 3, 2, f"mode {snap['mode'].upper()}", mode_attr)
            if snap["mode"] == "armed":
                safe_addstr(left, top_h - 2, 2, "ENTER → run w/ companion", curses.color_pair(3) | curses.A_BOLD)
            else:
                proto_s = snap["protocol"].upper() if snap["protocol"] != "—" else "—"
                safe_addstr(left, top_h - 2, 2, f"{proto_s} r{snap['round_id']} {fmt_age(now - started_at)}", curses.A_DIM)
            left.noutrefresh()

            if report_mode:
                # Compact mid strip; full tables live in the bottom panel.
                mid_ping.erase()
                draw_boxed(mid_ping, "PING", sc)
                ping_s = f"{snap['last_ping']:.1f} ms" if snap["last_ping"] is not None else "—"
                safe_addstr(mid_ping, 2, 2, ping_s[: mid_w - 4], curses.color_pair(sc) | curses.A_BOLD)
                if snap["last_ping_avg_5s"] is not None:
                    safe_addstr(
                        mid_ping, 3, 2,
                        f"5s {snap['last_ping_avg_5s']:.1f}ms"[: mid_w - 4],
                        curses.A_DIM,
                    )
                mid_ping.noutrefresh()

                mid_trend.erase()
                draw_boxed(mid_trend, "LOSS TOTAL", 1 if snap["total_packets_lost"] else 7)
                safe_addstr(
                    mid_trend, 2, 2,
                    f"{snap['total_packets_lost']:,} pkts"[: mid_w - 4],
                    curses.color_pair(1 if snap["total_packets_lost"] else 2) | curses.A_BOLD,
                )
                if snap["loss_runs"]:
                    last = snap["loss_runs"][0]
                    safe_addstr(
                        mid_trend, 3, 2,
                        f"{last.label}: {last.lost:,} ({last.loss_pct:.1f}%)"[: mid_w - 4],
                        curses.A_DIM,
                    )
                mid_trend.noutrefresh()

                right.erase()
                draw_boxed(right, "LAST IPERF", sc)
                if snap["last_up"] is not None:
                    safe_addstr(right, 2, 2, f"↑ {snap['last_up']:.1f} Mbps"[: right_w - 4])
                if snap["last_down"] is not None:
                    safe_addstr(right, 3, 2, f"↓ {snap['last_down']:.1f} Mbps"[: right_w - 4])
                if snap["fine_dog"]:
                    safe_addstr(right, 5, 2, "THIS IS FINE"[: right_w - 4], curses.color_pair(1) | curses.A_BOLD)
                right.noutrefresh()
            else:
                # Mid top: ping RTT; mid bottom: 5s average trend arrow
                base_ping = snap["baseline"].ping_ms if snap["baseline"].ready else None
                render_panel_graph(
                    mid_ping,
                    f"PING → {snap['ping_target']}",
                    [s.value for s in snap["ping"]],
                    "ms",
                    snap["last_ping"],
                    base_ping,
                    sc,
                )
                render_trend_panel(
                    mid_trend,
                    snap["last_ping_avg_5s"],
                    snap["ping_trend"],
                    snap["ping_avg"],
                )

                # Right: protocol-scoped iperf
                merged = sorted(
                    [(s.t, s.value) for s in snap["up"]] + [(s.t, s.value) for s in snap["down"]],
                    key=lambda x: x[0],
                )
                plot_vals = [v for _, v in merged]
                chart_title = {
                    "udp": "IPERF UDP only",
                    "tcp": "IPERF TCP only",
                }.get(snap["protocol"], "IPERF (UDP hist)")
                right.erase()
                draw_boxed(right, chart_title, sc)
                rows, lo, hi = sparkline(plot_vals, max(8, right_w - 4), max(3, top_h - 6))
                for i, row in enumerate(rows):
                    safe_addstr(right, 1 + i, 2, row, curses.color_pair(4 if snap["status"] in ("test", "nominal") else sc))

                if snap["protocol"] == "tcp":
                    up_s = (
                        f"↑ {snap['last_up']:.1f} ({int(snap['last_up_extra'] or 0)} rexmit)"
                        if snap["last_up"] is not None else "↑ —"
                    )
                    down_s = (
                        f"↓ {snap['last_down']:.1f} ({int(snap['last_down_extra'] or 0)} rexmit)"
                        if snap["last_down"] is not None else "↓ —"
                    )
                else:
                    up_s = (
                        f"↑ {snap['last_up']:.1f} ({(snap['last_up_extra'] or 0):.1f}% loss)"
                        if snap["last_up"] is not None else "↑ —"
                    )
                    down_s = (
                        f"↓ {snap['last_down']:.1f} ({(snap['last_down_extra'] or 0):.1f}% loss)"
                        if snap["last_down"] is not None else "↓ —"
                    )
                safe_addstr(right, top_h - 4, 2, up_s[: right_w - 4])
                safe_addstr(right, top_h - 3, 2, down_s[: right_w - 4])
                safe_addstr(
                    right, top_h - 2, 2,
                    f"{snap['suite_step']}  rng {lo:.0f}-{hi:.0f}"[: right_w - 4],
                    curses.A_DIM,
                )
                right.noutrefresh()

            # Bottom log / full peer-impact report / packet-loss counter
            bottom.erase()
            draw_boxed(
                bottom,
                "PEER-IMPACT RESULTS" if report_mode else "PACKET LOSS / COALMINE LOG",
                5 if report_mode else 7,
            )
            safe_addstr(
                bottom, 1, 2,
                f"ping {snap['ping_target']}  iperf {snap['server']}  "
                f"{snap['local_ip']} via {snap['gateway']}  @ {snap['rate']}  "
                f"probes {snap['probe_count']}  lostΣ {snap['total_packets_lost']:,}"[: w - 4],
                curses.A_DIM,
            )
            y = 2
            if report_mode:
                for line in snap["summary_lines"]:
                    if y >= bot_h - 2:
                        break
                    attr = 0
                    if line.startswith(("UDP", "TCP", "CANARY")):
                        attr = curses.A_BOLD | curses.color_pair(5)
                    safe_addstr(bottom, y, 2, line[: w - 4], attr)
                    y += 1
            else:
                if snap["loss_runs"]:
                    safe_addstr(
                        bottom, y, 2,
                        f"LOSS COUNTER  total {snap['total_packets_lost']:,} packets"
                        [: w - 4],
                        curses.color_pair(1 if snap["total_packets_lost"] else 2) | curses.A_BOLD,
                    )
                    y += 1
                    for run in snap["loss_runs"]:
                        if y >= bot_h - 3:
                            break
                        line = f"  {run.label:<16} {run.lost:>8,} pkts  {run.loss_pct:6.2f}%"
                        attr = curses.color_pair(1) if run.loss_pct > FINE_LOSS_PCT or run.lost > 0 else curses.A_DIM
                        safe_addstr(bottom, y, 2, line[: w - 4], attr)
                        y += 1
                if snap["mode"] == "armed":
                    safe_addstr(
                        bottom, y, 2,
                        ">>> PRESS ENTER to start suite — runs simultaneously with companion",
                        curses.color_pair(3) | curses.A_BOLD,
                    )
                    y += 1
                remain = max(0, bot_h - 2 - y)
                for ev in snap["events"][:remain]:
                    if y >= bot_h - 2:
                        break
                    safe_addstr(bottom, y, 2, ev[: w - 4])
                    y += 1
            if snap["errors"]:
                safe_addstr(bottom, bot_h - 2, 2, f"err: {snap['errors'][0]}"[: w - 4], curses.color_pair(1))
            elif report_mode and snap["results_dir"]:
                safe_addstr(
                    bottom, bot_h - 2, 2,
                    f"also written → {snap['results_dir']}/summary.txt   (q to quit)"[: w - 4],
                    curses.color_pair(5) | curses.A_BOLD,
                )
            elif snap["results_dir"]:
                safe_addstr(bottom, bot_h - 2, 2, f"evidence: {snap['results_dir']}"[: w - 4], curses.A_DIM)
            bottom.noutrefresh()

            # Ticker
            ticker.erase()
            phase_color = {
                "init": 6, "ping": 6, "calibrate": 6,
                "armed": 3, "test": 4,
                "udp": 4, "tcp": 5, "sim": 4, "idle": 3,
                "gap": 7, "report": 5, "error": 1,
                "iperf-up": 4, "iperf-down": 4,
            }.get(snap["task_phase"], sc)
            try:
                ticker.attron(curses.color_pair(phase_color) | curses.A_BOLD)
                ticker.hline(0, 0, curses.ACS_HLINE, w)
                ticker.attroff(curses.color_pair(phase_color) | curses.A_BOLD)
            except curses.error:
                pass
            line = format_ticker(snap, now, max(1, w - 1), scroll)
            safe_addstr(ticker, 1, 0, line, curses.color_pair(phase_color) | curses.A_REVERSE | curses.A_BOLD)
            if snap["task_ends_at"] is not None:
                total = max(0.01, snap["task_ends_at"] - snap["task_started"])
                done = min(1.0, max(0.0, (now - snap["task_started"]) / total))
                bar_w = max(10, w - 2)
                filled = int(done * bar_w)
                safe_addstr(ticker, 2, 1, ("█" * filled + "░" * (bar_w - filled))[: w - 2], curses.color_pair(phase_color))
            else:
                crumb = f"mode={snap['mode']} proto={snap['protocol']} step={snap['suite_step']}"
                safe_addstr(ticker, 2, 1, crumb[: w - 2], curses.A_DIM)
            ticker.noutrefresh()
            scroll += 1
            curses.doupdate()
        except curses.error:
            pass

        ch = stdscr.getch()
        if ch in (3, ord("q"), ord("Q")):
            state.stop.set()
            break
        if ch in (10, 13, curses.KEY_ENTER):
            handle_enter(state)


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Canary peer-impact companion (fragglepacket-aligned)",
        epilog=(
            "iperf target is required (--server / SERVER). "
            "Ping defaults to the interface gateway; override with --ping-target."
        ),
    )
    p.add_argument("--iface", default=os.environ.get("IFACE", DEFAULT_IFACE),
                   help=f"bind/source interface (default: {DEFAULT_IFACE})")
    p.add_argument(
        "--server",
        default=os.environ.get("SERVER"),
        help="iperf3 server host/IP (required unless --protoevidence; env: SERVER)",
    )
    p.add_argument(
        "--upload-port", type=int,
        default=int(os.environ.get("UPLOAD_PORT", DEFAULT_UPLOAD_PORT)),
        help=f"iperf upload port (default: {DEFAULT_UPLOAD_PORT}; env: UPLOAD_PORT)",
    )
    p.add_argument(
        "--download-port", type=int,
        default=int(os.environ.get("DOWNLOAD_PORT", DEFAULT_DOWNLOAD_PORT)),
        help=f"iperf download port (default: {DEFAULT_DOWNLOAD_PORT}; env: DOWNLOAD_PORT)",
    )
    p.add_argument(
        "--ping-target",
        default=os.environ.get("PING_TARGET"),
        help="ping target host/IP (default: iface gateway; env: PING_TARGET)",
    )
    p.add_argument("--rate", default=os.environ.get("RATE", DEFAULT_RATE))
    p.add_argument("--calibrate-seconds", type=float, default=float(os.environ.get("CALIBRATE_SECONDS", DEFAULT_CALIBRATE_SECONDS)))
    p.add_argument("--directional-seconds", type=int, default=int(os.environ.get("DIRECTIONAL_SECONDS", DEFAULT_DIRECTIONAL_SECONDS)))
    p.add_argument("--simultaneous-seconds", type=int, default=int(os.environ.get("SIMULTANEOUS_SECONDS", DEFAULT_SIMULTANEOUS_SECONDS)))
    p.add_argument("--tcp-parallel", type=int, default=int(os.environ.get("TCP_PARALLEL", DEFAULT_TCP_PARALLEL)))
    p.add_argument("--tcp-rate-per-stream", default=os.environ.get("TCP_RATE_PER_STREAM", DEFAULT_TCP_RATE_PER_STREAM))
    p.add_argument("--protoevidence", action="store_true", help="Use test.protoevidence.com:443/444")
    return p.parse_args(argv)


def build_config(
    args: argparse.Namespace,
    *,
    local_ip: str,
    gateway: str,
) -> Config:
    """Validate CLI/env inputs and assemble Config. Raises ValueError on bad input."""
    iface = validate_iface(args.iface)
    upload_port = validate_port(args.upload_port, what="upload port")
    download_port = validate_port(args.download_port, what="download port")
    rate = validate_rate(args.rate)
    tcp_rate = validate_rate(args.tcp_rate_per_stream, what="tcp rate per stream")

    if args.protoevidence:
        server = "test.protoevidence.com"
        upload_port = 443
        download_port = 444
    else:
        if not args.server:
            raise ValueError(
                "iperf server required: pass --server HOST or set SERVER "
                "(or use --protoevidence)"
            )
        server = validate_host(args.server, what="iperf server")
        if upload_port == download_port:
            raise ValueError(
                f"upload and download ports must differ for simultaneous tests "
                f"(both are {upload_port})"
            )

    if args.ping_target:
        ping_target = validate_host(args.ping_target, what="ping target")
    else:
        ping_target = gateway  # default: iface gateway

    if args.calibrate_seconds <= 0:
        raise ValueError("calibrate-seconds must be > 0")
    if args.directional_seconds <= 0 or args.simultaneous_seconds <= 0:
        raise ValueError("test durations must be > 0")
    if args.tcp_parallel < 1:
        raise ValueError("tcp-parallel must be >= 1")

    return Config(
        iface=iface,
        server=server,
        upload_port=upload_port,
        download_port=download_port,
        ping_target=ping_target,
        rate=rate,
        calibrate_seconds=args.calibrate_seconds,
        directional_seconds=args.directional_seconds,
        simultaneous_seconds=args.simultaneous_seconds,
        tcp_parallel=args.tcp_parallel,
        tcp_rate_per_stream=tcp_rate,
    )


def main() -> int:
    if not sys.stdout.isatty():
        print("canary needs an interactive terminal", file=sys.stderr)
        return 1
    if shutil.which("iperf3") is None:
        print("missing required tool: iperf3", file=sys.stderr)
        return 1
    if not os.path.exists("/usr/sbin/ipconfig"):
        print("ipconfig not found — macOS required", file=sys.stderr)
        return 1

    args = parse_args()
    try:
        iface = validate_iface(args.iface)
        local_ip, gateway = resolve_net(iface)
        cfg = build_config(args, local_ip=local_ip, gateway=gateway)
    except (subprocess.CalledProcessError, ValueError, RuntimeError) as exc:
        print(f"canary: {exc}", file=sys.stderr)
        return 1

    state = State(cfg=cfg, local_ip=local_ip, gateway=gateway)
    set_task(
        state,
        f"boot — iperf {cfg.server} ↑{cfg.upload_port}/↓{cfg.download_port} @ {cfg.rate}  "
        f"ping {cfg.ping_target}  calibrate → ENTER → suite",
        "init",
    )
    add_event(state, f"Canary perched on {cfg.iface} ({local_ip})")
    add_event(state, f"iperf target: {cfg.server} ↑{cfg.upload_port} ↓{cfg.download_port} @ {cfg.rate}")
    add_event(state, f"ping target: {cfg.ping_target} (gateway {gateway})")
    add_event(
        state,
        f"Calibrate {cfg.calibrate_seconds:.0f}s, then ENTER starts suite alongside companion",
    )
    maybe_quip(state, force=True)

    threads = [
        threading.Thread(target=ping_worker, args=(state,), daemon=True),
        threading.Thread(target=suite_worker, args=(state,), daemon=True),
    ]
    for t in threads:
        t.start()

    def handle_sigint(_sig, _frame):
        state.stop.set()

    signal.signal(signal.SIGINT, handle_sigint)
    signal.signal(signal.SIGTERM, handle_sigint)

    try:
        curses.wrapper(ui_loop, state)
    finally:
        state.stop.set()
        time.sleep(0.3)
        print()
        print("── Canary stopped ──")
        print(f"Ran for {fmt_age(time.time() - state.started)}")
        print(f"Final mode: {state.mode.upper()}  status: {state.status.upper()}")
        if state.baseline.ready:
            print(f"Ping baseline: {state.baseline.ping_ms:.1f} ms")
        if state.results_dir:
            print(f"Raw evidence: {state.results_dir}")
            summary_path = state.results_dir / "summary.txt"
            if summary_path.exists():
                print()
                print(summary_path.read_text())
        elif state.summary_text:
            print()
            print(state.summary_text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
