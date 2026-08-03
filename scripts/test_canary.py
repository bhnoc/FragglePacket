#!/usr/bin/env python3
"""Regression tests for canary helpers/config (no TUI / no live network)."""

from __future__ import annotations

import argparse
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

# Allow `python3 scripts/test_canary.py` from repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import canary as c


class ValidateInputs(unittest.TestCase):
    def test_iface_ok(self):
        self.assertEqual(c.validate_iface("en0"), "en0")
        self.assertEqual(c.validate_iface("en19"), "en19")

    def test_iface_rejects_metachar(self):
        with self.assertRaises(ValueError):
            c.validate_iface("en0;rm -rf /")
        with self.assertRaises(ValueError):
            c.validate_iface("../evil")

    def test_host_ok(self):
        self.assertEqual(c.validate_host("10.220.199.201"), "10.220.199.201")
        self.assertEqual(c.validate_host("iperf.example.com"), "iperf.example.com")

    def test_host_rejects_injection(self):
        with self.assertRaises(ValueError):
            c.validate_host("10.0.0.1; id")
        with self.assertRaises(ValueError):
            c.validate_host("host with spaces")
        with self.assertRaises(ValueError):
            c.validate_host("")

    def test_port_bounds(self):
        self.assertEqual(c.validate_port(5201), 5201)
        with self.assertRaises(ValueError):
            c.validate_port(0)
        with self.assertRaises(ValueError):
            c.validate_port(65536)

    def test_rate(self):
        self.assertEqual(c.validate_rate("350M"), "350M")
        self.assertEqual(c.validate_rate("87.5M"), "87.5M")
        with self.assertRaises(ValueError):
            c.validate_rate("350M;wget evil")


class PingParsers(unittest.TestCase):
    def test_parse_ping_line(self):
        self.assertEqual(c.parse_ping_line("64 bytes from 1.1.1.1: icmp_seq=1 ttl=64 time=12.3 ms"), 12.3)
        self.assertIsNone(c.parse_ping_line("Request timeout"))

    def test_parse_ping_loss(self):
        text = "5 packets transmitted, 4 packets received, 20.0% packet loss"
        self.assertEqual(c.parse_ping_loss_pct(text), 20.0)
        self.assertIsNone(c.parse_ping_loss_pct("no stats here"))


class TrendAndLoss(unittest.TestCase):
    def test_trend_up_down_flat(self):
        now = time.time()
        rising = c.State()
        for i in range(10):
            rising.ping_hist.append(c.Sample(now - 9 + i * 0.4, 10.0))
        for i in range(10):
            rising.ping_hist.append(c.Sample(now - 4 + i * 0.4, 40.0))
        c.update_ping_trend(rising, now=now)
        self.assertEqual(rising.ping_trend, "up")

        falling = c.State()
        for i in range(10):
            falling.ping_hist.append(c.Sample(now - 9 + i * 0.4, 40.0))
        for i in range(10):
            falling.ping_hist.append(c.Sample(now - 4 + i * 0.4, 10.0))
        c.update_ping_trend(falling, now=now)
        self.assertEqual(falling.ping_trend, "down")

        flat = c.State()
        for i in range(20):
            flat.ping_hist.append(c.Sample(now - 9 + i * 0.45, 12.0))
        c.update_ping_trend(flat, now=now)
        self.assertEqual(flat.ping_trend, "flat")

    def test_record_loss_totals(self):
        st = c.State()
        c.record_loss(st, "UDP ↑ control", 12, 1.5)
        c.record_loss(st, "UDP ↓ control", 100, 42.0)
        self.assertEqual(st.total_packets_lost, 112)
        self.assertEqual(st.loss_runs[0].label, "UDP ↓ control")


class BuildConfig(unittest.TestCase):
    def _args(self, **over):
        base = dict(
            iface="en0",
            server="10.1.2.3",
            upload_port=5201,
            download_port=5202,
            ping_target=None,
            rate="350M",
            calibrate_seconds=60.0,
            directional_seconds=7,
            simultaneous_seconds=12,
            tcp_parallel=4,
            tcp_rate_per_stream="87.5M",
            protoevidence=False,
        )
        base.update(over)
        return argparse.Namespace(**base)

    def test_requires_server(self):
        with self.assertRaises(ValueError):
            c.build_config(self._args(server=None), local_ip="10.0.0.2", gateway="10.0.0.1")

    def test_ping_defaults_to_gateway(self):
        cfg = c.build_config(self._args(), local_ip="10.0.0.2", gateway="10.0.0.1")
        self.assertEqual(cfg.ping_target, "10.0.0.1")
        self.assertEqual(cfg.server, "10.1.2.3")
        self.assertEqual(cfg.upload_port, 5201)
        self.assertEqual(cfg.download_port, 5202)

    def test_ping_override(self):
        cfg = c.build_config(
            self._args(ping_target="1.1.1.1"),
            local_ip="10.0.0.2",
            gateway="10.0.0.1",
        )
        self.assertEqual(cfg.ping_target, "1.1.1.1")

    def test_ports_must_differ(self):
        with self.assertRaises(ValueError):
            c.build_config(
                self._args(upload_port=5201, download_port=5201),
                local_ip="10.0.0.2",
                gateway="10.0.0.1",
            )

    def test_protoevidence_preset(self):
        cfg = c.build_config(
            self._args(server=None, protoevidence=True),
            local_ip="10.0.0.2",
            gateway="10.0.0.1",
        )
        self.assertEqual(cfg.server, "test.protoevidence.com")
        self.assertEqual(cfg.upload_port, 443)
        self.assertEqual(cfg.download_port, 444)

    def test_cli_help_lists_server(self):
        with mock.patch("sys.stdout"), mock.patch("sys.stderr"):
            with self.assertRaises(SystemExit) as cm:
                c.parse_args(["--help"])
        self.assertEqual(cm.exception.code, 0)


class FineDog(unittest.TestCase):
    def test_thresholds(self):
        s = c.State()
        s.mode = "test"
        s.protocol = "udp"
        s.last_ping_ms = 12
        c.update_fine_dog(s)
        self.assertFalse(s.fine_dog)
        s.last_ping_ms = 55
        c.update_fine_dog(s)
        self.assertTrue(s.fine_dog)


if __name__ == "__main__":
    # Keep import side-effects quiet; fail hard on first error for CI-style runs.
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)
