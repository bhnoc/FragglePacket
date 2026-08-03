#!/usr/bin/env bash
# Fake tcpdump that reproduces the macOS BPF permission-denied failure mode
# for GAP-007 harness checks, without needing real root/non-root state.
echo "tcpdump: fake0: You don't have permission to capture on that device" >&2
echo "((cannot open BPF device) /dev/bpf0: Permission denied)" >&2
exit 1
