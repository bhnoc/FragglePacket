#!/usr/bin/env bash
# Fake tcpdump for GAP-007 harness checks: ignores network entirely, just
# writes growing garbage to the -w path forever (until killed), simulating
# an uncapped capture that would otherwise never stop.
out=""
snaplen=""
args=("$@")
for ((i=0; i<${#args[@]}; i++)); do
  if [ "${args[$i]}" = "-w" ]; then
    out="${args[$((i+1))]}"
  fi
  if [ "${args[$i]}" = "-s" ]; then
    snaplen="${args[$((i+1))]}"
  fi
done
: > "$out"
while true; do
  head -c 65536 /dev/urandom >> "$out" 2>/dev/null || dd if=/dev/zero bs=1024 count=64 >> "$out" 2>/dev/null
  sleep 0.05
done
