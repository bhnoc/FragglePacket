#!/bin/bash
# Change to project root (parent of tests directory)
cd "$(dirname "$0")/.."
sudo ./target/release/fraggle-packet quick 8.8.8.8 2>&1 | head -30

