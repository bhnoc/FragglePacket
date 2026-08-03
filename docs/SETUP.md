# Setup

`setup.sh` detects the distro via `/etc/os-release`, installs runtime and GUI dependencies, ensures Rust is present, builds both binaries, and verifies the resulting environment.

## Supported distributions

| Family | Versions | Installer branch |
| --- | --- | --- |
| Ubuntu, Debian, Pop!_OS | Ubuntu 22.04 or newer, Debian 12 or newer | `apt-get` |
| Fedora, RHEL, CentOS, Rocky, AlmaLinux | Current stable releases | `dnf` |
| Arch Linux, Manjaro | Rolling | `pacman` |
| macOS (Darwin) | 12 or newer | Homebrew |

Older Ubuntu and Debian releases ship libwebkit2gtk-4.0, which the Dioxus desktop build does not support. Setup assumes the 4.1 packages.

## Package lists

### Ubuntu, Debian, Pop!_OS

```
build-essential pkg-config libssl-dev curl
iputils-ping iputils-tracepath traceroute tcpdump
dnsutils net-tools iproute2
libgtk-3-dev libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev
```

### Fedora family

```
gcc make pkg-config openssl-devel curl
iputils traceroute tcpdump bind-utils net-tools iproute
```

### Arch family

```
base-devel openssl curl iputils traceroute tcpdump
bind-tools net-tools iproute2
```

GUI dependencies on Fedora and Arch are not currently installed by setup.sh. Install the equivalents of `gtk3`, `webkit2gtk-4.1`, `libayatana-appindicator3`, and `librsvg` manually if you want to build `fraggle-desktop`.

### macOS

Homebrew installs:

```
openssl curl bind
```

GUI dependencies ship with the system webview.

## Rust toolchain

Setup uses rustup if cargo is missing:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
```

The stable channel is sufficient.

## Build stages

The script runs `cargo build --release --bin fraggle-packet`, then `cargo build --release --bin fraggle-desktop`. Desktop build failures are non-fatal so CLI-only installs still succeed.

Artifacts land in `target/release/`.

## Verification checks

Setup looks for the following after build:

| Check | Purpose |
| --- | --- |
| `target/release/fraggle-packet` | CLI and TUI binary exists |
| `target/release/fraggle-desktop` | Desktop binary exists |
| `tracepath` in PATH | Per-hop MTU discovery |
| `traceroute` in PATH | PathAnalysisTest fallback |
| `dig` in PATH | Multi-resolver DNS queries |
| `host` in PATH | Reverse lookups |
| `ping` or `ping6` in PATH | IPv6 MTU tests |
| `tcpdump` in PATH | External capture option |
| `sudo` passwordless | Needed for any raw-socket feature invoked via sudo |
| `targets.txt` | Custom target list; falls back to built-in defaults |

## Granting raw-socket privileges without root

Setup does not grant capabilities automatically. Apply them manually when you need PCAP Replay, Active PMTU Probe, or Capture without running the binary as root:

```bash
sudo setcap cap_net_raw,cap_net_admin+eip ./target/release/fraggle-desktop
sudo setcap cap_net_raw,cap_net_admin+eip ./target/release/fraggle-packet
```

macOS does not offer setcap; relaunch with `sudo` when raw-socket features are needed.

## Running

```bash
./start.sh                  # Desktop GUI
./start.sh --tui            # Terminal UI
./target/release/fraggle-packet test github.com
```

## Continuous integration

Automated CI and test coverage are configured in `.github/workflows/test.yml`. On every pull request and push to `main`, GitHub Actions runs:

| Step | Fails the build? |
| --- | --- |
| `cargo fmt --all -- --check` | No — advisory. The tree carries ~2,200 rustfmt diffs; gating on them would make every PR red for pre-existing reasons. |
| `cargo clippy --all-targets` | Only on hard errors. The ~190 existing warnings do not block, but deny-by-default lints (e.g. `unused_io_amount`) do, because those are bugs rather than style. |
| `cargo build --release` | Yes. The harness runs the release binary directly. |
| `cargo test --all-targets` | Yes — 589 tests. |
| `harness/smoke.sh` | Yes. |
| `harness/acid.sh` (with `FP_HARNESS_OFFLINE=1`) | Yes — this is the ratchet, so it is deliberately allowed to break the build. |
| `cargo-llvm-cov` coverage report | Yes, on report failure; the LCOV artifact is uploaded either way. |

Note `cargo test --workspace` does not apply here: this is a single crate with no `[workspace]` section, so `--workspace` is a no-op at best and misleading at worst.
