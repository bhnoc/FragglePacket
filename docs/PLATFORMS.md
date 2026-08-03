# Platform Feature Matrix

Behavior derives from `src/fuzzing/replay.rs`, `src/fuzzing/capture.rs`, `src/fuzzing/probe.rs`, and the MTU tests under `src/network_tests/`.

## Raw socket and packet features

| Feature | Linux | macOS | Windows |
| --- | --- | --- | --- |
| PCAP replay | AF_PACKET SOCK_RAW ETH_P_ALL, needs root or CAP_NET_RAW+CAP_NET_ADMIN | IPPROTO_RAW with IP_HDRINCL (L3 only), needs root | ReplayError::Unsupported |
| Passive capture | AF_PACKET, needs root or capabilities | `/dev/bpfN` with BIOCSETIF, needs sufficient privileges on that bpf device | Unsupported |
| Active PMTU probe | Runs, needs same privileges as replay plus capture | Runs at L3 only, still needs root | Unsupported |
| DSL demo output | Works without root | Works without root | Works without root |

Windows support in the fuzzing engine is limited to packet building and PCAP writing. Transmission and capture paths return unsupported errors.

## MTU methods

| Method | Linux | macOS | Windows |
| --- | --- | --- | --- |
| `IcmpMtuTest` (DF-bit ping sweep) | Uses IP_PMTUDISC_DO, runs without root because ping has setuid | Skips at runtime; IP_MTU_DISCOVER is Linux only | Not built in |
| `TcpMtuTest` (`TCP_MAXSEG` readback) | Reads socket option, falls back to `ss -ti` | Relies on `ss` which is absent, usually returns None | Not built in |
| `QuicPmtudTest` | Works via quinn everywhere | Works | Works where the binary builds |
| `TunnelMssClampingTest` | Works | Works | Works |
| `PathAnalysisTest` | Uses `tracepath` then `traceroute` | Uses `traceroute`, tracepath usually absent | Not built in |
| Kitchen sink UDP probe | Uses IP_MTU_DISCOVER; accurate | Falls back to send-and-wait, less accurate | Not built in |

## Application tests

All framework tests aside from those above rely on standard sockets and external tools (`ping`, `dig`, `ss`, `curl` for some paths). They build and run on Linux and macOS. Windows builds compile the library but lack the shell utilities, so tests that shell out degrade to failures.

## UI binaries

| UI | Linux | macOS | Windows |
| --- | --- | --- | --- |
| fraggle-packet CLI | Works | Works | Builds, relies on external tools |
| fraggle-packet tui | Works | Works | Builds, no known native bugs |
| fraggle-desktop | Works with gtk3, webkit2gtk-4.1, libayatana-appindicator3, librsvg2 | Works with system webview | Not tested in setup.sh; Dioxus desktop supports Windows separately |

## Privilege escalation paths

| Platform | Recommended path |
| --- | --- |
| Linux | `sudo setcap cap_net_raw,cap_net_admin+eip ./target/release/fraggle-desktop` once per build |
| macOS | Relaunch with `sudo` when raw-socket features are required |
| Windows | Launch elevated, otherwise expect Unsupported errors |

## Build dependencies summary

| Platform | Build tools |
| --- | --- |
| Ubuntu, Debian | build-essential, pkg-config, libssl-dev, libgtk-3-dev, libwebkit2gtk-4.1-dev, libayatana-appindicator3-dev, librsvg2-dev |
| Fedora family | gcc, make, pkg-config, openssl-devel |
| Arch family | base-devel, openssl |
| macOS | Xcode command line tools, Homebrew openssl |
