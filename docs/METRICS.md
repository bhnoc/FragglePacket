# Prometheus Metrics Exporter

`src/framework/metrics.rs` exposes a zero-dependency HTTP/1.1 exporter. The public surface is `MetricsRegistry` plus the free function `serve(registry, addr)`.

## Starting the exporter

### CLI

```bash
fraggle-packet serve
fraggle-packet serve --bind 0.0.0.0:9464
fraggle-packet serve --target example.com
```

Default bind is `127.0.0.1:9464`. Passing `--target` runs one `UploadSizeSweepTest` at startup and seeds `fraggle_upload_*` gauges before serving.

### Desktop

Probes panel, Prometheus Metrics card. Enter a bind address, click Start. The coroutine spawns `serve_metrics` on a blocking Tokio thread. Stopping the server requires quitting the app; the exporter has no shutdown hook.

### Library

```rust
use fraggle_packet::framework::{MetricsRegistry, serve_metrics};

let reg = MetricsRegistry::new();
reg.set_help("my_gauge", "example gauge");
reg.set_gauge("my_gauge", 1.0);
serve_metrics(reg, "127.0.0.1:9464")?;
```

`serve_metrics` spawns one thread per accepted connection. Any GET receives the full snapshot.

## Output format

Prometheus text 0.0.4. Every gauge is rendered as:

```
# HELP <name> <help text, if set>
# TYPE <name> gauge
<name> <value>
```

The registry only stores gauges today. Counters and histograms are not modeled.

## Metric names produced by the CLI

The `serve` subcommand seeds a fixed metric plus optional upload-sweep gauges.

| Metric | Origin | Notes |
| --- | --- | --- |
| `fraggle_build_info` | `serve` startup | Always 1, tagged with the help text `Build metadata` |
| `fraggle_upload_<sanitized_metric>` | `UploadSizeSweepTest.metrics` | Emitted only when `--target` is supplied; `sanitize_metric` replaces non-alphanumeric characters with `_` |

Example gauge set from an upload sweep (names depend on the metrics the test records):

```
fraggle_upload_first_fail_size
fraggle_upload_last_success_size
fraggle_upload_max_success_size
```

## Custom integrations

Call `MetricsRegistry::set_gauge` or `set_help` from anywhere in your process, then scrape with any tool that understands the Prometheus text exposition format.
