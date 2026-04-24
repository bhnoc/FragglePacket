# Scenario DSL

Implemented in `src/network_tests/scenario.rs`. The parser is whitespace-sensitive but intentionally tiny; no YAML dependency.

## Syntax rules

* Lines starting with `# step:` (or `#step:`) open a new step named after the trailing text.
* Lines of the form `key: value` set step fields.
* Blank lines terminate a step.
* Any other `#` line is a comment and is ignored.
* Anything outside a step definition is ignored.

Recognised keys:

| Key | Purpose |
| --- | --- |
| kind | Test type to run (required) |
| target | Hostname or IP passed as the test target (required) |
| port | Optional u16 port, consumed by tests that support it |
| Any other key | Stored in `extra: HashMap<String, String>` for future use, not read today |

## Supported `kind` values

| Value | Backing NetworkTest | Port aware |
| --- | --- | --- |
| `https` | `HttpsTest` | No |
| `upload_sweep`, `upload` | `UploadSizeSweepTest` | Yes |
| `ssh` | `SshDataPathTest` | No |
| `printer`, `raw9100` | `Raw9100BulkTest` | No |
| `quic` | `QuicPmtudTest` | No |
| `dns_secure`, `dns` | `DnsSecureCompareTest` | No |
| `tcp_options` | `TcpOptionsEchoTest` | No |

Unknown kinds produce a `unknown kind '...'` error on that step; other steps continue.

## Example

```
# step: check-http
kind: https
target: example.com

# step: bulk-upload
kind: upload_sweep
target: example.com
port: 443

# step: printer-bulk
kind: printer
target: printer.lan
```

Run it:

```bash
fraggle-packet scenario my-scenario.txt
cat my-scenario.txt | fraggle-packet scenario -
```

Each step prints a header line and then the full `TestResult` via the same formatter the CLI uses for individual tests.

## Result surface

`Scenario::run` returns `Vec<(String, Result<TestResult, String>)>`, so host tools (CLI, desktop Probes panel) can render successes and errors independently.
