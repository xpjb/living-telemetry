# living-telemetry

A small always-on telemetry runtime for native applications. It records exact slow
frames and operations, detects blocked UI callbacks from a sidecar process, keeps a
bounded durable spool, and ships reports to a simple collector.

## Client

The host executable must enter watchdog mode before normal argument handling:

```rust
fn main() {
    if living_telemetry::run_watchdog_from_args() {
        return;
    }
    let mut config = living_telemetry::Config::new("app", "1.0", data_dir);
    config.endpoint = Some("http://collector.tailnet:4318/v1/report".to_string());
    living_telemetry::init(config).expect("telemetry");

    run_app();
    living_telemetry::shutdown();
}
```

Use `busy!` around UI callbacks, `scope!` around meaningful phases, call
`redraw_requested()` and `input_received()` at the event boundary, and wrap each
paint with `Frame::start()`, `phase()`, and `finish()`. `set_state()` publishes
content-free identifiers and counts for incident context. `event_duration()` records
work that spans asynchronous boundaries. `report()` queues an immediate bounded
report such as an explicit user repro snapshot. `report_panic()` can be called from
an existing panic hook.

The UI path performs clock reads, atomics, and bounded in-memory writes. A reporter
thread and same-executable watchdog own serialization, disk, HTTP, process sampling,
and Windows dump creation.

## Collector

Build and install the binary:

```sh
/usr/local/bin/cargo build --release -p living-telemetry --bin living-telemetry-collector
install -m 0755 target/release/living-telemetry-collector /usr/local/bin/
```

The collector refuses binds outside loopback and the Tailscale address ranges unless
`--allow-public-bind` is passed. On a normal TUN host it can bind the machine's
Tailnet address directly. On a userspace-networking host, bind loopback and expose a
raw Tailnet-only forward:

```sh
living-telemetry-collector --bind 127.0.0.1:4318 --data /var/lib/living-telemetry
tailscale serve --bg --tcp=4318 tcp://127.0.0.1:4318
```

Endpoints:

- `GET /health`
- `POST /v1/report`
- `POST /v1/attachment`

Reports are stored under `<data>/<topic>/<app>/<device>/`; `index.jsonl` is the
arrival index. The included systemd unit uses a dynamic user, a private state
directory, a loopback listener, and a restricted service sandbox.

## Bounds and privacy

Default client bounds are 4,096 recent records, 1,024 pending slow samples, and a
128 MiB spool. Normal reports contain operation names, durations, identifiers,
counts, and process samples. They do not include document text, prompts, responses,
images, credentials, clipboard data, provider names, or full paths. Panic details
and Windows minidumps can contain process data and should stay inside the trusted
Tailnet collector.
