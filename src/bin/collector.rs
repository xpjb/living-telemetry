use std::net::SocketAddr;
use std::path::PathBuf;

use living_telemetry::{CollectorConfig, run_collector};

fn main() {
    let mut bind = None;
    let mut root = None;
    let mut allow_public_bind = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--bind" => bind = args.next().and_then(|value| value.parse::<SocketAddr>().ok()),
            "--data" => root = args.next().map(PathBuf::from),
            "--allow-public-bind" => allow_public_bind = true,
            "--help" | "-h" => {
                println!(
                    "usage: living-telemetry-collector --bind <ip:port> --data <directory> [--allow-public-bind]"
                );
                return;
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
    }
    let Some(bind) = bind else {
        eprintln!("--bind is required");
        std::process::exit(2);
    };
    let Some(root) = root else {
        eprintln!("--data is required");
        std::process::exit(2);
    };
    let mut config = CollectorConfig::new(bind, root);
    config.allow_public_bind = allow_public_bind;
    if let Err(err) = run_collector(config) {
        eprintln!("{err}");
        std::process::exit(1);
    }
}
