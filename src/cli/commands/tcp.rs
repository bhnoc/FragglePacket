use colored::*;
use fraggle_packet::probe::binary_search_mtu_tcp;

use crate::cli::GlobalArgs;

#[derive(clap::Args, Debug)]
pub struct TcpArgs {
    /// Target hostname:port
    pub target: String,

    /// Emit the result as JSON
    #[arg(long)]
    pub json: bool,
}

pub fn run(args: &TcpArgs, global: &GlobalArgs) {
    run_tcp_mtu_test(&args.target, global.timeout_ms, global.min, global.max, args.json);
}

fn run_tcp_mtu_test(target: &str, timeout_ms: u64, min_mtu: usize, max_mtu: usize, json: bool) {
    if !json {
        println!("TCP-based MTU discovery to {}", target.cyan());
        println!("(Does not require ICMP - useful when ping is blocked)");
        println!();
    }

    let found = binary_search_mtu_tcp(target, min_mtu, max_mtu, timeout_ms);

    if json {
        // A failed discovery reports mtu: null with a reason, never a zero or a
        // guessed floor -- an unmeasured MTU must not read as a measured one.
        let doc = match found {
            Some(mtu) => serde_json::json!({
                "target": target,
                "effective_tcp_mtu": mtu,
                "tcp_mss": mtu.saturating_sub(40),
            }),
            None => serde_json::json!({
                "target": target,
                "effective_tcp_mtu": serde_json::Value::Null,
                "tcp_mss": serde_json::Value::Null,
                "reason": "TCP MTU discovery did not complete",
            }),
        };
        match serde_json::to_string_pretty(&doc) {
            Ok(s) => println!("{s}"),
            Err(e) => eprintln!("failed to serialize result: {e}"),
        }
        return;
    }

    match found {
        Some(mtu) => {
            println!("{}", "RESULTS:".cyan().bold());
            println!("  Effective TCP MTU: {} bytes", mtu.to_string().green().bold());
            println!("  TCP MSS:           {} bytes", mtu - 40);
        }
        None => {
            eprintln!("{}: Could not complete TCP MTU discovery", "Error".red());
        }
    }
}
