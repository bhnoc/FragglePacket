use colored::*;
use fraggle_packet::probe::binary_search_mtu_tcp;

use crate::cli::GlobalArgs;

#[derive(clap::Args, Debug)]
pub struct TcpArgs {
    /// Target hostname:port
    pub target: String,
}

pub fn run(args: &TcpArgs, global: &GlobalArgs) {
    run_tcp_mtu_test(&args.target, global.timeout_ms, global.min, global.max);
}

fn run_tcp_mtu_test(target: &str, timeout_ms: u64, min_mtu: usize, max_mtu: usize) {
    println!("TCP-based MTU discovery to {}", target.cyan());
    println!("(Does not require ICMP - useful when ping is blocked)");
    println!();

    match binary_search_mtu_tcp(target, min_mtu, max_mtu, timeout_ms) {
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
