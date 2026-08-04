use colored::*;

use crate::cli::common::emit_test_result;

#[derive(clap::Args, Debug)]
pub struct TcpOptionsArgs {
    /// Target hostname or IP
    pub target: String,
    /// Target port (default 443)
    #[arg(short, long, default_value_t = 443)]
    pub port: u16,

    /// Emit the full result as JSON
    #[arg(long)]
    pub json: bool,
}

pub fn run(args: &TcpOptionsArgs) {
    use fraggle_packet::framework::NetworkTest;
    use fraggle_packet::network_tests::TcpOptionsEchoTest;
    let t = TcpOptionsEchoTest::new().with_port(args.port);
    match t.run(&args.target) {
        Ok(res) => emit_test_result(&res, args.json),
        Err(e) => eprintln!("{} tcp-options error: {}", "✗".red(), e),
    }
}
