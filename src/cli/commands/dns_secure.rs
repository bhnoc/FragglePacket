use colored::*;

use crate::cli::common::emit_test_result;

#[derive(clap::Args, Debug)]
pub struct DnsSecureArgs {
    /// Target hostname to resolve
    pub target: String,

    /// Emit the full result as JSON
    #[arg(long)]
    pub json: bool,
}

pub fn run(args: &DnsSecureArgs) {
    use fraggle_packet::framework::NetworkTest;
    use fraggle_packet::network_tests::DnsSecureCompareTest;
    let t = DnsSecureCompareTest::new();
    match t.run(&args.target) {
        Ok(res) => emit_test_result(&res, args.json),
        Err(e) => eprintln!("{} dns-secure error: {}", "✗".red(), e),
    }
}
