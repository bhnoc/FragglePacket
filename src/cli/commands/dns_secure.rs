use colored::*;

use crate::cli::common::print_test_result;

#[derive(clap::Args, Debug)]
pub struct DnsSecureArgs {
    /// Target hostname to resolve
    pub target: String,
}

pub fn run(args: &DnsSecureArgs) {
    use fraggle_packet::framework::NetworkTest;
    use fraggle_packet::network_tests::DnsSecureCompareTest;
    let t = DnsSecureCompareTest::new();
    match t.run(&args.target) {
        Ok(res) => print_test_result(&res),
        Err(e) => eprintln!("{} dns-secure error: {}", "✗".red(), e),
    }
}
