use colored::*;

use crate::cli::common::print_test_result;

#[derive(clap::Args, Debug)]
pub struct UploadSweepArgs {
    /// Target hostname
    pub target: String,
    /// Target port (default 443)
    #[arg(short, long, default_value_t = 443)]
    pub port: u16,
}

pub fn run(args: &UploadSweepArgs) {
    use fraggle_packet::framework::NetworkTest;
    use fraggle_packet::network_tests::UploadSizeSweepTest;
    let t = UploadSizeSweepTest::new().with_port(args.port);
    match t.run(&args.target) {
        Ok(res) => print_test_result(&res),
        Err(e) => eprintln!("{} upload-sweep error: {}", "✗".red(), e),
    }
}
