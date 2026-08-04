use colored::*;

use crate::cli::common::emit_test_result;

#[derive(clap::Args, Debug)]
pub struct UploadSweepArgs {
    /// Target hostname
    pub target: String,
    /// Target port (default 443)
    #[arg(short, long, default_value_t = 443)]
    pub port: u16,

    /// Emit the full result as JSON
    #[arg(long)]
    pub json: bool,
}

pub fn run(args: &UploadSweepArgs) {
    use fraggle_packet::framework::NetworkTest;
    use fraggle_packet::network_tests::UploadSizeSweepTest;
    let t = UploadSizeSweepTest::new().with_port(args.port);
    match t.run(&args.target) {
        Ok(res) => emit_test_result(&res, args.json),
        Err(e) => eprintln!("{} upload-sweep error: {}", "✗".red(), e),
    }
}
