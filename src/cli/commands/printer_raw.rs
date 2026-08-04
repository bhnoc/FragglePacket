use colored::*;

use crate::cli::common::emit_test_result;

#[derive(clap::Args, Debug)]
pub struct PrinterRawArgs {
    /// Target hostname or IP
    pub target: String,
    /// Target port (default 9100)
    #[arg(short, long, default_value_t = 9100)]
    pub port: u16,

    /// Emit the full result as JSON
    #[arg(long)]
    pub json: bool,
}

pub fn run(args: &PrinterRawArgs) {
    use fraggle_packet::framework::NetworkTest;
    use fraggle_packet::network_tests::Raw9100BulkTest;
    let t = Raw9100BulkTest::new().with_port(args.port);
    match t.run(&args.target) {
        Ok(res) => emit_test_result(&res, args.json),
        Err(e) => eprintln!("{} printer-raw error: {}", "✗".red(), e),
    }
}
