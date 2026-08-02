#[derive(clap::Args, Debug)]
pub struct TestArgs {
    /// Target hostname or IP
    pub target: String,
    /// Test categories (dns,https,tcp,rtt,loss,all)
    #[arg(short, long, default_value = "all")]
    pub categories: String,
    /// Packet count for RTT/loss tests
    #[arg(short = 'n', long, default_value = "20")]
    pub count: usize,
    /// Verbose output
    #[arg(short, long)]
    pub verbose: bool,
}

pub fn run(args: &TestArgs) {
    crate::cli_test_cmd::run_tests(crate::cli_test_cmd::TestCommand {
        target: args.target.clone(),
        categories: args.categories.clone(),
        count: args.count,
        verbose: args.verbose,
    });
}
