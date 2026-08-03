use colored::*;

use crate::cli::common::print_test_result;

#[derive(clap::Args, Debug)]
pub struct SshPathArgs {
    /// Target hostname or IP
    pub target: String,
    /// SSH port (default 22)
    #[arg(short, long, default_value_t = 22)]
    pub port: u16,
    /// SSH user for the optional exec stage (also enables it)
    #[arg(short, long)]
    pub user: Option<String>,
}

pub fn run(args: &SshPathArgs) {
    use fraggle_packet::framework::NetworkTest;
    use fraggle_packet::network_tests::SshDataPathTest;
    let mut t = SshDataPathTest::new().with_port(args.port);
    if let Some(u) = &args.user {
        t = t.with_user(u.clone());
    }
    match t.run(&args.target) {
        Ok(res) => print_test_result(&res),
        Err(e) => eprintln!("{} ssh-path error: {}", "✗".red(), e),
    }
}
