use clap::Parser;

use fraggle_packet::fuzzing;

#[path = "src/cli/mod.rs"]
mod cli;

#[path = "src/bin/cli/fuzzing.rs"]
mod cli_fuzzing;

#[path = "src/bin/cli/test_cmd.rs"]
mod cli_test_cmd;

#[path = "src/bin/tui/mod.rs"]
mod tui_app;

fn main() {
    env_logger::init();
    let args = cli::Args::parse();
    cli::dispatch(args);
}
