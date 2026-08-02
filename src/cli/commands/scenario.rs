use colored::*;

use crate::cli::common::print_test_result;

#[derive(clap::Args, Debug)]
pub struct ScenarioArgs {
    /// Path to scenario file ('-' for stdin)
    pub file: String,
}

pub fn run(args: &ScenarioArgs) {
    run_scenario(&args.file);
}

fn run_scenario(file: &str) {
    use fraggle_packet::network_tests::scenario::Scenario;
    let text = if file == "-" {
        let mut s = String::new();
        use std::io::Read;
        let _ = std::io::stdin().read_to_string(&mut s);
        s
    } else {
        match std::fs::read_to_string(file) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("{} read scenario: {}", "✗".red(), e);
                return;
            }
        }
    };
    let scenario = match Scenario::parse(&text) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{} parse scenario: {}", "✗".red(), e);
            return;
        }
    };
    let results = scenario.run();
    for (name, res) in results {
        println!("{}", format!("-- {} --", name).cyan().bold());
        match res {
            Ok(r) => print_test_result(&r),
            Err(e) => println!("error: {}", e),
        }
    }
}
