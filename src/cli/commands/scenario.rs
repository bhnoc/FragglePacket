use colored::*;

use crate::cli::common::print_test_result;

#[derive(clap::Args, Debug)]
pub struct ScenarioArgs {
    /// Path to scenario file ('-' for stdin)
    pub file: String,

    /// Emit every step's result as one JSON array
    #[arg(long)]
    pub json: bool,
}

pub fn run(args: &ScenarioArgs) {
    run_scenario(&args.file, args.json);
}

fn run_scenario(file: &str, json: bool) {
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

    if json {
        // One array, so a consumer parses a single document. A failed step is
        // recorded with its error rather than dropped: a missing step would read
        // as a scenario that never included it.
        let steps: Vec<serde_json::Value> = results
            .into_iter()
            .map(|(name, res)| match res {
                Ok(r) => serde_json::json!({ "step": name, "result": r }),
                Err(e) => serde_json::json!({ "step": name, "error": e.to_string() }),
            })
            .collect();
        match serde_json::to_string_pretty(&steps) {
            Ok(s) => println!("{s}"),
            Err(e) => eprintln!("failed to serialize scenario results: {e}"),
        }
        return;
    }

    for (name, res) in results {
        println!("{}", format!("-- {} --", name).cyan().bold());
        match res {
            Ok(r) => print_test_result(&r),
            Err(e) => println!("error: {}", e),
        }
    }
}
