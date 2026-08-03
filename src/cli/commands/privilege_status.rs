use colored::*;

use fraggle_packet::probe::privilege_status::{all_ops, classify_privilege_failure};

#[derive(clap::Args, Debug)]
pub struct PrivilegeStatusArgs {
    /// Classify a captured stderr string instead of listing the inventory.
    /// Useful for confirming a tool's failure was a permission problem rather
    /// than a network result.
    #[arg(long)]
    pub classify_stderr: Option<String>,

    /// Treat the classification as though the failing call also returned EPERM,
    /// which is what a refused raw-socket or BPF open reports even when the
    /// tool's own stderr is empty.
    #[arg(long)]
    pub as_eperm: bool,

    #[arg(long)]
    pub json: bool,
}

pub fn run(args: &PrivilegeStatusArgs) {
    if let Some(stderr) = &args.classify_stderr {
        let os_err = if args.as_eperm {
            Some(std::io::Error::from_raw_os_error(libc::EPERM))
        } else {
            None
        };
        let status = classify_privilege_failure(
            stderr,
            os_err.as_ref(),
            "sudo <the failing command>".to_string(),
        );

        if args.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({ "status": status }))
                    .unwrap_or_default()
            );
            return;
        }

        println!("\n== Privilege classification ==");
        match status {
            Some(s) => {
                println!("  denied: {}", s.is_denied());
                println!("  {:?}", s);
            }
            None => println!(
                "  not a privilege problem; the failure should be surfaced as its own error rather \
                 than sending the operator to sudo"
            ),
        }
        return;
    }

    let ops: Vec<_> = all_ops()
        .into_iter()
        .map(|o| {
            serde_json::json!({
                "operation": o.what,
                "required_command": o.required_command,
                "unprivileged_alternative": o.unprivileged_alternative,
            })
        })
        .collect();

    if args.json {
        println!("{}", serde_json::to_string_pretty(&ops).unwrap_or_default());
        return;
    }

    println!("\n== Privileged operations and unprivileged alternatives ==");
    for o in all_ops() {
        println!("\n  {}", o.what.bold());
        println!("    requires: {}", o.required_command);
        match o.unprivileged_alternative {
            Some(a) => println!("    without privilege: {}", a),
            None => println!("    without privilege: {}", "no alternative".yellow()),
        }
    }
    println!(
        "\n  A privileged operation that fails preserves the tool's own error text and names the \
         command above. An empty failure is reported with its errno rather than passed through as \
         though nothing went wrong."
    );
}
