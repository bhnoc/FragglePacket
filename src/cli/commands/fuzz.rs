use colored::*;

#[derive(clap::Args, Debug)]
pub struct FuzzArgs {
    /// Target hostname or IP
    pub target: String,
    /// Output PCAP file path
    #[arg(short, long, default_value = "reports/fuzz.pcap")]
    pub output: String,
    /// Fuzzing mode (segment-size, length-mismatch, tcp-options, fragmentation, checksum)
    #[arg(short, long, default_value = "segment-size")]
    pub mode: String,
}

pub fn run(args: &FuzzArgs) {
    match crate::cli_fuzzing::handle_fuzz_command(&args.target, &args.output, &args.mode) {
        Ok(_) => {}
        Err(e) => {
            eprintln!("{} Fuzzing error: {}", "✗".red().bold(), e);
            std::process::exit(1);
        }
    }
}
