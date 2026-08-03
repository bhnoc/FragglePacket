//! GAP-007: bounded packet capture CLI (`capture`).

use colored::*;

use fraggle_packet::network_tests::capture::{
    run_bounded_capture, CaptureError, CaptureOptions, DEFAULT_DURATION_SECS, DEFAULT_MAX_BYTES,
    DEFAULT_SNAPLEN,
};

#[derive(clap::Args, Debug)]
pub struct CaptureArgs {
    /// Interface to capture on, e.g. en0
    #[arg(short, long)]
    pub interface: String,

    /// Output pcap path
    #[arg(short, long, default_value = "capture.pcap")]
    pub output: String,

    /// Capture duration cap in seconds. A capture always stops on its own
    /// even with no flags given -- this is that default.
    #[arg(long, default_value_t = DEFAULT_DURATION_SECS)]
    pub duration_secs: u64,

    /// Per-packet snapshot length in bytes. Kept small by default so a
    /// bounded default capture stays small even at high packet rates.
    #[arg(long, default_value_t = DEFAULT_SNAPLEN)]
    pub snaplen: u32,

    /// Hard cap on total bytes written before the capture is stopped.
    #[arg(long, default_value_t = DEFAULT_MAX_BYTES)]
    pub max_bytes: u64,

    /// Rotate to a new file after this many megabytes.
    #[arg(long)]
    pub rotate_file_mb: Option<u64>,

    /// Keep at most this many rotated files.
    #[arg(long)]
    pub rotate_file_count: Option<u32>,

    /// BPF filter expression, e.g. "tcp port 443"
    #[arg(long)]
    pub filter: Option<String>,

    #[arg(long)]
    pub json: bool,
}

pub fn run(args: &CaptureArgs) {
    let mut opts = CaptureOptions::new(args.interface.clone(), args.output.clone());
    opts.duration_secs = args.duration_secs;
    opts.snaplen = args.snaplen;
    opts.max_bytes = args.max_bytes;
    opts.rotate_file_mb = args.rotate_file_mb;
    opts.rotate_file_count = args.rotate_file_count;
    opts.filter = args.filter.clone();

    if !args.json {
        println!(
            "{}",
            format!(
                "Capturing on {} for up to {}s, snaplen {}, cap {} bytes -> {}",
                args.interface, args.duration_secs, args.snaplen, args.max_bytes, args.output
            )
            .cyan()
        );
    }

    match run_bounded_capture(&opts) {
        Ok(meta) => {
            if args.json {
                println!("{}", serde_json::to_string_pretty(&meta).unwrap());
            } else {
                println!("{}", "Capture complete".green().bold());
                println!("  stop reason:   {:?}", meta.stop_reason);
                println!(
                    "  duration:      {:.1}s (requested {}s)",
                    meta.actual_duration_secs, meta.requested_duration_secs
                );
                println!("  bytes written: {}", meta.total_bytes_written);
                println!("  files:         {}", meta.output_files.join(", "));
            }
        }
        Err(CaptureError::PrivilegeRequired { detail, command }) => {
            eprintln!("{} capture requires elevated privilege", "✗".red().bold());
            eprintln!("  {}", detail.dimmed());
            eprintln!("  re-run as: {}", command.yellow());
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("{} capture error: {}", "✗".red(), e);
            std::process::exit(1);
        }
    }
}
