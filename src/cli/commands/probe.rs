use colored::*;

#[derive(clap::Args, Debug)]
pub struct ProbeArgs {
    /// Target IPv4 address
    pub target: std::net::Ipv4Addr,
    /// Interface
    #[arg(short, long)]
    pub iface: String,
    /// Minimum probe size
    #[arg(long, default_value_t = 576)]
    pub min: u16,
    /// Maximum probe size
    #[arg(long, default_value_t = 1500)]
    pub max: u16,
}

pub fn run(args: &ProbeArgs) {
    use fraggle_packet::fuzzing::probe::active_pmtu_probe;
    use std::time::Duration;
    println!(
        "{}",
        format!("Active PMTU probe {} -> {} on {}", args.min, args.max, args.iface)
            .cyan()
            .bold()
    );
    match active_pmtu_probe(&args.iface, args.target, args.min, args.max, Duration::from_millis(1500)) {
        Ok(r) => {
            println!("Samples tried: {:?}", r.samples_tried);
            println!("Frag needed seen: {}", r.frag_needed_reported);
            if let Some(mtu) = r.estimated_mtu {
                println!("Estimated MTU: {}", mtu);
            }
        }
        Err(e) => eprintln!("{} probe error: {}", "✗".red(), e),
    }
}
