use colored::*;

#[derive(clap::Args, Debug)]
pub struct ReplayArgs {
    /// PCAP path
    pub pcap: String,
    /// Interface to send on (required on Linux)
    #[arg(short, long)]
    pub iface: Option<String>,
    /// Packets-per-second rate
    #[arg(long)]
    pub pps: Option<u32>,
    /// Number of loops
    #[arg(long, default_value_t = 1)]
    pub loop_count: u32,
    /// Rewrite destination IP before sending
    #[arg(long)]
    pub rewrite_dst_ip: Option<std::net::Ipv4Addr>,
    /// Rewrite source IP before sending
    #[arg(long)]
    pub rewrite_src_ip: Option<std::net::Ipv4Addr>,
}

pub fn run(args: &ReplayArgs) {
    use fraggle_packet::fuzzing::replay::{replay_pcap, ReplayOptions};
    let mut opts = ReplayOptions::new().loop_count(args.loop_count);
    if let Some(i) = &args.iface {
        opts = opts.iface(i.clone());
    }
    if let Some(r) = args.pps {
        opts = opts.pps(r);
    }
    if let Some(ip) = args.rewrite_dst_ip {
        opts = opts.rewrite_dst_ip(ip);
    }
    if let Some(ip) = args.rewrite_src_ip {
        opts = opts.rewrite_src_ip(ip);
    }
    println!("{}", format!("Replaying {} ...", args.pcap).cyan().bold());
    match replay_pcap(&args.pcap, &opts) {
        Ok(report) => {
            println!("{}", "Replay complete".green().bold());
            println!("  Packets sent:    {}", report.packets_sent);
            println!("  Packets dropped: {}", report.packets_dropped);
            println!("  Bytes sent:      {}", report.bytes_sent);
            println!("  Duration:        {} ms", report.duration_ms);
        }
        Err(e) => eprintln!("{} replay error: {}", "✗".red(), e),
    }
}
