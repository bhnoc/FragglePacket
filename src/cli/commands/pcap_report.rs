use colored::*;

#[derive(clap::Args, Debug)]
pub struct PcapReportArgs {
    /// PCAP or pcapng file(s) to analyze
    #[arg(required = true)]
    pub files: Vec<String>,

    /// Output as JSON instead of a human-readable report
    #[arg(long)]
    pub json: bool,

    /// Force comparison-mode output (GAP-008) even with one file. With two
    /// or more files, comparison output is shown automatically.
    #[arg(long)]
    pub compare: bool,
}

pub fn run(args: &PcapReportArgs) {
    use fraggle_packet::network_tests::pcap_report::{analyze_pcap, compare_reports};

    let mut reports = Vec::new();
    let mut had_error = false;

    for path in &args.files {
        match analyze_pcap(path) {
            Ok(report) => reports.push(report),
            Err(e) => {
                eprintln!("{} {}: {}", "✗".red(), path, e);
                had_error = true;
            }
        }
    }

    let show_comparison = args.compare || reports.len() > 1;

    if show_comparison {
        let comparison = compare_reports(reports);
        if args.json {
            println!("{}", serde_json::to_string_pretty(&comparison).unwrap());
        } else {
            for report in &comparison.reports {
                print_report(report);
            }
            print_comparison(&comparison);
        }
        if had_error && comparison.reports.is_empty() {
            std::process::exit(1);
        }
        return;
    }

    if args.json {
        println!("{}", serde_json::to_string_pretty(&reports).unwrap());
    } else {
        for report in &reports {
            print_report(report);
        }
    }

    if had_error && reports.is_empty() {
        std::process::exit(1);
    }
}

fn print_comparison(comparison: &fraggle_packet::network_tests::pcap_report::PcapComparison) {
    println!("{}", "== Comparison ==".cyan().bold());
    println!(
        "  {:<40} {:>12} {:>12} {:>12} {:>10} {:>10} {:>10}",
        "file", "tcp_pkts", "udp_pkts", "quic_cand", "icmp", "flows(tcp)", "dur(s)"
    );
    for r in &comparison.reports {
        println!(
            "  {:<40} {:>12} {:>12} {:>12} {:>10} {:>10} {:>10}",
            r.path,
            r.protocol_breakdown.tcp_packets,
            r.protocol_breakdown.udp_packets,
            r.protocol_breakdown.quic_candidate_packets,
            r.protocol_breakdown.icmp_packets,
            r.directions_seen.total_tcp_flows,
            r.health
                .duration_secs
                .map(|d| format!("{:.1}", d))
                .unwrap_or_else(|| "?".to_string()),
        );
    }
    for r in &comparison.reports {
        println!(
            "  {}: retransmissions={} out_of_order={} dup_acks={}{}",
            r.path,
            r.tcp_anomalies.retransmissions,
            r.tcp_anomalies.out_of_order,
            r.tcp_anomalies.duplicate_acks,
            if r.tcp_anomalies.qualification_required {
                " (NOT on-wire evidence: host-side/offload-suspect)".yellow().to_string()
            } else {
                String::new()
            }
        );
    }
    if comparison.any_offload_suspect {
        println!(
            "  {}",
            "at least one capture is host-side/offload-suspect; see notes".yellow()
        );
    }
    println!("{}", "-- Notes --".white().bold());
    for n in &comparison.notes {
        println!("  * {}", n);
    }
    println!();
}

fn print_report(report: &fraggle_packet::network_tests::pcap_report::PcapReport) {
    println!("{}", format!("== {} ==", report.path).cyan().bold());

    println!("{}", "-- Capture health --".white().bold());
    println!("  format:       {}", report.health.file_format);
    println!("  link type:    {}", report.health.link_type);
    println!(
        "  interface:    {}",
        report.health.interface_name.as_deref().unwrap_or("(not recorded in file)")
    );
    println!("  snaplen:      {}", report.health.snaplen);
    println!("  packets:      {}", report.health.packet_count);
    println!("  bytes:        {}", report.health.byte_count);
    println!("  truncated:    {}", report.health.truncated);
    match report.health.drops_known {
        Some(d) => println!("  drops:        {}", d),
        None => println!("  drops:        {}", "unknown".yellow()),
    }

    println!("{}", "-- Vantage classification --".white().bold());
    println!("  vantage:      {:?}", report.vantage.vantage);
    println!("  confidence:   {:?}", report.vantage.confidence);
    for e in &report.vantage.evidence {
        println!("    - {}", e);
    }

    println!("{}", "-- Frame size --".white().bold());
    println!(
        "  oversize threshold (link MTU {} + L2): {} bytes",
        report.frame_size.link_mtu_assumed, report.frame_size.oversize_threshold
    );
    println!("  max observed frame len: {}", report.frame_size.max_observed_frame_len);
    println!("  frames over threshold:  {}", report.frame_size.observed_over_threshold);
    if report.frame_size.oversize_is_host_segment_artifact {
        println!(
            "  {}",
            "note: over-threshold frames are pre-segmentation host segments, not on-wire oversize frames".yellow()
        );
    }

    println!("{}", "-- TCP anomaly counts (sampled) --".white().bold());
    println!("  sampled packets:   {}", report.tcp_anomalies.sampled_packets);
    println!("  retransmissions:   {}", report.tcp_anomalies.retransmissions);
    println!("  out of order:      {}", report.tcp_anomalies.out_of_order);
    println!("  duplicate acks:    {}", report.tcp_anomalies.duplicate_acks);
    if report.tcp_anomalies.qualification_required {
        println!(
            "  {}",
            "qualification: NOT usable as on-wire network-fault evidence (host-side/offload-suspect capture)".yellow()
        );
    }

    println!("{}", "-- Notes --".white().bold());
    for n in &report.notes {
        println!("  * {}", n);
    }
    println!();
}
