use colored::*;

use fraggle_packet::redact::RedactionPolicy;

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

    /// GAP-018: by default, IP addresses and MAC-shaped strings that
    /// appear in vantage evidence/notes are redacted. Pass this to see
    /// raw values.
    #[arg(long)]
    pub retain_identifiers: bool,
}

pub fn run(args: &PcapReportArgs) {
    use fraggle_packet::network_tests::pcap_report::{analyze_pcap, compare_reports};

    let policy = RedactionPolicy::from_retain_flag(args.retain_identifiers);
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
            let mut buf = String::new();
            for report in &comparison.reports {
                render_report(report, &mut buf);
            }
            render_comparison(&comparison, &mut buf);
            print!("{}", policy.apply(&buf));
        }
        if had_error && comparison.reports.is_empty() {
            std::process::exit(1);
        }
        return;
    }

    if args.json {
        println!("{}", serde_json::to_string_pretty(&reports).unwrap());
    } else {
        let mut buf = String::new();
        for report in &reports {
            render_report(report, &mut buf);
        }
        print!("{}", policy.apply(&buf));
    }

    if had_error && reports.is_empty() {
        std::process::exit(1);
    }
}

fn render_comparison(
    comparison: &fraggle_packet::network_tests::pcap_report::PcapComparison,
    buf: &mut String,
) {
    buf.push_str("== Comparison ==\n");
    buf.push_str(&format!(
        "  {:<40} {:>12} {:>12} {:>12} {:>10} {:>10} {:>10}\n",
        "file", "tcp_pkts", "udp_pkts", "quic_cand", "icmp", "flows(tcp)", "dur(s)"
    ));
    for r in &comparison.reports {
        buf.push_str(&format!(
            "  {:<40} {:>12} {:>12} {:>12} {:>10} {:>10} {:>10}\n",
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
        ));
    }
    for r in &comparison.reports {
        buf.push_str(&format!(
            "  {}: retransmissions={} out_of_order={} dup_acks={}{}\n",
            r.path,
            r.tcp_anomalies.retransmissions,
            r.tcp_anomalies.out_of_order,
            r.tcp_anomalies.duplicate_acks,
            if r.tcp_anomalies.qualification_required {
                " (NOT on-wire evidence: host-side/offload-suspect)"
            } else {
                ""
            }
        ));
    }
    if comparison.any_offload_suspect {
        buf.push_str("  at least one capture is host-side/offload-suspect; see notes\n");
    }
    buf.push_str("-- Notes --\n");
    for n in &comparison.notes {
        buf.push_str(&format!("  * {}\n", n));
    }
    buf.push('\n');
}

fn render_report(
    report: &fraggle_packet::network_tests::pcap_report::PcapReport,
    buf: &mut String,
) {
    buf.push_str(&format!("== {} ==\n", report.path));

    buf.push_str("-- Capture health --\n");
    buf.push_str(&format!("  format:       {}\n", report.health.file_format));
    buf.push_str(&format!("  link type:    {}\n", report.health.link_type));
    buf.push_str(&format!(
        "  interface:    {}\n",
        report
            .health
            .interface_name
            .as_deref()
            .unwrap_or("(not recorded in file)")
    ));
    buf.push_str(&format!("  snaplen:      {}\n", report.health.snaplen));
    buf.push_str(&format!("  packets:      {}\n", report.health.packet_count));
    buf.push_str(&format!("  bytes:        {}\n", report.health.byte_count));
    buf.push_str(&format!("  truncated:    {}\n", report.health.truncated));
    match report.health.drops_known {
        Some(d) => buf.push_str(&format!("  drops:        {}\n", d)),
        None => buf.push_str("  drops:        unknown\n"),
    }

    buf.push_str("-- Vantage classification --\n");
    buf.push_str(&format!("  vantage:      {:?}\n", report.vantage.vantage));
    buf.push_str(&format!(
        "  confidence:   {:?}\n",
        report.vantage.confidence
    ));
    for e in &report.vantage.evidence {
        buf.push_str(&format!("    - {}\n", e));
    }

    buf.push_str("-- Frame size --\n");
    buf.push_str(&format!(
        "  oversize threshold (link MTU {} + L2): {} bytes\n",
        report.frame_size.link_mtu_assumed, report.frame_size.oversize_threshold
    ));
    buf.push_str(&format!(
        "  max observed frame len: {}\n",
        report.frame_size.max_observed_frame_len
    ));
    buf.push_str(&format!(
        "  frames over threshold:  {}\n",
        report.frame_size.observed_over_threshold
    ));
    if report.frame_size.oversize_is_host_segment_artifact {
        buf.push_str("  note: over-threshold frames are pre-segmentation host segments, not on-wire oversize frames\n");
    }

    buf.push_str("-- TCP anomaly counts (sampled) --\n");
    buf.push_str(&format!(
        "  sampled packets:   {}\n",
        report.tcp_anomalies.sampled_packets
    ));
    buf.push_str(&format!(
        "  retransmissions:   {}\n",
        report.tcp_anomalies.retransmissions
    ));
    buf.push_str(&format!(
        "  out of order:      {}\n",
        report.tcp_anomalies.out_of_order
    ));
    buf.push_str(&format!(
        "  duplicate acks:    {}\n",
        report.tcp_anomalies.duplicate_acks
    ));
    if report.tcp_anomalies.qualification_required {
        buf.push_str("  qualification: NOT usable as on-wire network-fault evidence (host-side/offload-suspect capture)\n");
    }

    buf.push_str("-- Notes --\n");
    for n in &report.notes {
        buf.push_str(&format!("  * {}\n", n));
    }
    buf.push('\n');
}
