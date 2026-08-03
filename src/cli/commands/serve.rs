use colored::*;

#[derive(clap::Args, Debug)]
pub struct ServeArgs {
    /// Bind address
    #[arg(short = 'b', long, default_value = "127.0.0.1:9464")]
    pub bind: String,
    /// Optional target to seed metrics from a single run
    #[arg(short, long)]
    pub target: Option<String>,
}

pub fn run(args: &ServeArgs) {
    run_serve(&args.bind, args.target.clone());
}

fn run_serve(bind: &str, target: Option<String>) {
    use fraggle_packet::framework::{serve_metrics, MetricsRegistry, NetworkTest};
    let reg = MetricsRegistry::new();
    reg.set_help("fraggle_build_info", "Build metadata");
    reg.set_gauge("fraggle_build_info", 1.0);
    if let Some(t) = target {
        use fraggle_packet::network_tests::UploadSizeSweepTest;
        if let Ok(r) = UploadSizeSweepTest::new().run(&t) {
            for (k, v) in &r.metrics {
                let metric = format!("fraggle_upload_{}", sanitize_metric(k));
                reg.set_gauge(&metric, *v);
            }
        }
    }
    println!(
        "{}",
        format!("Serving metrics on http://{}/metrics", bind)
            .green()
            .bold()
    );
    if let Err(e) = serve_metrics(reg, bind) {
        eprintln!("{} serve error: {}", "✗".red(), e);
    }
}

fn sanitize_metric(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .collect()
}
