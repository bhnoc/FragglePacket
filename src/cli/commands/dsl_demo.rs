use colored::*;

#[derive(clap::Args, Debug)]
pub struct DslDemoArgs {
    /// Destination IPv4
    #[arg(short, long, default_value = "1.1.1.1")]
    pub dst: std::net::Ipv4Addr,
    /// Destination port
    #[arg(short, long, default_value_t = 443)]
    pub port: u16,
    /// Payload size in bytes
    #[arg(long, default_value_t = 32)]
    pub size: usize,
}

pub fn run(args: &DslDemoArgs) {
    use fraggle_packet::fuzzing::dsl::*;
    let pkt = Ether::new()
        / Ip::new().dst_addr(args.dst).df()
        / Tcp::new()
            .dport(args.port)
            .syn()
            .options(vec![TcpOpt::Mss(1460), TcpOpt::SAckOK, TcpOpt::Nop])
        / Raw::of_size(args.size, b'X');
    println!("{}", pkt.summary().cyan());
    match pkt.hexdump() {
        Ok(h) => println!("{}", h),
        Err(e) => eprintln!("{} hexdump error: {}", "✗".red(), e),
    }
}
