//! Tiny Prometheus-text metrics exporter.
//!
//! Intentionally zero dependencies: a hand-rolled HTTP/1.1 server bound on a
//! local TCP port answers any GET with a snapshot of the current metrics
//! registry. Good enough for scraping with `curl` or Prometheus itself.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

#[derive(Default, Clone)]
pub struct MetricsRegistry {
    inner: Arc<Mutex<MetricsInner>>,
}

#[derive(Default)]
struct MetricsInner {
    gauges: HashMap<String, f64>,
    help: HashMap<String, String>,
}

impl MetricsRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_gauge(&self, name: &str, value: f64) {
        let mut g = self.inner.lock().unwrap();
        g.gauges.insert(name.to_string(), value);
    }

    pub fn set_help(&self, name: &str, help: &str) {
        let mut g = self.inner.lock().unwrap();
        g.help.insert(name.to_string(), help.to_string());
    }

    pub fn render(&self) -> String {
        let g = self.inner.lock().unwrap();
        let mut out = String::new();
        for (name, value) in &g.gauges {
            if let Some(help) = g.help.get(name) {
                out.push_str(&format!("# HELP {} {}\n", name, help));
            }
            out.push_str(&format!("# TYPE {} gauge\n", name));
            out.push_str(&format!("{} {}\n", name, value));
        }
        out
    }
}

pub fn serve(registry: MetricsRegistry, addr: &str) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                log::warn!("metrics accept failed: {}", e);
                continue;
            }
        };
        let reg = registry.clone();
        thread::spawn(move || handle(stream, reg));
    }
    Ok(())
}

fn handle(mut stream: TcpStream, reg: MetricsRegistry) {
    let mut buf = [0u8; 2048];
    let _ = stream.read(&mut buf);
    let body = reg.render();
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(response.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_includes_gauge_and_help() {
        let r = MetricsRegistry::new();
        r.set_help("foo_total", "test gauge");
        r.set_gauge("foo_total", 42.0);
        let s = r.render();
        assert!(s.contains("# HELP foo_total"));
        assert!(s.contains("foo_total 42"));
    }
}
