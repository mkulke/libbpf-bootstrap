use anyhow::{anyhow, bail, Result};
use core::time::Duration;
use lazy_static::lazy_static;
use libbpf_rs::PerfBufferBuilder;
use object::Object;
use object::ObjectSymbol;
use plain::Plain;
use prometheus::{register_int_counter_vec, IntCounterVec};
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use structopt::StructOpt;

lazy_static! {
    static ref TRACECON_COLLECTOR: IntCounterVec = register_int_counter_vec!(
        "traced_connections",
        "Traced Connections",
        &["pid", "host", "ip"]
    )
    .unwrap();
}

#[path = "bpf/.output/tracecon.skel.rs"]
mod tracecon;
use tracecon::*;

type Event = tracecon_bss_types::event;
unsafe impl Plain for Event {}

#[derive(Debug, StructOpt)]
struct Command {
    /// verbose output
    #[structopt(long, short)]
    verbose: bool,
    /// glibc path
    #[structopt(long, short, default_value = "/lib/x86_64-linux-gnu/libc.so.6")]
    glibc: String,
    #[structopt(long, short)]
    /// pid to observe
    pid: Option<i32>,
}

fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    }

    Ok(())
}

fn get_symbol_address(so_path: &str, fn_name: &str) -> Result<usize> {
    let path = Path::new(so_path);
    let buffer = fs::read(path)?;
    let file = object::File::parse(buffer.as_slice())?;

    let mut symbols = file.dynamic_symbols();
    let symbol = symbols
        .find(|symbol| {
            if let Ok(name) = symbol.name() {
                return name == fn_name;
            }
            false
        })
        .ok_or(anyhow!("symbol not found"))?;

    Ok(symbol.address() as usize)
}

enum ParsedEvent {
    Ip(u32, Ipv4Addr),
    Host(u32, String),
}

fn parse_event(data: &[u8]) -> Result<ParsedEvent> {
    let mut event = Event::default();
    plain::copy_from_bytes(&mut event, data)
        .map_err(|_| anyhow!("could not parse event buffer"))?;
    let utf8_hostname = std::str::from_utf8(&event.hostname)?
        .trim_end_matches(char::from(0))
        .to_string();
    let ip_v4 = Ipv4Addr::from(event.ip);

    let parsed_event = match event.tag {
        1 => ParsedEvent::Host(event.pid, utf8_hostname),
        _ => ParsedEvent::Ip(event.pid, ip_v4),
    };

    Ok(parsed_event)
}

fn handle_event(_cpu: i32, data: &[u8]) {
    if let Ok(event) = parse_event(data) {
        let (pid, host, ip) = match event {
            ParsedEvent::Host(pid, host) => (format!("{}", pid), host, String::new()),
            ParsedEvent::Ip(pid, ip) => (format!("{}", pid), String::new(), format!("{}", ip)),
        };
        TRACECON_COLLECTOR
            .with_label_values(&[&pid, &host, &ip])
            .inc();
    }
}

fn main() -> Result<()> {
    let opts = Command::from_args();

    let mut skel_builder = TraceconSkelBuilder::default();
    if opts.verbose {
        skel_builder.obj_builder.debug(true);
    }

    bump_memlock_rlimit()?;
    let mut open_skel = skel_builder.open()?;
    if let Some(pid) = opts.pid {
        open_skel.rodata().target_pid = pid;
    }
    let mut skel = open_skel.load()?;
    let address = get_symbol_address(&opts.glibc, "getaddrinfo")?;

    let _uprobe =
        skel.progs_mut()
            .getaddrinfo_enter()
            .attach_uprobe(false, -1, &opts.glibc, address)?;

    let _uretprobe =
        skel.progs_mut()
            .getaddrinfo_exit()
            .attach_uprobe(true, -1, &opts.glibc, address)?;

    let _kprobe = skel
        .progs_mut()
        .tcp_v4_connect_enter()
        .attach_kprobe(false, "tcp_v4_connect")?;

    let _kretprobe = skel
        .progs_mut()
        .tcp_v4_connect_exit()
        .attach_kprobe(true, "tcp_v4_connect")?;

    let perf = PerfBufferBuilder::new(skel.maps_mut().events())
        .sample_cb(handle_event)
        .build()?;
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    let addr = "0.0.0.0:9184".parse()?;
    prometheus_exporter::start(addr)?;

    while running.load(Ordering::SeqCst) {
        perf.poll(Duration::from_millis(200))?;
    }

    Ok(())
}
