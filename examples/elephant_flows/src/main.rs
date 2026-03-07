mod utils;
mod datatypes;

use clap::Parser;
use datatypes::{ConnVolume, ConnVolumeCsvRow};
use iris_compiler::*;
use iris_core::{CoreId, FiveTuple};
use iris_core::{config::load_config, Runtime};
use iris_core::protocols::stream::Session;
use utils::*;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

const ELEPHANT_MIN_DURATION_SECS: u64 = 20;
const ELEPHANT_MIN_THROUGHPUT_BPS: u64 = 1_000_000; // 1 Mbps

pub(crate) static TOTAL_BYTES: AtomicU64 = AtomicU64::new(0);
pub(crate) static TOTAL_PAYLOAD_BYTES: AtomicU64 = AtomicU64::new(0);
pub(crate) static TOTAL_FLOWS: AtomicU64 = AtomicU64::new(0);
pub(crate) static TOTAL_PACKETS: AtomicU64 = AtomicU64::new(0);
pub(crate) static ELEPHANT_BYTES: AtomicU64 = AtomicU64::new(0);
pub(crate) static ELEPHANT_PAYLOAD_BYTES: AtomicU64 = AtomicU64::new(0);
pub(crate) static ELEPHANT_PACKETS: AtomicU64 = AtomicU64::new(0);
pub(crate) static ELEPHANT_FLOWS: AtomicU64 = AtomicU64::new(0);
pub(crate) static SCANNING_BYTES: AtomicU64 = AtomicU64::new(0);
pub(crate) static SCANNING_FLOWS: AtomicU64 = AtomicU64::new(0);

// CLI
#[derive(Parser, Debug)]
struct Args {
    #[clap(
        short,
        long,
        parse(from_os_str),
        value_name = "FILE",
        default_value = "./configs/offline.toml"
    )]
    config: PathBuf,
}

#[callback("tcp or udp,level=L4Terminated,parsers=http&tls&quic")]
fn conn_done(
    vol: &ConnVolume,
    session: &Session,
    ft: &FiveTuple,
    core_id: &CoreId,
) {
    {
        TOTAL_BYTES.fetch_add(vol.total_bytes as u64, Ordering::Relaxed);
        TOTAL_PAYLOAD_BYTES.fetch_add(vol.payload_bytes as u64, Ordering::Relaxed);
        TOTAL_FLOWS.fetch_add(1, Ordering::Relaxed);
        TOTAL_PACKETS.fetch_add(vol.packets, Ordering::Relaxed);
    }
    if vol.packets == 1 {
        SCANNING_BYTES.fetch_add(vol.total_bytes as u64, Ordering::Relaxed);
        SCANNING_FLOWS.fetch_add(1, Ordering::Relaxed);
        return;
    }

    if (vol.last_ts - vol.start_ts).as_secs() < ELEPHANT_MIN_DURATION_SECS ||
        vol.curr_throughput_bps() < ELEPHANT_MIN_THROUGHPUT_BPS
    {
        return;
    }

    ELEPHANT_BYTES.fetch_add(vol.total_bytes as u64, Ordering::Relaxed);
    ELEPHANT_PAYLOAD_BYTES.fetch_add(vol.payload_bytes as u64, Ordering::Relaxed);
    ELEPHANT_FLOWS.fetch_add(1, Ordering::Relaxed);
    ELEPHANT_PACKETS.fetch_add(vol.packets, Ordering::Relaxed);

    let features = ConnVolumeCsvRow::new(&vol, session, ft);
    write_row(&features, core_id);
}

#[input_files("$IRIS_HOME/datatypes/data.txt")]
#[iris_main]
fn main() {
    env_logger::init();
    let args = Args::parse();
    let config = load_config(&args.config);
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
    println!("Done running");
    combine_results();
    print_summary();
}

