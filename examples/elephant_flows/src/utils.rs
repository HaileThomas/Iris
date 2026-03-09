use iris_core::CoreId;
use publicsuffix::List;
use publicsuffix::Psl;
use serde::Serialize;
use std::net::IpAddr;
use once_cell::sync::Lazy;
use std::fs::File;
use std::io::BufWriter;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicPtr, Ordering};
use array_init::array_init;
use csv::Writer;

const NUM_CORES: usize = 32;
const ARR_LEN: usize = NUM_CORES + 1;
const OUTFILE_PREFIX: &str = "flow_features_";
const OUTFILE: &str = "flow_features.csv";


// Logging

static RESULTS: OnceLock<[AtomicPtr<Writer<BufWriter<File>>>; ARR_LEN]> = OnceLock::new();

pub(crate) fn results() -> &'static [AtomicPtr<Writer<BufWriter<File>>>; ARR_LEN] {
    RESULTS.get_or_init(|| {
        let mut ptrs = vec![];
        for core_id in 0..ARR_LEN {
            let path = format!("{}{}.csv", OUTFILE_PREFIX, core_id);
            let file = File::create(&path).unwrap();
            let buf_writer = BufWriter::new(file);
            let csv_writer = Writer::from_writer(buf_writer);
            ptrs.push(Box::into_raw(Box::new(csv_writer)));
        }
        array_init(|i| AtomicPtr::new(ptrs[i]))
    })
}

pub(crate) fn combine_results() {
    println!("Combining results from {} cores...", ARR_LEN);
    let mut output = Vec::new();

    let mut first_nonempty = true;
    for core_id in 1..ARR_LEN { // core 0 is monitoring core
        let ptr = results()[core_id].load(Ordering::Relaxed);
        let wtr = unsafe { &mut *ptr };
        wtr.flush().unwrap();

        let path = format!("{}{}.csv", OUTFILE_PREFIX, core_id);
        let content = std::fs::read(&path).unwrap();
        if content.is_empty() {
            std::fs::remove_file(&path).unwrap();
            continue;
        }
        if first_nonempty {
            output.extend_from_slice(&content);
            first_nonempty = false;
        } else {
            // skip csv header
            if let Some(idx) = content.iter().position(|&b| b == b'\n') {
                output.extend_from_slice(&content[idx + 1..]);
            }
        }
        std::fs::remove_file(&path).unwrap();
    }

    std::fs::write(OUTFILE, &output).unwrap();
    println!("Written to {}", OUTFILE);
}

pub(crate) fn write_row<T: Serialize>(row: &T, core_id: &CoreId) {
    let ptr = results()[core_id.raw() as usize].load(Ordering::Relaxed);
    let wtr = unsafe { &mut *ptr };
    wtr.serialize(row).unwrap();
}

// Summary stats

pub(crate) fn print_summary() {
    println!("Elephant flows: >= {}s and >= {} bytes",
             crate::ELEPHANT_MIN_DURATION_SECS, crate::ELEPHANT_MIN_THROUGHPUT_BPS);

    let total_bytes = crate::TOTAL_BYTES.load(Ordering::Relaxed);
    let total_payload_bytes = crate::TOTAL_PAYLOAD_BYTES.load(Ordering::Relaxed);
    let total_flows = crate::TOTAL_FLOWS.load(Ordering::Relaxed);
    let total_packets = crate::TOTAL_PACKETS.load(Ordering::Relaxed);
    let elephant_bytes = crate::ELEPHANT_BYTES.load(Ordering::Relaxed);
    let elephant_payload_bytes = crate::ELEPHANT_PAYLOAD_BYTES.load(Ordering::Relaxed);
    let elephant_flows = crate::ELEPHANT_FLOWS.load(Ordering::Relaxed);
    let elephant_packets = crate::ELEPHANT_PACKETS.load(Ordering::Relaxed);
    let scanning_bytes = crate::SCANNING_BYTES.load(Ordering::Relaxed);
    let scanning_flows = crate::SCANNING_FLOWS.load(Ordering::Relaxed);

    println!(
        "Elephant flows are {:.2}% of flows ({}/{})",
        (elephant_flows as f64 / total_flows as f64) * 100.0,
        elephant_flows,
        total_flows
    );

    println!(
        "Elephant flows are {:.2}% of total bytes ({}/{})",
        (elephant_bytes as f64 / total_bytes as f64) * 100.0,
        elephant_bytes,
        total_bytes
    );

    println!(
        "Elephant flows are {:.2}% of payload bytes ({}/{})",
        (elephant_payload_bytes as f64 / total_payload_bytes as f64) * 100.0,
        elephant_payload_bytes,
        total_payload_bytes
    );

    println!(
        "Elephant flow (TCP/UDP) payloads are {:.2}% of total bytes ({}/{})",
        (elephant_payload_bytes as f64 / total_bytes as f64) * 100.0,
        elephant_payload_bytes,
        total_bytes
    );

    println!(
        "Elephant flow packets are {:.2}% of total packets ({}/{})",
        (elephant_packets as f64 / total_packets as f64) * 100.0,
        elephant_packets,
        total_packets
    );

    println!(
        "Unanswered \'connections\' are {:.2}% of bytes ({}/{})",
        (scanning_bytes as f64 / total_bytes as f64) * 100.0,
        scanning_bytes,
        total_bytes
    );

    println!(
        "Unanswered \'connections\' are {:.2}% of flows ({}/{})",
        (scanning_flows as f64 / total_flows as f64) * 100.0,
        scanning_flows,
        total_flows
    );

    println!(
        "Unanswered \'connections\' are {:.2}% of packets ({}/{})",
        (scanning_flows as f64 / total_packets as f64) * 100.0,
        scanning_flows,
        total_packets
    );
}

// URL and IP prefix normalization

static PSL: Lazy<List> = Lazy::new(List::new);

pub(crate) fn normalize_uri(host: &str) -> Option<String> {
    // Lowercase and trim trailing dot
    let host = host.to_lowercase();
    let host = host.trim_end_matches('.');

    // Convert to bytes for the publicsuffix API
    let host_bytes = host.as_bytes();

    // PSL.domain returns an Option<Domain<'_>>
    if let Some(domain) = PSL.domain(host_bytes) {
        // Convert `domain` (which displays as the registrable domain) to String
        return Some(
            String::from_utf8(domain.as_bytes().to_vec()).unwrap_or_default()
        );
    }

    None
}

pub(crate) fn ip_to_prefix(ip: &IpAddr) -> u128 {
    match ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            // /24
            let prefix = u32::from_be_bytes([octets[0], octets[1], octets[2], 0]);
            prefix as u128
        }
        IpAddr::V6(ipv6) => {
            let octets = ipv6.octets();
            // /48
            let mut prefix_bytes = [0u8; 16];
            prefix_bytes[..6].copy_from_slice(&octets[..6]);
            u128::from_be_bytes(prefix_bytes)
        }
    }
}


