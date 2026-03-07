use crate::utils;
use iris_compiler::*;
use iris_core::{FiveTuple, L4Pdu, protocols::{packet::{tcp::TCP_PROTOCOL, udp::UDP_PROTOCOL}, stream::{Session, SessionData}}};

use std::{time::{Instant, SystemTime}};
use serde::Serialize;

#[derive(Debug, Clone)]
#[datatype("level=L4Terminated")]
pub struct ConnVolume {
    /// Connection start time
    pub start_ts: Instant,
    /// Last seen packet (becomes end time)
    pub last_ts: Instant,
    /// System time (for start/end timestamps)
    pub start_system_ts: SystemTime,
    /// Number of packets seen
    pub packets: u64,
    /// Number of payload bytes seen
    pub payload_bytes: u64,
    /// Number of total bytes seen (includes headers)
    pub total_bytes: u64,
    /// Number of payload bytes orig -> resp
    pub fwd_payload_bytes: u64,
    /// Number of payload bytes resp -> orig
    pub rev_payload_bytes: u64,
    /// Number of total bytes orig -> resp
    pub fwd_total_bytes: u64,
    /// Number of total bytes resp -> orig
    pub rev_total_bytes: u64,
    /// Number of packets orig -> resp
    pub fwd_pkts: u64,
    /// Number of packets resp -> orig
    pub rev_pkts: u64,
    /// Interarrival time sum (for "burstiness" est)
    pub iat_sum: u128,
    /// IAT sum of squares (for "burstiness" est)
    pub iat_sq_sum: u128,
}

impl ConnVolume {
    pub fn new(pdu: &L4Pdu) -> Self {
        let ts = pdu.ts;

        ConnVolume {
            start_ts: ts,
            last_ts: ts,
            start_system_ts: SystemTime::now(),
            packets: 0,
            payload_bytes: 0,
            total_bytes: 0,
            fwd_payload_bytes: 0,
            rev_payload_bytes: 0,
            fwd_total_bytes: 0,
            rev_total_bytes: 0,
            fwd_pkts: 0,
            rev_pkts: 0,
            iat_sum: 0,
            iat_sq_sum: 0,
        }
    }

    /// Update internal data with new packet
    #[datatype_group("ConnVolume,level=L4InPayload")]
    pub fn new_packet(&mut self, pdu: &L4Pdu) {
        let payload_bytes = pdu.length() as u64;
        let bytes = pdu.mbuf_ref().data_len() as u64;

        self.packets += 1;
        self.payload_bytes += payload_bytes;
        self.total_bytes += bytes;

        if pdu.dir {
            self.fwd_payload_bytes += payload_bytes;
            self.fwd_total_bytes += bytes;
            self.fwd_pkts += 1;
        } else {
            self.rev_payload_bytes += payload_bytes;
            self.rev_total_bytes += bytes;
            self.rev_pkts += 1;
        }

        if self.packets > 1 {
            let delta = (pdu.ts - self.last_ts).as_nanos();
            self.iat_sum += delta;
            self.iat_sq_sum += delta * delta;
        }

        self.last_ts = pdu.ts;
    }

    pub fn curr_throughput_bps(&self) -> u64 {
        let duration_secs = (self.last_ts - self.start_ts).as_secs();
        self.total_bytes.saturating_mul(8) / duration_secs
    }
}


/// Helper struct for serializing to CSV
#[derive(Serialize)]
pub(crate) struct ConnVolumeCsvRow {
    /// General data
    start_ts: f64,
    end_ts: f64,
    duration_secs: f64,
    packets: u64,
    payload_bytes: u64,
    fwd_payload_bytes: u64,
    rev_payload_bytes: u64,
    fwd_pkts: u64,
    rev_pkts: u64,
    upload_throughput_bps: f64,
    download_throughput_bps: f64,
    burst_coeff: f64,

    /// Five-tuple data
    transport: String, // TCP or UDP
    src_ip_subn: u128,
    dst_ip_subn: u128,
    src_port: u16,
    dst_port: u16,

    /// Application-layer protocol
    session_proto: Option<String>,
    /// TLS/QUIC SNI or HTTP host
    host: Option<String>,
    /// HTTP user-agent or TLS/QUIC client hello data
    client: Option<String>,
}

impl ConnVolumeCsvRow {
    pub(crate) fn new(raw: &ConnVolume,
           session: &Session,
           five_tuple: &FiveTuple
    ) -> Self {
        // Connection stuff
        let duration = raw.last_ts.duration_since(raw.start_ts);
        let duration_secs = duration.as_secs_f64();

        let start_ts = raw.start_system_ts
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();

        let end_ts = start_ts + duration_secs;

        let upload_throughput = if duration_secs > 0.0 {
            (raw.fwd_payload_bytes as f64 * 8.0) / duration_secs
        } else {
            0.0
        };

        let download_throughput = if duration_secs > 0.0 {
            (raw.rev_payload_bytes as f64 * 8.0) / duration_secs
        } else {
            0.0
        };
        let transport = match five_tuple.proto {
            TCP_PROTOCOL => "tcp",
            UDP_PROTOCOL => "udp",
            _ => "",
        };

        let burst_coeff = if raw.packets > 1 {
            let mean = raw.iat_sum as f64 / raw.packets as f64;
            let variance =
                (raw.iat_sq_sum as f64 / raw.packets as f64)
                - (mean * mean);
            if variance > 0.0 && mean > 0.0 {
                variance.sqrt() / mean
            } else {
                0.0
            }
        } else {
            0.0
        };

        let mut vol = ConnVolumeCsvRow {
            start_ts,
            end_ts,
            duration_secs,
            packets: raw.packets,
            payload_bytes: raw.payload_bytes,
            fwd_payload_bytes: raw.fwd_payload_bytes,
            rev_payload_bytes: raw.rev_payload_bytes,
            fwd_pkts: raw.fwd_pkts,
            rev_pkts: raw.rev_pkts,
            upload_throughput_bps: upload_throughput,
            download_throughput_bps: download_throughput,
            burst_coeff,
            src_ip_subn: utils::ip_to_prefix(&five_tuple.orig.ip()),
            dst_ip_subn: utils::ip_to_prefix(&five_tuple.resp.ip()),
            src_port: five_tuple.orig.port(),
            dst_port: five_tuple.resp.port(),
            transport: transport.into(),
            session_proto: None,
            host: None,
            client: None,
        };
        vol.add_session(session);
        vol
    }

    fn add_session(&mut self, session: &Session) {
        // Populate session data
        match &session.data {
            SessionData::Tls(tls) => {
                let sni = tls.sni();
                if !sni.is_empty() {
                    self.host = utils::normalize_uri(sni);
                }
                self.client = Some(tls.ja3_str());
                self.session_proto = Some("tls".into());
            },
            SessionData::Http(http) => {
                let host = http.host();
                if !host.is_empty() {
                    self.host = utils::normalize_uri(host);
                }
                let ua = http.user_agent();
                if !ua.is_empty() {
                    self.client = Some(ua.into());
                }
                self.session_proto = Some("http".into());
            },
            SessionData::Quic(quic) => {
                let sni = quic.tls.sni();
                if !sni.is_empty() {
                    self.host = utils::normalize_uri(sni);
                }
                self.client = Some(quic.tls.ja3_str());
                self.session_proto = Some("quic".into());
            },
            _ => {},
        }
    }
}