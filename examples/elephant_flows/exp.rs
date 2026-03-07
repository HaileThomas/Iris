Parsed datatype: ConnDuration
Caching input in memory
Parsed datatype function: update
Caching input in memory
Parsed datatype: PktCount
Caching input in memory
Parsed datatype function: update
Caching input in memory
Parsed datatype: ByteCount
Caching input in memory
Parsed datatype function: update
Caching input in memory
Parsed datatype: InterArrivals
Caching input in memory
Parsed datatype function: update
Caching input in memory
Parsed datatype: ConnHistory
Caching input in memory
Parsed datatype function: update
Caching input in memory
Parsed datatype: ConnRecord
Caching input in memory
Parsed datatype function: update
Caching input in memory
Parsed datatype: DnsTransaction
Caching input in memory
Parsed datatype function: from_session
Caching input in memory
Parsed datatype: HttpTransaction
Caching input in memory
Parsed datatype function: from_session
Caching input in memory
Parsed datatype: BidirPktStream
Caching input in memory
Parsed datatype function: update
Caching input in memory
Parsed datatype: OrigPktStream
Caching input in memory
Parsed datatype function: update
Caching input in memory
Parsed datatype: RespPktStream
Caching input in memory
Parsed datatype function: update
Caching input in memory
Parsed datatype: ZcFrame
Caching input in memory
Parsed datatype function: new
Caching input in memory
Parsed datatype: Payload
Caching input in memory
Parsed datatype function: new
Caching input in memory
Parsed datatype: QuicStream
Caching input in memory
Parsed datatype function: from_session
Caching input in memory
Parsed datatype: SshHandshake
Caching input in memory
Parsed datatype function: from_session
Caching input in memory
Parsed datatype: FiveTuple
Caching input in memory
Parsed datatype: AnonFiveTuple
Caching input in memory
Parsed datatype: ClearedFiveTuple
Caching input in memory
Parsed datatype: StartTime
Caching input in memory
Parsed datatype: EtherTCI
Caching input in memory
Parsed datatype: EthAddr
Caching input in memory
Parsed datatype: TlsHandshake
Caching input in memory
Parsed datatype function: from_session
Caching input in memory
Warning - clearing existing contents of file /home/tcr6/iris/datatypes/data.txt
GOT OUTPUT FILE NAME: /home/tcr6/iris/datatypes/data.txt
Parsed datatype: ConnVolume
Caching input in memory
Parsed datatype function: new_packet
Caching input in memory
Parsed callback: "conn_done"
Caching input in memory
Done with macros - beginning code generation

Parsers: tls, http, quic

Tree Per-Packet:
`- ethernet (0)
   |- ipv4 (1)
   |  |- tcp (2)
   |  `- udp (3)
   `- ipv6 (4)
      |- tcp (5)
      `- udp (6)

Tree L4FirstPacket
,`- 0: ethernet
   |- 1: ipv4
   |  |- 2: tcp -- Actions: L4: Actions[Update, PassThrough, Track] (Until:  L7EndHdrs: Actions[PassThrough], L4Terminated: Actions[Update, PassThrough, Track]) L7: Actions[Parse] (Until:  L7EndHdrs: Actions[Parse], L4Terminated: Actions[Parse])
   |  `- 3: udp -- Actions: L4: Actions[Update, PassThrough, Track] (Until:  L7EndHdrs: Actions[PassThrough], L4Terminated: Actions[Update, PassThrough, Track]) L7: Actions[Parse] (Until:  L7EndHdrs: Actions[Parse], L4Terminated: Actions[Parse]) x
   `- 4: ipv6 x
      |- 5: tcp -- Actions: L4: Actions[Update, PassThrough, Track] (Until:  L7EndHdrs: Actions[PassThrough], L4Terminated: Actions[Update, PassThrough, Track]) L7: Actions[Parse] (Until:  L7EndHdrs: Actions[Parse], L4Terminated: Actions[Parse])
      `- 6: udp -- Actions: L4: Actions[Update, PassThrough, Track] (Until:  L7EndHdrs: Actions[PassThrough], L4Terminated: Actions[Update, PassThrough, Track]) L7: Actions[Parse] (Until:  L7EndHdrs: Actions[Parse], L4Terminated: Actions[Parse]) x

Tree L4InPayload(false)
,`- 0: ethernet
   |- 1: tcp -- Actions: L4: Actions[Update, Track] (Until:  L4Terminated: Actions[Update, Track]) L7: None
   |  |- 2: L7=Discovery -- Actions: L4: Actions[PassThrough] (Until:  L7EndHdrs: Actions[PassThrough], L4Terminated: Actions[PassThrough]) L7: Actions[Parse] (Until:  L7EndHdrs: Actions[Parse], L4Terminated: Actions[Parse])
   |  `- 3: L7=Headers -- Actions: L4: Actions[PassThrough] (Until:  L7EndHdrs: Actions[PassThrough], L4Terminated: Actions[PassThrough]) L7: Actions[Parse] (Until:  L7EndHdrs: Actions[Parse], L4Terminated: Actions[Parse])
   `- 4: udp -- Actions: L4: Actions[Update, Track] (Until:  L4Terminated: Actions[Update, Track]) L7: None x
      |- 5: L7=Discovery -- Actions: L4: Actions[PassThrough] (Until:  L7EndHdrs: Actions[PassThrough], L4Terminated: Actions[PassThrough]) L7: Actions[Parse] (Until:  L7EndHdrs: Actions[Parse], L4Terminated: Actions[Parse])
      `- 6: L7=Headers -- Actions: L4: Actions[PassThrough] (Until:  L7EndHdrs: Actions[PassThrough], L4Terminated: Actions[PassThrough]) L7: Actions[Parse] (Until:  L7EndHdrs: Actions[Parse], L4Terminated: Actions[Parse])

Tree L7EndHdrs
,`- 0: ethernet
   |- 1: tcp -- Actions: L4: Actions[Update, Track] (Until:  L4Terminated: Actions[Update, Track]) L7: None
   `- 2: udp -- Actions: L4: Actions[Update, Track] (Until:  L4Terminated: Actions[Update, Track]) L7: None x

Tree L4Terminated
,`- 0: ethernet Invoke: ( conn_done, )

#![feature(prelude_import)]
extern crate std;
#[prelude_import]
use std::prelude::rust_2024::*;
mod utils {
    use publicsuffix::List;
    use publicsuffix::Psl;
    use std::net::IpAddr;
    use once_cell::sync::Lazy;
    static PSL: Lazy<List> = Lazy::new(List::new);
    pub(crate) fn normalize_uri(host: &str) -> Option<String> {
        let host = host.to_lowercase();
        let host = host.trim_end_matches('.');
        let host_bytes = host.as_bytes();
        if let Some(domain) = PSL.domain(host_bytes) {
            return Some(
                String::from_utf8(domain.as_bytes().to_vec()).unwrap_or_default(),
            );
        }
        None
    }
    pub(crate) fn ip_to_prefix(ip: &IpAddr) -> u128 {
        match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                let prefix = u32::from_be_bytes([octets[0], octets[1], octets[2], 0]);
                prefix as u128
            }
            IpAddr::V6(ipv6) => {
                let octets = ipv6.octets();
                let mut prefix_bytes = [0u8; 16];
                prefix_bytes[..6].copy_from_slice(&octets[..6]);
                u128::from_be_bytes(prefix_bytes)
            }
        }
    }
}
mod datatypes {
    use crate::utils;
    use iris_compiler::*;
    use iris_core::{
        FiveTuple, L4Pdu,
        protocols::{
            packet::{tcp::TCP_PROTOCOL, udp::UDP_PROTOCOL},
            stream::{Session, SessionData},
        },
    };
    use std::time::{Instant, SystemTime};
    use serde::Serialize;
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
    #[automatically_derived]
    impl ::core::fmt::Debug for ConnVolume {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            let names: &'static _ = &[
                "start_ts",
                "last_ts",
                "start_system_ts",
                "packets",
                "payload_bytes",
                "total_bytes",
                "fwd_payload_bytes",
                "rev_payload_bytes",
                "fwd_total_bytes",
                "rev_total_bytes",
                "fwd_pkts",
                "rev_pkts",
                "iat_sum",
                "iat_sq_sum",
            ];
            let values: &[&dyn ::core::fmt::Debug] = &[
                &self.start_ts,
                &self.last_ts,
                &self.start_system_ts,
                &self.packets,
                &self.payload_bytes,
                &self.total_bytes,
                &self.fwd_payload_bytes,
                &self.rev_payload_bytes,
                &self.fwd_total_bytes,
                &self.rev_total_bytes,
                &self.fwd_pkts,
                &self.rev_pkts,
                &self.iat_sum,
                &&self.iat_sq_sum,
            ];
            ::core::fmt::Formatter::debug_struct_fields_finish(
                f,
                "ConnVolume",
                names,
                values,
            )
        }
    }
    #[automatically_derived]
    impl ::core::clone::Clone for ConnVolume {
        #[inline]
        fn clone(&self) -> ConnVolume {
            ConnVolume {
                start_ts: ::core::clone::Clone::clone(&self.start_ts),
                last_ts: ::core::clone::Clone::clone(&self.last_ts),
                start_system_ts: ::core::clone::Clone::clone(&self.start_system_ts),
                packets: ::core::clone::Clone::clone(&self.packets),
                payload_bytes: ::core::clone::Clone::clone(&self.payload_bytes),
                total_bytes: ::core::clone::Clone::clone(&self.total_bytes),
                fwd_payload_bytes: ::core::clone::Clone::clone(&self.fwd_payload_bytes),
                rev_payload_bytes: ::core::clone::Clone::clone(&self.rev_payload_bytes),
                fwd_total_bytes: ::core::clone::Clone::clone(&self.fwd_total_bytes),
                rev_total_bytes: ::core::clone::Clone::clone(&self.rev_total_bytes),
                fwd_pkts: ::core::clone::Clone::clone(&self.fwd_pkts),
                rev_pkts: ::core::clone::Clone::clone(&self.rev_pkts),
                iat_sum: ::core::clone::Clone::clone(&self.iat_sum),
                iat_sq_sum: ::core::clone::Clone::clone(&self.iat_sq_sum),
            }
        }
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
    struct ConnVolumeCsvRow {
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
        transport: String,
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
    #[doc(hidden)]
    #[allow(
        non_upper_case_globals,
        unused_attributes,
        unused_qualifications,
        clippy::absolute_paths,
    )]
    const _: () = {
        #[allow(unused_extern_crates, clippy::useless_attribute)]
        extern crate serde as _serde;
        #[automatically_derived]
        impl _serde::Serialize for ConnVolumeCsvRow {
            fn serialize<__S>(
                &self,
                __serializer: __S,
            ) -> _serde::__private::Result<__S::Ok, __S::Error>
            where
                __S: _serde::Serializer,
            {
                let mut __serde_state = _serde::Serializer::serialize_struct(
                    __serializer,
                    "ConnVolumeCsvRow",
                    false as usize + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 1
                        + 1 + 1 + 1 + 1 + 1 + 1 + 1,
                )?;
                _serde::ser::SerializeStruct::serialize_field(
                    &mut __serde_state,
                    "start_ts",
                    &self.start_ts,
                )?;
                _serde::ser::SerializeStruct::serialize_field(
                    &mut __serde_state,
                    "end_ts",
                    &self.end_ts,
                )?;
                _serde::ser::SerializeStruct::serialize_field(
                    &mut __serde_state,
                    "duration_secs",
                    &self.duration_secs,
                )?;
                _serde::ser::SerializeStruct::serialize_field(
                    &mut __serde_state,
                    "packets",
                    &self.packets,
                )?;
                _serde::ser::SerializeStruct::serialize_field(
                    &mut __serde_state,
                    "payload_bytes",
                    &self.payload_bytes,
                )?;
                _serde::ser::SerializeStruct::serialize_field(
                    &mut __serde_state,
                    "fwd_payload_bytes",
                    &self.fwd_payload_bytes,
                )?;
                _serde::ser::SerializeStruct::serialize_field(
                    &mut __serde_state,
                    "rev_payload_bytes",
                    &self.rev_payload_bytes,
                )?;
                _serde::ser::SerializeStruct::serialize_field(
                    &mut __serde_state,
                    "fwd_pkts",
                    &self.fwd_pkts,
                )?;
                _serde::ser::SerializeStruct::serialize_field(
                    &mut __serde_state,
                    "rev_pkts",
                    &self.rev_pkts,
                )?;
                _serde::ser::SerializeStruct::serialize_field(
                    &mut __serde_state,
                    "upload_throughput_bps",
                    &self.upload_throughput_bps,
                )?;
                _serde::ser::SerializeStruct::serialize_field(
                    &mut __serde_state,
                    "download_throughput_bps",
                    &self.download_throughput_bps,
                )?;
                _serde::ser::SerializeStruct::serialize_field(
                    &mut __serde_state,
                    "burst_coeff",
                    &self.burst_coeff,
                )?;
                _serde::ser::SerializeStruct::serialize_field(
                    &mut __serde_state,
                    "transport",
                    &self.transport,
                )?;
                _serde::ser::SerializeStruct::serialize_field(
                    &mut __serde_state,
                    "src_ip_subn",
                    &self.src_ip_subn,
                )?;
                _serde::ser::SerializeStruct::serialize_field(
                    &mut __serde_state,
                    "dst_ip_subn",
                    &self.dst_ip_subn,
                )?;
                _serde::ser::SerializeStruct::serialize_field(
                    &mut __serde_state,
                    "src_port",
                    &self.src_port,
                )?;
                _serde::ser::SerializeStruct::serialize_field(
                    &mut __serde_state,
                    "dst_port",
                    &self.dst_port,
                )?;
                _serde::ser::SerializeStruct::serialize_field(
                    &mut __serde_state,
                    "session_proto",
                    &self.session_proto,
                )?;
                _serde::ser::SerializeStruct::serialize_field(
                    &mut __serde_state,
                    "host",
                    &self.host,
                )?;
                _serde::ser::SerializeStruct::serialize_field(
                    &mut __serde_state,
                    "client",
                    &self.client,
                )?;
                _serde::ser::SerializeStruct::end(__serde_state)
            }
        }
    };
    impl ConnVolumeCsvRow {
        fn new(
            raw: &ConnVolume,
            session: &Option<Session>,
            five_tuple: &FiveTuple,
        ) -> Self {
            let duration = raw.last_ts.duration_since(raw.start_ts);
            let duration_secs = duration.as_secs_f64();
            let start_ts = raw
                .start_system_ts
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
                let variance = (raw.iat_sq_sum as f64 / raw.packets as f64)
                    - (mean * mean);
                if variance > 0.0 && mean > 0.0 { variance.sqrt() / mean } else { 0.0 }
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
        fn add_session(&mut self, session: &Option<Session>) {
            match session {
                Some(session) => {
                    match &session.data {
                        SessionData::Tls(tls) => {
                            let sni = tls.sni();
                            if !sni.is_empty() {
                                self.host = utils::normalize_uri(sni);
                            }
                            self.client = Some(tls.ja3_str());
                            self.session_proto = Some("tls".into());
                        }
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
                        }
                        SessionData::Quic(quic) => {
                            let sni = quic.tls.sni();
                            if !sni.is_empty() {
                                self.host = utils::normalize_uri(sni);
                            }
                            self.client = Some(quic.tls.ja3_str());
                            self.session_proto = Some("quic".into());
                        }
                        _ => {}
                    }
                }
                None => {}
            }
        }
    }
}
use clap::Parser;
use datatypes::ConnVolume;
use iris_compiler::*;
use iris_core::{config::load_config, Runtime};
use std::path::PathBuf;
use std::{fs::File, sync::Mutex};
use std::io::{BufWriter, Write};
use std::collections::HashMap;
use iris_core::protocols::stream::Session;
use once_cell::sync::Lazy;
const ELEPHANT_MIN_DURATION_SECS: u64 = 20;
const ELEPHANT_MIN_THROUGHPUT_BPS: u64 = 1_000_000;
static TOTAL_BYTES: Lazy<Mutex<u128>> = Lazy::new(|| Mutex::new(0));
static TOTAL_PAYLOAD_BYTES: Lazy<Mutex<u128>> = Lazy::new(|| Mutex::new(0));
static ELEPHANT_BYTES: Lazy<Mutex<u128>> = Lazy::new(|| Mutex::new(0));
static ELEPHANT_PAYLOAD_BYTES: Lazy<Mutex<u128>> = Lazy::new(|| Mutex::new(0));
static SCANNING_BYTES: Lazy<Mutex<u128>> = Lazy::new(|| Mutex::new(0));
struct Args {
    #[clap(
        short,
        long,
        parse(from_os_str),
        value_name = "FILE",
        default_value = "./configs/offline.toml"
    )]
    config: PathBuf,
    #[clap(short = 'o', long, parse(from_os_str), default_value = "./hists")]
    out_dir: PathBuf,
}
impl clap::Parser for Args {}
#[allow(dead_code, unreachable_code, unused_variables, unused_braces)]
#[allow(
    clippy::style,
    clippy::complexity,
    clippy::pedantic,
    clippy::restriction,
    clippy::perf,
    clippy::deprecated,
    clippy::nursery,
    clippy::cargo,
    clippy::suspicious_else_formatting,
    clippy::almost_swapped,
)]
#[allow(deprecated)]
impl clap::CommandFactory for Args {
    fn into_app<'b>() -> clap::Command<'b> {
        let __clap_app = clap::Command::new("elephant_flows");
        <Self as clap::Args>::augment_args(__clap_app)
    }
    fn into_app_for_update<'b>() -> clap::Command<'b> {
        let __clap_app = clap::Command::new("elephant_flows");
        <Self as clap::Args>::augment_args_for_update(__clap_app)
    }
}
#[allow(dead_code, unreachable_code, unused_variables, unused_braces)]
#[allow(
    clippy::style,
    clippy::complexity,
    clippy::pedantic,
    clippy::restriction,
    clippy::perf,
    clippy::deprecated,
    clippy::nursery,
    clippy::cargo,
    clippy::suspicious_else_formatting,
    clippy::almost_swapped,
)]
impl clap::FromArgMatches for Args {
    fn from_arg_matches(
        __clap_arg_matches: &clap::ArgMatches,
    ) -> ::std::result::Result<Self, clap::Error> {
        Self::from_arg_matches_mut(&mut __clap_arg_matches.clone())
    }
    fn from_arg_matches_mut(
        __clap_arg_matches: &mut clap::ArgMatches,
    ) -> ::std::result::Result<Self, clap::Error> {
        #![allow(deprecated)]
        let v = Args {
            config: __clap_arg_matches
                .get_one::<::std::ffi::OsString>("config")
                .map(|s| ::std::ops::Deref::deref(s))
                .ok_or_else(|| clap::Error::raw(
                    clap::ErrorKind::MissingRequiredArgument,
                    ::alloc::__export::must_use({
                        ::alloc::fmt::format(
                            format_args!(
                                "The following required argument was not provided: {0}",
                                "config",
                            ),
                        )
                    }),
                ))
                .and_then(|s| ::std::result::Result::Ok::<
                    _,
                    clap::Error,
                >(::std::convert::From::from(s)))?,
            out_dir: __clap_arg_matches
                .get_one::<::std::ffi::OsString>("out-dir")
                .map(|s| ::std::ops::Deref::deref(s))
                .ok_or_else(|| clap::Error::raw(
                    clap::ErrorKind::MissingRequiredArgument,
                    ::alloc::__export::must_use({
                        ::alloc::fmt::format(
                            format_args!(
                                "The following required argument was not provided: {0}",
                                "out-dir",
                            ),
                        )
                    }),
                ))
                .and_then(|s| ::std::result::Result::Ok::<
                    _,
                    clap::Error,
                >(::std::convert::From::from(s)))?,
        };
        ::std::result::Result::Ok(v)
    }
    fn update_from_arg_matches(
        &mut self,
        __clap_arg_matches: &clap::ArgMatches,
    ) -> ::std::result::Result<(), clap::Error> {
        self.update_from_arg_matches_mut(&mut __clap_arg_matches.clone())
    }
    fn update_from_arg_matches_mut(
        &mut self,
        __clap_arg_matches: &mut clap::ArgMatches,
    ) -> ::std::result::Result<(), clap::Error> {
        #![allow(deprecated)]
        if __clap_arg_matches.contains_id("config") {
            #[allow(non_snake_case)]
            let config = &mut self.config;
            *config = __clap_arg_matches
                .get_one::<::std::ffi::OsString>("config")
                .map(|s| ::std::ops::Deref::deref(s))
                .ok_or_else(|| clap::Error::raw(
                    clap::ErrorKind::MissingRequiredArgument,
                    ::alloc::__export::must_use({
                        ::alloc::fmt::format(
                            format_args!(
                                "The following required argument was not provided: {0}",
                                "config",
                            ),
                        )
                    }),
                ))
                .and_then(|s| ::std::result::Result::Ok::<
                    _,
                    clap::Error,
                >(::std::convert::From::from(s)))?;
        }
        if __clap_arg_matches.contains_id("out-dir") {
            #[allow(non_snake_case)]
            let out_dir = &mut self.out_dir;
            *out_dir = __clap_arg_matches
                .get_one::<::std::ffi::OsString>("out-dir")
                .map(|s| ::std::ops::Deref::deref(s))
                .ok_or_else(|| clap::Error::raw(
                    clap::ErrorKind::MissingRequiredArgument,
                    ::alloc::__export::must_use({
                        ::alloc::fmt::format(
                            format_args!(
                                "The following required argument was not provided: {0}",
                                "out-dir",
                            ),
                        )
                    }),
                ))
                .and_then(|s| ::std::result::Result::Ok::<
                    _,
                    clap::Error,
                >(::std::convert::From::from(s)))?;
        }
        ::std::result::Result::Ok(())
    }
}
#[allow(dead_code, unreachable_code, unused_variables, unused_braces)]
#[allow(
    clippy::style,
    clippy::complexity,
    clippy::pedantic,
    clippy::restriction,
    clippy::perf,
    clippy::deprecated,
    clippy::nursery,
    clippy::cargo,
    clippy::suspicious_else_formatting,
    clippy::almost_swapped,
)]
impl clap::Args for Args {
    fn augment_args<'b>(__clap_app: clap::Command<'b>) -> clap::Command<'b> {
        {
            let __clap_app = __clap_app;
            let __clap_app = __clap_app
                .arg({
                    #[allow(deprecated)]
                    let arg = clap::Arg::new("config")
                        .takes_value(true)
                        .value_name("CONFIG")
                        .required(false && clap::ArgAction::StoreValue.takes_values())
                        .value_parser(clap::builder::ValueParser::os_string())
                        .action(clap::ArgAction::StoreValue);
                    let arg = arg
                        .short('c')
                        .long("config")
                        .value_name("FILE")
                        .default_value("./configs/offline.toml");
                    arg
                });
            let __clap_app = __clap_app
                .arg({
                    #[allow(deprecated)]
                    let arg = clap::Arg::new("out-dir")
                        .takes_value(true)
                        .value_name("OUT_DIR")
                        .required(false && clap::ArgAction::StoreValue.takes_values())
                        .value_parser(clap::builder::ValueParser::os_string())
                        .action(clap::ArgAction::StoreValue);
                    let arg = arg.short('o').long("out-dir").default_value("./hists");
                    arg
                });
            __clap_app
        }
    }
    fn augment_args_for_update<'b>(__clap_app: clap::Command<'b>) -> clap::Command<'b> {
        {
            let __clap_app = __clap_app;
            let __clap_app = __clap_app
                .arg({
                    #[allow(deprecated)]
                    let arg = clap::Arg::new("config")
                        .takes_value(true)
                        .value_name("CONFIG")
                        .required(false && clap::ArgAction::StoreValue.takes_values())
                        .value_parser(clap::builder::ValueParser::os_string())
                        .action(clap::ArgAction::StoreValue);
                    let arg = arg
                        .short('c')
                        .long("config")
                        .value_name("FILE")
                        .default_value("./configs/offline.toml");
                    arg
                });
            let __clap_app = __clap_app
                .arg({
                    #[allow(deprecated)]
                    let arg = clap::Arg::new("out-dir")
                        .takes_value(true)
                        .value_name("OUT_DIR")
                        .required(false && clap::ArgAction::StoreValue.takes_values())
                        .value_parser(clap::builder::ValueParser::os_string())
                        .action(clap::ArgAction::StoreValue);
                    let arg = arg.short('o').long("out-dir").default_value("./hists");
                    arg
                });
            __clap_app
        }
    }
}
#[automatically_derived]
impl ::core::fmt::Debug for Args {
    #[inline]
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        ::core::fmt::Formatter::debug_struct_field2_finish(
            f,
            "Args",
            "config",
            &self.config,
            "out_dir",
            &&self.out_dir,
        )
    }
}
fn conn_done(vol: &ConnVolume, session: &Session) {
    {
        *TOTAL_BYTES.lock().unwrap() += vol.total_bytes as u128;
        *TOTAL_PAYLOAD_BYTES.lock().unwrap() += vol.payload_bytes as u128;
    }
    if (vol.last_ts - vol.start_ts).as_secs() < ELEPHANT_MIN_DURATION_SECS
        || vol.curr_throughput_bps() < ELEPHANT_MIN_THROUGHPUT_BPS
    {
        return;
    }
}
use iris_core::subscription::{Trackable, Subscribable};
use iris_core::conntrack::{TrackedActions, ConnInfo};
use iris_core::protocols::stream::ParserRegistry;
use iris_core::StateTransition;
use iris_core::subscription::*;
use iris_datatypes::*;
pub struct SubscribedWrapper;
impl Subscribable for SubscribedWrapper {
    type Tracked = TrackedWrapper;
}
pub struct TrackedWrapper {
    packets: Vec<iris_core::Mbuf>,
    core_id: iris_core::CoreId,
    connvolume: ConnVolume,
}
impl Trackable for TrackedWrapper {
    type Subscribed = SubscribedWrapper;
    fn new(first_pkt: &iris_core::L4Pdu, core_id: iris_core::CoreId) -> Self {
        Self {
            packets: Vec::new(),
            core_id,
            connvolume: ConnVolume::new(first_pkt),
        }
    }
    fn packets(&self) -> &Vec<iris_core::Mbuf> {
        &self.packets
    }
    fn core_id(&self) -> &iris_core::CoreId {
        &self.core_id
    }
    fn parsers() -> ParserRegistry {
        ParserRegistry::from_strings(Vec::from(["tls", "http", "quic"]))
    }
    fn clear(&mut self) {
        self.packets.clear();
    }
}
pub fn filter() -> iris_core::filter::FilterFactory<TrackedWrapper> {
    fn packet_filter(mbuf: &iris_core::Mbuf, core_id: &iris_core::CoreId) -> bool {
        if let Ok(ethernet) = &iris_core::protocols::packet::Packet::parse_to::<
            iris_core::protocols::packet::ethernet::Ethernet,
        >(mbuf) {
            if let Ok(ipv4) = &iris_core::protocols::packet::Packet::parse_to::<
                iris_core::protocols::packet::ipv4::Ipv4,
            >(ethernet) {
                if let Ok(tcp) = &iris_core::protocols::packet::Packet::parse_to::<
                    iris_core::protocols::packet::tcp::Tcp,
                >(ipv4) {
                    return true;
                } else if let Ok(udp) = &iris_core::protocols::packet::Packet::parse_to::<
                    iris_core::protocols::packet::udp::Udp,
                >(ipv4) {
                    return true;
                }
            } else if let Ok(ipv6) = &iris_core::protocols::packet::Packet::parse_to::<
                iris_core::protocols::packet::ipv6::Ipv6,
            >(ethernet) {
                if let Ok(tcp) = &iris_core::protocols::packet::Packet::parse_to::<
                    iris_core::protocols::packet::tcp::Tcp,
                >(ipv6) {
                    return true;
                } else if let Ok(udp) = &iris_core::protocols::packet::Packet::parse_to::<
                    iris_core::protocols::packet::udp::Udp,
                >(ipv6) {
                    return true;
                }
            }
            return false;
        }
        false
    }
    fn state_tx(conn: &mut ConnInfo<TrackedWrapper>, tx: &iris_core::StateTransition) {
        match tx {
            StateTransition::L4FirstPacket => tx_l4firstpacket(conn, &tx),
            StateTransition::L4InPayload(_) => tx_l4inpayload(conn, &tx),
            StateTransition::L7EndHdrs => tx_l7endhdrs(conn, &tx),
            StateTransition::L4Terminated => tx_l4terminated(conn, &tx),
            _ => {}
        }
    }
    fn tx_l4firstpacket(conn: &mut ConnInfo<TrackedWrapper>, tx: &StateTransition) {
        let mut ret = false;
        let tx = iris_core::StateTxData::from_tx(tx, &conn.layers[0]);
        let mut transport_actions = iris_core::conntrack::TrackedActions::new();
        let mut layer0_actions = iris_core::conntrack::TrackedActions::new();
        if let Ok(ipv4) = &iris_core::protocols::stream::ConnData::parse_to::<
            iris_core::protocols::stream::conn::Ipv4CData,
        >(&conn.cdata) {
            if let Ok(tcp) = &iris_core::protocols::stream::ConnData::parse_to::<
                iris_core::protocols::stream::conn::TcpCData,
            >(&conn.cdata) {
                transport_actions
                    .extend(
                        &TrackedActions {
                            active: iris_core::conntrack::Actions::from(13),
                            refresh_at: [
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(4),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(13),
                            ],
                        },
                    );
                layer0_actions
                    .extend(
                        &TrackedActions {
                            active: iris_core::conntrack::Actions::from(2),
                            refresh_at: [
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(2),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(2),
                            ],
                        },
                    );
            } else if let Ok(udp) = &iris_core::protocols::stream::ConnData::parse_to::<
                iris_core::protocols::stream::conn::UdpCData,
            >(&conn.cdata) {
                transport_actions
                    .extend(
                        &TrackedActions {
                            active: iris_core::conntrack::Actions::from(13),
                            refresh_at: [
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(4),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(13),
                            ],
                        },
                    );
                layer0_actions
                    .extend(
                        &TrackedActions {
                            active: iris_core::conntrack::Actions::from(2),
                            refresh_at: [
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(2),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(2),
                            ],
                        },
                    );
            }
        } else if let Ok(ipv6) = &iris_core::protocols::stream::ConnData::parse_to::<
            iris_core::protocols::stream::conn::Ipv6CData,
        >(&conn.cdata) {
            if let Ok(tcp) = &iris_core::protocols::stream::ConnData::parse_to::<
                iris_core::protocols::stream::conn::TcpCData,
            >(&conn.cdata) {
                transport_actions
                    .extend(
                        &TrackedActions {
                            active: iris_core::conntrack::Actions::from(13),
                            refresh_at: [
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(4),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(13),
                            ],
                        },
                    );
                layer0_actions
                    .extend(
                        &TrackedActions {
                            active: iris_core::conntrack::Actions::from(2),
                            refresh_at: [
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(2),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(2),
                            ],
                        },
                    );
            } else if let Ok(udp) = &iris_core::protocols::stream::ConnData::parse_to::<
                iris_core::protocols::stream::conn::UdpCData,
            >(&conn.cdata) {
                transport_actions
                    .extend(
                        &TrackedActions {
                            active: iris_core::conntrack::Actions::from(13),
                            refresh_at: [
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(4),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(13),
                            ],
                        },
                    );
                layer0_actions
                    .extend(
                        &TrackedActions {
                            active: iris_core::conntrack::Actions::from(2),
                            refresh_at: [
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(2),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(2),
                            ],
                        },
                    );
            }
        }
        conn.linfo.actions.extend(&transport_actions);
        conn.layers[0].extend_actions(&layer0_actions);
    }
    fn tx_l4inpayload(conn: &mut ConnInfo<TrackedWrapper>, tx: &StateTransition) {
        let mut ret = false;
        let tx = iris_core::StateTxData::from_tx(tx, &conn.layers[0]);
        let mut transport_actions = iris_core::conntrack::TrackedActions::new();
        let mut layer0_actions = iris_core::conntrack::TrackedActions::new();
        if let Ok(tcp) = &iris_core::protocols::stream::ConnData::parse_to::<
            iris_core::protocols::stream::conn::TcpCData,
        >(&conn.cdata) {
            if conn.layers[0].layer_info().state
                == iris_core::conntrack::LayerState::Discovery
            {
                transport_actions
                    .extend(
                        &TrackedActions {
                            active: iris_core::conntrack::Actions::from(4),
                            refresh_at: [
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(4),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(4),
                            ],
                        },
                    );
                layer0_actions
                    .extend(
                        &TrackedActions {
                            active: iris_core::conntrack::Actions::from(2),
                            refresh_at: [
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(2),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(2),
                            ],
                        },
                    );
            }
            if conn.layers[0].layer_info().state
                == iris_core::conntrack::LayerState::Headers
            {
                transport_actions
                    .extend(
                        &TrackedActions {
                            active: iris_core::conntrack::Actions::from(4),
                            refresh_at: [
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(4),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(4),
                            ],
                        },
                    );
                layer0_actions
                    .extend(
                        &TrackedActions {
                            active: iris_core::conntrack::Actions::from(2),
                            refresh_at: [
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(2),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(2),
                            ],
                        },
                    );
            }
            transport_actions
                .extend(
                    &TrackedActions {
                        active: iris_core::conntrack::Actions::from(9),
                        refresh_at: [
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(9),
                        ],
                    },
                );
        } else if let Ok(udp) = &iris_core::protocols::stream::ConnData::parse_to::<
            iris_core::protocols::stream::conn::UdpCData,
        >(&conn.cdata) {
            if conn.layers[0].layer_info().state
                == iris_core::conntrack::LayerState::Discovery
            {
                transport_actions
                    .extend(
                        &TrackedActions {
                            active: iris_core::conntrack::Actions::from(4),
                            refresh_at: [
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(4),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(4),
                            ],
                        },
                    );
                layer0_actions
                    .extend(
                        &TrackedActions {
                            active: iris_core::conntrack::Actions::from(2),
                            refresh_at: [
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(2),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(2),
                            ],
                        },
                    );
            }
            if conn.layers[0].layer_info().state
                == iris_core::conntrack::LayerState::Headers
            {
                transport_actions
                    .extend(
                        &TrackedActions {
                            active: iris_core::conntrack::Actions::from(4),
                            refresh_at: [
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(4),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(4),
                            ],
                        },
                    );
                layer0_actions
                    .extend(
                        &TrackedActions {
                            active: iris_core::conntrack::Actions::from(2),
                            refresh_at: [
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(2),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(2),
                            ],
                        },
                    );
            }
            transport_actions
                .extend(
                    &TrackedActions {
                        active: iris_core::conntrack::Actions::from(9),
                        refresh_at: [
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(9),
                        ],
                    },
                );
        }
        conn.linfo.actions.extend(&transport_actions);
        conn.layers[0].extend_actions(&layer0_actions);
    }
    fn tx_l7endhdrs(conn: &mut ConnInfo<TrackedWrapper>, tx: &StateTransition) {
        let mut ret = false;
        let tx = iris_core::StateTxData::from_tx(tx, &conn.layers[0]);
        let mut transport_actions = iris_core::conntrack::TrackedActions::new();
        let mut layer0_actions = iris_core::conntrack::TrackedActions::new();
        if let Ok(tcp) = &iris_core::protocols::stream::ConnData::parse_to::<
            iris_core::protocols::stream::conn::TcpCData,
        >(&conn.cdata) {
            transport_actions
                .extend(
                    &TrackedActions {
                        active: iris_core::conntrack::Actions::from(9),
                        refresh_at: [
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(9),
                        ],
                    },
                );
        } else if let Ok(udp) = &iris_core::protocols::stream::ConnData::parse_to::<
            iris_core::protocols::stream::conn::UdpCData,
        >(&conn.cdata) {
            transport_actions
                .extend(
                    &TrackedActions {
                        active: iris_core::conntrack::Actions::from(9),
                        refresh_at: [
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(0),
                            iris_core::conntrack::Actions::from(9),
                        ],
                    },
                );
        }
        conn.linfo.actions.extend(&transport_actions);
        conn.layers[0].extend_actions(&layer0_actions);
    }
    fn tx_l4terminated(conn: &mut ConnInfo<TrackedWrapper>, tx: &StateTransition) {
        let mut ret = false;
        let tx = iris_core::StateTxData::from_tx(tx, &conn.layers[0]);
        let mut transport_actions = iris_core::conntrack::TrackedActions::new();
        let mut layer0_actions = iris_core::conntrack::TrackedActions::new();
        conn_done(&conn.tracked.connvolume, conn.layers[0].last_session());
        conn.linfo.actions.extend(&transport_actions);
        conn.layers[0].extend_actions(&layer0_actions);
    }
    fn update(
        conn: &mut ConnInfo<TrackedWrapper>,
        pdu: &iris_core::L4Pdu,
        state: iris_core::StateTransition,
    ) -> bool {
        let mut ret = false;
        match state {
            StateTransition::L4InPayload(_) => {
                conn.tracked.connvolume.new_packet(pdu);
            }
            _ => {}
        }
        ret
    }
    iris_core::filter::FilterFactory::new(
        "((ipv4) and (tcp)) or ((ipv4) and (udp)) or ((ipv6) and (tcp)) or ((ipv6) and (udp))",
        packet_filter,
        state_tx,
        update,
    )
}
fn main() {
    {
        ::std::io::_print(format_args!("Hello, world!\n"));
    };
}
