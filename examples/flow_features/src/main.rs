use iris_core::{config::load_config, CoreId, Runtime};
use iris_datatypes::{DnsTransaction, TlsHandshake, ConnRecord};
use iris_datatypes::conn_fts::InterArrivals;
use iris_compiler::*;

mod conn_features;
mod dns_features;
mod tls_features;
mod headers;
mod csv_output;
mod hash_utils;

use conn_features::ConnFeatures;
use dns_features::DnsFeatures;
use tls_features::TlsFeatures;

use lightgbm3::Booster;
use std::sync::OnceLock;

struct SendSyncBooster(Booster);
unsafe impl Send for SendSyncBooster {}
unsafe impl Sync for SendSyncBooster {}

static BOOSTER: OnceLock<SendSyncBooster> = OnceLock::new();

fn load_model(path: &str) {
    let booster = Booster::from_file(path).expect("Failed to load elephant flow model");
    BOOSTER.set(SendSyncBooster(booster)).ok();
}

fn predict(f: &ConnFeatures) -> Option<f64> {
    let booster = &BOOSTER.get()?.0;

    let features: Vec<f64> = vec![
        f.first_seen_ts               as f64,
        f.src_ip_hash                 as f64,
        f.dst_ip_hash                 as f64,
        f.src_ip_subn                 as f64,
        f.dst_ip_subn                 as f64,
        f.src_port                    as f64,
        f.dst_port                    as f64,
        f.protocol                    as f64,
        f.duration_ms                 as f64,
        f.max_inactivity_ms           as f64,
        f.time_to_second_pkt_ms       as f64,
        f.hist_syn                    as f64,
        f.hist_synack                 as f64,
        f.hist_ack                    as f64,
        f.hist_data                   as f64,
        f.hist_fin                    as f64,
        f.hist_rst                    as f64,
        f.hist_syn_r                  as f64,
        f.hist_synack_r               as f64,
        f.hist_ack_r                  as f64,
        f.hist_data_r                 as f64,
        f.hist_fin_r                  as f64,
        f.hist_rst_r                  as f64,
        f.orig_nb_pkts                as f64,
        f.orig_nb_malformed_pkts      as f64,
        f.orig_nb_late_start_pkts     as f64,
        f.orig_nb_pkt_bytes           as f64,
        f.orig_nb_payload_bytes       as f64,
        f.orig_max_simult_gaps        as f64,
        f.orig_content_gaps           as f64,
        f.orig_missed_bytes           as f64,
        f.orig_mean_pkts_to_fill,
        f.orig_median_pkts_to_fill    as f64,
        f.resp_nb_pkts                as f64,
        f.resp_nb_malformed_pkts      as f64,
        f.resp_nb_late_start_pkts     as f64,
        f.resp_nb_pkt_bytes           as f64,
        f.resp_nb_payload_bytes       as f64,
        f.resp_max_simult_gaps        as f64,
        f.resp_content_gaps           as f64,
        f.resp_missed_bytes           as f64,
        f.resp_mean_pkts_to_fill,
        f.resp_median_pkts_to_fill    as f64,
        f.orig_iat_mean,
        f.orig_iat_median,
        f.orig_iat_min                as f64,
        f.orig_iat_max                as f64,
        f.orig_iat_std,
        f.resp_iat_mean,
        f.resp_iat_median,
        f.resp_iat_min                as f64,
        f.resp_iat_max                as f64,
    ];

    let n_features = features.len() as i32;

    match booster.predict_with_params(&features, n_features, true, "num_threads=1") {
        Ok(result) => Some(result[0]),
        Err(e) => {
            println!("[ELEPHANT ERROR] predict failed: {:?}", e);
            None
        }
    }
}

#[callback("tcp or udp,level=L4Terminated")]
fn flow_cb(
    conn: &ConnRecord,
    iat: &InterArrivals,
    core_id: &CoreId
) {
    if let Some(features) = ConnFeatures::from_conn(conn, iat) {
        if let Some(proba) = predict(&features) {
            println!(
                "[FLOW] src_subn={} dst_subn={} src_port={} dst_port={} proto={} p={:.4}",
                features.src_ip_subn,
                features.dst_ip_subn,
                features.src_port,
                features.dst_port,
                features.protocol,
                proba,
            );
        }
        // csv_output::write(&features, core_id);
    }
}


// #[callback("tls or quic,level=L4Terminated")]
// fn flow_cb_tls(
//     conn: &ConnRecord,
//     iat: &InterArrivals,
//     proto: &TlsHandshake,
//     core_id: &CoreId
// ) {
//     if let (Some(conn_features), Some(tls_features)) = (
//         ConnFeatures::from_conn(conn, iat),
//         TlsFeatures::from_tls(proto),
//     ) {
//         csv_output::write_tls(&conn_features, &tls_features, core_id);
//     }
// }


// #[callback("dns,level=L4Terminated")]
// fn flow_cb_dns(
//     conn: &ConnRecord,
//     iat: &InterArrivals,
//     proto: &DnsTransaction,
//     core_id: &CoreId
// ) {
//     if let (Some(conn_features), Some(dns_features)) = (
//         ConnFeatures::from_conn(conn, iat),
//         DnsFeatures::from_dns(proto, conn.client().ip()),
//     ) {
//         csv_output::write_dns(&conn_features, &dns_features, core_id);
//     }
// }

// Needed to use any data types from `datatypes/`
#[input_files("$IRIS_HOME/datatypes/data.txt")]
// Needed to indicate end of macros (I will rename this to "macro_end" or something)
#[iris_main]
fn main() {
    let config = load_config("./configs/offline.toml");
    load_model("./elephant_flow_model.txt");
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();

    csv_output::combine();
}
