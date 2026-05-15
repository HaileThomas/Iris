use iris_core::{config::load_config, CoreId, Runtime};
use iris_datatypes::ConnRecord;
use iris_datatypes::connection::Flow;
use iris_compiler::*;

mod csv_writer;

use serde::Serialize;

#[derive(Serialize)]
struct PktSizeHistRow {
    pkt_0_64:      u64,
    pkt_64_128:    u64,
    pkt_128_256:   u64,
    pkt_256_512:   u64,
    pkt_512_1024:  u64,
    pkt_1024_1500: u64,
    pkt_1500_inf:  u64,
}

impl PktSizeHistRow {
    fn from_conn(conn: &ConnRecord) -> Self {
        let h = |i: usize| conn.orig.pkt_size_hist[i] + conn.resp.pkt_size_hist[i];
        Self {
            pkt_0_64:      h(0),
            pkt_64_128:    h(1),
            pkt_128_256:   h(2),
            pkt_256_512:   h(3),
            pkt_512_1024:  h(4),
            pkt_1024_1500: h(5),
            pkt_1500_inf:  h(6),
        }
    }
}

#[callback("tcp or udp or tls or quic, level=L4Terminated")]
fn flow_cb(conn: &ConnRecord, core_id: &CoreId) {
    csv_writer::write(&PktSizeHistRow::from_conn(conn), core_id);
}

#[input_files("$IRIS_HOME/datatypes/data.txt")]
#[iris_main]
fn main() {
    let config = load_config("./configs/online.toml");
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();

    csv_writer::combine();
}