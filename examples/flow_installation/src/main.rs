use iris_core::{config::load_config, CoreId, Runtime};
use iris_datatypes::ConnRecord;
use iris_compiler::*;

#[callback("tcp or udp,level=L4Terminated")]
fn flow_cb_tcp(_conn: &ConnRecord, _core_id: &CoreId) { }

#[callback("tls or quic,level=L4Terminated")]
fn flow_cb_tls(_conn: &ConnRecord, _core_id: &CoreId) { }

#[callback("dns,level=L4Terminated")]
fn flow_cb_dns(_conn: &ConnRecord, _core_id: &CoreId) { }

#[input_files("$IRIS_HOME/datatypes/data.txt")]
#[iris_main]
fn main() {
    let config = load_config("./configs/online.toml");
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
}