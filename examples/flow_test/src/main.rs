use iris_core::{
    config::{load_config, FlowMode},
    port::PortId,
    CoreId, FiveTuple, Runtime,
};
use iris_datatypes::PktCount;
use iris_compiler::{callback, input_files, iris_end_macros};

mod dispatcher;
mod flows;

use dispatcher::FLOW_DISPATCHER;
use flows::FlowEvent;

#[callback("tcp,level=InL4Conn")]
fn on_tcp_flow(five_tuple: &FiveTuple, rx_core: &CoreId, pkts: &PktCount) -> bool {
    if pkts.total() >= flows::MIN_PACKETS {
        if let Some(d) = FLOW_DISPATCHER.get() {
            let _ = d.dispatch(
                FlowEvent::TlsSeen { tuple: five_tuple.clone(), rx_core: *rx_core },
                Some(rx_core),
            );
        }
    }
    true
}

#[input_files("$IRIS_HOME/datatypes/data.txt")]
#[iris_end_macros]
fn main() {
    let config = load_config("./configs/online.toml");

    let rx_cores = config.get_all_rx_core_ids();
    let port_devices: Vec<String> = config.online.as_ref()
        .map(|o| o.ports.iter().map(|p| p.device.clone()).collect())
        .unwrap_or_default();

    let flow_mode = config.online.as_ref().map_or(FlowMode::Standard, |o| o.flow_mode);
    flows::set_mode(flow_mode);

    if flow_mode == FlowMode::Split {
        flows::init_split_queues(&config);
    }

    let _worker_handle = dispatcher::start_worker(rx_cores);

    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();

    let port_ids: Vec<PortId> = port_devices.iter()
        .map(|d| PortId::new_from_device(d.clone()))
        .collect();
    flows::set_ports(port_ids);
    
    runtime.run();
}