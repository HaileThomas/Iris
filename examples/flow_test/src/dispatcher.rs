use std::sync::{Arc, OnceLock};
use iris_core::{
    multicore::{ChannelDispatcher, ChannelMode, SharedWorkerThreadSpawner},
    CoreId,
};
use crate::flows::{FlowEvent, handle_flow_event};

const CHANNEL_SIZE: usize = 32768;
const BATCH_SIZE: usize = 16;

pub static FLOW_DISPATCHER: OnceLock<Arc<ChannelDispatcher<FlowEvent>>> = OnceLock::new();

pub fn start_worker(rx_cores: Vec<CoreId>) -> impl std::any::Any {
    let dispatcher = Arc::new(ChannelDispatcher::new(
        ChannelMode::PerCore(rx_cores.clone()),
        CHANNEL_SIZE,
        "flow_dispatcher".to_string(),
    ));

    FLOW_DISPATCHER
        .set(dispatcher.clone())
        .map_err(|_| "Failed to set FLOW dispatcher")
        .unwrap();

    SharedWorkerThreadSpawner::new()
        .set_cores(rx_cores)
        .set_batch_size(BATCH_SIZE)
        .add_dispatcher(dispatcher, |event| handle_flow_event(event))
        .run()
}