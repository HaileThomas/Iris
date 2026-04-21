use anyhow::Result;
use std::ptr;

use crate::FiveTuple;
use crate::port::PortId;
use crate::dpdk::{self, rte_flow, rte_flow_action, rte_flow_action_queue};

use super::{ingress_attr, install_bidirectional};

pub fn install_split_flow(
    port_ids: Vec<PortId>,
    tuple:    &FiveTuple,
    queue_id: u16,
) -> Result<Vec<*mut rte_flow>> {
    let conf = rte_flow_action_queue { index: queue_id };
    let actions = [
        rte_flow_action {
            type_: dpdk::rte_flow_action_type_RTE_FLOW_ACTION_TYPE_QUEUE,
            conf:  &conf as *const _ as *const _,
        },
        rte_flow_action {
            type_: dpdk::rte_flow_action_type_RTE_FLOW_ACTION_TYPE_END,
            conf:  ptr::null(),
        },
    ];

    install_bidirectional(&port_ids, tuple, &ingress_attr(1, 0), &actions)
}