use anyhow::Result;
use std::ptr;

use crate::FiveTuple;
use crate::port::PortId;
use crate::dpdk::{self, rte_flow, rte_flow_action};

use super::{ingress_attr, install_bidirectional};

pub fn install_drop_flow(
    port_ids: Vec<PortId>,
    tuple:    &FiveTuple,
) -> Result<Vec<*mut rte_flow>> {
    let actions = [
        rte_flow_action {
            type_: dpdk::rte_flow_action_type_RTE_FLOW_ACTION_TYPE_DROP,
            conf: ptr::null(),
        },
        rte_flow_action {
            type_: dpdk::rte_flow_action_type_RTE_FLOW_ACTION_TYPE_END,
            conf: ptr::null(),
        },
    ];

    install_bidirectional(&port_ids, tuple, &ingress_attr(1, 0), &actions)
}