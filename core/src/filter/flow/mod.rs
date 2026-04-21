use std::ffi::CStr;
use std::mem;

use anyhow::{bail, Result};
use crate::FiveTuple;
use crate::port::PortId;
use crate::dpdk::{rte_flow, rte_flow_attr, rte_flow_error, rte_flow_create, rte_flow_destroy, rte_flow_action};

mod pattern;
pub use pattern::FlowPattern;

pub mod drop;
pub mod split;

pub fn ingress_attr(group: u32, priority: u32) -> rte_flow_attr {
    let mut attr: rte_flow_attr = unsafe { mem::zeroed() };
    attr.set_ingress(1);
    attr.group    = group;
    attr.priority = priority;
    attr
}

pub fn install_flows(
    port_ids: &[PortId],
    attr:     &rte_flow_attr,
    pattern:  &FlowPattern,
    actions:  &[rte_flow_action],
) -> Result<Vec<*mut rte_flow>> {
    let mut flows = Vec::with_capacity(port_ids.len());

    for port_id in port_ids {
        let mut error: rte_flow_error = unsafe { mem::zeroed() };
        let flow = unsafe {
            rte_flow_create(
                port_id.raw(),
                attr,
                pattern.items.as_ptr(),
                actions.as_ptr(),
                &mut error,
            )
        };

        if flow.is_null() {
            let msg = unsafe {
                CStr::from_ptr(error.message).to_string_lossy().into_owned()
            };
            bail!("Failed to install flow on port {}: {}", port_id.raw(), msg);
        }

        flows.push(flow);
    }

    Ok(flows)
}

pub fn install_bidirectional(
    port_ids: &[PortId],
    tuple:    &FiveTuple,
    attr:     &rte_flow_attr,
    actions:  &[rte_flow_action],
) -> Result<Vec<*mut rte_flow>> {
    let fwd = install_flows(port_ids, attr, &FlowPattern::build(tuple)?, actions)?;
    let rev = install_flows(port_ids, attr, &FlowPattern::build(&tuple.reversed())?, actions)?;
    Ok([fwd, rev].concat())
}

pub fn uninstall_flows(port_ids: &[PortId], flows: &[*mut rte_flow]) -> Result<()> {
    if flows.len() % port_ids.len() != 0 {
        bail!(
            "flows.len() ({}) is not a multiple of port_ids.len() ({})",
            flows.len(), port_ids.len(),
        );
    }

    for (port_id, flow) in port_ids.iter().cycle().zip(flows.iter()) {
        if flow.is_null() {
            println!("No flow to uninstall on port {}", port_id.raw());
            continue;
        }

        let mut error: rte_flow_error = unsafe { mem::zeroed() };
        let ret = unsafe { rte_flow_destroy(port_id.raw(), *flow, &mut error) };

        if ret != 0 {
            let msg = unsafe {
                CStr::from_ptr(error.message).to_string_lossy().into_owned()
            };
            bail!("Failed to uninstall flow on port {}: {}", port_id.raw(), msg);
        }
    }

    Ok(())
}

pub fn uninstall_bidirectional(port_ids: Vec<PortId>, flows: Vec<*mut rte_flow>) -> Result<()> {
    if port_ids.len() * 2 != flows.len() {
        anyhow::bail!(
            "Expected {} flows (2 per port), got {}",
            port_ids.len() * 2,
            flows.len(),
        );
    }
    uninstall_flows(&port_ids, &flows)
}