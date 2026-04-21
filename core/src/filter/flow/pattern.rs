use std::mem;
use std::ptr;
use std::net::IpAddr;

use anyhow::{bail, Result};
use crate::FiveTuple;
use crate::protocols::packet::tcp::TCP_PROTOCOL;
use crate::protocols::packet::udp::UDP_PROTOCOL;
use crate::dpdk;
use crate::dpdk::{
    rte_flow_item,
    rte_flow_item_ipv4, rte_flow_item_ipv6,
    rte_flow_item_tcp, rte_flow_item_udp,
};

struct FlowPatternStorage {
    ipv4_spec: rte_flow_item_ipv4,
    ipv4_mask: rte_flow_item_ipv4,
    ipv6_spec: rte_flow_item_ipv6,
    ipv6_mask: rte_flow_item_ipv6,
    tcp_spec:  rte_flow_item_tcp,
    tcp_mask:  rte_flow_item_tcp,
    udp_spec:  rte_flow_item_udp,
    udp_mask:  rte_flow_item_udp,
}

pub struct FlowPattern {
    _storage: Box<FlowPatternStorage>,
    pub items: [rte_flow_item; 5],
}

impl FlowPattern {
    pub fn build(tuple: &FiveTuple) -> Result<Self> {
        let mut storage = Box::new(FlowPatternStorage {
            ipv4_spec: unsafe { mem::zeroed() },
            ipv4_mask: unsafe { mem::zeroed() },
            ipv6_spec: unsafe { mem::zeroed() },
            ipv6_mask: unsafe { mem::zeroed() },
            tcp_spec:  unsafe { mem::zeroed() },
            tcp_mask:  unsafe { mem::zeroed() },
            udp_spec:  unsafe { mem::zeroed() },
            udp_mask:  unsafe { mem::zeroed() },
        });

        let mut items: [rte_flow_item; 5] = unsafe { mem::zeroed() };
        let mut i = 0;

        let (src_ip, dst_ip)     = (tuple.orig.ip(),   tuple.resp.ip());
        let (src_port, dst_port) = (tuple.orig.port(), tuple.resp.port());

        items[i] = rte_flow_item {
            type_: dpdk::rte_flow_item_type_RTE_FLOW_ITEM_TYPE_ETH,
            spec: ptr::null(),
            mask: ptr::null(),
            last: ptr::null(),
        };
        i += 1;

        match (src_ip, dst_ip) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => {
                storage.ipv4_spec.hdr.src_addr      = u32::from_ne_bytes(src.octets());
                storage.ipv4_spec.hdr.dst_addr      = u32::from_ne_bytes(dst.octets());
                storage.ipv4_spec.hdr.next_proto_id = tuple.proto as u8;
                storage.ipv4_mask.hdr.src_addr      = u32::MAX;
                storage.ipv4_mask.hdr.dst_addr      = u32::MAX;
                storage.ipv4_mask.hdr.next_proto_id = 0xFF;

                items[i] = rte_flow_item {
                    type_: dpdk::rte_flow_item_type_RTE_FLOW_ITEM_TYPE_IPV4,
                    spec: &storage.ipv4_spec as *const _ as *const _,
                    mask: &storage.ipv4_mask as *const _ as *const _,
                    last: ptr::null(),
                };
            }
            (IpAddr::V6(src), IpAddr::V6(dst)) => {
                storage.ipv6_spec.hdr.src_addr = dpdk::rte_ipv6_addr { a: src.octets() };
                storage.ipv6_spec.hdr.dst_addr = dpdk::rte_ipv6_addr { a: dst.octets() };
                storage.ipv6_spec.hdr.proto    = tuple.proto as u8;
                storage.ipv6_mask.hdr.src_addr = dpdk::rte_ipv6_addr { a: [0xFF; 16] };
                storage.ipv6_mask.hdr.dst_addr = dpdk::rte_ipv6_addr { a: [0xFF; 16] };
                storage.ipv6_mask.hdr.proto    = 0xFF;

                items[i] = rte_flow_item {
                    type_: dpdk::rte_flow_item_type_RTE_FLOW_ITEM_TYPE_IPV6,
                    spec: &storage.ipv6_spec as *const _ as *const _,
                    mask: &storage.ipv6_mask as *const _ as *const _,
                    last: ptr::null(),
                };
            }
            _ => bail!("Mismatched IP versions in flow pattern"),
        }
        i += 1;

        match tuple.proto {
            TCP_PROTOCOL => {
                storage.tcp_spec.hdr.src_port = src_port.to_be();
                storage.tcp_spec.hdr.dst_port = dst_port.to_be();
                storage.tcp_mask.hdr.src_port = 0xFFFF;
                storage.tcp_mask.hdr.dst_port = 0xFFFF;

                items[i] = rte_flow_item {
                    type_: dpdk::rte_flow_item_type_RTE_FLOW_ITEM_TYPE_TCP,
                    spec: &storage.tcp_spec as *const _ as *const _,
                    mask: &storage.tcp_mask as *const _ as *const _,
                    last: ptr::null(),
                };
            }
            UDP_PROTOCOL => {
                storage.udp_spec.hdr.src_port = src_port.to_be();
                storage.udp_spec.hdr.dst_port = dst_port.to_be();
                storage.udp_mask.hdr.src_port = 0xFFFF;
                storage.udp_mask.hdr.dst_port = 0xFFFF;

                items[i] = rte_flow_item {
                    type_: dpdk::rte_flow_item_type_RTE_FLOW_ITEM_TYPE_UDP,
                    spec: &storage.udp_spec as *const _ as *const _,
                    mask: &storage.udp_mask as *const _ as *const _,
                    last: ptr::null(),
                };
            }
            _ => bail!("Unsupported L4 protocol: {}", tuple.proto),
        }
        i += 1;

        items[i] = rte_flow_item {
            type_: dpdk::rte_flow_item_type_RTE_FLOW_ITEM_TYPE_END,
            spec: ptr::null(),
            mask: ptr::null(),
            last: ptr::null(),
        };

        Ok(Self {
            _storage: storage,
            items,
        })
    }
}