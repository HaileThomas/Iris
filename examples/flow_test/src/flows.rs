use iris_core::{port::PortId, CoreId, FiveTuple};
use iris_core::dpdk::rte_flow;
use iris_core::filter::flow::{drop::install_drop_flow, uninstall_flows};

use std::{
    collections::VecDeque,
    sync::{Mutex, RwLock},
    time::{Duration, Instant},
};

pub const MIN_PACKETS: usize = 10;
const TIMEOUT_SECS: u64 = 10;
const MAX_FLOWS: usize = 100;

// ===== Types =====

#[derive(Clone)]
pub enum FlowEvent {
    TlsSeen { tuple: FiveTuple, rx_core: CoreId },
}

#[derive(Clone, Copy)]
struct FlowPtr(*mut rte_flow);
unsafe impl Send for FlowPtr {}
unsafe impl Sync for FlowPtr {}

struct FlowEntry {
    tuple: FiveTuple,
    ports: Vec<PortId>,
    flow_ptrs: Vec<FlowPtr>,
    expires_at: Instant,
}

// ===== Active flows =====

struct ActiveFlows(VecDeque<FlowEntry>);

impl ActiveFlows {
    const fn new() -> Self {
        Self(VecDeque::new())
    }

    fn insert(&mut self, tuple: FiveTuple, ports: Vec<PortId>) {
        if self.0.len() >= MAX_FLOWS || self.0.iter().any(|e| e.tuple == tuple) {
            return;
        }
        
        match install_drop_flow(ports.clone(), &tuple) {
            Ok(raw_flows) => self.0.push_back(FlowEntry {
                tuple,
                ports,
                flow_ptrs: raw_flows.into_iter().map(FlowPtr).collect(),
                expires_at: Instant::now() + Duration::from_secs(TIMEOUT_SECS),
            }),
            
            Err(e) => eprintln!("install_drop_flow failed: {e:?}"),
        }
    }

    fn expire(&mut self) {
        let now = Instant::now();
        
        while self.0.front().map_or(false, |e| e.expires_at <= now) {
            let expired = self.0.pop_front().unwrap();
            let ptrs: Vec<*mut rte_flow> = expired.flow_ptrs.iter().map(|f| f.0).collect();
            
            if let Err(e) = uninstall_flows(&expired.ports, &ptrs) {
                eprintln!("uninstall_flows failed: {e:?}");
            }
        }
    }
}

// ===== State =====

static PORT_IDS: RwLock<Option<Vec<PortId>>> = RwLock::new(None);
static ACTIVE_FLOWS: Mutex<ActiveFlows> = Mutex::new(ActiveFlows::new());

pub fn set_ports(ports: Vec<PortId>) {
    *PORT_IDS.write().unwrap() = Some(ports);
}

// ===== Event handler =====

pub fn handle_flow_event(event: FlowEvent) {
    let FlowEvent::TlsSeen { tuple, .. } = event;

    let Some(ports) = PORT_IDS.read().unwrap().clone() else {
        eprintln!("No ports available when installing drop flow");
        return;
    };

    let mut active = ACTIVE_FLOWS.lock().unwrap();
    active.expire();
    active.insert(tuple, ports);
}