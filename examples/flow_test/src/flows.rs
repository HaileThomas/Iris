use iris_core::{port::PortId, CoreId, FiveTuple};
use iris_core::config::{FlowMode, RuntimeConfig};
use iris_core::dpdk::rte_flow;
use iris_core::filter::flow::{drop::install_drop_flow, split::install_split_flow, uninstall_flows};

use std::{
    collections::{HashMap, VecDeque},
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

    fn insert(&mut self, tuple: FiveTuple, ports: Vec<PortId>, mode: FlowMode, split_queue: Option<u16>) {
        if self.0.len() >= MAX_FLOWS || self.0.iter().any(|e| e.tuple == tuple) {
            return;
        }

        let result = match mode {
            FlowMode::Drop => install_drop_flow(ports.clone(), &tuple),
            FlowMode::Split => install_split_flow(ports.clone(), &tuple, split_queue.unwrap()),
            FlowMode::Standard => return,
        };

        match result {
            Ok(raw_flows) => self.0.push_back(FlowEntry {
                tuple,
                ports,
                flow_ptrs: raw_flows.into_iter().map(FlowPtr).collect(),
                expires_at: Instant::now() + Duration::from_secs(TIMEOUT_SECS),
            }),

            Err(e) => eprintln!("install flow failed: {e:?}"),
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
static MODE: RwLock<FlowMode> = RwLock::new(FlowMode::Standard);
static SPLIT_QUEUES: RwLock<Option<HashMap<CoreId, u16>>> = RwLock::new(None);

pub fn set_ports(ports: Vec<PortId>) {
    *PORT_IDS.write().unwrap() = Some(ports);
}

pub fn set_mode(mode: FlowMode) {
    *MODE.write().unwrap() = mode;
}

pub fn init_split_queues(config: &RuntimeConfig) {
    // Layout per port (no sink): q0=receive q1=split q2=receive q3=split ...
    // Layout per port (sink):    q0=sink q1=receive q2=split q3=receive q4=split ...
    let mut split_queues: HashMap<CoreId, u16> = HashMap::new();
    if let Some(online) = &config.online {
        for port_map in &online.ports {
            let sink_offset: u16 = if port_map.sink.is_some() { 1 } else { 0 };
            let mut cores = port_map.cores.clone();
            cores.sort_unstable();
            cores.dedup();
            for (i, core) in cores.iter().enumerate() {
                let split_qid = sink_offset + (i as u16) * 2 + 1;
                split_queues.insert(CoreId(*core), split_qid);
            }
        }
    }
    *SPLIT_QUEUES.write().unwrap() = Some(split_queues);
}

// ===== Event handler =====

pub fn handle_flow_event(event: FlowEvent) {
    let FlowEvent::TlsSeen { tuple, rx_core } = event;

    let mode = *MODE.read().unwrap();
    if mode == FlowMode::Standard {
        return;
    }

    let Some(ports) = PORT_IDS.read().unwrap().clone() else {
        eprintln!("No ports available when installing drop flow");
        return;
    };

    let split_queue = if mode == FlowMode::Split {
        let queues = SPLIT_QUEUES.read().unwrap();
        match queues.as_ref().and_then(|m| m.get(&rx_core)).copied() {
            Some(q) => Some(q),
            None => {
                eprintln!("No split queue mapped for core {rx_core:?}");
                return;
            }
        }
    } else {
        None
    };

    let mut active = ACTIVE_FLOWS.lock().unwrap();
    active.expire();
    active.insert(tuple, ports, mode, split_queue);
}