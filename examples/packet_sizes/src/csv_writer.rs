use array_init::array_init;
use csv::Writer;
use serde::Serialize;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::OnceLock;
use iris_core::CoreId;

const NUM_CORES: usize = 32;
const ARR_LEN: usize = NUM_CORES + 1;

const HEADER: &str = "pkt_0_64,\
                      pkt_64_128,\
                      pkt_128_256,\
                      pkt_256_512,\
                      pkt_512_1024,\
                      pkt_1024_1500,\
                      pkt_1500_inf \n";

static WRITERS: OnceLock<[AtomicPtr<Writer<BufWriter<File>>>; ARR_LEN]> = OnceLock::new();

fn init() -> &'static [AtomicPtr<Writer<BufWriter<File>>>; ARR_LEN] {
    WRITERS.get_or_init(|| {
        let ptrs: Vec<_> = (0..ARR_LEN)
            .map(|core| {
                let file = File::create(format!("pkt_hist_{}.csv", core)).unwrap();
                let w = csv::WriterBuilder::new()
                    .has_headers(false)
                    .from_writer(BufWriter::new(file));
                Box::into_raw(Box::new(w))
            })
            .collect();
        array_init(|i| AtomicPtr::new(ptrs[i]))
    })
}

pub fn write<T: Serialize>(row: &T, core: &CoreId) {
    let ptr = init()[core.raw() as usize].load(Ordering::Relaxed);
    unsafe { &mut *ptr }.serialize(row).unwrap();
}

pub fn combine() {
    println!("Combining {} shared files...", ARR_LEN);
    let mut out = BufWriter::new(File::create("pkt_hist.csv").unwrap());
    out.write_all(HEADER.as_bytes()).unwrap();

    for core in 0..ARR_LEN {
        let ptr = init()[core].load(Ordering::Relaxed);
        unsafe { &mut *ptr }.flush().unwrap();

        let path = format!("pkt_hist_{}.csv", core);
        std::io::copy(&mut File::open(&path).unwrap(), &mut out).unwrap();
        std::fs::remove_file(&path).unwrap();
    }
}