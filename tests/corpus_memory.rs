// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Memory-residency measurements for canonical JSON benchmark corpora.
//!
//! This test is intentionally isolated in its own integration-test binary so
//! the custom global allocator counters reflect only the current fixture load +
//! parse workload. Set `MULT` to parse and retain multiple copies of a fixture.

#![cfg(not(feature = "mimalloc"))]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

struct Tracking;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static TOTAL_ALLOC: AtomicUsize = AtomicUsize::new(0);
static NALLOC: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Tracking {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = System.alloc(l);
        if !p.is_null() {
            let n = l.size();
            let cur = LIVE.fetch_add(n, Ordering::Relaxed) + n;
            TOTAL_ALLOC.fetch_add(n, Ordering::Relaxed);
            NALLOC.fetch_add(1, Ordering::Relaxed);
            let mut peak = PEAK.load(Ordering::Relaxed);
            while cur > peak {
                match PEAK.compare_exchange_weak(peak, cur, Ordering::Relaxed, Ordering::Relaxed) {
                    Ok(_) => break,
                    Err(p) => peak = p,
                }
            }
        }
        p
    }

    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        System.dealloc(p, l);
        LIVE.fetch_sub(l.size(), Ordering::Relaxed);
    }
}

#[global_allocator]
static A: Tracking = Tracking;

#[derive(Copy, Clone)]
struct Snap {
    live: usize,
    peak: usize,
    total: usize,
    nalloc: usize,
}

#[derive(Default)]
struct ObjectStats {
    inline: usize,
    frozen: usize,
    btree: usize,
    fields: usize,
}

impl ObjectStats {
    fn add_value(&mut self, value: &regorus::Value) {
        match value {
            regorus::Value::Array(values) => {
                for value in values.iter() {
                    self.add_value(value);
                }
            }
            regorus::Value::Set(values) => {
                for value in values.iter() {
                    self.add_value(value);
                }
            }
            regorus::Value::Object(object) => {
                match object.storage_variant_for_memory_diagnostics() {
                    "Inline" => self.inline += 1,
                    "Frozen" => self.frozen += 1,
                    "BTree" => self.btree += 1,
                    _ => unreachable!("unknown Object storage variant"),
                }
                self.fields += object.len();
                for (_, value) in object.iter() {
                    self.add_value(value);
                }
            }
            _ => {}
        }
    }

    fn object_count(&self) -> usize {
        self.inline + self.frozen + self.btree
    }

    fn avg_fields(&self) -> f64 {
        let objects = self.object_count();
        if objects == 0 {
            0.0
        } else {
            self.fields as f64 / objects as f64
        }
    }
}

fn snap() -> Snap {
    Snap {
        live: LIVE.load(Ordering::Relaxed),
        peak: PEAK.load(Ordering::Relaxed),
        total: TOTAL_ALLOC.load(Ordering::Relaxed),
        nalloc: NALLOC.load(Ordering::Relaxed),
    }
}

fn reset_counters() {
    let live = LIVE.load(Ordering::Relaxed);
    PEAK.store(live, Ordering::Relaxed);
    TOTAL_ALLOC.store(0, Ordering::Relaxed);
    NALLOC.store(0, Ordering::Relaxed);
}

fn mib(b: usize) -> f64 {
    b as f64 / (1024.0 * 1024.0)
}

fn measure(path: &str, mult: usize) {
    reset_counters();
    let base = snap();
    let source = std::fs::read_to_string(path).expect("read JSON fixture");
    let file_size = source.len();

    let values: Vec<regorus::Value> = (0..mult)
        .map(|_| regorus::Value::from_json_str(&source).expect("parse JSON fixture to Value"))
        .collect();
    let after_parse = snap();

    let mut stats = ObjectStats::default();
    for value in &values {
        stats.add_value(value);
    }

    drop(source);
    let after_drop_source = snap();

    println!();
    println!("=== CORPUS_MEMORY path={path} mult={mult} size_bytes={file_size} ===");
    println!(
        "METRIC path={path} mult={mult} size_bytes={file_size} nalloc={} total_alloc_bytes={} peak_bytes={} live_bytes={} objects={} inline={} frozen={} btree={} avg_fields_per_object={:.3}",
        after_parse.nalloc - base.nalloc,
        after_parse.total - base.total,
        after_parse.peak.saturating_sub(base.peak),
        after_drop_source.live.saturating_sub(base.live),
        stats.object_count(),
        stats.inline,
        stats.frozen,
        stats.btree,
        stats.avg_fields(),
    );
    println!(
        "  total_alloc={:.3} MiB peak={:.3} MiB live_after_drop_source={:.3} MiB objects={} avg_fields_per_object={:.3}",
        mib(after_parse.total - base.total),
        mib(after_parse.peak.saturating_sub(base.peak)),
        mib(after_drop_source.live.saturating_sub(base.live)),
        stats.object_count(),
        stats.avg_fields(),
    );
    println!(
        "  Object variants after parse: Inline={} Frozen={} BTree={}",
        stats.inline, stats.frozen, stats.btree,
    );

    drop(values);
    let after_drop_values = snap();
    println!(
        "  live_after_drop_values={:.3} MiB",
        mib(after_drop_values.live.saturating_sub(base.live)),
    );
}

fn mult() -> usize {
    std::env::var("MULT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1)
}

#[test]
fn twitter_memory_residency() {
    measure("tests/data/corpus_memory/twitter.json", mult());
}

#[test]
fn citm_catalog_memory_residency() {
    measure("tests/data/corpus_memory/citm_catalog.json", mult());
}

#[test]
fn canada_memory_residency() {
    measure("tests/data/corpus_memory/canada.json", mult());
}

#[test]
fn synthea_fhir_memory_residency() {
    measure("tests/data/corpus_memory/synthea_fhir.json", mult());
}
