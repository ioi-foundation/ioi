//! Agentgres substrate bench harness.
//!
//! Measures the doctrine performance contract (docs/architecture/components/
//! agentgres/doctrine.md, "Performance contract"):
//!   1. admission latency  (submit -> durable ack), p50/p95/p99/max
//!   2. projection freshness proxy (full replay rate; IVM lands later)
//!   3. fork/checkpoint/restore time
//! Aggregate throughput across independent domains is reported to evidence
//! ownership-partitioned scaling; TPS is explicitly not the contract.
//!
//! The HARNESS may read clocks; the ENGINE never does.

use agentgres::mux::{spawn_mux_writer, spawn_mux_writer_cfg, MuxEngine, MuxHandle, WriterConfig};
use agentgres::replica::ReplicaLink;
use agentgres::{spawn_writer, AgentgresSubstrate, Operation, SubstrateEngine};
use std::path::PathBuf;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}
fn env_flag(key: &str, default: bool) -> bool {
    std::env::var(key).map(|v| v != "0").unwrap_or(default)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn pct(sorted_ns: &[u64], p: f64) -> f64 {
    if sorted_ns.is_empty() {
        return 0.0;
    }
    let idx = ((sorted_ns.len() as f64 - 1.0) * p).round() as usize;
    sorted_ns[idx] as f64 / 1_000_000.0
}

struct DomainResult {
    domain: String,
    admitted: u64,
    refused: u64,
    wall_s: f64,
    lat_sorted_ns: Vec<u64>,
}

fn run_domain(
    dir: PathBuf,
    domain: String,
    ops_total: u64,
    clients: u64,
    objects: u64,
    payload_bytes: usize,
    max_batch: usize,
    sync: bool,
) -> DomainResult {
    let engine = SubstrateEngine::open(&dir, sync).expect("open engine");
    let (handle, writer) = spawn_writer(engine, max_batch);
    let filler = "x".repeat(payload_bytes);
    let started = Instant::now();
    let mut joins = Vec::new();
    for c in 0..clients {
        let handle = handle.clone();
        let domain = domain.clone();
        let filler = filler.clone();
        // Distribute the remainder — never silently drop ops (INV-14).
        let per_client = ops_total / clients + u64::from(c < ops_total % clients);
        // Disjoint object slice per client: expected-head admission with no
        // artificial conflicts; heads chain per object.
        let obj_lo = c * objects / clients;
        let obj_hi = ((c + 1) * objects / clients).max(obj_lo + 1);
        joins.push(std::thread::spawn(move || {
            let mut lat = Vec::with_capacity(per_client as usize);
            let mut heads: std::collections::HashMap<u64, String> =
                std::collections::HashMap::new();
            let mut refused = 0u64;
            for i in 0..per_client {
                let obj = obj_lo + (i % (obj_hi - obj_lo));
                let expected = heads.get(&obj).cloned();
                let op = Operation {
                    domain: domain.clone(),
                    object_ref: format!("bench://{domain}/obj-{obj}"),
                    op_kind: "bench.write".into(),
                    expected_head: expected,
                    payload: serde_json::json!({ "i": i, "fill": filler }),
                    recorded_at_ms: now_ms(),
                    idem_key: format!("{domain}-{c}-{i}"),
                };
                let t0 = Instant::now();
                match handle.admit(op) {
                    Ok(ack) => {
                        lat.push(t0.elapsed().as_nanos() as u64);
                        heads.insert(obj, ack.new_head);
                    }
                    Err(_) => refused += 1,
                }
            }
            (lat, refused)
        }));
    }
    let mut lat_all: Vec<u64> = Vec::with_capacity(ops_total as usize);
    let mut refused = 0u64;
    for j in joins {
        let (lat, r) = j.join().expect("client join");
        lat_all.extend(lat);
        refused += r;
    }
    let wall_s = started.elapsed().as_secs_f64();
    handle.shutdown();
    writer.join.join().expect("writer join").expect("writer io");
    lat_all.sort_unstable();
    DomainResult {
        domain,
        admitted: lat_all.len() as u64,
        refused,
        wall_s,
        lat_sorted_ns: lat_all,
    }
}

#[allow(clippy::too_many_arguments)]
fn run_mux_all(
    base: &PathBuf,
    domains: u64,
    ops_per_domain: u64,
    clients: u64,
    objects: u64,
    payload_bytes: usize,
    max_batch: usize,
    sync: bool,
    replica_addr: Option<&str>,
    durability_seen: std::sync::Arc<std::sync::Mutex<Option<String>>>,
) -> Vec<DomainResult> {
    let dir = base.join("mux");
    // Replicated ack policy: device flush leaves the critical path
    // (async cadence); durability comes from the peer holding the bytes.
    let engine_sync = replica_addr.is_none() && sync;
    let engine = MuxEngine::open(&dir, engine_sync).expect("open mux engine");
    let (handle, writer): (MuxHandle, _) = if let Some(addrs) = replica_addr {
        let epoch = engine.current_epoch();
        let len = engine.log_len().expect("log len");
        let log_path = dir.join("muxlog.bin");
        let independent = env_flag("REPLICA_INDEPENDENT", false);
        let replicas: Vec<ReplicaLink> = addrs
            .split(',')
            .map(str::trim)
            .filter(|a| !a.is_empty())
            .map(|a| {
                ReplicaLink::connect(a, independent, epoch, &log_path, len)
                    .expect("connect replica")
            })
            .collect();
        spawn_mux_writer_cfg(
            engine,
            WriterConfig {
                max_batch,
                replicas,
                ack_quorum: env_u64("ACK_QUORUM", 0) as usize,
                flush_every_batches: 0,
                background_flush_ms: env_u64("BG_FLUSH_MS", 200),
            },
        )
    } else {
        spawn_mux_writer(engine, max_batch)
    };
    let filler = "x".repeat(payload_bytes);
    let started = Instant::now();
    let mut joins = Vec::new();
    for d in 0..domains {
        for c in 0..clients {
            let handle = handle.clone();
            let filler = filler.clone();
            let domain = format!("d{d}");
            let per_client = ops_per_domain / clients + u64::from(c < ops_per_domain % clients);
            let obj_lo = c * objects / clients;
            let obj_hi = ((c + 1) * objects / clients).max(obj_lo + 1);
            let durability_seen = durability_seen.clone();
            joins.push(std::thread::spawn(move || {
                let mut lat = Vec::with_capacity(per_client as usize);
                let mut heads: std::collections::HashMap<u64, String> =
                    std::collections::HashMap::new();
                let mut refused = 0u64;
                for i in 0..per_client {
                    let obj = obj_lo + (i % (obj_hi - obj_lo));
                    let op = Operation {
                        domain: domain.clone(),
                        object_ref: format!("bench://{domain}/obj-{obj}"),
                        op_kind: "bench.write".into(),
                        expected_head: heads.get(&obj).cloned(),
                        payload: serde_json::json!({ "i": i, "fill": filler }),
                        recorded_at_ms: now_ms(),
                        idem_key: format!("{domain}-{c}-{i}"),
                    };
                    let t0 = Instant::now();
                    match handle.admit(op) {
                        Ok(ack) => {
                            lat.push(t0.elapsed().as_nanos() as u64);
                            heads.insert(obj, ack.new_head);
                            if i == 0 {
                                let mut g = durability_seen.lock().unwrap();
                                if g.is_none() {
                                    *g = Some(ack.durability.to_string());
                                }
                            }
                        }
                        Err(_) => refused += 1,
                    }
                }
                (domain, lat, refused)
            }));
        }
    }
    let mut per_domain: std::collections::BTreeMap<String, (Vec<u64>, u64)> = Default::default();
    for j in joins {
        let (domain, lat, refused) = j.join().expect("mux client join");
        let e = per_domain.entry(domain).or_default();
        e.0.extend(lat);
        e.1 += refused;
    }
    let wall_s = started.elapsed().as_secs_f64();
    handle.shutdown();
    writer
        .join
        .join()
        .expect("mux writer join")
        .expect("mux writer io");
    per_domain
        .into_iter()
        .map(|(domain, (mut lat, refused))| {
            lat.sort_unstable();
            DomainResult {
                domain,
                admitted: lat.len() as u64,
                refused,
                wall_s,
                lat_sorted_ns: lat,
            }
        })
        .collect()
}

fn main() {
    let ops = env_u64("OPS", 200_000);
    let clients = env_u64("CLIENTS", 8).max(1);
    let objects = env_u64("OBJECTS", 1_024).max(clients);
    let payload = env_u64("PAYLOAD", 256) as usize;
    let domains = env_u64("DOMAINS", 1).max(1);
    let max_batch = env_u64("MAX_BATCH", 4_096) as usize;
    let sync = env_flag("SYNC", true);
    let mux = env_flag("MUX", false);
    let base: PathBuf = std::env::var("DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir().join("agentgres-substrate-bench"));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).expect("create bench dir");

    let cpu = std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("model name"))
                .map(|l| l.split(':').nth(1).unwrap_or("").trim().to_string())
        })
        .unwrap_or_else(|| "unknown".into());
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(0);

    eprintln!(
        "substrate-bench: ops/domain={ops} clients={clients} objects={objects} payload={payload}B domains={domains} max_batch={max_batch} sync={sync}"
    );

    // Phase 1: admission across independent domains (ownership partitioning).
    // MUX=1 combines all domains through ONE multiplexed log: one fsync per
    // combined batch (the single-box flush combiner). MUX=0 gives each
    // domain its own log file (separate fsync streams — the session-1 shape).
    let replica_addr = std::env::var("REPLICA_ADDR").ok();
    let durability_seen = std::sync::Arc::new(std::sync::Mutex::new(None::<String>));
    if replica_addr.is_some() && !mux {
        eprintln!("REPLICA_ADDR requires MUX=1 (replicated ack policy lives on the mux writer)");
        std::process::exit(2);
    }
    let bench_started = Instant::now();
    let results: Vec<DomainResult> = if mux {
        run_mux_all(
            &base,
            domains,
            ops,
            clients,
            objects,
            payload,
            max_batch,
            sync,
            replica_addr.as_deref(),
            durability_seen.clone(),
        )
    } else {
        let mut joins = Vec::new();
        for d in 0..domains {
            let dir = base.join(format!("domain-{d}"));
            joins.push(std::thread::spawn({
                let domain = format!("d{d}");
                move || run_domain(dir, domain, ops, clients, objects, payload, max_batch, sync)
            }));
        }
        joins
            .into_iter()
            .map(|j| j.join().expect("domain join"))
            .collect()
    };
    let aggregate_wall = bench_started.elapsed().as_secs_f64();

    let mut all_lat: Vec<u64> = Vec::new();
    let mut admitted_total = 0u64;
    let mut refused_total = 0u64;
    let mut per_domain = Vec::new();
    for r in &results {
        admitted_total += r.admitted;
        refused_total += r.refused;
        all_lat.extend(&r.lat_sorted_ns);
        per_domain.push(serde_json::json!({
            "domain": r.domain,
            "admitted": r.admitted,
            "refused": r.refused,
            "wall_s": r.wall_s,
            "throughput_ops_s": r.admitted as f64 / r.wall_s,
            "p50_ms": pct(&r.lat_sorted_ns, 0.50),
            "p95_ms": pct(&r.lat_sorted_ns, 0.95),
            "p99_ms": pct(&r.lat_sorted_ns, 0.99),
            "max_ms": pct(&r.lat_sorted_ns, 1.0),
        }));
    }
    all_lat.sort_unstable();
    let aggregate_tp = admitted_total as f64 / aggregate_wall;

    // Phase 2: checkpoint + fork + recovery + projection.
    let (ck_v, fork_v, rec_v, proj_v, recovery_ok);
    if mux {
        let mdir = base.join("mux");
        let t0 = Instant::now();
        let mut e1 = MuxEngine::open(&mdir, sync).expect("mux recovery reopen");
        let recovery_ms = t0.elapsed().as_secs_f64() * 1_000.0;
        let e2 = MuxEngine::open(&mdir, sync).expect("mux second reopen");
        let roots1: Vec<String> = e1
            .domains()
            .map(|d| e1.domain_root(d).unwrap().clone())
            .collect();
        let roots2: Vec<String> = e2
            .domains()
            .map(|d| e2.domain_root(d).unwrap().clone())
            .collect();
        recovery_ok = roots1 == roots2 && !roots1.is_empty();
        let mut ck_times = Vec::new();
        let mut heads_n = 0usize;
        for _ in 0..10 {
            let t0 = Instant::now();
            let ck = e1
                .checkpoint_domain("d0", now_ms())
                .expect("mux checkpoint d0");
            ck_times.push(t0.elapsed().as_secs_f64() * 1_000.0);
            heads_n = ck.heads.len();
        }
        ck_times.sort_by(|a, b| a.partial_cmp(b).unwrap());
        ck_v = serde_json::json!({ "iterations": 10, "median_ms": ck_times[ck_times.len()/2], "heads": heads_n, "scope": "per-domain (d0)" });
        fork_v = serde_json::json!({ "deferred": "mux fork lands session 3; v1 single-domain fork measured in MUX=0 mode" });
        rec_v = serde_json::json!({ "replay_ms": recovery_ms, "heads_and_root_match": recovery_ok, "domains_recovered": roots1.len() });
        proj_v = serde_json::json!({ "deferred": "mux projection replay lands with mux fork" });
    } else {
        let d0 = base.join("domain-0");
        let mut engine = SubstrateEngine::open(&d0, sync).expect("reopen d0");
        let mut ck_times = Vec::new();
        let mut last_ck = None;
        for _ in 0..10 {
            let t0 = Instant::now();
            let ck = engine.checkpoint(now_ms()).expect("checkpoint");
            ck_times.push(t0.elapsed().as_secs_f64() * 1_000.0);
            last_ck = Some(ck);
        }
        ck_times.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let ck = last_ck.unwrap();

        let mut fork_times = Vec::new();
        for i in 0..5 {
            let fdir = base.join(format!("fork-{i}"));
            let t0 = Instant::now();
            SubstrateEngine::fork_from(&ck, &d0, &fdir).expect("fork");
            let forked = SubstrateEngine::open(&fdir, sync).expect("open fork");
            fork_times.push(t0.elapsed().as_secs_f64() * 1_000.0);
            assert_eq!(forked.current_root(), &ck.root, "fork root mismatch");
        }
        fork_times.sort_by(|a, b| a.partial_cmp(b).unwrap());

        let t0 = Instant::now();
        let recovered = SubstrateEngine::open(&d0, sync).expect("recovery reopen");
        let recovery_ms = t0.elapsed().as_secs_f64() * 1_000.0;
        recovery_ok = recovered.current_root() == engine.current_root()
            && recovered.next_seq() == engine.next_seq();

        let t0 = Instant::now();
        let mut frames = 0u64;
        engine
            .project(0, &mut |_f| {
                frames += 1;
            })
            .expect("project");
        let replay_s = t0.elapsed().as_secs_f64();
        ck_v = serde_json::json!({ "iterations": 10, "median_ms": ck_times[ck_times.len()/2], "heads": ck.heads.len() });
        fork_v = serde_json::json!({ "iterations": 5, "median_ms": fork_times[fork_times.len()/2], "o1_claim": "no history bytes copied; head-map seed only" });
        rec_v =
            serde_json::json!({ "replay_ms": recovery_ms, "heads_and_root_match": recovery_ok });
        proj_v = serde_json::json!({ "frames_replayed": frames, "replay_s": replay_s,
                                      "replay_frames_per_s": frames as f64 / replay_s.max(1e-9) });
    }

    let report = serde_json::json!({
        "harness": "agentgres-substrate-bench v0",
        "contract": {
            "targets": { "admission_p99_ms": 5.0, "admission_ops_s_per_domain": 5000.0, "fork_ms": 1000.0 },
            "note": "doctrine performance contract; TPS is explicitly not the contract"
        },
        "hardware": { "cpu": cpu, "threads": threads, "disk": "NVMe (ext4/LVM)" },
        "mode": if replica_addr.is_some() { "mux_replicated_ack" } else if mux { "mux_combined_flush" } else { "separate_domain_logs" },
        "durability": {
            "ack_class": durability_seen.lock().unwrap().clone().unwrap_or_else(|| if sync { "device_flush".into() } else { "buffered".into() }),
            "replica_addr": replica_addr,
            "replica_root_match": std::env::var("REPLICA_DIR").ok().map(|rd| {
                let primary = MuxEngine::open(&base.join("mux"), false).expect("reopen primary");
                let replica = MuxEngine::open(std::path::Path::new(&rd), false).expect("open replica dir");
                primary.domains().all(|d| primary.domain_root(d) == replica.domain_root(d))
                    && primary.domains().count() == replica.domains().count()
            }),
            "note": "replicated_same_host = peer holds the bytes but shares this host's failure domain; quorum_replicated requires failure-independent peers",
        },
        "config": { "ops_per_domain": ops, "clients": clients, "objects": objects,
                     "payload_bytes": payload, "domains": domains, "max_batch": max_batch, "sync_on_commit": sync },
        "admission": {
            "admitted_total": admitted_total,
            "refused_total": refused_total,
            "aggregate_wall_s": aggregate_wall,
            "aggregate_throughput_ops_s": aggregate_tp,
            "overall_p50_ms": pct(&all_lat, 0.50),
            "overall_p95_ms": pct(&all_lat, 0.95),
            "overall_p99_ms": pct(&all_lat, 0.99),
            "overall_max_ms": pct(&all_lat, 1.0),
            "per_domain": per_domain,
        },
        "checkpoint": ck_v,
        "fork": fork_v,
        "recovery": rec_v,
        "projection": proj_v,
    });
    let report_path = base.join("bench-report.json");
    std::fs::write(&report_path, serde_json::to_vec_pretty(&report).unwrap())
        .expect("write report");

    println!("{}", serde_json::to_string_pretty(&report).unwrap());
    eprintln!("report: {}", report_path.display());
    if !recovery_ok {
        eprintln!("FATAL: recovery replay mismatch");
        std::process::exit(1);
    }
}
