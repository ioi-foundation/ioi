use ioi_scs::{
    l2_distance, lower_bound_l2, unit_cosine_distance_to_l2, CoarseQuantizerCluster,
    CoarseQuantizerManifest, LowerBoundMetric, RetrievalSearchPolicy, VectorIndex,
};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

const DIMENSIONS: usize = 48;
const CLUSTER_COUNT: usize = 16;
const BEST_POINTS_PER_CLUSTER: usize = 20;
const WORST_POINTS_PER_CLUSTER: usize = 8;
const BEST_QUERY_COUNT: usize = 16;
const WORST_QUERY_COUNT: usize = 8;
const TOP_K: usize = 8;

#[derive(Clone, Copy, Debug)]
enum ScenarioKind {
    BestCase,
    WorstCase,
}

impl ScenarioKind {
    fn label(self) -> &'static str {
        match self {
            Self::BestCase => "best_case",
            Self::WorstCase => "worst_case",
        }
    }
}

#[derive(Clone, Debug)]
struct Corpus {
    vectors: Vec<Vec<f32>>,
    frame_ids: Vec<u64>,
    cluster_members: BTreeMap<u32, Vec<usize>>,
    queries: Vec<Vec<f32>>,
    quantizer: CoarseQuantizerManifest,
}

#[derive(Clone, Debug)]
struct LatencySummary {
    mean_ms: f64,
    p50_ms: f64,
    p95_ms: f64,
}

#[derive(Clone, Debug)]
struct StrategyStats {
    name: &'static str,
    latency: LatencySummary,
    recall_at_k: f64,
    min_cert_gap_l2: Option<f32>,
    avg_visited_clusters: Option<f64>,
}

#[derive(Clone, Debug)]
struct ExactBaseline {
    results: Vec<Vec<(u64, f32)>>,
    stats: StrategyStats,
}

#[derive(Clone, Debug)]
struct ScenarioReport {
    kind: ScenarioKind,
    exact: StrategyStats,
    fixed_ann: StrategyStats,
    adaptive_ann: StrategyStats,
    certifying: StrategyStats,
}

#[derive(Clone, Copy, Debug)]
struct ClusterBound {
    cluster_id: u32,
    lb_l2: f32,
}

fn env_f64(name: &str, default: f64) -> f64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(default)
}

fn normalize(mut values: Vec<f32>) -> Vec<f32> {
    let norm_sq: f32 = values.iter().map(|v| v * v).sum();
    if norm_sq <= 1e-12 {
        if let Some(first) = values.first_mut() {
            *first = 1.0;
        }
        return values;
    }
    let norm = norm_sq.sqrt();
    for value in &mut values {
        *value /= norm;
    }
    values
}

fn random_unit_vector(rng: &mut StdRng) -> Vec<f32> {
    let mut values = Vec::with_capacity(DIMENSIONS);
    for _ in 0..DIMENSIONS {
        values.push(rng.gen_range(-1.0..1.0));
    }
    normalize(values)
}

fn perturb_unit_vector(base: &[f32], amplitude: f32, rng: &mut StdRng) -> Vec<f32> {
    let mut values = Vec::with_capacity(base.len());
    for value in base {
        let delta = rng.gen_range(-amplitude..amplitude);
        values.push(*value + delta);
    }
    normalize(values)
}

fn l2_distance_local(a: &[f32], b: &[f32]) -> f32 {
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| {
            let d = x - y;
            d * d
        })
        .sum::<f32>()
        .sqrt()
}

fn cosine_distance(a: &[f32], b: &[f32]) -> f32 {
    let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let norm_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let norm_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();

    if norm_a <= 1e-12 || norm_b <= 1e-12 {
        return 1.0;
    }

    let cosine = (dot / (norm_a * norm_b)).clamp(-1.0, 1.0);
    1.0 - cosine
}

fn cmp_distance_then_id(
    left_distance: f32,
    left_id: u64,
    right_distance: f32,
    right_id: u64,
) -> Ordering {
    match left_distance
        .partial_cmp(&right_distance)
        .unwrap_or(Ordering::Equal)
    {
        Ordering::Equal => left_id.cmp(&right_id),
        order => order,
    }
}

fn summarize_latency(latencies_ms: &[f64]) -> LatencySummary {
    let mean_ms = if latencies_ms.is_empty() {
        0.0
    } else {
        latencies_ms.iter().sum::<f64>() / (latencies_ms.len() as f64)
    };

    let percentile = |q: f64| {
        if latencies_ms.is_empty() {
            return 0.0;
        }
        let mut sorted = latencies_ms.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal));
        let idx = ((sorted.len() - 1) as f64 * q).round() as usize;
        sorted[idx.min(sorted.len() - 1)]
    };

    LatencySummary {
        mean_ms,
        p50_ms: percentile(0.50),
        p95_ms: percentile(0.95),
    }
}

fn membership_root(cluster_id: u32, members: &[usize], total_points: usize) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..4].copy_from_slice(&cluster_id.to_le_bytes());
    out[4..12].copy_from_slice(&(members.len() as u64).to_le_bytes());
    out[12..20].copy_from_slice(&(total_points as u64).to_le_bytes());

    let checksum = members.iter().fold(0u64, |acc, idx| {
        acc.wrapping_mul(1_099_511_628_211)
            .wrapping_add((*idx as u64).wrapping_add(1))
    });
    out[20..28].copy_from_slice(&checksum.to_le_bytes());
    out
}

fn build_quantizer(
    vectors: &[Vec<f32>],
    cluster_members: &BTreeMap<u32, Vec<usize>>,
) -> CoarseQuantizerManifest {
    let mut clusters = Vec::with_capacity(cluster_members.len());

    for (cluster_id, members) in cluster_members {
        let mut centroid = vec![0.0f32; DIMENSIONS];
        for member_index in members {
            let vector = &vectors[*member_index];
            for (dim, value) in vector.iter().enumerate() {
                centroid[dim] += *value;
            }
        }

        let inv_count = 1.0f32 / (members.len() as f32);
        for value in &mut centroid {
            *value *= inv_count;
        }

        let mut radius_l2 = 0.0f32;
        for member_index in members {
            let dist = l2_distance_local(&centroid, &vectors[*member_index]);
            if dist > radius_l2 {
                radius_l2 = dist;
            }
        }

        clusters.push(CoarseQuantizerCluster {
            cluster_id: *cluster_id,
            centroid,
            radius_l2,
            member_count: members.len() as u32,
            membership_root: membership_root(*cluster_id, members, vectors.len()),
        });
    }

    CoarseQuantizerManifest::new(1, DIMENSIONS as u32, LowerBoundMetric::L2, true, clusters)
        .expect("quantizer manifest should build")
}

fn build_corpus(kind: ScenarioKind, seed: u64) -> Corpus {
    let mut rng = StdRng::seed_from_u64(seed);
    let shared_base = random_unit_vector(&mut rng);

    let mut centroids = Vec::with_capacity(CLUSTER_COUNT);
    for _ in 0..CLUSTER_COUNT {
        let centroid = match kind {
            ScenarioKind::BestCase => random_unit_vector(&mut rng),
            ScenarioKind::WorstCase => perturb_unit_vector(&shared_base, 0.08, &mut rng),
        };
        centroids.push(centroid);
    }

    let point_noise = match kind {
        ScenarioKind::BestCase => 0.035,
        ScenarioKind::WorstCase => 0.24,
    };

    let query_noise = match kind {
        ScenarioKind::BestCase => 0.020,
        ScenarioKind::WorstCase => 0.16,
    };

    let points_per_cluster = match kind {
        ScenarioKind::BestCase => BEST_POINTS_PER_CLUSTER,
        ScenarioKind::WorstCase => WORST_POINTS_PER_CLUSTER,
    };
    let query_count = match kind {
        ScenarioKind::BestCase => BEST_QUERY_COUNT,
        ScenarioKind::WorstCase => WORST_QUERY_COUNT,
    };

    let mut vectors = Vec::with_capacity(CLUSTER_COUNT * points_per_cluster);
    let mut frame_ids = Vec::with_capacity(CLUSTER_COUNT * points_per_cluster);
    let mut cluster_members: BTreeMap<u32, Vec<usize>> = BTreeMap::new();

    for cluster_index in 0..CLUSTER_COUNT {
        let centroid = &centroids[cluster_index];
        for _ in 0..points_per_cluster {
            let vector = perturb_unit_vector(centroid, point_noise, &mut rng);
            let frame_id = vectors.len() as u64 + 1;
            vectors.push(vector);
            frame_ids.push(frame_id);
            cluster_members
                .entry(cluster_index as u32)
                .or_default()
                .push((frame_id - 1) as usize);
        }
    }

    let mut queries = Vec::with_capacity(query_count);
    for i in 0..query_count {
        let cluster_index = match kind {
            ScenarioKind::BestCase => i % CLUSTER_COUNT,
            ScenarioKind::WorstCase => rng.gen_range(0..CLUSTER_COUNT),
        };
        queries.push(perturb_unit_vector(
            &centroids[cluster_index],
            query_noise,
            &mut rng,
        ));
    }

    let quantizer = build_quantizer(&vectors, &cluster_members);

    Corpus {
        vectors,
        frame_ids,
        cluster_members,
        queries,
        quantizer,
    }
}

fn build_index(corpus: &Corpus) -> VectorIndex {
    let mut index = VectorIndex::new(6, 16);
    for (idx, vector) in corpus.vectors.iter().enumerate() {
        index
            .insert(corpus.frame_ids[idx], vector.clone())
            .expect("index insert should succeed");
    }

    index
        .set_coarse_quantizer(corpus.quantizer.clone())
        .expect("quantizer should install");

    index
}

fn exact_top_k(query: &[f32], corpus: &Corpus, k: usize) -> Vec<(u64, f32)> {
    let mut scored = Vec::with_capacity(corpus.vectors.len());
    for (idx, vector) in corpus.vectors.iter().enumerate() {
        scored.push((corpus.frame_ids[idx], cosine_distance(query, vector)));
    }

    scored.sort_by(|a, b| cmp_distance_then_id(a.1, a.0, b.1, b.0));
    scored.truncate(k);
    scored
}

fn recall_at_k(actual: &[(u64, f32)], expected: &[(u64, f32)]) -> f64 {
    let expected_ids: BTreeSet<u64> = expected.iter().map(|(id, _)| *id).collect();
    if expected_ids.is_empty() {
        return 1.0;
    }

    let hits = actual
        .iter()
        .filter(|(id, _)| expected_ids.contains(id))
        .count();

    (hits as f64) / (expected_ids.len() as f64)
}

fn run_exact_baseline(corpus: &Corpus) -> ExactBaseline {
    let mut latencies_ms = Vec::with_capacity(corpus.queries.len());
    let mut results = Vec::with_capacity(corpus.queries.len());

    for query in &corpus.queries {
        let started = Instant::now();
        let top_k = exact_top_k(query, corpus, TOP_K);
        latencies_ms.push(started.elapsed().as_secs_f64() * 1_000.0);
        results.push(top_k);
    }

    ExactBaseline {
        results,
        stats: StrategyStats {
            name: "exact_scan",
            latency: summarize_latency(&latencies_ms),
            recall_at_k: 1.0,
            min_cert_gap_l2: None,
            avg_visited_clusters: None,
        },
    }
}

fn make_policy(k: usize, ef_search: u32, candidate_limit: u32) -> RetrievalSearchPolicy {
    RetrievalSearchPolicy {
        k: k as u32,
        ef_search,
        candidate_limit: candidate_limit.max(k as u32),
        distance_metric: "cosine_distance".to_string(),
        embedding_normalized: true,
    }
}

fn run_ann_policy(
    index: &VectorIndex,
    corpus: &Corpus,
    exact_results: &[Vec<(u64, f32)>],
    policy: &RetrievalSearchPolicy,
    name: &'static str,
) -> StrategyStats {
    let mut latencies_ms = Vec::with_capacity(corpus.queries.len());
    let mut recall_sum = 0.0f64;

    for (query_idx, query) in corpus.queries.iter().enumerate() {
        let started = Instant::now();
        let mut hits = index
            .search_with_policy(query, policy)
            .expect("ANN search should succeed");
        latencies_ms.push(started.elapsed().as_secs_f64() * 1_000.0);

        hits.sort_by(|a, b| cmp_distance_then_id(a.1, a.0, b.1, b.0));
        if hits.len() > TOP_K {
            hits.truncate(TOP_K);
        }

        recall_sum += recall_at_k(&hits, &exact_results[query_idx]);
    }

    StrategyStats {
        name,
        latency: summarize_latency(&latencies_ms),
        recall_at_k: recall_sum / (corpus.queries.len() as f64),
        min_cert_gap_l2: None,
        avg_visited_clusters: None,
    }
}

fn pick_better_stats(current: &StrategyStats, candidate: &StrategyStats) -> bool {
    let recall_delta = candidate.recall_at_k - current.recall_at_k;
    if recall_delta > 1e-9 {
        return true;
    }

    if recall_delta.abs() <= 1e-9 {
        return candidate.latency.p95_ms < current.latency.p95_ms;
    }

    false
}

fn tune_fixed_ann_policy(
    index: &VectorIndex,
    corpus: &Corpus,
    exact_results: &[Vec<(u64, f32)>],
) -> (RetrievalSearchPolicy, StrategyStats) {
    let candidates: &[(u32, u32)] = &[(24, 64), (48, 96), (64, 128), (96, 192), (128, 256)];

    let mut best: Option<(RetrievalSearchPolicy, StrategyStats)> = None;

    for (ef_search, candidate_limit) in candidates {
        let policy = make_policy(TOP_K, *ef_search, *candidate_limit);
        let stats = run_ann_policy(index, corpus, exact_results, &policy, "fixed_ann");

        match &best {
            None => best = Some((policy, stats)),
            Some((_, current_stats)) => {
                if pick_better_stats(current_stats, &stats) {
                    best = Some((policy, stats));
                }
            }
        }
    }

    best.expect("at least one ANN policy candidate")
}

fn adaptive_ann_search(
    index: &VectorIndex,
    query: &[f32],
    base_ef: u32,
    base_cap: u32,
) -> Vec<(u64, f32)> {
    let mut previous_ids: Option<Vec<u64>> = None;
    let mut best_hits = Vec::new();
    let mut ef = base_ef.max(1);
    let mut cap = base_cap.max(TOP_K as u32);

    for _ in 0..3 {
        let policy = make_policy(TOP_K, ef, cap);
        let mut hits = index
            .search_with_policy(query, &policy)
            .expect("adaptive ANN search should succeed");
        hits.sort_by(|a, b| cmp_distance_then_id(a.1, a.0, b.1, b.0));
        if hits.len() > TOP_K {
            hits.truncate(TOP_K);
        }

        let ids: Vec<u64> = hits.iter().map(|(id, _)| *id).collect();
        if let Some(prev) = &previous_ids {
            if *prev == ids {
                return hits;
            }
        }

        previous_ids = Some(ids);
        best_hits = hits;
        ef = ef.saturating_mul(2);
        cap = cap.saturating_mul(2);
    }

    best_hits
}

fn run_adaptive_ann(
    index: &VectorIndex,
    corpus: &Corpus,
    exact_results: &[Vec<(u64, f32)>],
    base_ef: u32,
    base_cap: u32,
) -> StrategyStats {
    let mut latencies_ms = Vec::with_capacity(corpus.queries.len());
    let mut recall_sum = 0.0f64;

    for (query_idx, query) in corpus.queries.iter().enumerate() {
        let started = Instant::now();
        let hits = adaptive_ann_search(index, query, base_ef, base_cap);
        latencies_ms.push(started.elapsed().as_secs_f64() * 1_000.0);
        recall_sum += recall_at_k(&hits, &exact_results[query_idx]);
    }

    StrategyStats {
        name: "adaptive_ann",
        latency: summarize_latency(&latencies_ms),
        recall_at_k: recall_sum / (corpus.queries.len() as f64),
        min_cert_gap_l2: None,
        avg_visited_clusters: None,
    }
}

fn certifying_branch_and_bound(
    query: &[f32],
    corpus: &Corpus,
    k: usize,
) -> (Vec<(u64, f32)>, Vec<u32>, f32) {
    let mut bounds = Vec::with_capacity(corpus.quantizer.clusters.len());
    for cluster in &corpus.quantizer.clusters {
        let query_centroid_l2 = l2_distance(query, &cluster.centroid)
            .expect("query-centroid l2 distance should compute");
        let lb_l2 = lower_bound_l2(query_centroid_l2, cluster.radius_l2)
            .expect("triangle lower bound should compute");
        bounds.push(ClusterBound {
            cluster_id: cluster.cluster_id,
            lb_l2,
        });
    }

    bounds.sort_by(|left, right| {
        cmp_distance_then_id(
            left.lb_l2,
            left.cluster_id as u64,
            right.lb_l2,
            right.cluster_id as u64,
        )
    });

    let mut visited_ids = Vec::new();
    let mut visited_set = BTreeSet::new();
    let mut top_k = Vec::<(u64, f32)>::with_capacity(k);

    for bound in &bounds {
        let kth_l2 = if top_k.len() >= k {
            unit_cosine_distance_to_l2(top_k[k - 1].1)
                .expect("k-th cosine distance must convert to l2")
        } else {
            f32::INFINITY
        };

        if top_k.len() >= k && bound.lb_l2 + 1e-6 >= kth_l2 {
            break;
        }

        visited_ids.push(bound.cluster_id);
        visited_set.insert(bound.cluster_id);

        let members = corpus
            .cluster_members
            .get(&bound.cluster_id)
            .expect("cluster id must resolve to members");
        for member_index in members {
            let frame_id = corpus.frame_ids[*member_index];
            let distance = cosine_distance(query, &corpus.vectors[*member_index]);
            top_k.push((frame_id, distance));
        }

        top_k.sort_by(|a, b| cmp_distance_then_id(a.1, a.0, b.1, b.0));
        if top_k.len() > k {
            top_k.truncate(k);
        }
    }

    let kth_l2 = if top_k.len() >= k {
        unit_cosine_distance_to_l2(top_k[k - 1].1).expect("k-th cosine distance must convert to l2")
    } else {
        f32::INFINITY
    };

    let mut min_unseen_lb = f32::INFINITY;
    for bound in &bounds {
        if !visited_set.contains(&bound.cluster_id) {
            min_unseen_lb = min_unseen_lb.min(bound.lb_l2);
        }
    }

    let cert_gap = if min_unseen_lb.is_finite() {
        min_unseen_lb - kth_l2
    } else {
        f32::INFINITY
    };

    (top_k, visited_ids, cert_gap)
}

fn run_certifying_search(
    index: &VectorIndex,
    corpus: &Corpus,
    exact_results: &[Vec<(u64, f32)>],
) -> StrategyStats {
    let mut latencies_ms = Vec::with_capacity(corpus.queries.len());
    let mut recall_sum = 0.0f64;
    let mut min_cert_gap_l2 = f32::INFINITY;
    let mut visited_cluster_total = 0usize;

    for (query_idx, query) in corpus.queries.iter().enumerate() {
        let started = Instant::now();
        let (hits, visited_clusters, cert_gap_l2) =
            certifying_branch_and_bound(query, corpus, TOP_K);
        latencies_ms.push(started.elapsed().as_secs_f64() * 1_000.0);

        recall_sum += recall_at_k(&hits, &exact_results[query_idx]);
        min_cert_gap_l2 = min_cert_gap_l2.min(cert_gap_l2);
        visited_cluster_total += visited_clusters.len();

        let kth_cosine_distance = hits
            .last()
            .map(|(_, distance)| *distance)
            .expect("top-k should contain at least one result");
        let kth_l2_distance = unit_cosine_distance_to_l2(kth_cosine_distance)
            .expect("k-th cosine distance must convert to l2");
        let returned_frame_ids: Vec<u64> = hits.iter().map(|(id, _)| *id).collect();

        let certificate = index
            .build_lower_bound_certificate(
                query,
                TOP_K as u32,
                kth_l2_distance,
                returned_frame_ids,
                visited_clusters,
            )
            .expect("lower-bound certificate should build");

        index
            .verify_lower_bound_certificate(query, &certificate)
            .expect("lower-bound certificate should verify");
    }

    StrategyStats {
        name: "certifying_branch_and_bound",
        latency: summarize_latency(&latencies_ms),
        recall_at_k: recall_sum / (corpus.queries.len() as f64),
        min_cert_gap_l2: Some(min_cert_gap_l2),
        avg_visited_clusters: Some(visited_cluster_total as f64 / corpus.queries.len() as f64),
    }
}

fn run_scenario(kind: ScenarioKind, seed: u64) -> ScenarioReport {
    let corpus = build_corpus(kind, seed);
    let index = build_index(&corpus);

    let exact = run_exact_baseline(&corpus);
    let (best_policy, fixed_ann) = tune_fixed_ann_policy(&index, &corpus, &exact.results);
    let adaptive_ann = run_adaptive_ann(
        &index,
        &corpus,
        &exact.results,
        best_policy.ef_search,
        best_policy.candidate_limit,
    );
    let certifying = run_certifying_search(&index, &corpus, &exact.results);

    ScenarioReport {
        kind,
        exact: exact.stats,
        fixed_ann,
        adaptive_ann,
        certifying,
    }
}

fn print_report(reports: &[ScenarioReport]) {
    println!(
        "\n=== mHNSW Retrieval Benchmark (best/worst case) ===\n\
strategy: p50_ms | p95_ms | mean_ms | recall@k | cert_gap_min_l2 | avg_visited_clusters"
    );

    for report in reports {
        println!("\nscenario: {}", report.kind.label());
        for stats in [
            &report.exact,
            &report.fixed_ann,
            &report.adaptive_ann,
            &report.certifying,
        ] {
            let cert_gap = stats
                .min_cert_gap_l2
                .map(|v| format!("{v:.6}"))
                .unwrap_or_else(|| "-".to_string());
            let avg_visited = stats
                .avg_visited_clusters
                .map(|v| format!("{v:.2}"))
                .unwrap_or_else(|| "-".to_string());

            println!(
                "  {:28} {:8.3} {:8.3} {:8.3} {:9.4} {:14} {:18}",
                stats.name,
                stats.latency.p50_ms,
                stats.latency.p95_ms,
                stats.latency.mean_ms,
                stats.recall_at_k,
                cert_gap,
                avg_visited,
            );
        }

        let best_speedup = report.exact.latency.p95_ms / report.certifying.latency.p95_ms.max(1e-9);
        let worst_slowdown =
            report.certifying.latency.p95_ms / report.exact.latency.p95_ms.max(1e-9);
        println!(
            "  derived: certifying_p95_speedup_vs_exact={:.3}x certifying_p95_slowdown_vs_exact={:.3}x",
            best_speedup,
            worst_slowdown,
        );
    }
}

#[test]
#[ignore = "performance harness; run with --ignored --nocapture"]
fn mhnsw_best_worst_speed_profiles() {
    let best = run_scenario(ScenarioKind::BestCase, 0xA11CE_u64);
    let worst = run_scenario(ScenarioKind::WorstCase, 0xBADC0DE_u64);

    print_report(&[best.clone(), worst.clone()]);

    let min_best_speedup = env_f64("IOI_MHNSW_BENCH_MIN_BEST_SPEEDUP", 1.05);
    let max_worst_slowdown = env_f64("IOI_MHNSW_BENCH_MAX_WORST_SLOWDOWN", 1.80);

    let best_speedup = best.exact.latency.p95_ms / best.certifying.latency.p95_ms.max(1e-9);
    let worst_slowdown = worst.certifying.latency.p95_ms / worst.exact.latency.p95_ms.max(1e-9);

    assert!(
        best.certifying.recall_at_k >= 0.9999,
        "certifying strategy must be exact in best-case; got recall@k={:.6}",
        best.certifying.recall_at_k
    );
    assert!(
        worst.certifying.recall_at_k >= 0.9999,
        "certifying strategy must be exact in worst-case; got recall@k={:.6}",
        worst.certifying.recall_at_k
    );

    assert!(
        best.certifying.min_cert_gap_l2.unwrap_or(-1.0) >= -1e-4,
        "best-case cert gap violated: {:?}",
        best.certifying.min_cert_gap_l2
    );
    assert!(
        worst.certifying.min_cert_gap_l2.unwrap_or(-1.0) >= -1e-4,
        "worst-case cert gap violated: {:?}",
        worst.certifying.min_cert_gap_l2
    );

    assert!(
        best_speedup >= min_best_speedup,
        "best-case speedup gate failed: {:.3}x < {:.3}x",
        best_speedup,
        min_best_speedup,
    );
    assert!(
        worst_slowdown <= max_worst_slowdown,
        "worst-case slowdown gate failed: {:.3}x > {:.3}x",
        worst_slowdown,
        max_worst_slowdown,
    );
}
