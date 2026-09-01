// M05.9 — the synthetic corpus generator for the scheduled qualification lane.
//
// SYNTHETIC ONLY. No real recording, no real Session, no real actor media, no real device capture,
// no network fetch, no paid resource, no metered service. The corpus is generated from a declared
// seed, is pure, and is CONTENT-ADDRESSED so the census can bind exact bytes rather than a
// description of them.
//
// WHY IT IS SHAPED THIS WAY. ACC-19 clause 5 asks the scheduled lane to consume input meeting
// M05.9's floor: at least two hours of accepted source time AFTER exact and near-duplicate
// exclusion, at least eight independently bounded episodes/tasks from at least two source Sessions,
// and every profile-required action, field and exception label class. So the generator emits MORE
// raw time than the floor and then throws some away through a dedup path that is actually
// exercised — a corpus that met the floor only because nothing was ever excluded would prove the
// floor and not the exclusion.
//
// THE CORRECTION THIS FILE CARRIES. The first version of this generator did not prove deduplication
// at all. It gave every row a `content_sha256` of `sha256(<short id string>)` — a digest of a LABEL,
// not of any bytes — while claiming a `byte_count` near 1.2 MB that nothing produced or measured.
// Worse, its "exact duplicates" each received their OWN unique digest, so two rows never shared a
// payload, and the v1 contract of the day refused any repeated digest outright. A real exact
// duplicate was therefore not merely absent from the corpus, it was UNREPRESENTABLE, and
// `exact_duplicate` was a label no corpus could earn. Everything below is built the other way
// round: bytes first, digests of those bytes, counts summed from those bytes.
//
// IDENTITY IS NOT CONTENT. `source_file_ref` identifies a raw source INSTANCE and is unique; a
// `content_sha256` identifies its PAYLOAD and may legitimately repeat. An exact duplicate is
// precisely two distinct source refs over one payload digest, with exactly one instance accepted.
//
// NEAR DUPLICATION IS RE-DECIDABLE. Exact duplication is decidable from a digest; near duplication
// is a judgement, so a near-duplicate payload here is DERIVED FROM the retained payload by a bounded
// block edit, and the declared distance is recomputed from both fingerprints under the declared
// method. Generating an unrelated payload and asserting `distance = 3` beside it would produce a row
// nobody could recheck against the sibling it names.
//
// THE ADVERSARIAL MEMBERS ARE DELIBERATE. A corrupt chunk, a truncated file, a variable-rate
// segment, a padded silent span, an exact duplicate and a near-duplicate are all generated ON
// PURPOSE, because each must be refused or excluded BY NAME rather than absorbed. A generator that
// emitted only clean material would let a pipeline that absorbs defects look identical to one that
// refuses them.
//
// DURATION AND DIVERSITY ARE THE FLOORS; FIDELITY IS NOT. Payloads are small synthetic blocks, which
// is how the whole corpus stays far under the 2 GiB ceiling and needs no GPU runner or object
// storage. NO THROUGHPUT OR LATENCY NUMBER IS PRODUCED OR CLAIMED ANYWHERE IN THIS FILE.

import crypto from "node:crypto";

const sha256Hex = (text) => crypto.createHash("sha256").update(text).digest("hex");
const sha256 = (bytes) => `sha256:${crypto.createHash("sha256").update(bytes).digest("hex")}`;

export const NEAR_DUPLICATE_METHOD = "perceptual-block-mean-hamming-64";
export const NEAR_DUPLICATE_THRESHOLD = 8;
export const EXACT_KEY_ALGORITHM = "sha256";

const BLOCKS = 64;
const PAYLOAD_BYTES = 65536;
const BLOCK_WIDTH = PAYLOAD_BYTES / BLOCKS;
const LOW = 40;
const HIGH = 210;
const FRAMES_PER_SECOND = 30;
const CHUNKS_PER_FILE = 12;

/**
 * A deterministic payload: 64 blocks each held at one of two levels, chosen by the seed's bits.
 *
 * THE TWO-LEVEL STRUCTURE IS LOAD-BEARING, not decoration. It keeps every block sum far from the
 * mean, so flipping one block moves the mean far too little to disturb any other block's bit — which
 * is what makes a bounded edit produce a bounded Hamming distance. Pseudo-random block content sits
 * within about one standard deviation of the mean, so a single-block edit there cascades into a
 * dozen bit flips and "bounded edit" stops implying "small distance".
 */
export function payloadBytes(tag, flippedBlocks = []) {
  const seed = crypto.createHash("sha256").update(`ioi.m059.corpus.payload:${tag}`).digest();
  const bytes = Buffer.alloc(PAYLOAD_BYTES);
  for (let block = 0; block < BLOCKS; block += 1) {
    const bit = (seed[block >> 3] >> (block & 7)) & 1;
    const level = (bit === 1) !== flippedBlocks.includes(block) ? HIGH : LOW;
    bytes.fill(level, block * BLOCK_WIDTH, (block + 1) * BLOCK_WIDTH);
  }
  return bytes;
}

/**
 * THE RECIPE IS THE CUSTODY SEAM. It states the payload as a function the DAEMON re-runs, so
 * `content_sha256`, `byte_count` and `similarity_fingerprint` stop being three caller-supplied
 * strings that agree with each other and become three values the runtime derives for itself. Without
 * it a wholly fabricated but internally consistent corpus would satisfy every cross-check the record
 * can express, and no amount of label-to-label validation would notice.
 */
export function payloadRecipe(tag, flippedBlocks = []) {
  return {
    recipe_method: "ioi.m059.two-level-block-payload.v1",
    seed_tag: tag,
    block_count: BLOCKS,
    block_width_bytes: BLOCK_WIDTH,
    low_level: LOW,
    high_level: HIGH,
    flipped_blocks: [...flippedBlocks].sort((a, b) => a - b),
  };
}

/**
 * `perceptual-block-mean-hamming-64` — the declared near-duplicate method, as an actual function.
 *
 * The payload is cut into 64 equal blocks and bit i is set when block i's byte sum exceeds the mean
 * block sum. A cryptographic digest would be useless here: any edit moves about half its bits, so
 * every pair of payloads would sit near distance 32 and "near" would carry no information at all.
 */
export function similarityFingerprint(bytes) {
  const width = Math.floor(bytes.length / BLOCKS);
  const sums = [];
  for (let block = 0; block < BLOCKS; block += 1) {
    let sum = 0;
    for (let at = block * width; at < (block + 1) * width; at += 1) sum += bytes[at];
    sums.push(sum);
  }
  const mean = sums.reduce((total, value) => total + value, 0) / BLOCKS;
  let hex = "";
  for (let nibble = 0; nibble < 16; nibble += 1) {
    let value = 0;
    for (let bit = 0; bit < 4; bit += 1) value = (value << 1) | (sums[nibble * 4 + bit] > mean ? 1 : 0);
    hex += value.toString(16);
  }
  return hex;
}

/** The distance between two equal-length lowercase-hex fingerprints. Recomputed, never asserted. */
export function hammingDistance(left, right) {
  if (typeof left !== "string" || left.length !== right.length || left.length === 0) return null;
  let distance = 0;
  for (let i = 0; i < left.length; i += 1) {
    const a = Number.parseInt(left[i], 16);
    const b = Number.parseInt(right[i], 16);
    if (Number.isNaN(a) || Number.isNaN(b)) return null;
    let diff = a ^ b;
    while (diff) {
      distance += diff & 1;
      diff >>= 1;
    }
  }
  return distance;
}

/** The bounded, deterministic block set a near variant of `tag` flips. */
export function nearVariantFlips(seed) {
  const flipped = new Set();
  for (let i = 0; i <= seed % NEAR_DUPLICATE_THRESHOLD; i += 1) flipped.add((seed * 7 + i * 11) % BLOCKS);
  return [...flipped];
}

export const PROFILES = Object.freeze([
  "composed-model-harness",
  "interactive-learned",
  "synthetic-learned-sensitive",
]);

/**
 * The label vocabulary each profile REQUIRES. Every class here must appear in the generated corpus
 * or the census's coverage rule refuses — which is what stops a large corpus over a narrow
 * vocabulary passing as coverage.
 */
export function requiredLabelClasses(profile) {
  const shared = [
    "label-class://ioi/action/click",
    "label-class://ioi/action/drag",
    "label-class://ioi/action/keypress",
    "label-class://ioi/field/record-id",
    "label-class://ioi/field/amount",
    "label-class://ioi/exception/operator-abort",
    "label-class://ioi/exception/timeout",
  ];
  if (profile === "interactive-learned") {
    return [...shared, "label-class://ioi/action/continuous-control", "label-class://ioi/exception/controller-disconnect"];
  }
  if (profile === "synthetic-learned-sensitive") {
    return [...shared, "label-class://ioi/field/reviewer-correction", "label-class://ioi/exception/policy-refusal"];
  }
  return [...shared, "label-class://ioi/action/tool-call"];
}

/**
 * Generate one synthetic corpus.
 *
 * Returns the raw file set, the disposition of every file, the payload table, the near-duplicate
 * exclusions, the derived censuses and the episode plan — everything the scheduled lane needs to
 * admit real snapshots, episodes, a split manifest and a census WITHOUT inventing numbers: every
 * count below is SUMMED FROM the generated members, and every digest is of generated bytes.
 */
export function generateCorpus({ profile, seed = "m059-default", sessions = 3, episodesPerSession = 4 }) {
  if (!PROFILES.includes(profile)) {
    throw new Error(`unknown profile '${profile}'; expected one of ${PROFILES.join(", ")}`);
  }
  const required = requiredLabelClasses(profile);
  const family = `${profile}.${seed}`.replace(/[^a-z0-9._-]/gu, "-");

  const files = [];
  const episodes = [];
  const payloads = new Map();
  const nearExclusions = [];
  let tick = 0;

  const bytesBySource = new Map();
  const ingest = ({ ref, tag, flipped = [], disposition, reason_class, seconds, session_index, episode_index }) => {
    const bytes = payloadBytes(tag, flipped);
    const digest = sha256(bytes);
    const row = {
      source_file_ref: `media-file://${family}/${ref}`,
      content_sha256: digest,
      byte_count: bytes.length,
      disposition,
      reason_class,
      source_seconds: seconds,
      session_index,
      episode_index,
    };
    files.push(row);
    bytesBySource.set(row.source_file_ref, bytes);
    if (!payloads.has(digest)) {
      payloads.set(digest, {
        content_sha256: digest,
        canonical_source_file_ref: row.source_file_ref,
        instance_count: 0,
        byte_count: bytes.length,
        similarity_fingerprint: similarityFingerprint(bytes),
        payload_recipe: payloadRecipe(tag, flipped),
      });
    }
    payloads.get(digest).instance_count += 1;
    return row;
  };

  // ---- the clean, accepted material -------------------------------------------------------------
  // 3 Sessions x 4 episodes x 23 chunks x 30 s = 8280 accepted seconds, which clears the 7200-second
  // floor with headroom rather than sitting exactly on it. A corpus tuned to land ON the floor would
  // turn any future exclusion into a spurious failure, and the floor is a floor, not a target.
  const chunkSeconds = 30;
  const chunksPerEpisode = 23;
  const acceptedTags = [];
  for (let s = 0; s < sessions; s += 1) {
    for (let e = 0; e < episodesPerSession; e += 1) {
      const episodeIndex = episodes.length;
      const startTick = tick;
      let episodeFiles = 0;
      for (let c = 0; c < chunksPerEpisode; c += 1) {
        const tag = `${family}:s${s}:e${e}:c${c}`;
        acceptedTags.push(tag);
        ingest({
          ref: `session-${s}/episode-${e}/chunk-${String(c).padStart(4, "0")}`,
          tag,
          disposition: "accepted",
          reason_class: null,
          seconds: chunkSeconds,
          session_index: s,
          episode_index: episodeIndex,
        });
        episodeFiles += 1;
        tick += chunkSeconds * 1000;
      }
      // Every required label class appears somewhere; the episode that owns each is deterministic.
      const labels = required.filter((_, index) => index % episodesPerSession === e || episodeIndex === 0);
      episodes.push({
        episode_index: episodeIndex,
        session_index: s,
        start_tick: startTick,
        end_tick: tick,
        label_classes: labels.length ? labels : [required[episodeIndex % required.length]],
        actor_partition_key: `actor-${s}`,
        world_partition_key: `world-${s}`,
        file_count: episodeFiles,
      });
    }
  }

  // ---- the deliberate adversarial members --------------------------------------------------------
  // Each is REFUSED by name. They inflate the RAW census and never the accepted one, which is
  // exactly the arithmetic a padded corpus cannot reproduce.
  const adversarial = [
    { kind: "corrupt", reason_class: "corrupt", seconds: 30 },
    { kind: "truncated", reason_class: "truncated", seconds: 18 },
    { kind: "variable-rate", reason_class: "variable_rate", seconds: 30 },
    { kind: "padded-silence", reason_class: "padded", seconds: 60 },
    { kind: "out-of-rights", reason_class: "out_of_rights", seconds: 45 },
  ];
  for (const [index, entry] of adversarial.entries()) {
    ingest({
      ref: `rejected/${entry.kind}-${index}`,
      tag: `${family}:rejected:${entry.kind}:${index}`,
      disposition: "rejected",
      reason_class: entry.reason_class,
      seconds: entry.seconds,
      session_index: 0,
      episode_index: null,
    });
  }

  // EXACT DUPLICATES: a NEW source instance re-ingesting an ALREADY ACCEPTED payload byte for byte.
  // The canonical instance stays accepted and every repeat is excluded, so `raw` grows and
  // `accepted` cannot. This is the case the first contract made unrepresentable.
  const exactDuplicates = 14;
  for (let index = 0; index < exactDuplicates; index += 1) {
    const tag = acceptedTags[(index * 17) % acceptedTags.length];
    ingest({
      ref: `reingest/${String(index).padStart(4, "0")}`,
      tag,
      disposition: "deduplicated",
      reason_class: "exact_duplicate",
      seconds: chunkSeconds,
      session_index: 0,
      episode_index: null,
    });
  }

  // NEAR DUPLICATES: derived from a retained accepted payload by a bounded block edit, with the
  // distance MEASURED between the two fingerprints rather than declared beside them.
  const nearDuplicates = 12;
  for (let index = 0; index < nearDuplicates; index += 1) {
    const tag = acceptedTags[(index * 23) % acceptedTags.length];
    const retainedRow = files.find((row) => row.content_sha256 === sha256(payloadBytes(tag)) && row.disposition === "accepted");
    const flipped = nearVariantFlips(index + 1);
    const fingerprint = similarityFingerprint(payloadBytes(tag, flipped));
    const retainedFingerprint = similarityFingerprint(payloadBytes(tag));
    const distance = hammingDistance(fingerprint, retainedFingerprint);
    if (distance === null || distance === 0 || distance > NEAR_DUPLICATE_THRESHOLD) {
      throw new Error(`near variant ${index} measured ${distance}, outside (0, ${NEAR_DUPLICATE_THRESHOLD}]`);
    }
    const row = ingest({
      ref: `near/${String(index).padStart(4, "0")}`,
      tag,
      flipped,
      disposition: "deduplicated",
      reason_class: "near_duplicate",
      seconds: chunkSeconds,
      session_index: 0,
      episode_index: null,
    });
    nearExclusions.push({
      source_file_ref: row.source_file_ref,
      retained_source_file_ref: retainedRow.source_file_ref,
      cluster_id: `cluster-${String(index % 6).padStart(2, "0")}`,
      similarity_method: NEAR_DUPLICATE_METHOD,
      similarity_fingerprint: fingerprint,
      retained_similarity_fingerprint: retainedFingerprint,
      distance,
      threshold: NEAR_DUPLICATE_THRESHOLD,
    });
  }

  // ---- derive every census number FROM THE MEMBERS ------------------------------------------------
  const sum = (rows, key) => rows.reduce((total, row) => total + row[key], 0);
  const accepted = files.filter((f) => f.disposition === "accepted");
  const rejected = files.filter((f) => f.disposition === "rejected");
  const deduplicated = files.filter((f) => f.disposition === "deduplicated");
  const block = (rows) => ({
    source_seconds: sum(rows, "source_seconds"),
    file_count: rows.length,
    byte_count: sum(rows, "byte_count"),
    frame_or_sample_count: sum(rows, "source_seconds") * FRAMES_PER_SECOND,
    chunk_count: rows.length * CHUNKS_PER_FILE,
  });

  const observedLabelClasses = [...new Set(episodes.flatMap((e) => e.label_classes))].sort();
  const acceptedBlock = block(accepted);

  // The disposition rows carry ONLY the contract's own fields; the session/episode indices above are
  // the generator's bookkeeping and never travel into the census.
  const file_dispositions = files.map((row) => ({
    source_file_ref: row.source_file_ref,
    content_sha256: row.content_sha256,
    byte_count: row.byte_count,
    disposition: row.disposition,
    reason_class: row.reason_class,
    source_seconds: row.source_seconds,
  }));

  return {
    profile,
    seed,
    family,
    files,
    episodes,
    required_label_classes: required,
    observed_label_classes: observedLabelClasses,
    deduplication_policy: {
      exact_key_algorithm: EXACT_KEY_ALGORITHM,
      near_duplicate_method: NEAR_DUPLICATE_METHOD,
      near_duplicate_threshold: NEAR_DUPLICATE_THRESHOLD,
    },
    // Recipe-borne custody: the daemon regenerates every payload and derives its digest, length and
    // fingerprint itself. Nothing here claims custody of imported media bytes.
    payload_custody: "deterministic_recipe",
    file_dispositions,
    distinct_payloads: [...payloads.values()],
    near_duplicate_exclusions: nearExclusions,
    raw: block(files),
    accepted: {
      // BEFORE exclusion includes the excluded time; AFTER excludes it. The floor is measured
      // against AFTER, which is the only honest place to measure it.
      seconds_before_deduplication: acceptedBlock.source_seconds + sum(deduplicated, "source_seconds"),
      seconds_after_deduplication: acceptedBlock.source_seconds,
      file_count: acceptedBlock.file_count,
      byte_count: acceptedBlock.byte_count,
      frame_or_sample_count: acceptedBlock.frame_or_sample_count,
      chunk_count: acceptedBlock.chunk_count,
      bounded_episode_count: episodes.length,
      task_count: episodes.length,
      source_session_count: sessions,
      label_count: episodes.reduce((total, e) => total + e.label_classes.length, 0),
    },
    rejected: {
      ...block(rejected),
      reason_classes: [...new Set(rejected.map((f) => f.reason_class))].sort(),
    },
    deduplicated: {
      ...block(deduplicated),
      reason_classes: [...new Set(deduplicated.map((f) => f.reason_class))].sort(),
      exact_duplicate_file_count: deduplicated.filter((f) => f.reason_class === "exact_duplicate").length,
      near_duplicate_file_count: nearExclusions.length,
    },
  };
}

/**
 * THE FULL NEAR-DUPLICATE CLOSURE, EXECUTED — the offline half of what the runtime re-checks.
 *
 * Resolves each exclusion's source ref to exactly one `deduplicated`/`near_duplicate` row, its
 * retained ref to exactly one `accepted` row, both rows' digests through the payload table, then
 * RECOMPUTES both fingerprints FROM THE ACTUAL PAYLOAD BYTES and the distance from those
 * fingerprints, requiring exact equality and `0 < distance <= threshold`. A checker that stopped at
 * the labels would pass an exclusion whose fingerprints belonged to other payloads entirely.
 *
 * Returns an array of human-readable failures; empty means the closure holds.
 */
export function nearDuplicateClosureFailures(corpus, bytesFor) {
  const failures = [];
  const rowBySource = new Map(corpus.file_dispositions.map((row) => [row.source_file_ref, row]));
  const payloadByDigest = new Map(corpus.distinct_payloads.map((p) => [p.content_sha256, p]));
  const threshold = corpus.deduplication_policy.near_duplicate_threshold;
  const seen = new Set();
  for (const exclusion of corpus.near_duplicate_exclusions) {
    const at = exclusion.source_file_ref;
    if (seen.has(at)) failures.push(`${at}: excluded twice`);
    seen.add(at);
    if (exclusion.similarity_method !== corpus.deduplication_policy.near_duplicate_method) {
      failures.push(`${at}: judged under an undeclared method '${exclusion.similarity_method}'`);
      continue;
    }
    if (exclusion.threshold !== threshold) {
      failures.push(`${at}: carries threshold ${exclusion.threshold} against a declared ${threshold}`);
      continue;
    }
    const sourceRow = rowBySource.get(at);
    if (!sourceRow) { failures.push(`${at}: excluded but present in no disposition row`); continue; }
    if (sourceRow.disposition !== "deduplicated" || sourceRow.reason_class !== "near_duplicate") {
      failures.push(`${at}: filed as ${sourceRow.disposition}/${sourceRow.reason_class}, not as a near duplicate`);
      continue;
    }
    const retainedRow = rowBySource.get(exclusion.retained_source_file_ref);
    if (!retainedRow) { failures.push(`${at}: retains ${exclusion.retained_source_file_ref}, present in no row`); continue; }
    if (retainedRow.disposition !== "accepted") {
      failures.push(`${at}: retains ${retainedRow.source_file_ref}, which is ${retainedRow.disposition} and not accepted`);
      continue;
    }
    if (sourceRow.content_sha256 === retainedRow.content_sha256) {
      failures.push(`${at}: shares its retained sibling's payload exactly — that is an exact duplicate`);
      continue;
    }
    const sourcePayload = payloadByDigest.get(sourceRow.content_sha256);
    const retainedPayload = payloadByDigest.get(retainedRow.content_sha256);
    if (!sourcePayload || !retainedPayload) { failures.push(`${at}: a cited payload is absent from the payload table`); continue; }
    // RECOMPUTED FROM THE BYTES THEMSELVES, which is the step no record-only check can perform.
    const sourceBytes = bytesFor(sourceRow.source_file_ref);
    const retainedBytes = bytesFor(retainedRow.source_file_ref);
    if (!sourceBytes || !retainedBytes) { failures.push(`${at}: payload bytes are unavailable for recomputation`); continue; }
    if (sha256(sourceBytes) !== sourceRow.content_sha256) failures.push(`${at}: payload bytes do not digest to the row's content hash`);
    if (sha256(retainedBytes) !== retainedRow.content_sha256) failures.push(`${at}: retained payload bytes do not digest to its row's content hash`);
    const sourceFingerprint = similarityFingerprint(sourceBytes);
    const retainedFingerprint = similarityFingerprint(retainedBytes);
    if (sourcePayload.similarity_fingerprint !== sourceFingerprint) {
      failures.push(`${at}: the payload table's fingerprint ${sourcePayload.similarity_fingerprint} is not the one its bytes produce (${sourceFingerprint})`);
    }
    if (retainedPayload.similarity_fingerprint !== retainedFingerprint) {
      failures.push(`${at}: the retained payload's table fingerprint ${retainedPayload.similarity_fingerprint} is not the one its bytes produce (${retainedFingerprint})`);
    }
    if (exclusion.similarity_fingerprint !== sourceFingerprint) {
      failures.push(`${at}: cites fingerprint ${exclusion.similarity_fingerprint} while its bytes produce ${sourceFingerprint}`);
    }
    if (exclusion.retained_similarity_fingerprint !== retainedFingerprint) {
      failures.push(`${at}: cites its sibling's fingerprint as ${exclusion.retained_similarity_fingerprint} while those bytes produce ${retainedFingerprint}`);
    }
    const distance = hammingDistance(sourceFingerprint, retainedFingerprint);
    if (distance === null) { failures.push(`${at}: fingerprints are not comparable`); continue; }
    if (exclusion.distance !== distance) failures.push(`${at}: declares distance ${exclusion.distance} against a recomputed ${distance}`);
    if (distance === 0) failures.push(`${at}: is at distance 0 — an exact duplicate, not a near one`);
    if (distance > threshold) failures.push(`${at}: is ${distance} away, past the declared threshold of ${threshold}`);
  }
  const nearRows = corpus.file_dispositions
    .filter((row) => row.disposition === "deduplicated" && row.reason_class === "near_duplicate")
    .map((row) => row.source_file_ref);
  for (const row of nearRows) {
    if (!seen.has(row)) failures.push(`${row}: filed as a near duplicate with no exclusion showing its working`);
  }
  return failures;
}

/**
 * The bytes behind any generated source ref, RE-DERIVED FROM THE PUBLISHED RECIPE rather than
 * handed back from the generator's own memory. That matters: a resolver that returned the bytes it
 * happened to build would prove the generator self-consistent and nothing else, whereas re-running
 * the recipe the census actually carries is the same act the daemon performs on admission.
 */
export function corpusBytesResolver(corpus) {
  const rowBySource = new Map(corpus.file_dispositions.map((row) => [row.source_file_ref, row]));
  const recipeByDigest = new Map(corpus.distinct_payloads.map((p) => [p.content_sha256, p.payload_recipe]));
  return (sourceRef) => {
    const row = rowBySource.get(sourceRef);
    if (!row) return null;
    const recipe = recipeByDigest.get(row.content_sha256);
    if (!recipe || recipe.recipe_method !== "ioi.m059.two-level-block-payload.v1") return null;
    return payloadBytes(recipe.seed_tag, recipe.flipped_blocks);
  };
}
