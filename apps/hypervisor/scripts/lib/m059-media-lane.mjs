// M05.9 — the ONE lane both M05.9 harnesses drive.
//
// The deterministic gate and the scheduled scale soak ask different questions of the same runtime,
// and they must ask them of the SAME daemon lifecycle, the SAME owner seams and the SAME route set.
// A soak that stood up its own isolated daemon, its own seed chain and its own route constants would
// be a second spine: it could pass while the blocking gate's spine was broken, or drift from it
// silently, and the two greens would no longer be about one system.
//
// NOTHING HERE ASSERTS. This module opens and closes a daemon, seeds the M05.7/M05.8/M10.3 owners
// each family binds, and hands back refs. Every judgement lives in the harness that imports it.

import crypto from "node:crypto";
import fs from "node:fs";
import { spawn, spawnSync } from "node:child_process";
import net from "node:net";
import os from "node:os";
import path from "node:path";

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
export const code = (j) => j?.error?.code ?? j?.code ?? "";
export const canonicalJson = (value) => {
  if (value === null || value === undefined || typeof value !== "object") return JSON.stringify(value ?? null);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
    .join(",")}}`;
};
export const sha256 = (text) => `sha256:${crypto.createHash("sha256").update(text).digest("hex")}`;

export const ROUTES_V1 = Object.freeze({
  OV: "/v1/hypervisor/ontology-versions",
  MAP: "/v1/hypervisor/connector-mapping-revisions",
  REC: "/v1/hypervisor/data-recipe-revisions",
  ROUTE_RIGHTS: "/v1/hypervisor/model-route-rights-contracts",
  CLAIMS: "/v1/hypervisor/learning-source-rights-claims",
  RUNS: "/v1/hypervisor/transformation-runs",
  SNAPS: "/v1/hypervisor/media-snapshot-revisions",
  EPISODES: "/v1/hypervisor/observation-action-episode-revisions",
  SPLITS: "/v1/hypervisor/dataset-split-manifest-revisions",
  CENSUSES: "/v1/hypervisor/media-corpus-censuses",
  IMPACT: "/v1/hypervisor/media-snapshot-revisions/erasure-impact",
});

export const OWNER = "org://local";
export const TENANT = "tenant://local";
export const POLICY = `sha256:${"77".repeat(32)}`;

/** THE corpus root, defined once — the registered invariant and the runtime both compute exactly this. */
export const corpusContentRoot = (body) =>
  sha256(
    canonicalJson({
      domain: "ioi.media-corpus-content-root-jcs-sha256.v1",
      file_dispositions: body.file_dispositions,
      distinct_payloads: body.distinct_payloads,
      near_duplicate_exclusions: body.near_duplicate_exclusions,
      deduplication_policy: body.deduplication_policy,
      raw: body.raw,
      accepted: body.accepted,
      rejected: body.rejected,
      deduplicated: body.deduplicated,
    }),
  );

/**
 * The daemon under test, PINNED INSIDE THIS WORKTREE.
 *
 * `IOI_HYPERVISOR_DAEMON_BINARY` and `CARGO_TARGET_DIR` are honoured — a warm shared target dir is
 * normal here — but only when they resolve INSIDE the tree being verified. An env var that silently
 * pointed at another checkout's binary would produce a green run about a different tree, and the
 * green would be indistinguishable from one about this one. That is the worst failure a harness can
 * have, so it is refused loudly rather than trusted.
 */
export function resolveDaemonBinary(root) {
  const inside = (candidate) => {
    const resolved = path.resolve(candidate);
    const base = path.resolve(root);
    return resolved === base || resolved.startsWith(`${base}${path.sep}`);
  };
  const declared = process.env.IOI_HYPERVISOR_DAEMON_BINARY
    ? path.resolve(process.env.IOI_HYPERVISOR_DAEMON_BINARY)
    : process.env.CARGO_TARGET_DIR
      ? path.resolve(process.env.CARGO_TARGET_DIR, "debug", "hypervisor-daemon")
      : null;
  const fallback = path.join(root, "target", "debug", "hypervisor-daemon");
  if (declared === null) return fallback;
  if (!inside(declared)) {
    throw new Error(
      `the daemon binary ${declared} resolves outside the worktree under test (${path.resolve(root)}); ` +
        "a harness that verified another checkout's binary would report a green about a tree nobody changed",
    );
  }
  return declared;
}

const freePort = () =>
  new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.on("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });

/**
 * Open an isolated daemon over a scratch data dir.
 *
 * `root` is the repo root; there is deliberately no env-overridable root, so a harness cannot be
 * pointed at a tree other than the one under test.
 */
export function createLane({ root, label }) {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), `${label}-`));
  const dataDir = path.join(scratch, "data");
  const sessions = { A: "", B: "" };
  let daemon = null;
  let daemonLog = "";
  let base = "";
  let starts = 0;
  let interruptions = 0;
  let peakResidentBytes = 0;

  /**
   * The daemon's PEAK resident set, read from the kernel rather than asserted.
   *
   * `VmHWM` is the high-water mark, so it survives the process shrinking again, and it is sampled
   * BEFORE each stop because the value disappears with the process. A census that carried a
   * hard-coded `peak_resident_bytes` would be reporting a number nobody measured.
   */
  const sampleResident = () => {
    if (!daemon?.pid) return;
    try {
      const status = fs.readFileSync(`/proc/${daemon.pid}/status`, "utf8");
      const hwm = /^VmHWM:\s+(\d+)\s+kB$/mu.exec(status);
      if (hwm) peakResidentBytes = Math.max(peakResidentBytes, Number(hwm[1]) * 1024);
    } catch {
      /* the process may already be gone; the previous sample stands */
    }
  };

  const daemonBinary = () => resolveDaemonBinary(root);

  const rebuildDaemon = () => {
    const build = spawnSync("cargo", ["build", "--locked", "-p", "ioi-node", "--bin", "hypervisor-daemon"], {
      cwd: root,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    if (build.status !== 0) throw new Error(`daemon did not build:\n${build.stderr?.slice(-4000)}`);
  };

  const waitFor = async (url, timeoutMs = 120000) => {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      try {
        const response = await fetch(url);
        if (response.status < 500) return true;
      } catch {
        /* not listening yet */
      }
      await sleep(120);
    }
    return false;
  };

  const start = async () => {
    const port = await freePort();
    base = `http://127.0.0.1:${port}`;
    daemon = spawn(daemonBinary(), [], {
      env: {
        ...process.env,
        IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${port}`,
        IOI_HYPERVISOR_DATA_DIR: dataDir,
        IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:1",
        IOI_WALLET_SECRET_PASS: `ioi-${label}`,
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    daemon.stdout.on("data", (chunk) => {
      daemonLog = `${daemonLog}${chunk}`.slice(-64000);
    });
    daemon.stderr.on("data", (chunk) => {
      daemonLog = `${daemonLog}${chunk}`.slice(-64000);
    });
    if (!(await waitFor(`${base}/healthz`))) throw new Error("the isolated daemon never became healthy");
    starts += 1;
  };

  const stop = async () => {
    if (!daemon) return;
    sampleResident();
    interruptions += 1;
    const child = daemon;
    daemon = null;
    try {
      child.kill("SIGTERM");
    } catch {
      /* already gone */
    }
    await Promise.race([
      new Promise((resolve) => child.once("exit", resolve)),
      sleep(4000).then(() => {
        try {
          child.kill("SIGKILL");
        } catch {
          /* already gone */
        }
      }),
    ]);
    await sleep(150);
  };

  const cleanup = () => {
    try {
      daemon?.kill("SIGKILL");
    } catch {
      /* already gone */
    }
    try {
      fs.rmSync(scratch, { recursive: true, force: true });
    } catch {
      /* best effort */
    }
  };

  const req = async (method, url, body, opts = {}) => {
    const as = "as" in opts ? opts.as : "A";
    const headers = { "content-type": "application/json" };
    if (as && sessions[as]) headers.cookie = `ioi_session=${sessions[as]}`;
    try {
      const response = await fetch(`${base}${url}`, {
        method,
        headers,
        body: body === null || body === undefined ? undefined : JSON.stringify(body),
      });
      const text = await response.text();
      let json = null;
      try {
        json = JSON.parse(text);
      } catch {
        /* non-json */
      }
      return { status: response.status, j: json, text };
    } catch (error) {
      return { status: 0, j: { transport_error: String(error) }, text: String(error) };
    }
  };

  /**
   * Bootstrap the isolated daemon's first owner session from the token it printed to its OWN log.
   *
   * Authentication is part of the lifecycle, not a detail each harness re-implements: a gate that
   * bootstrapped and a soak that did not would be exercising two different authorisation postures
   * against what its header called one spine.
   */
  const bootstrap = async (password) => {
    const token = daemonLog.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
    const boot = await req("POST", "/v1/hypervisor/auth/bootstrap", { token, password }, { as: null });
    sessions.A = boot.j?.session_token ?? "";
    return { status: boot.status, email: boot.j?.email ?? "owner@ioi.local", sessionToken: sessions.A };
  };

  /** Re-establish the session after a restart; the process is new, the durable truth is not. */
  const login = async (email, password) => {
    const relogin = await req("POST", "/v1/hypervisor/auth/login", { email, password }, { as: null });
    if (relogin.j?.session_token) sessions.A = relogin.j.session_token;
    return { status: relogin.status, sessionToken: sessions.A };
  };

  /** Re-read a family stream so a refusal can be counted BY EFFECT rather than by status code. */
  const streamState = async (route, family) => {
    const response = await req("GET", `${route}?family=${encodeURIComponent(family)}`);
    const body = response.j ?? {};
    const list = body.revisions ?? [];
    return { count: Array.isArray(list) ? list.length : 0, head: body.expected_head_for_successor ?? "" };
  };

  return {
    scratch,
    dataDir,
    sessions,
    req,
    start,
    stop,
    cleanup,
    streamState,
    rebuildDaemon,
    sampleResident,
    bootstrap,
    login,
    get base() {
      return base;
    },
    get log() {
      return daemonLog;
    },
    get pid() {
      return daemon?.pid ?? null;
    },
    /** Counted, not declared: how many times this lane actually stopped and restarted the daemon. */
    get interruptionCount() {
      return interruptions;
    },
    get resumeCount() {
      return Math.max(0, starts - 1);
    },
    get peakResidentBytes() {
      sampleResident();
      return peakResidentBytes;
    },
    /**
     * The durability class this lane actually REACHED. One process, one local data dir, no replica
     * and no quorum — so `local_only` is the honest answer. Reporting `replicated_same_host` here,
     * as the first draft of the soak did, would have claimed a replication topology that does not
     * exist in this run.
     */
    get durabilityClassAchieved() {
      return "local_only";
    },
  };
}

/**
 * Seed every owner seam the four M05.9 families bind, through the real routes.
 *
 * EACH IS A REAL ADMISSION, not a fixture: the ontology and mapping and recipe from M05.7, the route
 * rights and source-rights claims from M10.3, and the transformation run whose content-derived
 * identity the media snapshot's lineage cites. A harness that hand-wrote these refs would be testing
 * its own strings.
 */
export async function seedOwners(req, { prefix = "m059" } = {}) {
  const R = ROUTES_V1;
  const ontology = await req("POST", R.OV, {
    owner_ref: OWNER,
    idempotency_key: `${prefix}-ontology`,
    namespace: "acme-desk",
    name: "support-desk",
    governing_scope_ref: "domain://acme-desk/support",
    policy_hash: POLICY,
    entity_types: [{ term_id: "ontology://acme-desk/support-desk/term/ticket", label: "ticket" }],
    valid_time: { starts_at: "2026-01-01T00:00:00Z", ends_at: null },
  });
  const ONT = ontology.j?.ontology_version?.ontology_id ?? "";

  const mapping =
    (
      await req("POST", R.MAP, {
        owner_ref: OWNER,
        idempotency_key: `${prefix}-map`,
        family: "acme.desk-ingest",
        name: "desk-ingest",
        connector_id: "connector://google-drive",
        ontology_revision_ref: ONT,
        source_schema_ref: "artifact://acme/desk/provider-schema/2026-09",
        target_object_model_refs: ["object-model://om_desk_ticket"],
        field_mappings: [
          {
            role: "key",
            source_field: "record_id",
            target_property_ref: "object-model://om_desk_ticket#ticket_id",
            source_type: "string",
            source_cardinality: "one",
          },
        ],
        action_mappings: [],
        authority_scopes_required: ["scope:connector.google_drive.read"],
        redaction_policy_ref: "policy://acme-desk/redaction",
        evidence_required: ["evidence-contract://acme-desk/consent"],
        effective_policy_hash: POLICY,
        registry_status: "active",
      })
    ).j?.connector_mapping ?? {};

  const recipe =
    (
      await req("POST", R.REC, {
        owner_ref: OWNER,
        idempotency_key: `${prefix}-recipe`,
        family: "acme.desk-redact",
        name: "desk-redact",
        ontology_revision_refs: [ONT],
        input_source_types: ["connector"],
        connector_mapping_revision_refs: [mapping.revision_ref],
        output_object_model_refs: ["object-model://om_desk_ticket"],
        output_dataset_contract_refs: ["schema://acme-desk/ticket-row/v2"],
        transformation_steps: ["extract", "redact", "normalize"],
        policy_bound_data_view_refs: [],
        receipt_obligations: ["data_recipe_run", "transformation"],
        effective_policy_hash: POLICY,
        registry_status: "active",
      })
    ).j?.data_recipe ?? {};

  const route =
    (
      await req("POST", R.ROUTE_RIGHTS, {
        owner_ref: OWNER,
        idempotency_key: `${prefix}-route`,
        family: "acme.desk-inference",
        effective_at: "2026-05-01T10:00:00Z",
        route_binding: {
          route_ref: "route://acme-desk/inference",
          provider_ref: "provider://acme-desk/external-a",
          model_ref: "model://external-a/general",
          model_revision_ref: "model://external-a/general/revision/11",
          intermediary_ref: null,
          upstream_terms_ref: null,
          intermediary_is_supply_adapter_not_trust_boundary: true,
        },
        purposes: ["inference_service_delivery"],
        data_classes: ["prompts_and_completions"],
        declared_prohibited_route_uses: ["publication", "downstream_use", "oem_or_reseller_use"],
        unresolved_rights_findings: [],
        destination_and_egress: {
          permitted_destination_classes: ["model_provider"],
          egress_ceiling: "redacted_only",
          region_refs: ["region://us-west"],
          residency_refs: ["region://us-west"],
          cross_border_transfer_basis_ref: null,
        },
        customer_output_rights: {
          intended_customer_output_uses: ["retain", "internal_evaluation"],
          effective_customer_output_rights_hash: sha256("cor"),
          competing_model_training_permitted: false,
        },
        provider_use_of_customer_material: {
          request_or_prompt_logging: "prohibited",
          human_review: "prohibited",
          abuse_and_security_processing: "transient_only",
          service_improvement: "prohibited",
          provider_model_training: "prohibited",
          provider_model_training_basis_ref: null,
          cross_customer_aggregation: "prohibited",
          cross_customer_aggregation_basis_ref: null,
          publication: "prohibited",
        },
        retention_posture: "zero_retention",
        retention_policy_ref: "policy://acme/retention/route/v1",
        commercial_terms_refs: ["contract://acme/order-form/v3"],
        technical_terms_refs: ["terms://acme/provider-a/v7"],
        fallback_substitution: { fallback_is_semantic_substitution: true, fallback_route_rights_revision_ref: null },
        validity: { valid_from: "2026-05-01T00:00:00Z", valid_until: "2027-05-01T00:00:00Z" },
        revocation: { revocation_state: "live", revoked_at: null, revocation_reason: null, revocation_authority_ref: null },
        status: "active",
        resolved_principal_ref: "worker://acme-desk/assistant",
        credential_principal_ref: "service://acme-desk/credential-a",
      })
    ).j?.model_route_rights_contract ?? {};

  const claim = async (key, family, validUntil) =>
    (
      await req("POST", R.CLAIMS, {
        owner_ref: OWNER,
        idempotency_key: key,
        family,
        effective_at: "2026-06-01T09:14:03Z",
        asserted_by_ref: OWNER,
        asserted_rights_holder_refs: [OWNER],
        source_class: "customer",
        subject_refs: ["dataset://acme/desk-rows/v3"],
        rights_basis_refs: ["contract://acme/customer-msa/v4", "grant://acme/desk-consent/v3"],
        declared_prohibited_uses: ["competing_model_training", "publish"],
        unresolved_rights_findings: [],
        derivative_disposition: "inherit_intersection",
        beneficiary_scope_refs: [OWNER],
        jurisdiction_refs: ["jurisdiction://us-ca"],
        residency_refs: ["region://us-west"],
        retention_policy_ref: "policy://acme/retention/desk/v3",
        deletion_or_forget_policy_ref: "policy://acme/deletion/desk/v2",
        legal_or_audit_hold_state: "none",
        validity: { valid_from: "2026-06-01T00:00:00Z", valid_until: validUntil },
        evidence_refs: ["evidence://acme/msa/v4"],
        claim_commitment: sha256("claim"),
        status: "admitted",
        route_rights_contract_refs: [route.revision_ref],
      })
    ).j?.learning_source_rights_claim ?? {};

  const captureClaim = await claim(`${prefix}-claim-capture`, "acme.desk-capture", null);
  const learnedClaim = await claim(`${prefix}-claim-learned`, "acme.desk-learned", null);
  // A claim whose window has already closed at the admission instant: still `admitted`, and its own
  // bytes carry every permission. Only a check against the instant finds it lapsed.
  const lapsedClaim = await claim(`${prefix}-claim-lapsed`, "acme.desk-lapsed", "2026-07-01T00:00:00Z");

  const run =
    (
      await req("POST", R.RUNS, {
        owner_ref: OWNER,
        idempotency_key: `${prefix}-run`,
        data_recipe_revision_ref: recipe.revision_ref,
        output_intent: "ontology_objects",
        execution_status: "completed",
        input_refs: ["artifact://acme/desk/batch-2026-08"],
        authority_grant_refs: ["grant://acme-desk/read/2026-08"],
        output_object_refs: ["agentgres://object/desk_ticket/2026-08"],
        receipt_refs: ["receipt://acme-desk/transformation/2026-08"],
        derivative_policy_ref: "policy://acme-desk/derivatives",
        impact_graph_ref: "agentgres://projection/desk-impact",
      })
    ).j?.transformation_run ?? {};

  return { ONT, mapping, recipe, route, captureClaim, learnedClaim, lapsedClaim, run };
}
