#!/usr/bin/env node

import { spawn } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const binary = path.join(root, "target", "debug", "hypervisor-daemon");
const artifactRoot = path.join(
  root,
  ".artifacts",
  "implementation",
  "package-registry-smoke",
);
const reportPath = path.join(artifactRoot, "report.json");
let sessionToken = "";

const report = {
  schema_version: "ioi.hypervisor.package-registry-smoke-report.v1",
  status: "running",
  assertions: [],
  interactions: [],
  restart_count: 0,
  route_inventory: null,
  objects: {},
  nonclaims: [
    "No extension_application registration is created.",
    "No System interface or serving binding is created.",
    "No executable process, public route, or launch eligibility is claimed.",
  ],
};

fs.mkdirSync(artifactRoot, { recursive: true });

function writeReport() {
  fs.writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`);
}

function assertThat(condition, name, detail = {}) {
  if (!condition) {
    // Carry the detail into the message. A failure that reports only its own name forces the
    // reader to re-run the smoke by hand to learn which status or code it actually saw.
    throw new Error(
      `assertion failed: ${name}${
        Object.keys(detail).length ? ` — ${JSON.stringify(detail)}` : ""
      }`,
    );
  }
  report.assertions.push({ name, status: "passed", ...detail });
}

function errorCode(body) {
  return typeof body?.error?.code === "string" ? body.error.code : null;
}

function expectStatus(response, status, name) {
  assertThat(response.status === status, name, {
    expected_status: status,
    actual_status: response.status,
    error_code: errorCode(response.body),
    message: response.body?.error?.message ?? response.body?.message ?? null,
  });
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      server.close((error) => {
        if (error) reject(error);
        else resolve(address.port);
      });
    });
  });
}

async function startDaemon(dataDir) {
  const port = await freePort();
  const endpoint = `http://127.0.0.1:${port}`;
  const child = spawn(binary, [], {
    cwd: root,
    env: {
      ...process.env,
      IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${port}`,
      IOI_HYPERVISOR_DATA_DIR: dataDir,
      IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:1/v1",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let log = "";
  let spawnError = null;
  const retain = (chunk) => {
    log = `${log}${chunk}`.slice(-128_000);
  };
  child.stdout.on("data", retain);
  child.stderr.on("data", retain);
  child.once("error", (error) => {
    spawnError = error;
  });
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    if (spawnError) throw spawnError;
    if (child.exitCode !== null) {
      throw new Error(
        `daemon exited before readiness (${child.exitCode}):\n${log}`,
      );
    }
    try {
      const response = await fetch(`${endpoint}/healthz`, {
        signal: AbortSignal.timeout(1_000),
      });
      if (response.ok) {
        return {
          endpoint,
          bootstrapToken:
            log.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null,
          log: () => log,
          async close() {
            if (child.exitCode !== null) return;
            const exited = new Promise((resolve) =>
              child.once("exit", resolve),
            );
            child.kill("SIGTERM");
            const graceful = await Promise.race([
              exited.then(() => true),
              delay(5_000).then(() => false),
            ]);
            if (!graceful && child.exitCode === null) {
              child.kill("SIGKILL");
              await exited;
            }
          },
        };
      }
    } catch {}
    await delay(100);
  }
  child.kill("SIGKILL");
  throw new Error(`daemon did not become ready:\n${log}`);
}

async function request(
  daemon,
  name,
  method,
  route,
  body,
  authenticated = true,
) {
  const headers = { accept: "application/json" };
  if (authenticated && sessionToken) {
    headers.authorization = `Bearer ${sessionToken}`;
  }
  if (body !== undefined) headers["content-type"] = "application/json";
  const response = await fetch(`${daemon.endpoint}${route}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(10_000),
  });
  const text = await response.text();
  let parsed;
  try {
    parsed = text ? JSON.parse(text) : {};
  } catch {
    parsed = { non_json_response: text.slice(0, 2_000) };
  }
  report.interactions.push({
    name,
    method,
    route,
    status: response.status,
    error_code: errorCode(parsed),
  });
  return { status: response.status, body: parsed };
}

async function bootstrap(daemon) {
  if (!daemon.bootstrapToken) {
    throw new Error(
      `fresh daemon emitted no bootstrap token:\n${daemon.log()}`,
    );
  }
  const response = await request(
    daemon,
    "bootstrap_operator",
    "POST",
    "/v1/hypervisor/auth/bootstrap",
    {
      token: daemon.bootstrapToken,
      password: "package-registry-smoke-password-v1",
      email: "package-registry-smoke@ioi.local",
    },
    false,
  );
  expectStatus(
    response,
    200,
    "fresh deployment bootstraps through one-boot credential",
  );
  assertThat(
    typeof response.body.session_token === "string" &&
      response.body.session_token.startsWith("ioi_sess_"),
    "bootstrap returns daemon-issued bearer session",
  );
  sessionToken = response.body.session_token;
}

function encoded(value) {
  return encodeURIComponent(value);
}

function exactPackageRoutes(index) {
  return (index.families ?? [])
    .flatMap((family) => family.paths ?? [])
    .filter((row) => row.path.startsWith("/v1/hypervisor/packages"))
    .map((row) => ({ path: row.path, methods: [...row.methods].sort() }))
    .sort((left, right) => left.path.localeCompare(right.path));
}

async function run() {
  fs.accessSync(binary, fs.constants.X_OK);
  const dataDir = fs.mkdtempSync(
    path.join(os.tmpdir(), "ioi-package-registry-smoke-"),
  );
  let daemon;
  try {
    daemon = await startDaemon(dataDir);
    await bootstrap(daemon);

    const index = await request(daemon, "v1_inventory", "GET", "/v1");
    expectStatus(index, 200, "daemon capability inventory is readable");
    const routes = exactPackageRoutes(index.body);
    const expectedRoutes = [
      { path: "/v1/hypervisor/packages", methods: ["GET", "POST"] },
      { path: "/v1/hypervisor/packages/:package_id", methods: ["GET"] },
      {
        path: "/v1/hypervisor/packages/:package_id/releases",
        methods: ["GET", "POST"],
      },
      {
        path: "/v1/hypervisor/packages/:package_id/releases/:release_digest",
        methods: ["GET"],
      },
      {
        path: "/v1/hypervisor/packages/:package_id/releases/:release_digest/installations",
        methods: ["GET", "POST"],
      },
      {
        path: "/v1/hypervisor/packages/:package_id/releases/:release_digest/installations/:installation_id",
        methods: ["GET"],
      },
      {
        path: "/v1/hypervisor/packages/:package_id/releases/:release_digest/installations/:installation_id/uninstall",
        methods: ["POST"],
      },
      {
        path: "/v1/hypervisor/packages/:package_id/releases/:release_digest/recall",
        methods: ["POST"],
      },
    ].sort((left, right) => left.path.localeCompare(right.path));
    assertThat(
      JSON.stringify(routes) === JSON.stringify(expectedRoutes),
      "mechanical route inventory exposes the exact package family",
      { routes },
    );
    report.route_inventory = {
      schema_version: index.body.schema_version,
      derivation: index.body.derivation?.kind,
      routes,
    };

    const ontology = await request(
      daemon,
      "create_domain_ontology",
      "POST",
      "/v1/hypervisor/odk/domain-ontologies",
      {
        domain: "package-registry-smoke",
        canonical_object_model: {
          value_types: [],
          object_types: [],
          link_types: [],
          action_types: [],
        },
      },
    );
    expectStatus(ontology, 201, "ODK ontology source is durable");
    const ontologyRef = ontology.body.ontology.ref;

    const descriptor = await request(
      daemon,
      "create_domain_app_descriptor",
      "POST",
      "/v1/hypervisor/odk/surface-descriptors",
      {
        name: "Package registry smoke surface",
        composition_pattern: "domain_app",
        ontology_ref: ontologyRef,
        recipe_refs: [],
        owner_ref: "org://local",
        idempotency_key: "package-registry-smoke-descriptor-v1",
      },
    );
    expectStatus(descriptor, 201, "ODK domain-app descriptor is durable");
    const descriptorRef = descriptor.body.surface_descriptor.ref;

    const manifest = await request(
      daemon,
      "create_odk_manifest",
      "POST",
      "/v1/hypervisor/odk/manifests",
      {
        name: "Package registry smoke manifest",
        ontology_refs: [ontologyRef],
        recipe_refs: [],
        surface_descriptor_refs: [descriptorRef],
        owner_ref: "org://local",
        idempotency_key: "package-registry-smoke-manifest-v1",
      },
    );
    expectStatus(manifest, 201, "ODK manifest source is durable");
    const manifestRef = manifest.body.manifest.ref;

    const domainApp = await request(
      daemon,
      "create_domain_app",
      "POST",
      "/v1/hypervisor/domain-apps",
      {
        name: "Package registry smoke app",
        surface_descriptor_ref: descriptorRef,
        odk_manifest_ref: manifestRef,
        owner_ref: "org://local",
        idempotency_key: "package-registry-smoke-domain-app-v1",
      },
    );
    expectStatus(domainApp, 201, "DomainApp source is durable");
    const domainAppRef = domainApp.body.domain_app.domain_app_ref;

    const candidateRequest = {
      package_id: "local-package-registry-smoke",
      owner_ref: "org://local",
      domain_app_ref: domainAppRef,
      idempotency_key: "package-registry-smoke-candidate-v1",
      recorded_at_ms: 1,
    };
    const anonymous = await request(
      daemon,
      "anonymous_package_refused",
      "POST",
      "/v1/hypervisor/packages",
      candidateRequest,
      false,
    );
    expectStatus(
      anonymous,
      401,
      "package mutation fails closed without identity",
    );

    const candidate = await request(
      daemon,
      "admit_package_candidate",
      "POST",
      "/v1/hypervisor/packages",
      candidateRequest,
    );
    expectStatus(
      candidate,
      201,
      "ODK source mesh becomes an admitted package candidate",
    );
    const candidateProjection = candidate.body.package;
    const candidateRecord = candidateProjection.record;
    assertThat(
      candidateRecord.registration_state === "absent" &&
        candidateRecord.surface_class === "extension_application",
      "candidate names the missing registration instead of inventing it",
    );
    assertThat(
      [
        candidateRecord.source_snapshots.domain_app_content_hash,
        candidateRecord.source_snapshots.odk_manifest_content_hash,
        candidateRecord.source_snapshots.surface_descriptor_content_hash,
      ].every((value) => /^sha256:[0-9a-f]{64}$/u.test(value)),
      "candidate freezes DomainApp, manifest, and descriptor bytes",
    );
    const candidateHead = candidateProjection.agentgres.head;

    const candidateReplay = await request(
      daemon,
      "replay_package_candidate",
      "POST",
      "/v1/hypervisor/packages",
      { ...candidateRequest, recorded_at_ms: 999 },
    );
    expectStatus(candidateReplay, 201, "candidate retry replays exactly");
    assertThat(
      candidateReplay.body.package.agentgres.replayed === true &&
        candidateReplay.body.package.agentgres.head === candidateHead &&
        candidateReplay.body.package.agentgres.receipt_ref ===
          candidateProjection.agentgres.receipt_ref,
      "candidate retry returns the original head and receipt",
    );

    const candidateList = await request(
      daemon,
      "list_package_candidates",
      "GET",
      "/v1/hypervisor/packages",
    );
    expectStatus(
      candidateList,
      200,
      "package inventory is owner filtered and readable",
    );
    assertThat(
      candidateList.body.packages.length === 1,
      "package inventory reconstructs one candidate from Agentgres",
    );

    const releaseRequest = {
      expected_package_head: candidateHead,
      surface_distribution: "private_registry",
      surface_capability_depth: "propose",
      object_contract_refs: ["object-model://package-registry-smoke"],
      action_contract_refs: ["action://package-registry-smoke/propose"],
      evidence_refs: ["artifact://package-registry-smoke/conformance"],
      idempotency_key: "package-registry-smoke-release-v1",
      recorded_at_ms: 2,
    };
    const release = await request(
      daemon,
      "admit_immutable_release",
      "POST",
      "/v1/hypervisor/packages/local-package-registry-smoke/releases",
      releaseRequest,
    );
    expectStatus(release, 201, "Packages admits an immutable surface release");
    const releaseProjection = release.body.release;
    const releaseRecord = releaseProjection.record;
    assertThat(
      /^package:\/\/local-package-registry-smoke\/release\/sha256:[0-9a-f]{64}$/u.test(
        releaseRecord.release_ref,
      ),
      "release identity is content addressed",
    );
    assertThat(
      releaseRecord.surface_admission_state === "admitted" &&
        releaseRecord.surface_package_disposition === "active" &&
        releaseRecord.evidence_refs.includes(
          candidateProjection.agentgres.receipt_ref,
        ),
      "release binds local admission, active disposition, and candidate receipt",
    );
    const releaseHead = releaseProjection.agentgres.head;
    const releaseDigest = releaseRecord.release_ref.split("/release/").at(-1);

    const staleRelease = await request(
      daemon,
      "stale_candidate_head_refused",
      "POST",
      "/v1/hypervisor/packages/local-package-registry-smoke/releases",
      {
        ...releaseRequest,
        expected_package_head: `sha256:${"0".repeat(64)}`,
        idempotency_key: "package-registry-smoke-release-stale",
      },
    );
    expectStatus(
      staleRelease,
      409,
      "release admission enforces exact package-head CAS",
    );

    const installRoute = `/v1/hypervisor/packages/local-package-registry-smoke/releases/${encoded(releaseDigest)}/installations`;
    const widening = await request(
      daemon,
      "widening_install_refused",
      "POST",
      installRoute,
      {
        installation_id: "widening",
        expected_release_head: releaseHead,
        project_ref: null,
        visibility: "organization",
        allowed_object_contract_refs: ["object-model://package-registry-smoke"],
        allowed_action_refs: ["action://not-in-release"],
        idempotency_key: "package-registry-smoke-install-widening",
        recorded_at_ms: 3,
      },
    );
    expectStatus(widening, 422, "installation cannot widen release contracts");

    const installationRequest = {
      installation_id: "primary",
      expected_release_head: releaseHead,
      project_ref: null,
      visibility: "organization",
      allowed_object_contract_refs: ["object-model://package-registry-smoke"],
      allowed_action_refs: ["action://package-registry-smoke/propose"],
      idempotency_key: "package-registry-smoke-install-v1",
      recorded_at_ms: 4,
    };
    const installation = await request(
      daemon,
      "install_disabled_binding",
      "POST",
      installRoute,
      installationRequest,
    );
    expectStatus(
      installation,
      201,
      "exact release receives a local installation binding",
    );
    const installationProjection = installation.body.installation;
    assertThat(
      installationProjection.record.surface_installation_state ===
        "installed" &&
        installationProjection.record.surface_enablement_state === "disabled" &&
        installationProjection.registration_state === "absent" &&
        installationProjection.launch_eligible === false,
      "installation is real but remains disabled and non-launchable",
    );
    const installationHead = installationProjection.agentgres.head;

    const installationList = await request(
      daemon,
      "list_installations",
      "GET",
      installRoute,
    );
    expectStatus(
      installationList,
      200,
      "release installation inventory is readable",
    );
    assertThat(
      installationList.body.installations.length === 1,
      "installation inventory reconstructs one binding from Agentgres",
    );

    report.objects = {
      ontology_ref: ontologyRef,
      surface_descriptor_ref: descriptorRef,
      odk_manifest_ref: manifestRef,
      domain_app_ref: domainAppRef,
      package_ref: candidateRecord.package_ref,
      package_candidate_ref: candidateRecord.package_candidate_ref,
      release_ref: releaseRecord.release_ref,
      installation_ref: installationProjection.record.installation_ref,
    };

    // Recall lands WITH the registry (W2.3): the one disposition successor, exercised
    // through the same restart the rest of the family already proves.
    const releaseRoute = installRoute.replace(/\/installations$/u, "");
    const recallRoute = `${releaseRoute}/recall`;
    // The install steps advance the release stream, so recall CAS-swaps against the
    // CURRENT head, re-read here — never the head captured at release cut.
    const preRecall = await request(daemon, "read_release_before_recall", "GET", releaseRoute);
    expectStatus(preRecall, 200, "release reads back before recall");
    const preRecallHead = preRecall.body.release.agentgres.head;
    const preRecallSequence = preRecall.body.release.agentgres.sequence;
    const recall = await request(daemon, "recall_release", "POST", recallRoute, {
      expected_release_head: preRecallHead,
      idempotency_key: "package-registry-smoke-recall-v1",
      reason: "package-registry smoke: recall must land WITH the registry",
      recorded_at_ms: 4,
    });
    expectStatus(recall, 200, "release recall appends the disposition successor");
    const recalledRelease = await request(daemon, "read_release_after_recall", "GET", releaseRoute);
    expectStatus(recalledRelease, 200, "recalled release reads back");
    assertThat(
      recalledRelease.body.release.record.surface_package_disposition === "recalled" &&
        recall.body.release.agentgres.sequence === preRecallSequence + 1,
      "recall flips active -> recalled as an immutable stream successor",
      { disposition: recalledRelease.body.release.record.surface_package_disposition,
        sequence: recall.body.release.agentgres.sequence, prior: preRecallSequence },
    );
    const recalledBinding = await request(daemon, "read_installation_after_recall", "GET", `${installRoute}/primary`);
    expectStatus(recalledBinding, 200, "binding reads back after recall");
    assertThat(
      JSON.stringify(recalledBinding.body).includes("surface_release_recalled"),
      "a recalled release derives binding ineligibility with its typed reason",
    );

    await daemon.close();
    daemon = await startDaemon(dataDir);
    report.restart_count += 1;

    const recovered = await request(
      daemon,
      "read_installation_after_restart",
      "GET",
      `${installRoute}/primary`,
    );
    expectStatus(
      recovered,
      200,
      "installation reconstructs after daemon restart",
    );
    assertThat(
      recovered.body.installation.agentgres.head === installationHead,
      "restart recovery preserves exact installation head",
    );
    const recalledAfterRestart = await request(daemon, "read_release_after_restart", "GET", releaseRoute);
    expectStatus(recalledAfterRestart, 200, "release reconstructs after restart");
    assertThat(
      recalledAfterRestart.body.release.record.surface_package_disposition === "recalled",
      "the recalled disposition survives daemon restart",
    );
    assertThat(
      JSON.stringify(recovered.body).includes("surface_release_recalled"),
      "derived recall ineligibility survives daemon restart",
    );

    const uninstallRoute = `${installRoute}/primary/uninstall`;
    const uninstall = await request(
      daemon,
      "uninstall_binding",
      "POST",
      uninstallRoute,
      {
        expected_installation_head: installationHead,
        idempotency_key: "package-registry-smoke-uninstall-v1",
        recorded_at_ms: 5,
      },
    );
    expectStatus(
      uninstall,
      200,
      "installation uninstalls under exact-head CAS",
    );
    assertThat(
      uninstall.body.installation.record.surface_installation_state ===
        "uninstalled" && uninstall.body.installation.record.revision === 2,
      "uninstall appends immutable revision two",
    );

    const uninstallReplay = await request(
      daemon,
      "replay_uninstall",
      "POST",
      uninstallRoute,
      {
        expected_installation_head: uninstall.body.installation.agentgres.head,
        idempotency_key: "package-registry-smoke-uninstall-v1",
        recorded_at_ms: 999,
      },
    );
    expectStatus(
      uninstallReplay,
      200,
      "uninstall retry replays the original transition",
    );
    assertThat(
      uninstallReplay.body.installation.agentgres.replayed === true &&
        uninstallReplay.body.installation.agentgres.head ===
          uninstall.body.installation.agentgres.head,
      "uninstall replay returns the original transition head",
    );

    const staleUninstall = await request(
      daemon,
      "stale_uninstall_refused",
      "POST",
      uninstallRoute,
      {
        expected_installation_head: installationHead,
        idempotency_key: "package-registry-smoke-uninstall-stale",
        recorded_at_ms: 6,
      },
    );
    expectStatus(
      staleUninstall,
      409,
      "uninstall rejects a stale head under a new key",
    );

    report.status = "passed";
    report.completed_stages = [
      "5: ODK DomainApp source mesh frozen as package candidate",
      "6: immutable local package release admitted",
      "7a: disabled organization installation binding admitted and uninstallable",
    ];
    writeReport();
    console.log(
      `package registry smoke passed (${report.assertions.length} assertions)`,
    );
    console.log(reportPath);
  } catch (error) {
    report.status = "failed";
    report.error =
      error instanceof Error ? (error.stack ?? error.message) : String(error);
    writeReport();
    throw error;
  } finally {
    if (daemon) await daemon.close();
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
}

await run();
