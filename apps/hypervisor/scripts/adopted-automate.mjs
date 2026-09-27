// The Automate seed's adapter (R-241, UX seed depth phase). The reference Automate app itself is the
// seed: it boots from the local reference mirror through the `/__apps/monitors` lane (never vendored —
// the repository is public and the bundle is not ours to publish). This module answers the app's own
// data requests from DAEMON TRUTH in the app's own wire shapes, so the adopted list, overview and
// detail render the Hypervisor's automations. Every request it does not answer passes through to the
// mirror and is counted, so the unbound surface shrinks by measurement, not by claim.
//
// Wire shapes are the ones recorded read-only from the reference (docs/ux-seed-depth-phase.md,
// "Automate — the adapter contract"): the GraphQL gateway answers `text/event-stream`, one
// `data:{…}` line per operation tagged with `extensions.requestIndex`; the monitor registry is REST.
import crypto from "node:crypto";

const MONITOR_PREFIX = "ri.object-sentinel.main.monitor.";

// A Hypervisor automation id as a monitor RID. The app parses the suffix as a UUID, so the 16-hex
// daemon id is laid into UUID grouping; the first 16 hex characters ARE the id (reversible).
export function monitorRidOf(automationId) {
  const hex = String(automationId || "").replace(/^auto_/, "").replace(/[^0-9a-f]/g, "").padEnd(16, "0").slice(0, 16);
  return `${MONITOR_PREFIX}${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(0, 4)}-${hex.slice(4, 16)}`;
}
export function automationIdOf(rid) {
  const tail = String(rid || "").startsWith(MONITOR_PREFIX) ? String(rid).slice(MONITOR_PREFIX.length) : "";
  const hex = tail.replace(/-/g, "").slice(0, 16);
  return /^[0-9a-f]{16}$/.test(hex) ? `auto_${hex}` : null;
}
// The app's normalized-cache ids are opaque; a stable digest of the object's identity serves.
const cacheId = (s) => crypto.createHash("sha256").update(String(s)).digest("base64");
const userIdOf = (principalRef) => {
  const h = crypto.createHash("sha256").update(String(principalRef || "unknown")).digest("hex");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20, 32)}`;
};
const folderRidOf = (project) => {
  const h = crypto.createHash("sha256").update(`project:${project}`).digest("hex");
  return `ri.compass.main.folder.${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20, 32)}`;
};
const iso = (t) => (t && !Number.isNaN(Date.parse(t)) ? new Date(t).toISOString() : new Date(0).toISOString());

function attribution(time, principalRef) {
  return { time: iso(time), user: { id: userIdOf(principalRef), _id: cacheId(`user:${principalRef}`), __typename: "User" }, __typename: "Attribution" };
}

// SearchMonitorsQuery → one ResourceSearchResult per automation, newest first (the query's own sort).
export function searchMonitorsData(automations) {
  const sorted = [...automations].sort((a, b) => String(b.updated_at || b.created_at || "").localeCompare(String(a.updated_at || a.created_at || "")));
  return {
    searchResourcesV2: {
      results: sorted.map((a) => {
        const rid = monitorRidOf(a.automation_id);
        const creator = (a.executor_identity || {}).ref || a.acting_principal_ref || "";
        const project = a.project_id || "unfiled";
        return {
          resource: {
            rid,
            modified: attribution(a.updated_at || a.created_at, creator),
            urlVariables: [{ key: "compass:isProject", value: "false", __typename: "UrlVariable" }],
            name: a.name || a.automation_id,
            path: `/${project}/${a.name || a.automation_id}`,
            description: a.description || "",
            autosaved: false,
            hidden: false,
            trashedStatus: "NOT_TRASHED",
            // The app files each automation under its parent folder and DROPS one with no parent below the
            // root; the Hypervisor's parent is the automation's project.
            ancestors: [
              { name: "All files", rid: "ri.compass.main.folder.0", _id: cacheId("folder:0"), __typename: "ResourceMetadata" },
              { name: project, rid: folderRidOf(project), _id: cacheId(`folder:${project}`), __typename: "ResourceMetadata" },
            ],
            created: attribution(a.created_at, creator),
            namespace: { rid: "ri.compass.main.folder.0", _id: cacheId("folder:0"), __typename: "ResourceMetadata" },
            _id: cacheId(rid),
            __typename: "ResourceMetadata",
          },
          __typename: "ResourceSearchResult",
        };
      }),
      nextPageToken: null,
      __typename: "ResourceSearchResultsPage",
    },
    __typename: "Query",
  };
}

// The automation's trigger as the registry's monitor logic. A schedule is a cron schedule; an interval
// is expressed as the cron it runs on; a manual or webhook automation has no time condition in the
// reference's vocabulary, so it is a schedule with no expression — the app renders it without a time.
function logicOf(a) {
  const spec = a.schedule_spec || {};
  const trig = (a.trigger || {}).kind || spec.kind || "manual";
  let cron = "";
  if (spec.cron) cron = spec.cron;
  else if (trig === "interval" || spec.every_seconds || spec.interval_seconds) {
    const secs = Number(spec.every_seconds || spec.interval_seconds || 0);
    cron = secs >= 3600 && secs % 3600 === 0 ? `0 */${secs / 3600} * * *` : secs >= 60 ? `*/${Math.max(1, Math.round(secs / 60))} * * * *` : "";
  }
  // A manual or webhook automation has no time condition in the reference's vocabulary. A type the app
  // does not know makes it hide the row's name ("Restricted") and say it failed to parse, which is
  // worse; so it is a schedule with no expression, and the adopted app's "Running on schedule" for it is
  // a NAMED GAP (docs/ux-seed-depth-phase.md) until the condition labels are reshaped.
  return { type: "schedule", schedule: { cronExpression: cron, additionalCronExpressions: [], timeZone: spec.timezone || spec.tz || "UTC" } };
}

function historyEventOf(a, run) {
  if (!run) return null;
  return {
    metadata: { id: run.execution_id, triggerTime: iso(run.started_at), otherNotificationsTriggered: [], monitorRid: null, jobId: null, isScopedEvent: false, seen: null, queueMetadata: { timeInQueueSeconds: 0, isQueueEffectExecution: false }, evaluationId: run.execution_id, branchRid: null, scenarioRid: null },
    type: { type: "monitorTriggered", monitorTriggered: { monitorVersion: 1, objectChanges: [], metricChanges: { changes: {} }, effectsTriggered: {}, effectsTriggeredV2: [], anyEffectFailedByEffectId: {}, droppedObjects: { numDropped: 0 }, eventOrigin: null, scopedEventMetadata: { userIds: [], metadata: { notificationResults: {} } }, runtimeError: run.status === "failed" ? { safeMessage: "The execution failed", unsafeMessage: "" } : null, mgsAttemptMetadata: [], longTermRetryMetadata: null, timeline: { evaluation: { timelineEvents: [] }, execution: { timelineEvents: [], futureEvents: [] } } } },
  };
}

// monitors-getMonitors → the registry record for each requested automation.
export function monitorOf(a, runs) {
  const latest = [...(runs || [])].sort((x, y) => String(y.started_at || "").localeCompare(String(x.started_at || "")))[0] || null;
  const creator = (a.executor_identity || {}).ref || "";
  const event = historyEventOf(a, latest);
  return {
    metadata: {
      rid: monitorRidOf(a.automation_id),
      owningResource: null,
      subscribers: [{ subscriberType: { type: "user", user: { userId: userIdOf(creator) } }, triggerEffects: {}, recoveryEffects: {} }],
      expiryDate: "+999999999-12-31T23:59:59.999999999-18:00",
      expiry: { expireOn: null },
      muted: { until: null, isMutedIndefinitely: null, forUsers: [], mutedReason: null, isMutedGlobally: null },
      disabled: { isDisabledIndefinitely: a.enabled === false, until: null, reason: a.enabled === false ? "Paused in the Hypervisor" : null },
      rendering: null,
      renderingV2: {},
      liveConfig: { lowLatencyPatchesEnabled: false, monitorMetricsEnabled: false, streamBackedObjectsEnabled: false, editsOnlyMonitoring: false, skipPeeringEnabled: null },
      management: null,
      globalEffectExecutionSettings: { batchSize: 0, effectOrdering: null, doNotMuteAutomationOnFailures: false, rateLimitConfig: null, longTermRetryConfig: null, queueExpirationInSeconds: null, enableAdaptiveParallelism: null },
      scopedTokenEffects: null,
      priority: null,
      cycleDetectionSettings: { type: "noCyclesAllowed", noCyclesAllowed: {} },
      triggerExecutionSettings: { dropEventsConfig: { type: "dropEventsOverLimit", dropEventsOverLimit: {} } },
      dependentAutomations: [],
      telemetryConfig: { enableTelemetry: false },
      timeSeriesAlertingOverrides: null,
      mgsConfig: null,
      branchRid: null,
      onBehalfOf: null,
      scenarioTarget: null,
    },
    logic: logicOf(a),
    version: 1,
    publishedMonitorVersion: 1,
    monitorType: "SCHEDULED",
    lastEvaluationTime: latest ? iso(latest.started_at) : null,
    lastHistoryEvent: event,
    lastTriggerEvent: event,
    lastRecoveryEvent: null,
    isCurrentlyInTriggeringState: false,
    versionedObjectSetsVersionsUsed: {},
    attribution: { createdBy: userIdOf(creator), createdAt: iso(a.created_at) },
  };
}

// Profiles the app asks for by user id: the principals our automations name.
export function profilesFor(userIds, principals) {
  const byId = new Map(principals.map((p) => [userIdOf(p.ref), p]));
  const profiles = {};
  for (const id of userIds) {
    const p = byId.get(id);
    if (!p) continue;
    const name = p.name || p.ref;
    const [given, ...rest] = String(name).split(" ");
    profiles[id] = { userId: id, username: p.email || p.ref, realm: "hypervisor", givenName: given || name, familyName: rest.join(" "), email: p.email || null, attributes: {}, status: "ACTIVE", type: "USER" };
  }
  return { profiles };
}

export const HANDLED_GRAPHQL = new Set(["SearchMonitorsQuery"]);

// Parse a bulk request's operation names by index.
// The bulk gateway's request: { operations: { <hash>: query }, requests: [{ hash, name, variables }] };
// each streamed answer's `extensions.requestIndex` is the position in `requests`.
export function bulkOperations(body) {
  try {
    const j = JSON.parse(body);
    const ops = j.operations || {};
    const nameOf = (q) => (/^\s*(?:query|mutation|subscription)\s+(\w+)/.exec(String(q || "")) || [])[1] || "";
    if (Array.isArray(j.requests)) return j.requests.map((r, index) => ({ index, name: r.name || nameOf(ops[r.hash]), variables: r.variables || {}, query: ops[r.hash] || "" }));
    return Object.entries(ops).map(([index, query]) => ({ index: Number(index), name: nameOf(query), variables: {}, query }));
  } catch { return []; }
}

// Merge our answers into the mirror's event stream: replace the events for the indexes we answer, keep
// the rest verbatim, append ours where the mirror sent none.
export function mergeStream(mirrorText, answers) {
  const lines = String(mirrorText || "").split(/\n\n/).filter((l) => l.trim());
  const out = [];
  const answered = new Set(Object.keys(answers).map(Number));
  for (const block of lines) {
    const m = /^data:(.*)$/s.exec(block.trim());
    let idx = null;
    if (m) { try { idx = JSON.parse(m[1]).extensions?.requestIndex ?? null; } catch { /* keep verbatim */ } }
    if (idx !== null && answered.has(idx)) continue;
    out.push(block.trim());
  }
  for (const [idx, data] of Object.entries(answers)) out.push(`data:${JSON.stringify({ data, extensions: { requestIndex: Number(idx) } })}`);
  return out.join("\n\n") + "\n\n";
}

// ---- Every operation the adopted app makes gets an answer from HERE, never from the mirror's loose
// mock (which returns whatever captured document matches least badly — a marketplace component crashed
// on another operation's data). Daemon truth where a plane exists; an honest EMPTY in the operation's
// own shape where none does (marketplace templates, walkthroughs, announcements, the reference's own
// sidebar — our shell owns the rail); a GraphQL error naming the gap for an operation not yet mapped.
export const OPERATIONS = new Set([
  "SearchMonitorsQuery", "AutomationOverviewEventsQuery", "SplashTableQuery", "GetCompassResource",
  "AutomationTriggeredEventPillQuery", "AutomationNamespaceFilterComponentQuery", "GetObjectTypeInSetForNotSavedSet",
  "RecentInstallationsPopoverQuery", "GetRemoteStoreRid", "SelectWalkthroughsForAppQuery",
  "BrowseTemplatesViewQuery", "LatestAnnouncementQuery", "UpdateAipAssistWalkthroughMetric",
]);
// The reference's own chrome (its sidebar, its principal badges) queries types whose list-ness only the
// schema knows. For these the mirror's answer is used ONLY as a shape-correct ENVELOPE and every identity
// fact in it is overwritten with the signed-in principal (the model-catalog rebind's pattern) — no tenant
// name, email or picture survives.
export const ENVELOPE_OPERATIONS = new Set([
  "CustomerDataSupportedQuery", "WorkspaceSidebarQuery", "ShellSidebarQuery", "SidebarWithPanelQuery", "PrincipalsQuery",
]);
export function scrubIdentity(v, principal) {
  const p = principal || {};
  const full = p.name || p.email || p.ref || "Hypervisor user";
  const [first, ...rest] = String(full).split(" ");
  const facts = { fullName: full, displayName: full, firstName: first, givenName: first, lastName: rest.join(" "), familyName: rest.join(" "), username: p.email || p.ref || "user", email: p.email || null, initials: (first[0] || "U").toUpperCase() + (rest[0]?.[0] || "").toUpperCase(), imageUrl: null };
  const walk = (x) => {
    if (Array.isArray(x)) {
      // Favorites, notifications and recents are the TENANT's — none survive.
      return x;
    }
    if (x && typeof x === "object") {
      const out = {};
      const isUser = x.__typename === "User";
      for (const [k, val] of Object.entries(x)) {
        if (isUser && k === "id") out[k] = userIdOf(p.ref || "anonymous");
        else if (isUser && k === "_id") out[k] = cacheId(`user:${p.ref}`);
        else if (k in facts && (typeof val === "string" || val === null)) out[k] = facts[k];
        else if (/^favorite|^notifications$|^values$|^recents$|^pinnedNotifications$/.test(k) && Array.isArray(val)) out[k] = [];
        else out[k] = walk(val);
      }
      return out;
    }
    return x;
  };
  return walk(v);
}
const Q = (data) => ({ ...data, __typename: "Query" });

// ctx: { automations, principal: { ref, name, email } }
export function graphqlAnswer(name, variables, ctx) {
  const autos = Array.isArray(ctx.automations) ? ctx.automations : [];
  const me = ctx.principal || {};
  const meId = userIdOf(me.ref || "anonymous");
  const fullName = me.name || me.email || me.ref || "Hypervisor user";
  switch (name) {
    case "SearchMonitorsQuery": return searchMonitorsData(autos);
    case "AutomationOverviewEventsQuery": return Q({ objectSetMonitorEvents: { nextPageToken: null, values: [], __typename: "ObjectSetMonitorEventsPage" } });
    case "SplashTableQuery": return Q({ recents: [], favorites: [] });
    case "GetCompassResource": {
      const rid = variables?.rid || variables?.resourceRid || "";
      const a = autos.find((x) => monitorRidOf(x.automation_id) === rid);
      return Q({ resourceMetadata: a ? { rid, collections: [], status: null, trashedStatus: "NOT_TRASHED", type: { iconName: "lightning", __typename: "ResourceType" }, alias: a.name || a.automation_id, name: a.name || a.automation_id, openUrl: `/workspace/object-monitoring/automation/${rid}/main/view/overview`, permissions: { canOpenLink: true, __typename: "ResourcePermissions" }, _id: cacheId(`meta:${rid}`), __typename: "ResourceMetadata" } : null });
    }
    case "AutomationTriggeredEventPillQuery": {
      const rid = variables?.monitorRid || variables?.rid || "";
      return Q({ objectSetMonitor: { rid, defaultBranchV2: { event: null, _id: cacheId(`branch:${rid}`), __typename: "ObjectSetMonitorBranch" }, _id: cacheId(rid), __typename: "ObjectSetMonitor" } });
    }
    case "AutomationNamespaceFilterComponentQuery": return Q({ namespaces: { nextPageToken: null, values: [], __typename: "NamespacesPage" } });
    case "GetObjectTypeInSetForNotSavedSet": return Q({ objectSet: { objectTypes: [], __typename: "ObjectSet" } });
    case "RecentInstallationsPopoverQuery": return Q({ store: null });
    case "GetRemoteStoreRid": return Q({ remoteStore: null });
    case "SelectWalkthroughsForAppQuery": return Q({ workspaceApplication: { aipAssistWalkthroughs: [], _id: cacheId("app:automate"), __typename: "WorkspaceApplication" } });
    case "BrowseTemplatesViewQuery": return Q({ searchMarketplaceProducts: { values: [], nextPageToken: null, __typename: "MarketplaceProductsPage" } });
    case "LatestAnnouncementQuery": return Q({ pinnedNotifications: [] });
    case "UpdateAipAssistWalkthroughMetric": return { updateAipAssistWalkthroughMetric: null, __typename: "Mutation" };
    default: return undefined;
  }
}
export const opNameOf = (op) => (op && (op.operationName || (/^\s*(?:query|mutation|subscription)\s+(\w+)/.exec(String(op.query || "")) || [])[1])) || "";
// THE FALLTHROUGH COUNT: every operation the adopted app asked for and the adapter could not answer,
// by name — the unbound surface, measured (GET /__ioi/adopted-seeds/unbound).
const unbound = new Map();
export const unboundCounts = () => Object.fromEntries([...unbound.entries()].sort((a, b) => b[1] - a[1]));
export const unboundError = (name) => {
  unbound.set(name || "(unnamed)", (unbound.get(name || "(unnamed)") || 0) + 1);
  return { data: null, errors: [{ message: `${name || "This operation"} is not bound in the Hypervisor adapter yet (a named gap of the adopted Automate seed)` }] };
};

// THE IDENTITY TOKEN a seed page reads client-side (it decodes the cookie's JWT `sub` — 16 bytes,
// base64 — into the current user's UUID). The local mirror injects the reference TENANT'S REAL session
// token there; a page served through the estate must never carry it. This synthetic token is unsigned
// and authorizes nothing (the serve and daemon never read it) — it only names the signed-in Hypervisor
// principal as the same user id the adapter stamps on their automations.
export function identityTokenFor(principalRef) {
  const uuid = userIdOf(principalRef || "anonymous").replace(/-/g, "");
  const sub = Buffer.from(uuid, "hex").toString("base64");
  const b64url = (o) => Buffer.from(JSON.stringify(o)).toString("base64").replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
  return `${b64url({ alg: "none", typ: "JWT" })}.${b64url({ sub, sid: sub, exp: 4102444800 })}.hypervisor-unsigned`;
}
// Replace any tenant token a mirrored page injects with the synthetic one (every seed, not only Automate).
export function replaceInjectedToken(html, principalRef) {
  return String(html).replace(/const token = "[^"]*";/g, `const token = ${JSON.stringify(identityTokenFor(principalRef))};`);
}

// ---- THE HARVEST ENVELOPE (for operations not bound yet). The real answer the reference gave for the
// same operation (recorded read-only, kept in the local mirror, never in the repo) is used as a
// shape-correct envelope and made honest: the recorded monitor becomes the requested automation (its
// rid and name), identity becomes the signed-in principal, and EVERY LIST IS EMPTIED — no recorded
// effect, rule, event or favourite survives onto a Hypervisor automation. An operation with no recording
// is a named GraphQL error, never the mirror's loose guess.
import fsH from "node:fs";
import pathH from "node:path";
let harvestCache = null;
export function harvestOperations(mirrorDir) {
  if (harvestCache) return harvestCache;
  const map = new Map();
  const dir = pathH.join(mirrorDir, "tools/traffic/object-monitoring-flow/operations");
  let files = [];
  try { files = fsH.readdirSync(dir).filter((f) => /^g.*\.json$/.test(f)).sort(); } catch { /* no mirror */ }
  for (const f of files) {
    let d;
    try { d = JSON.parse(fsH.readFileSync(pathH.join(dir, f), "utf8")); } catch { continue; }
    let ops = {};
    try { ops = JSON.parse(d.request).operations || {}; } catch { continue; }
    const names = Object.fromEntries(Object.entries(ops).map(([i, q]) => [Number(i), (/^\s*(?:query|mutation)\s+(\w+)/.exec(String(q)) || [])[1]]));
    for (const line of String(d.stream || "").split("\n")) {
      if (!line.startsWith("data:")) continue;
      let ev; try { ev = JSON.parse(line.slice(5)); } catch { continue; }
      const n = names[ev.extensions?.requestIndex];
      if (n && ev.data && !map.has(n)) map.set(n, { data: ev.data, recordedMonitor: (/ri\.object-sentinel\.main\.monitor\.[0-9a-f-]{36}/.exec(String(d.request)) || [])[0] || null });
    }
  }
  harvestCache = map;
  return map;
}
const RECORDED_NAMES = ["Automation for Priority Classification for Recent Incidents"];
// ONLY operations whose recorded answers carry NO automation facts may be enveloped: the reference's
// chrome, permissions, protection, walkthrough and branch reads. An operation that DESCRIBES an
// automation (its condition, effects, status, times, location) must be bound from daemon truth — an
// envelope there showed the recorded tenant monitor's "Objects added · Live monitoring · last triggered
// Jun 23" on a Hypervisor automation. Until bound, those are named gaps.
export const SAFE_ENVELOPE = new Set([
  "CustomerDataSupportedQuery", "WorkspaceSidebarQuery", "ShellSidebarQuery", "SidebarWithPanelQuery", "PrincipalsQuery",
  "PermissionsQuery", "GetProtectionStatus", "ActiveResourceQuery", "WalkthroughsForResourceQuery",
  "UseOntologiesForResourceQuery", "IssueBadgeData", "ScopedSessionStatus", "GetObjectSentinelUserId", "GetAvailableBranches",
]);
export function envelopeAnswer(name, variables, ctx, mirrorDir) {
  if (!SAFE_ENVELOPE.has(name)) return undefined;
  const rec = harvestOperations(mirrorDir).get(name);
  if (!rec) return undefined;
  const wantRid = (JSON.stringify(variables || {}).match(/ri\.object-sentinel\.main\.monitor\.[0-9a-f-]{36}/) || [])[0] || null;
  const auto = wantRid ? (ctx.automations || []).find((a) => monitorRidOf(a.automation_id) === wantRid) : null;
  const recordedRid = rec.recordedMonitor;
  const swap = (v) => {
    if (typeof v !== "string") return v;
    if (recordedRid && wantRid && v === recordedRid) return wantRid;
    if (auto && RECORDED_NAMES.includes(v)) return auto.name || auto.automation_id;
    return v;
  };
  const walk = (x) => {
    if (Array.isArray(x)) return [];
    if (x && typeof x === "object") return Object.fromEntries(Object.entries(x).map(([k, v]) => [k, walk(v)]));
    return swap(x);
  };
  return scrubIdentity(walk(rec.data), ctx.principal);
}

// ---- FACT OPERATIONS: the detail page's reads, answered by walking each query against the automation's
// facts (adopted-graphql.mjs). Recorded answers lend structure only.
import { answerDocument } from "./adopted-graphql.mjs";
export const FACT_OPERATIONS = new Set([
  "ResourceHeaderQuery", "CompassResourceQuery", "SingleAutomationOverviewV2Query", "AutomationFlowQuery",
  "AutomationLiveStatusQuery", "AutomationStatusControlQuery", "AutomationMonitoringRulesCardQuery",
  "AutomationDependenciesQuery", "ExpiryDateProjectQuery", "GetLiveStatusForNonVersionedObjectSet",
]);
export const requestedMonitorRid = (variables) => (JSON.stringify(variables || {}).match(/ri\.object-sentinel\.main\.monitor\.[0-9a-f-]{36}/) || [])[0] || null;

export function factsRoot(a, runs, principal) {
  const rid = monitorRidOf(a.automation_id);
  const creator = (a.executor_identity || {}).ref || (principal || {}).ref || "";
  const project = a.project_id || "unfiled";
  const who = (ref) => ({ __typename: "User", id: userIdOf(ref), _id: cacheId(`user:${ref}`), realm: { __typename: "PrincipalRealm", id: "hypervisor" } });
  const at = (t, ref) => ({ __typename: "Attribution", time: iso(t), user: who(ref) });
  const latest = [...(runs || [])].sort((x, y) => String(y.started_at || "").localeCompare(String(x.started_at || "")))[0] || null;
  const running = (runs || []).find((r) => r.status === "running") || null;
  const spec = a.schedule_spec || {};
  const paused = a.enabled === false;
  const folder = { __typename: "ResourceMetadata", rid: folderRidOf(project), name: project, openUrl: null, _id: cacheId(`folder:${project}`) };
  const resource = {
    __typename: "ResourceMetadata", _id: cacheId(`meta:${rid}`), rid, name: a.name || a.automation_id, description: a.description || "",
    path: `/${project}/${a.name || a.automation_id}`, autosaved: false, hidden: false, trashedStatus: "NOT_TRASHED", favorited: null,
    isProtected: false, created: at(a.created_at, creator), modified: at(a.updated_at || a.created_at, creator), parent: folder,
    ancestors: [{ __typename: "ResourceMetadata", name: "All files", rid: "ri.compass.main.folder.0", _id: cacheId("folder:0") }, folder],
    urlVariables: [{ __typename: "UrlVariable", key: "compass:isProject", value: "false" }],
    type: { __typename: "ResourceTypeMetadata", iconName: "pt-svg-icon-automation" },
    permissions: { __typename: "ResourceMetadataPermissions", canEditAutomation: true, canShare: false, canShareLink: false, canTrash: false, canEditTags: false, canEditMetadata: false, canMoveBetweenProjects: false, canMoveWithinProject: false, canRestore: false, canOpenLink: true, canCreateIssue: false },
    project: { __typename: "Project", userProjectOwner: null },
  };
  const condition = { __typename: "ObjectSetMonitorSchedule", __implements: ["ObjectSetMonitorLogicV3", "ObjectSetMonitorCondition"], cronExpression: logicOf(a).schedule?.cronExpression || "", additionalCronExpressions: [], timeZone: spec.timezone || spec.tz || "UTC" };
  const event = (r) => r ? { __typename: "ObjectSetMonitorHistoryEvent_MonitorTriggered", __implements: ["ObjectSetMonitorHistoryEvent"], _id: cacheId(`event:${r.execution_id}`), id: r.execution_id, triggerTime: iso(r.started_at), triggerReason: "SCHEDULE", triggeredEffectsV2: [] } : null;
  const branch = {
    __typename: "ObjectSetMonitorBranch", _id: cacheId(`branch:${rid}`), isProjectScoped: false, scenarioTarget: null,
    isPausedIndefinitely: paused, pausedUntil: null, isMutedIndefinitely: false, mutedUntil: null, expiresAt: null,
    owner: who(creator), dependentAutomations: [],
    monitor: { __typename: "ObjectSetMonitor", _id: cacheId(rid), rid, metadata: resource },
    latestVersion: { __typename: "ObjectSetMonitorVersion", _id: cacheId(`version:${rid}`), monitorLogicV3: condition, mergedEffects: [], effectOrdering: null, subscribers: [], persistsSharedHistoryEvent: false },
    latestEvents: { __typename: "ObjectSetMonitorLatestEvents", completeTriggered: event(latest && latest.status !== "running" ? latest : null), inProgressTriggered: event(running), evaluationRuntimeError: null, effectsRuntimeError: null },
    scheduledMonitoringEvaluationStatus: { __typename: "ObjectSetMonitorScheduledEvaluationStatus", isRunning: !!running, scheduledAt: a.next_run_at ? iso(a.next_run_at) : null },
  };
  return {
    __typename: "Query",
    objectSetMonitor: { __typename: "ObjectSetMonitor", _id: cacheId(rid), rid, branch, defaultBranchV2: branch, monitorRules: [] },
    resourceMetadata: resource,
    objectSet: null,
  };
}

export function answerFactOperation(name, query, variables, ctx, runsFor, template) {
  const rid = requestedMonitorRid(variables);
  const a = rid ? (ctx.automations || []).find((x) => monitorRidOf(x.automation_id) === rid) : null;
  if (!a) return null;
  return answerDocument(query, factsRoot(a, runsFor(a.automation_id), ctx.principal), template, name);
}

// ---- SAVE LOCATION (ADR 0056 P3 cut 3b): the wizard's "Save as…" dialog picks where the automation
// lives. In the Hypervisor that is a PROJECT — every automation's required durable container — so the
// caller's projects are the locations offered (as the reference's project folders), and nothing else.
// Creating a project is not offered here; it belongs to Projects.
export const SAVE_LOCATION_OPERATIONS = new Set(["InlineSaveLocationSelectorQuery", "PagedNamespacesQuery", "SearchProjectsQuery", "FavoriteProjectsQuery", "CanCreateCompassResourceForAutomation", "GetNameValidInLocationQuery", "ClientDetailsQuery"]);
export const projectFolderRid = (projectId) => folderRidOf(projectId);
// `variables` scope `resourceMetadata` to the one location a request names (parentRid / locationRid):
// the caller may create an automation in their own project, and a name is valid there when it is not
// empty and no automation in that project already has it.
export function saveLocationFactsRoot(projects, variables = {}, automations = []) {
  const allFiles = { __typename: "ResourceMetadata", name: "All files", rid: "ri.compass.main.folder.0", _id: cacheId("folder:0"), openUrl: null, permissions: { __typename: "ResourceMetadataPermissions", _id: cacheId("perm:folder:0"), canOpenLink: false, canEditMetadata: false } };
  const namespace = { __typename: "Namespace", _id: cacheId("namespace:hypervisor"), rid: "ri.compass.main.namespace.hypervisor" };
  const namespaceFolder = { __typename: "ResourceMetadata", name: "Hypervisor", rid: "ri.compass.main.folder.hypervisor-namespace", _id: cacheId("folder:namespace"), openUrl: null, permissions: { __typename: "ResourceMetadataPermissions", _id: cacheId("perm:folder:namespace"), canOpenLink: false, canEditMetadata: false } };
  const folder = (p) => {
    const rid = folderRidOf(p.project_id);
    return {
      __typename: "ResourceMetadata", __implements: ["Recent"], _id: cacheId(`folder:${p.project_id}`), rid, name: p.name || p.project_id, alias: "",
      openUrl: null, path: `/${p.name || p.project_id}`, collections: [], status: null, trashedStatus: "NOT_TRASHED", statusInfo: null, autosaved: false,
      type: { __typename: "ResourceTypeMetadata", iconName: "pt-svg-icon-project" },
      permissions: { __typename: "ResourceMetadataPermissions", _id: cacheId(`perm:${rid}`), canOpenLink: true, canEditMetadata: true },
      ancestors: [allFiles, namespaceFolder], parent: namespaceFolder, namespace, projectRid: rid, projectSettings: null,
      resource: { __typename: "Folder", _id: cacheId(`resource:${rid}`) },
      project: { __typename: "Project", _id: cacheId(`project:${rid}`), type: "PROJECT" },
    };
  };
  return {
    __typename: "Query",
    favorites: [],
    // No OAuth client acts for an automation: it runs as the principal who owns it.
    oauthClient: null,
    resourceMetadata: (() => {
      const wantRid = variables.parentRid || variables.locationRid || null;
      const target = wantRid ? (projects || []).find((p) => folderRidOf(p.project_id) === wantRid) : null;
      if (!target) return null;
      const node = folder(target);
      const name = String(variables.name ?? "").trim();
      const taken = (automations || []).some((a) => (a.project_id || a.project_ref) === target.project_id && String(a.name || "").trim().toLowerCase() === name.toLowerCase());
      return { ...node, permissions: { ...node.permissions, canCreateAutomation: true }, childNameValid: name.length > 0 && name.length <= 200 && !taken };
    })(),
    recents: (projects || []).map((p) => ({ __typename: "RecentEntry", recent: folder(p) })),
    searchResources: { __typename: "ResourceSearchPage", nextPageToken: null, results: [...(projects || [])].sort((a, b) => String(a.name || a.project_id).localeCompare(String(b.name || b.project_id))).map((p) => ({ __typename: "ResourceSearchResult", highlights: [], resource: folder(p) })) },
    namespaces: { __typename: "NamespacePage", nextPageToken: null, values: [{ ...namespace, permissions: { __typename: "NamespacePermissions", _id: cacheId("perm:namespace"), canCreateProject: false } }] },
  };
}

// Compass REST for the same save locations: the project folders' resources and their file system. A rid
// that is not one of the caller's project folders gets no entry (never a recorded tenant resource).
// A project sits under the root and its organization's namespace, as the reference's projects do (the
// save picker refuses a location with fewer than two ancestors: "root" or "namespace" not allowed).
const NAMESPACE_FOLDER_RID = "ri.compass.main.folder.hypervisor-namespace";
const WRITABLE_OPERATIONS = ["gatekeeper:view-resource", "compass:read-resource", "compass:write-resource", "compass:import-resource-to"];
export function compassProjectResources(projects, rids, principalRef) {
  const byRid = new Map((projects || []).map((p) => [folderRidOf(p.project_id), p]));
  const out = {};
  for (const rid of rids || []) {
    const p = byRid.get(rid);
    if (!p) continue;
    const at = { time: iso(p.created_at || p.createdAt), userId: userIdOf(principalRef) };
    out[rid] = {
      rid, name: p.name || p.project_id, created: at, modified: at, lastModified: Date.parse(at.time) || 0, description: p.description || null,
      operations: WRITABLE_OPERATIONS, urlVariables: { "compass:isProject": "true", "compass:folderType": "project", "compass:roleContext": "PROJECT" }, favorite: null, branches: null, defaultBranch: null,
      path: `/${p.name || p.project_id}`, longDescription: null, directlyTrashed: false, inTrash: false, isAutosave: false, isHidden: false,
      isPreviewResource: false, deprecation: null, collections: null, namedCollections: [], tags: null, namedTags: null, alias: "",
      collaborators: [], namedAncestors: [{ rid: "ri.compass.main.folder.0", name: "All files" }, { rid: NAMESPACE_FOLDER_RID, name: "Hypervisor" }], markings: null, projectAccessMarkings: null, linkedItems: null, contactInformation: null,
      classification: null, portfolioRid: null, namespaceRid: "ri.compass.main.namespace.hypervisor", status: null,
    };
  }
  return out;
}
export function compassFileSystems(projects, rids) {
  const ours = new Set([...(projects || []).map((p) => folderRidOf(p.project_id)), "ri.compass.main.folder.0"]);
  return { ridToFileSystemId: Object.fromEntries((rids || []).filter((rid) => ours.has(rid)).map((rid) => [rid, "ri.foundry.main.filesystem.hypervisor"])) };
}

// ---- CREATE (ADR 0056 P3 cut 3b): the adopted wizard's monitor request, translated into the Hypervisor
// automation it describes. What the Hypervisor automation cannot carry yet is refused BY NAME — never
// dropped: an object condition, an action / logic / notification effect, a second cron expression, a
// function input that is not a static value. The expiry the wizard proposes and its retry settings are
// not enforced by the Hypervisor executor (named in `unenforced`).
function staticValueOf(v) {
  if (!v || typeof v !== "object") return { error: "a function input must be a static value" };
  if (v.type === "list") {
    const out = [];
    for (const item of v.list?.values || []) {
      const one = staticValueOf(item);
      if (one.error) return one;
      out.push(one.value);
    }
    return { value: out };
  }
  if (!Object.prototype.hasOwnProperty.call(v, v.type)) return { error: `unsupported static value type ${v.type}` };
  return { value: v[v.type] };
}

export function automationFromMonitorRequest(request, { projects = [], releasedRevisionOf = () => null } = {}) {
  const r = request || {};
  const name = String(r.name || "").trim();
  const project = (projects || []).find((p) => folderRidOf(p.project_id) === r.parentRid);
  if (!project) return { issue: "choose one of your projects as the automation's location" };
  const logic = r.logic || {};
  if (logic.type !== "schedule") return { issue: `a ${logic.type || "missing"} condition is not supported by the Hypervisor automation yet — use a Time condition` };
  const sched = logic.schedule || {};
  if ((sched.additionalCronExpressions || []).length) return { issue: "only one cron expression per automation is supported" };
  if (!String(sched.cronExpression || "").trim()) return { issue: "the Time condition has no schedule" };
  const effects = new Map();
  for (const sub of r.metadata?.subscribers || []) {
    for (const [id, effect] of Object.entries(sub.triggerEffects || {})) effects.set(id, effect);
    if (Object.keys(sub.recoveryEffects || {}).length) return { issue: "failure (recovery) effects are not supported by the Hypervisor automation yet" };
  }
  if (!effects.size) return { issue: "add at least one effect" };
  const steps = [];
  for (const effect of effects.values()) {
    if (effect.type !== "function") return { issue: `a ${effect.type} effect is not supported by the Hypervisor automation yet — use a Function effect` };
    const loc = effect.function?.functionLocator || {};
    const revision = releasedRevisionOf(loc.functionRid, loc.functionVersion);
    if (!revision) return { issue: `function ${loc.functionRid || "?"} ${loc.functionVersion || ""} is not a released revision you can run` };
    const inputs = {};
    for (const [inputName, input] of Object.entries(effect.function?.functionInputs || {})) {
      if (input?.type !== "staticValue") return { issue: `function input ${inputName} must be a static value` };
      const v = staticValueOf(input.staticValue);
      if (v.error) return { issue: `function input ${inputName}: ${v.error}` };
      inputs[inputName] = v.value;
    }
    steps.push({ kind: "function", function_revision_ref: revision.revision_ref, content_hash: revision.content_hash, inputs });
  }
  return {
    body: {
      project_ref: project.project_id,
      name: name || "automation",
      trigger_kind: "time",
      schedule_spec: { type: "cron", cron: String(sched.cronExpression).trim(), timezone: sched.timeZone || "UTC" },
      steps,
    },
    unenforced: [r.metadata?.expiry?.expireOn ? `expiry ${r.metadata.expiry.expireOn}` : null, "effect retry settings"].filter(Boolean),
  };
}

// The compass resource of one automation (the monitor the wizard just created), under its project.
export function compassAutomationResource(a, projects, principalRef) {
  const rid = monitorRidOf(a.automation_id);
  const project = (projects || []).find((p) => p.project_id === (a.project_id || a.project_ref));
  const projectName = project?.name || a.project_id || "project";
  const at = (t) => ({ time: iso(t), userId: userIdOf(principalRef) });
  return {
    rid, name: a.name || a.automation_id, created: at(a.created_at), modified: at(a.updated_at || a.created_at),
    lastModified: Date.parse(iso(a.updated_at || a.created_at)) || 0, description: a.description || null,
    operations: WRITABLE_OPERATIONS, urlVariables: {}, favorite: null, branches: null, defaultBranch: null,
    path: `/${projectName}/${a.name || a.automation_id}`, longDescription: null, directlyTrashed: false, inTrash: false,
    isAutosave: false, isHidden: false, isPreviewResource: false, deprecation: null, collections: null, namedCollections: [],
    tags: null, namedTags: [], alias: "", collaborators: [], markings: [], projectAccessMarkings: [], linkedItems: null,
    namedAncestors: [{ rid: "ri.compass.main.folder.0", name: "All files" }, { rid: NAMESPACE_FOLDER_RID, name: "Hypervisor" }, { rid: folderRidOf(a.project_id || a.project_ref), name: projectName }],
    contactInformation: null, classification: null, portfolioRid: null, namespaceRid: "ri.compass.main.namespace.hypervisor", status: null,
  };
}
