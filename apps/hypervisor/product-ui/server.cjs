#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const http = require('http');

const PORT = process.env.PORT || 9228;
// Shell tree selection: IOI_PRODUCT_UI_PUBLIC points at an alternate served tree — the OWNED
// vendored source (product-ui/owned/public), proven wire-equivalent by the shell-parity oracle.
// Default stays the original bundle so the switch is explicit and reversible.
const PUBLIC_DIR = process.env.IOI_PRODUCT_UI_PUBLIC
  ? path.resolve(process.env.IOI_PRODUCT_UI_PUBLIC)
  : path.join(__dirname, 'public');

const chunkMap = {};

const preferenceMocks = new Map([
  ['IS_ONA_ONBOARDED', 'true'],
  ['PREFERRED_AGENT', '00000000-0000-0000-0000-000000007800'],
  ['changelog_last_seen_title', 'User budgets for AI usage'],
  ['ENVIRONMENT_START_COUNT', '1'],
  ['PREFERRED_ENVIRONMENT_CLASS_ID_PER_PROJECT', '[]'],
  ['CONTEXT_URLS', '[]'],
  ['CODEX_SETTINGS', '{}'],
  ['ORGS_PENDING_ONBOARDING', '[]'],
  ['SIDEBAR_SESSION_NUMBER_SHORTCUTS', 'false'],
  ['ENTERPRISE_TRIAL_REQUESTED', 'false'],
  ['PRIVACY_POLICY_UPDATED', 'true'],
  ['DELETE_ARCHIVED_ENVIRONMENTS_AFTER', ''],
  ['PREVIOUS_AUTO_DELETE_POLICY_VALUE', '']
]);

function makePreference(key, value) {
  const stableId = Buffer.from(key).toString('hex').slice(0, 24).padEnd(24, '0');
  return {
    key,
    value,
    id: `mock-${stableId}`,
    createdAt: '2026-06-16T11:22:19.296596Z',
    updatedAt: '2026-06-22T01:01:51.524435Z'
  };
}

function readRequestBody(req, callback) {
  const chunks = [];
  req.on('data', chunk => chunks.push(chunk));
  req.on('end', () => callback(Buffer.concat(chunks).toString('utf8')));
}

function getPreferenceKey(bodyText) {
  if (!bodyText.trim()) return undefined;
  try {
    const body = JSON.parse(bodyText);
    return body.preferenceKey || body.preference?.value || body.preference?.preferenceKey;
  } catch {
    return undefined;
  }
}

function connectEndStreamBuffer() {
  const payload = Buffer.from('{}');
  const header = Buffer.alloc(5);
  header[0] = 2;
  header.writeUInt32BE(payload.length, 1);
  return Buffer.concat([header, payload]);
}

function sendJson(res, payload) {
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(payload));
}

function parseJsonBody(bodyText) {
  if (!bodyText.trim()) return {};
  const jsonStart = bodyText.indexOf('{');
  const jsonText = jsonStart >= 0 ? bodyText.slice(jsonStart) : bodyText;
  try {
    return JSON.parse(jsonText);
  } catch {
    return {};
  }
}

function readJsonFixture(relativePath, fallback = {}) {
  try {
    return JSON.parse(fs.readFileSync(path.join(PUBLIC_DIR, relativePath), 'utf8'));
  } catch {
    return fallback;
  }
}

const environmentPhaseOverrides = new Map();
const primaryEnvironmentId = '019ee1b5-0cdd-72af-81e4-327345446648';
const primaryAgentExecutionId = '019ee1b5-526c-76b5-acdb-ddded343b271';
const primaryMachineSessionId = '019ee5e9-626b-7ae8-892d-0990ec3cfd6d';
const runnerId = '019ed02a-fe51-766f-8663-1c478f189fde';
const runtimeHost = '01984226-59c0-76bf-b179-480c41c9ef06.us-east-1-01.ioi.dev';
const hypervisorLogoSvg = '<svg width="24" height="24" viewBox="108.97 89.47 781.56 706.06" fill="none" xmlns="http://www.w3.org/2000/svg"><g stroke="currentColor" stroke-width="12" stroke-linejoin="round" stroke-linecap="round"><path d="M295.299 434.631L295.299 654.116 485.379 544.373z"></path><path d="M500 535.931L697.39 421.968 500 308.005 302.61 421.968z"></path><path d="M514.621 544.373L704.701 654.115 704.701 434.631z"></path><path d="M280.678 662.557L280.678 425.086 123.957 695.903 145.513 740.594z"></path><path d="M719.322 662.557L854.487 740.594 876.043 695.903 719.322 425.085z"></path><path d="M287.988 675.22L151.883 753.8 164.878 780.741 470.757 780.741 287.988 675.22z"></path><path d="M712.012 675.219L529.242 780.741 835.122 780.741 848.117 753.8 712.012 675.219z"></path><path d="M492.689 295.343L492.689 104.779 466.038 104.779 287.055 414.066z"></path><path d="M507.31 295.342L712.945 414.066 533.962 104.779 507.31 104.779z"></path><path d="M302.61 666.778L500 780.741 500 552.815z"></path><path d="M500 552.815L500 780.741 697.39 666.778z"></path></g></svg>';
const hypervisorBrandStyles = `<style id="hypervisor-brand-style">
:root {
  --hypervisor-activity-text: currentColor;
  --hypervisor-activity-text-strong: currentColor;
  --hypervisor-activity-brand-tick: currentColor;
}
.hypervisor-activity-brand-tick {
  width: 1px;
  height: 13px;
  display: block;
  flex-shrink: 0;
  background: var(--hypervisor-activity-brand-tick);
}
.hypervisor-activity-brand {
  width: 50px;
  height: 32px;
  color: var(--hypervisor-activity-text-strong);
}
.hypervisor-activity-brand {
  width: auto;
  min-width: 50px;
  height: 32px;
  flex-shrink: 0;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  padding: 0;
  border: 0;
  background: transparent;
  color: var(--hypervisor-activity-text);
  cursor: pointer;
}
.hypervisor-activity-brand-mark {
  width: 16px;
  height: 16px;
  display: block;
  flex-shrink: 0;
  overflow: visible;
}
.hypervisor-logo-home-link {
  color: var(--content-primary, currentColor);
  gap: 8px;
}
.hypervisor-wordmark-brand-host {
  width: 100%;
  height: 100%;
  display: flex;
  align-items: center;
  justify-content: center;
}
.hypervisor-applications-sidebar-section {
  margin: 0;
  padding: 0;
}
.hypervisor-applications-sidebar-heading {
  display: flex;
  align-items: center;
  justify-content: flex-start;
  min-height: 32px;
  padding: 0 8px 0 0;
  color: var(--content-secondary, var(--content-muted, rgba(255, 255, 255, 0.58)));
  font-size: 14px;
  font-weight: 500;
  letter-spacing: 0;
  text-transform: none;
}
.hypervisor-applications-sidebar-heading-main {
  display: flex;
  align-items: center;
  gap: 6px;
  min-width: 0;
}
.hypervisor-applications-sidebar-heading-icon {
  width: 32px;
  height: 32px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  flex: 0 0 auto;
}
.hypervisor-selected-application {
  width: 100%;
  min-height: 36px;
  margin: 2px 0 0 0;
  padding: 6px 8px;
  display: flex;
  align-items: center;
  gap: 9px;
  border: 0;
  border-radius: 8px;
  background: transparent;
  color: var(--content-primary, currentColor);
  cursor: pointer;
  text-align: left;
}
.hypervisor-selected-application:hover,
.hypervisor-selected-application:focus-visible {
  background: var(--surface-hover, rgba(255, 255, 255, 0.08));
  outline: none;
}
.hypervisor-application-icon {
  width: 20px;
  height: 20px;
  display: block;
  flex: 0 0 auto;
  border-radius: 4px;
}
.hypervisor-selected-application-copy {
  min-width: 0;
  display: flex;
  flex-direction: column;
  gap: 2px;
}
.hypervisor-selected-application-title {
  overflow: hidden;
  white-space: nowrap;
  text-overflow: ellipsis;
  font-size: 14px;
  font-weight: 650;
  line-height: 18px;
}
.hypervisor-applications-sidebar-empty {
  margin: 2px 0 0 0;
  padding: 2px 8px 6px 0;
  color: var(--content-tertiary, var(--content-muted, rgba(255, 255, 255, 0.45)));
  font-size: 13px;
  line-height: 18px;
}
[data-sidebar-container="true"] .hypervisor-applications-sidebar-section {
  padding-left: 0;
}
[data-sidebar-container="true"][style*="48px"] .hypervisor-applications-sidebar-heading,
[data-sidebar-container="true"]:has([style*="width: 48px"]) .hypervisor-applications-sidebar-heading {
  display: none;
}
[data-sidebar-container="true"][style*="48px"] .hypervisor-selected-application-copy,
[data-sidebar-container="true"]:has([style*="width: 48px"]) .hypervisor-selected-application-copy {
  display: none;
}
[data-sidebar-container="true"][style*="48px"] .hypervisor-applications-sidebar-section,
[data-sidebar-container="true"]:has([style*="width: 48px"]) .hypervisor-applications-sidebar-section {
  padding-left: 8px;
  padding-right: 8px;
}
[data-sidebar-container="true"][style*="48px"] .hypervisor-selected-application,
[data-sidebar-container="true"]:has([style*="width: 48px"]) .hypervisor-selected-application {
  width: 32px;
  height: 32px;
  min-height: 32px;
  justify-content: center;
  padding: 0;
}
.hypervisor-applications-modal-backdrop {
  position: fixed;
  inset: 0;
  z-index: 2147483000;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 32px;
  background: rgba(0, 0, 0, 0.56);
  color: var(--content-primary, #f3f4f6);
  backdrop-filter: blur(2px);
}
.hypervisor-applications-modal {
  width: min(1300px, calc(100vw - 96px));
  height: min(750px, calc(100vh - 96px));
  min-height: 540px;
  display: grid;
  grid-template-rows: 48px 1fr;
  overflow: hidden;
  border: 1px solid var(--border-base, rgba(255, 255, 255, 0.16));
  border-radius: 4px;
  background: var(--surface-01, #151a20);
  box-shadow: 0 24px 80px rgba(0, 0, 0, 0.45);
}
.hypervisor-applications-modal-header {
  display: grid;
  grid-template-columns: 1fr auto auto;
  align-items: center;
  gap: 12px;
  border-bottom: 1px solid var(--border-base, rgba(255, 255, 255, 0.16));
  background: var(--surface-02, #171d24);
}
.hypervisor-applications-search {
  height: 100%;
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 0 16px;
  color: var(--content-muted, #9aa4b2);
}
.hypervisor-applications-search input {
  width: 100%;
  min-width: 0;
  border: 0;
  outline: 0;
  background: transparent;
  color: var(--content-primary, #f3f4f6);
  font-size: 16px;
}
.hypervisor-applications-search input::placeholder {
  color: var(--content-muted, #9aa4b2);
}
.hypervisor-applications-modal-action {
  height: 32px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  border: 0;
  border-left: 1px solid var(--border-base, rgba(255, 255, 255, 0.14));
  background: transparent;
  color: var(--content-primary, #f3f4f6);
  cursor: pointer;
  padding: 0 16px;
  font-size: 14px;
}
.hypervisor-applications-modal-action:hover,
.hypervisor-applications-modal-action:focus-visible {
  background: rgba(255, 255, 255, 0.06);
  outline: none;
}
.hypervisor-applications-modal-body {
  min-height: 0;
  display: grid;
  grid-template-columns: 250px minmax(420px, 1fr) 315px;
}
.hypervisor-applications-category-rail {
  overflow: auto;
  border-right: 1px solid var(--border-base, rgba(255, 255, 255, 0.14));
  background: #151b22;
  padding: 8px 0 18px;
}
.hypervisor-applications-category {
  width: 100%;
  min-height: 38px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  border: 0;
  background: transparent;
  color: var(--content-primary, #f3f4f6);
  cursor: pointer;
  padding: 0 16px;
  text-align: left;
  font-size: 14px;
}
.hypervisor-applications-category[data-active="true"],
.hypervisor-applications-category:hover,
.hypervisor-applications-category:focus-visible {
  background: rgba(255, 255, 255, 0.11);
  outline: none;
}
.hypervisor-applications-category-count {
  color: var(--content-muted, #9aa4b2);
}
.hypervisor-applications-category-label {
  margin: 18px 16px 8px;
  color: var(--content-muted, #a8b1be);
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}
.hypervisor-applications-list {
  min-height: 0;
  overflow: auto;
  padding: 18px 20px 24px;
}
.hypervisor-applications-group-title {
  margin: 0 0 12px;
  color: var(--content-muted, #a8b1be);
  font-size: 16px;
  font-weight: 500;
}
.hypervisor-applications-group {
  padding-bottom: 24px;
  border-bottom: 1px solid var(--border-base, rgba(255, 255, 255, 0.14));
  margin-bottom: 22px;
}
.hypervisor-applications-group:last-child {
  border-bottom: 0;
}
.hypervisor-application-row {
  width: 100%;
  min-height: 52px;
  display: grid;
  grid-template-columns: 38px 1fr auto;
  align-items: center;
  gap: 2px;
  border: 0;
  border-radius: 2px;
  background: transparent;
  color: var(--content-primary, #f3f4f6);
  cursor: pointer;
  padding: 7px 10px;
  text-align: left;
}
.hypervisor-application-row:hover,
.hypervisor-application-row:focus-visible,
.hypervisor-application-row[data-selected="true"] {
  background: rgba(255, 255, 255, 0.12);
  outline: none;
}
.hypervisor-application-row-title {
  font-size: 14px;
  font-weight: 650;
  line-height: 18px;
}
.hypervisor-application-row-description {
  color: var(--content-muted, #a8b1be);
  font-size: 12px;
  line-height: 17px;
}
.hypervisor-applications-detail {
  min-height: 0;
  border-left: 1px solid var(--border-base, rgba(255, 255, 255, 0.14));
  background: #151b22;
  padding: 16px;
}
.hypervisor-applications-detail-card {
  display: flex;
  flex-direction: column;
  gap: 14px;
}
.hypervisor-applications-detail-top {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 12px;
}
.hypervisor-applications-open {
  border: 0;
  border-radius: 4px;
  background: rgba(80, 129, 210, 0.28);
  color: #b7d1ff;
  cursor: pointer;
  padding: 7px 12px;
  font-size: 13px;
}
.hypervisor-applications-open:hover,
.hypervisor-applications-open:focus-visible {
  background: rgba(80, 129, 210, 0.38);
  outline: none;
}
.hypervisor-applications-detail-title {
  margin: 0;
  font-size: 16px;
  font-weight: 750;
}
.hypervisor-applications-detail-description {
  margin: 0;
  color: var(--content-muted, #a8b1be);
  font-size: 14px;
  line-height: 22px;
}
.hypervisor-applications-detail-link {
  width: fit-content;
  border: 0;
  background: transparent;
  color: #9ec5ff;
  cursor: pointer;
  padding: 0;
  font-size: 12px;
}
.hypervisor-applications-empty-detail {
  height: 100%;
  display: flex;
  align-items: center;
  justify-content: center;
  color: var(--content-muted, #a8b1be);
  text-align: center;
}
.hypervisor-blank-application-surface {
  min-height: 100%;
  background: var(--surface-01, #121212);
  color: var(--content-primary, currentColor);
  padding: 32px;
}
.hypervisor-blank-application-title {
  display: inline-flex;
  align-items: center;
  gap: 10px;
  color: var(--content-muted, rgba(255, 255, 255, 0.58));
  font-size: 14px;
  font-weight: 500;
}
@media (max-width: 980px) {
  .hypervisor-applications-modal-backdrop {
    padding: 12px;
  }
  .hypervisor-applications-modal {
    width: calc(100vw - 24px);
    height: calc(100vh - 24px);
  }
  .hypervisor-applications-modal-body {
    grid-template-columns: 180px 1fr;
  }
  .hypervisor-applications-detail {
    display: none;
  }
}
</style>`;
const hypervisorBrandMarkup = `<span class="hypervisor-activity-brand" aria-hidden="true"><span class="hypervisor-activity-brand-tick"></span>${hypervisorLogoSvg.replace('<svg ', '<svg class="hypervisor-activity-brand-mark" ')}<span class="hypervisor-activity-brand-tick"></span></span>`;
const hypervisorMarkMarkup = hypervisorLogoSvg.replace('<svg ', '<svg class="hypervisor-activity-brand-mark" ');

function brandText(value) {
  return String(value);
}

function brandHtml(content) {
  return brandText(content)
    .replace(/\/static\/ioi-logo\.svg/g, '/static/hypervisor-logo.svg')
    .replace(/\/static\/ioi-lettermark\.svg/g, '/static/hypervisor-logo.svg')
    .replace(/\/static\/ioi-dark\.ico/g, '/static/hypervisor-logo.svg')
    .replace(/\/static\/ioi-light\.ico/g, '/static/hypervisor-logo.svg')
    .replace(/\/ioi-logo\.svg/g, '/static/hypervisor-logo.svg')
    .replace(/\/ioi\.png/g, '/static/hypervisor-logo.svg')
    // Rebrand the .ioi/ config-dir convention to .ioi/ (e.g. .ioi/automations.yaml).
    // The trailing slash scopes this to config paths only — never the `.ioi` theme class.
    .replace(/\.ioi\//g, '.ioi/');
}

function mockAccessToken(scope, id) {
  return Buffer.from(`ioi-mirror:${scope}:${id}:2026-06-22`).toString('base64url');
}

function getEnvironmentFixture(environmentId = primaryEnvironmentId) {
  const list = readJsonFixture('api/ioi.v1.EnvironmentService/ListEnvironments', { environments: [] });
  const fromList = list.environments?.find(environment => environment.id === environmentId)
    || list.environments?.find(environment => environment.id === primaryEnvironmentId);
  if (fromList) return structuredClone(fromList);

  const single = readJsonFixture('api/ioi.v1.EnvironmentService/GetEnvironment', {});
  if (single.environment) return structuredClone(single.environment);
  return null;
}

function normalizeAgentExecution(agentExecution) {
  if (!agentExecution) return null;
  const agentExecutionId = agentExecution.id || primaryAgentExecutionId;
  const next = structuredClone(agentExecution);
  next.id = agentExecutionId;
  next.status ||= {};
  next.status.conversationUrl ||= `https://${runtimeHost}/runners/${runnerId}/agent/${agentExecutionId}/conversation`;
  next.status.transcriptUrl ||= `https://${runtimeHost}/runners/${runnerId}/agent/${agentExecutionId}/transcript`;
  delete next.status.conversationUrls;
  next.status.usedEnvironments ||= [{ environmentId: primaryEnvironmentId }];
  next.metadata ||= {};
  next.metadata.annotations ||= {};
  delete next.metadata.annotations['ioi.com/conversation-streaming-v2'];
  return next;
}

function listAgentExecutionsFixture() {
  const payload = readJsonFixture('api/ioi.v1.AgentService/ListAgentExecutions', { pagination: {}, agentExecutions: [] });
  return {
    ...payload,
    agentExecutions: (payload.agentExecutions || []).map(normalizeAgentExecution).filter(Boolean)
  };
}

function getAgentExecutionFixture(agentExecutionId = primaryAgentExecutionId) {
  const list = listAgentExecutionsFixture().agentExecutions;
  return list.find(agentExecution => agentExecution.id === agentExecutionId)
    || list.find(agentExecution => agentExecution.id === primaryAgentExecutionId)
    || normalizeAgentExecution({
      id: agentExecutionId,
      spec: {
        desiredPhase: 'PHASE_RUNNING',
        agentId: '00000000-0000-0000-0000-000000007800',
        codeContext: { environmentId: primaryEnvironmentId }
      },
      metadata: {
        name: 'Design Post-Quantum Computing Website',
        createdAt: '2026-06-19T21:06:57.260435Z',
        updatedAt: '2026-06-19T21:09:32.521165Z',
        annotations: {}
      },
      status: {
        phase: 'PHASE_STOPPED',
        usedEnvironments: [{ environmentId: primaryEnvironmentId }]
      }
    });
}

function projectEnvironmentFromBody(body) {
  return body.environmentId
    || body.req?.environmentId
    || body.environment?.id
    || body.id
    || primaryEnvironmentId;
}

function normalizeEnvironment(environment, phaseOverride) {
  if (!environment) return null;
  const environmentId = environment.id || primaryEnvironmentId;
  const next = structuredClone(environment);
  const desired = phaseOverride || environmentPhaseOverrides.get(environmentId);
  const running = desired === 'running';
  const stopping = desired === 'stopping';
  const deleting = desired === 'deleting';

  next.id = environmentId;
  next.metadata ||= {};
  next.metadata.runnerId ||= runnerId;
  next.metadata.lastStartedAt ||= '2026-06-21T23:14:00.000000Z';
  next.spec ||= {};
  next.spec.desiredPhase = running
    ? 'ENVIRONMENT_PHASE_RUNNING'
    : deleting
      ? 'ENVIRONMENT_PHASE_DELETED'
      : 'ENVIRONMENT_PHASE_STOPPED';

  next.status ||= {};
  next.status.phase = running
    ? 'ENVIRONMENT_PHASE_RUNNING'
    : stopping
      ? 'ENVIRONMENT_PHASE_STOPPING'
      : deleting
        ? 'ENVIRONMENT_PHASE_DELETING'
        : 'ENVIRONMENT_PHASE_STOPPED';
  next.status.environmentUrls ||= {};
  next.status.environmentUrls.ssh ||= { url: `https://${environmentId}.us-east-1-01.ioi.dev:443` };
  next.status.environmentUrls.logs ||= `https://${runtimeHost}/runners/${runnerId}/logs/environments/${environmentId}`;
  next.status.environmentUrls.supportBundle ||= `https://${runtimeHost}/runners/${runnerId}/support-bundle/environments/${environmentId}`;
  next.status.environmentUrls.vmLiveUsage ||= `https://${runtimeHost}/runners/${runnerId}/vm-live-usage/environments/${environmentId}`;
  next.status.environmentUrls.ops ||= `https://${runtimeHost}/runners/${runnerId}/supervisor/environments/${environmentId}`;
  next.status.machine ||= {};
  next.status.machine.phase = running ? 'PHASE_RUNNING' : stopping ? 'PHASE_STOPPING' : 'PHASE_STOPPED';
  if (running) {
    next.status.devcontainer ||= {};
    next.status.devcontainer.phase ||= 'CONTENT_PHASE_READY';
    next.status.devcontainer.remoteWorkspaceFolder ||= '/workspaces/workspaces';
    next.status.content ||= {};
    next.status.content.phase ||= 'CONTENT_PHASE_READY';
    next.status.content.contentLocationInMachine ||= '/workspaces/workspaces';
  }
  return next;
}

function sendEnvironment(res, environmentId, phaseOverride) {
  sendJson(res, { environment: normalizeEnvironment(getEnvironmentFixture(environmentId), phaseOverride) });
}

function managedRunnerPayload() {
  return {
    runner: {
      runnerId: '019ed02a-fe51-766f-8663-1c478f189fde',
      createdAt: '2026-06-16T11:22:19.089417Z',
      updatedAt: '2026-06-22T01:20:35.398903Z',
      name: 'Hypervisor Cloud (US01)',
      spec: {
        desiredPhase: 'RUNNER_PHASE_ACTIVE',
        configuration: {
          region: 'us-east-1',
          releaseChannel: 'RUNNER_RELEASE_CHANNEL_STABLE',
          devcontainerImageCacheEnabled: true
        },
        variant: 'RUNNER_VARIANT_STANDARD'
      },
      status: {
        updatedAt: '2026-06-22T01:02:35.396174112Z',
        version: '20260616.716',
        phase: 'RUNNER_PHASE_ACTIVE',
        message: 'Managed runner ready in local mirror'
      },
      kind: 'RUNNER_KIND_REMOTE'
    }
  };
}

function handleDynamicApi(req, res, pathname) {
  if (pathname === '/api/ioi.v1.EventService/WatchEvents') {
    res.writeHead(200, {
      'Content-Type': 'application/connect+json',
      'Connect-Protocol-Version': '1',
      'Cache-Control': 'no-cache'
    });
    res.end(connectEndStreamBuffer());
    return true;
  }

  if (pathname === '/api/ioi.v1.RunnerService/CreateRunner') {
    readRequestBody(req, () => sendJson(res, managedRunnerPayload()));
    return true;
  }

  if (pathname === '/api/ioi.v1.RunnerService/CheckAuthenticationForHost') {
    readRequestBody(req, () => sendJson(res, { type: 'Authenticated' }));
    return true;
  }

  if (pathname === '/api/ioi.v1.UserService/GetPreference') {
    readRequestBody(req, bodyText => {
      const key = getPreferenceKey(bodyText);
      if (!key || !preferenceMocks.has(key)) {
        sendJson(res, { preference: null });
        return;
      }
      sendJson(res, { preference: makePreference(key, preferenceMocks.get(key)) });
    });
    return true;
  }

  if (pathname === '/api/ioi.v1.UserService/SetPreference') {
    readRequestBody(req, bodyText => {
      const body = parseJsonBody(bodyText);
      const key = body.preference?.key || body.key || body.preferenceKey || 'MIRROR_PREFERENCE';
      const value = body.preference?.value ?? body.value ?? '';
      preferenceMocks.set(key, value);
      sendJson(res, { preference: makePreference(key, value) });
    });
    return true;
  }

  if (pathname === '/api/ioi.v1.EnvironmentService/GetEnvironment') {
    readRequestBody(req, bodyText => {
      const body = parseJsonBody(bodyText);
      sendEnvironment(res, body.environmentId || primaryEnvironmentId);
    });
    return true;
  }

  if (pathname === '/api/ioi.v1.EnvironmentService/CreateEnvironmentAccessToken') {
    readRequestBody(req, bodyText => {
      const body = parseJsonBody(bodyText);
      const environmentId = projectEnvironmentFromBody(body);
      sendJson(res, { accessToken: mockAccessToken('environment', environmentId) });
    });
    return true;
  }

  if (pathname === '/api/ioi.v1.EnvironmentService/CreateEnvironmentLogsToken') {
    readRequestBody(req, bodyText => {
      const body = parseJsonBody(bodyText);
      const environmentId = projectEnvironmentFromBody(body);
      sendJson(res, { accessToken: mockAccessToken('logs', environmentId) });
    });
    return true;
  }

  if (pathname === '/api/ioi.v1.EnvironmentService/StartEnvironment') {
    readRequestBody(req, bodyText => {
      const body = parseJsonBody(bodyText);
      const environmentId = projectEnvironmentFromBody(body);
      environmentPhaseOverrides.set(environmentId, 'running');
      sendJson(res, { environment: normalizeEnvironment(getEnvironmentFixture(environmentId), 'running') });
    });
    return true;
  }

  if (pathname === '/api/ioi.v1.EnvironmentService/StopEnvironment') {
    readRequestBody(req, bodyText => {
      const body = parseJsonBody(bodyText);
      const environmentId = projectEnvironmentFromBody(body);
      environmentPhaseOverrides.set(environmentId, 'stopped');
      sendJson(res, { environment: normalizeEnvironment(getEnvironmentFixture(environmentId), 'stopped') });
    });
    return true;
  }

  if (pathname === '/api/ioi.v1.EnvironmentService/DeleteEnvironment') {
    readRequestBody(req, bodyText => {
      const body = parseJsonBody(bodyText);
      const environmentId = projectEnvironmentFromBody(body);
      environmentPhaseOverrides.set(environmentId, 'deleting');
      sendJson(res, { environment: normalizeEnvironment(getEnvironmentFixture(environmentId), 'deleting') });
    });
    return true;
  }

  if (pathname === '/api/ioi.v1.EnvironmentService/UpdateEnvironment') {
    readRequestBody(req, bodyText => {
      const body = parseJsonBody(bodyText);
      const environmentId = projectEnvironmentFromBody(body);
      const desiredPhase = body.spec?.desiredPhase || body.req?.spec?.desiredPhase;
      if (desiredPhase === 'ENVIRONMENT_PHASE_RUNNING') environmentPhaseOverrides.set(environmentId, 'running');
      if (desiredPhase === 'ENVIRONMENT_PHASE_STOPPED') environmentPhaseOverrides.set(environmentId, 'stopped');
      sendEnvironment(res, environmentId);
    });
    return true;
  }

  if (
    pathname === '/api/ioi.v1.EnvironmentService/CreateEnvironment'
    || pathname === '/api/ioi.v1.EnvironmentService/CreateEnvironmentFromProject'
  ) {
    readRequestBody(req, () => {
      environmentPhaseOverrides.set(primaryEnvironmentId, 'running');
      sendJson(res, { environment: normalizeEnvironment(getEnvironmentFixture(primaryEnvironmentId), 'running') });
    });
    return true;
  }

  if (
    pathname === '/api/ioi.v1.EnvironmentService/MarkEnvironmentActive'
    || pathname === '/api/ioi.v1.EnvironmentService/ArchiveEnvironment'
    || pathname === '/api/ioi.v1.EnvironmentService/UnarchiveEnvironment'
  ) {
    readRequestBody(req, () => sendJson(res, {}));
    return true;
  }

  if (pathname === '/api/ioi.v1.AgentService/CreateAgentExecution') {
    readRequestBody(req, () => sendJson(res, { agentExecutionId: primaryAgentExecutionId }));
    return true;
  }

  if (pathname === '/api/ioi.v1.AgentService/StartAgent') {
    readRequestBody(req, () => sendJson(res, { agentExecutionId: primaryAgentExecutionId }));
    return true;
  }

  if (pathname === '/api/ioi.v1.AgentService/ListAgentExecutions') {
    readRequestBody(req, () => sendJson(res, listAgentExecutionsFixture()));
    return true;
  }

  if (pathname === '/api/ioi.v1.AgentService/GetAgentExecution') {
    readRequestBody(req, bodyText => {
      const body = parseJsonBody(bodyText);
      sendJson(res, { agentExecution: getAgentExecutionFixture(body.agentExecutionId || primaryAgentExecutionId) });
    });
    return true;
  }

  if (pathname === '/api/ioi.v1.AgentService/CreateAgentExecutionConversationToken') {
    readRequestBody(req, bodyText => {
      const body = parseJsonBody(bodyText);
      const agentExecutionId = body.agentExecutionId || primaryAgentExecutionId;
      sendJson(res, { token: mockAccessToken('conversation', agentExecutionId) });
    });
    return true;
  }

  if (
    pathname === '/api/ioi.v1.AgentService/SendToAgentExecution'
    || pathname === '/api/ioi.v1.AgentService/StopAgentExecution'
    || pathname === '/api/ioi.v1.AgentService/DeleteAgentExecution'
  ) {
    readRequestBody(req, () => sendJson(res, {}));
    return true;
  }

  return false;
}

function mirrorBootGuard() {
  return `<script>
(() => {
  try {
    navigator.serviceWorker?.getRegistrations?.().then((registrations) => {
      registrations.forEach((registration) => registration.unregister());
    }).catch(() => {});
    window.caches?.keys?.().then((keys) => {
      keys.forEach((key) => window.caches.delete(key));
    }).catch(() => {});
  } catch {}
  const blockedHosts = ['widget.usepylon.com', 'apichatwidget.usepylon.com', 'vscode.ioi.io', 'vscode.localhost'];
  const isBlocked = (value) => typeof value === 'string' && blockedHosts.some((host) => value.includes(host));
  const isRuntimeProbe = (value) => typeof value === 'string' && value.includes('.ioi.dev/');
  const hypervisorBrandMarkup = ${JSON.stringify(hypervisorBrandMarkup)};
  const hypervisorMarkMarkup = ${JSON.stringify(hypervisorMarkMarkup)};
  const brandText = (value) => String(value).replace(/\\bONA\\b/g, 'Hypervisor').replace(/\\bOna\\b/g, 'Hypervisor');
  const brandAssetPath = (value) => brandText(value)
    .replace(/\\/static\\/ioi-logo\\.svg/g, '/static/hypervisor-logo.svg')
    .replace(/\\/static\\/ioi-lettermark\\.svg/g, '/static/hypervisor-logo.svg')
    .replace(/\\/static\\/ioi-dark\\.ico/g, '/static/hypervisor-logo.svg')
    .replace(/\\/static\\/ioi-light\\.ico/g, '/static/hypervisor-logo.svg')
    .replace(/\\/ioi-logo\\.svg/g, '/static/hypervisor-logo.svg')
    .replace(/\\/ioi\\.png/g, '/static/hypervisor-logo.svg');
  const shouldSkipBrandNode = (node) => {
    const parent = node.parentElement;
    if (!parent) return true;
    return ['SCRIPT', 'STYLE', 'NOSCRIPT', 'TEXTAREA', 'INPUT', 'CODE', 'PRE'].includes(parent.tagName);
  };
  const hypervisorApplicationStorageKey = 'hypervisor.selectedApplicationId';
  const hypervisorApplicationCatalog = [
    { id: 'control-panel', name: 'Control Panel', category: 'Administration', description: 'Manage critical platform operations for an enrollment or organization.', color: '#48607d', glyph: 'C' },
    { id: 'resource-management', name: 'Resource Management', category: 'Administration', description: 'Track and manage costs, budgets, resource queues, and usage limits.', color: '#125f6b', glyph: 'R' },
    { id: 'upgrade-assistant', name: 'Upgrade Assistant', category: 'Administration', description: 'Track important platform updates and changes affecting the platform.', color: '#265e9b', glyph: 'U' },
    { id: 'aip-analyst', name: 'AIP Analyst', category: 'Analytics & Operations', description: 'Agentic ad-hoc analysis.', color: '#8b4d1f', glyph: 'A' },
    { id: 'contour', name: 'Contour', category: 'Analytics & Operations', description: 'Analyze large datasets with filters, joins, and visualizations.', color: '#8a5c27', glyph: 'C' },
    { id: 'fusion', name: 'Fusion', category: 'Analytics & Operations', description: 'Interact with live data in a familiar spreadsheet interface.', color: '#126441', glyph: 'F' },
    { id: 'insight', name: 'Insight', category: 'Analytics & Operations', description: 'Search, analyze, and view data in your ontology.', color: '#3e6c2d', glyph: 'I' },
    { id: 'map', name: 'Map', category: 'Analytics & Operations', description: 'Analyze geospatial and geotemporal data.', color: '#16703f', glyph: 'M' },
    { id: 'notepad', name: 'Notepad', category: 'Analytics & Operations', description: 'Create, share, and export object-aware documents and reports.', color: '#285b8f', glyph: 'N' },
    { id: 'quiver', name: 'Quiver', category: 'Analytics & Operations', description: 'Visualize, analyze, and build interactive dashboards.', color: '#514184', glyph: 'Q' },
    { id: 'vertex', name: 'Vertex', category: 'Analytics & Operations', description: 'Visualize and analyze complex relationships between objects and systems.', color: '#195d86', glyph: 'V' },
    { id: 'pipeline-builder', name: 'Pipeline Builder', category: 'Application development', description: 'Build, inspect, and publish data pipelines.', color: '#0e7f79', glyph: 'P' },
    { id: 'code-repositories', name: 'Code Repositories', category: 'Application development', description: 'Browse and manage repository-backed development work.', color: '#44546f', glyph: '<>' },
    { id: 'workshop', name: 'Workshop', category: 'Application development', description: 'Create operational applications and workflows.', color: '#5d4f9c', glyph: 'W' },
    { id: 'slate', name: 'Slate', category: 'Application development', description: 'Compose operational interfaces and dashboards.', color: '#7750a6', glyph: 'S' },
    { id: 'automate', name: 'Automate', category: 'Application development', description: 'Create event-driven application automation.', color: '#265b9a', glyph: 'A' },
    { id: 'developer-console', name: 'Developer Console', category: 'Application development', description: 'Inspect developer resources, clients, and integrations.', color: '#455469', glyph: 'D' },
    { id: 'workflow-builder', name: 'Workflow Builder', category: 'Application development', description: 'Draft and manage process workflows.', color: '#546078', glyph: 'W' },
    { id: 'ontology-manager', name: 'Ontology Manager', category: 'Data integration', description: 'Design object types, links, and action contracts.', color: '#294a7b', glyph: 'O' },
    { id: 'object-explorer', name: 'Object Explorer', category: 'Data integration', description: 'Inspect object data and relationships.', color: '#2c6770', glyph: 'O' },
    { id: 'data-lineage', name: 'Data Lineage', category: 'Data integration', description: 'Trace datasets, transforms, and downstream consumers.', color: '#735f25', glyph: 'L' },
    { id: 'file-imports', name: 'File Imports', category: 'Data integration', description: 'Stage and validate uploaded source files.', color: '#555d69', glyph: 'F' },
    { id: 'data-connector', name: 'Data Connector', category: 'Data integration', description: 'Configure external source connections.', color: '#226c52', glyph: 'D' },
    { id: 'transform', name: 'Transform', category: 'Data integration', description: 'Author transform logic and pipeline steps.', color: '#7a4b2d', glyph: 'T' },
    { id: 'time-series-catalog', name: 'Time Series Catalog', category: 'Data integration', description: 'Manage time series signals and telemetry.', color: '#3c5d86', glyph: 'T' },
    { id: 'media-sets', name: 'Media Sets', category: 'Data integration', description: 'Catalog media artifacts and annotations.', color: '#5b526f', glyph: 'M' },
    { id: 'data-health', name: 'Data Health', category: 'Data integration', description: 'Monitor pipeline freshness and quality.', color: '#266843', glyph: 'H' },
    { id: 'tables', name: 'Tables', category: 'Data integration', description: 'Browse structured datasets and table schemas.', color: '#394f7a', glyph: 'T' },
    { id: 'jobs', name: 'Jobs', category: 'Data integration', description: 'Inspect scheduled and ad-hoc execution jobs.', color: '#6b5035', glyph: 'J' },
    { id: 'schedules', name: 'Schedules', category: 'Data integration', description: 'Coordinate recurring pipeline execution.', color: '#5d6231', glyph: 'S' },
    { id: 'syncs', name: 'Syncs', category: 'Data integration', description: 'Observe replication and sync activity.', color: '#2a6362', glyph: 'S' },
    { id: 'sources', name: 'Sources', category: 'Data integration', description: 'Manage source-system inventory.', color: '#4b5c72', glyph: 'S' },
    { id: 'monitoring', name: 'Monitoring', category: 'Data integration', description: 'Track operational health and incidents.', color: '#395f7d', glyph: 'M' },
    { id: 'models', name: 'Models', category: 'Developer toolchain', description: 'Manage model artifacts and serving endpoints.', color: '#4b5f89', glyph: 'M' },
    { id: 'foundry-sdk', name: 'Foundry SDK', category: 'Developer toolchain', description: 'Explore SDK clients and generated bindings.', color: '#4e5365', glyph: 'S' },
    { id: 'api-explorer', name: 'API Explorer', category: 'Developer toolchain', description: 'Inspect and test API contracts.', color: '#59647a', glyph: 'A' },
    { id: 'checkpoints', name: 'Checkpoints', category: 'Developer toolchain', description: 'Review saved execution and development checkpoints.', color: '#66624a', glyph: 'C' },
    { id: 'model-garden', name: 'Model Garden', category: 'Models', description: 'Discover model options and local configuration targets.', color: '#4b5aa3', glyph: 'G' },
    { id: 'model-studio', name: 'Model Studio', category: 'Models', description: 'Evaluate and package model behavior.', color: '#384f8c', glyph: 'S' },
    { id: 'model-evaluation', name: 'Model Evaluation', category: 'Models', description: 'Compare runs, prompts, and quality metrics.', color: '#5d4f83', glyph: 'E' },
    { id: 'prompt-studio', name: 'Prompt Studio', category: 'Models', description: 'Draft and test reusable prompt templates.', color: '#6a4e7f', glyph: 'P' },
    { id: 'agent-studio', name: 'Agent Studio', category: 'Models', description: 'Configure agent skills and tool bindings.', color: '#365f8d', glyph: 'A' },
    { id: 'notepad-template', name: 'Notepad Template', category: 'Models', description: 'Author reusable report and analysis templates.', color: '#3a6178', glyph: 'N' },
    { id: 'vector-index', name: 'Vector Index', category: 'Models', description: 'Manage embeddings and retrieval indexes.', color: '#45617a', glyph: 'V' },
    { id: 'ontology', name: 'Ontology', category: 'Ontology', description: 'Browse object models and semantic resources.', color: '#4f5c69', glyph: 'O' },
    { id: 'actions', name: 'Actions', category: 'Ontology', description: 'Manage admitted user and agent actions.', color: '#69577a', glyph: 'A' },
    { id: 'approvals', name: 'Approvals', category: 'Ontology', description: 'Review approvals and pending requests.', color: '#71613f', glyph: 'A' },
    { id: 'object-types', name: 'Object Types', category: 'Ontology', description: 'Inspect object schemas and constraints.', color: '#38646c', glyph: 'O' },
    { id: 'functions', name: 'Functions', category: 'Ontology', description: 'Register and test ontology functions.', color: '#5c5270', glyph: 'F' },
    { id: 'scenario', name: 'Scenario', category: 'Ontology', description: 'Explore planning and what-if scenarios.', color: '#51633e', glyph: 'S' },
    { id: 'cipher', name: 'Cipher', category: 'Security & governance', description: 'Manage governed secrets and sensitive policy posture.', color: '#44586d', glyph: 'C' },
    { id: 'policies', name: 'Policies', category: 'Security & governance', description: 'Review policy controls and enforcement.', color: '#615a3d', glyph: 'P' },
    { id: 'audit', name: 'Audit', category: 'Security & governance', description: 'Inspect audit trails and access events.', color: '#6a4b4b', glyph: 'A' },
    { id: 'markings', name: 'Markings', category: 'Security & governance', description: 'Configure data markings and access labels.', color: '#4d5d76', glyph: 'M' },
    { id: 'marketplace', name: 'Marketplace', category: 'Security & governance', description: 'Browse governed extensions and packaged capabilities.', color: '#536165', glyph: 'M' },
    { id: 'help-center', name: 'Help Center', category: 'Support', description: 'Find documentation and operational support.', color: '#4b6070', glyph: 'H' },
    { id: 'support', name: 'Support', category: 'Support', description: 'Open support resources and diagnostics.', color: '#59606b', glyph: 'S' },
    { id: 'status', name: 'Status', category: 'Support', description: 'Review service status and incidents.', color: '#576f50', glyph: 'S' },
    { id: 'releases', name: 'Releases', category: 'Support', description: 'Track product release notes and changes.', color: '#6d5d42', glyph: 'R' },
    { id: 'admin-docs', name: 'Admin Docs', category: 'Support', description: 'Open administration documentation.', color: '#4c5f78', glyph: 'D' }
  ];
  const hypervisorApplicationCategories = ['Administration', 'Analytics & Operations', 'Application development', 'Data integration', 'Developer toolchain', 'Models', 'Ontology', 'Security & governance', 'Support'];
  const escapeHypervisorHtml = (value) => String(value).replace(/[&<>"']/g, (character) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  })[character]);
  const getHypervisorSelectedApplicationId = () => {
    // Default to zero pinned applications: no app is selected until the operator opens
    // one from the launcher (which calls setHypervisorSelectedApplicationId).
    try {
      return localStorage.getItem(hypervisorApplicationStorageKey) || null;
    } catch {
      return null;
    }
  };
  const setHypervisorSelectedApplicationId = (id) => {
    try {
      localStorage.setItem(hypervisorApplicationStorageKey, id);
    } catch {}
  };
  const getHypervisorApplication = (id) => (id ? hypervisorApplicationCatalog.find((app) => app.id === id) || null : null);
  const renderHypervisorApplicationIcon = (app, className = '') => {
    const label = escapeHypervisorHtml(app.glyph || app.name.slice(0, 1));
    const color = escapeHypervisorHtml(app.color || '#3b5368');
    return '<span class="hypervisor-application-icon ' + className + '" aria-hidden="true" style="background:' + color + ';color:#f5f7fb;display:inline-flex;align-items:center;justify-content:center;font-size:11px;font-weight:750;">' + label + '</span>';
  };
  const renderHypervisorApplicationsSidebarSection = () => {
    const sessions = document.querySelector('[data-testid="sidebar-activity-tabs"]');
    if (!sessions || !sessions.parentElement) return;
    let section = document.querySelector('[data-hypervisor-applications-section]');
    if (!section) {
      section = document.createElement('section');
      section.setAttribute('data-hypervisor-applications-section', 'true');
      section.className = 'hypervisor-applications-sidebar-section';
      sessions.parentElement.insertBefore(section, sessions);
    } else if (section.nextElementSibling !== sessions) {
      sessions.parentElement.insertBefore(section, sessions);
    }
    const selected = getHypervisorApplication(getHypervisorSelectedApplicationId());
    const renderedId = selected ? selected.id : '__none__';
    if (section.dataset.renderedApplicationId === renderedId) return;
    section.dataset.renderedApplicationId = renderedId;
    const heading = '<div class="hypervisor-applications-sidebar-heading text-content-secondary"><span class="hypervisor-applications-sidebar-heading-main"><span class="hypervisor-applications-sidebar-heading-icon" aria-hidden="true"><svg width="18px" height="18px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M4.75 4.75H9.25V9.25H4.75V4.75Z M14.75 4.75H19.25V9.25H14.75V4.75Z M4.75 14.75H9.25V19.25H4.75V14.75Z M14.75 14.75H19.25V19.25H14.75V14.75Z" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/></svg></span><span>Applications</span></span></div>';
    if (!selected) {
      // Zero pinned applications by default: heading + quiet empty hint.
      section.innerHTML = heading + '<p class="hypervisor-applications-sidebar-empty">Your favorite apps will appear here</p>';
      return;
    }
    section.innerHTML = heading
      + '<button type="button" class="hypervisor-selected-application" data-hypervisor-selected-application aria-label="Open selected application: ' + escapeHypervisorHtml(selected.name) + '">'
      + renderHypervisorApplicationIcon(selected)
      + '<span class="hypervisor-selected-application-copy"><span class="hypervisor-selected-application-title">' + escapeHypervisorHtml(selected.name) + '</span></span>'
      + '</button>';
    section.querySelector('[data-hypervisor-selected-application]')?.addEventListener('click', openHypervisorSelectedApplicationSurface);
  };
  const renderHypervisorBlankApplicationSurface = () => {
    if (location.pathname !== '/insights') return;
    const main = document.querySelector('main#main-content');
    if (!main) return;
    const selected = getHypervisorApplication(getHypervisorSelectedApplicationId());
    if (!selected || main.dataset.hypervisorBlankApplicationId === selected.id) return;
    main.dataset.hypervisorBlankApplicationId = selected.id;
    main.innerHTML = '<section class="hypervisor-blank-application-surface" data-hypervisor-blank-application-surface>'
      + '<div class="hypervisor-blank-application-title">' + renderHypervisorApplicationIcon(selected) + '<span>' + escapeHypervisorHtml(selected.name) + '</span></div>'
      + '</section>';
  };
  const hypervisorModalState = { category: 'All apps', query: '', activeId: getHypervisorSelectedApplicationId() };
  const getFilteredHypervisorApplications = () => {
    const query = hypervisorModalState.query.trim().toLowerCase();
    return hypervisorApplicationCatalog.filter((app) => {
      const categoryMatch = hypervisorModalState.category === 'All apps' || app.category === hypervisorModalState.category;
      const queryMatch = !query || (app.name + ' ' + app.description + ' ' + app.category).toLowerCase().includes(query);
      return categoryMatch && queryMatch;
    });
  };
  const renderHypervisorApplicationsModal = () => {
    const modal = document.querySelector('[data-hypervisor-applications-modal]');
    if (!modal) return;
    const filtered = getFilteredHypervisorApplications();
    const active = getHypervisorApplication(hypervisorModalState.activeId) || filtered[0];
    const categoryButtons = ['All apps'].concat(hypervisorApplicationCategories).map((category) => {
      const count = category === 'All apps' ? hypervisorApplicationCatalog.length : hypervisorApplicationCatalog.filter((app) => app.category === category).length;
      return '<button type="button" class="hypervisor-applications-category" data-hypervisor-application-category="' + escapeHypervisorHtml(category) + '" data-active="' + String(hypervisorModalState.category === category) + '"><span>' + escapeHypervisorHtml(category) + '</span><span class="hypervisor-applications-category-count">' + count + '</span></button>';
    }).join('');
    const promoted = getHypervisorApplication(getHypervisorSelectedApplicationId());
    const grouped = hypervisorApplicationCategories.map((category) => {
      const apps = filtered.filter((app) => app.category === category);
      if (!apps.length) return '';
      return '<section class="hypervisor-applications-group"><h3 class="hypervisor-applications-group-title">' + escapeHypervisorHtml(category) + '</h3>'
        + apps.map((app) => '<button type="button" class="hypervisor-application-row" data-hypervisor-application-id="' + escapeHypervisorHtml(app.id) + '" data-selected="' + String(active && active.id === app.id) + '">'
          + renderHypervisorApplicationIcon(app)
          + '<span><span class="hypervisor-application-row-title">' + escapeHypervisorHtml(app.name) + '</span><span class="hypervisor-application-row-description">' + escapeHypervisorHtml(app.description) + '</span></span>'
          + '<span aria-hidden="true">&gt;</span></button>').join('')
        + '</section>';
    }).join('');
    modal.innerHTML = '<section class="hypervisor-applications-modal" role="dialog" aria-modal="true" aria-label="Applications">'
      + '<header class="hypervisor-applications-modal-header"><label class="hypervisor-applications-search"><span aria-hidden="true">Search</span><input data-hypervisor-applications-search value="' + escapeHypervisorHtml(hypervisorModalState.query) + '" placeholder="Search for applications..." /></label><button type="button" class="hypervisor-applications-modal-action" data-hypervisor-applications-filters>Filters</button><button type="button" class="hypervisor-applications-modal-action" data-hypervisor-applications-close aria-label="Close applications">x</button></header>'
      + '<div class="hypervisor-applications-modal-body"><nav class="hypervisor-applications-category-rail" aria-label="Application categories">' + categoryButtons + (promoted ? '<div class="hypervisor-applications-category-label">Promoted apps</div><button type="button" class="hypervisor-applications-category" data-hypervisor-application-id="' + escapeHypervisorHtml(promoted.id) + '"><span>' + escapeHypervisorHtml(promoted.name) + '</span><span class="hypervisor-applications-category-count">Selected</span></button>' : '') + '</nav>'
      + '<main class="hypervisor-applications-list">' + (grouped || '<div class="hypervisor-applications-empty-detail">No applications match this search.</div>') + '</main>'
      + '<aside class="hypervisor-applications-detail">' + (active ? '<div class="hypervisor-applications-detail-card"><div class="hypervisor-applications-detail-top">' + renderHypervisorApplicationIcon(active) + '<button type="button" class="hypervisor-applications-open" data-hypervisor-open-application="' + escapeHypervisorHtml(active.id) + '">Open</button></div><h2 class="hypervisor-applications-detail-title">' + escapeHypervisorHtml(active.name) + '</h2><p class="hypervisor-applications-detail-description">' + escapeHypervisorHtml(active.description) + '</p><button type="button" class="hypervisor-applications-detail-link">Documentation</button></div>' : '<div class="hypervisor-applications-empty-detail">Click on an application to see details</div>') + '</aside></div></section>';
    modal.querySelector('[data-hypervisor-applications-close]')?.addEventListener('click', closeHypervisorApplicationsModal);
    modal.querySelector('[data-hypervisor-applications-search]')?.addEventListener('input', (event) => {
      hypervisorModalState.query = event.target.value || '';
      renderHypervisorApplicationsModal();
      document.querySelector('[data-hypervisor-applications-search]')?.focus();
    });
    modal.querySelectorAll('[data-hypervisor-application-category]').forEach((button) => {
      button.addEventListener('click', () => {
        hypervisorModalState.category = button.getAttribute('data-hypervisor-application-category') || 'All apps';
        renderHypervisorApplicationsModal();
      });
    });
    modal.querySelectorAll('[data-hypervisor-application-id]').forEach((button) => {
      button.addEventListener('click', () => {
        hypervisorModalState.activeId = button.getAttribute('data-hypervisor-application-id') || hypervisorModalState.activeId;
        renderHypervisorApplicationsModal();
      });
    });
    modal.querySelector('[data-hypervisor-open-application]')?.addEventListener('click', (event) => {
      const id = event.currentTarget.getAttribute('data-hypervisor-open-application');
      if (id) setHypervisorSelectedApplicationId(id);
      document.querySelector('[data-hypervisor-applications-section]')?.removeAttribute('data-rendered-application-id');
      renderHypervisorApplicationsSidebarSection();
      closeHypervisorApplicationsModal();
      openHypervisorSelectedApplicationSurface(event);
    });
    modal.addEventListener('click', (event) => {
      if (event.target === modal) closeHypervisorApplicationsModal();
    }, { once: true });
  };
  function openHypervisorApplicationsModal(event) {
    event?.preventDefault?.();
    event?.stopPropagation?.();
    let modal = document.querySelector('[data-hypervisor-applications-modal]');
    if (!modal) {
      modal = document.createElement('div');
      modal.setAttribute('data-hypervisor-applications-modal', 'true');
      modal.className = 'hypervisor-applications-modal-backdrop';
      document.body.appendChild(modal);
    }
    hypervisorModalState.activeId = getHypervisorSelectedApplicationId();
    renderHypervisorApplicationsModal();
    setTimeout(() => document.querySelector('[data-hypervisor-applications-search]')?.focus(), 0);
  }
  function closeHypervisorApplicationsModal() {
    document.querySelector('[data-hypervisor-applications-modal]')?.remove();
  }
  function openHypervisorSelectedApplicationSurface(event) {
    event?.preventDefault?.();
    event?.stopPropagation?.();
    closeHypervisorApplicationsModal();
    if (location.pathname === '/insights') {
      renderHypervisorBlankApplicationSurface();
      return;
    }
    window.location.assign('/insights');
  }
  const applyHypervisorApplicationsSurface = () => {
    const sidebarRoots = Array.from(document.querySelectorAll('[data-testid="sidebar"], [data-sidebar-container="true"]'));
    const sidebarLinks = Array.from(new Set(sidebarRoots.flatMap((root) => Array.from(root.querySelectorAll('a, [role="link"]')))));
    sidebarLinks.filter((link) => {
      const rawHref = link.getAttribute('href') || '';
      let pathname = rawHref;
      try {
        pathname = rawHref ? new URL(rawHref, location.origin).pathname : '';
      } catch {}
      return pathname === '/insights'
        || link.getAttribute('aria-label') === 'Insights'
        || link.getAttribute('data-hypervisor-applications-launcher') === 'true'
        || (link.textContent || '').trim() === 'Insights';
    }).forEach((link) => {
      link.setAttribute('href', '#applications');
      link.setAttribute('aria-label', 'Applications');
      link.setAttribute('data-hypervisor-applications-launcher', 'true');
      if (!link.dataset.hypervisorApplicationsBound) {
        link.dataset.hypervisorApplicationsBound = 'true';
        link.addEventListener('click', openHypervisorApplicationsModal);
      }
      const svg = link.querySelector('svg');
      if (svg && !link.querySelector('.hypervisor-sidebar-applications-icon')) {
        const host = svg.parentElement;
        if (host) {
          host.innerHTML = '<svg class="hypervisor-sidebar-applications-icon" width="20px" height="20px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path d="M4.75 4.75H9.25V9.25H4.75V4.75Z M14.75 4.75H19.25V9.25H14.75V4.75Z M4.75 14.75H9.25V19.25H4.75V14.75Z M14.75 14.75H19.25V19.25H14.75V14.75Z" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/></svg>';
        }
      }
      const walker = document.createTreeWalker(link, NodeFilter.SHOW_TEXT, {
        acceptNode(node) {
          return /Insights/.test(node.nodeValue || '') ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT;
        }
      });
      const nodes = [];
      while (walker.nextNode()) nodes.push(walker.currentNode);
      nodes.forEach((node) => {
        node.nodeValue = (node.nodeValue || '').replace(/Insights/g, 'Applications');
      });
    });
    renderHypervisorApplicationsSidebarSection();
    renderHypervisorBlankApplicationSurface();
  };
  const applyHypervisorBranding = () => {
    document.title = brandText(document.title);
    document.querySelectorAll('meta[name], meta[content], img[alt], img[src], link[href], [aria-label]').forEach((element) => {
      ['name', 'content', 'alt', 'aria-label', 'src', 'href'].forEach((attribute) => {
        if (!element.hasAttribute(attribute)) return;
        const current = element.getAttribute(attribute);
        const next = attribute === 'src' || attribute === 'href' ? brandAssetPath(current) : brandText(current);
        if (current !== next) element.setAttribute(attribute, next);
      });
    });
    document.querySelectorAll('a[data-tracking-id="logo-home-link"]').forEach((link) => {
      link.classList.add('hypervisor-logo-home-link');
      link.setAttribute('aria-label', 'Go to Hypervisor home');
      if (!link.querySelector('.hypervisor-activity-brand')) {
        link.innerHTML = hypervisorBrandMarkup;
      }
    });
    const replaceStandaloneMark = (svg) => {
      if (!svg || svg.closest('.hypervisor-activity-brand')) return;
      const wrapper = document.createElement('span');
      wrapper.innerHTML = hypervisorMarkMarkup;
      const nextSvg = wrapper.firstElementChild;
      if (!nextSvg) return;
      const currentClass = svg.getAttribute('class');
      if (currentClass && currentClass !== 'hypervisor-activity-brand-mark') {
        nextSvg.setAttribute('class', 'hypervisor-activity-brand-mark ' + currentClass);
      }
      svg.replaceWith(nextSvg);
    };
    document.querySelectorAll('button[aria-label="Change agent mode"] svg[viewBox="0 0 24 24"]').forEach((svg) => {
      const path = svg.querySelector('path')?.getAttribute('d') || '';
      if (path.startsWith('M22.2819 9.8211')) replaceStandaloneMark(svg);
    });
    document.querySelectorAll('[role="group"][aria-label="Sidebar logo and expand control"]').forEach((group) => {
      group.querySelectorAll('div[aria-hidden="false"] svg[viewBox="0 0 32 32"]').forEach(replaceStandaloneMark);
    });
    document.querySelectorAll('[role="menuitem"], [data-radix-collection-item]').forEach((item) => {
      if (!/Hypervisor Agent|IOI Agent|Codex|ChatGPT/i.test(item.textContent || '')) return;
      const svg = item.querySelector('svg[viewBox="0 0 32 32"], svg[viewBox="0 0 24 24"]');
      if (svg) replaceStandaloneMark(svg);
    });
    document.querySelectorAll('svg[viewBox="0 0 283 96"], svg[width="283"][height="96"]').forEach((svg) => {
      if (svg.closest('a[data-tracking-id="logo-home-link"], .hypervisor-activity-brand')) return;
      const host = svg.parentElement;
      if (!host) return;
      host.classList.add('hypervisor-wordmark-brand-host');
      if (!host.querySelector('.hypervisor-activity-brand')) {
        host.innerHTML = hypervisorBrandMarkup;
      }
    });
    if (!document.body || !window.NodeFilter) return;
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, {
      acceptNode(node) {
        if (shouldSkipBrandNode(node)) return NodeFilter.FILTER_REJECT;
        return /\\b(?:IOI|IOI)\\b/.test(node.nodeValue || '') ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT;
      }
    });
    const pendingTextNodes = [];
    while (walker.nextNode()) pendingTextNodes.push(walker.currentNode);
    pendingTextNodes.forEach((node) => {
      node.nodeValue = brandText(node.nodeValue || '');
    });
  };
  let hypervisorBrandingScheduled = false;
  const scheduleHypervisorBranding = () => {
    if (hypervisorBrandingScheduled) return;
    hypervisorBrandingScheduled = true;
    const run = () => {
      hypervisorBrandingScheduled = false;
      applyHypervisorBranding();
      applyHypervisorApplicationsSurface();
    };
    const timeout = setTimeout(run, 50);
    if (typeof requestAnimationFrame === 'function') {
      requestAnimationFrame(() => {
        clearTimeout(timeout);
        run();
      });
    }
  };
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', scheduleHypervisorBranding, { once: true });
  } else {
    scheduleHypervisorBranding();
  }
  new MutationObserver(scheduleHypervisorBranding).observe(document.documentElement, {
    childList: true,
    subtree: true,
    characterData: true
  });
  const environmentLogStream = [
    '[section-create]{"id":"${primaryMachineSessionId}","title":"System logs","continuous":false}',
    '[id:${primaryMachineSessionId}] [2026-06-21T22:11:18.000Z] INFO Starting supervisor build.version=8ed5412 build.commit=8ed5412ddcb37b2f9805b9a326a38ea2da450091 build.time=2026-06-16T11:31:04Z',
    '[id:${primaryMachineSessionId}] [2026-06-21T22:11:19.000Z] INFO Starting SSH proxy and waiting for connections',
    '[id:${primaryMachineSessionId}] [2026-06-21T22:11:19.000Z] INFO Waiting for Docker buildx setup to complete, skipping dev container reconciliation',
    '[id:${primaryMachineSessionId}] [2026-06-21T22:11:22.000Z] INFO Waiting for Docker buildx setup to complete, skipping dev container reconciliation',
    '[id:${primaryMachineSessionId}] [2026-06-21T22:11:23.000Z] INFO Waiting for Docker buildx setup to complete, skipping dev container reconciliation',
    '[section-end]{"id":"${primaryMachineSessionId}","success":true,"secondsElapsed":1}',
    '[section-create]{"id":"start-machine","title":"Starting","continuous":false}',
    '[id:start-machine] [2026-06-21T22:11:18.000Z] INFO Setting up Docker Buildx builder',
    '[id:start-machine] [2026-06-21T22:11:19.000Z] INFO Tracing initialized export=false startup_trace_context=true',
    '[id:start-machine] [2026-06-21T22:11:19.000Z] INFO datadisk resize completed mount=/mnt/data device=/dev/nvme1n1',
    '[id:start-machine] [2026-06-21T22:11:19.000Z] INFO Started git status monitor',
    '[id:start-machine] [2026-06-21T22:11:19.000Z] INFO Supervisor browser disabled by feature flag',
    '[id:start-machine] [2026-06-21T22:11:19.000Z] INFO Setting machine as ready',
    '[id:start-machine] [2026-06-21T22:11:19.000Z] INFO Supervisor is running',
    '[section-end]{"id":"start-machine","success":true,"secondsElapsed":1}',
    '[section-create]{"id":"start-dev-container","title":"Creating dev container","continuous":false}',
    '[id:start-dev-container] [2026-06-21T22:11:23.000Z] INFO Building and starting dev container session=019ee1b5-0cdd-7448-aa24-31ea12f0c3fd workspaceFolder=/workspaces/workspaces',
    '[id:start-dev-container] [2026-06-21T22:11:23.000Z] INFO Using devcontainer.json path=/workspaces/workspaces/.devcontainer/devcontainer.json',
    '[id:start-dev-container] [2026-06-21T22:11:23.000Z] INFO Writing secrets env file path=/usr/local/ioi/shared/.env',
    '[id:start-dev-container] [2026-06-21T22:11:23.000Z] INFO Creating dev container durationSinceStart=1.020313ms',
    '[id:start-dev-container] [2026-06-21T22:11:24.000Z] INFO Dev container up durationSinceStart=658.571106ms containerID=5e350009b0fe2663fe8eb98101dd02c84051e97523ced32ec05fc1dc8f913a4c',
    '[id:start-dev-container] [2026-06-21T22:11:24.000Z] INFO Setting up file secrets in container secrets=1',
    '[id:start-dev-container] [2026-06-21T22:11:24.000Z] INFO Writing configuration to path=/usr/local/ioi/shared/configuration.json',
    '[id:start-dev-container] [2026-06-21T22:11:24.000Z] INFO Running dev container blocking commands',
    '[id:start-dev-container] [2026-06-21T22:11:24.000Z] INFO Starting SSH',
    '[id:start-dev-container] [2026-06-21T22:11:24.000Z] INFO Waiting for SSH to be ready',
    '[id:start-dev-container] [2026-06-21T22:11:25.000Z] INFO @devcontainers/cli 0.84.1. Node.js v24.14.1. linux 7.0.0-1006-aws x64.',
    '[section-end]{"id":"start-dev-container","success":true,"secondsElapsed":2}',
    '[section-create]{"id":"stop-environment","title":"Stopping environment","continuous":false}',
    '[id:stop-environment] [2026-06-21T22:41:25.000Z] INFO Auto-stop triggered after 30m of inactivity',
    '[id:stop-environment] [2026-06-21T22:41:26.000Z] INFO Stopping dev container session=019ee1b5-0cdd-7448-aa24-31ea12f0c3fd',
    '[id:stop-environment] [2026-06-21T22:41:27.000Z] INFO Flushing workspace file watcher and git status monitor',
    '[id:stop-environment] [2026-06-21T22:41:28.000Z] INFO Stopping SSH proxy and supervisor services',
    '[id:stop-environment] [2026-06-21T22:41:29.000Z] INFO Machine stopped cleanly',
    '[section-end]{"id":"stop-environment","success":true,"secondsElapsed":4}'
  ].join('\\n') + '\\n';
  const conversationReplayStream = [
    {
      id: 'ioi-user-request',
      phase: 'PHASE_COMPLETED',
      userInput: {
        id: 'ioi-user-request',
        createdAt: '2026-06-19T21:06:57.260435Z',
        inputs: [
          { text: { content: 'Design a standalone static website about post-quantum computers. Use a polished educational style and create a small static site if the repo is empty.' } }
        ]
      }
    },
    {
      id: 'ioi-todo-summary',
      phase: 'PHASE_COMPLETED',
      todoGroup: {
        groupId: 'ioi-mirror-todos',
        todos: [
          { id: 'inspect-project-structure', title: 'Inspect project structure', phase: 'PHASE_DONE' },
          { id: 'implement-website-ui', title: 'Implement website UI and content', phase: 'PHASE_DONE' },
          { id: 'validate-locally', title: 'Run or validate locally', phase: 'PHASE_DONE' },
          { id: 'report-files-preview', title: 'Report files and preview path', phase: 'PHASE_DONE' }
        ]
      }
    },
    {
      id: 'ioi-summary',
      phase: 'PHASE_COMPLETED',
      text: {
        content: 'Created a standalone static website about post-quantum computers:\\n\\n- index.html\\n- styles.css\\n- script.js\\n\\nIt includes a responsive educational layout, animated quantum-network canvas visual, cards explaining the impact, an interactive risk explorer, and a migration checklist.\\n\\nValidation: checked file links, ASCII cleanliness, and JavaScript brace/parenthesis balance. Runtime browser/server validation was blocked because this container does not have node, python3, or another local server runtime installed. You can open index.html directly in a browser.',
        sequenceId: 1
      }
    }
  ].map((entry) => JSON.stringify(entry)).join('\\n') + '\\n';
  const runtimeProbeResponse = (value) => {
    window.__HYPERVISOR_MIRROR_RUNTIME_PROBES__ = window.__HYPERVISOR_MIRROR_RUNTIME_PROBES__ || [];
    window.__HYPERVISOR_MIRROR_RUNTIME_PROBES__.push(value);
    if (value.includes('/agent/') && /\\/conversation(?:$|[?#])/.test(value)) {
      return new Response(conversationReplayStream, {
        status: 200,
        headers: { 'Content-Type': 'text/plain', 'Cache-Control': 'no-cache' }
      });
    }
    if (value.includes('/conversation/history')) {
      return new Response(JSON.stringify({ chunks: [], has_more: false }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    if (value.includes('/conversation/live')) {
      const state = {
        chunk_id: 'ioi-mirror-live-state',
        todo_groups: [],
        available_commands: null,
        clarifying_questions: null,
        next_steps_proposal: null,
        user_inputs: []
      };
      return new Response('event: state\\ndata: ' + JSON.stringify(state) + '\\n\\nevent: end\\n\\n', {
        status: 200,
        headers: { 'Content-Type': 'text/event-stream' }
      });
    }
    if (value.includes('/transcript')) {
      return new Response('# Hypervisor local mirror transcript\\n\\nSession replay is available for crawl coverage.\\n', {
        status: 200,
        headers: { 'Content-Type': 'text/markdown' }
      });
    }
    if (value.includes('/logs/environments/')) {
      return new Response(environmentLogStream, {
        status: 200,
        headers: { 'Content-Type': 'text/plain', 'Cache-Control': 'no-cache' }
      });
    }
    if (value.includes('/support-bundle/')) {
      return new Response('hypervisor mirror support bundle', {
        status: 200,
        headers: { 'Content-Type': 'text/plain' }
      });
    }
    if (value.includes('/vm-live-usage/')) {
      return new Response(JSON.stringify({
        vm: {
          cpu: { usage_percent: 12 },
          memory: { used_bytes: 2147483648, total_bytes: 8589934592 },
          disk: { used_bytes: 17179869184, total_bytes: 53687091200 },
          data_disk: { used_bytes: 17179869184, total_bytes: 53687091200 }
        }
      }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    }
    if (value.includes('/supervisor/')) {
      return new Response(JSON.stringify({ terminals: [], profiles: [], capabilities: ['CAPABILITY_WATCH', 'CAPABILITY_BROWSER'] }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    return new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } });
  };
  const noop = function() {};
  Object.assign(noop, { boot() {}, update() {}, shutdown() {}, show() {}, hide() {} });
  try {
    Object.defineProperty(window, 'Pylon', { configurable: true, get: () => noop, set: () => {} });
  } catch {
    window.Pylon = noop;
  }
  const originalSetAttribute = Element.prototype.setAttribute;
  Element.prototype.setAttribute = function(name, value) {
    if (this.tagName === 'SCRIPT' && String(name).toLowerCase() === 'src' && isBlocked(String(value))) {
      return originalSetAttribute.call(this, name, 'data:text/javascript,');
    }
    if (this.tagName === 'IFRAME' && String(name).toLowerCase() === 'src' && isBlocked(String(value))) {
      return originalSetAttribute.call(this, name, 'about:blank');
    }
    return originalSetAttribute.call(this, name, value);
  };
  const iframeSrc = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'src');
  if (iframeSrc && iframeSrc.set && iframeSrc.get) {
    Object.defineProperty(HTMLIFrameElement.prototype, 'src', {
      configurable: true,
      get() { return iframeSrc.get.call(this); },
      set(value) { return iframeSrc.set.call(this, isBlocked(String(value)) ? 'about:blank' : value); }
    });
  }
  if (window.Worker) {
    const NativeWorker = window.Worker;
    window.Worker = function(url, options) {
      const nextUrl = typeof url === 'string' && url.startsWith('https://app.ioi.io/static/')
        ? url.replace('https://app.ioi.io', window.location.origin)
        : url;
      return new NativeWorker(nextUrl, options);
    };
    window.Worker.prototype = NativeWorker.prototype;
  }
  if (window.WebSocket) {
    const NativeWebSocket = window.WebSocket;
    class MirrorWebSocket extends EventTarget {
      static CONNECTING = 0;
      static OPEN = 1;
      static CLOSING = 2;
      static CLOSED = 3;
      constructor(url, protocols) {
        super();
        this.url = String(url);
        this.protocol = Array.isArray(protocols) ? protocols[0] || '' : protocols || '';
        this.extensions = '';
        this.binaryType = 'blob';
        this.bufferedAmount = 0;
        this.readyState = MirrorWebSocket.CONNECTING;
        setTimeout(() => {
          if (this.readyState !== MirrorWebSocket.CONNECTING) return;
          this.readyState = MirrorWebSocket.OPEN;
          const event = new Event('open');
          this.onopen?.(event);
          this.dispatchEvent(event);
        }, 0);
      }
      send() {}
      close(code = 1000, reason = 'mirror closed') {
        if (this.readyState === MirrorWebSocket.CLOSED) return;
        this.readyState = MirrorWebSocket.CLOSED;
        const event = new CloseEvent('close', { code, reason, wasClean: true });
        this.onclose?.(event);
        this.dispatchEvent(event);
      }
    }
    window.WebSocket = function(url, protocols) {
      const value = String(url);
      if (value.includes('.ioi.dev') || isBlocked(value)) return new MirrorWebSocket(url, protocols);
      return new NativeWebSocket(url, protocols);
    };
    Object.assign(window.WebSocket, NativeWebSocket, {
      CONNECTING: 0,
      OPEN: 1,
      CLOSING: 2,
      CLOSED: 3
    });
    window.WebSocket.prototype = NativeWebSocket.prototype;
  }
  const originalFetch = window.fetch;
  window.fetch = function(input, init) {
    const url = typeof input === 'string' ? input : input && input.url;
    if (typeof url === 'string' && url.includes('/api/ioi.v1.EventService/WatchEvents')) {
      return new Promise(() => {});
    }
    if (isBlocked(url)) {
      return Promise.resolve(new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } }));
    }
    if (isRuntimeProbe(url)) {
      return Promise.resolve(runtimeProbeResponse(url));
    }
    return originalFetch.apply(this, arguments);
  };
})();
</script>`;
}

function sanitizeHtml(content) {
  return brandHtml(content).replace(/<head>/, `<head>${hypervisorBrandStyles}${mirrorBootGuard()}`).replace(
    /<script[^>]+src=["']https:\/\/widget\.usepylon\.com\/widget\/[^"']+["'][^>]*><\/script>/g,
    '<script>window.Pylon = window.Pylon || function() {}; Object.assign(window.Pylon, { boot() {}, update() {}, shutdown() {}, show() {}, hide() {} });</script>'
  ).replace(/https:\/\/widget\.usepylon\.com\/fonts\.css/g, 'data:text/css,')
   .replace(/src="https:\/\/vscode\.ioi\.io"/g, 'src="about:blank"')
   .replace(/<iframe id="vscode-server-helper"[^>]*><\/iframe>/g, '')
   .replace(/<iframe id="pylon-frame"[\s\S]*?<div id="pylon-chat"[\s\S]*?<\/div><\/body><\/html>$/g, '</body></html>');
}

function transformJavaScript(content, pathname) {
  if (pathname.includes('/static/assets/use-boot-in-app-chat-')) {
    // Formatting-tolerant: the served tree may be the original minified bundle OR the owned
    // beautified source (same AST, different whitespace) — the semantic rewrite must land
    // identically on both, and the shell-parity wire gate holds it to that.
    return content.replace(
      /([$\w]+)\s*=\s*\(\)\s*=>\s*\{\s*let\s*\{\s*value:\s*([$\w]+),\s*loading:\s*([$\w]+),?\s*\}\s*=\s*[$\w]+\(\s*[$\w]+\.PylonWebChatDisabled,\s*!1,?\s*\)\s*;?\s*return\s*\{\s*value:\s*\2,\s*loading:\s*\3,?\s*\}\s*;?\s*\}/,
      '$1=()=>({value:!0,loading:!1})'
    );
  }
  return content;
}

function buildChunkMap() {
  const getFiles = (dir) => {
    let results = [];
    if (!fs.existsSync(dir)) return results;
    fs.readdirSync(dir).forEach(file => {
      const p = path.join(dir, file);
      if (fs.statSync(p).isDirectory()) {
        results = results.concat(getFiles(p));
      } else if (file.endsWith('.html')) {
        results.push(p);
      }
    });
    return results;
  };

  const htmlFiles = getFiles(PUBLIC_DIR);
  // Match webpack chunk IDs from scripts
  const regex = /\\?"(\d+)\\?",\\?"static\/chunks\/([^?"]+?\.js)(?:\?[^"]*)?\\?"/g;

  htmlFiles.forEach(file => {
    try {
      const content = fs.readFileSync(file, 'utf8');
      let match;
      while ((match = regex.exec(content)) !== null) {
        const id = parseInt(match[1], 10);
        const chunkPath = match[2];
        const filename = path.basename(chunkPath);
        chunkMap[filename] = id;
      }
    } catch (e) {
      // ignore
    }
  });
  console.log(`[SERVER] Discovered ${Object.keys(chunkMap).length} chunk mappings from HTML files.`);
}

buildChunkMap();

const server = http.createServer((req, res) => {
  let pathname;
  let hasRsc = false;
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  try {
    const urlObj = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    pathname = urlObj.pathname;
    hasRsc = urlObj.searchParams.has('_rsc');
  } catch (e) {
    pathname = req.url.split('?')[0];
    hasRsc = req.url.includes('_rsc=');
  }

  // Remove trailing slash
  if (pathname.endsWith('/') && pathname !== '/') {
    pathname = pathname.slice(0, -1);
  }

  // Intercept RSC (React Server Component) prefetch calls to prevent Next.js html fallbacks
  if (hasRsc) {
    console.log(`[SERVER] Mocking RSC call: ${pathname}`);
    res.writeHead(200, { 'Content-Type': 'text/x-component' });
    res.end();
    return;
  }

  if (handleDynamicApi(req, res, pathname)) {
    return;
  }

  // Wildcard API Mocking
  if (pathname.startsWith('/api/') && !fs.existsSync(path.join(PUBLIC_DIR, pathname))) {
    console.log(`[SERVER] Mocking API call: ${pathname}`);
    if ((req.headers['content-type'] || '').includes('application/connect+json')) {
      res.writeHead(200, {
        'Content-Type': 'application/connect+json',
        'Connect-Protocol-Version': '1'
      });
      res.end(connectEndStreamBuffer());
    } else {
      sendJson(res, {});
    }
    return;
  }

  if (pathname === '/sentry-tunnel') {
    sendJson(res, {});
    return;
  }

  if (
    pathname === '/static/ioi-logo.svg'
    || pathname === '/static/ioi-lettermark.svg'
    || pathname === '/static/ioi-dark.ico'
    || pathname === '/static/ioi-light.ico'
    || pathname === '/static/hypervisor-logo.svg'
    || pathname === '/ioi-logo.svg'
    || pathname === '/ioi.png'
    || pathname === '/hypervisor-logo.svg'
  ) {
    res.writeHead(200, { 'Content-Type': 'image/svg+xml' });
    res.end(hypervisorLogoSvg);
    return;
  }

  let filePath = path.join(PUBLIC_DIR, pathname);

  // Missing JS chunks/assets fallback mock (prevents client-side ChunkLoadErrors)
  if (pathname.endsWith('.js') && !fs.existsSync(filePath)) {
    const filename = path.basename(pathname);
    let fallbackChunkId = chunkMap[filename];
    
    if (fallbackChunkId === undefined) {
      const chunkMatch = filename.match(/^([a-zA-Z0-9_-]+?)(?:[-.][a-f0-9]+)?\.js$/);
      fallbackChunkId = 'unknown';
      if (chunkMatch) {
        fallbackChunkId = chunkMatch[1];
        if (/^\d+$/.test(fallbackChunkId)) {
          fallbackChunkId = parseInt(fallbackChunkId, 10);
        }
      }
    }
    
    const mockContent = `
      (() => {
        let chunkId = ${JSON.stringify(fallbackChunkId)};
        const filename = ${JSON.stringify(filename)};
        const scriptEl = document.querySelector(\`script[src*="\${filename}"]\`);
        if (scriptEl) {
          const dw = scriptEl.getAttribute('data-webpack');
          if (dw && dw.includes(':')) {
            const parts = dw.split(':');
            let id = parts[parts.length - 1];
            if (id.startsWith('chunk-')) {
              id = id.slice(6);
            }
            chunkId = /^\\d+$/.test(id) ? parseInt(id, 10) : id;
          }
        }
        (self.webpackChunk_N_E = self.webpackChunk_N_E || []).push([[chunkId], {}]);
      })();
    `;
    console.log(`[SERVER] Mocking missing JS chunk: ${pathname}`);
    res.writeHead(200, { 'Content-Type': 'application/javascript' });
    res.end(mockContent);
    return;
  }

  // Missing CSS assets fallback mock (prevents 404/403 errors)
  if (pathname.endsWith('.css') && !fs.existsSync(filePath)) {
    console.log(`[SERVER] Mocking missing CSS: ${pathname}`);
    res.writeHead(200, { 'Content-Type': 'text/css' });
    res.end('/* mocked CSS */');
    return;
  }

  // Missing image assets fallback mock (returns 1x1 transparent PNG/SVG)
  if (/\.(png|jpg|jpeg|gif|ico|svg|webp)$/i.test(pathname) && !fs.existsSync(filePath)) {
    console.log(`[SERVER] Mocking missing image: ${pathname}`);
    const pngBase64 = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=';
    const contentType = pathname.endsWith('.svg') ? 'image/svg+xml' : (pathname.endsWith('.webp') ? 'image/webp' : 'image/png');
    res.writeHead(200, { 'Content-Type': contentType });
    res.end(pathname.endsWith('.svg') ? '<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"/>' : Buffer.from(pngBase64, 'base64'));
    return;
  }

  // Missing font assets fallback mock
  if (/\.(woff|woff2|ttf|otf|eot)$/i.test(pathname) && !fs.existsSync(filePath)) {
    console.log(`[SERVER] Mocking missing font: ${pathname}`);
    res.writeHead(200, { 'Content-Type': 'font/woff2' });
    res.end(Buffer.alloc(0));
    return;
  }

  // SPA Routing Fallback
  if (!fs.existsSync(filePath) || fs.lstatSync(filePath).isDirectory()) {
    if (!path.extname(filePath)) {
      const pathWithIndex = path.join(filePath, 'index.html');
      if (fs.existsSync(pathWithIndex)) {
        filePath = pathWithIndex;
      } else if (fs.existsSync(filePath + '.html')) {
        filePath = filePath + '.html';
      } else {
        // Fallback to SPA root index.html (the main dashboard view)
        filePath = path.join(PUBLIC_DIR, 'index.html');
      }
    }
  }

  if (!fs.existsSync(filePath)) {
    res.statusCode = 404;
    res.setHeader('Content-Type', 'text/plain');
    res.end('404 Not Found');
    return;
  }

  // Determine content type
  let contentType = 'text/html';
  const ext = path.extname(filePath);
  switch (ext) {
    case '.js': contentType = 'application/javascript'; break;
    case '.css': contentType = 'text/css'; break;
    case '.json': contentType = 'application/json'; break;
    case '.png': contentType = 'image/png'; break;
    case '.jpg': case '.jpeg': contentType = 'image/jpeg'; break;
    case '.gif': contentType = 'image/gif'; break;
    case '.svg': contentType = 'image/svg+xml'; break;
    case '.woff2': contentType = 'font/woff2'; break;
    case '.ico': contentType = 'image/x-icon'; break;
  }
  if (pathname.startsWith('/api/')) {
    contentType = 'application/json';
  }

  res.statusCode = 200;
  res.setHeader('Content-Type', contentType);
  if (contentType === 'text/html') {
    res.end(sanitizeHtml(fs.readFileSync(filePath, 'utf8')));
    return;
  }
  if (contentType === 'application/javascript') {
    res.end(transformJavaScript(fs.readFileSync(filePath, 'utf8'), pathname));
    return;
  }
  fs.createReadStream(filePath).pipe(res);
});

server.listen(PORT, () => {
  console.log(`============================================================`);
  console.log(`   HYPERVISOR APP MIRROR STATIC SERVER STARTED SUCCESSFULLY`);
  console.log(`============================================================`);
  console.log(`Local URL:  http://localhost:${PORT}`);
  console.log(`Serving:    ${PUBLIC_DIR}`);
  console.log(`============================================================`);
});
