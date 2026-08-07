import { sha256 } from './receipts.mjs';

export class OwnerDependencyError extends Error {
  constructor(owner, message, status = 503, code = 'owner_unavailable') {
    super(message);
    this.name = 'OwnerDependencyError';
    this.owner = owner;
    this.status = status;
    this.code = code;
  }
}

const ref = (kind, owner, action, body) => `${kind}://development/${owner}/${action}/${sha256(body).slice(7, 31)}`;

const contracts = {
  'packages.releaseCandidate': { owner: 'packages', action: 'release-candidate', required: { release_ref: ['package-release://', 'package://'] } },
  'packages.install': { owner: 'packages', action: 'install', required: { install_id: ['install://'] } },
  'evaluations.benchmark': { owner: 'evaluations', action: 'benchmark', required: { benchmark_ref: ['benchmark://', 'evaluation://'] } },
  'authority.bindIntegration': { owner: 'authority', action: 'bind-integration', required: { grant_ref: ['authority-grant://', 'credential-grant://'] } },
  'authority.testIntegration': { owner: 'authority', action: 'test-integration', required: { test_ref: ['integration-test://'] } },
  'settlement.quote': { owner: 'settlement', action: 'quote', required: { owner_quote_ref: ['settlement-quote://'] } },
  'settlement.acquire': { owner: 'settlement', action: 'acquire-entitlement', required: { entitlement_ref: ['settlement-entitlement://', 'entitlement://'] } },
  'runtime.initialize': { owner: 'hypervisor', action: 'initialize-instance', required: { runtime_assignment_ref: ['runtime-assignment://'] } },
  'runtime.transition': { owner: 'hypervisor', action: 'transition-instance', required: { transition_ref: ['runtime-transition://', 'lifecycle-transition://'] } },
};

const hasPrefix = (value, prefixes) => typeof value === 'string' && prefixes.some((prefix) => value.startsWith(prefix));

export function validateOwnerDecision(contractKey, payload) {
  const contract = contracts[contractKey];
  if (!contract) throw new OwnerDependencyError('unknown', `No owner response contract exists for ${contractKey}`, 503, 'canonical_owner_contract_unavailable');
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)
    || payload.schema_version !== 'ioi.owner-decision.v1'
    || payload.owner !== contract.owner
    || payload.action !== contract.action
    || payload.status !== 'admitted'
    || !hasPrefix(payload.receipt_ref, ['receipt://', 'agentgres://receipt/'])) {
    throw new OwnerDependencyError(contract.owner, `Malformed authoritative response for ${contractKey}`, 502, 'owner_contract_invalid');
  }
  for (const [field, prefixes] of Object.entries(contract.required)) {
    if (!hasPrefix(payload[field], prefixes)) throw new OwnerDependencyError(contract.owner, `Authoritative response for ${contractKey} is missing ${field}`, 502, 'owner_contract_invalid');
  }
  return payload;
}

const developmentDecision = (contractKey, body) => {
  const contract = contracts[contractKey];
  const extra = {
    'packages.releaseCandidate': { release_ref: ref('package-release', contract.owner, contract.action, body) },
    'packages.install': { install_id: ref('install', contract.owner, contract.action, body) },
    'evaluations.benchmark': { benchmark_ref: ref('benchmark', contract.owner, contract.action, body) },
    'authority.bindIntegration': { grant_ref: ref('authority-grant', contract.owner, contract.action, body) },
    'authority.testIntegration': { test_ref: ref('integration-test', contract.owner, contract.action, body) },
    'settlement.quote': { owner_quote_ref: ref('settlement-quote', contract.owner, contract.action, body) },
    'settlement.acquire': { entitlement_ref: ref('settlement-entitlement', contract.owner, contract.action, body) },
    'runtime.initialize': { runtime_assignment_ref: ref('runtime-assignment', contract.owner, contract.action, body) },
    'runtime.transition': { transition_ref: ref('runtime-transition', contract.owner, contract.action, body) },
  }[contractKey];
  return validateOwnerDecision(contractKey, {
    schema_version: 'ioi.owner-decision.v1',
    authority_mode: 'development',
    owner: contract.owner,
    action: contract.action,
    status: 'admitted',
    receipt_ref: ref('receipt', contract.owner, contract.action, body),
    observed_at: new Date().toISOString(),
    ...extra,
  });
};

const postJson = async (contractKey, endpoint, body, context) => {
  const contract = contracts[contractKey];
  if (!endpoint?.baseUrl || !endpoint?.route) throw new OwnerDependencyError(contract.owner, `Canonical owner endpoint is not registered for ${contractKey}`, 503, 'canonical_owner_contract_unavailable');
  let response;
  try {
    response = await fetch(new URL(endpoint.route, endpoint.baseUrl), {
      method: 'POST',
      signal: AbortSignal.timeout(10_000),
      headers: { 'content-type': 'application/json', 'x-ioi-principal': context.principalRef, 'x-ioi-tenant': context.tenantRef, 'idempotency-key': context.idempotencyKey },
      body: JSON.stringify(body),
    });
  } catch (error) {
    throw new OwnerDependencyError(contract.owner, `Owner request failed for ${contractKey}: ${error.message}`);
  }
  const source = await response.text();
  if (source.length > 1_000_000) throw new OwnerDependencyError(contract.owner, `Owner response exceeded one megabyte for ${contractKey}`, 502, 'owner_contract_invalid');
  let payload;
  try { payload = source ? JSON.parse(source) : {}; } catch { throw new OwnerDependencyError(contract.owner, `Owner returned invalid JSON for ${contractKey}`, 502, 'owner_contract_invalid'); }
  if (!response.ok) throw new OwnerDependencyError(payload.owner || contract.owner, payload.error?.message || payload.error || `Owner returned ${response.status}`, response.status);
  return validateOwnerDecision(contractKey, payload);
};

export function createOwnerAdapters(config = {}) {
  const development = config.developmentAuthority === true;
  const invoke = (contractKey, body, context) => development ? Promise.resolve(developmentDecision(contractKey, body)) : postJson(contractKey, config.operations?.[contractKey], body, context);
  return {
    mode: development ? 'development' : 'network',
    packages: { releaseCandidate: (body, context) => invoke('packages.releaseCandidate', body, context), install: (body, context) => invoke('packages.install', body, context) },
    evaluations: { benchmark: (body, context) => invoke('evaluations.benchmark', body, context) },
    authority: { bindIntegration: (body, context) => invoke('authority.bindIntegration', body, context), testIntegration: (body, context) => invoke('authority.testIntegration', body, context) },
    settlement: { quote: (body, context) => invoke('settlement.quote', body, context), acquire: (body, context) => invoke('settlement.acquire', body, context) },
    runtime: { initialize: (body, context) => invoke('runtime.initialize', body, context), transition: (body, context) => invoke('runtime.transition', body, context) },
  };
}
