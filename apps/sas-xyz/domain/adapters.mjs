import { sha256 } from './receipts.mjs';

export class OwnerDependencyError extends Error {
  constructor(owner, message, status = 503, code = 'owner_unavailable') { super(message); this.owner = owner; this.status = status; this.code = code; }
}

const ref = (kind, owner, action, body) => `${kind}://development/${owner}/${action}/${sha256(body).slice(7, 31)}`;
const contracts = {
  'runtime.assign': { owner: 'hypervisor', action: 'assign-outcome-runtime', required: { runtime_assignment_ref: ['runtime-assignment://'] } },
  'runtime.substitute': { owner: 'hypervisor', action: 'substitute-provider', required: { substitution_ref: ['runtime-substitution://'] } },
  'settlement.reserve': { owner: 'settlement', action: 'reserve', required: { settlement_ref: ['settlement://'] } },
  'settlement.accept': { owner: 'settlement', action: 'accept-delivery', required: { settlement_intent_ref: ['settlement-intent://'] } },
  'settlement.freeze': { owner: 'settlement', action: 'freeze-dispute', required: { hold_ref: ['settlement-hold://'] } },
  'settlement.resolve': { owner: 'settlement', action: 'resolve-dispute', required: { resolution_ref: ['settlement-resolution://'] } },
  'authority.artifactDownload': { owner: 'authority', action: 'authorize-download', required: { authorization_ref: ['download-authorization://'] } },
  'authority.productionReserve': { owner: 'authority', action: 'reserve-production', required: { production_admission_ref: ['production-admission://'] } },
  'authority.productionConsume': { owner: 'authority', action: 'consume-production', required: { production_usage_admission_ref: ['production-usage-admission://'] } },
  'storage.verifyDelivery': { owner: 'storage', action: 'verify-delivery', required: { verification_ref: ['artifact-verification://'] } },
};
const hasPrefix = (value, prefixes) => typeof value === 'string' && prefixes.some((prefix) => value.startsWith(prefix));

export function validateOwnerDecision(contractKey, payload) {
  const contract = contracts[contractKey];
  if (!contract) throw new OwnerDependencyError('unknown', `No owner response contract exists for ${contractKey}`, 503, 'canonical_owner_contract_unavailable');
  if (!payload || typeof payload !== 'object' || Array.isArray(payload) || payload.schema_version !== 'ioi.owner-decision.v1' || payload.owner !== contract.owner || payload.action !== contract.action || payload.status !== 'admitted' || !hasPrefix(payload.receipt_ref, ['receipt://', 'agentgres://receipt/'])) throw new OwnerDependencyError(contract.owner, `Malformed authoritative response for ${contractKey}`, 502, 'owner_contract_invalid');
  for (const [field, prefixes] of Object.entries(contract.required)) if (!hasPrefix(payload[field], prefixes)) throw new OwnerDependencyError(contract.owner, `Authoritative response for ${contractKey} is missing ${field}`, 502, 'owner_contract_invalid');
  if (payload.download_capability !== undefined && (!payload.download_capability || typeof payload.download_capability !== 'object' || typeof payload.download_capability.href !== 'string' || !payload.download_capability.href.startsWith('https://'))) throw new OwnerDependencyError(contract.owner, 'Download capability is malformed', 502, 'owner_contract_invalid');
  return payload;
}

const developmentDecision = (contractKey, body) => {
  const contract = contracts[contractKey];
  const extra = {
    'runtime.assign': { runtime_assignment_ref: ref('runtime-assignment', contract.owner, contract.action, body) },
    'runtime.substitute': { substitution_ref: ref('runtime-substitution', contract.owner, contract.action, body) },
    'settlement.reserve': { settlement_ref: ref('settlement', contract.owner, contract.action, body) },
    'settlement.accept': { settlement_intent_ref: ref('settlement-intent', contract.owner, contract.action, body) },
    'settlement.freeze': { hold_ref: ref('settlement-hold', contract.owner, contract.action, body) },
    'settlement.resolve': { resolution_ref: ref('settlement-resolution', contract.owner, contract.action, body) },
    'authority.artifactDownload': { authorization_ref: ref('download-authorization', contract.owner, contract.action, body) },
    'authority.productionReserve': { production_admission_ref: ref('production-admission', contract.owner, contract.action, body) },
    'authority.productionConsume': { production_usage_admission_ref: ref('production-usage-admission', contract.owner, contract.action, body) },
    'storage.verifyDelivery': { verification_ref: ref('artifact-verification', contract.owner, contract.action, body) },
  }[contractKey];
  return validateOwnerDecision(contractKey, { schema_version: 'ioi.owner-decision.v1', authority_mode: 'development', owner: contract.owner, action: contract.action, status: 'admitted', receipt_ref: ref('receipt', contract.owner, contract.action, body), observed_at: new Date().toISOString(), ...extra });
};

const postJson = async (contractKey, endpoint, body, context) => {
  const contract = contracts[contractKey];
  if (!endpoint?.baseUrl || !endpoint?.route) throw new OwnerDependencyError(contract.owner, `Canonical owner endpoint is not registered for ${contractKey}`, 503, 'canonical_owner_contract_unavailable');
  let response;
  try {
    response = await fetch(new URL(endpoint.route, endpoint.baseUrl), { method: 'POST', signal: AbortSignal.timeout(10_000), headers: { 'content-type': 'application/json', 'x-ioi-principal': context.principalRef, 'x-ioi-tenant': context.tenantRef, 'idempotency-key': context.idempotencyKey }, body: JSON.stringify(body) });
  } catch (error) { throw new OwnerDependencyError(contract.owner, `Owner request failed for ${contractKey}: ${error.message}`); }
  const source = await response.text(); if (source.length > 1_000_000) throw new OwnerDependencyError(contract.owner, `Owner response exceeded one megabyte for ${contractKey}`, 502, 'owner_contract_invalid');
  let payload; try { payload = source ? JSON.parse(source) : {}; } catch { throw new OwnerDependencyError(contract.owner, `Owner returned invalid JSON for ${contractKey}`, 502, 'owner_contract_invalid'); }
  if (!response.ok) throw new OwnerDependencyError(payload.owner || contract.owner, payload.error?.message || payload.error || `Owner returned ${response.status}`, response.status);
  return validateOwnerDecision(contractKey, payload);
};

export function createOwnerAdapters(config = {}) {
  const development = config.developmentAuthority === true;
  const invoke = (key, body, context) => development ? Promise.resolve(developmentDecision(key, body)) : postJson(key, config.operations?.[key], body, context);
  return {
    mode: development ? 'development' : 'network',
    runtime: { assign: (body, context) => invoke('runtime.assign', body, context), substitute: (body, context) => invoke('runtime.substitute', body, context) },
    settlement: { reserve: (body, context) => invoke('settlement.reserve', body, context), accept: (body, context) => invoke('settlement.accept', body, context), freeze: (body, context) => invoke('settlement.freeze', body, context), resolve: (body, context) => invoke('settlement.resolve', body, context) },
    authority: { artifactDownload: (body, context) => invoke('authority.artifactDownload', body, context), productionReserve: (body, context) => invoke('authority.productionReserve', body, context), productionConsume: (body, context) => invoke('authority.productionConsume', body, context) },
    storage: { verifyDelivery: (body, context) => invoke('storage.verifyDelivery', body, context) },
  };
}
