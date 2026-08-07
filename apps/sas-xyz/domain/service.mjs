import { randomUUID } from 'node:crypto';
import { appendReceipt, sha256, verifyReceiptChain } from './receipts.mjs';

export const seedState = {
  schema: 'sas-outcome-marketplace-state/v1', services: [], orders: [], deliveries: [], disputes: [], substitutions: [], artifactLicenses: [], productionEntitlements: [], productionReservations: [], productionUsageReceipts: [], receipts: [], events: [], idempotency: {},
};

export class DomainError extends Error {
  constructor(status, code, message, details) { super(message); this.status = status; this.code = code; this.details = details; }
}

const required = (value, field) => { if (value === undefined || value === null || value === '') throw new DomainError(422, 'invalid_request', `${field} is required`); return value; };
const now = () => new Date().toISOString();
const ref = (kind) => `${kind}://${randomUUID()}`;
const owned = (items, context) => items.filter((item) => item.tenant_ref === context.tenantRef);
const findOwned = (items, value, context, field) => {
  const item = items.find((candidate) => candidate[field] === value && candidate.tenant_ref === context.tenantRef);
  if (!item) throw new DomainError(404, 'not_found', `${field} was not found`);
  return item;
};
const findOrderParty = (state, orderId, context) => {
  const order = state.orders.find((item) => item.order_id === orderId);
  if (!order) throw new DomainError(404, 'not_found', 'order_id was not found');
  const buyer = order.buyer_ref === context.principalRef && order.buyer_tenant_ref === context.tenantRef;
  const provider = order.provider_ref === context.principalRef && order.provider_tenant_ref === context.tenantRef;
  if (!buyer && !provider) throw new DomainError(404, 'not_found', 'order_id was not found');
  return order;
};
const findDeliveryParty = (state, deliveryId, context) => {
  const delivery = state.deliveries.find((item) => item.delivery_id === deliveryId);
  if (!delivery) throw new DomainError(404, 'not_found', 'delivery_id was not found');
  findOrderParty(state, delivery.order_id, context);
  return delivery;
};
const positiveInteger = (value, field) => {
  if (!Number.isSafeInteger(value) || value <= 0) throw new DomainError(422, 'invalid_units', `${field} must be a positive safe integer`);
  return value;
};
const nonemptyRefs = (value, field, prefixes) => {
  if (!Array.isArray(value) || !value.length || value.some((item) => typeof item !== 'string' || !prefixes.some((prefix) => item.startsWith(prefix)))) throw new DomainError(422, 'invalid_refs', `${field} must be a non-empty array of typed refs`);
  return value;
};
const ENFORCEMENT_MODES = ['contractual_audit', 'governed_remote_production'];

function idempotent(state, context, payload, effect) {
  required(context.idempotencyKey, 'Idempotency-Key');
  const key = `${context.tenantRef}:${context.principalRef}:${context.idempotencyKey}`;
  const fingerprint = sha256(payload);
  if (state.idempotency[key]) {
    if (state.idempotency[key].fingerprint !== fingerprint) throw new DomainError(409, 'idempotency_conflict', 'Idempotency key was already used with another body');
    return state.idempotency[key].result;
  }
  const result = effect(); state.idempotency[key] = { fingerprint, result }; return result;
}

export class SasService {
  constructor(store, owners) { this.store = store; this.owners = owners; }

  async prior(context, payload) {
    required(context.idempotencyKey, 'Idempotency-Key');
    const entry = (await this.store.read()).idempotency[`${context.tenantRef}:${context.principalRef}:${context.idempotencyKey}`];
    if (!entry) return null;
    if (entry.fingerprint !== sha256(payload)) throw new DomainError(409, 'idempotency_conflict', 'Idempotency key was already used with another body');
    return entry.result;
  }

  async status() { const state = await this.store.read(); return { service: 'sas.xyz', storage: 'durable-json', authority_mode: this.owners.mode, revision: state.revision, receipt_chain_valid: verifyReceiptChain(state.receipts) }; }

  async createService(body, context) {
    return this.store.transact((state) => idempotent(state, context, body, () => {
      const price = required(body.price, 'price'); positiveInteger(price.amount_minor, 'price.amount_minor');
      if (typeof price.asset !== 'string' || !/^[A-Z][A-Z0-9]{1,11}$/.test(price.asset)) throw new DomainError(422, 'invalid_price_asset', 'price.asset must be an uppercase asset symbol');
      const service = {
        service_id: randomUUID(), tenant_ref: context.tenantRef, provider_ref: context.principalRef, state: 'published', version: required(body.version, 'version'),
        name: required(body.name, 'name'), summary: required(body.summary, 'summary'), outcome_contract: required(body.outcome_contract, 'outcome_contract'),
        deliverable_kind: body.deliverable_kind === 'cad' ? 'cad' : 'general', price, sla: required(body.sla, 'sla'),
        artifact_rights: body.artifact_rights || null, published_at: now(),
      };
      if (service.deliverable_kind === 'cad') {
        if (!service.artifact_rights || typeof service.artifact_rights !== 'object') throw new DomainError(422, 'missing_artifact_rights', 'CAD services must declare artifact rights and enforcement modes');
        const modes = service.artifact_rights.enforcement_modes;
        if (!Array.isArray(modes) || !modes.length || modes.some((mode) => !ENFORCEMENT_MODES.includes(mode))) throw new DomainError(422, 'invalid_enforcement_modes', 'CAD enforcement modes are invalid');
        positiveInteger(service.artifact_rights.production_limit_units, 'artifact_rights.production_limit_units');
        if (!service.artifact_rights.granted_rights || typeof service.artifact_rights.granted_rights !== 'object') throw new DomainError(422, 'invalid_granted_rights', 'CAD services must declare granted rights');
      }
      state.services.push(service);
      const receipt = appendReceipt(state, context, 'service.published', `service://${service.service_id}`, { version: service.version, terms_root: sha256(service.outcome_contract) });
      return { ...service, receipt_ref: receipt.receipt_ref };
    }));
  }

  async listServices() { return (await this.store.read()).services.filter((item) => item.state === 'published'); }
  async getService(serviceId) { const service = (await this.store.read()).services.find((item) => item.service_id === serviceId && item.state === 'published'); if (!service) throw new DomainError(404, 'not_found', 'Service was not found'); return service; }

  async createOrder(body, context) {
    const payload = body; const prior = await this.prior(context, payload); if (prior) return prior;
    const service = await this.getService(required(body.service_id, 'service_id'));
    const terms = {
      service_id: service.service_id, service_version: service.version, objective: required(body.objective, 'objective'),
      acceptance_criteria: required(body.acceptance_criteria, 'acceptance_criteria'), privacy: body.privacy || 'tenant-private', price: service.price,
      settlement_rail: required(body.settlement_rail, 'settlement_rail'), deliverable_kind: service.deliverable_kind,
      artifact_rights: service.artifact_rights && { ...service.artifact_rights, production_limit_units: body.production_limit_units ?? service.artifact_rights.production_limit_units, enforcement_mode: body.enforcement_mode || service.artifact_rights.enforcement_modes?.[0] },
    };
    if (terms.deliverable_kind === 'cad') {
      positiveInteger(terms.artifact_rights.production_limit_units, 'production_limit_units');
      if (terms.artifact_rights.production_limit_units > service.artifact_rights.production_limit_units) throw new DomainError(422, 'production_limit_exceeds_offer', 'Requested production units exceed the published service release');
      if (!ENFORCEMENT_MODES.includes(terms.artifact_rights.enforcement_mode) || !terms.artifact_rights.enforcement_modes.includes(terms.artifact_rights.enforcement_mode)) throw new DomainError(422, 'enforcement_mode_not_offered', 'Selected CAD enforcement mode is not offered by this service release');
    }
    const settlement = await this.owners.settlement.reserve({ buyer_ref: context.principalRef, provider_ref: service.provider_ref, amount: service.price, terms_root: sha256(terms), rail: terms.settlement_rail }, context);
    const runtime = await this.owners.runtime.assign({ service_id: service.service_id, terms_root: sha256(terms), privacy: terms.privacy }, context);
    return this.store.transact((state) => idempotent(state, context, payload, () => {
      const order = {
        order_id: randomUUID(), tenant_ref: context.tenantRef, buyer_tenant_ref: context.tenantRef, provider_tenant_ref: service.tenant_ref, buyer_ref: context.principalRef, provider_ref: service.provider_ref, service_id: service.service_id,
        state: 'awaiting_provider', delivery_state: 'none', settlement_state: 'reserved', terms, terms_root: sha256(terms),
        settlement_ref: settlement.settlement_ref || null, settlement_owner_receipt_ref: settlement.receipt_ref,
        runtime_assignment_ref: runtime.runtime_assignment_ref || null, runtime_owner_receipt_ref: runtime.receipt_ref,
        created_at: now(), updated_at: now(),
      };
      state.orders.push(order);
      const receipt = appendReceipt(state, context, 'order.created', `order://${order.order_id}`, { terms_root: order.terms_root, settlement_ref: order.settlement_ref, runtime_assignment_ref: order.runtime_assignment_ref }, [settlement.receipt_ref, runtime.receipt_ref]);
      return { ...order, receipt_ref: receipt.receipt_ref, authority_mode: this.owners.mode };
    }));
  }

  async listOrders(context) {
    return (await this.store.read()).orders.filter((order) =>
      (order.buyer_ref === context.principalRef && order.buyer_tenant_ref === context.tenantRef)
      || (order.provider_ref === context.principalRef && order.provider_tenant_ref === context.tenantRef));
  }
  async getOrder(orderId, context) {
    const state = await this.store.read(); const order = findOrderParty(state, orderId, context);
    return { ...order, deliveries: state.deliveries.filter((item) => item.order_id === orderId), disputes: state.disputes.filter((item) => item.order_id === orderId), substitutions: state.substitutions.filter((item) => item.order_id === orderId), artifact_license: state.artifactLicenses.filter((item) => item.order_id === orderId).at(-1) || null, production_entitlement: state.productionEntitlements.filter((item) => item.order_id === orderId).at(-1) || null };
  }

  async claimOrder(orderId, body, context) {
    return this.store.transact((state) => idempotent(state, context, { orderId, ...body }, () => {
      const order = findOrderParty(state, orderId, context);
      if (order.provider_ref !== context.principalRef) throw new DomainError(403, 'wrong_provider', 'Only the selected provider may claim this order');
      if (order.state !== 'awaiting_provider') throw new DomainError(409, 'invalid_state', 'Order is not awaiting provider claim');
      order.state = 'in_progress'; order.claimed_at = now(); order.updated_at = now();
      const receipt = appendReceipt(state, context, 'order.claimed', `order://${orderId}`, { provider_ref: order.provider_ref });
      return { ...order, receipt_ref: receipt.receipt_ref };
    }));
  }

  async submitDelivery(orderId, body, context) {
    const payload = { orderId, ...body }; const prior = await this.prior(context, payload); if (prior) return prior;
    const snapshot = await this.store.read(); const order = findOrderParty(snapshot, orderId, context);
    if (order.provider_ref !== context.principalRef) throw new DomainError(403, 'wrong_provider', 'Only the selected provider may submit delivery');
    if (!['in_progress', 'revision_requested'].includes(order.state)) throw new DomainError(409, 'invalid_state', 'Order is not accepting provider delivery');
    const artifacts = required(body.artifacts, 'artifacts'); if (!Array.isArray(artifacts) || !artifacts.length || artifacts.some((item) => !item.artifact_ref || !item.content_hash)) throw new DomainError(422, 'invalid_artifacts', 'Each delivery artifact requires artifact_ref and content_hash');
    const storage = await this.owners.storage.verifyDelivery({ order_id: orderId, terms_root: order.terms_root, artifacts }, context);
    return this.store.transact((state) => idempotent(state, context, payload, () => {
      const current = findOrderParty(state, orderId, context);
      if (current.provider_ref !== context.principalRef || !['in_progress', 'revision_requested'].includes(current.state) || current.terms_root !== order.terms_root) throw new DomainError(409, 'delivery_race', 'Order changed during artifact verification');
      const delivery = { delivery_id: randomUUID(), tenant_ref: current.buyer_tenant_ref, order_id: orderId, provider_ref: context.principalRef, predecessor_delivery_id: state.deliveries.filter((item) => item.order_id === orderId).at(-1)?.delivery_id || null, state: 'submitted', kind: body.kind === 'partial' ? 'partial' : 'final', artifacts, evidence_refs: body.evidence_refs || [], verifier_result_refs: body.verifier_result_refs || [], submitted_at: now(), storage_receipt_ref: storage.receipt_ref };
      state.deliveries.push(delivery); current.state = delivery.kind === 'partial' ? 'in_progress' : 'delivered'; current.delivery_state = delivery.kind === 'partial' ? 'partial' : 'final'; current.updated_at = now();
      const receipt = appendReceipt(state, context, 'delivery.submitted', `delivery://${delivery.delivery_id}`, { order_id: orderId, terms_root: current.terms_root, kind: delivery.kind, artifact_roots: artifacts.map((item) => item.content_hash) }, [storage.receipt_ref]);
      return { ...delivery, receipt_ref: receipt.receipt_ref };
    }));
  }

  async requestRevision(deliveryId, body, context) {
    return this.store.transact((state) => idempotent(state, context, { deliveryId, ...body }, () => {
      const delivery = findDeliveryParty(state, deliveryId, context); const order = findOrderParty(state, delivery.order_id, context);
      if (order.buyer_ref !== context.principalRef) throw new DomainError(403, 'wrong_buyer', 'Only the buyer may request revision');
      if (delivery.state !== 'submitted') throw new DomainError(409, 'invalid_state', 'Delivery is not awaiting acceptance');
      if (state.deliveries.filter((item) => item.order_id === order.order_id).at(-1)?.delivery_id !== deliveryId) throw new DomainError(409, 'delivery_superseded', 'Only the latest delivery may be revised');
      delivery.state = 'revision_requested'; delivery.revision_request = required(body.reason, 'reason'); order.state = 'revision_requested'; order.delivery_state = 'revision_requested'; order.updated_at = now();
      const receipt = appendReceipt(state, context, 'delivery.revision_requested', `delivery://${deliveryId}`, { reason: delivery.revision_request });
      return { ...delivery, receipt_ref: receipt.receipt_ref };
    }));
  }

  async acceptDelivery(deliveryId, body, context) {
    const payload = { deliveryId, ...body }; const prior = await this.prior(context, payload); if (prior) return prior;
    const snapshot = await this.store.read(); const delivery = findDeliveryParty(snapshot, deliveryId, context); const order = findOrderParty(snapshot, delivery.order_id, context);
    if (order.buyer_ref !== context.principalRef) throw new DomainError(403, 'wrong_buyer', 'Only the buyer may accept delivery');
    if (delivery.state !== 'submitted' || delivery.kind !== 'final' || order.state !== 'delivered') throw new DomainError(409, 'invalid_state', 'Only the latest final delivery may be accepted');
    if (snapshot.deliveries.filter((item) => item.order_id === order.order_id).at(-1)?.delivery_id !== deliveryId) throw new DomainError(409, 'delivery_superseded', 'Only the latest final delivery may be accepted');
    const decision = await this.owners.settlement.accept({ order_id: order.order_id, delivery_id: deliveryId, terms_root: order.terms_root, settlement_ref: order.settlement_ref, decision: 'accept' }, context);
    return this.store.transact((state) => idempotent(state, context, payload, () => {
      const currentDelivery = findDeliveryParty(state, deliveryId, context); const currentOrder = findOrderParty(state, currentDelivery.order_id, context);
      if (currentDelivery.state !== 'submitted' || currentDelivery.kind !== 'final' || currentOrder.state !== 'delivered' || state.deliveries.filter((item) => item.order_id === currentOrder.order_id).at(-1)?.delivery_id !== deliveryId) throw new DomainError(409, 'acceptance_race', 'Delivery changed during settlement admission');
      currentDelivery.state = 'accepted'; currentDelivery.accepted_at = now(); currentOrder.state = 'completed'; currentOrder.delivery_state = 'accepted'; currentOrder.settlement_state = 'settlement_requested'; currentOrder.updated_at = now();
      let license = null; let entitlement = null;
      if (currentOrder.terms.deliverable_kind === 'cad') {
        const artifact = currentDelivery.artifacts[0]; const rights = currentOrder.terms.artifact_rights;
        license = { license_ref: ref('artifact-license'), tenant_ref: context.tenantRef, order_id: currentOrder.order_id, artifact_ref: artifact.artifact_ref, artifact_content_hash: artifact.content_hash, licensor_ref: currentOrder.provider_ref, licensee_ref: currentOrder.buyer_ref, order_ref: `order://${currentOrder.order_id}`, terms_body_root: currentOrder.terms_root, granted_rights: rights.granted_rights, production_enforcement_mode: rights.enforcement_mode, production_limit_units: rights.production_limit_units, state: 'active', accepted_at: now(), acceptance_receipt_ref: null };
        state.artifactLicenses.push(license);
        if (rights.enforcement_mode === 'contractual_audit' || rights.enforcement_mode === 'governed_remote_production') {
          entitlement = { entitlement_ref: ref('production-entitlement'), tenant_ref: context.tenantRef, artifact_license_ref: license.license_ref, order_id: currentOrder.order_id, licensee_ref: currentOrder.buyer_ref, enforcement_mode: rights.enforcement_mode, total_units: rights.production_limit_units, reserved_units: 0, admitted_consumed_units: 0, remaining_units: rights.production_limit_units, state: 'active', latest_usage_receipt_hash: null, revision: 1 };
          state.productionEntitlements.push(entitlement);
        }
      }
      const receipt = appendReceipt(state, context, 'delivery.accepted', `delivery://${deliveryId}`, { order_id: currentOrder.order_id, artifact_license_ref: license?.license_ref || null, production_entitlement_ref: entitlement?.entitlement_ref || null }, [decision.receipt_ref]);
      if (license) license.acceptance_receipt_ref = receipt.receipt_ref;
      return { order: currentOrder, delivery: currentDelivery, artifact_license: license, production_entitlement: entitlement, receipt_ref: receipt.receipt_ref, settlement_owner_decision: decision };
    }));
  }

  async openDispute(deliveryId, body, context) {
    const payload = { deliveryId, ...body }; const prior = await this.prior(context, payload); if (prior) return prior;
    const snapshot = await this.store.read(); const delivery = findDeliveryParty(snapshot, deliveryId, context); const order = findOrderParty(snapshot, delivery.order_id, context);
    if (context.principalRef !== order.buyer_ref && context.principalRef !== order.provider_ref) throw new DomainError(403, 'not_a_party', 'Only an order party may open a dispute');
    if (!['submitted', 'accepted'].includes(delivery.state) || snapshot.deliveries.filter((item) => item.order_id === order.order_id).at(-1)?.delivery_id !== deliveryId) throw new DomainError(409, 'invalid_state', 'Only the latest submitted or accepted delivery may be disputed');
    if (snapshot.disputes.some((item) => item.order_id === order.order_id && item.state === 'open')) throw new DomainError(409, 'dispute_exists', 'An open dispute already exists for this order');
    const decision = await this.owners.settlement.freeze({ order_id: order.order_id, delivery_id: deliveryId, settlement_ref: order.settlement_ref, claim: required(body.claim, 'claim') }, context);
    return this.store.transact((state) => idempotent(state, context, payload, () => {
      const currentOrder = findOrderParty(state, order.order_id, context); const currentDelivery = findDeliveryParty(state, deliveryId, context);
      if (!['submitted', 'accepted'].includes(currentDelivery.state) || state.deliveries.filter((item) => item.order_id === currentOrder.order_id).at(-1)?.delivery_id !== deliveryId || state.disputes.some((item) => item.order_id === currentOrder.order_id && item.state === 'open')) throw new DomainError(409, 'dispute_race', 'Order or delivery changed during settlement hold admission');
      const dispute = { dispute_id: randomUUID(), tenant_ref: currentOrder.buyer_tenant_ref, order_id: order.order_id, delivery_id: deliveryId, opened_by: context.principalRef, state: 'open', claim: body.claim, evidence: [], proposed_resolution: null, opened_at: now(), settlement_hold_receipt_ref: decision.receipt_ref };
      state.disputes.push(dispute); currentOrder.state = 'disputed'; currentOrder.settlement_state = 'disputed_hold'; currentDelivery.state = 'disputed';
      const license = state.artifactLicenses.filter((item) => item.order_id === currentOrder.order_id).at(-1);
      const entitlement = state.productionEntitlements.filter((item) => item.order_id === currentOrder.order_id).at(-1);
      if (license?.state === 'active') license.state = 'disputed_hold';
      if (entitlement?.state === 'active') entitlement.state = 'disputed_hold';
      const receipt = appendReceipt(state, context, 'dispute.opened', `dispute://${dispute.dispute_id}`, { order_id: order.order_id, delivery_id: deliveryId, claim_root: sha256(body.claim) }, [decision.receipt_ref]);
      return { ...dispute, receipt_ref: receipt.receipt_ref };
    }));
  }

  async addDisputeEvidence(disputeId, body, context) {
    return this.store.transact((state) => idempotent(state, context, { disputeId, ...body }, () => {
      const dispute = state.disputes.find((item) => item.dispute_id === disputeId); if (!dispute) throw new DomainError(404, 'not_found', 'dispute_id was not found'); const order = findOrderParty(state, dispute.order_id, context);
      if (![order.buyer_ref, order.provider_ref].includes(context.principalRef)) throw new DomainError(403, 'not_a_party', 'Only an order party may submit evidence');
      if (dispute.state !== 'open') throw new DomainError(409, 'invalid_state', 'Evidence may only be added to an open dispute');
      const evidence = { evidence_ref: required(body.evidence_ref, 'evidence_ref'), content_hash: required(body.content_hash, 'content_hash'), submitted_by: context.principalRef, submitted_at: now() };
      dispute.evidence.push(evidence); const receipt = appendReceipt(state, context, 'dispute.evidence.submitted', `dispute://${disputeId}`, evidence);
      return { ...evidence, receipt_ref: receipt.receipt_ref };
    }));
  }

  async resolveDispute(disputeId, body, context) {
    const payload = { disputeId, ...body }; const prior = await this.prior(context, payload); if (prior) return prior;
    const snapshot = await this.store.read(); const dispute = snapshot.disputes.find((item) => item.dispute_id === disputeId); if (!dispute) throw new DomainError(404, 'not_found', 'dispute_id was not found'); const order = findOrderParty(snapshot, dispute.order_id, context);
    if (context.principalRef !== order.buyer_ref && context.principalRef !== order.provider_ref) throw new DomainError(403, 'not_a_party', 'Only an order party may accept a resolution in this MVP');
    const allowed = ['refund', 'partial_refund', 'payout', 'partial_payout', 'rework', 'no_fault']; required(body.decision, 'decision'); if (!allowed.includes(body.decision)) throw new DomainError(422, 'invalid_decision', 'Unsupported dispute resolution');
    if (dispute.state !== 'open') throw new DomainError(409, 'invalid_state', 'Dispute is not open');
    const decision = await this.owners.settlement.resolve({ dispute_id: disputeId, order_id: order.order_id, settlement_ref: order.settlement_ref, decision: body.decision, amount: body.amount || null, evidence_roots: dispute.evidence.map((item) => item.content_hash) }, context);
    return this.store.transact((state) => idempotent(state, context, payload, () => {
      const current = state.disputes.find((item) => item.dispute_id === disputeId); const currentOrder = findOrderParty(state, current.order_id, context);
      if (current.state !== 'open') throw new DomainError(409, 'resolution_race', 'Dispute changed during settlement resolution');
      current.state = 'resolved'; current.resolution = { decision: body.decision, amount: body.amount || null, resolved_at: now(), owner_receipt_ref: decision.receipt_ref };
      currentOrder.state = body.decision === 'rework' ? 'revision_requested' : 'closed'; currentOrder.settlement_state = 'resolution_requested'; currentOrder.updated_at = now();
      const currentDelivery = state.deliveries.find((item) => item.delivery_id === current.delivery_id);
      if (currentDelivery) currentDelivery.state = body.decision === 'rework' ? 'revision_requested' : ['payout', 'no_fault'].includes(body.decision) ? 'accepted' : 'resolved';
      const license = state.artifactLicenses.filter((item) => item.order_id === currentOrder.order_id).at(-1);
      const entitlement = state.productionEntitlements.filter((item) => item.order_id === currentOrder.order_id).at(-1);
      const rightsState = ['payout', 'no_fault'].includes(body.decision) ? 'active' : body.decision === 'refund' ? 'revoked' : body.decision === 'rework' ? 'superseded_pending_rework' : 'restricted';
      if (license?.state === 'disputed_hold') license.state = rightsState;
      if (entitlement?.state === 'disputed_hold') entitlement.state = rightsState;
      const receipt = appendReceipt(state, context, 'dispute.resolved', `dispute://${disputeId}`, current.resolution, [decision.receipt_ref]);
      return { ...current, receipt_ref: receipt.receipt_ref };
    }));
  }

  async proposeSubstitution(orderId, body, context) {
    return this.store.transact((state) => idempotent(state, context, { orderId, ...body }, () => {
      const order = findOrderParty(state, orderId, context);
      const newProviderRef = required(body.new_provider_ref, 'new_provider_ref');
      const newProviderTenantRef = required(body.new_provider_tenant_ref, 'new_provider_tenant_ref');
      const successorBindingRef = required(body.successor_binding_ref, 'successor_binding_ref');
      if (!newProviderRef.startsWith('principal://') || !newProviderTenantRef.startsWith('tenant://') || !successorBindingRef.startsWith('provider-binding://')) throw new DomainError(422, 'successor_binding_invalid', 'Successor principal, tenant, and provider binding refs are required');
      if (newProviderRef === order.provider_ref && newProviderTenantRef === order.provider_tenant_ref) throw new DomainError(409, 'same_provider', 'Successor must differ from the current provider');
      const proposal = { proposal_id: randomUUID(), tenant_ref: order.buyer_tenant_ref, order_id: orderId, proposed_by: context.principalRef, old_provider_ref: order.provider_ref, old_provider_tenant_ref: order.provider_tenant_ref, new_provider_ref: newProviderRef, new_provider_tenant_ref: newProviderTenantRef, successor_binding_ref: successorBindingRef, state: 'proposed', price_delta: required(body.price_delta, 'price_delta'), sla_delta: required(body.sla_delta, 'sla_delta'), privacy_delta: body.privacy_delta || 'none', authority_delta: body.authority_delta || [], in_flight_disposition: required(body.in_flight_disposition, 'in_flight_disposition'), rollback_posture: required(body.rollback_posture, 'rollback_posture'), created_at: now() };
      state.substitutions.push(proposal); const receipt = appendReceipt(state, context, 'provider_substitution.proposed', `provider-substitution://${proposal.proposal_id}`, proposal);
      return { ...proposal, receipt_ref: receipt.receipt_ref };
    }));
  }

  async decideSubstitution(orderId, proposalId, decision, body, context) {
    return this.store.transact((state) => idempotent(state, context, { orderId, proposalId, decision, ...body }, () => {
      const proposal = state.substitutions.find((item) => item.proposal_id === proposalId); if (!proposal) throw new DomainError(404, 'not_found', 'proposal_id was not found'); const order = findOrderParty(state, proposal.order_id, context);
      if (proposal.order_id !== orderId) throw new DomainError(409, 'binding_mismatch', 'Provider substitution does not belong to the URL order');
      if (context.principalRef !== order.buyer_ref) throw new DomainError(403, 'buyer_decision_required', 'The buyer must decide provider substitution');
      if (proposal.state !== 'proposed') throw new DomainError(409, 'invalid_state', 'Proposal is no longer pending');
      proposal.state = decision === 'accept' ? 'accepted' : 'rejected'; proposal.decided_at = now();
      const receipt = appendReceipt(state, context, `provider_substitution.${proposal.state}`, `provider-substitution://${proposalId}`, { decision_reason: body.reason || null }); return { ...proposal, receipt_ref: receipt.receipt_ref };
    }));
  }

  async applySubstitution(orderId, proposalId, body, context) {
    const payload = { orderId, proposalId, ...body }; const prior = await this.prior(context, payload); if (prior) return prior;
    const snapshot = await this.store.read(); const proposal = snapshot.substitutions.find((item) => item.proposal_id === proposalId); if (!proposal) throw new DomainError(404, 'not_found', 'proposal_id was not found'); const order = findOrderParty(snapshot, proposal.order_id, context);
    if (proposal.order_id !== orderId) throw new DomainError(409, 'binding_mismatch', 'Provider substitution does not belong to the URL order');
    if (context.principalRef !== order.buyer_ref || context.tenantRef !== order.buyer_tenant_ref) throw new DomainError(403, 'buyer_apply_required', 'The buyer must apply provider substitution');
    if (proposal.state !== 'accepted') throw new DomainError(409, 'not_accepted', 'Substitution must be accepted before cutover');
    const decision = await this.owners.runtime.substitute({ order_id: order.order_id, old_provider_ref: proposal.old_provider_ref, old_provider_tenant_ref: proposal.old_provider_tenant_ref, new_provider_ref: proposal.new_provider_ref, new_provider_tenant_ref: proposal.new_provider_tenant_ref, successor_binding_ref: proposal.successor_binding_ref, terms_root: order.terms_root, in_flight_disposition: proposal.in_flight_disposition }, context);
    return this.store.transact((state) => idempotent(state, context, payload, () => {
      const current = state.substitutions.find((item) => item.proposal_id === proposalId); const currentOrder = findOrderParty(state, current.order_id, context);
      if (current.order_id !== orderId || current.state !== 'accepted' || currentOrder.provider_ref !== current.old_provider_ref || currentOrder.provider_tenant_ref !== current.old_provider_tenant_ref) throw new DomainError(409, 'substitution_race', 'Provider binding changed during successor preflight');
      current.state = 'applied'; current.effective_at = now(); current.owner_receipt_ref = decision.receipt_ref; currentOrder.provider_ref = current.new_provider_ref; currentOrder.provider_tenant_ref = current.new_provider_tenant_ref; currentOrder.provider_binding_ref = current.successor_binding_ref; currentOrder.updated_at = now();
      const receipt = appendReceipt(state, context, 'provider_substitution.applied', `provider-substitution://${proposalId}`, { predecessor_provider_ref: current.old_provider_ref, successor_provider_ref: current.new_provider_ref, terms_root: currentOrder.terms_root }, [decision.receipt_ref]);
      return { ...current, receipt_ref: receipt.receipt_ref };
    }));
  }

  async getLicense(licenseRef, context) {
    const license = findOwned((await this.store.read()).artifactLicenses, licenseRef, context, 'license_ref');
    if (license.licensee_ref !== context.principalRef) throw new DomainError(404, 'not_found', 'license_ref was not found');
    return license;
  }
  async getEntitlement(entitlementRef, context) {
    const state = await this.store.read(); const entitlement = findOwned(state.productionEntitlements, entitlementRef, context, 'entitlement_ref');
    if (entitlement.licensee_ref !== context.principalRef) throw new DomainError(404, 'not_found', 'entitlement_ref was not found');
    return { ...entitlement, reservations: state.productionReservations.filter((item) => item.entitlement_ref === entitlementRef), usage_receipts: state.productionUsageReceipts.filter((item) => item.entitlement_ref === entitlementRef) };
  }

  async authorizeDownload(artifactRef, body, context) {
    const payload = { artifactRef, ...body }; const prior = await this.prior(context, payload); if (prior) return prior;
    const state = await this.store.read(); const license = state.artifactLicenses.find((item) => item.artifact_ref === artifactRef && item.tenant_ref === context.tenantRef && item.licensee_ref === context.principalRef && item.state === 'active');
    if (!license) throw new DomainError(403, 'license_required', 'An active buyer-bound artifact license is required');
    if (!license.granted_rights?.download || license.production_enforcement_mode === 'governed_remote_production') throw new DomainError(403, 'download_not_granted', 'This license keeps raw CAD inside the governed production boundary');
    const decision = await this.owners.authority.artifactDownload({ artifact_ref: artifactRef, artifact_content_hash: license.artifact_content_hash, license_ref: license.license_ref, purpose: body.purpose || 'licensed-use' }, context);
    return this.store.transact((current) => idempotent(current, context, payload, () => {
      const receipt = appendReceipt(current, context, 'artifact.download.authorized', artifactRef, { license_ref: license.license_ref, statement: `Licensed for ${license.production_limit_units} pieces; buyer reporting and audit terms apply.` }, [decision.receipt_ref]);
      return { artifact_ref: artifactRef, license_ref: license.license_ref, authorization_receipt_ref: receipt.receipt_ref, owner_authorization_ref: decision.authorization_ref, expires_at: new Date(Date.now() + 5 * 60_000).toISOString(), enforcement_statement: receipt.body.statement, download_available: Boolean(decision.download_capability), download_capability: decision.download_capability || null };
    }));
  }

  async reserveProduction(entitlementRef, body, context) {
    const payload = { entitlementRef, ...body }; const prior = await this.prior(context, payload); if (prior) return prior;
    positiveInteger(body.units, 'units');
    const snapshot = await this.store.read(); const entitlement = findOwned(snapshot.productionEntitlements, entitlementRef, context, 'entitlement_ref');
    if (entitlement.licensee_ref !== context.principalRef || entitlement.enforcement_mode !== 'governed_remote_production' || entitlement.state !== 'active') throw new DomainError(403, 'production_not_admitted', 'Active governed remote-production entitlement is required');
    if (Number(body.expected_revision) !== entitlement.revision) throw new DomainError(409, 'revision_conflict', 'Production entitlement revision changed; reload before reserving units');
    if (entitlement.remaining_units < body.units) throw new DomainError(409, 'insufficient_units', `Only ${entitlement.remaining_units} controlled production units remain`);
    const decision = await this.owners.authority.productionReserve({ entitlement_ref: entitlementRef, expected_revision: entitlement.revision, units: body.units, facility_ref: required(body.facility_ref, 'facility_ref'), machine_ref: required(body.machine_ref, 'machine_ref') }, context);
    return this.store.transact((state) => idempotent(state, context, payload, () => {
      const current = findOwned(state.productionEntitlements, entitlementRef, context, 'entitlement_ref');
      if (current.licensee_ref !== context.principalRef || current.revision !== entitlement.revision) throw new DomainError(409, 'reservation_race', 'Production entitlement changed during reservation admission');
      if (current.remaining_units < body.units) throw new DomainError(409, 'insufficient_units', `Only ${current.remaining_units} controlled production units remain`);
      current.reserved_units += body.units; current.remaining_units = current.total_units - current.reserved_units - current.admitted_consumed_units; current.revision += 1;
      const reservation = { reservation_ref: ref('production-reservation'), tenant_ref: context.tenantRef, licensee_ref: context.principalRef, entitlement_ref: entitlementRef, units: body.units, facility_ref: body.facility_ref, machine_ref: body.machine_ref, state: 'reserved', created_at: now(), production_admission_ref: decision.production_admission_ref, authority_receipt_ref: decision.receipt_ref };
      state.productionReservations.push(reservation); const receipt = appendReceipt(state, context, 'production.units.reserved', reservation.reservation_ref, { entitlement_ref: entitlementRef, units: body.units, remaining_units: current.remaining_units }, [decision.receipt_ref]);
      return { reservation, entitlement: current, receipt_ref: receipt.receipt_ref };
    }));
  }

  async consumeProduction(entitlementRef, body, context) {
    const payload = { entitlementRef, ...body }; const prior = await this.prior(context, payload); if (prior) return prior;
    const snapshot = await this.store.read(); const entitlementSnapshot = findOwned(snapshot.productionEntitlements, entitlementRef, context, 'entitlement_ref'); const reservationSnapshot = findOwned(snapshot.productionReservations, required(body.reservation_ref, 'reservation_ref'), context, 'reservation_ref');
    if (entitlementSnapshot.licensee_ref !== context.principalRef || reservationSnapshot.licensee_ref !== context.principalRef || entitlementSnapshot.enforcement_mode !== 'governed_remote_production' || entitlementSnapshot.state !== 'active') throw new DomainError(403, 'production_not_admitted', 'Only the active bound licensee may consume controlled production units');
    if (Number(body.expected_revision) !== entitlementSnapshot.revision) throw new DomainError(409, 'revision_conflict', 'Production entitlement revision changed; reload before consuming units');
    if (reservationSnapshot.entitlement_ref !== entitlementRef || reservationSnapshot.state !== 'reserved') throw new DomainError(409, 'invalid_reservation', 'Reservation is not open for this entitlement');
    const admittedUnits = positiveInteger(body.admitted_units, 'admitted_units'); if (admittedUnits > reservationSnapshot.units) throw new DomainError(422, 'reservation_overflow', 'Admitted units exceed reservation');
    const evidenceRefs = nonemptyRefs(body.evidence_refs, 'evidence_refs', ['evidence://', 'artifact://', 'verifier-result://']);
    const decision = await this.owners.authority.productionConsume({ entitlement_ref: entitlementRef, expected_revision: entitlementSnapshot.revision, reservation_ref: reservationSnapshot.reservation_ref, production_admission_ref: reservationSnapshot.production_admission_ref, admitted_units: admittedUnits, batch_or_work_order_ref: required(body.batch_or_work_order_ref, 'batch_or_work_order_ref'), facility_ref: reservationSnapshot.facility_ref, machine_ref: reservationSnapshot.machine_ref, evidence_refs: evidenceRefs }, context);
    return this.store.transact((state) => idempotent(state, context, payload, () => {
      const entitlement = findOwned(state.productionEntitlements, entitlementRef, context, 'entitlement_ref'); const reservation = findOwned(state.productionReservations, body.reservation_ref, context, 'reservation_ref');
      if (entitlement.licensee_ref !== context.principalRef || reservation.licensee_ref !== context.principalRef || entitlement.enforcement_mode !== 'governed_remote_production' || entitlement.state !== 'active' || entitlement.revision !== entitlementSnapshot.revision) throw new DomainError(409, 'consumption_race', 'Production entitlement changed during usage admission');
      if (reservation.entitlement_ref !== entitlementRef || reservation.state !== 'reserved') throw new DomainError(409, 'invalid_reservation', 'Reservation is not open for this entitlement');
      reservation.state = 'consumed'; reservation.consumed_at = now(); entitlement.reserved_units -= reservation.units; entitlement.admitted_consumed_units += admittedUnits; entitlement.remaining_units = entitlement.total_units - entitlement.reserved_units - entitlement.admitted_consumed_units; entitlement.revision += 1; if (entitlement.remaining_units === 0) entitlement.state = 'exhausted';
      const previous = state.productionUsageReceipts.filter((item) => item.entitlement_ref === entitlementRef).at(-1);
      const usage = { usage_receipt_ref: ref('production-usage-receipt'), tenant_ref: context.tenantRef, licensee_ref: context.principalRef, entitlement_ref: entitlementRef, sequence: (previous?.sequence || 0) + 1, previous_receipt_hash: previous?.body_hash || null, reservation_ref: reservation.reservation_ref, production_usage_admission_ref: decision.production_usage_admission_ref, batch_or_work_order_ref: body.batch_or_work_order_ref, requested_units: reservation.units, admitted_units: admittedUnits, facility_ref: reservation.facility_ref, machine_ref: reservation.machine_ref, evidence_refs: evidenceRefs, owner_receipt_ref: decision.receipt_ref, occurred_at: now() };
      usage.body_hash = sha256(usage); state.productionUsageReceipts.push(usage); entitlement.latest_usage_receipt_hash = usage.body_hash;
      const receipt = appendReceipt(state, context, 'production.units.consumed', usage.usage_receipt_ref, { entitlement_ref: entitlementRef, admitted_units: admittedUnits, remaining_units: entitlement.remaining_units, usage_body_hash: usage.body_hash }, [decision.receipt_ref]);
      return { usage_receipt: usage, entitlement, receipt_ref: receipt.receipt_ref };
    }));
  }

  async receipts(context, objectRef = null) { return (await this.store.read()).receipts.filter((item) => item.tenant_ref === context.tenantRef && item.principal_ref === context.principalRef && (!objectRef || item.object_ref === objectRef)); }
}
