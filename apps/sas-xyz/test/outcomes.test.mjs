import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { createOwnerAdapters, OwnerDependencyError, validateOwnerDecision } from '../domain/adapters.mjs';
import { DomainError, SasService, seedState } from '../domain/service.mjs';
import { JsonStore, StateIntegrityError } from '../domain/store.mjs';

const provider = (key) => ({ idempotencyKey: key, principalRef: 'principal://provider/cadco', tenantRef: 'tenant://provider/cadco' });
const buyer = (key) => ({ idempotencyKey: key, principalRef: 'principal://buyer/acme', tenantRef: 'tenant://buyer/acme' });

async function fixture(t) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'sas-outcomes-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const file = path.join(directory, 'state.json'); const store = await new JsonStore(file, seedState).init();
  return { file, store, service: new SasService(store, createOwnerAdapters({ developmentAuthority: true })) };
}

const serviceBody = {
  name: 'Engineering CAD outcome', version: '1.0.0', summary: 'Validated mechanical CAD and evidence.',
  outcome_contract: { output: 'STEP CAD and validation report', acceptance: 'Hashes resolve and declared validation passes' },
  deliverable_kind: 'cad', price: { asset: 'USD', amount_minor: 250000, decimals: 2 }, sla: '10 business days',
  artifact_rights: { enforcement_modes: ['contractual_audit', 'governed_remote_production'], production_limit_units: 100, granted_rights: { inspect: true, download: true, modify: true, manufacture: true, sublicense: false, transfer: false } },
};

test('CAD order, delivery, acceptance, rights, reservation, and usage survive restart', async (t) => {
  const { file, service } = await fixture(t);
  const listing = await service.createService(serviceBody, provider('service'));
  const order = await service.createOrder({ service_id: listing.service_id, objective: 'Produce a validated bracket', acceptance_criteria: 'STEP hash and validation evidence pass', settlement_rail: 'settlement-rail://escrow/usdc', production_limit_units: 100, enforcement_mode: 'governed_remote_production' }, buyer('order'));
  assert.equal((await service.listOrders(provider('provider-list'))).length, 1, 'selected provider can see cross-tenant order');
  assert.equal((await service.listOrders({ ...buyer('other'), principalRef: 'principal://stranger' })).length, 0);
  await service.claimOrder(order.order_id, {}, provider('claim'));
  const delivery = await service.submitDelivery(order.order_id, { kind: 'final', artifacts: [{ artifact_ref: 'artifact://cad/bracket.step', content_hash: 'sha256:cad-bracket' }], evidence_refs: ['evidence://cad/validation'], verifier_result_refs: ['verifier-result://cad/pass'] }, provider('delivery'));
  const accepted = await service.acceptDelivery(delivery.delivery_id, {}, buyer('accept'));
  assert.equal(accepted.artifact_license.state, 'active');
  assert.equal(accepted.production_entitlement.remaining_units, 100);
  assert.equal((await service.getOrder(order.order_id, buyer('rights-projection'))).artifact_license.license_ref, accepted.artifact_license.license_ref);

  const reserved = await service.reserveProduction(accepted.production_entitlement.entitlement_ref, { expected_revision: accepted.production_entitlement.revision, units: 25, facility_ref: 'facility://controlled/one', machine_ref: 'machine://cnc/one' }, buyer('reserve'));
  assert.equal(reserved.entitlement.remaining_units, 75);
  const retry = await service.reserveProduction(accepted.production_entitlement.entitlement_ref, { expected_revision: accepted.production_entitlement.revision, units: 25, facility_ref: 'facility://controlled/one', machine_ref: 'machine://cnc/one' }, buyer('reserve'));
  assert.equal(retry.reservation.reservation_ref, reserved.reservation.reservation_ref);
  const consumed = await service.consumeProduction(accepted.production_entitlement.entitlement_ref, { expected_revision: reserved.entitlement.revision, reservation_ref: reserved.reservation.reservation_ref, admitted_units: 25, batch_or_work_order_ref: 'work-order://batch/one', evidence_refs: ['evidence://machine/batch-one'] }, buyer('consume'));
  assert.equal(consumed.entitlement.admitted_consumed_units, 25);
  assert.equal(consumed.entitlement.remaining_units, 75);
  assert.equal(consumed.usage_receipt.sequence, 1);
  const concurrent = await Promise.allSettled([
    service.reserveProduction(accepted.production_entitlement.entitlement_ref, { expected_revision: consumed.entitlement.revision, units: 60, facility_ref: 'facility://controlled/one', machine_ref: 'machine://cnc/one' }, buyer('concurrent-a')),
    service.reserveProduction(accepted.production_entitlement.entitlement_ref, { expected_revision: consumed.entitlement.revision, units: 60, facility_ref: 'facility://controlled/one', machine_ref: 'machine://cnc/one' }, buyer('concurrent-b')),
  ]);
  assert.equal(concurrent.filter((result) => result.status === 'fulfilled').length, 1);
  assert.equal(concurrent.filter((result) => result.status === 'rejected').length, 1);
  const afterConcurrent = await service.getEntitlement(accepted.production_entitlement.entitlement_ref, buyer('after-concurrent'));
  await assert.rejects(() => service.reserveProduction(accepted.production_entitlement.entitlement_ref, { expected_revision: afterConcurrent.revision, units: 76, facility_ref: 'facility://controlled/one', machine_ref: 'machine://cnc/one' }, buyer('over')), (error) => error instanceof DomainError && error.code === 'insufficient_units');
  assert.equal((await service.status()).receipt_chain_valid, true);

  const restarted = new SasService(await new JsonStore(file, seedState).init(), createOwnerAdapters({ developmentAuthority: true }));
  assert.equal((await restarted.getEntitlement(accepted.production_entitlement.entitlement_ref, buyer('read'))).remaining_units, 15);
});

test('contractual mode is honest and download authorization is owner-backed', async (t) => {
  const { service } = await fixture(t); const listing = await service.createService(serviceBody, provider('service-contract'));
  await assert.rejects(() => service.createOrder({ service_id: listing.service_id, objective: 'Over-license CAD', acceptance_criteria: 'Artifact accepted', settlement_rail: 'settlement-rail://escrow/usdc', production_limit_units: 101, enforcement_mode: 'contractual_audit' }, buyer('order-over-limit')), (error) => error.code === 'production_limit_exceeds_offer');
  await assert.rejects(() => service.createOrder({ service_id: listing.service_id, objective: 'Unsupported mode', acceptance_criteria: 'Artifact accepted', settlement_rail: 'settlement-rail://escrow/usdc', production_limit_units: 40, enforcement_mode: 'invented_drm' }, buyer('order-invalid-mode')), (error) => error.code === 'enforcement_mode_not_offered');
  const order = await service.createOrder({ service_id: listing.service_id, objective: 'Produce downloadable CAD', acceptance_criteria: 'Artifact accepted', settlement_rail: 'settlement-rail://escrow/usdc', production_limit_units: 40, enforcement_mode: 'contractual_audit' }, buyer('order-contract'));
  await service.claimOrder(order.order_id, {}, provider('claim-contract'));
  const delivery = await service.submitDelivery(order.order_id, { artifacts: [{ artifact_ref: 'artifact://cad/download.step', content_hash: 'sha256:download' }], evidence_refs: ['evidence://validation'] }, provider('delivery-contract'));
  const accepted = await service.acceptDelivery(delivery.delivery_id, {}, buyer('accept-contract'));
  const authorization = await service.authorizeDownload('artifact://cad/download.step', { purpose: 'licensed-production' }, buyer('download'));
  assert.match(authorization.enforcement_statement, /Licensed for 40 pieces; buyer reporting and audit terms apply\./);
  assert.doesNotMatch(authorization.enforcement_statement, /DRM|guaranteed/i);
  assert.equal(accepted.production_entitlement.enforcement_mode, 'contractual_audit');
  assert.equal(authorization.download_available, false);
  assert.equal(authorization.download_capability, null);
  const dispute = await service.openDispute(delivery.delivery_id, { claim: 'Accepted CAD requires settlement review' }, buyer('contract-dispute'));
  assert.equal((await service.getOrder(order.order_id, buyer('contract-hold-read'))).artifact_license.state, 'disputed_hold');
  await assert.rejects(() => service.authorizeDownload('artifact://cad/download.step', { purpose: 'licensed-production' }, buyer('download-on-hold')), (error) => error.code === 'license_required');
  await service.resolveDispute(dispute.dispute_id, { decision: 'payout' }, buyer('contract-resolution'));
  assert.equal((await service.getOrder(order.order_id, buyer('contract-resolved-read'))).artifact_license.state, 'active');
  await assert.rejects(() => service.reserveProduction(accepted.production_entitlement.entitlement_ref, { expected_revision: accepted.production_entitlement.revision, units: 1, facility_ref: 'facility://one', machine_ref: 'machine://one' }, buyer('contract-reserve')), (error) => error instanceof DomainError && error.code === 'production_not_admitted');
});

test('revision, dispute, evidence, resolution, and provider substitution preserve history', async (t) => {
  const { service } = await fixture(t); const listing = await service.createService({ ...serviceBody, deliverable_kind: 'general', artifact_rights: null }, provider('service-general'));
  const order = await service.createOrder({ service_id: listing.service_id, objective: 'Analyze design', acceptance_criteria: 'Report passes rubric', settlement_rail: 'settlement-rail://escrow/usdc' }, buyer('order-general'));
  await service.claimOrder(order.order_id, {}, provider('claim-general'));
  const first = await service.submitDelivery(order.order_id, { artifacts: [{ artifact_ref: 'artifact://report/one', content_hash: 'sha256:one' }] }, provider('delivery-one'));
  await service.requestRevision(first.delivery_id, { reason: 'Missing validation section' }, buyer('revision'));
  const second = await service.submitDelivery(order.order_id, { artifacts: [{ artifact_ref: 'artifact://report/two', content_hash: 'sha256:two' }] }, provider('delivery-two'));
  const dispute = await service.openDispute(second.delivery_id, { claim: 'Validation still fails the frozen rubric' }, buyer('dispute'));
  await service.addDisputeEvidence(dispute.dispute_id, { evidence_ref: 'evidence://rubric/fail', content_hash: 'sha256:evidence' }, buyer('evidence'));
  const resolved = await service.resolveDispute(dispute.dispute_id, { decision: 'rework' }, provider('resolution'));
  assert.equal(resolved.state, 'resolved');
  const proposal = await service.proposeSubstitution(order.order_id, { new_provider_ref: 'principal://provider/successor', new_provider_tenant_ref: 'tenant://provider/successor', successor_binding_ref: 'provider-binding://successor/admitted-v1', price_delta: 'none', sla_delta: '+2 days', privacy_delta: 'none', authority_delta: [], in_flight_disposition: 'preserve-artifacts', rollback_posture: 'restore-predecessor' }, buyer('proposal'));
  await assert.rejects(() => service.decideSubstitution('wrong-order', proposal.proposal_id, 'accept', {}, buyer('proposal-wrong-order')), (error) => error.code === 'binding_mismatch');
  const accepted = await service.decideSubstitution(order.order_id, proposal.proposal_id, 'accept', {}, buyer('proposal-accept'));
  const applied = await service.applySubstitution(order.order_id, accepted.proposal_id, {}, buyer('proposal-apply'));
  assert.equal(applied.state, 'applied');
  const projection = await service.getOrder(order.order_id, buyer('read-order'));
  assert.equal(projection.deliveries.length, 2);
  assert.equal(projection.deliveries[0].state, 'revision_requested');
  assert.equal(projection.provider_ref, 'principal://provider/successor');
  assert.equal((await service.getOrder(order.order_id, { idempotencyKey: 'successor-read', principalRef: 'principal://provider/successor', tenantRef: 'tenant://provider/successor' })).provider_tenant_ref, 'tenant://provider/successor');
});

test('governed production is licensee-bound, evidence-bound, and CAS protected', async (t) => {
  const { service } = await fixture(t); const listing = await service.createService(serviceBody, provider('guard-service'));
  const order = await service.createOrder({ service_id: listing.service_id, objective: 'Guard units', acceptance_criteria: 'Accepted', settlement_rail: 'settlement-rail://escrow/usdc', enforcement_mode: 'governed_remote_production' }, buyer('guard-order'));
  await service.claimOrder(order.order_id, {}, provider('guard-claim'));
  const delivery = await service.submitDelivery(order.order_id, { artifacts: [{ artifact_ref: 'artifact://cad/guard.step', content_hash: 'sha256:guard' }] }, provider('guard-delivery'));
  const accepted = await service.acceptDelivery(delivery.delivery_id, {}, buyer('guard-accept'));
  const reserved = await service.reserveProduction(accepted.production_entitlement.entitlement_ref, { expected_revision: 1, units: 5, facility_ref: 'facility://one', machine_ref: 'machine://one' }, buyer('guard-reserve'));
  const attacker = { idempotencyKey: 'attacker', principalRef: 'principal://buyer/peer', tenantRef: 'tenant://buyer/acme' };
  await assert.rejects(() => service.getEntitlement(accepted.production_entitlement.entitlement_ref, attacker), (error) => error.code === 'not_found');
  await assert.rejects(() => service.consumeProduction(accepted.production_entitlement.entitlement_ref, { expected_revision: reserved.entitlement.revision, reservation_ref: reserved.reservation.reservation_ref, admitted_units: 5, batch_or_work_order_ref: 'work-order://bad', evidence_refs: ['evidence://one'] }, attacker), (error) => error.code === 'production_not_admitted');
  await assert.rejects(() => service.consumeProduction(accepted.production_entitlement.entitlement_ref, { expected_revision: reserved.entitlement.revision, reservation_ref: reserved.reservation.reservation_ref, admitted_units: 5, batch_or_work_order_ref: 'work-order://bad', evidence_refs: [] }, buyer('empty-evidence')), (error) => error.code === 'invalid_refs');
  await assert.rejects(() => service.consumeProduction(accepted.production_entitlement.entitlement_ref, { expected_revision: 1, reservation_ref: reserved.reservation.reservation_ref, admitted_units: 5, batch_or_work_order_ref: 'work-order://stale', evidence_refs: ['evidence://one'] }, buyer('stale')), (error) => error.code === 'revision_conflict');
});

test('partial delivery and dispute transitions remain monotonic', async (t) => {
  const { service } = await fixture(t); const listing = await service.createService({ ...serviceBody, deliverable_kind: 'general', artifact_rights: null }, provider('partial-service'));
  const order = await service.createOrder({ service_id: listing.service_id, objective: 'Partial work', acceptance_criteria: 'Final required', settlement_rail: 'settlement-rail://escrow/usdc' }, buyer('partial-order'));
  await service.claimOrder(order.order_id, {}, provider('partial-claim'));
  const partial = await service.submitDelivery(order.order_id, { kind: 'partial', artifacts: [{ artifact_ref: 'artifact://partial', content_hash: 'sha256:partial' }] }, provider('partial-one'));
  assert.equal((await service.getOrder(order.order_id, buyer('partial-read'))).state, 'in_progress');
  await assert.rejects(() => service.acceptDelivery(partial.delivery_id, {}, buyer('partial-accept')), (error) => error.code === 'invalid_state');
  const final = await service.submitDelivery(order.order_id, { kind: 'final', artifacts: [{ artifact_ref: 'artifact://final', content_hash: 'sha256:final' }] }, provider('partial-final'));
  const dispute = await service.openDispute(final.delivery_id, { claim: 'Fails final criteria' }, buyer('partial-dispute'));
  await service.resolveDispute(dispute.dispute_id, { decision: 'rework' }, buyer('partial-resolve'));
  await assert.rejects(() => service.resolveDispute(dispute.dispute_id, { decision: 'rework' }, buyer('partial-resolve-twice')), (error) => error.code === 'invalid_state');
  await assert.rejects(() => service.addDisputeEvidence(dispute.dispute_id, { evidence_ref: 'evidence://late', content_hash: 'sha256:late' }, buyer('partial-late')), (error) => error.code === 'invalid_state');
});

test('malformed owner success and tampered receipt chains fail closed', async (t) => {
  assert.throws(() => validateOwnerDecision('runtime.assign', { status: 'admitted' }), (error) => error instanceof OwnerDependencyError && error.code === 'owner_contract_invalid');
  const upstream = createServer((request, response) => { response.writeHead(200, { 'content-type': 'application/json' }); response.end('{}'); });
  await new Promise((resolve) => upstream.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => upstream.close(resolve)));
  const owners = createOwnerAdapters({ operations: { 'runtime.assign': { baseUrl: `http://127.0.0.1:${upstream.address().port}`, route: '/decision' } } });
  await assert.rejects(() => owners.runtime.assign({}, buyer('malformed-owner')), (error) => error instanceof OwnerDependencyError && error.code === 'owner_contract_invalid');
  const { file, service } = await fixture(t);
  await service.createService(serviceBody, provider('chain-service'));
  const state = JSON.parse(await readFile(file, 'utf8')); state.receipts[0].action = 'tampered'; await writeFile(file, `${JSON.stringify(state)}\n`, 'utf8');
  await assert.rejects(() => new JsonStore(file, seedState).init(), StateIntegrityError);
});
