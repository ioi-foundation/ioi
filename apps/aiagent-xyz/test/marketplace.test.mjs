import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { createOwnerAdapters, OwnerDependencyError, validateOwnerDecision } from '../domain/adapters.mjs';
import { AiagentService, DomainError, seedState } from '../domain/service.mjs';
import { JsonStore, StateIntegrityError } from '../domain/store.mjs';

const context = (key, tenantRef = 'tenant://buyer/acme', principalRef = 'principal://buyer/alex') => ({ idempotencyKey: key, tenantRef, principalRef });

async function fixture(t) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'aiagent-marketplace-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const file = path.join(directory, 'state.json');
  const store = await new JsonStore(file, seedState).init();
  return { file, store, service: new AiagentService(store, createOwnerAdapters({ developmentAuthority: true })) };
}

test('worker supply, publication, hire, integration, and lifecycle are durable and receipted', async (t) => {
  const { file, service } = await fixture(t);
  const draft = await service.createDraft({
    template_ref: 'worker-template://telesupport/v1', name: 'Telesupport operator', description: 'Typed support triage and bounded reply worker.',
    task_contract: { input: 'SupportTicket', output: 'SupportResolution' }, model_route_ref: 'model-route://support/default',
    harness_ref: 'harness://worker/v1', runtime_profile_ref: 'runtime-profile://zero-to-idle/v1', integration_surfaces: ['helpdesk'],
    authority_scopes: ['ticket:read', 'reply:draft'], pricing: { asset: 'USD', amount_minor: 4900, cadence: 'month' },
  }, context('draft'));
  await service.validateDraft(draft.draft_ref, { expected_revision: draft.revision }, context('validate'));
  const release = await service.releaseDraft(draft.draft_ref, { version: '1.0.0', sbom_ref: 'sbom://support/v1', provenance_ref: 'provenance://support/v1' }, context('release'));
  assert.match(release.release_ref, /^package-release:\/\//);
  const registration = await service.registerWorker({ draft_ref: draft.draft_ref, visibility: 'private' }, context('register'));
  assert.equal(registration.visibility, 'private');
  const promotion = await service.createPromotion(registration.registration_ref, { disclosure_allowlist: ['name', 'description'], license: 'commercial-managed', pricing: { asset: 'USD', amount_minor: 4900, cadence: 'month' } }, context('promote'));
  const submission = await service.submitPromotion(registration.registration_ref, promotion.promotion_ref, {}, context('submit'));
  await service.benchmarkSubmission(submission.submission_id, { evaluation_plan_ref: 'evaluation-plan://support/adversarial-v1' }, context('benchmark'));
  const listing = await service.publishSubmission(submission.submission_id, {}, context('publish'));
  assert.equal(listing.state, 'published');

  const quote = await service.quoteWorker(listing.worker_id, { intent: 'hire' }, context('quote'));
  const hired = await service.hireWorker(listing.worker_id, { quote_ref: quote.quote_ref, runtime_profile_ref: 'runtime-profile://zero-to-idle/v1', persistence_profile_ref: 'storage-profile://encrypted/v1', authority_grant_refs: [] }, context('hire'));
  assert.equal(hired.instance.desired_state, 'active');
  assert.equal(hired.instance.observed_state, 'unknown');
  assert.notEqual(hired.entitlement.entitlement_ref, hired.install.install_id);

  await assert.rejects(() => service.addIntegration(hired.instance.worker_instance_id, { integration_surface: 'helpdesk', credential_ref: 'credential-grant://wallet/1', scope_refs: ['tickets:read'], secret: 'never-store-me' }, context('secret')), (error) => error instanceof DomainError && error.code === 'secret_custody_forbidden');
  const integration = await service.addIntegration(hired.instance.worker_instance_id, { integration_surface: 'helpdesk', credential_ref: 'credential-grant://wallet/1', scope_refs: ['tickets:read'] }, context('integration'));
  const tested = await service.testIntegration(hired.instance.worker_instance_id, integration.binding_id, {}, context('integration-test'));
  assert.equal(tested.state, 'ready');
  const suspended = await service.transitionInstance(hired.instance.worker_instance_id, 'suspend', { reason: 'operator request' }, context('suspend'));
  assert.equal(suspended.desired_state, 'suspended');
  assert.equal(suspended.observed_state, 'unknown');

  const retry = await service.transitionInstance(hired.instance.worker_instance_id, 'suspend', { reason: 'operator request' }, context('suspend'));
  assert.equal(retry.receipt_ref, suspended.receipt_ref);
  assert.equal((await service.status()).receipt_chain_valid, true);

  const restarted = new AiagentService(await new JsonStore(file, seedState).init(), createOwnerAdapters({ developmentAuthority: true }));
  assert.equal((await restarted.getInstance(hired.instance.worker_instance_id, context('read'))).desired_state, 'suspended');
  assert.doesNotReject(() => readFile(file, 'utf8'));
});

test('tenant isolation, idempotency conflicts, and secret custody fail closed', async (t) => {
  const { service } = await fixture(t);
  const body = { template_ref: 'worker-template://blank/v1', name: 'Private worker', description: 'Tenant-bound worker draft.', model_route_ref: 'model-route://one', harness_ref: 'harness://one', runtime_profile_ref: 'runtime-profile://one' };
  await service.createDraft(body, context('same-key'));
  assert.deepEqual(await service.listDrafts(context('read-other', 'tenant://other', 'principal://other')), []);
  assert.deepEqual(await service.listDrafts(context('read-peer', 'tenant://buyer/acme', 'principal://buyer/peer')), []);
  const ownDraft = (await service.listDrafts(context('read-own')))[0];
  await assert.rejects(() => service.updateDraft(ownDraft.draft_ref, { expected_revision: ownDraft.revision, name: 'Peer mutation' }, context('peer-mutation', 'tenant://buyer/acme', 'principal://buyer/peer')), (error) => error.code === 'not_found');
  await assert.rejects(() => service.createDraft({ ...body, name: 'Changed' }, context('same-key')), (error) => error instanceof DomainError && error.code === 'idempotency_conflict');
});

test('network mode refuses missing owner services', async (t) => {
  const { store } = await fixture(t);
  const service = new AiagentService(store, createOwnerAdapters({ developmentAuthority: false }));
  const draft = await service.createDraft({ template_ref: 'worker-template://blank/v1', name: 'Network worker', description: 'Requires real package owner.', model_route_ref: 'model-route://one', harness_ref: 'harness://one', runtime_profile_ref: 'runtime-profile://one' }, context('network-draft'));
  await service.validateDraft(draft.draft_ref, { expected_revision: draft.revision }, context('network-validate'));
  await assert.rejects(() => service.releaseDraft(draft.draft_ref, { version: '1.0.0', sbom_ref: 'sbom://one', provenance_ref: 'provenance://one' }, context('network-release')), OwnerDependencyError);
});

test('released drafts and published submissions are terminal and unique', async (t) => {
  const { service } = await fixture(t);
  const draft = await service.createDraft({ template_ref: 'worker-template://blank/v1', name: 'Immutable', description: 'Immutable release.', model_route_ref: 'model-route://one', harness_ref: 'harness://one', runtime_profile_ref: 'runtime-profile://one' }, context('terminal-draft'));
  await service.validateDraft(draft.draft_ref, { expected_revision: draft.revision }, context('terminal-validate'));
  await service.releaseDraft(draft.draft_ref, { version: '1.0.0', sbom_ref: 'sbom://one', provenance_ref: 'provenance://one' }, context('terminal-release'));
  await assert.rejects(() => service.validateDraft(draft.draft_ref, { expected_revision: draft.revision }, context('revalidate')), (error) => error.code === 'invalid_state');
  await assert.rejects(() => service.updateDraft(draft.draft_ref, { expected_revision: draft.revision, name: 'Mutated' }, context('mutate-release')), (error) => error.code === 'immutable_candidate');
  const registration = await service.registerWorker({ draft_ref: draft.draft_ref }, context('terminal-register'));
  const promotion = await service.createPromotion(registration.registration_ref, { disclosure_allowlist: ['name'], license: 'commercial', pricing: { asset: 'USD', amount_minor: 1 } }, context('terminal-promotion'));
  const submission = await service.submitPromotion(registration.registration_ref, promotion.promotion_ref, {}, context('terminal-submit'));
  await service.benchmarkSubmission(submission.submission_id, { evaluation_plan_ref: 'evaluation-plan://one' }, context('terminal-benchmark'));
  await service.publishSubmission(submission.submission_id, {}, context('terminal-publish'));
  await assert.rejects(() => service.benchmarkSubmission(submission.submission_id, { evaluation_plan_ref: 'evaluation-plan://two' }, context('rebenchmark')), (error) => error.code === 'invalid_state');
  await assert.rejects(() => service.publishSubmission(submission.submission_id, {}, context('republish')), (error) => error.code === 'not_admitted');
  assert.equal((await service.listWorkers()).length, 1);
});

test('malformed owner success and tampered receipt chains fail closed', async (t) => {
  assert.throws(() => validateOwnerDecision('packages.releaseCandidate', { status: 'admitted' }), (error) => error instanceof OwnerDependencyError && error.code === 'owner_contract_invalid');
  const upstream = createServer((request, response) => { response.writeHead(200, { 'content-type': 'application/json' }); response.end('{}'); });
  await new Promise((resolve) => upstream.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => upstream.close(resolve)));
  const owners = createOwnerAdapters({ operations: { 'packages.releaseCandidate': { baseUrl: `http://127.0.0.1:${upstream.address().port}`, route: '/decision' } } });
  await assert.rejects(() => owners.packages.releaseCandidate({}, context('malformed-owner')), (error) => error instanceof OwnerDependencyError && error.code === 'owner_contract_invalid');
  const { file, service } = await fixture(t);
  await service.createDraft({ template_ref: 'worker-template://blank/v1', name: 'Chain', description: 'Chain state.', model_route_ref: 'model-route://one', harness_ref: 'harness://one', runtime_profile_ref: 'runtime-profile://one' }, context('chain'));
  const state = JSON.parse(await readFile(file, 'utf8'));
  state.receipts[0].action = 'tampered';
  await writeFile(file, `${JSON.stringify(state)}\n`, 'utf8');
  await assert.rejects(() => new JsonStore(file, seedState).init(), StateIntegrityError);
});
