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

  await assert.rejects(() => service.addIntegration(hired.instance.worker_instance_id, { integration_surface: 'helpdesk', credential_ref: 'credential-grant://wallet/1', scope_refs: ['ticket:read'], secret: 'never-store-me' }, context('secret')), (error) => error instanceof DomainError && error.code === 'secret_custody_forbidden');
  // `ticket:read`, not `tickets:read`. This test bound the plural against a
  // package that declares the singular and passed for as long as nothing
  // compared the two lists.
  const integration = await service.addIntegration(hired.instance.worker_instance_id, { integration_surface: 'helpdesk', credential_ref: 'credential-grant://wallet/1', scope_refs: ['ticket:read'] }, context('integration'));
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
  const draft = await service.createDraft({ template_ref: 'worker-template://blank/v1', name: 'Network worker', description: 'Requires real package owner.', task_contract: { input: 'Ticket', output: 'Resolution' }, model_route_ref: 'model-route://one', harness_ref: 'harness://one', runtime_profile_ref: 'runtime-profile://one' }, context('network-draft'));
  await service.validateDraft(draft.draft_ref, { expected_revision: draft.revision }, context('network-validate'));
  await assert.rejects(() => service.releaseDraft(draft.draft_ref, { version: '1.0.0', sbom_ref: 'sbom://one', provenance_ref: 'provenance://one' }, context('network-release')), OwnerDependencyError);
});

test('released drafts and published submissions are terminal and unique', async (t) => {
  const { service } = await fixture(t);
  const draft = await service.createDraft({ template_ref: 'worker-template://blank/v1', name: 'Immutable', description: 'Immutable release.', task_contract: { input: 'Ticket', output: 'Resolution' }, model_route_ref: 'model-route://one', harness_ref: 'harness://one', runtime_profile_ref: 'runtime-profile://one' }, context('terminal-draft'));
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

// Publishing a composition is the act that decides what a stranger may see of
// it. Before this, `disclosure_allowlist` was required, type-checked, stored and
// receipted by createPromotion, and read by nothing: the listing carried name,
// description, licence and price, and every other declaration in the admitted
// package — what it connects to, what authority it will hold, which model route
// and runtime profile it runs on — was unreachable from the public listing that
// a buyer decides on.
async function published(service, overrides = {}) {
  const key = overrides.key || 'disclose';
  const draft = await service.createDraft({
    template_ref: 'worker-template://blank/v1',
    name: 'Disclosure worker',
    description: 'A worker whose package declarations are the thing under test.',
    task_contract: { input: 'SupportTicket', output: 'SupportResolution' },
    model_route_ref: 'model-route://support/default',
    harness_ref: 'harness://managed-worker/v1',
    runtime_profile_ref: 'runtime-profile://zero-to-idle/v1',
    memory_policy: 'buyer-bound',
    pricing: { asset: 'USD', amount_minor: 4900, cadence: 'month' },
    ...overrides.draft,
  }, context(`${key}-draft`));
  await service.validateDraft(draft.draft_ref, { expected_revision: draft.revision }, context(`${key}-validate`));
  await service.releaseDraft(draft.draft_ref, { version: '1.0.0', sbom_ref: 'sbom://one', provenance_ref: 'provenance://one' }, context(`${key}-release`));
  const registration = await service.registerWorker({ draft_ref: draft.draft_ref }, context(`${key}-register`));
  const promotion = await service.createPromotion(registration.registration_ref, {
    disclosure_allowlist: overrides.allowlist || ['name', 'description', 'pricing', 'task_contract', 'integration_surfaces', 'authority_scopes'],
    license: 'commercial-managed',
    pricing: { asset: 'USD', amount_minor: 4900, cadence: 'month' },
  }, context(`${key}-promote`));
  const submission = await service.submitPromotion(registration.registration_ref, promotion.promotion_ref, {}, context(`${key}-submit`));
  await service.benchmarkSubmission(submission.submission_id, { evaluation_plan_ref: 'evaluation-plan://one' }, context(`${key}-benchmark`));
  return { draft, listing: await service.publishSubmission(submission.submission_id, {}, context(`${key}-publish`)) };
}

test('a public listing discloses exactly what the publisher admitted of the composition it published', async (t) => {
  const { service } = await fixture(t);
  const { listing } = await published(service, {
    draft: { integration_surfaces: ['helpdesk', 'crm'], authority_scopes: ['ticket:read', 'reply:draft'] },
  });
  const projected = await service.getWorker(listing.worker_id);
  assert.equal(projected.disclosure.resolved, true);
  // The values are the admitted ones, and the projection says which composition
  // they came out of rather than leaving that to be assumed.
  assert.equal(projected.disclosure.composition_root, listing.composition_root);
  assert.deepEqual(projected.disclosure.fields.integration_surfaces, { state: 'disclosed', value: ['helpdesk', 'crm'] });
  assert.deepEqual(projected.disclosure.fields.authority_scopes, { state: 'disclosed', value: ['ticket:read', 'reply:draft'] });
  // Canon, "Listing Admission And Benchmark Metadata": ModelRoute policy,
  // harness ref, runtime profile and privacy posture are DEFAULT metadata on
  // every public listing, so they do not wait for a seller to allowlist them.
  assert.deepEqual(projected.disclosure.fields.model_route_ref, { state: 'disclosed', value: 'model-route://support/default' });
  assert.deepEqual(projected.disclosure.fields.memory_policy, { state: 'disclosed', value: 'buyer-bound' });
  // The catalogue read carries the same projection as the detail read; a buyer
  // filtering a list and a buyer reading one listing see one answer.
  const listed = (await service.listWorkers()).find((item) => item.worker_id === listing.worker_id);
  assert.deepEqual(listed.disclosure, projected.disclosure);
  // And nothing leaks past the closed set: the composition also carries the
  // owner principal, the tenant, the validation block and its revision.
  const disclosed = Object.keys(projected.disclosure.fields);
  assert.deepEqual(disclosed.filter((field) => ['owner_ref', 'tenant_ref', 'validation', 'revision', 'draft_ref'].includes(field)), []);
});

test('a field the publisher did not admit is withheld, and a field the package never declared is undeclared', async (t) => {
  const { service } = await fixture(t);
  const { listing } = await published(service, {
    key: 'narrow',
    allowlist: ['name', 'description', 'pricing', 'integration_surfaces'],
    draft: { integration_surfaces: [], authority_scopes: ['ticket:read'] },
  });
  const { disclosure } = await service.getWorker(listing.worker_id);
  // Three different facts, three different words. "The publisher declined to
  // show this" is not "the package declares none", and neither is "there is no
  // owner for this" — which is what the surface said about all three.
  assert.deepEqual(disclosure.fields.authority_scopes, { state: 'withheld' });
  assert.deepEqual(disclosure.fields.task_contract, { state: 'withheld' });
  assert.deepEqual(disclosure.fields.integration_surfaces, { state: 'disclosed', value: [] });
  const bare = await published(service, { key: 'bare', draft: { integration_surfaces: undefined, authority_scopes: undefined } });
  const declared = await service.getWorker(bare.listing.worker_id);
  assert.deepEqual(declared.disclosure.fields.authority_scopes, { state: 'undeclared' });
});

test('a principal reads the quotes they hold, with expiry as a state rather than a timestamp to interpret', async (t) => {
  const { service } = await fixture(t);
  const { listing } = await published(service, { key: 'quotes' });
  const buyer = context('quote-read', 'tenant://buyer/acme', 'principal://buyer/alex');
  assert.deepEqual(await service.listQuotes(buyer), []);

  const quote = await service.quoteWorker(listing.worker_id, { intent: 'hire' }, context('mint-quote'));
  const [held] = await service.listQuotes(buyer);
  assert.equal(held.quote_ref, quote.quote_ref);
  assert.equal(held.state, 'open');
  assert.equal(held.worker_id, listing.worker_id);
  assert.deepEqual(held.amount, listing.pricing);
  assert.equal(held.worker_name, listing.name);
  // The settlement owner's decision receipt travels with the quote: a cart that
  // shows a price with no receipt behind it is showing a number this domain
  // minted for itself.
  assert.match(held.owner_decision_receipt_ref, /^receipt:\/\//);
  // And nothing else does: a quote carries the buyer principal and the owner's
  // whole decision envelope, neither of which belongs in a cart projection.
  assert.deepEqual(Object.keys(held).filter((key) => ['buyer_ref', 'tenant_ref', 'owner_decision'].includes(key)), []);

  // Another principal in the same tenant holds none of them.
  assert.deepEqual(await service.listQuotes(context('peer-quote', 'tenant://buyer/acme', 'principal://buyer/peer')), []);

  // Consuming it moves it out of the open set without deleting it.
  await service.hireWorker(listing.worker_id, {
    quote_ref: quote.quote_ref, runtime_profile_ref: 'runtime-profile://zero-to-idle/v1',
    persistence_profile_ref: 'storage-profile://encrypted/v1', authority_grant_refs: [],
  }, context('quote-hire'));
  assert.equal((await service.listQuotes(buyer))[0].state, 'consumed');
});

test('an open quote past its expiry reads as expired, because the hire path already refuses it', async (t) => {
  const { file, service } = await fixture(t);
  const { listing } = await published(service, { key: 'expiry' });
  const quote = await service.quoteWorker(listing.worker_id, { intent: 'hire' }, context('expiring-quote'));
  const state = JSON.parse(await readFile(file, 'utf8'));
  state.quotes.find((item) => item.quote_ref === quote.quote_ref).expires_at = new Date(Date.now() - 60_000).toISOString();
  await writeFile(file, `${JSON.stringify(state)}\n`, 'utf8');
  const reopened = new AiagentService(await new JsonStore(file, seedState).init(), createOwnerAdapters({ developmentAuthority: true }));
  const [held] = await reopened.listQuotes(context('expired-read', 'tenant://buyer/acme', 'principal://buyer/alex'));
  // The stored record still says `open`. A surface reading that field alone
  // would offer a checkout the domain declines.
  assert.equal(held.state, 'expired');
  await assert.rejects(
    () => reopened.hireWorker(listing.worker_id, { quote_ref: quote.quote_ref, runtime_profile_ref: 'runtime-profile://one', persistence_profile_ref: 'storage-profile://one' }, context('expired-hire')),
    (error) => error instanceof DomainError && error.code === 'invalid_quote',
  );
});

test('the onboarding plan is compiled from the package and the buyer environment, and says which kinds it cannot compile', async (t) => {
  const { service } = await fixture(t);
  // A telesupport template declares three required surfaces; the composition
  // adds a fourth the template does not require, which is the case that
  // separates a declared requirement level from an absent one.
  const draft = await service.createDraft({
    template_ref: 'worker-template://telesupport/v1', name: 'Plan worker', description: 'Onboarding plan compiler.',
    task_contract: { input: 'SupportTicket', output: 'SupportResolution' }, model_route_ref: 'model-route://one',
    harness_ref: 'harness://one', runtime_profile_ref: 'runtime-profile://one',
    integration_surfaces: ['helpdesk', 'crm', 'email', 'storage'],
    authority_scopes: ['ticket:read', 'reply:draft'],
    pricing: { asset: 'USD', amount_minor: 1000, cadence: 'month' },
  }, context('plan-draft'));
  await service.validateDraft(draft.draft_ref, { expected_revision: draft.revision }, context('plan-validate'));
  await service.releaseDraft(draft.draft_ref, { version: '1.0.0', sbom_ref: 'sbom://one', provenance_ref: 'provenance://one' }, context('plan-release'));
  const registration = await service.registerWorker({ draft_ref: draft.draft_ref }, context('plan-register'));
  const promotion = await service.createPromotion(registration.registration_ref, { disclosure_allowlist: ['name'], license: 'commercial', pricing: { asset: 'USD', amount_minor: 1000 } }, context('plan-promote'));
  const submission = await service.submitPromotion(registration.registration_ref, promotion.promotion_ref, {}, context('plan-submit'));
  await service.benchmarkSubmission(submission.submission_id, { evaluation_plan_ref: 'evaluation-plan://one' }, context('plan-benchmark'));
  const listing = await service.publishSubmission(submission.submission_id, {}, context('plan-publish'));
  const quote = await service.quoteWorker(listing.worker_id, {}, context('plan-quote'));
  const hired = await service.hireWorker(listing.worker_id, {
    quote_ref: quote.quote_ref, runtime_profile_ref: 'runtime-profile://one',
    persistence_profile_ref: 'storage-profile://one', authority_grant_refs: [],
  }, context('plan-hire'));
  const instanceId = hired.instance.worker_instance_id;

  const fresh = await service.onboardingPlan(instanceId, context('plan-read'));
  assert.equal(fresh.compiled, true);
  const step = (ref) => fresh.steps.find((item) => item.step_ref === ref);
  // Four declared surfaces, four connector steps, all missing: nothing is bound.
  assert.equal(fresh.steps.filter((item) => item.kind === 'connector_binding').length, 4);
  assert.equal(step('onboarding-step://connector-binding/helpdesk').requirement, 'required');
  assert.equal(step('onboarding-step://connector-binding/helpdesk').requirement_source, 'worker-template://telesupport/v1');
  // The template does not require `storage`, so its level is absent — not
  // optional, which is a different declaration nobody made.
  assert.equal(step('onboarding-step://connector-binding/storage').requirement, null);
  assert.equal(step('onboarding-step://connector-binding/storage').status, 'missing');
  // The runtime was selected at hire and admitted by the runtime owner.
  assert.equal(step('onboarding-step://runtime-selection').status, 'completed');
  // A required step is missing, so the plan blocks. Fail closed.
  assert.equal(fresh.readiness.mode, 'blocked');
  assert.equal(fresh.readiness.missing_required_steps.length, 3);
  assert.equal(fresh.readiness.next_action_ref, 'onboarding-step://connector-binding/helpdesk');
  // Three of canon's eleven step kinds are compiled, and the other eight are
  // named with the reason. A plan that omitted them silently would report a
  // worker ready when nothing had checked what it left out.
  assert.deepEqual(fresh.compiled_step_kinds, ['connector_binding', 'authority_grant', 'runtime_selection']);
  assert.ok(fresh.uncompiled_step_kinds.contact_channel_binding);
  assert.equal(Object.keys(fresh.uncompiled_step_kinds).length, 8);

  // Binding one surface moves exactly one step, and only to `ready` — a grant
  // that nothing has exercised is not a completed step.
  const binding = await service.addIntegration(instanceId, { integration_surface: 'helpdesk', credential_ref: 'credential-grant://wallet/1', scope_refs: ['ticket:read'] }, context('plan-bind'));
  const bound = await service.onboardingPlan(instanceId, context('plan-read-2'));
  const boundStep = bound.steps.find((item) => item.step_ref === 'onboarding-step://connector-binding/helpdesk');
  assert.equal(boundStep.status, 'ready');
  assert.deepEqual(boundStep.authority_grant_refs, ['credential-grant://wallet/1']);
  // The scope carried by that binding is a completed authority step; the one it
  // did not carry is still missing.
  assert.equal(bound.steps.find((item) => item.step_ref === 'onboarding-step://authority-grant/ticket%3Aread').status, 'completed');
  assert.equal(bound.steps.find((item) => item.step_ref === 'onboarding-step://authority-grant/reply%3Adraft').status, 'missing');
  assert.equal(bound.readiness.mode, 'blocked');

  await service.testIntegration(instanceId, binding.binding_id, {}, context('plan-test'));
  const tested = await service.onboardingPlan(instanceId, context('plan-read-3'));
  const testedStep = tested.steps.find((item) => item.step_ref === 'onboarding-step://connector-binding/helpdesk');
  assert.equal(testedStep.status, 'completed');
  assert.match(testedStep.test_receipt_ref, /^receipt:\/\//);

  // Another principal cannot read this plan at all.
  await assert.rejects(
    () => service.onboardingPlan(instanceId, context('plan-peer', 'tenant://buyer/acme', 'principal://buyer/peer')),
    (error) => error instanceof DomainError && error.code === 'not_found',
  );
});

test('a plan compiles no readiness mode when the package declares no requirement level, rather than guessing one', async (t) => {
  const { service } = await fixture(t);
  // The blank template requires nothing, so every surface this composition
  // declares has an absent requirement level.
  const { listing } = await published(service, {
    key: 'levels',
    draft: { integration_surfaces: ['storage'], authority_scopes: [] },
  });
  const quote = await service.quoteWorker(listing.worker_id, {}, context('levels-quote'));
  const hired = await service.hireWorker(listing.worker_id, {
    quote_ref: quote.quote_ref, runtime_profile_ref: 'runtime-profile://one',
    persistence_profile_ref: 'storage-profile://one',
  }, context('levels-hire'));
  const plan = await service.onboardingPlan(hired.instance.worker_instance_id, context('levels-read'));
  // Nothing required is missing, and not everything is done. The honest answer
  // is that no mode can be compiled, with the reason and the steps that caused
  // it — not `degraded`, which would be this domain deciding how much of a
  // publisher's manifest is optional.
  assert.equal(plan.readiness.mode, null);
  assert.equal(plan.readiness.reason, 'undeclared_requirement_levels');
  assert.deepEqual(plan.readiness.undeclared_steps, ['onboarding-step://connector-binding/storage']);
  assert.deepEqual(plan.readiness.missing_required_steps, []);
});

test('a binding may not grant authority the admitted package never asked for', async (t) => {
  const { service } = await fixture(t);
  const { listing } = await published(service, {
    key: 'least',
    draft: { integration_surfaces: ['helpdesk'], authority_scopes: ['ticket:read', 'reply:draft'] },
  });
  const quote = await service.quoteWorker(listing.worker_id, {}, context('least-quote'));
  const hired = await service.hireWorker(listing.worker_id, {
    quote_ref: quote.quote_ref, runtime_profile_ref: 'runtime-profile://one', persistence_profile_ref: 'storage-profile://one',
  }, context('least-hire'));
  const instanceId = hired.instance.worker_instance_id;

  // A scope one character off the declared one is not the declared one, and this
  // is exactly how it went unnoticed: the seed bound `tickets:read` against a
  // package that asks for `ticket:read`.
  await assert.rejects(
    () => service.addIntegration(instanceId, { integration_surface: 'helpdesk', credential_ref: 'credential-grant://wallet/1', scope_refs: ['tickets:read'] }, context('typo-scope')),
    (error) => error instanceof DomainError && error.code === 'scope_not_declared' && error.details.undeclared.includes('tickets:read'),
  );
  // A scope the package never mentions, granted alongside two it does.
  await assert.rejects(
    () => service.addIntegration(instanceId, { integration_surface: 'helpdesk', credential_ref: 'credential-grant://wallet/1', scope_refs: ['ticket:read', 'reply:draft', 'billing:write'] }, context('extra-scope')),
    (error) => error instanceof DomainError && error.code === 'scope_not_declared' && error.details.undeclared.length === 1,
  );
  // A surface the package never declared.
  await assert.rejects(
    () => service.addIntegration(instanceId, { integration_surface: 'crm', credential_ref: 'credential-grant://wallet/1', scope_refs: ['ticket:read'] }, context('extra-surface')),
    (error) => error instanceof DomainError && error.code === 'surface_not_declared' && error.details.declared.includes('helpdesk'),
  );
  // A subset of what the package declares is the whole point: least privilege is
  // allowed, more privilege is not.
  const bound = await service.addIntegration(instanceId, { integration_surface: 'helpdesk', credential_ref: 'credential-grant://wallet/1', scope_refs: ['ticket:read'] }, context('declared-scope'));
  assert.deepEqual(bound.scope_refs, ['ticket:read']);
});

test('a binding is refused when the composition it would be checked against cannot be resolved', async (t) => {
  const { file, service } = await fixture(t);
  const { listing } = await published(service, { key: 'unresolvable', draft: { integration_surfaces: ['helpdesk'], authority_scopes: ['ticket:read'] } });
  const quote = await service.quoteWorker(listing.worker_id, {}, context('unresolvable-quote'));
  const hired = await service.hireWorker(listing.worker_id, {
    quote_ref: quote.quote_ref, runtime_profile_ref: 'runtime-profile://one', persistence_profile_ref: 'storage-profile://one',
  }, context('unresolvable-hire'));
  const state = JSON.parse(await readFile(file, 'utf8'));
  const registration = state.registrations.find((item) => item.release_ref === hired.instance.release_ref);
  state.drafts.find((item) => item.draft_ref === registration.draft_ref).validation.composition_root = 'sha256:not-the-admitted-one';
  await writeFile(file, `${JSON.stringify(state)}\n`, 'utf8');
  const drifted = new AiagentService(await new JsonStore(file, seedState).init(), createOwnerAdapters({ developmentAuthority: true }));
  // Fail closed: an unknown ceiling is not an absent one.
  await assert.rejects(
    () => drifted.addIntegration(hired.instance.worker_instance_id, { integration_surface: 'helpdesk', credential_ref: 'credential-grant://wallet/1', scope_refs: ['ticket:read'] }, context('unresolvable-bind')),
    (error) => error instanceof DomainError && error.code === 'admitted_composition_not_resolvable',
  );
});

test('a disclosure allowlist naming a field the projection cannot disclose is refused at admission', async (t) => {
  const { service } = await fixture(t);
  const draft = await service.createDraft({ template_ref: 'worker-template://blank/v1', name: 'Unknown field', description: 'Allowlist admission.', task_contract: { input: 'Ticket', output: 'Resolution' }, model_route_ref: 'model-route://one', harness_ref: 'harness://one', runtime_profile_ref: 'runtime-profile://one' }, context('unknown-draft'));
  await service.validateDraft(draft.draft_ref, { expected_revision: draft.revision }, context('unknown-validate'));
  await service.releaseDraft(draft.draft_ref, { version: '1.0.0', sbom_ref: 'sbom://one', provenance_ref: 'provenance://one' }, context('unknown-release'));
  const registration = await service.registerWorker({ draft_ref: draft.draft_ref }, context('unknown-register'));
  await assert.rejects(
    () => service.createPromotion(registration.registration_ref, { disclosure_allowlist: ['name', 'owner_ref'], license: 'commercial', pricing: { asset: 'USD', amount_minor: 1 } }, context('unknown-promote')),
    (error) => error instanceof DomainError && error.code === 'invalid_disclosure' && error.details.unknown.includes('owner_ref'),
  );
});

test('disclosure is refused when the admitted composition cannot be reached', async (t) => {
  const { file, service } = await fixture(t);
  const { listing } = await published(service, { key: 'drift' });
  // A listing whose composition root no longer matches the draft it names is not
  // a listing that declares nothing — it is one whose declarations cannot be
  // shown to be the ones that were admitted, and it says so.
  const state = JSON.parse(await readFile(file, 'utf8'));
  const registration = state.registrations.find((item) => item.registration_ref === listing.registration_ref);
  state.drafts.find((item) => item.draft_ref === registration.draft_ref).validation.composition_root = 'sha256:not-the-admitted-one';
  await writeFile(file, `${JSON.stringify(state)}\n`, 'utf8');
  const drifted = new AiagentService(await new JsonStore(file, seedState).init(), createOwnerAdapters({ developmentAuthority: true }));
  const { disclosure } = await drifted.getWorker(listing.worker_id);
  assert.equal(disclosure.resolved, false);
  assert.equal(disclosure.reason, 'admitted_composition_not_resolvable');
  assert.equal(disclosure.fields, undefined);
});

test('a declaration the publisher did not make is never written on their behalf', async (t) => {
  const { service } = await fixture(t);
  const draft = await service.createDraft({
    template_ref: 'worker-template://blank/v1', name: 'Silent', description: 'Declares nothing beyond identity.',
  }, context('silent-draft'));
  // Three fields this function used to fill in: a task contract, a retention
  // posture, and a price. Each would have gone into the composition hash, been
  // admitted under it, and been published as the publisher's own word.
  assert.equal(draft.task_contract, null);
  assert.equal(draft.memory_policy, null);
  assert.equal(draft.pricing, null);
  assert.equal(draft.authority_scopes, null);
  // And the refusal the task-contract default had made unreachable now fires.
  await assert.rejects(
    () => service.validateDraft(draft.draft_ref, { expected_revision: draft.revision }, context('silent-validate')),
    (error) => error instanceof DomainError && error.code === 'validation_failed' && error.details.missing.includes('task_contract'),
  );
  // A template's required surfaces are that template's own declaration, so they
  // are a value from a record rather than one invented here.
  const fromTemplate = await service.createDraft({
    template_ref: 'worker-template://telesupport/v1', name: 'From template', description: 'Inherits the template requirement.',
  }, context('template-draft'));
  assert.deepEqual(fromTemplate.integration_surfaces, ['helpdesk', 'crm', 'email']);
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
