import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { AiagentService, seedState } from '../domain/service.mjs';
import { JsonStore } from '../domain/store.mjs';
import { createOwnerAdapters } from '../domain/adapters.mjs';
import { AVATAR_BODIES, DEFAULT_APPEARANCE, avatarPortrait } from '../shared/avatar-catalog.mjs';

const context = (id, tenant = 'tenant://one', principal = 'principal://one') => ({ idempotencyKey: id, tenantRef: tenant, principalRef: principal });
const appearance = (id, palette = 'original') => {
  const body = AVATAR_BODIES.find((item) => item.id === id);
  return { ...DEFAULT_APPEARANCE, body: id, asset_revision: body.revision, finish: body.finishes[0].id, palette };
};
async function fixture(t) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'aiagent-appearance-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const store = await new JsonStore(path.join(directory, 'state.json'), seedState).init();
  const owners = createOwnerAdapters({ developmentAuthority: true });
  const service = new AiagentService(store, owners);
  let sequence = 0;
  const draft = async () => service.createDraft({ template_ref: 'worker-template://blank/v1', name: 'Appearance worker',
    description: 'A worker with independently editable cosmetics.', task_contract: { input: 'Input', output: 'Output' },
    model_route_ref: 'model-route://one', harness_ref: 'harness://one', runtime_profile_ref: 'runtime-profile://one',
  }, context(`draft-${sequence++}`));
  const register = async (item) => {
    const key = sequence++;
    await service.validateDraft(item.draft_ref, { expected_revision: item.revision }, context(`validate-${key}`));
    await service.releaseDraft(item.draft_ref, { version: '1.0.0', sbom_ref: 'sbom://one', provenance_ref: 'provenance://one' }, context(`release-${key}`));
    return service.registerWorker({ draft_ref: item.draft_ref }, context(`register-${key}`));
  };
  const publish = async (registration, body = {}) => {
    const key = sequence++;
    const promotion = await service.createPromotion(registration.registration_ref, { disclosure_allowlist: ['name'], license: 'commercial', pricing: { asset: 'USD', amount_minor: 100 } }, context(`promotion-${key}`));
    const submission = await service.submitPromotion(registration.registration_ref, promotion.promotion_ref, {}, context(`submit-${key}`));
    await service.benchmarkSubmission(submission.submission_id, { evaluation_plan_ref: 'evaluation-plan://one' }, context(`benchmark-${key}`));
    return service.publishSubmission(submission.submission_id, body, context(`publish-${key}`));
  };
  return { service, store, owners, draft, register, publish };
}

test('appearances bind existing owned profiles, persist independently, and never create identities', async (t) => {
  const { service, store, owners, draft } = await fixture(t);
  const first = await draft(), second = await draft();
  const target = { kind: 'draft_ref', ref: first.draft_ref };
  const other = { kind: 'draft_ref', ref: second.draft_ref };
  const initial = await service.getProfileAppearance(target, context('read'));
  assert.equal(initial.revision, 0);
  assert.equal((await store.read()).profile_appearances.length, 0);
  const body = { target, expected_revision: 0, appearance: { ...appearance('human'), parts: { ...DEFAULT_APPEARANCE.parts, hair: 'shaved-v1', face: 'warm-v1' } } };
  const saved = await service.saveProfileAppearance(body, context('save-first'));
  assert.deepEqual(await service.saveProfileAppearance(body, context('save-first')), saved);
  await service.saveProfileAppearance({ target: other, expected_revision: 0, appearance: appearance('anime', 'ocean') }, context('save-second'));
  const restarted = new AiagentService(await new JsonStore(store.filePath, seedState).init(), owners);
  assert.equal((await restarted.getProfileAppearance(target, context('read'))).appearance.body, 'human');
  assert.equal((await restarted.getProfileAppearance(target, context('read'))).appearance.parts.hair, 'shaved-v1');
  assert.equal((await restarted.getProfileAppearance(other, context('read'))).appearance.palette, 'ocean');
  const state = await store.read();
  assert.equal(state.drafts.length, 2);
  assert.equal(state.registrations.length, 0);
  assert.equal(state.listings.length, 0);
  assert.equal(state.drafts[0].revision, first.revision);
  assert.equal(saved.portrait_ref, avatarPortrait(saved.appearance));
  for (const identity of [context('peer', 'tenant://one', 'principal://two'), context('tenant', 'tenant://two')]) {
    await assert.rejects(service.getProfileAppearance(target, identity), { code: 'not_found' });
    await assert.rejects(service.saveProfileAppearance({ ...body, expected_revision: 1 }, identity), { code: 'not_found' });
  }
  await assert.rejects(service.saveProfileAppearance({ ...body, target: { kind: 'worker_id', ref: 'invented' } }, context('invented')), { code: 'not_found' });
  await assert.rejects(service.saveProfileAppearance({ ...body, target: { kind: 'account', ref: first.owner_ref } }, context('account')), { code: 'invalid_appearance' });
  await assert.rejects(service.saveProfileAppearance({ ...body, appearance: { ...body.appearance, asset_url: 'https://example.invalid/model.glb' } }, context('injected')), { code: 'invalid_appearance' });
  await assert.rejects(service.saveProfileAppearance({ ...body, appearance: { ...body.appearance, finish: 'etched' } }, context('incompatible')), { code: 'invalid_appearance' });
  for (const parts of [{ hair: 'headset-v1' }, { face: 'https://example.invalid/head.glb' }, { uploaded_model: 'custom.glb' }]) {
    await assert.rejects(service.saveProfileAppearance({ ...body, appearance: { ...body.appearance, parts } }, context(JSON.stringify(parts))), { code: 'invalid_appearance' });
  }
  await assert.rejects(service.saveProfileAppearance({ ...body, appearance: { ...body.appearance, palette: 'ocean', parts: { outerwear: 'pinstripe-v1' } } }, context('unsupported-fabric-palette')), { code: 'invalid_appearance' });
});

test('private revisions transfer through registration without leaking into the public listing', async (t) => {
  const { service, store, draft, register, publish } = await fixture(t);
  const item = await draft();
  const target = { kind: 'draft_ref', ref: item.draft_ref };
  await service.saveProfileAppearance({ target, expected_revision: 0, appearance: appearance('anime') }, context('draft-appearance'));
  const registration = await register(item);
  const registrationTarget = { kind: 'registration_ref', ref: registration.registration_ref };
  const inherited = await service.getProfileAppearance(registrationTarget, context('read'));
  assert.equal(inherited.appearance.body, 'anime');
  assert.deepEqual(inherited.history[0].source, { target, appearance_revision: 1 });
  await assert.rejects(service.publishProfileAppearance({ target: registrationTarget, expected_revision: 1, appearance_revision: 1 }, context('premature')), { code: 'invalid_appearance' });
  const listing = await publish(registration);
  const workerTarget = { kind: 'worker_id', ref: listing.worker_id };
  const privateWorker = await service.getProfileAppearance(workerTarget, context('read'));
  assert.equal(privateWorker.appearance.body, 'anime');
  assert.equal(privateWorker.public_revision, null);
  assert.equal((await service.getWorker(listing.worker_id)).avatar.appearance.body, 'robot');
  assert.equal((await service.getWorker(listing.worker_id)).avatar.history, undefined);
  const before = await store.read();
  const publicOne = await service.publishProfileAppearance({ target: workerTarget, expected_revision: 1, appearance_revision: 1 }, context('public-one'));
  assert.equal(publicOne.revision, 2);
  assert.equal((await service.getWorker(listing.worker_id)).avatar.appearance.body, 'anime');
  const privateTwo = await service.saveProfileAppearance({ target: workerTarget, expected_revision: 2, appearance: appearance('human', 'ember') }, context('private-two'));
  assert.equal(privateTwo.appearance_revision, 2);
  assert.equal(privateTwo.public_revision, 1);
  assert.equal((await service.listWorkers())[0].avatar.appearance.body, 'anime');
  await assert.rejects(service.publishProfileAppearance({ target: workerTarget, expected_revision: 2, appearance_revision: 2 }, context('stale-publish')), { code: 'appearance_revision_conflict' });
  await service.publishProfileAppearance({ target: workerTarget, expected_revision: 3, appearance_revision: 2 }, context('public-two'));
  const publicTwo = (await service.getWorker(listing.worker_id)).avatar;
  assert.equal(publicTwo.appearance.palette, 'ember');
  assert.equal(publicTwo.appearance_revision, 2);
  const after = await store.read();
  for (const collection of ['drafts', 'registrations', 'promotions', 'submissions', 'listings']) assert.deepEqual(after[collection], before[collection]);
  assert.equal((await service.status()).receipt_chain_valid, true);
});

test('publication selects an exact registration revision and concurrent saves reject stale writers', async (t) => {
  const { service, draft, register, publish } = await fixture(t);
  const registration = await register(await draft());
  const target = { kind: 'registration_ref', ref: registration.registration_ref };
  const first = { target, expected_revision: 0, appearance: appearance('human') };
  const second = { target, expected_revision: 0, appearance: appearance('anime') };
  const raced = await Promise.allSettled([service.saveProfileAppearance(first, context('race-one')), service.saveProfileAppearance(second, context('race-two'))]);
  assert.equal(raced.filter((result) => result.status === 'fulfilled').length, 1);
  assert.equal(raced.find((result) => result.status === 'rejected').reason.code, 'appearance_revision_conflict');
  const selected = await service.getProfileAppearance(target, context('read'));
  await service.saveProfileAppearance({ target, expected_revision: 1, appearance: appearance('robot', 'ink') }, context('later-private'));
  const listing = await publish(registration, { appearance_revision: selected.appearance_revision });
  assert.deepEqual(listing.avatar.appearance, selected.appearance);
  assert.equal((await service.getProfileAppearance(target, context('read'))).appearance.body, 'robot');
  await assert.rejects(service.saveProfileAppearance({ target, expected_revision: 2, appearance: appearance('anime') }, context('later-private')), { code: 'idempotency_conflict' });
  await assert.rejects(service.publishProfileAppearance({ target, expected_revision: 2, appearance_revision: 1 }, context('later-private')), { code: 'idempotency_conflict' });
});

test('a target kind must be a string: coerced kinds are refused and cannot bypass the revision check', async (t) => {
  const { service, store, draft } = await fixture(t);
  const item = await draft();
  const coerced = [['draft_ref'], { toString: () => 'draft_ref' }];
  for (const [index, kind] of coerced.entries()) {
    await assert.rejects(() => service.saveProfileAppearance({ target: { kind, ref: item.draft_ref }, expected_revision: 0, appearance: appearance('human') }, context(`coerced-${index}`)),
      (error) => error.status === 422 && error.code === 'invalid_appearance');
  }
  assert.equal((await store.read()).profile_appearances?.length || 0, 0);
  const target = { kind: 'draft_ref', ref: item.draft_ref };
  await service.saveProfileAppearance({ target, expected_revision: 0, appearance: appearance('human') }, context('first-write'));
  await assert.rejects(() => service.saveProfileAppearance({ target, expected_revision: 0, appearance: appearance('anime') }, context('stale-write')),
    (error) => error.status === 409 && error.code === 'appearance_revision_conflict');
});

test('explicit nulls in an appearance are refused, while omitted optional fields still default', async (t) => {
  const { service, draft } = await fixture(t);
  const item = await draft();
  const target = { kind: 'draft_ref', ref: item.draft_ref };
  await assert.rejects(() => service.saveProfileAppearance({ target, expected_revision: 0, appearance: { ...appearance('human'), proportion: null } }, context('null-proportion')),
    (error) => error.status === 422 && error.code === 'invalid_appearance');
  await assert.rejects(() => service.saveProfileAppearance({ target, expected_revision: 0, appearance: { ...appearance('human'), parts: { hair: null } } }, context('null-part')),
    (error) => error.status === 422 && error.code === 'invalid_appearance');
  const { proportion: _proportion, parts: _parts, ...omitted } = appearance('human');
  const saved = await service.saveProfileAppearance({ target, expected_revision: 0, appearance: omitted }, context('omitted'));
  assert.equal(saved.appearance.proportion, 'balanced');
  assert.equal(saved.appearance.parts.hair, DEFAULT_APPEARANCE.parts.hair);
});
