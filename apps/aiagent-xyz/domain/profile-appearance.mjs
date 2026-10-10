import { DEFAULT_APPEARANCE, validateAppearance, avatarPortrait } from '../shared/avatar-catalog.mjs';
import { DomainError } from './errors.mjs';

const targets = {
  draft_ref: ['drafts', 'owner_ref'],
  registration_ref: ['registrations', 'owner_ref'],
  worker_id: ['listings', 'seller_ref'],
};
const invalid = (message) => { throw new DomainError(422, 'invalid_appearance', message); };
const sameTarget = (a, b) => a.kind === b.kind && a.ref === b.ref;

function resolveTarget(state, target, context) {
  if (!target || typeof target !== 'object' || Array.isArray(target)
    || Object.keys(target).length !== 2 || !Object.hasOwn(targets, target.kind)
    || typeof target.ref !== 'string' || !target.ref || target.ref.length > 512) invalid('Select an existing worker profile.');
  const [collection, ownerField] = targets[target.kind];
  const profile = state[collection].find((item) => item[target.kind] === target.ref
    && item.tenant_ref === context.tenantRef && item[ownerField] === context.principalRef);
  if (!profile) throw new DomainError(404, 'not_found', 'Worker profile was not found');
  return profile;
}

function findRecord(state, target, context) {
  return state.profile_appearances?.find((item) => sameTarget(item.target, target)
    && item.tenant_ref === context.tenantRef && item.owner_ref === context.principalRef);
}

function project(record, target) {
  const selected = record?.history.find((item) => item.appearance_revision === record.appearance_revision);
  const published = record?.history.find((item) => item.appearance_revision === record.public_revision);
  const appearance = validateAppearance(selected?.appearance || DEFAULT_APPEARANCE);
  return {
    target: { ...target }, revision: record?.revision || 0,
    appearance_revision: selected?.appearance_revision || 0,
    appearance: structuredClone(appearance), portrait_ref: avatarPortrait(appearance),
    public_revision: published?.appearance_revision || null,
    public_appearance: published ? validateAppearance(published.appearance) : null,
    public_portrait_ref: published ? avatarPortrait(published.appearance) : null,
    history: structuredClone(record?.history || []),
  };
}

export function readAppearance(state, target, context) {
  const profile = resolveTarget(state, target, context);
  return { ...project(findRecord(state, target, context), target), profile_name: profile.name };
}

function checkMutation(body, fields) {
  if (!body || typeof body !== 'object' || Array.isArray(body)
    || Object.keys(body).some((key) => !fields.includes(key))) invalid('Appearance request contains unsupported fields.');
  if (!Number.isSafeInteger(body.expected_revision) || body.expected_revision < 0) invalid('expected_revision must be a non-negative integer.');
}

function checkRevision(record, expected) {
  if ((record?.revision || 0) !== expected) throw new DomainError(409, 'appearance_revision_conflict',
    'This appearance changed in another session. Reload before saving.', { current_revision: record?.revision || 0 });
}

function createRecord(state, target, context) {
  const record = { target: { ...target }, tenant_ref: context.tenantRef, owner_ref: context.principalRef,
    revision: 0, appearance_revision: 0, public_revision: null, history: [] };
  (state.profile_appearances ||= []).push(record);
  return record;
}

export function saveAppearance(state, body, context) {
  checkMutation(body, ['target', 'expected_revision', 'appearance']);
  resolveTarget(state, body.target, context);
  let appearance;
  try { appearance = validateAppearance(body.appearance); } catch (error) { invalid(error.message); }
  let record = findRecord(state, body.target, context);
  checkRevision(record, body.expected_revision);
  record ||= createRecord(state, body.target, context);
  const appearance_revision = record.history.length + 1;
  record.history.push({ appearance_revision, appearance, created_at: new Date().toISOString() });
  record.appearance_revision = appearance_revision;
  record.revision++;
  return project(record, body.target);
}

export function publishAppearance(state, body, context) {
  checkMutation(body, ['target', 'expected_revision', 'appearance_revision']);
  resolveTarget(state, body.target, context);
  if (body.target.kind !== 'worker_id') invalid('Public appearance requires an existing published worker listing.');
  const listing = state.listings.find((item) => item.worker_id === body.target.ref);
  if (listing.state !== 'published') throw new DomainError(409, 'invalid_state', 'Worker listing is not published');
  const record = findRecord(state, body.target, context);
  checkRevision(record, body.expected_revision);
  if (!Number.isSafeInteger(body.appearance_revision) || !record?.history.some((item) => item.appearance_revision === body.appearance_revision)) invalid('Select a saved appearance revision.');
  record.public_revision = body.appearance_revision;
  record.revision++;
  return project(record, body.target);
}

// Lifecycle transfer copies cosmetics only. It neither creates a worker
// identity nor modifies an admitted package or benchmark result. A listing
// receives a public choice only when that exact source revision was selected.
export function transferAppearance(state, from, to, context, selectedPublicRevision) {
  resolveTarget(state, from, context);
  resolveTarget(state, to, context);
  const source = findRecord(state, from, context);
  if (selectedPublicRevision !== undefined && (!Number.isSafeInteger(selectedPublicRevision)
    || !source?.history.some((item) => item.appearance_revision === selectedPublicRevision))) invalid('Select a saved registration appearance revision for publication.');
  if (!source) return;
  const selected = source.history.find((item) => item.appearance_revision === (selectedPublicRevision ?? source.appearance_revision));
  if (!selected) return;
  const record = createRecord(state, to, context);
  record.revision = 1;
  record.appearance_revision = 1;
  record.public_revision = selectedPublicRevision === undefined ? null : 1;
  record.history.push({ appearance_revision: 1, appearance: structuredClone(selected.appearance),
    created_at: new Date().toISOString(), source: { target: { ...from }, appearance_revision: selected.appearance_revision } });
}

export function publicAppearance(state, listing) {
  const target = { kind: 'worker_id', ref: listing.worker_id };
  const record = findRecord(state, target, { tenantRef: listing.tenant_ref, principalRef: listing.seller_ref });
  const selected = record?.history.find((item) => item.appearance_revision === record.public_revision);
  const appearance = validateAppearance(selected?.appearance || DEFAULT_APPEARANCE);
  return { appearance_revision: selected?.appearance_revision || 0,
    appearance: structuredClone(appearance), portrait_ref: avatarPortrait(appearance) };
}
