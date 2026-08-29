import { randomUUID } from 'node:crypto';
import { appendReceipt, sha256, verifyReceiptChain } from './receipts.mjs';

export const seedState = {
  schema: 'aiagent-marketplace-state/v1',
  templates: [
    {
      template_ref: 'worker-template://telesupport/v1',
      name: 'Telesupport worker',
      description: 'Non-executable starter for support triage, reply drafting, escalation, and buyer-bound improvement.',
      executable: false,
      required_integration_surfaces: ['helpdesk', 'crm', 'email'],
    },
    {
      template_ref: 'worker-template://blank/v1',
      name: 'Blank typed worker',
      description: 'An empty non-executable composition with explicit contracts and authority boundaries.',
      executable: false,
      required_integration_surfaces: [],
    },
  ],
  drafts: [],
  registrations: [],
  promotions: [],
  submissions: [],
  listings: [],
  quotes: [],
  entitlements: [],
  installs: [],
  instances: [],
  receipts: [],
  events: [],
  idempotency: {},
};

/* ── listing disclosure ─────────────────────────────────────────────────
 *
 * A public listing carries a projection of the exact composition the package
 * owner admitted. Two tiers, and canon draws the line between them.
 *
 * Canon, "Listing Admission And Benchmark Metadata": every public worker
 * listing exposes "ModelRoute policy, HarnessProfile or AgentHarnessAdapter
 * ref, runtime profile, privacy posture" as DEFAULT metadata. Default is not
 * the seller's option, so these project whatever the promotion says.
 *
 * Canon, "Hire And Configure Flow": the buyer's first act is to "inspect fit,
 * benchmarks, evals, access needs, runtime options, and delivery options".
 * Access needs and the task contract are the seller's to admit, and the record
 * of that decision already exists — `disclosure_allowlist` on the promotion
 * proposal, which this domain has required, type-checked, stored and receipted
 * since the first cut, and never once read.
 */
const DEFAULT_LISTING_DISCLOSURE = ['model_route_ref', 'harness_ref', 'runtime_profile_ref', 'memory_policy'];
const ALLOWLISTABLE_DISCLOSURE = ['task_contract', 'integration_surfaces', 'authority_scopes'];
// Identity: a listing that cannot be named cannot be listed, so these are not
// disclosure decisions. They are already copied onto the listing at publication
// and are named here only so an allowlist naming them is not rejected as unknown.
const LISTING_IDENTITY_FIELDS = ['name', 'description', 'pricing'];
const KNOWN_DISCLOSURE_FIELDS = [...LISTING_IDENTITY_FIELDS, ...DEFAULT_LISTING_DISCLOSURE, ...ALLOWLISTABLE_DISCLOSURE];

// Four states per field, decided here rather than inferred by a surface:
//   disclosed   the admitted composition declares it and it may be shown
//   undeclared  it may be shown, and the composition carries no value for it
//   withheld    the publisher did not admit this field for public disclosure
// and, for the whole block, `resolved: false` — the admitted composition could
// not be reached, which is not the same as a package that declares nothing.
function projectDisclosure(state, listing) {
  const registration = state.registrations.find((item) => item.registration_ref === listing.registration_ref);
  const submission = state.submissions.find((item) => item.submission_id === listing.submission_id);
  const promotion = submission && state.promotions.find((item) => item.promotion_ref === submission.promotion_ref);
  const draft = registration && state.drafts.find((item) => item.draft_ref === registration.draft_ref);
  // The values are only the admitted ones if they are the values that were
  // hashed. A released draft is immutable, so this holds — and it is asserted
  // rather than assumed, because the whole disclosure rests on it.
  if (!draft || !promotion || draft.validation?.composition_root !== listing.composition_root) {
    return { resolved: false, reason: 'admitted_composition_not_resolvable' };
  }
  const allowlist = Array.isArray(promotion.disclosure_allowlist) ? promotion.disclosure_allowlist : [];
  const fields = {};
  for (const field of [...DEFAULT_LISTING_DISCLOSURE, ...ALLOWLISTABLE_DISCLOSURE]) {
    const admitted = DEFAULT_LISTING_DISCLOSURE.includes(field) || allowlist.includes(field);
    if (!admitted) { fields[field] = { state: 'withheld' }; continue; }
    const value = draft[field];
    if (value === undefined || value === null || value === '') { fields[field] = { state: 'undeclared' }; continue; }
    fields[field] = { state: 'disclosed', value };
  }
  return { resolved: true, composition_root: listing.composition_root, fields };
}

/* ── onboarding plan ────────────────────────────────────────────────────
 *
 * Canon, "Managed Worker Onboarding Plans": "Agent onboarding should be compiled
 * from package declarations and buyer environment state, not hardcoded as a
 * bespoke wizard per worker." Both sides of that compiler are records this
 * domain already holds — the admitted composition on one side, the instance's
 * bindings and runtime assignment on the other — so the plan is a derivation
 * and never a second spine.
 *
 * It compiles three of canon's eleven step kinds, because three are all this
 * domain has records for, and it says so rather than presenting three as the
 * whole plan. A plan that silently omitted contact channels and dry runs would
 * report a worker ready when nothing had checked the things it left out.
 */
const COMPILED_STEP_KINDS = ['connector_binding', 'authority_grant', 'runtime_selection'];
const UNCOMPILED_STEP_KINDS = {
  contact_channel_binding: 'no ContactDeliveryChannel record exists in this domain',
  model_route_selection: 'the package declares one model route and nothing selects between routes',
  harness_selection: 'the package declares one harness and nothing selects between harnesses',
  schedule_or_standing_order: 'no schedule or standing-order record exists in this domain',
  notification_policy: 'no notification policy record exists in this domain',
  dry_run: 'no dry-run record exists in this domain',
  policy_acceptance: 'no policy-acceptance record exists in this domain',
  admin_review: 'no admin-review record exists in this domain',
};

function compileOnboardingPlan(state, instance) {
  const listing = state.listings.find((item) => item.worker_id === instance.worker_id);
  const registration = listing && state.registrations.find((item) => item.registration_ref === listing.registration_ref);
  const draft = registration && state.drafts.find((item) => item.draft_ref === registration.draft_ref);
  if (!draft || draft.validation?.composition_root !== instance_composition(state, instance)) {
    return { compiled: false, reason: 'admitted_composition_not_resolvable' };
  }
  // The template is where a requirement LEVEL comes from: it declares which
  // surfaces it requires. A surface the composition names that the template
  // does not require has no declared level, and this says so rather than
  // promoting it to `required` — canon's vocabulary has four levels and a
  // compiler that picks one for the publisher is inventing their manifest.
  const template = state.templates.find((item) => item.template_ref === draft.template_ref);
  const requiredSurfaces = template?.required_integration_surfaces || [];
  const bindings = instance.integrations || [];
  const boundScopes = new Set(bindings.flatMap((binding) => binding.scope_refs || []));

  const steps = [];
  for (const surface of draft.integration_surfaces || []) {
    const binding = bindings.find((item) => item.integration_surface === surface);
    steps.push({
      step_ref: `onboarding-step://connector-binding/${encodeURIComponent(surface)}`,
      kind: 'connector_binding',
      // Canon's four levels, or null. Null is not "optional".
      requirement: requiredSurfaces.includes(surface) ? 'required' : null,
      requirement_source: requiredSurfaces.includes(surface) ? draft.template_ref : null,
      // This domain's binding states mapped onto canon's step statuses, which is
      // what a compiler is for. bound_untested is `ready` — the grant exists and
      // nothing has exercised it; only a test receipt makes it `completed`.
      status: !binding ? 'missing' : binding.state === 'ready' ? 'completed' : 'ready',
      integration_surface_ref: surface,
      authority_grant_refs: binding ? [binding.credential_ref] : [],
      test_receipt_ref: binding?.test_receipt_ref || null,
    });
  }
  for (const scope of draft.authority_scopes || []) {
    steps.push({
      step_ref: `onboarding-step://authority-grant/${encodeURIComponent(scope)}`,
      kind: 'authority_grant',
      requirement: null,
      requirement_source: null,
      status: boundScopes.has(scope) ? 'completed' : 'missing',
      authority_requirement_refs: [scope],
      authority_grant_refs: bindings.filter((item) => (item.scope_refs || []).includes(scope)).map((item) => item.credential_ref),
      test_receipt_ref: null,
    });
  }
  steps.push({
    step_ref: 'onboarding-step://runtime-selection',
    kind: 'runtime_selection',
    requirement: 'required',
    requirement_source: 'hire',
    status: instance.runtime_assignment_ref ? 'completed' : 'missing',
    runtime_assignment_ref: instance.runtime_assignment_ref || null,
    test_receipt_ref: null,
  });

  const missingRequired = steps.filter((step) => step.requirement === 'required' && step.status === 'missing');
  const undeclared = steps.filter((step) => step.requirement === null && step.status !== 'completed');
  // Fail closed, and refuse to guess. A missing required step blocks. Everything
  // completed is full. Anything left over is a step whose requirement level the
  // package never declared, and a mode compiled over that would be this domain
  // deciding how much of a worker's manifest is optional.
  const readiness = missingRequired.length
    ? { mode: 'blocked', missing_required_steps: missingRequired.map((step) => step.step_ref) }
    : steps.every((step) => step.status === 'completed')
      ? { mode: 'full', missing_required_steps: [] }
      : { mode: null, reason: 'undeclared_requirement_levels', undeclared_steps: undeclared.map((step) => step.step_ref), missing_required_steps: [] };

  return {
    compiled: true,
    worker_composition_ref: draft.validation.composition_root,
    target_instance_ref: `worker-instance://${instance.worker_instance_id}`,
    steps,
    readiness: {
      ...readiness,
      next_action_ref: steps.find((step) => step.status === 'missing')?.step_ref || null,
    },
    compiled_step_kinds: COMPILED_STEP_KINDS,
    uncompiled_step_kinds: UNCOMPILED_STEP_KINDS,
  };
}

// What the admitted composition behind an instance declares it needs. Null when
// that composition cannot be resolved, which callers treat as a refusal rather
// than as an empty declaration.
function declaredAuthority(state, instance) {
  const registration = state.registrations.find((item) => item.release_ref === instance.release_ref);
  const draft = registration && state.drafts.find((item) => item.draft_ref === registration.draft_ref);
  if (!draft || draft.validation?.composition_root !== registration.composition_root) return null;
  return {
    integration_surfaces: draft.integration_surfaces || [],
    authority_scopes: draft.authority_scopes || [],
  };
}

// The composition an instance is actually running, taken through the release it
// was installed from rather than through the listing's current contents.
const instance_composition = (state, instance) => {
  const registration = state.registrations.find((item) => item.release_ref === instance.release_ref);
  return registration?.composition_root ?? null;
};

export class DomainError extends Error {
  constructor(status, code, message, details = undefined) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

const required = (value, field) => {
  if (value === undefined || value === null || value === '') throw new DomainError(422, 'invalid_request', `${field} is required`);
  return value;
};

const owned = (items, context, principalField = 'owner_ref') => items.filter((item) => item.tenant_ref === context.tenantRef && item[principalField] === context.principalRef);
const findOwned = (items, ref, context, field, principalField = 'owner_ref') => {
  const item = items.find((candidate) => candidate[field] === ref && candidate.tenant_ref === context.tenantRef && candidate[principalField] === context.principalRef);
  if (!item) throw new DomainError(404, 'not_found', `${field} was not found`);
  return item;
};

const now = () => new Date().toISOString();
const ref = (kind) => `${kind}://${randomUUID()}`;

function idempotent(state, context, body, effect) {
  required(context.idempotencyKey, 'Idempotency-Key');
  const key = `${context.tenantRef}:${context.principalRef}:${context.idempotencyKey}`;
  const fingerprint = sha256(body);
  const prior = state.idempotency[key];
  if (prior) {
    if (prior.fingerprint !== fingerprint) throw new DomainError(409, 'idempotency_conflict', 'Idempotency key was already used with a different body');
    return prior.result;
  }
  const result = effect();
  state.idempotency[key] = { fingerprint, result };
  return result;
}

export class AiagentService {
  constructor(store, owners) {
    this.store = store;
    this.owners = owners;
  }

  async priorResult(context, body) {
    required(context.idempotencyKey, 'Idempotency-Key');
    const prior = (await this.store.read()).idempotency[`${context.tenantRef}:${context.principalRef}:${context.idempotencyKey}`];
    if (!prior) return null;
    if (prior.fingerprint !== sha256(body)) throw new DomainError(409, 'idempotency_conflict', 'Idempotency key was already used with a different body');
    return prior.result;
  }

  async status() {
    const state = await this.store.read();
    return { service: 'aiagent.xyz', storage: 'durable-json', authority_mode: this.owners.mode, revision: state.revision, receipt_chain_valid: verifyReceiptChain(state.receipts) };
  }

  async templates() {
    return (await this.store.read()).templates;
  }

  async listDrafts(context) {
    return owned((await this.store.read()).drafts, context);
  }

  async creatorState(context) {
    const state = await this.store.read();
    return {
      drafts: owned(state.drafts, context),
      registrations: owned(state.registrations, context),
      promotions: owned(state.promotions, context),
      submissions: owned(state.submissions, context),
      listings: owned(state.listings, context, 'seller_ref'),
    };
  }

  async createDraft(body, context) {
    return this.store.transact((state) => idempotent(state, context, body, () => {
      const template = state.templates.find((item) => item.template_ref === body.template_ref);
      if (!template) throw new DomainError(422, 'unknown_template', 'Select a registered starter template');
      const draft = {
        draft_ref: ref('worker-draft'),
        tenant_ref: context.tenantRef,
        owner_ref: context.principalRef,
        template_ref: template.template_ref,
        revision: 1,
        state: 'draft',
        name: required(body.name, 'name'),
        description: required(body.description, 'description'),
        // Null where nothing was declared, never a substitute for it. These are
        // the publisher's declarations about their own package, and three of
        // them used to be written by this function when the publisher said
        // nothing: a task contract of SupportTicket → SupportResolution, a
        // retention posture of buyer-bound, and a price of USD 49.00 a month.
        //
        // Every one of those then entered the composition hash, was admitted by
        // the package owner under it, and — once a listing projects the
        // composition — would be published as the publisher's own word. The
        // store this UI was designed against carries seven workers whose task
        // contract says SupportTicket because of this line, including a game
        // resource farmer and a medical billing agent.
        //
        // A missing declaration is a validation failure, not a default. Canon:
        // "task classes and typed input/output contracts" is a binding a
        // registration must carry, and `validateDraft` already refuses a draft
        // that has no task contract — a refusal this default made unreachable.
        task_contract: body.task_contract ?? null,
        model_route_ref: body.model_route_ref ?? null,
        harness_ref: body.harness_ref ?? null,
        runtime_profile_ref: body.runtime_profile_ref ?? null,
        // The one defensible default on this record: a template's required
        // surfaces are that template's own declaration, and a draft created from
        // it does require them. It is a value from a record, not one invented
        // here.
        integration_surfaces: body.integration_surfaces ?? template.required_integration_surfaces,
        authority_scopes: body.authority_scopes ?? null,
        memory_policy: body.memory_policy ?? null,
        pricing: body.pricing ?? null,
        created_at: now(),
        updated_at: now(),
      };
      state.drafts.push(draft);
      const receipt = appendReceipt(state, context, 'worker.draft.created', draft.draft_ref, { revision: draft.revision });
      return { ...draft, receipt_ref: receipt.receipt_ref };
    }));
  }

  async updateDraft(draftRef, body, context) {
    return this.store.transact((state) => idempotent(state, context, { draftRef, ...body }, () => {
      const draft = findOwned(state.drafts, draftRef, context, 'draft_ref');
      if (draft.state !== 'draft' && draft.state !== 'validated') throw new DomainError(409, 'immutable_candidate', 'A released candidate cannot be edited');
      if (Number(body.expected_revision) !== draft.revision) throw new DomainError(409, 'revision_conflict', 'Draft revision changed; reload and merge');
      for (const field of ['name', 'description', 'task_contract', 'model_route_ref', 'harness_ref', 'runtime_profile_ref', 'integration_surfaces', 'authority_scopes', 'memory_policy', 'pricing']) {
        if (body[field] !== undefined) draft[field] = body[field];
      }
      draft.revision += 1;
      draft.state = 'draft';
      delete draft.validation;
      draft.updated_at = now();
      const receipt = appendReceipt(state, context, 'worker.draft.updated', draft.draft_ref, { revision: draft.revision });
      return { ...draft, receipt_ref: receipt.receipt_ref };
    }));
  }

  async validateDraft(draftRef, body, context) {
    return this.store.transact((state) => idempotent(state, context, { draftRef, ...body }, () => {
      const draft = findOwned(state.drafts, draftRef, context, 'draft_ref');
      if (draft.state !== 'draft') throw new DomainError(409, 'invalid_state', 'Only an editable draft can be validated');
      if (Number(body.expected_revision) !== draft.revision) throw new DomainError(409, 'revision_conflict', 'Draft revision changed; reload and merge');
      const missing = ['name', 'description', 'task_contract', 'model_route_ref', 'harness_ref', 'runtime_profile_ref'].filter((field) => !draft[field]);
      if (missing.length) throw new DomainError(422, 'validation_failed', 'Draft is not eligible for packaging', { missing });
      draft.state = 'validated';
      const { validation: ignoredValidation, ...composition } = draft;
      void ignoredValidation;
      draft.validation = { passed: true, validated_revision: draft.revision, composition_root: sha256(composition), validated_at: now() };
      const receipt = appendReceipt(state, context, 'worker.draft.validated', draft.draft_ref, draft.validation);
      return { draft_ref: draft.draft_ref, ...draft.validation, receipt_ref: receipt.receipt_ref };
    }));
  }

  async releaseDraft(draftRef, body, context) {
    const payload = { draftRef, ...body };
    const prior = await this.priorResult(context, payload);
    if (prior) return prior;
    const snapshot = await this.store.read();
    const draft = findOwned(snapshot.drafts, draftRef, context, 'draft_ref');
    if (draft.state !== 'validated') throw new DomainError(409, 'not_validated', 'Validate the exact draft revision before releasing it');
    if (draft.validation?.validated_revision !== draft.revision) throw new DomainError(409, 'validation_stale', 'Validated revision no longer matches the draft');
    const decision = await this.owners.packages.releaseCandidate({
      draft_ref: draft.draft_ref,
      composition_root: draft.validation.composition_root,
      version: required(body.version, 'version'),
      sbom_ref: required(body.sbom_ref, 'sbom_ref'),
      provenance_ref: required(body.provenance_ref, 'provenance_ref'),
    }, context);
    return this.store.transact((state) => idempotent(state, context, payload, () => {
      const current = findOwned(state.drafts, draftRef, context, 'draft_ref');
      if (current.state !== 'validated' || current.revision !== draft.revision || current.validation?.composition_root !== draft.validation.composition_root) throw new DomainError(409, 'release_race', 'Draft changed during package admission');
      current.state = 'released';
      current.release_ref = decision.release_ref;
      current.release_version = body.version;
      current.owner_admission = decision;
      const receipt = appendReceipt(state, context, 'worker.package.released', current.release_ref, { draft_ref: draftRef, composition_root: current.validation.composition_root }, [decision.receipt_ref]);
      return { release_ref: current.release_ref, draft_ref: draftRef, authority_mode: decision.authority_mode, receipt_ref: receipt.receipt_ref };
    }));
  }

  async listRegistrations(context) {
    return owned((await this.store.read()).registrations, context);
  }

  async registerWorker(body, context) {
    return this.store.transact((state) => idempotent(state, context, body, () => {
      const draft = findOwned(state.drafts, required(body.draft_ref, 'draft_ref'), context, 'draft_ref');
      if (draft.state !== 'released' || !draft.release_ref) throw new DomainError(409, 'missing_release', 'Private registration requires an admitted immutable package release');
      if (state.registrations.some((item) => item.draft_ref === draft.draft_ref && item.tenant_ref === context.tenantRef)) throw new DomainError(409, 'registration_exists', 'This immutable release is already registered');
      const registration = {
        registration_ref: ref('worker-registration'), tenant_ref: context.tenantRef, owner_ref: context.principalRef,
        draft_ref: draft.draft_ref, release_ref: draft.release_ref, composition_root: draft.validation.composition_root,
        name: draft.name, visibility: body.visibility === 'organization' ? 'organization' : 'private', state: 'ready',
        goal_space_refs: body.goal_space_refs || [], created_at: now(),
      };
      state.registrations.push(registration);
      const receipt = appendReceipt(state, context, 'worker.registration.created', registration.registration_ref, { release_ref: registration.release_ref, visibility: registration.visibility });
      return { ...registration, receipt_ref: receipt.receipt_ref };
    }));
  }

  async createPromotion(registrationRef, body, context) {
    return this.store.transact((state) => idempotent(state, context, { registrationRef, ...body }, () => {
      const registration = findOwned(state.registrations, registrationRef, context, 'registration_ref');
      if (state.promotions.some((item) => item.registration_ref === registrationRef && item.tenant_ref === context.tenantRef)) throw new DomainError(409, 'promotion_exists', 'A promotion proposal already exists for this registration');
      const promotion = {
        promotion_ref: ref('worker-promotion'), registration_ref: registrationRef, tenant_ref: context.tenantRef, owner_ref: context.principalRef,
        state: 'draft', disclosure_allowlist: required(body.disclosure_allowlist, 'disclosure_allowlist'),
        license: required(body.license, 'license'), pricing: required(body.pricing, 'pricing'), created_at: now(),
      };
      if (!Array.isArray(promotion.disclosure_allowlist)) throw new DomainError(422, 'invalid_disclosure', 'disclosure_allowlist must be an array');
      // The allowlist decides what a public listing carries, so a name nothing
      // recognises is not a harmless extra: it is a disclosure the seller
      // believes they made and the projection will never make. Closed set,
      // refused at admission, with the known names in the error.
      const unknown = promotion.disclosure_allowlist.filter((field) => !KNOWN_DISCLOSURE_FIELDS.includes(field));
      if (unknown.length) throw new DomainError(422, 'invalid_disclosure', 'disclosure_allowlist names fields this listing projection cannot disclose', { unknown, known: KNOWN_DISCLOSURE_FIELDS });
      state.promotions.push(promotion);
      const receipt = appendReceipt(state, context, 'worker.promotion.created', promotion.promotion_ref, { registration_ref: registration.registration_ref });
      return { ...promotion, receipt_ref: receipt.receipt_ref };
    }));
  }

  async submitPromotion(registrationRef, promotionRef, body, context) {
    return this.store.transact((state) => idempotent(state, context, { registrationRef, promotionRef, ...body }, () => {
      findOwned(state.registrations, registrationRef, context, 'registration_ref');
      const promotion = findOwned(state.promotions, promotionRef, context, 'promotion_ref');
      if (promotion.registration_ref !== registrationRef) throw new DomainError(409, 'binding_mismatch', 'Promotion does not belong to registration');
      if (promotion.state !== 'draft') throw new DomainError(409, 'invalid_state', 'Promotion proposal is no longer editable');
      if (state.submissions.some((item) => item.promotion_ref === promotionRef && item.tenant_ref === context.tenantRef)) throw new DomainError(409, 'submission_exists', 'Promotion proposal was already submitted');
      promotion.state = 'submitted';
      const submission = {
        submission_id: randomUUID(), tenant_ref: context.tenantRef, owner_ref: context.principalRef, promotion_ref: promotionRef,
        registration_ref: registrationRef, state: 'awaiting_benchmark', composition_root: state.registrations.find((item) => item.registration_ref === registrationRef).composition_root,
        created_at: now(),
      };
      state.submissions.push(submission);
      const receipt = appendReceipt(state, context, 'worker.promotion.submitted', `submission://${submission.submission_id}`, { promotion_ref: promotionRef });
      return { ...submission, receipt_ref: receipt.receipt_ref };
    }));
  }

  async benchmarkSubmission(submissionId, body, context) {
    const payload = { submissionId, ...body };
    const prior = await this.priorResult(context, payload);
    if (prior) return prior;
    const snapshot = await this.store.read();
    const submission = findOwned(snapshot.submissions, submissionId, context, 'submission_id');
    if (submission.state !== 'awaiting_benchmark') throw new DomainError(409, 'invalid_state', 'Submission is not awaiting benchmark admission');
    const decision = await this.owners.evaluations.benchmark({ submission_id: submissionId, composition_root: submission.composition_root, evaluation_plan_ref: required(body.evaluation_plan_ref, 'evaluation_plan_ref') }, context);
    return this.store.transact((state) => idempotent(state, context, payload, () => {
      const current = findOwned(state.submissions, submissionId, context, 'submission_id');
      if (current.state !== 'awaiting_benchmark' || current.composition_root !== submission.composition_root) throw new DomainError(409, 'benchmark_race', 'Submission changed during benchmark admission');
      current.state = 'admitted';
      current.benchmark = { ...decision, evaluation_plan_ref: body.evaluation_plan_ref, composition_root: current.composition_root };
      const receipt = appendReceipt(state, context, 'worker.submission.benchmarked', `submission://${submissionId}`, current.benchmark, [decision.receipt_ref]);
      return { ...current, receipt_ref: receipt.receipt_ref };
    }));
  }

  async publishSubmission(submissionId, body, context) {
    return this.store.transact((state) => idempotent(state, context, { submissionId, ...body }, () => {
      const submission = findOwned(state.submissions, submissionId, context, 'submission_id');
      if (submission.state !== 'admitted') throw new DomainError(409, 'not_admitted', 'Benchmark and admission must complete before explicit publication');
      if (state.listings.some((item) => item.submission_id === submissionId)) throw new DomainError(409, 'listing_exists', 'Submission is already published');
      const registration = findOwned(state.registrations, submission.registration_ref, context, 'registration_ref');
      const promotion = findOwned(state.promotions, submission.promotion_ref, context, 'promotion_ref');
      const listing = {
        worker_id: randomUUID(), tenant_ref: context.tenantRef, seller_ref: context.principalRef, submission_id: submissionId,
        registration_ref: registration.registration_ref, release_ref: registration.release_ref,
        composition_root: registration.composition_root, name: registration.name,
        description: state.drafts.find((item) => item.draft_ref === registration.draft_ref).description,
        license: promotion.license, pricing: promotion.pricing, state: 'published', published_at: now(),
        benchmark: submission.benchmark,
      };
      submission.state = 'published';
      state.listings.push(listing);
      const receipt = appendReceipt(state, context, 'worker.listing.published', `worker://${listing.worker_id}`, { release_ref: listing.release_ref, composition_root: listing.composition_root });
      return { ...listing, receipt_ref: receipt.receipt_ref };
    }));
  }

  // Disclosure is projected on read rather than copied at publication. The
  // composition is immutable and a submitted promotion is no longer editable,
  // so the two agree forever; projecting keeps one source of truth instead of a
  // second copy on the listing that could drift from the record that admitted it.
  async listWorkers() {
    const state = await this.store.read();
    return state.listings.filter((item) => item.state === 'published')
      .map((listing) => ({ ...listing, disclosure: projectDisclosure(state, listing) }));
  }

  async getWorker(workerId) {
    const state = await this.store.read();
    const listing = state.listings.find((item) => item.worker_id === workerId && item.state === 'published');
    if (!listing) throw new DomainError(404, 'not_found', 'Worker listing was not found');
    return { ...listing, disclosure: projectDisclosure(state, listing) };
  }

  async quoteWorker(workerId, body, context) {
    const payload = { workerId, ...body };
    const prior = await this.priorResult(context, payload);
    if (prior) return prior;
    const listing = await this.getWorker(workerId);
    const decision = await this.owners.settlement.quote({ worker_id: workerId, release_ref: listing.release_ref, buyer_ref: context.principalRef, pricing: listing.pricing, intent: body.intent || 'hire' }, context);
    return this.store.transact((state) => idempotent(state, context, payload, () => {
      const quote = { quote_ref: ref('marketplace-quote'), worker_id: workerId, release_ref: listing.release_ref, tenant_ref: context.tenantRef, buyer_ref: context.principalRef, state: 'open', amount: listing.pricing, expires_at: new Date(Date.now() + 15 * 60_000).toISOString(), owner_decision: decision };
      state.quotes.push(quote);
      const receipt = appendReceipt(state, context, 'worker.quote.created', quote.quote_ref, { worker_id: workerId, amount: quote.amount }, [decision.receipt_ref]);
      return { ...quote, receipt_ref: receipt.receipt_ref };
    }));
  }

  // Quotes this principal holds, newest first, each with the listing it was
  // minted against.
  //
  // Expiry is derived here rather than left to a surface: a quote's stored state
  // is `open` until something consumes it, and an open quote fifteen minutes
  // past `expires_at` is not open — `hireWorker` already refuses it. A cart that
  // read `state` alone would have offered a checkout the domain would decline,
  // which is the same defect in the other direction from an absence rendered as
  // a finding.
  async listQuotes(context) {
    const state = await this.store.read();
    const now = Date.now();
    return owned(state.quotes, context, 'buyer_ref')
      .map((quote) => ({
        quote_ref: quote.quote_ref,
        worker_id: quote.worker_id,
        // Joined here rather than by a caller: a shell that resolved seven
        // quotes into seven names would read the whole catalogue on every route
        // to do it. Null when the listing is no longer published, which is a
        // different fact from a quote with no worker and renders as one.
        worker_name: state.listings.find((item) => item.worker_id === quote.worker_id && item.state === 'published')?.name ?? null,
        release_ref: quote.release_ref,
        amount: quote.amount,
        expires_at: quote.expires_at,
        // Three states, not two: the record's own, plus the one time makes true
        // of it. `expired` is a fact about a stored timestamp, never a guess.
        state: quote.state === 'open' && Date.parse(quote.expires_at) <= now ? 'expired' : quote.state,
        owner_decision_receipt_ref: quote.owner_decision?.receipt_ref || null,
      }))
      .sort((left, right) => String(right.expires_at).localeCompare(String(left.expires_at)));
  }

  async hireWorker(workerId, body, context) {
    const payload = { workerId, ...body };
    const prior = await this.priorResult(context, payload);
    if (prior) return prior;
    const snapshot = await this.store.read();
    const listing = snapshot.listings.find((item) => item.worker_id === workerId && item.state === 'published');
    if (!listing) throw new DomainError(404, 'not_found', 'Worker listing was not found');
    const quote = findOwned(snapshot.quotes, required(body.quote_ref, 'quote_ref'), context, 'quote_ref', 'buyer_ref');
    if (quote.worker_id !== workerId || quote.state !== 'open' || Date.parse(quote.expires_at) <= Date.now()) throw new DomainError(409, 'invalid_quote', 'Quote is expired, closed, or bound to another listing');

    const entitlementDecision = await this.owners.settlement.acquire({ quote_ref: quote.quote_ref, worker_id: workerId, release_ref: listing.release_ref, buyer_ref: context.principalRef }, context);
    const installDecision = await this.owners.packages.install({ release_ref: listing.release_ref, buyer_ref: context.principalRef, entitlement_receipt_ref: entitlementDecision.receipt_ref }, context);
    const runtimeDecision = await this.owners.runtime.initialize({ release_ref: listing.release_ref, runtime_profile_ref: required(body.runtime_profile_ref, 'runtime_profile_ref'), persistence_profile_ref: required(body.persistence_profile_ref, 'persistence_profile_ref'), authority_grant_refs: body.authority_grant_refs || [], transition: 'initialize' }, context);

    return this.store.transact((state) => idempotent(state, context, payload, () => {
      const currentQuote = findOwned(state.quotes, quote.quote_ref, context, 'quote_ref', 'buyer_ref');
      if (currentQuote.state !== 'open') throw new DomainError(409, 'hire_race', 'Quote was consumed while owner admissions were pending');
      currentQuote.state = 'consumed';
      const entitlement = { entitlement_ref: entitlementDecision.entitlement_ref, tenant_ref: context.tenantRef, buyer_ref: context.principalRef, worker_id: workerId, release_ref: listing.release_ref, state: 'active', quote_ref: quote.quote_ref, owner_decision: entitlementDecision };
      const install = { install_id: installDecision.install_id, tenant_ref: context.tenantRef, entitlement_ref: entitlement.entitlement_ref, release_ref: listing.release_ref, state: 'installed', owner_decision: installDecision };
      const instance = {
        worker_instance_id: randomUUID(), tenant_ref: context.tenantRef, owner_ref: context.principalRef,
        worker_id: workerId, release_ref: listing.release_ref, entitlement_ref: entitlement.entitlement_ref,
        install_id: install.install_id, desired_state: 'active', observed_state: 'unknown',
        runtime_profile_ref: body.runtime_profile_ref, persistence_profile_ref: body.persistence_profile_ref,
        runtime_assignment_ref: runtimeDecision.runtime_assignment_ref, runtime_observed_at: runtimeDecision.observed_at || null,
        readiness: 'authority_pending', integrations: [], subscription: { state: 'active', amount: listing.pricing, owner_receipt_ref: entitlementDecision.receipt_ref },
        config_revision: 1, created_at: now(), updated_at: now(),
      };
      state.entitlements.push(entitlement); state.installs.push(install); state.instances.push(instance);
      const receipt = appendReceipt(state, context, 'worker.instance.hired', `worker-instance://${instance.worker_instance_id}`, { entitlement_ref: entitlement.entitlement_ref, install_id: install.install_id, runtime_assignment_ref: instance.runtime_assignment_ref }, [entitlementDecision.receipt_ref, installDecision.receipt_ref, runtimeDecision.receipt_ref]);
      return { instance, entitlement, install, receipt_ref: receipt.receipt_ref, authority_mode: this.owners.mode };
    }));
  }

  async listInstances(context) {
    return owned((await this.store.read()).instances, context);
  }

  async getInstance(instanceId, context) {
    return findOwned((await this.store.read()).instances, instanceId, context, 'worker_instance_id');
  }

  async onboardingPlan(instanceId, context) {
    const state = await this.store.read();
    const instance = findOwned(state.instances, instanceId, context, 'worker_instance_id');
    return compileOnboardingPlan(state, instance);
  }

  async transitionInstance(instanceId, transition, body, context) {
    const payload = { instanceId, transition, ...body };
    const prior = await this.priorResult(context, payload);
    if (prior) return prior;
    const allowed = { suspend: 'suspended', resume: 'active', archive: 'archived', restore: 'active' };
    if (!allowed[transition]) throw new DomainError(422, 'invalid_transition', 'Unsupported managed-instance transition');
    const snapshot = await this.store.read();
    const instance = findOwned(snapshot.instances, instanceId, context, 'worker_instance_id');
    const sources = { suspend: ['active'], resume: ['suspended'], archive: ['active', 'suspended'], restore: ['archived'] };
    if (!sources[transition].includes(instance.desired_state)) throw new DomainError(409, 'invalid_state', `Cannot ${transition} an instance in ${instance.desired_state}`);
    const decision = await this.owners.runtime.transition({ worker_instance_id: instanceId, transition, runtime_assignment_ref: instance.runtime_assignment_ref, reason: body.reason || null }, context);
    return this.store.transact((state) => idempotent(state, context, payload, () => {
      const current = findOwned(state.instances, instanceId, context, 'worker_instance_id');
      if (!sources[transition].includes(current.desired_state)) throw new DomainError(409, 'transition_race', 'Managed instance changed while transition admission was pending');
      current.desired_state = allowed[transition];
      current.observed_state = 'unknown';
      current.updated_at = now();
      const receipt = appendReceipt(state, context, `worker.instance.${transition}.requested`, `worker-instance://${instanceId}`, { desired_state: current.desired_state }, [decision.receipt_ref]);
      return { ...current, receipt_ref: receipt.receipt_ref, owner_decision: decision };
    }));
  }

  async addIntegration(instanceId, body, context) {
    const payload = { instanceId, ...body };
    const prior = await this.priorResult(context, payload);
    if (prior) return prior;
    const snapshot = await this.store.read();
    findOwned(snapshot.instances, instanceId, context, 'worker_instance_id');
    if ('secret' in body || 'token' in body || 'password' in body) throw new DomainError(422, 'secret_custody_forbidden', 'Submit a credential_ref; marketplace state never accepts raw credentials');
    if (typeof body.credential_ref !== 'string' || !/^(credential-grant|authority-grant):\/\//.test(body.credential_ref)) throw new DomainError(422, 'credential_ref_invalid', 'credential_ref must identify an admitted credential or authority grant');
    if (!Array.isArray(body.scope_refs) || !body.scope_refs.length || body.scope_refs.some((item) => typeof item !== 'string' || !/^[A-Za-z][A-Za-z0-9._:-]+$/.test(item))) throw new DomainError(422, 'scope_refs_invalid', 'scope_refs must be a non-empty array of typed scope refs');
    // A binding may not grant authority the package never asked for, and may not
    // reach a surface the package never declared.
    //
    // Nothing checked either. The seeded deployment binds `tickets:read` and
    // `replies:draft` against a composition that declares `ticket:read`,
    // `reply:draft` and `escalation:create` — three scopes granted, none of them
    // the ones the manifest asked for, and no record anywhere said so until the
    // onboarding plan compiled the two lists side by side and every authority
    // step came out missing.
    //
    // The estate's structural law runs one way: policy narrows always, and
    // widens only through governed authority. A buyer over-granting on their own
    // instance is that law inverted, and the manifest is the ceiling.
    const declared = declaredAuthority(snapshot, findOwned(snapshot.instances, instanceId, context, 'worker_instance_id'));
    if (!declared) throw new DomainError(409, 'admitted_composition_not_resolvable', 'The composition this instance runs could not be resolved, so a binding cannot be checked against what it declares');
    const surface = required(body.integration_surface, 'integration_surface');
    if (!declared.integration_surfaces.includes(surface)) {
      throw new DomainError(422, 'surface_not_declared', 'The admitted package does not declare this integration surface', { surface, declared: declared.integration_surfaces });
    }
    const undeclaredScopes = body.scope_refs.filter((scope) => !declared.authority_scopes.includes(scope));
    if (undeclaredScopes.length) {
      throw new DomainError(422, 'scope_not_declared', 'A binding may not grant a scope the admitted package does not declare', { undeclared: undeclaredScopes, declared: declared.authority_scopes });
    }
    const request = { worker_instance_id: instanceId, integration_surface: surface, credential_ref: required(body.credential_ref, 'credential_ref'), scope_refs: required(body.scope_refs, 'scope_refs') };
    const decision = await this.owners.authority.bindIntegration(request, context);
    return this.store.transact((state) => idempotent(state, context, payload, () => {
      const instance = findOwned(state.instances, instanceId, context, 'worker_instance_id');
      const binding = { binding_id: randomUUID(), ...request, state: 'bound_untested', authority_receipt_ref: decision.receipt_ref, created_at: now() };
      instance.integrations.push(binding);
      instance.readiness = 'integration_test_pending';
      const receipt = appendReceipt(state, context, 'worker.integration.bound', `integration-binding://${binding.binding_id}`, { worker_instance_id: instanceId, integration_surface: binding.integration_surface, scope_refs: binding.scope_refs }, [decision.receipt_ref]);
      return { ...binding, receipt_ref: receipt.receipt_ref };
    }));
  }

  async testIntegration(instanceId, bindingId, body, context) {
    const payload = { instanceId, bindingId, ...body };
    const prior = await this.priorResult(context, payload);
    if (prior) return prior;
    const snapshot = await this.store.read();
    const instance = findOwned(snapshot.instances, instanceId, context, 'worker_instance_id');
    const binding = instance.integrations.find((item) => item.binding_id === bindingId);
    if (!binding) throw new DomainError(404, 'not_found', 'Integration binding was not found');
    const decision = await this.owners.authority.testIntegration({ worker_instance_id: instanceId, binding_id: bindingId, authority_receipt_ref: binding.authority_receipt_ref }, context);
    return this.store.transact((state) => idempotent(state, context, payload, () => {
      const current = findOwned(state.instances, instanceId, context, 'worker_instance_id');
      const currentBinding = current.integrations.find((item) => item.binding_id === bindingId);
      currentBinding.state = 'ready'; currentBinding.tested_at = now(); currentBinding.test_receipt_ref = decision.receipt_ref;
      current.readiness = current.integrations.every((item) => item.state === 'ready') ? 'ready' : 'integration_test_pending';
      const receipt = appendReceipt(state, context, 'worker.integration.tested', `integration-binding://${bindingId}`, { state: currentBinding.state }, [decision.receipt_ref]);
      return { ...currentBinding, receipt_ref: receipt.receipt_ref, instance_readiness: current.readiness };
    }));
  }

  async receipts(context, objectRef = null) {
    const state = await this.store.read();
    return state.receipts.filter((receipt) => receipt.tenant_ref === context.tenantRef && receipt.principal_ref === context.principalRef && (!objectRef || receipt.object_ref === objectRef));
  }
}
