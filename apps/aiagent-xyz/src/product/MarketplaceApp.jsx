import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, NavLink, Route, Routes, useNavigate, useParams } from 'react-router-dom';
import { api } from './api';

const cx = (...values) => values.filter(Boolean).join(' ');

function useLoad(loader, deps = []) {
  const [state, setState] = useState({ loading: true, value: null, error: null });
  const reload = useCallback(async () => {
    setState((current) => ({ ...current, loading: true, error: null }));
    try { setState({ loading: false, value: await loader(), error: null }); }
    catch (error) { setState({ loading: false, value: null, error }); }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  useEffect(() => { reload(); }, [reload]);
  return { ...state, reload };
}

const button = 'inline-flex min-h-10 items-center justify-center rounded-lg px-4 py-2 text-sm font-bold transition disabled:cursor-not-allowed disabled:opacity-45';
const primary = `${button} bg-slate-950 text-white hover:bg-blue-700`;
const secondary = `${button} border border-slate-300 bg-white text-slate-800 hover:border-slate-500`;
const input = 'w-full rounded-lg border border-slate-300 bg-white px-3 py-2.5 text-sm outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-100';

function Shell({ children }) {
  const status = useLoad(() => api('/v1/status'), []);
  const development = status.value?.authority_mode === 'development';
  return <div className="min-h-screen bg-slate-50 text-slate-950">
    <header className="sticky top-0 z-30 border-b border-slate-200 bg-white/95 backdrop-blur">
      <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-x-7 gap-y-2 px-4 py-3">
        <Link to="/agents" className="shrink-0 text-xl font-black tracking-tight">aiagent<span className="text-blue-600">.xyz</span></Link>
        <nav className="order-3 flex w-full flex-wrap items-center gap-1 md:order-none md:w-auto md:flex-1" aria-label="Marketplace">
          {[['/agents', 'Workers'], ['/builder', 'Builder'], ['/my-workers', 'My workers'], ['/instances', 'Instances']].map(([to, label]) => <NavLink key={to} to={to} className={({ isActive }) => cx('rounded-md px-3 py-2 text-sm font-semibold', isActive ? 'bg-slate-950 text-white' : 'text-slate-600 hover:bg-slate-100')}>{label}</NavLink>)}
        </nav>
        <span className="hidden text-xs font-medium text-slate-500 md:block">Package ≠ listing ≠ entitlement ≠ instance</span>
      </div>
    </header>
    {development && <div className="border-b border-amber-300 bg-amber-100 px-4 py-2 text-center text-xs font-bold tracking-wide text-amber-950">LOCAL DEVELOPMENT AUTHORITY — NOT NETWORK STATE</div>}
    {status.error && <div className="bg-red-50 px-4 py-3 text-center text-sm text-red-800">Domain API unavailable: {status.error.message}</div>}
    {children}
  </div>;
}

function ErrorNotice({ error }) {
  if (!error) return null;
  return <div role="alert" className="rounded-lg border border-red-200 bg-red-50 p-3 text-sm text-red-800"><strong>{error.code || 'Request failed'}.</strong> {error.message}{error.owner ? ` Owner: ${error.owner}.` : ''}{error.details?.missing ? ` Missing: ${error.details.missing.join(', ')}.` : ''}</div>;
}

function Empty({ children }) { return <div className="border-y border-slate-200 py-14 text-center text-sm text-slate-500">{children}</div>; }

function Builder() {
  const templates = useLoad(() => api('/v1/worker-templates'), []);
  const supply = useLoad(() => api('/v1/creator/supply'), []);
  const [form, setForm] = useState({ template_ref: 'worker-template://telesupport/v1', name: 'Telesupport operator', description: 'Triages support tickets, drafts bounded replies, and escalates actions requiring human authority.', model_route_ref: 'model-route://support/default', harness_ref: 'harness://managed-worker/v1', runtime_profile_ref: 'runtime-profile://zero-to-idle/v1' });
  const [busy, setBusy] = useState('');
  const [error, setError] = useState(null);
  const act = async (key, operation) => {
    setBusy(key); setError(null);
    try { await operation(); await supply.reload(); } catch (cause) { setError(cause); } finally { setBusy(''); }
  };
  const relations = useMemo(() => {
    const value = supply.value || {};
    return Object.fromEntries((value.drafts || []).map((draft) => {
      const registration = (value.registrations || []).find((item) => item.draft_ref === draft.draft_ref);
      const promotion = registration && (value.promotions || []).find((item) => item.registration_ref === registration.registration_ref);
      const submission = promotion && (value.submissions || []).find((item) => item.promotion_ref === promotion.promotion_ref);
      const listing = registration && (value.listings || []).find((item) => item.registration_ref === registration.registration_ref);
      return [draft.draft_ref, { registration, promotion, submission, listing }];
    }));
  }, [supply.value]);
  const create = (event) => { event.preventDefault(); act('create', () => api('/v1/worker-package-drafts', { method: 'POST', body: { ...form, integration_surfaces: ['helpdesk', 'crm', 'email'], authority_scopes: ['ticket:read', 'reply:draft', 'escalation:create'] } })); };
  return <main className="mx-auto max-w-7xl px-4 py-10">
    <div className="grid gap-10 lg:grid-cols-[minmax(0,1fr)_360px]">
      <section>
        <p className="text-xs font-bold uppercase tracking-[.18em] text-blue-700">Supply lifecycle</p>
        <h1 className="mt-2 text-3xl font-black tracking-tight">Build an immutable worker package.</h1>
        <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-600">Draft, validation, package admission, private registration, disclosure, benchmark, and publication remain separate receipted transitions.</p>
        <ErrorNotice error={error || supply.error} />
        <div className="mt-8 divide-y divide-slate-200 border-y border-slate-200">
          {(supply.value?.drafts || []).map((draft) => {
            const relation = relations[draft.draft_ref] || {};
            const action = draft.state === 'draft' ? ['Validate', () => api(`/v1/worker-package-drafts/${encodeURIComponent(draft.draft_ref)}/validate`, { method: 'POST', body: { expected_revision: draft.revision } })]
              : draft.state === 'validated' ? ['Release package', () => api(`/v1/worker-package-drafts/${encodeURIComponent(draft.draft_ref)}/package-candidates`, { method: 'POST', body: { version: '1.0.0', sbom_ref: 'sbom://generated/v1', provenance_ref: 'provenance://builder/local' } })]
              : !relation.registration ? ['Save privately', () => api('/v1/worker-registrations', { method: 'POST', body: { draft_ref: draft.draft_ref, visibility: 'private' } })]
              : !relation.promotion ? ['Propose publication', () => api(`/v1/worker-registrations/${encodeURIComponent(relation.registration.registration_ref)}/promotion-proposals`, { method: 'POST', body: { disclosure_allowlist: ['name', 'description', 'task_contract', 'pricing'], license: 'commercial-managed', pricing: draft.pricing } })]
              : relation.promotion.state === 'draft' ? ['Submit', () => api(`/v1/worker-registrations/${encodeURIComponent(relation.registration.registration_ref)}/promotion-proposals/${encodeURIComponent(relation.promotion.promotion_ref)}/submit`, { method: 'POST', body: {} })]
              : relation.submission?.state === 'awaiting_benchmark' ? ['Run benchmark', () => api(`/v1/marketplace/submissions/${relation.submission.submission_id}/benchmark`, { method: 'POST', body: { evaluation_plan_ref: 'evaluation-plan://telesupport/adversarial-v1' } })]
              : relation.submission?.state === 'admitted' ? ['Publish explicitly', () => api(`/v1/marketplace/submissions/${relation.submission.submission_id}/publish`, { method: 'POST', body: {} })]
              : null;
            return <article key={draft.draft_ref} className="grid gap-4 py-5 md:grid-cols-[1fr_auto] md:items-center">
              <div><div className="flex flex-wrap items-center gap-2"><h2 className="font-bold">{draft.name}</h2><State value={relation.listing ? 'published' : relation.submission?.state || relation.promotion?.state || relation.registration?.state || draft.state} /></div><p className="mt-1 text-sm text-slate-600">{draft.description}</p><p className="mt-2 font-mono text-[11px] text-slate-400">draft r{draft.revision} · {draft.release_ref || 'no immutable release yet'}</p></div>
              {action && <button className={primary} disabled={!!busy} onClick={() => act(draft.draft_ref, action[1])}>{busy === draft.draft_ref ? 'Working…' : action[0]}</button>}
            </article>;
          })}
          {!supply.loading && !(supply.value?.drafts || []).length && <Empty>No worker drafts yet.</Empty>}
        </div>
      </section>
      <form onSubmit={create} className="h-fit space-y-4 border-l border-slate-200 pl-6">
        <h2 className="text-lg font-bold">New draft</h2>
        <label className="block text-sm font-semibold">Starter<select className={`${input} mt-1`} value={form.template_ref} onChange={(e) => setForm({ ...form, template_ref: e.target.value })}>{(templates.value?.items || []).map((item) => <option key={item.template_ref} value={item.template_ref}>{item.name} — non-executable</option>)}</select></label>
        <Field label="Name" value={form.name} onChange={(name) => setForm({ ...form, name })} />
        <Field label="Description" value={form.description} onChange={(description) => setForm({ ...form, description })} multiline />
        <Field label="Model route ref" value={form.model_route_ref} onChange={(model_route_ref) => setForm({ ...form, model_route_ref })} />
        <Field label="Harness ref" value={form.harness_ref} onChange={(harness_ref) => setForm({ ...form, harness_ref })} />
        <Field label="Runtime profile ref" value={form.runtime_profile_ref} onChange={(runtime_profile_ref) => setForm({ ...form, runtime_profile_ref })} />
        <button className={`${primary} w-full`} disabled={!!busy}>{busy === 'create' ? 'Saving…' : 'Create durable draft'}</button>
      </form>
    </div>
  </main>;
}

function Workers() {
  const workers = useLoad(() => api('/v1/marketplace/workers'), []);
  return <main className="mx-auto max-w-7xl px-4 py-10"><p className="text-xs font-bold uppercase tracking-[.18em] text-blue-700">Public supply</p><h1 className="mt-2 text-3xl font-black tracking-tight">Admitted workers.</h1><p className="mt-2 text-sm text-slate-600">A listing is discoverable metadata. Hire still requires a quote, entitlement, package install, authority, and runtime assignment.</p><div className="mt-8 divide-y divide-slate-200 border-y border-slate-200">{workers.value?.items?.map((worker) => <Link key={worker.worker_id} to={`/agents/${worker.worker_id}`} className="grid min-w-0 gap-3 py-6 hover:bg-white md:grid-cols-[minmax(0,1fr)_auto] md:items-center"><div className="min-w-0"><h2 className="break-words text-xl font-bold">{worker.name}</h2><p className="mt-1 max-w-2xl break-words text-sm text-slate-600">{worker.description}</p><p className="mt-2 break-all font-mono text-[11px] text-slate-400">{worker.release_ref} · {worker.composition_root}</p></div><div className="min-w-0 text-left md:text-right"><strong>{formatAmount(worker.pricing)}</strong><p className="break-all text-xs text-slate-500">{worker.license}</p></div></Link>)}{!workers.loading && !workers.value?.items?.length && <Empty>No public workers. Publish one through Builder.</Empty>}</div><ErrorNotice error={workers.error} /></main>;
}

function WorkerDetail() {
  const { workerId } = useParams(); const navigate = useNavigate();
  const worker = useLoad(() => api(`/v1/marketplace/workers/${workerId}`), [workerId]);
  const [error, setError] = useState(null); const [busy, setBusy] = useState(false);
  const hire = async () => { setBusy(true); setError(null); try { const quote = await api(`/v1/marketplace/workers/${workerId}/quote`, { method: 'POST', body: { intent: 'hire' } }); const result = await api(`/v1/marketplace/workers/${workerId}/instances`, { method: 'POST', body: { quote_ref: quote.quote_ref, runtime_profile_ref: 'runtime-profile://zero-to-idle/v1', persistence_profile_ref: 'storage-profile://encrypted-backup/v1', authority_grant_refs: [] } }); navigate(`/instances/${result.instance.worker_instance_id}`); } catch (cause) { setError(cause); } finally { setBusy(false); } };
  if (worker.loading) return <main className="mx-auto max-w-5xl px-4 py-16">Loading exact release…</main>;
  return <main className="mx-auto grid max-w-5xl gap-10 px-4 py-10 lg:grid-cols-[1fr_320px]"><section><Link className="text-sm text-blue-700" to="/agents">← Workers</Link><h1 className="mt-5 text-4xl font-black tracking-tight">{worker.value?.name}</h1><p className="mt-4 text-lg leading-8 text-slate-600">{worker.value?.description}</p><dl className="mt-10 divide-y divide-slate-200 border-y border-slate-200 text-sm">{[['Release', worker.value?.release_ref], ['Composition root', worker.value?.composition_root], ['License', worker.value?.license], ['Benchmark owner', worker.value?.benchmark?.owner || 'unknown']].map(([label, value]) => <div className="grid gap-2 py-4 md:grid-cols-[180px_1fr]" key={label}><dt className="font-semibold">{label}</dt><dd className="break-all font-mono text-xs text-slate-600">{value}</dd></div>)}</dl></section><aside className="h-fit border-l border-slate-200 pl-6"><p className="text-xs font-bold uppercase tracking-[.18em] text-slate-500">Hire</p><p className="mt-2 text-2xl font-black">{formatAmount(worker.value?.pricing)}</p><p className="mt-3 text-sm leading-6 text-slate-600">Creates distinct quote, entitlement, install, runtime request, and managed-instance records. Missing owners fail closed.</p><ErrorNotice error={error || worker.error} /><button onClick={hire} disabled={busy} className={`${primary} mt-5 w-full`}>{busy ? 'Admitting owners…' : 'Quote and Hire'}</button></aside></main>;
}

function MyWorkers() {
  const state = useLoad(() => api('/v1/creator/supply'), []);
  return <main className="mx-auto max-w-6xl px-4 py-10"><h1 className="text-3xl font-black">My workers</h1><p className="mt-2 text-sm text-slate-600">Private and organization registrations remain usable without public promotion.</p><div className="mt-8 divide-y divide-slate-200 border-y border-slate-200">{state.value?.registrations?.map((item) => <div key={item.registration_ref} className="py-5"><div className="flex items-center gap-2"><strong>{item.name}</strong><State value={item.visibility} /><State value={item.state} /></div><p className="mt-2 font-mono text-xs text-slate-500">{item.registration_ref}<br />{item.release_ref}</p></div>)}{!state.loading && !state.value?.registrations?.length && <Empty>No private workers. Release and save one from Builder.</Empty>}</div></main>;
}

function Instances() {
  const state = useLoad(() => api('/v1/marketplace/instances'), []);
  return <main className="mx-auto max-w-6xl px-4 py-10"><h1 className="text-3xl font-black">Managed instances</h1><p className="mt-2 text-sm text-slate-600">Desired lifecycle and observed runtime are shown independently.</p><div className="mt-8 divide-y divide-slate-200 border-y border-slate-200">{state.value?.items?.map((item) => <Link to={`/instances/${item.worker_instance_id}`} key={item.worker_instance_id} className="grid gap-3 py-5 md:grid-cols-[1fr_auto]"><div><strong>{item.worker_instance_id}</strong><p className="mt-1 font-mono text-xs text-slate-500">{item.release_ref}</p></div><div className="flex gap-2"><State value={`desired: ${item.desired_state}`} /><State value={`observed: ${item.observed_state}`} /><State value={item.readiness} /></div></Link>)}{!state.loading && !state.value?.items?.length && <Empty>No instances. Hire a published worker first.</Empty>}</div><ErrorNotice error={state.error} /></main>;
}

function InstanceDetail() {
  const { instanceId } = useParams(); const state = useLoad(() => api(`/v1/marketplace/instances/${instanceId}`), [instanceId]);
  const [error, setError] = useState(null); const [busy, setBusy] = useState(''); const [integration, setIntegration] = useState({ integration_surface: 'helpdesk', credential_ref: 'credential-grant://wallet-network/select-me', scope_refs: ['tickets:read', 'replies:draft'] });
  const act = async (key, operation) => { setBusy(key); setError(null); try { await operation(); await state.reload(); } catch (cause) { setError(cause); } finally { setBusy(''); } };
  const item = state.value;
  return <main className="mx-auto max-w-6xl px-4 py-10"><Link to="/instances" className="text-sm text-blue-700">← Instances</Link><h1 className="mt-5 break-all text-3xl font-black">Managed instance</h1><div className="mt-4 flex flex-wrap gap-2"><State value={`desired: ${item?.desired_state}`} /><State value={`observed: ${item?.observed_state}`} /><State value={item?.readiness} /></div><ErrorNotice error={error || state.error} /><div className="mt-8 grid gap-10 lg:grid-cols-[1fr_360px]"><section><h2 className="font-bold">Owner-bound state</h2><dl className="mt-3 divide-y divide-slate-200 border-y border-slate-200 text-sm">{[['Instance', item?.worker_instance_id], ['Entitlement', item?.entitlement_ref], ['Install', item?.install_id], ['Runtime assignment', item?.runtime_assignment_ref || 'pending owner projection'], ['Runtime observed at', item?.runtime_observed_at || 'never observed'], ['Subscription', item?.subscription?.state]].map(([label, value]) => <div key={label} className="grid gap-2 py-3 md:grid-cols-[170px_1fr]"><dt className="font-semibold">{label}</dt><dd className="break-all font-mono text-xs text-slate-600">{value}</dd></div>)}</dl><div className="mt-5 flex flex-wrap gap-2">{['suspend', 'resume', 'archive', 'restore'].map((transition) => <button key={transition} className={secondary} disabled={!!busy} onClick={() => act(transition, () => api(`/v1/marketplace/instances/${instanceId}/${transition}`, { method: 'POST', body: { reason: 'operator request' } }))}>{busy === transition ? 'Requesting…' : transition}</button>)}</div></section><aside className="border-l border-slate-200 pl-6"><h2 className="font-bold">Integration authority</h2><p className="mt-1 text-xs leading-5 text-slate-500">Only credential references and exact scopes enter marketplace state.</p><div className="mt-4 space-y-3"><Field label="Surface" value={integration.integration_surface} onChange={(integration_surface) => setIntegration({ ...integration, integration_surface })} /><Field label="Credential grant ref" value={integration.credential_ref} onChange={(credential_ref) => setIntegration({ ...integration, credential_ref })} /><button className={`${primary} w-full`} disabled={!!busy} onClick={() => act('bind', () => api(`/v1/marketplace/instances/${instanceId}/integrations`, { method: 'POST', body: integration }))}>Bind grant</button></div><div className="mt-6 divide-y divide-slate-200 border-y border-slate-200">{item?.integrations?.map((binding) => <div className="py-4" key={binding.binding_id}><div className="flex items-center justify-between"><strong className="text-sm">{binding.integration_surface}</strong><State value={binding.state} /></div><p className="mt-1 break-all font-mono text-[10px] text-slate-400">{binding.authority_receipt_ref}</p>{binding.state !== 'ready' && <button className={`${secondary} mt-3 w-full`} disabled={!!busy} onClick={() => act(binding.binding_id, () => api(`/v1/marketplace/instances/${instanceId}/integrations/${binding.binding_id}/test`, { method: 'POST', body: {} }))}>Test binding</button>}</div>)}</div></aside></div></main>;
}

function Field({ label, value, onChange, multiline = false }) { const Tag = multiline ? 'textarea' : 'input'; return <label className="block text-sm font-semibold">{label}<Tag required className={`${input} mt-1 ${multiline ? 'min-h-24' : ''}`} value={value || ''} onChange={(event) => onChange(event.target.value)} /></label>; }
function State({ value }) { return <span className="inline-flex rounded-full bg-slate-200 px-2 py-1 text-[10px] font-bold uppercase tracking-wide text-slate-700">{value || 'unknown'}</span>; }
function formatAmount(value) { if (!value) return 'Owner quote required'; return `${value.asset || ''} ${(Number(value.amount_minor || 0) / 100).toFixed(2)} / ${value.cadence || 'once'}`; }

export default function MarketplaceApp() {
  return <Shell><Routes><Route path="/" element={<Workers />} /><Route path="/agents" element={<Workers />} /><Route path="/agents/:workerId" element={<WorkerDetail />} /><Route path="/builder" element={<Builder />} /><Route path="/my-workers" element={<MyWorkers />} /><Route path="/instances" element={<Instances />} /><Route path="/instances/:instanceId" element={<InstanceDetail />} /><Route path="*" element={<main className="mx-auto max-w-5xl px-4 py-20"><h1 className="text-3xl font-black">Route not found</h1><Link className="mt-4 inline-block text-blue-700" to="/agents">Return to workers</Link></main>} /></Routes></Shell>;
}
