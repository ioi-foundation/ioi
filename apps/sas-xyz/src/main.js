import './styles.css';
import { api } from './api.js';

const root = document.querySelector('#app');
const state = { status: null, loading: false, error: null, notice: null };
const h = (value) => String(value ?? '').replace(/[&<>'"]/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' })[character]);
const amount = (price) => price ? `${h(price.asset)} ${(Number(price.amount_minor) / 100).toFixed(2)}` : '—';
const stamp = (value) => value ? new Date(value).toLocaleString() : 'not observed';
const badge = (value) => `<span class="badge">${h(value || 'unknown')}</span>`;

const navigate = (path) => { history.pushState({}, '', path); render(); };
window.addEventListener('popstate', render);

const request = async (operation, message) => {
  state.loading = true; state.error = null; state.notice = null; renderChrome();
  try { const result = await operation(); state.notice = typeof message === 'function' ? message(result) : message; return result; }
  catch (error) { state.error = error; throw error; }
  finally { state.loading = false; }
};

function chrome(content) {
  const development = state.status?.authority_mode === 'development';
  root.innerHTML = `<div class="app-shell">
    <header class="topbar"><button class="brand" data-nav="/services">sas<span>.xyz</span></button><nav aria-label="Outcome marketplace"><button data-nav="/services">Services</button><button data-nav="/orders">Orders</button><button data-nav="/provider">Provider</button></nav><div class="truth">order ≠ delivery ≠ settlement ≠ rights</div></header>
    ${development ? '<div class="dev-banner">LOCAL DEVELOPMENT AUTHORITY — NOT NETWORK STATE</div>' : ''}
    <div id="global-status" aria-live="polite">${statusMarkup()}</div>
    ${content}
  </div>`;
  root.querySelectorAll('[data-nav]').forEach((element) => element.addEventListener('click', () => navigate(element.dataset.nav)));
}

function statusMarkup() {
  if (state.loading) return '<div class="global pending">Submitting to canonical owners…</div>';
  if (state.error) return `<div class="global error"><strong>${h(state.error.code || 'Request failed')}</strong> · ${h(state.error.message)}${state.error.owner ? ` · owner: ${h(state.error.owner)}` : ''}</div>`;
  if (state.notice) return `<div class="global success">${h(state.notice)}</div>`;
  return '';
}

function renderChrome() {
  const target = document.querySelector('#global-status'); if (target) target.innerHTML = statusMarkup();
}

async function render() {
  const path = location.pathname.replace(/\/$/, '') || '/services';
  chrome('<main class="workspace"><p class="loading">Loading owner state…</p></main>');
  try {
    if (path === '/services') return renderServices();
    if (path.startsWith('/services/')) return renderService(path.split('/')[2]);
    if (path === '/orders') return renderOrders();
    if (path.startsWith('/orders/')) return renderOrder(path.split('/')[2]);
    if (path === '/provider') return renderProvider();
    if (path.startsWith('/rights/')) return renderRights(path.split('/')[2]);
    navigate('/services');
  } catch (error) { state.error = error; chrome(`<main class="workspace"><div class="empty"><h1>Owner state unavailable</h1><p>${h(error.message)}</p><button class="primary" data-nav="/services">Return to services</button></div></main>`); }
}

async function renderServices() {
  const { items } = await api('/v1/services');
  chrome(`<main class="workspace"><section class="working"><p class="eyebrow">Outcome catalog</p><h1>Contract the result, not the machinery.</h1><p class="lede">Every service release freezes output, acceptance, price, SLA, privacy, and evidence expectations before execution.</p><div class="rows">${items.map((item) => `<button class="row" data-nav="/services/${h(item.service_id)}"><div><strong>${h(item.name)}</strong><p>${h(item.summary)}</p><code>${h(item.version)} · ${h(item.deliverable_kind)}</code></div><div class="row-tail"><b>${amount(item.price)}</b>${badge(item.state)}</div></button>`).join('') || '<div class="empty">No published services. A provider can publish the first governed release.</div>'}</div></section><aside class="inspector"><p class="eyebrow">State boundary</p><h2>Discoverable is not executable.</h2><p>A catalog row is a provider release. Ordering separately reserves settlement and requests an admitted runtime assignment.</p><button class="secondary" data-nav="/provider">Open provider workspace</button></aside></main>`);
  wireNavigation();
}

async function renderService(serviceId) {
  const item = await api(`/v1/services/${serviceId}`);
  chrome(`<main class="workspace"><section class="working"><button class="back" data-nav="/services">← Services</button><p class="eyebrow">Service release ${h(item.version)}</p><h1>${h(item.name)}</h1><p class="lede">${h(item.summary)}</p><dl class="facts"><div><dt>Outcome</dt><dd>${h(item.outcome_contract?.output || JSON.stringify(item.outcome_contract))}</dd></div><div><dt>Acceptance</dt><dd>${h(item.outcome_contract?.acceptance || 'Defined in order contract')}</dd></div><div><dt>SLA</dt><dd>${h(item.sla)}</dd></div><div><dt>Price</dt><dd>${amount(item.price)}</dd></div><div><dt>Deliverable</dt><dd>${h(item.deliverable_kind)}</dd></div></dl></section><aside class="inspector"><p class="eyebrow">Create order</p><h2>Freeze exact terms.</h2><form id="order-form" class="form"><label>Objective<textarea name="objective" required>Produce the accepted ${h(item.name)} outcome with linked evidence.</textarea></label><label>Acceptance criteria<textarea name="acceptance" required>${h(item.outcome_contract?.acceptance || 'All declared artifacts and verifier evidence pass.')}</textarea></label><label>Settlement rail<input name="rail" required value="settlement-rail://development/escrow" /></label>${item.deliverable_kind === 'cad' ? '<label>Licensed production units<input name="units" type="number" min="1" value="100" required /></label><label>Enforcement mode<select name="mode"><option value="contractual_audit">Contractual / audited</option><option value="governed_remote_production">Governed remote production</option></select></label>' : ''}<button class="primary" ${state.loading ? 'disabled' : ''}>Reserve and order</button></form></aside></main>`);
  wireNavigation();
  document.querySelector('#order-form').addEventListener('submit', async (event) => {
    event.preventDefault(); const data = new FormData(event.currentTarget);
    try { const order = await request(() => api('/v1/orders', { method: 'POST', body: { service_id: serviceId, objective: data.get('objective'), acceptance_criteria: data.get('acceptance'), settlement_rail: data.get('rail'), production_limit_units: data.get('units') ? Number(data.get('units')) : undefined, enforcement_mode: data.get('mode') || undefined } }), 'Order admitted; settlement and runtime requests are linked.'); navigate(`/orders/${order.order_id}`); } catch { renderChrome(); }
  });
}

async function renderOrders() {
  const { items } = await api('/v1/orders');
  chrome(`<main class="workspace"><section class="working wide"><p class="eyebrow">Buyer and provider work</p><h1>Outcome orders.</h1><p class="lede">Operational, delivery, and settlement state never collapse into one status.</p><div class="rows">${items.map((item) => `<button class="row" data-nav="/orders/${h(item.order_id)}"><div><strong>${h(item.terms.objective)}</strong><p>${h(item.order_id)}</p><code>${h(item.terms_root)}</code></div><div class="states">${badge(`order: ${item.state}`)}${badge(`delivery: ${item.delivery_state}`)}${badge(`settlement: ${item.settlement_state}`)}</div></button>`).join('') || '<div class="empty">No orders yet. Choose a service and freeze the first contract.</div>'}</div></section></main>`);
  wireNavigation();
}

async function renderOrder(orderId) {
  const order = await api(`/v1/orders/${orderId}`);
  const latest = order.deliveries.at(-1); const openDispute = order.disputes.find((item) => item.state === 'open');
  chrome(`<main class="workspace"><section class="working"><button class="back" data-nav="/orders">← Orders</button><p class="eyebrow">Order ${h(order.order_id)}</p><h1>${h(order.terms.objective)}</h1><div class="states large">${badge(`order: ${order.state}`)}${badge(`delivery: ${order.delivery_state}`)}${badge(`settlement: ${order.settlement_state}`)}</div><dl class="facts"><div><dt>Terms root</dt><dd><code>${h(order.terms_root)}</code></dd></div><div><dt>Provider</dt><dd>${h(order.provider_ref)}</dd></div><div><dt>Runtime assignment</dt><dd>${h(order.runtime_assignment_ref || 'pending owner projection')}</dd></div><div><dt>Settlement</dt><dd>${h(order.settlement_ref || 'pending owner projection')}</dd></div><div><dt>Acceptance</dt><dd>${h(order.terms.acceptance_criteria)}</dd></div></dl><h2 class="section-title">Immutable deliveries</h2><div class="rows compact">${order.deliveries.map((delivery) => `<div class="row static"><div><strong>${h(delivery.kind)} delivery</strong><p>${h(delivery.delivery_id)}</p><code>${delivery.artifacts.map((artifact) => h(artifact.content_hash)).join(' · ')}</code></div>${badge(delivery.state)}</div>`).join('') || '<div class="empty">No delivery submitted.</div>'}</div>${order.artifact_license ? `<button class="secondary rights-link" data-nav="/rights/${h(order.order_id)}">Open artifact and production rights →</button>` : ''}</section><aside class="inspector">${orderActions(order, latest, openDispute)}</aside></main>`);
  wireNavigation(); wireOrderActions(order, latest, openDispute);
}

function orderActions(order, delivery, dispute) {
  if (dispute) return `<p class="eyebrow">Dispute rail</p><h2>Evidence-bound resolution.</h2><p>${h(dispute.claim)}</p><form id="evidence-form" class="form"><label>Evidence ref<input name="ref" value="evidence://inspection/report-1" required /></label><label>Content hash<input name="hash" value="sha256:evidence-report" required /></label><button class="secondary">Submit evidence</button></form><form id="resolution-form" class="form"><label>Resolution<select name="decision"><option>rework</option><option>partial_refund</option><option>refund</option><option>payout</option><option>no_fault</option></select></label><button class="primary">Request rail resolution</button></form>`;
  if (order.state === 'awaiting_provider') return `<p class="eyebrow">Provider action</p><h2>Claim admitted work.</h2><p>The selected provider must accept the frozen terms before delivery.</p><button class="primary" id="claim">Claim order</button>`;
  if (['in_progress', 'revision_requested'].includes(order.state)) return `<p class="eyebrow">Provider delivery</p><h2>Submit immutable artifacts.</h2><form id="delivery-form" class="form"><label>Artifact ref<input name="ref" value="artifact://cad/final.step" required /></label><label>SHA-256 content hash<input name="hash" value="sha256:replace-with-content-hash" required /></label><label>Evidence ref<input name="evidence" value="evidence://cad/validation" required /></label><button class="primary">Verify and submit</button></form>`;
  if (order.state === 'delivered' && delivery) return `<p class="eyebrow">Buyer decision</p><h2>Inspect before settlement.</h2><p>Acceptance may create artifact rights, then requests settlement separately.</p><button class="primary" id="accept">Accept delivery</button><button class="secondary" id="revise">Request revision</button><button class="danger" id="dispute">Open dispute</button>`;
  return `<p class="eyebrow">Provider continuity</p><h2>Governed substitution.</h2><p>A provider name is never edited in place. Propose exact identity binding, SLA, price, privacy, authority, and in-flight deltas.</p><form id="swap-form" class="form"><label>Successor provider ref<input name="provider" value="principal://provider/successor" required /></label><label>Successor tenant ref<input name="tenant" value="tenant://provider/successor" required /></label><label>Successor binding ref<input name="binding" value="provider-binding://successor/admitted-v1" required /></label><label>Price delta<input name="price" value="none" required /></label><label>SLA delta<input name="sla" value="none" required /></label><button class="secondary">Create proposal</button></form>${order.substitutions.map((item) => `<div class="proposal"><strong>${h(item.new_provider_ref)}</strong>${badge(item.state)}${item.state === 'proposed' ? `<button class="secondary" data-accept-swap="${h(item.proposal_id)}">Accept</button>` : ''}${item.state === 'accepted' ? `<button class="primary" data-apply-swap="${h(item.proposal_id)}">Preflight and apply</button>` : ''}</div>`).join('')}`;
}

function wireOrderActions(order, delivery, dispute) {
  const perform = async (operation, notice) => { try { await request(operation, notice); await renderOrder(order.order_id); } catch { renderChrome(); } };
  document.querySelector('#claim')?.addEventListener('click', () => perform(() => api(`/v1/provider/orders/${order.order_id}/claim`, { method: 'POST', body: {} }), 'Provider claim receipted.'));
  document.querySelector('#delivery-form')?.addEventListener('submit', (event) => { event.preventDefault(); const data = new FormData(event.currentTarget); perform(() => api(`/v1/provider/orders/${order.order_id}/submit-delivery`, { method: 'POST', body: { kind: 'final', artifacts: [{ artifact_ref: data.get('ref'), content_hash: data.get('hash') }], evidence_refs: [data.get('evidence')] } }), 'Delivery verified and submitted.'); });
  document.querySelector('#accept')?.addEventListener('click', () => perform(() => api(`/v1/deliveries/${delivery.delivery_id}/accept`, { method: 'POST', body: {} }), 'Delivery accepted; rights minted and settlement requested.'));
  document.querySelector('#revise')?.addEventListener('click', () => perform(() => api(`/v1/deliveries/${delivery.delivery_id}/request-revision`, { method: 'POST', body: { reason: 'Acceptance criteria require a corrected successor artifact.' } }), 'Revision request linked to the immutable delivery.'));
  document.querySelector('#dispute')?.addEventListener('click', () => perform(() => api(`/v1/deliveries/${delivery.delivery_id}/open-dispute`, { method: 'POST', body: { claim: 'Delivered artifact does not satisfy the frozen acceptance contract.' } }), 'Dispute opened; settlement hold requested.'));
  document.querySelector('#evidence-form')?.addEventListener('submit', (event) => { event.preventDefault(); const data = new FormData(event.currentTarget); perform(() => api(`/v1/disputes/${dispute.dispute_id}/submit-evidence`, { method: 'POST', body: { evidence_ref: data.get('ref'), content_hash: data.get('hash') } }), 'Typed dispute evidence appended.'); });
  document.querySelector('#resolution-form')?.addEventListener('submit', (event) => { event.preventDefault(); const data = new FormData(event.currentTarget); perform(() => api(`/v1/disputes/${dispute.dispute_id}/resolve`, { method: 'POST', body: { decision: data.get('decision') } }), 'Resolution sent to the authoritative settlement rail.'); });
  document.querySelector('#swap-form')?.addEventListener('submit', (event) => { event.preventDefault(); const data = new FormData(event.currentTarget); perform(() => api(`/v1/orders/${order.order_id}/provider-substitutions`, { method: 'POST', body: { new_provider_ref: data.get('provider'), new_provider_tenant_ref: data.get('tenant'), successor_binding_ref: data.get('binding'), price_delta: data.get('price'), sla_delta: data.get('sla'), privacy_delta: 'none', authority_delta: [], in_flight_disposition: 'finish-current-step', rollback_posture: 'restore-predecessor-assignment' } }), 'Provider substitution proposed; routing unchanged.'); });
  document.querySelectorAll('[data-accept-swap]').forEach((element) => element.addEventListener('click', () => perform(() => api(`/v1/orders/${order.order_id}/provider-substitutions/${element.dataset.acceptSwap}/accept`, { method: 'POST', body: {} }), 'Buyer accepted substitution proposal; routing unchanged pending preflight.')));
  document.querySelectorAll('[data-apply-swap]').forEach((element) => element.addEventListener('click', () => perform(() => api(`/v1/orders/${order.order_id}/provider-substitutions/${element.dataset.applySwap}/apply`, { method: 'POST', body: {} }), 'Successor preflight and effective-boundary receipt completed.')));
}

async function renderProvider() {
  chrome(`<main class="workspace"><section class="working"><p class="eyebrow">Provider supply</p><h1>Publish a governed release.</h1><p class="lede">This creates a service listing only. It does not reserve settlement, assign runtime, or imply successful delivery.</p><form id="service-form" class="form two-column"><label>Name<input name="name" value="Engineering CAD outcome" required /></label><label>Version<input name="version" value="1.0.0" required /></label><label class="span-two">Summary<textarea name="summary" required>Design and validate a production-ready mechanical part with STEP artifact and evidence.</textarea></label><label>Price, USD cents<input name="amount" type="number" min="1" value="250000" required /></label><label>SLA<input name="sla" value="10 business days" required /></label><label class="span-two">Output contract<input name="output" value="STEP CAD, drawings, validation report" required /></label><label class="span-two">Acceptance contract<input name="acceptance" value="Artifact hash resolves; geometry and declared validation checks pass" required /></label><button class="primary span-two">Publish service release</button></form></section><aside class="inspector"><p class="eyebrow">CAD truth</p><h2>Two honest enforcement modes.</h2><p><strong>Contractual/audited:</strong> downloadable bytes; buyer reporting and audit apply.</p><p><strong>Governed remote production:</strong> raw CAD remains controlled and each admitted batch consumes units.</p></aside></main>`);
  document.querySelector('#service-form').addEventListener('submit', async (event) => { event.preventDefault(); const data = new FormData(event.currentTarget); try { const service = await request(() => api('/v1/provider/services', { method: 'POST', body: { name: data.get('name'), version: data.get('version'), summary: data.get('summary'), outcome_contract: { output: data.get('output'), acceptance: data.get('acceptance') }, deliverable_kind: 'cad', price: { asset: 'USD', amount_minor: Number(data.get('amount')), decimals: 2 }, sla: data.get('sla'), artifact_rights: { enforcement_modes: ['contractual_audit', 'governed_remote_production'], production_limit_units: 100, granted_rights: { inspect: true, download: true, modify: true, make_derivatives: false, manufacture: true, sublicense: false, transfer: false } } } }), 'Service release published.'); navigate(`/services/${service.service_id}`); } catch { renderChrome(); } });
}

async function renderRights(orderId) {
  const order = await api(`/v1/orders/${orderId}`); const license = order.artifact_license; const entitlement = order.production_entitlement;
  if (!license) throw new Error('This order has no accepted artifact license.');
  chrome(`<main class="workspace"><section class="working"><button class="back" data-nav="/orders/${h(orderId)}">← Order</button><p class="eyebrow">Artifact rights</p><h1>${h(license.production_enforcement_mode === 'governed_remote_production' ? `${entitlement.remaining_units} controlled units remaining` : `Licensed for ${license.production_limit_units} pieces`)}</h1><p class="lede">${license.production_enforcement_mode === 'governed_remote_production' ? 'Raw CAD remains inside the governed adapter boundary. Counters derive from admitted reservation and usage records.' : 'Downloadable artifact. Quantity is a legal and audit obligation; sas.xyz does not claim to block off-system production.'}</p><dl class="facts"><div><dt>Artifact</dt><dd>${h(license.artifact_ref)}</dd></div><div><dt>Content hash</dt><dd><code>${h(license.artifact_content_hash)}</code></dd></div><div><dt>License</dt><dd>${h(license.license_ref)}</dd></div><div><dt>Mode</dt><dd>${h(license.production_enforcement_mode)}</dd></div>${entitlement ? `<div><dt>Entitlement</dt><dd>${h(entitlement.entitlement_ref)}</dd></div><div><dt>Reserved / consumed / remaining</dt><dd>${entitlement.reserved_units} / ${entitlement.admitted_consumed_units} / ${entitlement.remaining_units}</dd></div>` : ''}</dl></section><aside class="inspector">${rightsActions(license, entitlement)}</aside></main>`);
  wireNavigation(); wireRights(orderId, license, entitlement);
}

function rightsActions(license, entitlement) {
  if (license.production_enforcement_mode === 'contractual_audit') return `<p class="eyebrow">Licensed download</p><h2>Authorize audited use.</h2><p>The receipt will say “licensed for ${license.production_limit_units} pieces; buyer reporting and audit terms apply.”</p><button class="primary" id="download">Authorize download</button>`;
  const open = entitlement.reservations?.find((item) => item.state === 'reserved');
  return `<p class="eyebrow">Controlled production</p><h2>${open ? 'Consume admitted batch.' : 'Reserve a batch.'}</h2>${open ? `<p>${open.units} units reserved at ${h(open.facility_ref)}.</p><form id="consume-form" class="form"><label>Work order ref<input name="work" value="work-order://cad/batch-001" required /></label><label>Evidence ref<input name="evidence" value="evidence://machine/batch-001" required /></label><button class="primary">Append usage receipt</button></form>` : `<form id="reserve-form" class="form"><label>Units<input name="units" type="number" min="1" max="${entitlement.remaining_units}" value="25" required /></label><label>Facility ref<input name="facility" value="facility://controlled/cell-1" required /></label><label>Machine ref<input name="machine" value="machine://controlled/cnc-1" required /></label><button class="primary">Reserve with CAS</button></form>`}`;
}

function wireRights(orderId, license, entitlement) {
  const perform = async (operation, notice) => { try { await request(operation, notice); await renderRights(orderId); } catch { renderChrome(); } };
  document.querySelector('#download')?.addEventListener('click', () => perform(() => api(`/v1/artifacts/${encodeURIComponent(license.artifact_ref)}/download-authorizations`, { method: 'POST', body: { purpose: 'licensed-production' } }), (result) => result.download_available ? 'Owner issued a short-lived download capability.' : 'Authorization receipted; the owner did not issue downloadable bytes.'));
  document.querySelector('#reserve-form')?.addEventListener('submit', (event) => { event.preventDefault(); const data = new FormData(event.currentTarget); perform(() => api(`/v1/production-entitlements/${encodeURIComponent(entitlement.entitlement_ref)}/reservations`, { method: 'POST', body: { expected_revision: entitlement.revision, units: Number(data.get('units')), facility_ref: data.get('facility'), machine_ref: data.get('machine') } }), 'Production units reserved atomically.'); });
  const open = entitlement?.reservations?.find((item) => item.state === 'reserved');
  document.querySelector('#consume-form')?.addEventListener('submit', (event) => { event.preventDefault(); const data = new FormData(event.currentTarget); perform(() => api(`/v1/production-entitlements/${encodeURIComponent(entitlement.entitlement_ref)}/usage-receipts`, { method: 'POST', body: { expected_revision: entitlement.revision, reservation_ref: open.reservation_ref, admitted_units: open.units, batch_or_work_order_ref: data.get('work'), evidence_refs: [data.get('evidence')] } }), 'Owner-admitted production usage receipt appended.'); });
}

function wireNavigation() { document.querySelectorAll('[data-nav]').forEach((element) => element.addEventListener('click', () => navigate(element.dataset.nav))); }

async function boot() {
  try { state.status = await api('/v1/status'); }
  catch (error) { state.error = error; }
  await render();
}

boot();
