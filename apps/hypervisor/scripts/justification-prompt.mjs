// The JUSTIFICATION PROMPT (ADR 0056 P5) — what a person sees when an action they submitted meets a
// Governance / Leases & Limits checkpoint. The daemon answers such a submission 428
// `justification_required` (or 409 `justification_checkpoint_changed`) with each applicable
// checkpoint's prompt, the justification it asks for, and the interaction it names. This page shows
// every prompt, carries the person's original form untouched, and resubmits it to the SAME lane with
// the answers; the daemon judges them, records each one, and only then runs the action.
//
// A checkpoint is a speed bump and an audit trail, not an approval: the page says so, and nothing on
// it grants anything. The prompt text is the configurator's — shown as text, never as HTML.
import { escHtml as esc } from "../surfaces/kit.mjs";

const PREFIX = "justify__";

export const isJustificationPrompt = (status, body) =>
  (status === 428 || status === 409) && Array.isArray(body?.checkpoints) && /^justification_(?:required|checkpoint_changed)$/u.test(body?.error?.code || "");

// The answers a resubmitted prompt carries, in the daemon's shape.
export function justificationsFrom(form) {
  const out = [];
  for (let i = 0; i < 20; i += 1) {
    const ref = form.get(`${PREFIX}${i}__ref`);
    if (!ref) break;
    out.push({
      checkpoint_ref: ref,
      checkpoint_head: form.get(`${PREFIX}${i}__head`) || "",
      acknowledged: form.get(`${PREFIX}${i}__ack`) === "on",
      text: (form.get(`${PREFIX}${i}__text`) || "").slice(0, 4000),
      selected: form.getAll(`${PREFIX}${i}__selected`).map((s) => s.slice(0, 200)),
    });
  }
  return out;
}

// What the daemon needs beside the action's own fields: the answers and the interaction they belong
// to (so a double submission replays the same records instead of writing new ones).
export function justificationPayload(form) {
  const justifications = justificationsFrom(form);
  const interaction = form.get(`${PREFIX}interaction`) || "";
  return justifications.length ? { justifications, ...(interaction ? { interaction_ref: interaction } : {}) } : {};
}

const paragraphs = (text) => String(text || "").split(/\n{2,}/u).map((p) => `<p style="margin:0 0 8px;white-space:pre-wrap">${esc(p)}</p>`).join("");

function answerInput(i, spec) {
  if (spec.kind === "acknowledgment") {
    return `<label style="display:flex;gap:8px;align-items:flex-start"><input type="checkbox" name="${PREFIX}${i}__ack" data-justify-ack="${i}"> <span>${esc(spec.acknowledgment_text || "I acknowledge this")}</span></label>`;
  }
  if (spec.kind === "response") {
    return `<textarea name="${PREFIX}${i}__text" rows="4" maxlength="4000" style="width:100%;box-sizing:border-box" data-justify-text="${i}" placeholder="Your justification"></textarea>${spec.has_pattern ? `<div class="sub" style="margin:4px 0 0">This checkpoint expects a particular form of answer.</div>` : ""}`;
  }
  const type = spec.multiple ? "checkbox" : "radio";
  const choices = (spec.options || []).map((o) => `<label style="display:flex;gap:8px;align-items:center"><input type="${type}" name="${PREFIX}${i}__selected" value="${esc(o)}"> ${esc(o)}</label>`).join("");
  const free = spec.free_text && spec.free_text !== "none"
    ? `<textarea name="${PREFIX}${i}__text" rows="3" maxlength="4000" style="width:100%;box-sizing:border-box;margin-top:8px" placeholder="${spec.free_text === "required" ? "Explanation (required)" : "Explanation (optional)"}"></textarea>`
    : "";
  return `<div data-justify-choices="${i}">${choices}</div>${free}`;
}

// The page. `action` is the lane the form posted to; `carried` the original form's fields (the
// answers and hidden interaction are dropped and re-rendered); `reply` the daemon's 428/409 body.
export function renderJustificationPrompt({ action, carried, reply, backHref, what }) {
  const keep = [...carried].filter(([k]) => !k.startsWith(PREFIX));
  const hiddenFields = keep.map(([k, v]) => `<input type="hidden" name="${esc(k)}" value="${esc(v)}">`).join("");
  const changed = reply?.error?.code === "justification_checkpoint_changed";
  const blocks = (reply.checkpoints || []).map((c, i) => `<section class="card" style="display:block;margin:0 0 12px" data-justify-checkpoint="${esc(c.checkpoint_ref || "")}">
      <input type="hidden" name="${PREFIX}${i}__ref" value="${esc(c.checkpoint_ref || "")}">
      <input type="hidden" name="${PREFIX}${i}__head" value="${esc(c.checkpoint_head || "")}">
      <h2 style="margin:0 0 8px;text-transform:none;letter-spacing:0;font-size:16px;color:inherit">${esc(c.prompt?.title || "Justification required")}</h2>
      ${paragraphs(c.prompt?.body)}
      ${c.prompt?.description ? `<div class="sub" style="margin:0 0 8px">${paragraphs(c.prompt.description)}</div>` : ""}
      ${c.error ? `<div class="pill warn" style="margin:0 0 8px;white-space:normal" data-justify-error="${i}">${esc(c.error)}</div>` : ""}
      ${answerInput(i, c.justification || {})}
    </section>`).join("");
  return `<h1 data-justification-prompt="1">Justification required</h1>
    <p class="sub">${esc(what || "This action")} needs a justification before it runs. Your answer is recorded with the exact wording shown here and who gave it; it is an audit record, not an approval. ${changed ? "<b>A checkpoint changed after it was shown — read it again.</b>" : ""}</p>
    <form method="post" action="${esc(action)}" data-justify-form="1">
      ${hiddenFields}
      <input type="hidden" name="${PREFIX}interaction" value="${esc(reply.interaction_ref || "")}">
      ${blocks}
      <div class="row"><button class="act" type="submit" data-justify-submit="1">Continue</button><a class="act ghost" href="${esc(backHref || "/")}">Cancel</a></div>
    </form>`;
}
