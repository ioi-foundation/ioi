// The editor-side rendering of a Hypervisor challenge notification (M08.12, register R-214).
//
// A pure function from the relay's typed notification (ioi.editor-challenge-notification.v1) to what an
// editor shows: one message and the actions that open the operator's decision on the Hypervisor App.
// It is VS Code-free so it can be proven without a host; the extension host wires the result into
// `vscode.window.showWarningMessage(message, ...actions)` and opens `url` on the chosen action. The
// renderer never sees a facet, a grant or a key — the notification cannot carry them — and it never
// offers an in-editor approval: approving happens on the App's card, under the operator's own session.
"use strict";

const SCHEMA = "ioi.editor-challenge-notification.v1";

function renderChallengeNotification(notification) {
  const n = notification && typeof notification === "object" ? notification : {};
  if (n.schema_version !== SCHEMA) {
    return { ok: false, code: "notification_schema_invalid", message: null, actions: [], detail: null };
  }
  const d = n.decision && typeof n.decision === "object" ? n.decision : {};
  const actions = [];
  if (typeof d.card_url === "string") actions.push({ title: "Open approval", url: d.card_url });
  if (typeof d.timeline_url === "string") actions.push({ title: "View timeline", url: d.timeline_url });
  const detail = {
    run_id: typeof n.run_id === "string" ? n.run_id : null,
    request_hash: typeof n.request_hash === "string" ? n.request_hash : null,
    policy_hash: typeof n.policy_hash === "string" ? n.policy_hash : null,
    receipt_ref: typeof n.receipt_ref === "string" ? n.receipt_ref : null,
    byte_derived: n.byte_derived === true,
  };
  const message = typeof n.message === "string" && n.message.length > 0 ? n.message : "Hypervisor blocked an operation pending your decision on the App";
  return { ok: true, code: null, message, actions, detail };
}

module.exports = { SCHEMA, renderChallengeNotification };
