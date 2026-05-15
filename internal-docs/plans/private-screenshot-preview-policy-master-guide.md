# Private Screenshot Preview Policy Master Guide

Owner: privacy / Autopilot / computer-use harness / artifacts

Status: future-platform leg, ready for implementation

Created: 2026-05-15

## Executive Verdict

The computer-use workbench can already render URL/data screenshot refs and draw
target overlays. The remaining privacy deferral is previewing non-retained or
private screenshot binaries safely. This needs a policy leg, not a quick image
viewer.

Screenshots can contain credentials, personal data, customer data, private
messages, internal docs, and sensitive product state. IOI should make private
preview explicit, local-first, auditable, and revocable.

## Doctrine

- No private screenshot persistence by default.
- Screenshot preview is a policy decision, not a renderer convenience.
- Redacted previews are preferred over raw previews.
- Raw screenshot access is local/private unless policy explicitly allows
  export.
- Preview state is UI projection; retained artifacts and access receipts are
  runtime truth.
- Screenshots referenced by actions must stay observation-bound.

## Retention Modes

| Mode | Meaning |
| --- | --- |
| `prompt_visible_summary_only` | Model sees summaries, not raw images. |
| `no_persistence` | Screenshot may be used transiently and then discarded. |
| `local_redacted_artifacts` | Redacted images can be retained locally. |
| `local_raw_artifacts` | Raw images retained locally after explicit policy. |
| `encrypted_local_raw_artifacts` | Raw images retained locally with encryption and access receipts. |
| `shareable_eval_artifacts` | Redacted/eval-safe artifacts can leave local boundary. |

## Preview Classes

| Preview class | Default |
| --- | --- |
| Redacted thumbnail | Allowed when retention mode permits local redacted artifacts. |
| Raw local preview | Requires explicit local-private preview decision. |
| Raw export/download | Requires explicit export authority. |
| Model-visible raw image | Requires privacy-tier policy and task justification. |
| Shareable eval image | Requires redaction report and eval-retention policy. |

## Runtime Objects

This leg should introduce or standardize:

- `ScreenshotArtifactRef`
- `ScreenshotPreviewPolicy`
- `ScreenshotAccessReceipt`
- `RedactionReport`
- `PreviewLease`
- `PreviewRevocationReceipt`
- `ObservationRetentionMode`
- `PrivateArtifactAccessDecision`

## Preview Pipeline

```text
capture_or_import
-> classify_sensitivity
-> apply_retention_policy
-> redact_if_required
-> create_preview_lease
-> render_local_preview
-> record_access_receipt
-> revoke_or_expire_preview
```

## Autopilot Workbench

Autopilot should show:

- screenshot retention mode;
- whether raw image bytes are retained;
- redaction status;
- preview availability;
- access decision and expiry;
- target overlay independent of raw preview;
- revocation/clear action;
- artifact refs without leaking private file paths.

## React Flow Projection

Computer-use and Visual Observation nodes should configure:

- retention mode;
- redaction profile;
- whether raw preview is allowed;
- whether model-visible image input is allowed;
- screenshot expiry;
- export policy.

The run inspector should render overlays even when raw preview is unavailable.

## Validation Plan

Required tests:

- private screenshots do not persist without explicit retention;
- raw preview is unavailable without policy decision;
- redacted preview includes redaction report;
- artifact refs never expose source local file paths;
- preview access emits receipts;
- preview leases expire or revoke;
- model-visible raw image access requires privacy-tier policy;
- run inspector still shows target boxes when raw preview is blocked.

## Definition Of Done

This leg is complete when:

- screenshot preview behavior is governed by runtime policy;
- raw and redacted previews have separate receipts;
- UI can preview permitted images without becoming artifact truth;
- private screenshots can be cleared or revoked;
- external/export paths require explicit policy;
- computer-use verification remains possible when previews are unavailable.
