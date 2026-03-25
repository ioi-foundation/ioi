# chat_contract_v1

This contract defines the primary chat-lane response payload for deterministic rendering.
It is designed to keep conversational output CIRC/CEC compliant without ad hoc text heuristics.

## Envelope

```json
{
  "schema_version": "chat_contract_v1",
  "intent_id": "search.list_files",
  "outcome": {
    "status": "success",
    "count": 4,
    "summary": "Found 4 matching files."
  },
  "interpretation": {
    "time_window_start": "2026-02-20T19:48:48-05:00",
    "time_window_end": "2026-02-27T19:48:48-05:00",
    "timezone": "America/New_York",
    "sort": "modified_desc"
  },
  "result_columns": [
    { "key": "name", "label": "File" },
    { "key": "path_short", "label": "Folder" },
    { "key": "modified", "label": "Modified" }
  ],
  "result_rows": [
    {
      "name": "IOI_Web4_Technical_Whitepaper_v7.pdf",
      "path_short": "marketing/ioi-whitepaper/v7",
      "modified": "2026-02-27T19:48:48-05:00"
    }
  ],
  "actions": [
    { "id": "open_all", "label": "Open all" },
    { "id": "reveal_in_folder", "label": "Reveal in folder" }
  ],
  "artifact_ref": "artifact://turn/123/files",
  "answer_markdown": "Found **4 files** modified in the last 7 days."
}
```

## Required Fields

- `schema_version`: must be exactly `"chat_contract_v1"`.
- `intent_id`: non-empty string.
- `outcome`: object with `status` in `success|partial|failed`.
- `interpretation`: object with scalar or scalar-array values.
- `result_rows`: array of row objects with scalar values only.

## Optional Fields

- `result_columns`: ordered display columns (`key`, `label`).
- `actions`: list of suggested actions (`id`, `label`).
- `artifact_ref`: supplementary artifact pointer.
- `answer_markdown`: optional high-level summary markdown.

## Validation Rules (Pass/Fail)

### Pass

- Envelope is valid JSON object and all required fields pass type checks.
- `result_columns` keys are unique.
- `actions` ids are unique.
- Primary-lane strings do not contain internal/transport labels.

### Fail

- Any required field missing or wrong type.
- Unsupported `schema_version`.
- Nested non-scalar values in `interpretation` or `result_rows`.
- Duplicate `result_columns.key` or duplicate `actions.id`.
- Forbidden internal labels in user-facing fields (for example:
  `final response emitted via chat_reply`).
- On fail, renderer must not show the raw contract payload in the primary lane.

## Rendering Contract

- Primary chat surface is rendered from these blocks only:
  - `Outcome`
  - `Interpretation`
  - `Results`
  - `Actions`
- Artifact hub remains supplementary and should not duplicate the full primary payload.
- Transport/debug/system fields must never be shown in the primary lane.
