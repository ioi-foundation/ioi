import type {
  ChatContractAction,
  ChatContractEnvelopeV1,
  ChatContractInterpretation,
  ChatContractResultColumn,
  ChatContractResultRow,
  ChatContractScalar,
  ChatContractValidationIssue,
  ChatContractValue,
} from "../../../types";

const CHAT_CONTRACT_SCHEMA = "chat_contract_v1";
const FORBIDDEN_PRIMARY_LABELS = [
  "final response emitted via chat_reply",
  "terminal_chat_reply_emitted",
  "terminal_tool_output_suppressed_for_chat_reply",
];

interface ChatContractValidationResult {
  valid: boolean;
  envelope: ChatContractEnvelopeV1 | null;
  issues: ChatContractValidationIssue[];
}

interface ChatContractParseResult {
  envelope: ChatContractEnvelopeV1 | null;
  issues: ChatContractValidationIssue[];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isScalar(value: unknown): value is ChatContractScalar {
  return (
    value === null ||
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean"
  );
}

function trimString(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function pushIssue(
  issues: ChatContractValidationIssue[],
  path: string,
  code: string,
  message: string,
): void {
  issues.push({ path, code, message });
}

function validateOutcome(
  value: unknown,
  issues: ChatContractValidationIssue[],
): ChatContractEnvelopeV1["outcome"] | null {
  if (!isRecord(value)) {
    pushIssue(issues, "outcome", "invalid_type", "Expected object.");
    return null;
  }

  const status = trimString(value.status);
  if (!status) {
    pushIssue(issues, "outcome.status", "missing_field", "Expected non-empty status.");
    return null;
  }

  if (status !== "success" && status !== "partial" && status !== "failed") {
    pushIssue(
      issues,
      "outcome.status",
      "invalid_value",
      "Expected success, partial, or failed.",
    );
    return null;
  }

  const summary = trimString(value.summary) || undefined;
  let count: number | undefined;
  if (value.count !== undefined) {
    if (typeof value.count !== "number" || !Number.isFinite(value.count)) {
      pushIssue(issues, "outcome.count", "invalid_type", "Expected finite number.");
    } else {
      count = value.count;
    }
  }

  return {
    status,
    summary,
    count,
  };
}

function validateInterpretation(
  value: unknown,
  issues: ChatContractValidationIssue[],
): ChatContractInterpretation | null {
  if (!isRecord(value)) {
    pushIssue(issues, "interpretation", "invalid_type", "Expected object.");
    return null;
  }

  const interpretation: ChatContractInterpretation = {};
  for (const [key, raw] of Object.entries(value)) {
    const cleanKey = key.trim();
    if (!cleanKey) {
      pushIssue(issues, "interpretation", "invalid_key", "Interpretation key cannot be empty.");
      continue;
    }

    if (Array.isArray(raw)) {
      if (raw.some((entry) => !isScalar(entry))) {
        pushIssue(
          issues,
          `interpretation.${cleanKey}`,
          "invalid_type",
          "Array values must be scalar.",
        );
        continue;
      }
      interpretation[cleanKey] = raw as ChatContractScalar[];
      continue;
    }

    if (!isScalar(raw)) {
      pushIssue(
        issues,
        `interpretation.${cleanKey}`,
        "invalid_type",
        "Expected scalar or scalar array.",
      );
      continue;
    }

    interpretation[cleanKey] = raw as ChatContractValue;
  }

  return interpretation;
}

function validateResultRows(
  value: unknown,
  issues: ChatContractValidationIssue[],
): ChatContractResultRow[] | null {
  if (!Array.isArray(value)) {
    pushIssue(issues, "result_rows", "invalid_type", "Expected array.");
    return null;
  }

  const rows: ChatContractResultRow[] = [];
  value.forEach((rowValue, rowIndex) => {
    if (!isRecord(rowValue)) {
      pushIssue(
        issues,
        `result_rows[${rowIndex}]`,
        "invalid_type",
        "Each row must be an object.",
      );
      return;
    }

    const row: ChatContractResultRow = {};
    for (const [key, cell] of Object.entries(rowValue)) {
      const cleanKey = key.trim();
      if (!cleanKey) {
        pushIssue(
          issues,
          `result_rows[${rowIndex}]`,
          "invalid_key",
          "Row keys cannot be empty.",
        );
        continue;
      }

      if (!isScalar(cell)) {
        pushIssue(
          issues,
          `result_rows[${rowIndex}].${cleanKey}`,
          "invalid_type",
          "Row values must be scalar.",
        );
        continue;
      }

      row[cleanKey] = cell;
    }

    rows.push(row);
  });

  return rows;
}

function validateResultColumns(
  value: unknown,
  issues: ChatContractValidationIssue[],
): ChatContractResultColumn[] | undefined {
  if (value === undefined) {
    return undefined;
  }

  if (!Array.isArray(value)) {
    pushIssue(issues, "result_columns", "invalid_type", "Expected array.");
    return undefined;
  }

  const columns: ChatContractResultColumn[] = [];
  const seenKeys = new Set<string>();
  value.forEach((entry, index) => {
    if (!isRecord(entry)) {
      pushIssue(
        issues,
        `result_columns[${index}]`,
        "invalid_type",
        "Each column must be an object.",
      );
      return;
    }

    const key = trimString(entry.key);
    const label = trimString(entry.label);
    if (!key) {
      pushIssue(
        issues,
        `result_columns[${index}].key`,
        "missing_field",
        "Column key is required.",
      );
      return;
    }
    if (!label) {
      pushIssue(
        issues,
        `result_columns[${index}].label`,
        "missing_field",
        "Column label is required.",
      );
      return;
    }

    if (seenKeys.has(key)) {
      pushIssue(
        issues,
        `result_columns[${index}].key`,
        "duplicate",
        "Duplicate column key.",
      );
      return;
    }
    seenKeys.add(key);
    columns.push({ key, label });
  });

  return columns;
}

function validateActions(
  value: unknown,
  issues: ChatContractValidationIssue[],
): ChatContractAction[] | undefined {
  if (value === undefined) {
    return undefined;
  }

  if (!Array.isArray(value)) {
    pushIssue(issues, "actions", "invalid_type", "Expected array.");
    return undefined;
  }

  const actions: ChatContractAction[] = [];
  const seenIds = new Set<string>();
  value.forEach((entry, index) => {
    if (!isRecord(entry)) {
      pushIssue(issues, `actions[${index}]`, "invalid_type", "Each action must be an object.");
      return;
    }

    const id = trimString(entry.id);
    const label = trimString(entry.label);
    if (!id) {
      pushIssue(issues, `actions[${index}].id`, "missing_field", "Action id is required.");
      return;
    }
    if (!label) {
      pushIssue(issues, `actions[${index}].label`, "missing_field", "Action label is required.");
      return;
    }
    if (seenIds.has(id)) {
      pushIssue(issues, `actions[${index}].id`, "duplicate", "Duplicate action id.");
      return;
    }
    seenIds.add(id);
    actions.push({ id, label });
  });

  return actions;
}

function formatScalar(value: ChatContractScalar): string {
  if (value === null) return "null";
  return String(value);
}

function formatValue(value: ChatContractValue): string {
  if (Array.isArray(value)) {
    return value.map((entry) => formatScalar(entry)).join(", ");
  }
  return formatScalar(value);
}

function lintForbiddenLabels(
  envelope: ChatContractEnvelopeV1,
  issues: ChatContractValidationIssue[],
): void {
  const inputs: string[] = [];
  if (envelope.outcome.summary) {
    inputs.push(envelope.outcome.summary);
  }
  if (envelope.answer_markdown) {
    inputs.push(envelope.answer_markdown);
  }
  for (const value of Object.values(envelope.interpretation)) {
    inputs.push(formatValue(value));
  }
  for (const row of envelope.result_rows) {
    for (const value of Object.values(row)) {
      inputs.push(formatScalar(value));
    }
  }

  const fullText = inputs.join("\n").toLowerCase();
  for (const forbidden of FORBIDDEN_PRIMARY_LABELS) {
    if (fullText.includes(forbidden)) {
      pushIssue(
        issues,
        "primary_lane",
        "forbidden_internal_label",
        `Forbidden internal label in primary lane: ${forbidden}`,
      );
    }
  }
}

export function validateChatContractEnvelope(value: unknown): ChatContractValidationResult {
  const issues: ChatContractValidationIssue[] = [];
  if (!isRecord(value)) {
    pushIssue(issues, "", "invalid_type", "Expected top-level object.");
    return { valid: false, envelope: null, issues };
  }

  const schemaVersion = trimString(value.schema_version);
  if (!schemaVersion) {
    pushIssue(issues, "schema_version", "missing_field", "schema_version is required.");
    return { valid: false, envelope: null, issues };
  }

  if (schemaVersion !== CHAT_CONTRACT_SCHEMA) {
    pushIssue(
      issues,
      "schema_version",
      "unsupported_schema",
      `Expected ${CHAT_CONTRACT_SCHEMA}.`,
    );
    return { valid: false, envelope: null, issues };
  }

  const intentId = trimString(value.intent_id);
  if (!intentId) {
    pushIssue(issues, "intent_id", "missing_field", "intent_id is required.");
  }

  const outcome = validateOutcome(value.outcome, issues);
  const interpretation = validateInterpretation(value.interpretation, issues);
  const resultRows = validateResultRows(value.result_rows, issues);
  const resultColumns = validateResultColumns(value.result_columns, issues);
  const actions = validateActions(value.actions, issues);
  const artifactRefRaw = value.artifact_ref;
  const answerMarkdownRaw = value.answer_markdown;

  const artifactRef =
    artifactRefRaw === undefined
      ? undefined
      : typeof artifactRefRaw === "string" && artifactRefRaw.trim().length > 0
        ? artifactRefRaw.trim()
        : (pushIssue(
            issues,
            "artifact_ref",
            "invalid_type",
            "artifact_ref must be a non-empty string.",
          ),
          undefined);

  const answerMarkdown =
    answerMarkdownRaw === undefined
      ? undefined
      : typeof answerMarkdownRaw === "string"
        ? answerMarkdownRaw
        : (pushIssue(
            issues,
            "answer_markdown",
            "invalid_type",
            "answer_markdown must be a string.",
          ),
          undefined);

  if (!intentId || !outcome || !interpretation || !resultRows) {
    return { valid: false, envelope: null, issues };
  }

  const envelope: ChatContractEnvelopeV1 = {
    schema_version: CHAT_CONTRACT_SCHEMA,
    intent_id: intentId,
    outcome,
    interpretation,
    result_rows: resultRows,
    result_columns: resultColumns,
    actions,
    artifact_ref: artifactRef,
    answer_markdown: answerMarkdown,
  };

  lintForbiddenLabels(envelope, issues);
  return { valid: issues.length === 0, envelope: issues.length === 0 ? envelope : null, issues };
}

export function parseChatContractEnvelope(rawText: string): ChatContractParseResult {
  const trimmed = rawText.trim();
  if (!trimmed.startsWith("{") || !trimmed.endsWith("}")) {
    return { envelope: null, issues: [] };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    return {
      envelope: null,
      issues: [
        {
          path: "",
          code: "invalid_json",
          message: "Response looked like JSON but could not be parsed.",
        },
      ],
    };
  }

  const validated = validateChatContractEnvelope(parsed);
  return { envelope: validated.envelope, issues: validated.issues };
}

export function formatChatContractForClipboard(envelope: ChatContractEnvelopeV1): string {
  const lines: string[] = [];
  lines.push(`Intent: ${envelope.intent_id}`);
  const countLabel =
    typeof envelope.outcome.count === "number" ? ` (${envelope.outcome.count})` : "";
  lines.push(`Outcome: ${envelope.outcome.status}${countLabel}`);
  if (envelope.outcome.summary) {
    lines.push(`Summary: ${envelope.outcome.summary}`);
  }

  const interpretationEntries = Object.entries(envelope.interpretation);
  if (interpretationEntries.length > 0) {
    lines.push("Interpretation:");
    for (const [key, value] of interpretationEntries) {
      lines.push(`- ${key}: ${formatValue(value)}`);
    }
  }

  if (envelope.result_rows.length > 0) {
    const columns =
      envelope.result_columns?.length
        ? envelope.result_columns
        : Object.keys(envelope.result_rows[0]).map((key) => ({ key, label: key }));

    lines.push("Results:");
    envelope.result_rows.forEach((row, rowIndex) => {
      const cells = columns
        .map((column) => {
          const value = row[column.key];
          if (value === undefined) {
            return null;
          }
          return `${column.label}: ${formatScalar(value)}`;
        })
        .filter((entry): entry is string => !!entry);
      lines.push(`${rowIndex + 1}. ${cells.join(" | ")}`);
    });
  }

  if (envelope.actions?.length) {
    lines.push("Actions:");
    envelope.actions.forEach((action) => lines.push(`- ${action.label} (${action.id})`));
  }

  if (envelope.artifact_ref) {
    lines.push(`Artifact: ${envelope.artifact_ref}`);
  }

  return lines.join("\n");
}

