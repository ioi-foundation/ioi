import type { Node, WorkflowNodeFixture } from "../types/graph";
import { workflowOutputBundleSchema } from "./workflow-schema";

export function stableStringHash(value: unknown): string {
  const text = typeof value === "string" ? value : JSON.stringify(value ?? null);
  let hash = 0;
  for (let index = 0; index < text.length; index += 1) {
    hash = (hash * 31 + text.charCodeAt(index)) >>> 0;
  }
  return hash.toString(16).padStart(8, "0");
}

export function groupFixturesByNodeId(fixtures: WorkflowNodeFixture[]): Record<string, WorkflowNodeFixture[]> {
  return fixtures.reduce<Record<string, WorkflowNodeFixture[]>>((grouped, fixture) => {
    grouped[fixture.nodeId] = [...(grouped[fixture.nodeId] ?? []), fixture];
    return grouped;
  }, {});
}

export function workflowFixtureHashesForNode(
  node: Node,
): Pick<WorkflowNodeFixture, "schemaHash" | "nodeConfigHash"> {
  return {
    schemaHash: stableStringHash(workflowOutputSchemaForNode(node) ?? {}),
    nodeConfigHash: stableStringHash(node.config ?? {}),
  };
}

function workflowOutputSchemaForNode(node: Node): Record<string, unknown> | null {
  const logic = node.config?.logic ?? {};
  const schema = logic.outputSchema ?? logic.functionBinding?.outputSchema;
  if (!schema && node.type === "output") {
    return workflowOutputBundleSchema() as Record<string, unknown>;
  }
  return schema && typeof schema === "object" && !Array.isArray(schema)
    ? schema as Record<string, unknown>
    : null;
}

export function workflowFixtureValidationForNode(
  node: Node,
  output: unknown,
): Pick<WorkflowNodeFixture, "validationStatus" | "validationMessage"> {
  const schema = workflowOutputSchemaForNode(node);
  if (!schema) {
    return {
      validationStatus: "not_declared",
      validationMessage: "No output schema is declared for this node.",
    };
  }
  if (output === undefined || output === null) {
    return {
      validationStatus: "failed",
      validationMessage: "Fixture does not include captured output.",
    };
  }
  const schemaType = typeof schema.type === "string" ? schema.type : "object";
  const isObject = output !== null && typeof output === "object" && !Array.isArray(output);
  if (schemaType === "object" && !isObject) {
    return {
      validationStatus: "failed",
      validationMessage: "Fixture output is not an object.",
    };
  }
  const required = Array.isArray(schema.required) ? schema.required.filter((item): item is string => typeof item === "string") : [];
  if (isObject && required.length > 0) {
    const outputRecord = output as Record<string, unknown>;
    const missing = required.filter((key) => !(key in outputRecord));
    if (missing.length > 0) {
      return {
        validationStatus: "failed",
        validationMessage: `Missing required output fields: ${missing.join(", ")}.`,
      };
    }
  }
  return {
    validationStatus: "passed",
    validationMessage: "Fixture output matches the current output schema.",
  };
}

export function workflowFixtureWithFreshness(
  node: Node,
  fixture: WorkflowNodeFixture,
): WorkflowNodeFixture {
  const hashes = workflowFixtureHashesForNode(node);
  const stale =
    Boolean(fixture.stale) ||
    (fixture.schemaHash ? fixture.schemaHash !== hashes.schemaHash : false) ||
    (fixture.nodeConfigHash ? fixture.nodeConfigHash !== hashes.nodeConfigHash : false);
  const validation = stale
    ? {
        validationStatus: "stale" as const,
        validationMessage: "Fixture was captured before the current node schema or configuration.",
      }
    : fixture.validationStatus
      ? {
          validationStatus: fixture.validationStatus,
          validationMessage: fixture.validationMessage,
        }
      : workflowFixtureValidationForNode(node, fixture.output);
  return { ...fixture, stale, ...validation };
}

export function workflowFixturesForNode(
  node: Node | null,
  fixturesByNodeId: Record<string, WorkflowNodeFixture[]>,
): WorkflowNodeFixture[] {
  if (!node) return [];
  return (fixturesByNodeId[node.id] ?? [])
    .map((fixture) => workflowFixtureWithFreshness(node, fixture))
    .sort((left, right) => {
      if (Boolean(left.pinned) !== Boolean(right.pinned)) {
        return left.pinned ? -1 : 1;
      }
      return right.createdAtMs - left.createdAtMs;
    });
}

export function workflowFixtureSourceLabel(fixture: WorkflowNodeFixture): string {
  if (fixture.sourceRunId) return "captured";
  if (fixture.input !== undefined || fixture.output !== undefined) return "imported";
  return "manual";
}
