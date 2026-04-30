import type { Node } from "../types/graph";

export interface WorkflowSchemaFieldReference {
  path: string;
  label: string;
  type: string;
}

export function schemaFromSample(value: unknown): unknown {
  if (Array.isArray(value)) {
    return {
      type: "array",
      items: value.length > 0 ? schemaFromSample(value[0]) : { type: "unknown" },
    };
  }
  if (value && typeof value === "object") {
    return {
      type: "object",
      properties: Object.fromEntries(
        Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, schemaFromSample(child)]),
      ),
    };
  }
  return { type: value === null ? "null" : typeof value };
}

export function workflowSchemaIsObjectLike(schema: unknown): boolean {
  return Boolean(
    schema &&
      typeof schema === "object" &&
      !Array.isArray(schema) &&
      String((schema as Record<string, unknown>).type ?? "").trim().length > 0,
  );
}

export function workflowOutputBundleSchema(): unknown {
  return {
    type: "object",
    required: ["kind", "nodeId", "outputBundle"],
    properties: {
      kind: { type: "string" },
      nodeId: { type: "string" },
      outputName: { type: "string" },
      outputBundle: {
        type: "object",
        required: ["id", "nodeId", "format", "value", "createdAtMs"],
        properties: {
          id: { type: "string" },
          nodeId: { type: "string" },
          format: { type: "string" },
          value: { type: "unknown" },
          rendererRef: { type: "object" },
          materializedAssets: { type: "array" },
          deliveryTarget: { type: "object" },
          dependencyRefs: { type: "array" },
          evidenceRefs: { type: "array" },
          version: { type: "object" },
          createdAtMs: { type: "number" },
        },
      },
    },
  };
}

export function workflowNodeHasDeclaredOutputSchema(node: Node): boolean {
  const logic = node.config?.logic ?? {};
  return Boolean(
    logic.functionBinding?.outputSchema ||
      (logic.toolBinding?.bindingKind === "workflow_tool" && logic.toolBinding.workflowTool?.resultSchema) ||
      logic.parserBinding?.resultSchema ||
      logic.modelBinding?.resultSchema ||
      logic.outputSchema ||
      logic.schema ||
      node.type === "output" ||
      node.type === "model_call" ||
      node.type === "model_binding" ||
      node.type === "parser" ||
      node.type === "adapter" ||
      node.type === "plugin_tool" ||
      node.type === "state",
  );
}

export function workflowNodeDeclaredOutputSchema(node: Node, latestOutput?: unknown): unknown {
  const logic = node.config?.logic ?? {};
  if (logic.functionBinding?.outputSchema) return logic.functionBinding.outputSchema;
  if (logic.toolBinding?.bindingKind === "workflow_tool" && logic.toolBinding.workflowTool?.resultSchema) {
    return logic.toolBinding.workflowTool.resultSchema;
  }
  if (logic.parserBinding?.resultSchema) return logic.parserBinding.resultSchema;
  if (logic.modelBinding?.resultSchema) return logic.modelBinding.resultSchema;
  if (logic.outputSchema) return logic.outputSchema;
  if (logic.schema) return logic.schema;
  if (node.type === "output") return workflowOutputBundleSchema();
  if (latestOutput !== undefined && latestOutput !== null) return schemaFromSample(latestOutput);
  if (logic.payload !== undefined) return schemaFromSample(logic.payload);
  if (node.type === "model_call") return { type: "object", properties: { message: { type: "string" } } };
  if (node.type === "model_binding") return { type: "object", properties: { modelRef: { type: "string" } } };
  if (node.type === "parser") return { type: "object" };
  if (node.type === "adapter") return { type: "object", properties: { response: { type: "object" } } };
  if (node.type === "plugin_tool") return { type: "object", properties: { result: { type: "object" } } };
  if (node.type === "state") return { type: "object", properties: { state: { type: "object" } } };
  return { type: "object" };
}

export function workflowNodeDeclaredInputSchema(node: Node): unknown {
  const logic = node.config?.logic ?? {};
  if (logic.functionBinding?.inputSchema) return logic.functionBinding.inputSchema;
  if (logic.toolBinding?.bindingKind === "workflow_tool" && logic.toolBinding.workflowTool?.argumentSchema) {
    return logic.toolBinding.workflowTool.argumentSchema;
  }
  if (logic.inputSchema) return logic.inputSchema;
  if (node.type === "model_binding") return { type: "object" };
  if (node.type === "parser") return { type: "object" };
  if (logic.schema && node.type === "source") return logic.schema;
  if (logic.testInput !== undefined) return schemaFromSample(logic.testInput);
  if (logic.functionBinding?.testInput !== undefined) return schemaFromSample(logic.functionBinding.testInput);
  if (node.type === "model_call") return { type: "object", properties: { prompt: { type: "string" } } };
  if (node.type === "decision") return { type: "object", properties: { value: { type: "unknown" } } };
  if (node.type === "output") return { type: "object", properties: { value: { type: "unknown" } } };
  return { type: "object" };
}

export function workflowSchemaFieldReferences(schema: unknown, latestOutput?: unknown): WorkflowSchemaFieldReference[] {
  const fields: WorkflowSchemaFieldReference[] = [];
  const seen = new Set<string>();
  const pushField = (path: string, label: string, type: string) => {
    if (!path || seen.has(path)) return;
    seen.add(path);
    fields.push({ path, label, type });
  };
  const visitSchema = (value: unknown, path: string[] = []) => {
    if (!value || typeof value !== "object" || fields.length >= 12) return;
    const record = value as Record<string, unknown>;
    const type = String(record.type ?? "unknown");
    if (path.length > 0) pushField(path.join("."), path[path.length - 1], type);
    if (type === "object" && record.properties && typeof record.properties === "object") {
      for (const [key, child] of Object.entries(record.properties as Record<string, unknown>)) {
        visitSchema(child, [...path, key]);
      }
      return;
    }
    if (type === "array" && record.items) {
      visitSchema(record.items, [...path, "[]"]);
    }
  };
  const visitSample = (value: unknown, path: string[] = []) => {
    if (fields.length >= 12 || value === null || value === undefined) return;
    if (path.length > 0) {
      pushField(path.join("."), path[path.length - 1], Array.isArray(value) ? "array" : typeof value);
    }
    if (Array.isArray(value)) {
      if (value.length > 0) visitSample(value[0], [...path, "[]"]);
      return;
    }
    if (typeof value === "object") {
      for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
        visitSample(child, [...path, key]);
      }
    }
  };
  visitSchema(schema);
  if (fields.length === 0) visitSample(latestOutput);
  return fields.slice(0, 12);
}

export function workflowSchemaHasFieldPath(schema: unknown, path: string): boolean {
  const segments = path.split(".").filter(Boolean);
  if (segments.length === 0) return false;
  let current = schema;
  for (const segment of segments) {
    if (!current || typeof current !== "object" || Array.isArray(current)) return false;
    const record = current as Record<string, unknown>;
    if (segment === "[]") {
      if (record.type !== "array" || !record.items) return false;
      current = record.items;
      continue;
    }
    const properties = record.properties;
    if (!properties || typeof properties !== "object" || Array.isArray(properties)) return false;
    if (!(segment in properties)) return false;
    current = (properties as Record<string, unknown>)[segment];
  }
  return true;
}

export function workflowExpressionReferences(value: unknown): Array<{ expression: string; nodeId: string; portId: string }> {
  const references: Array<{ expression: string; nodeId: string; portId: string }> = [];
  const visit = (next: unknown) => {
    if (typeof next === "string") {
      const pattern = /\{\{\s*nodes\.([A-Za-z0-9_.:-]+)\.([A-Za-z0-9_.:-]+)\s*\}\}/g;
      let match: RegExpExecArray | null;
      while ((match = pattern.exec(next)) !== null) {
        references.push({ expression: match[0], nodeId: match[1], portId: match[2] });
      }
      return;
    }
    if (Array.isArray(next)) {
      next.forEach(visit);
      return;
    }
    if (next && typeof next === "object") {
      Object.values(next as Record<string, unknown>).forEach(visit);
    }
  };
  visit(value);
  return references;
}

export function workflowFieldMappingEntries(value: unknown): Array<{ key: string; source: string; path: string }> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return [];
  return Object.entries(value as Record<string, unknown>)
    .map(([key, item]) => {
      if (!item || typeof item !== "object" || Array.isArray(item)) return null;
      const record = item as Record<string, unknown>;
      const source = typeof record.source === "string" ? record.source : "";
      const path = typeof record.path === "string" ? record.path : "";
      if (!source || !path) return null;
      return { key, source, path };
    })
    .filter((item): item is { key: string; source: string; path: string } => Boolean(item));
}
