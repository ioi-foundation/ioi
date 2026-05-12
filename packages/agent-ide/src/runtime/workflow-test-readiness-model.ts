import type {
  Node,
  WorkflowProject,
  WorkflowTestCase,
  WorkflowTestRunResult,
  WorkflowTestStatus,
} from "../types/graph";

export type WorkflowUnitTestResult = WorkflowTestRunResult["results"][number];

export type WorkflowUnitTestRow = {
  test: WorkflowTestCase;
  latestResult: WorkflowUnitTestResult | null;
  targetNode: Node | null;
  status: WorkflowTestStatus;
  message: string;
};

export type WorkflowTestReadinessStatusCounts = Partial<
  Record<WorkflowTestStatus, number>
>;

export type WorkflowTestReadinessModelInput = {
  workflow: WorkflowProject;
  tests: WorkflowTestCase[];
  testResult: WorkflowTestRunResult | null;
  searchQuery: string;
};

export type WorkflowTestReadinessModel = {
  normalizedSearch: string;
  totalTests: number;
  coveredNodeIds: Set<string>;
  uncoveredNodes: Node[];
  statusCounts: WorkflowTestReadinessStatusCounts;
  resultById: Map<string, WorkflowUnitTestResult>;
  rows: WorkflowUnitTestRow[];
};

function workflowTestMatchesSearch(
  test: WorkflowTestCase,
  normalizedSearch: string,
): boolean {
  if (!normalizedSearch) return true;
  return [
    test.id,
    test.name,
    test.status,
    test.lastMessage,
    test.assertion.kind,
    ...test.targetNodeIds,
  ]
    .join(" ")
    .toLowerCase()
    .includes(normalizedSearch);
}

export function workflowTestReadinessModel({
  workflow,
  tests,
  testResult,
  searchQuery,
}: WorkflowTestReadinessModelInput): WorkflowTestReadinessModel {
  const normalizedSearch = searchQuery.trim().toLowerCase();
  const resultById = new Map(
    (testResult?.results ?? []).map((result) => [result.testId, result]),
  );
  const coveredNodeIds = new Set(tests.flatMap((test) => test.targetNodeIds));
  const uncoveredNodes = workflow.nodes.filter(
    (nodeItem) => !coveredNodeIds.has(nodeItem.id),
  );
  const statusCounts = tests.reduce<WorkflowTestReadinessStatusCounts>(
    (counts, test) => {
      const status = test.status ?? "idle";
      counts[status] = (counts[status] ?? 0) + 1;
      return counts;
    },
    {},
  );
  const rows = tests
    .filter((test) => workflowTestMatchesSearch(test, normalizedSearch))
    .map<WorkflowUnitTestRow>((test) => {
      const latestResult = resultById.get(test.id) ?? null;
      const targetNode = test.targetNodeIds[0]
        ? (workflow.nodes.find(
            (nodeItem) => nodeItem.id === test.targetNodeIds[0],
          ) ?? null)
        : null;
      return {
        test,
        latestResult,
        targetNode,
        status: latestResult?.status ?? test.status ?? "idle",
        message:
          latestResult?.message ||
          test.lastMessage ||
          `${test.targetNodeIds.length} covered targets`,
      };
    });

  return {
    normalizedSearch,
    totalTests: tests.length,
    coveredNodeIds,
    uncoveredNodes,
    statusCounts,
    resultById,
    rows,
  };
}
