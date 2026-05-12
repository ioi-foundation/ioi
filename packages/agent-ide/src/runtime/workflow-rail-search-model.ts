import type { WorkflowProject, WorkflowTestCase } from "../types/graph";
import {
  workflowRailSearchResults,
  type WorkflowRailSearchResult,
} from "./workflow-rail-model";

export type WorkflowRailSearchResultKind = WorkflowRailSearchResult["resultKind"];

export type WorkflowRailSearchRow = WorkflowRailSearchResult & {
  actionable: boolean;
};

export type WorkflowRailSearchCounts = Record<WorkflowRailSearchResultKind, number>;

export interface WorkflowRailSearchGroup {
  resultKind: WorkflowRailSearchResultKind;
  count: number;
  results: WorkflowRailSearchRow[];
}

export interface WorkflowRailSearchModelInput {
  workflow: WorkflowProject;
  tests: WorkflowTestCase[];
  searchQuery: string;
  visibleLimit?: number;
}

export interface WorkflowRailSearchModel {
  normalizedSearch: string;
  hasQuery: boolean;
  totalNodes: number;
  totalTests: number;
  outputCount: number;
  totalIndexed: number;
  results: WorkflowRailSearchRow[];
  visibleResults: WorkflowRailSearchRow[];
  hiddenResultCount: number;
  actionableResultCount: number;
  resultKindCounts: WorkflowRailSearchCounts;
  resultGroups: WorkflowRailSearchGroup[];
  emptyTitle: string;
  emptyDescription: string;
}

const SEARCH_RESULT_KINDS: WorkflowRailSearchResultKind[] = [
  "Node",
  "Test",
  "Output",
];

export function workflowRailSearchModel({
  workflow,
  tests,
  searchQuery,
  visibleLimit = 18,
}: WorkflowRailSearchModelInput): WorkflowRailSearchModel {
  const normalizedSearch = searchQuery.trim().toLowerCase();
  const outputCount = workflow.nodes.filter(
    (nodeItem) => nodeItem.type === "output",
  ).length;
  const results = workflowRailSearchResults(
    workflow,
    tests,
    normalizedSearch,
  ).map((item) => ({
    ...item,
    actionable: Boolean(item.nodeId),
  }));
  const resultKindCounts = SEARCH_RESULT_KINDS.reduce(
    (counts, resultKind) => {
      counts[resultKind] = results.filter(
        (item) => item.resultKind === resultKind,
      ).length;
      return counts;
    },
    { Node: 0, Test: 0, Output: 0 } as WorkflowRailSearchCounts,
  );
  const resultGroups = SEARCH_RESULT_KINDS.map((resultKind) => {
    const groupedResults = results.filter(
      (item) => item.resultKind === resultKind,
    );
    return {
      resultKind,
      count: groupedResults.length,
      results: groupedResults,
    };
  }).filter((group) => group.count > 0);
  const visibleResults = results.slice(0, Math.max(0, visibleLimit));

  return {
    normalizedSearch,
    hasQuery: normalizedSearch.length > 0,
    totalNodes: workflow.nodes.length,
    totalTests: tests.length,
    outputCount,
    totalIndexed: workflow.nodes.length + tests.length + outputCount,
    results,
    visibleResults,
    hiddenResultCount: Math.max(0, results.length - visibleResults.length),
    actionableResultCount: results.filter((item) => item.actionable).length,
    resultKindCounts,
    resultGroups,
    emptyTitle: normalizedSearch.length > 0 ? "No matches" : "No indexed items",
    emptyDescription:
      normalizedSearch.length > 0
        ? "Try a node name, binding, test id, status, or output format."
        : "Add nodes, tests, or outputs before using workflow search.",
  };
}
