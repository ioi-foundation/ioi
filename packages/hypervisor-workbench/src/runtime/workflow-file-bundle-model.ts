import type {
  WorkflowBindingManifest,
  WorkflowPortablePackage,
  WorkflowProject,
  WorkflowProposal,
  WorkflowRunSummary,
  WorkflowTestCase,
} from "../types/graph";
import {
  workflowFileBundleItems,
  type WorkflowFileBundleItem,
} from "./workflow-rail-model";

export type WorkflowFileBundleItemId =
  | "workflow-graph"
  | "tests-sidecar"
  | "proposal-sidecar"
  | "run-sidecar"
  | "binding-manifest"
  | "portable-package";

export type WorkflowFileBundleRow = WorkflowFileBundleItem & {
  id: WorkflowFileBundleItemId;
  exported: boolean;
  ready: boolean;
};

export interface WorkflowFileBundleModelInput {
  workflow: WorkflowProject;
  tests: WorkflowTestCase[];
  proposals: WorkflowProposal[];
  runs: WorkflowRunSummary[];
  portablePackage: WorkflowPortablePackage | null;
  bindingManifest?: WorkflowBindingManifest | null;
}

export interface WorkflowFileBundleModel {
  items: WorkflowFileBundleRow[];
  totalItems: number;
  workflowPath: string;
  dirty: boolean;
  testCount: number;
  proposalCount: number;
  runCount: number;
  bindingManifestReady: number | null;
  bindingManifestTotal: number | null;
  portablePackagePath: string | null;
  portablePackageExported: boolean;
  readyItems: number;
  pendingItems: number;
}

const ITEM_IDS: WorkflowFileBundleItemId[] = [
  "workflow-graph",
  "tests-sidecar",
  "proposal-sidecar",
  "run-sidecar",
  "binding-manifest",
  "portable-package",
];

function enrichItem(
  item: WorkflowFileBundleItem,
  id: WorkflowFileBundleItemId,
): WorkflowFileBundleRow {
  const pending =
    item.status === "not generated" ||
    item.status === "not exported" ||
    item.status.startsWith("blocked:");
  return {
    ...item,
    id,
    exported: id === "portable-package" ? item.status !== "not exported" : true,
    ready: !pending,
  };
}

export function workflowFileBundleModel({
  workflow,
  tests,
  proposals,
  runs,
  portablePackage,
  bindingManifest = null,
}: WorkflowFileBundleModelInput): WorkflowFileBundleModel {
  const items = workflowFileBundleItems(
    workflow,
    tests,
    proposals,
    runs,
    portablePackage,
    bindingManifest,
  ).map((item, index) => enrichItem(item, ITEM_IDS[index] ?? "workflow-graph"));
  const readyItems = items.filter((item) => item.ready).length;

  return {
    items,
    totalItems: items.length,
    workflowPath:
      workflow.metadata.gitLocation ||
      `.agents/workflows/${workflow.metadata.slug}.workflow.json`,
    dirty: workflow.metadata.dirty === true,
    testCount: tests.length,
    proposalCount: proposals.length,
    runCount: runs.length,
    bindingManifestReady: bindingManifest?.summary.ready ?? null,
    bindingManifestTotal: bindingManifest?.summary.total ?? null,
    portablePackagePath: portablePackage?.packagePath ?? null,
    portablePackageExported: portablePackage !== null,
    readyItems,
    pendingItems: items.length - readyItems,
  };
}
