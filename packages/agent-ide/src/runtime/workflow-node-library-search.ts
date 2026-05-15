import type { WorkflowCompositionHelperDefinition } from "./workflow-composition-helpers";
import type {
  WorkflowNodeCreatorDefinition,
  WorkflowNodeDefinition,
} from "./workflow-node-registry";
import type {
  WorkflowCanonicalPrimitive,
  WorkflowPaletteVisibility,
} from "./workflow-node-taxonomy";

export interface WorkflowNodeLibrarySearchContext {
  scaffoldKeywords?: string[];
  scaffoldConnectionClasses?: string[];
  actionDescription?: string;
  actionRequiredBinding?: string | null;
  actionSideEffectClass?: string;
  actionKeywords?: string[];
  actionConnectionClasses?: string[];
  actionRequiresApproval?: boolean;
  actionSupportsMockBinding?: boolean;
  actionSchemaRequired?: boolean;
}

export interface WorkflowNodeLibrarySearchResult<T> {
  item: T;
  score: number;
  matchedTerms: string[];
}

type SearchableWorkflowNode =
  | WorkflowNodeDefinition
  | WorkflowNodeCreatorDefinition;

const AUTHORING_SYNONYMS: Record<string, string[]> = {
  agent: ["agent step", "model call", "model", "reasoning"],
  approval: ["approval", "human gate", "policy gate", "review gate"],
  browser: ["browser use", "web automation", "chromium", "cdp", "selector"],
  computer: ["computer use", "gui", "desktop", "screen", "cua"],
  cua: ["computer use", "visual gui", "screenshot", "coordinate"],
  desktop: ["computer use", "visual gui", "gui", "screen"],
  gui: ["computer use", "visual gui", "desktop", "screen"],
  hosted: ["hosted computer", "sandboxed computer", "sandbox", "vm"],
  memory: ["memory", "recall", "remember", "retention"],
  policy: ["policy", "policy gate", "approval", "authority", "guardrail"],
  pr: ["pr", "pull request", "github pr", "review gate"],
  pull: ["pull request", "pr"],
  repo: ["repo", "repository", "github", "branch"],
  repository: ["repo", "repository", "github", "branch"],
  skills: ["skills", "skill", "skill pack", "skill context"],
  skill: ["skills", "skill", "skill pack", "skill context"],
  sandbox: ["sandboxed computer", "hosted computer", "vm", "container", "eval"],
  sandboxed: ["sandboxed computer", "hosted computer", "sandbox", "vm"],
  terminal: [
    "terminal",
    "terminal coding loop",
    "tui",
    "slash loop",
    "shell",
    "coding tool",
  ],
  tool: ["tool", "tool pack", "capability", "mcp", "browser", "coding tool"],
  worker: ["worker", "subagent", "sub agent", "child agent", "worker pool"],
};

const QUERY_PRIMITIVE_BOOSTS: Array<{
  terms: string[];
  primitives: WorkflowCanonicalPrimitive[];
}> = [
  { terms: ["agent", "model", "reasoning"], primitives: ["agent_step"] },
  { terms: ["worker", "subagent", "child agent"], primitives: ["worker"] },
  { terms: ["terminal", "tui", "slash loop", "shell"], primitives: ["tool_pack"] },
  {
    terms: [
      "tool",
      "mcp",
      "capability",
      "browser",
      "browser use",
      "computer",
      "computer use",
      "cua",
      "gui",
      "desktop",
      "sandbox",
    ],
    primitives: ["tool_pack"],
  },
  { terms: ["pull request", "pr"], primitives: ["pull_request"] },
  { terms: ["repo", "repository", "github"], primitives: ["context", "pull_request"] },
  { terms: ["skills", "skill"], primitives: ["skills"] },
  { terms: ["memory", "remember", "recall"], primitives: ["memory"] },
  { terms: ["policy", "approval", "authority"], primitives: ["policy_gate"] },
  { terms: ["output", "artifact", "deliver"], primitives: ["output"] },
];

const PALETTE_SCORE: Record<WorkflowPaletteVisibility, number> = {
  default: 24,
  template: 20,
  advanced: -24,
  hidden: -48,
};

function normalizeSearchText(value: string): string {
  return value
    .toLowerCase()
    .replace(/[_./:-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function tokenize(value: string): string[] {
  const normalized = normalizeSearchText(value);
  if (!normalized) return [];
  return normalized.split(" ").filter(Boolean);
}

function uniqueStrings(values: Array<string | null | undefined>): string[] {
  return Array.from(
    new Set(
      values
        .map((value) => (value ? normalizeSearchText(value) : ""))
        .filter(Boolean),
    ),
  );
}

function expandedQueryTerms(query: string): string[] {
  const normalizedQuery = normalizeSearchText(query);
  const tokens = tokenize(query);
  return uniqueStrings([
    normalizedQuery,
    ...tokens,
    ...tokens.flatMap((token) => AUTHORING_SYNONYMS[token] ?? []),
    ...(AUTHORING_SYNONYMS[normalizedQuery] ?? []),
  ]);
}

function fieldTokens(fields: string[]): Set<string> {
  return new Set(fields.flatMap((field) => tokenize(field)));
}

function scoreFields(
  query: string,
  fields: Array<{ value: string; weight: number }>,
): { score: number; matchedTerms: string[] } {
  const terms = expandedQueryTerms(query);
  if (terms.length === 0) {
    return { score: 0, matchedTerms: [] };
  }

  const normalizedFields = fields
    .map((field) => ({
      value: normalizeSearchText(field.value),
      weight: field.weight,
    }))
    .filter((field) => field.value);
  const tokens = fieldTokens(normalizedFields.map((field) => field.value));
  const matchedTerms: string[] = [];
  let score = 0;

  for (const term of terms) {
    const termTokens = tokenize(term);
    let termScore = 0;
    for (const field of normalizedFields) {
      if (field.value === term) {
        termScore = Math.max(termScore, field.weight);
      } else if (term.length >= 3 && field.value.startsWith(term)) {
        termScore = Math.max(termScore, field.weight - 4);
      } else if (tokens.has(term)) {
        termScore = Math.max(termScore, field.weight - 8);
      } else if (
        term.length >= 3 &&
        Array.from(tokens).some((token) => token.startsWith(term))
      ) {
        termScore = Math.max(termScore, field.weight - 14);
      } else if (term.length >= 3 && field.value.includes(term)) {
        termScore = Math.max(termScore, field.weight - 22);
      } else if (
        termTokens.length > 1 &&
        termTokens.every((termToken) => tokens.has(termToken))
      ) {
        termScore = Math.max(termScore, field.weight - 12);
      }
    }
    if (termScore > 0) {
      matchedTerms.push(term);
      score += termScore;
    }
  }

  return {
    score,
    matchedTerms: uniqueStrings(matchedTerms),
  };
}

function primitiveBoost(
  query: string,
  primitive: WorkflowCanonicalPrimitive,
): number {
  const terms = expandedQueryTerms(query);
  for (const boost of QUERY_PRIMITIVE_BOOSTS) {
    if (
      boost.primitives.includes(primitive) &&
      boost.terms.some((term) => terms.includes(normalizeSearchText(term)))
    ) {
      return 48;
    }
  }
  return 0;
}

function itemBaseFields(
  item: SearchableWorkflowNode,
  context: WorkflowNodeLibrarySearchContext,
): Array<{ value: string; weight: number }> {
  return [
    { value: item.displayLabel, weight: 96 },
    { value: item.label, weight: 88 },
    { value: item.canonicalPrimitive.replace(/_/g, " "), weight: 82 },
    { value: "creatorId" in item ? item.creatorId : item.type, weight: 78 },
    { value: item.type, weight: 74 },
    { value: item.group, weight: 68 },
    { value: item.familyLabel, weight: 64 },
    { value: item.metricLabel, weight: 56 },
    { value: item.metricValue, weight: 48 },
    {
      value: "creatorDescription" in item ? item.creatorDescription : "",
      weight: 42,
    },
    { value: context.actionDescription ?? "", weight: 36 },
    { value: context.actionRequiredBinding ?? "", weight: 34 },
    { value: context.actionSideEffectClass ?? "", weight: 32 },
    ...item.searchAliases.map((value) => ({ value, weight: 72 })),
    ...(context.scaffoldKeywords ?? []).map((value) => ({ value, weight: 44 })),
    ...(context.scaffoldConnectionClasses ?? []).map((value) => ({
      value,
      weight: 42,
    })),
    ...(context.actionKeywords ?? []).map((value) => ({ value, weight: 44 })),
    ...(context.actionConnectionClasses ?? []).map((value) => ({
      value,
      weight: 42,
    })),
    {
      value: context.actionRequiresApproval ? "approval policy gate" : "",
      weight: 46,
    },
    {
      value: context.actionSupportsMockBinding ? "mock live credential" : "",
      weight: 32,
    },
    {
      value: context.actionSchemaRequired ? "schema typed contract" : "",
      weight: 30,
    },
  ];
}

function exactAuthoringIntentBoost(
  query: string,
  item: SearchableWorkflowNode,
): number {
  const exactFields = uniqueStrings([
    item.label,
    item.displayLabel,
    "creatorId" in item ? item.creatorId : item.type,
    ...item.searchAliases,
  ]);
  return exactFields.includes(normalizeSearchText(query)) ? 220 : 0;
}

export function rankWorkflowNodeLibrary<T extends SearchableWorkflowNode>(
  items: T[],
  query: string,
  contextForItem: (item: T) => WorkflowNodeLibrarySearchContext = () => ({}),
): Array<WorkflowNodeLibrarySearchResult<T>> {
  const normalizedQuery = normalizeSearchText(query);
  if (!normalizedQuery) {
    return items.map((item) => ({ item, score: 0, matchedTerms: [] }));
  }

  return items
    .map((item, index) => {
      const context = contextForItem(item);
      const scored = scoreFields(
        normalizedQuery,
        itemBaseFields(item, context),
      );
      return {
        item,
        score:
          scored.score +
          exactAuthoringIntentBoost(normalizedQuery, item) +
          primitiveBoost(normalizedQuery, item.canonicalPrimitive) +
          PALETTE_SCORE[item.paletteVisibility],
        matchedTerms: scored.matchedTerms,
        index,
      };
    })
    .filter((result) => result.score > 0 && result.matchedTerms.length > 0)
    .sort((left, right) => {
      if (right.score !== left.score) return right.score - left.score;
      const leftVisibility = PALETTE_SCORE[left.item.paletteVisibility];
      const rightVisibility = PALETTE_SCORE[right.item.paletteVisibility];
      if (rightVisibility !== leftVisibility)
        return rightVisibility - leftVisibility;
      return (
        left.item.displayLabel.localeCompare(right.item.displayLabel) ||
        left.index - right.index
      );
    })
    .map(({ index: _index, ...result }) => result);
}

export function searchWorkflowNodeLibrary<T extends SearchableWorkflowNode>(
  items: T[],
  query: string,
  contextForItem?: (item: T) => WorkflowNodeLibrarySearchContext,
): T[] {
  return rankWorkflowNodeLibrary(items, query, contextForItem).map(
    (result) => result.item,
  );
}

export function rankWorkflowCompositionHelpers(
  helpers: WorkflowCompositionHelperDefinition[],
  query: string,
): Array<WorkflowNodeLibrarySearchResult<WorkflowCompositionHelperDefinition>> {
  const normalizedQuery = normalizeSearchText(query);
  if (!normalizedQuery) {
    return helpers.map((item) => ({ item, score: 0, matchedTerms: [] }));
  }
  return helpers
    .map((helper, index) => {
      const scored = scoreFields(normalizedQuery, [
        { value: helper.label, weight: 96 },
        { value: helper.canonicalPrimitive.replace(/_/g, " "), weight: 82 },
        { value: helper.helperId, weight: 78 },
        { value: helper.description, weight: 44 },
        ...helper.searchAliases.map((value) => ({ value, weight: 76 })),
      ]);
      return {
        item: helper,
        score:
          scored.score +
          primitiveBoost(normalizedQuery, helper.canonicalPrimitive) +
          PALETTE_SCORE[helper.paletteVisibility] +
          18,
        matchedTerms: scored.matchedTerms,
        index,
      };
    })
    .filter((result) => result.score > 0 && result.matchedTerms.length > 0)
    .sort((left, right) => {
      if (right.score !== left.score) return right.score - left.score;
      return left.item.label.localeCompare(right.item.label) || left.index - right.index;
    })
    .map(({ index: _index, ...result }) => result);
}

export function searchWorkflowCompositionHelpers(
  helpers: WorkflowCompositionHelperDefinition[],
  query: string,
): WorkflowCompositionHelperDefinition[] {
  return rankWorkflowCompositionHelpers(helpers, query).map(
    (result) => result.item,
  );
}
