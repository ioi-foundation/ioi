export interface SessionActivityEventRef<
  TEvent,
  TActivityKind extends string,
> {
  key: string;
  event: TEvent;
  kind: TActivityKind;
  toolName?: string;
  normalizedOutputHash?: string;
}

export interface SessionRunPresentation<
  TPrompt,
  TFinalAnswer,
  TSourceSummary,
  TThoughtSummary,
  TPlanSummary,
  TActivitySummary,
  TActivityGroup,
  TArtifactRef,
> {
  prompt: TPrompt | null;
  finalAnswer: TFinalAnswer | null;
  sourceSummary: TSourceSummary | null;
  thoughtSummary: TThoughtSummary | null;
  planSummary: TPlanSummary | null;
  activitySummary: TActivitySummary;
  activityGroups: TActivityGroup[];
  artifactRefs: TArtifactRef[];
}

export interface BuildSessionRunPresentationOptions<
  THistoryMessage,
  TEvent,
  TArtifact,
  TActivityKind extends string,
  TPrompt,
  TFinalAnswer,
  TSourceSummary,
  TThoughtSummary,
  TPlanSummary,
  TActivitySummary,
  TActivityGroup,
  TArtifactRef,
> {
  history: THistoryMessage[];
  events: TEvent[];
  artifacts: TArtifact[];
  classifyActivityEvent: (event: TEvent) => TActivityKind;
  buildSemanticDedupKey: (kind: TActivityKind, event: TEvent) => string;
  eventToolName: (event: TEvent) => string | undefined;
  eventOutput: (event: TEvent) => string;
  normalizeOutputForHash: (value: string) => string;
  hashString: (input: string) => string;
  latestPrompt: (history: THistoryMessage[]) => TPrompt | null;
  resolveFinalAnswer: (
    history: THistoryMessage[],
    events: TEvent[],
  ) => TFinalAnswer | null;
  buildSourceSummary: (
    events: SessionActivityEventRef<TEvent, TActivityKind>[],
  ) => TSourceSummary | null;
  buildThoughtSummary: (groups: TActivityGroup[]) => TThoughtSummary | null;
  buildPlanSummary: (
    events: SessionActivityEventRef<TEvent, TActivityKind>[],
  ) => TPlanSummary | null;
  buildActivityGroups: (
    events: SessionActivityEventRef<TEvent, TActivityKind>[],
  ) => TActivityGroup[];
  buildActivitySummary: (
    events: SessionActivityEventRef<TEvent, TActivityKind>[],
    artifacts: TArtifact[],
  ) => TActivitySummary;
  collectArtifactRefs: (
    events: SessionActivityEventRef<TEvent, TActivityKind>[],
    artifacts: TArtifact[],
  ) => TArtifactRef[];
}

export function dedupeSessionActivityEvents<
  TEvent,
  TActivityKind extends string,
>({
  events,
  classifyActivityEvent,
  buildSemanticDedupKey,
  eventToolName,
  eventOutput,
  normalizeOutputForHash,
  hashString,
}: Pick<
  BuildSessionRunPresentationOptions<
    never,
    TEvent,
    never,
    TActivityKind,
    never,
    never,
    never,
    never,
    never,
    never,
    never,
    never
  >,
  | "events"
  | "classifyActivityEvent"
  | "buildSemanticDedupKey"
  | "eventToolName"
  | "eventOutput"
  | "normalizeOutputForHash"
  | "hashString"
>): SessionActivityEventRef<TEvent, TActivityKind>[] {
  const deduped: SessionActivityEventRef<TEvent, TActivityKind>[] = [];
  const seenKeys = new Set<string>();

  for (const event of events) {
    const kind = classifyActivityEvent(event);
    const toolName = eventToolName(event);
    const normalized = normalizeOutputForHash(eventOutput(event));
    const outputHash = normalized ? hashString(normalized) : undefined;
    const key = buildSemanticDedupKey(kind, event);

    if (seenKeys.has(key)) {
      continue;
    }
    seenKeys.add(key);

    deduped.push({
      key,
      event,
      kind,
      toolName,
      normalizedOutputHash: outputHash,
    });
  }

  return deduped;
}

export function buildSessionRunPresentation<
  THistoryMessage,
  TEvent,
  TArtifact,
  TActivityKind extends string,
  TPrompt,
  TFinalAnswer,
  TSourceSummary,
  TThoughtSummary,
  TPlanSummary,
  TActivitySummary,
  TActivityGroup,
  TArtifactRef,
>(
  options: BuildSessionRunPresentationOptions<
    THistoryMessage,
    TEvent,
    TArtifact,
    TActivityKind,
    TPrompt,
    TFinalAnswer,
    TSourceSummary,
    TThoughtSummary,
    TPlanSummary,
    TActivitySummary,
    TActivityGroup,
    TArtifactRef
  >,
): SessionRunPresentation<
  TPrompt,
  TFinalAnswer,
  TSourceSummary,
  TThoughtSummary,
  TPlanSummary,
  TActivitySummary,
  TActivityGroup,
  TArtifactRef
> {
  const deduped = dedupeSessionActivityEvents(options);
  const activityGroups = options.buildActivityGroups(deduped);

  return {
    prompt: options.latestPrompt(options.history),
    finalAnswer: options.resolveFinalAnswer(options.history, options.events),
    sourceSummary: options.buildSourceSummary(deduped),
    thoughtSummary: options.buildThoughtSummary(activityGroups),
    planSummary: options.buildPlanSummary(deduped),
    activitySummary: options.buildActivitySummary(deduped, options.artifacts),
    activityGroups,
    artifactRefs: options.collectArtifactRefs(deduped, options.artifacts),
  };
}
