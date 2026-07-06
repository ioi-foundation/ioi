import { Qd as e, g_ as t } from "./vendor-DAwbZtf0.js";
import {
  A as n,
  C as r,
  D as i,
  M as a,
  N as o,
  O as s,
  S as c,
  T as l,
  k as u,
  w as d,
} from "./workflow_pb-DOR6D5WK.js";
var f = (function (e) {
    return (
      (e.RepositoriesSearch = `repositories`),
      (e.RepositoriesList = `repositories-list`),
      (e.Projects = `projects`),
      e
    );
  })({}),
  p = (t) =>
    !t?.steps || t.steps.length === 0
      ? []
      : t.steps.map((t, n) => {
          let r = `step-${n}-${e()}`;
          return t.step?.case === `task`
            ? { id: r, type: `command`, content: t.step.value.command || `` }
            : t.step?.case === `agent`
              ? { id: r, type: `prompt`, content: t.step.value.prompt || `` }
              : t.step?.case === `pullRequest`
                ? {
                    id: r,
                    type: `pr`,
                    title: t.step.value.title || ``,
                    description: t.step.value.description || ``,
                    branch: t.step.value.branch || ``,
                    isDraft: t.step.value.draft || !1,
                  }
                : t.step?.case === `report`
                  ? {
                      id: r,
                      type: `report`,
                      outputs: (t.step.value.outputs || []).map((t, n) => {
                        let r = `output-${n}-${e()}`,
                          i = `string`,
                          a,
                          o,
                          s,
                          c,
                          l;
                        t.schema?.case === `string`
                          ? ((i = `string`), (a = t.schema.value.pattern || void 0))
                          : t.schema?.case === `integer`
                            ? ((i = `integer`), (o = t.schema.value.min ?? void 0), (s = t.schema.value.max ?? void 0))
                            : t.schema?.case === `float`
                              ? ((i = `float`), (c = t.schema.value.min ?? void 0), (l = t.schema.value.max ?? void 0))
                              : t.schema?.case === `boolean` && (i = `boolean`);
                        let u = `prompt`,
                          d = ``;
                        return (
                          t.extraction?.case === `prompt`
                            ? ((u = `prompt`), (d = t.extraction.value || ``))
                            : t.extraction?.case === `command` && ((u = `command`), (d = t.extraction.value || ``)),
                          {
                            id: r,
                            title: t.title || ``,
                            key: t.key || ``,
                            schemaType: i,
                            stringPattern: a,
                            integerMin: o,
                            integerMax: s,
                            floatMin: c,
                            floatMax: l,
                            acceptanceCriteria: t.acceptanceCriteria || void 0,
                            extractionType: u,
                            extractionValue: d,
                          }
                        );
                      }),
                    }
                  : { id: r, type: `command`, content: `` };
        }),
  m = (e) => {
    if (e?.limits)
      return {
        maxParallel: e.limits.maxParallel > 0 ? e.limits.maxParallel : void 0,
        maxTotal: e.limits.maxTotal > 0 ? e.limits.maxTotal : void 0,
      };
  },
  h = (e) =>
    e.map((e) => {
      switch (e.type) {
        case `command`:
          return { step: { case: `task`, value: { command: e.content } } };
        case `prompt`:
          return { step: { case: `agent`, value: { prompt: e.content } } };
        case `pr`:
          return {
            step: {
              case: `pullRequest`,
              value: { title: e.title, description: e.description, branch: e.branch, draft: e.isDraft },
            },
          };
        case `report`:
          return {
            step: {
              case: `report`,
              value: {
                outputs: e.outputs.map((e) => {
                  let t;
                  switch (e.schemaType) {
                    case `string`:
                      t = { case: `string`, value: { pattern: e.stringPattern || `` } };
                      break;
                    case `integer`:
                      t = { case: `integer`, value: { min: e.integerMin, max: e.integerMax } };
                      break;
                    case `float`:
                      t = { case: `float`, value: { min: e.floatMin, max: e.floatMax } };
                      break;
                    case `boolean`:
                      t = { case: `boolean`, value: {} };
                      break;
                  }
                  let n =
                    e.extractionType === `prompt`
                      ? { case: `prompt`, value: e.extractionValue }
                      : { case: `command`, value: e.extractionValue };
                  return {
                    title: e.title,
                    key: e.key,
                    schema: t,
                    acceptanceCriteria: e.acceptanceCriteria,
                    extraction: n,
                  };
                }),
              },
            },
          };
      }
    }),
  g = (t) =>
    t
      ? t
          .map((t) => {
            let n = `trigger-${e()}`;
            if (!t.trigger?.case)
              return (console.warn(`Trigger configuration ignored as the trigger type wasn't set.`), null);
            let r = t.trigger.case;
            if (r !== `manual` && r !== `time` && r !== `pullRequest` && r !== `incident`)
              return (console.warn(`Trigger configuration ignored, unsupported trigger type.`, t), null);
            let i = t.context?.context,
              a = { id: n, config: {}, context: { type: `projects`, projectIds: [] }, type: r };
            switch (t.trigger?.case) {
              case `manual`:
                break;
              case `time`:
                t.trigger.value?.cronExpression !== void 0 &&
                  (a.config.time = { cronExpression: t.trigger.value.cronExpression });
                break;
              case `pullRequest`:
                t.trigger.value?.events !== void 0 &&
                  (a.config.pullRequest = {
                    events: t.trigger.value.events,
                    webhookId: t.trigger.value.webhookId,
                    integrationId: t.trigger.value.integrationId,
                  });
                break;
              case `incident`: {
                let e = t.trigger.value;
                a.config.incident = {
                  integrationId: e?.integrationId ?? ``,
                  events: e?.events ?? [],
                  severityRanks:
                    e?.providerFilters.case === `incidentIo`
                      ? e.providerFilters.value.severityRanks
                      : (e?.severityRanks ?? []),
                  alertPriorityRanks:
                    e?.providerFilters.case === `incidentIo`
                      ? e.providerFilters.value.alertPriorityRanks
                      : (e?.alertPriorityRanks ?? []),
                  pagerDuty:
                    e?.providerFilters.case === `pagerDuty`
                      ? {
                          serviceIds: e.providerFilters.value.serviceIds,
                          priorityIds: e.providerFilters.value.priorityIds,
                          urgencies: e.providerFilters.value.urgencies,
                        }
                      : void 0,
                  defaultProjectId: ``,
                };
                break;
              }
              default:
                return (console.warn(`Trigger configuration ignored, unsupported trigger type.`, t), null);
            }
            switch (i?.case) {
              case `projects`:
                a.context = { type: `projects`, projectIds: i.value.projectIds };
                break;
              case `repositories`: {
                let { repositorySelector: e, environmentClassId: t } = i.value;
                e.case === `repoSelector`
                  ? (a.context = {
                      type: `repositories`,
                      repoSearchString: e.value.repoSearchString,
                      scmHost: e.value.scmHost,
                      runnerId: ``,
                      environmentClassId: t,
                    })
                  : e.case === `repositoryUrls` &&
                    (a.context = { type: `repositories-list`, environmentClassId: t, repoUrls: e.value.repoUrls });
                break;
              }
              default:
                return (
                  console.warn(`Trigger context ignored, we only support projects or repositories context for now.`, t),
                  null
                );
            }
            return a;
          })
          .filter((e) => e !== null)
      : [],
  _ = (e) =>
    e.map((e) => {
      let r = v(e.context);
      if (e.config.pullRequest)
        return t(l, {
          trigger: {
            case: `pullRequest`,
            value: t(a, {
              events: e.config.pullRequest.events,
              webhookId: e.config.pullRequest.webhookId,
              integrationId: e.config.pullRequest.integrationId,
            }),
          },
          context: r,
        });
      if (e.config.time)
        return t(l, {
          trigger: { case: `time`, value: t(o, { cronExpression: e.config.time.cronExpression }) },
          context: r,
        });
      if (e.config.incident) {
        let { incident: a } = e.config,
          o = a.pagerDuty,
          c =
            o && (o.serviceIds.length > 0 || o.priorityIds.length > 0 || o.urgencies.length > 0)
              ? {
                  case: `pagerDuty`,
                  value: t(n, { serviceIds: o.serviceIds, priorityIds: o.priorityIds, urgencies: o.urgencies }),
                }
              : a.severityRanks.length > 0 || a.alertPriorityRanks.length > 0
                ? {
                    case: `incidentIo`,
                    value: t(i, { severityRanks: a.severityRanks, alertPriorityRanks: a.alertPriorityRanks }),
                  }
                : void 0;
        return t(l, {
          trigger: {
            case: `incident`,
            value: t(s, {
              events: a.events,
              integrationId: a.integrationId,
              severityRanks: a.severityRanks,
              alertPriorityRanks: a.alertPriorityRanks,
              providerFilters: c,
            }),
          },
          context: r,
        });
      }
      return t(l, { trigger: { case: `manual`, value: t(u) }, context: r });
    }),
  v = (e) => {
    let n;
    switch (e.type) {
      case `projects`:
        n = t(c, { context: { case: `projects`, value: t(r, { projectIds: e.projectIds }) } });
        break;
      case `repositories`:
        n = t(c, {
          context: {
            case: `repositories`,
            value: t(d, {
              repositorySelector: {
                case: `repoSelector`,
                value: { repoSearchString: e.repoSearchString, scmHost: e.scmHost },
              },
              environmentClassId: e.environmentClassId,
            }),
          },
        });
        break;
      case `repositories-list`:
        n = t(c, {
          context: {
            case: `repositories`,
            value: t(d, {
              repositorySelector: { case: `repositoryUrls`, value: { repoUrls: e.repoUrls } },
              environmentClassId: e.environmentClassId,
            }),
          },
        });
        break;
      default:
        break;
    }
    return n;
  },
  y = (e) => {
    let t = e?.spec?.triggers ?? [];
    for (let e of t) {
      let t = e.context?.context;
      if (t)
        switch (t.case) {
          case `projects`:
            return { type: `projects`, projectIds: t.value.projectIds ?? [] };
          case `repositories`: {
            let { repositorySelector: e, environmentClassId: n } = t.value;
            if (e?.case === `repoSelector`)
              return {
                type: `repositories`,
                repoSearchString: e.value.repoSearchString ?? ``,
                scmHost: e.value.scmHost ?? ``,
                runnerId: ``,
                environmentClassId: n ?? ``,
              };
            if (e?.case === `repositoryUrls`)
              return { type: `repositories-list`, environmentClassId: n ?? ``, repoUrls: e.value.repoUrls ?? [] };
            break;
          }
        }
    }
    return { type: `projects`, projectIds: [] };
  },
  b = (e) =>
    (e?.spec?.triggers ?? []).some((e) => {
      let t = e.context?.context;
      return t?.case === `repositories` && t.value.repositorySelector.case === `repositoryUrls`;
    }),
  x = (e, t) =>
    e === null && t === null
      ? !0
      : e === null || t === null || e.length !== t.length
        ? !1
        : e.every((e, n) => {
            let r = t[n];
            if (e.type !== r.type) return !1;
            switch (e.type) {
              case `command`:
              case `prompt`:
                return e.content === r.content;
              case `pr`:
                return (
                  e.title === r.title &&
                  e.description === r.description &&
                  e.branch === r.branch &&
                  e.isDraft === r.isDraft
                );
              case `report`: {
                let t = r.outputs;
                return e.outputs.length === t.length
                  ? e.outputs.every((e, n) => {
                      let r = t[n];
                      return (
                        e.title === r.title &&
                        e.key === r.key &&
                        e.schemaType === r.schemaType &&
                        e.stringPattern === r.stringPattern &&
                        e.integerMin === r.integerMin &&
                        e.integerMax === r.integerMax &&
                        e.floatMin === r.floatMin &&
                        e.floatMax === r.floatMax &&
                        e.acceptanceCriteria === r.acceptanceCriteria &&
                        e.extractionType === r.extractionType &&
                        e.extractionValue === r.extractionValue
                      );
                    })
                  : !1;
              }
            }
          }),
  S = (e, t) => {
    if (e.type !== t.type) return !1;
    switch (e.type) {
      case `projects`:
        return j(e.projectIds, t.projectIds);
      case `repositories`:
        return (
          e.repoSearchString === t.repoSearchString &&
          e.scmHost === t.scmHost &&
          e.environmentClassId === t.environmentClassId
        );
      case `repositories-list`:
        return e.environmentClassId === t.environmentClassId && j(e.repoUrls, t.repoUrls);
    }
  },
  C = (e, t) =>
    !(
      e.time?.cronExpression !== t.time?.cronExpression ||
      !j(e.pullRequest?.events ?? [], t.pullRequest?.events ?? []) ||
      e.pullRequest?.webhookId !== t.pullRequest?.webhookId ||
      e.incident?.integrationId !== t.incident?.integrationId ||
      !j(e.incident?.events ?? [], t.incident?.events ?? []) ||
      !j(e.incident?.severityRanks ?? [], t.incident?.severityRanks ?? []) ||
      !j(e.incident?.alertPriorityRanks ?? [], t.incident?.alertPriorityRanks ?? []) ||
      e.incident?.defaultProjectId !== t.incident?.defaultProjectId ||
      !j(e.incident?.pagerDuty?.serviceIds ?? [], t.incident?.pagerDuty?.serviceIds ?? []) ||
      !j(e.incident?.pagerDuty?.priorityIds ?? [], t.incident?.pagerDuty?.priorityIds ?? []) ||
      !j(e.incident?.pagerDuty?.urgencies ?? [], t.incident?.pagerDuty?.urgencies ?? [])
    ),
  w = (e, t) =>
    e.length === t.length
      ? e.every((e, n) => {
          let r = t[n];
          return e.type === r.type && S(e.context, r.context) && C(e.config, r.config);
        })
      : !1,
  T = (e, t) => (e === void 0 && t === void 0 ? !0 : e === void 0 || t === void 0 ? !1 : e.id === t.id),
  E = (e, t) => {
    if (!T(e, t)) return e;
  },
  D = (e, t) =>
    e === void 0 && t === void 0
      ? !0
      : e === void 0 || t === void 0
        ? !1
        : e.model === t.model && e.reasoningEffort === t.reasoningEffort && e.serviceTier === t.serviceTier,
  O = (e, t) => (e.agentId ?? ``) === (t.agentId ?? ``) && D(e.codexSettings, t.codexSettings),
  k = (e, t) => e?.maxParallel === t?.maxParallel && e?.maxTotal === t?.maxTotal,
  A = (e, t) => e.name === t.name && e.description === t.description,
  j = (e, t) => (e.length === t.length ? e.every((e, n) => e === t[n]) : !1),
  M = (e) => {
    let t = e.spec?.action ? p(e.spec.action) : [],
      n = e.spec?.triggers?.[0] ? g(e.spec.triggers) : [],
      r = e.metadata?.executor,
      i = m(e.spec?.action);
    return {
      name: e.metadata?.name ?? ``,
      description: e.metadata?.description ?? ``,
      steps: t,
      triggers: n,
      executor: r,
      limits: i,
      agentId: e.spec?.agentId ?? ``,
      codexSettings: e.spec?.codexSettings,
    };
  };
export {
  b as _,
  A as a,
  E as c,
  _ as d,
  g as f,
  y as g,
  M as h,
  k as i,
  v as l,
  p as m,
  O as n,
  x as o,
  m as p,
  T as r,
  w as s,
  f as t,
  h as u,
};
