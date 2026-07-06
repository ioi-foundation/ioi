import { Xh as e, Yh as t, Zh as n, eg as r, g_ as i, qh as a } from "./vendor-DAwbZtf0.js";
import {
  Dr as o,
  Fs as s,
  Lr as c,
  Ns as l,
  Ps as u,
  _r as d,
  hr as f,
  lt as p,
  xr as m,
} from "./use-boot-in-app-chat-t-J_VjKS.js";
import { g as h } from "./workflow_pb-DOR6D5WK.js";
import {
  a as g,
  c as _,
  d as v,
  i as y,
  l as b,
  n as x,
  o as ee,
  p as S,
  r as C,
  s as w,
  t as T,
  u as E,
} from "./webhook_pb-C1T_Ekd7.js";
import { t as D } from "./use-resource-permission-Dd1Jv7de.js";
import { i as O, n as k, r as A } from "./SourceControlProviderIcon-DRPBTuTO.js";
import { t as j } from "./IconGitHub-DdVg_DwS.js";
var M = {
    list: () => f([`webhooks`, `list`]),
    get: (e) => f([`webhooks`, { webhookId: e }]),
    secret: (e) => f([`webhooks`, `secret`, { webhookId: e }]),
    workflows: (e) => f([`webhooks`, `workflows`, { webhookId: e }]),
    workflowRunningExecution: (e) =>
      f([`webhooks`, `workflow-running-execution`, { workflowId: e, status: `running` }]),
  },
  N = 1e3 * 60 * 5,
  P = () => {
    let e = o(),
      { data: n } = p();
    return t({
      queryKey: M.list(),
      queryFn: async () => {
        if (!n) throw Error(`User not authenticated`);
        return (
          await d(
            (t) => e.webhookService.listWebhooks(t),
            i(ee),
            (e) => e.webhooks,
          )
        ).map((e) => e);
      },
      throwOnError: !1,
      retry: m,
      enabled: !!n,
      staleTime: N,
      refetchOnReconnect: !1,
      refetchOnWindowFocus: !1,
    });
  },
  F = () => e(P()),
  I = (e) => {
    let n = o();
    return t({
      queryKey: M.get(e),
      queryFn: async () => {
        if (!e) throw Error(`webhookId is required`);
        let t = await n.webhookService.getWebhook(i(C, { webhookId: e }));
        if (!t.webhook) throw Error(`Webhook not found`);
        return t.webhook;
      },
      enabled: !!e,
      retry: m,
    });
  },
  L = (t) => e(I(t)),
  te = (e) => {
    let n = o();
    return t({
      queryKey: M.secret(e),
      queryFn: async () => {
        if (!e) throw Error(`webhookId is required`);
        return (await n.webhookService.getWebhookSecret(i(y, { webhookId: e }))).secret;
      },
      enabled: !!e,
      retry: m,
    });
  },
  R = (t) => e(te(t)),
  z = () => {
    let e = o(),
      t = r();
    return a({
      mutationFn: async (t) => (await e.webhookService.rotateWebhookSecret(i(w, { webhookId: t }))).secret,
      onSuccess: (e, n) => {
        t.setQueryData(M.secret(n), e);
      },
    });
  },
  B = () => {
    let e = o(),
      t = r();
    return a({
      mutationFn: async (t) => {
        let n = await e.webhookService.createWebhook(
          i(T, {
            name: t.name,
            description: t.description,
            type: t.type,
            scope: t.scope,
            provider: t.provider,
            scopes: t.scopes?.map((e) => i(v, { host: e.host, owner: e.owner, name: e.name })),
            organizationScope: t.organizationScope ? i(b, t.organizationScope) : void 0,
          }),
        );
        if (!n.webhook) throw Error(`Failed to create webhook`);
        return n.webhook;
      },
      onSuccess: () => {
        t.invalidateQueries({ queryKey: M.list() });
      },
    });
  },
  V = () => {
    let e = o(),
      t = r();
    return a({
      mutationFn: async (t) => {
        await e.webhookService.deleteWebhook(i(x, { webhookId: t }));
      },
      onSuccess: (e, n) => {
        (t.setQueryData(M.list(), (e) => e?.filter((e) => e.id !== n)),
          t.removeQueries({ queryKey: M.get(n) }),
          t.removeQueries({ queryKey: M.secret(n) }));
      },
    });
  },
  H = () => {
    let e = o(),
      t = r();
    return a({
      mutationFn: async (t) => {
        let n = await e.webhookService.updateWebhook(
          i(_, {
            webhookId: t.webhookId,
            name: t.name,
            description: t.description,
            scope: t.scope,
            scopes: t.scopes?.map((e) => i(v, { host: e.host, owner: e.owner, name: e.name })),
            organizationScope: t.organizationScope ? i(b, t.organizationScope) : void 0,
          }),
        );
        if (!n.webhook) throw Error(`Failed to update webhook`);
        return n.webhook;
      },
      onSuccess: (e) => {
        (t.setQueryData(M.list(), (t) => t?.map((t) => (t.id === e.id ? e : t))), t.setQueryData(M.get(e.id), e));
      },
    });
  },
  U = (e) => {
    let { hasPermission: t, isLoading: n } = D(c.WEBHOOK, e || ``, `webhook:delete`);
    return { canDeleteWebhook: e ? t : !1, isLoading: n };
  },
  W = (e) => {
    let n = o(),
      { data: r } = p();
    return t({
      queryKey: M.workflows(e),
      queryFn: async () => {
        if (!e) throw Error(`webhookId is required`);
        return (
          await d(
            (e) => n.webhookService.listWebhookWorkflows(e),
            i(g, { webhookId: e }),
            (e) => e.workflows,
          )
        ).map((e) => e);
      },
      enabled: !!e && !!r,
      retry: m,
    });
  },
  G = (t) => e(W(t)),
  K = (e, t = !0) => {
    let r = o(),
      { data: a, isLoading: c } = G(t ? e : void 0),
      d = n({
        queries: (a ?? []).map((e) => ({
          queryKey: M.workflowRunningExecution(e.id),
          queryFn: async () => {
            let t = await r.workflowService.listWorkflowExecutions({
              filter: { workflowIds: [e.id], statusPhases: [h.PENDING, h.RUNNING, h.STOPPING] },
              sort: i(s, { field: `startedAt`, order: u.DESC }),
              pagination: i(l, { pageSize: 1 }),
            });
            return t.workflowExecutions.length === 0 ? null : t.workflowExecutions[0];
          },
          enabled: t && !!a?.length,
          retry: m,
        })),
      }),
      f = d.some((e) => e.isLoading),
      p = c || f,
      g = (a ?? []).map((e, t) => {
        let n = d[t]?.data;
        return {
          workflow: e,
          isRunning:
            n?.status?.phase === h.PENDING || n?.status?.phase === h.RUNNING || n?.status?.phase === h.STOPPING,
        };
      });
    return {
      workflows: g,
      isLoading: p,
      hasRunningExecutions: g.some((e) => e.isRunning),
      hasBoundWorkflows: (a?.length ?? 0) > 0,
    };
  },
  q = (e) => {
    try {
      return new URL(e).pathname.slice(1);
    } catch {
      return e;
    }
  },
  J = {
    [E.GITHUB]: { icon: j, name: `GitHub` },
    [E.GITLAB]: { icon: k, name: `GitLab` },
    [E.BITBUCKET]: { icon: O, name: `Bitbucket` },
    [E.UNSPECIFIED]: { icon: A, name: `Unknown` },
  },
  Y = {
    [S.SCM_REPOSITORY]: { name: `Repository` },
    [S.SCM_ORGANIZATION]: { name: `Organization` },
    [S.UNSPECIFIED]: { name: `Unknown` },
  },
  X = (e, t, n, r = !1, i) => {
    if (!n) return ``;
    if (e === E.GITHUB) {
      let e = i || `github.com`,
        a = r ? `/new` : ``;
      return t === S.SCM_ORGANIZATION
        ? `https://${e}/organizations/${n}/settings/hooks${a}`
        : `https://${e}/${n}/settings/hooks${a}`;
    }
    if (e === E.GITLAB) {
      let e = i || `gitlab.com`;
      return t === S.SCM_ORGANIZATION ? `https://${e}/groups/${n}/-/hooks` : `https://${e}/${n}/-/hooks`;
    }
    return e === E.BITBUCKET ? `https://${i || `bitbucket.org`}/${n}/admin/webhooks` : ``;
  },
  Z = (e) => (e.spec?.organizationScope || (e.spec?.scopes && e.spec.scopes.length > 0) ? !0 : !!e.spec?.scope),
  Q = (e) => {
    switch (e) {
      case E.GITHUB:
        return `github`;
      case E.GITLAB:
        return `gitlab`;
      case E.BITBUCKET:
        return `bitbucket`;
      default:
        return `unspecified`;
    }
  },
  ne = (e) => {
    switch (e) {
      case S.SCM_ORGANIZATION:
        return { isOrgType: !0, scopeLabel: `Organization`, comboboxPlaceholder: `Select an organization` };
      case S.SCM_REPOSITORY:
        return { isOrgType: !1, scopeLabel: `Repository`, comboboxPlaceholder: `Select a repository` };
      default:
        return { isOrgType: !1, scopeLabel: `Organization`, comboboxPlaceholder: `Select an organization` };
    }
  },
  re = (e) => {
    let t = $(e.url),
      n = q(e.url).split(`/`);
    return { host: t, owner: n[0] || ``, name: n[1] || `` };
  },
  $ = (e) => {
    try {
      return new URL(e).hostname;
    } catch {
      return ``;
    }
  },
  ie = (e) => `${e.owner || ``}/${e.name || ``}`;
export {
  P as _,
  X as a,
  K as b,
  re as c,
  U as d,
  B as f,
  F as g,
  R as h,
  ne as i,
  ie as l,
  L as m,
  Y as n,
  Z as o,
  V as p,
  $ as r,
  Q as s,
  J as t,
  q as u,
  z as v,
  H as y,
};
