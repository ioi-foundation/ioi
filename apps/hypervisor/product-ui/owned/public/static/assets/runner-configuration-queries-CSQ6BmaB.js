import { Xh as e, Yh as t, eg as n, g_ as r, qh as i } from "./vendor-DAwbZtf0.js";
import {
  Dr as a,
  Go as o,
  Ho as s,
  Jo as c,
  Ko as l,
  Lr as u,
  Ls as ee,
  Qo as d,
  Uo as f,
  Vo as p,
  Wo as m,
  Xo as h,
  Zo as te,
  _r as g,
  ct as _,
  ds as v,
  es as y,
  fs as b,
  gr as x,
  gs as S,
  hr as C,
  hs as w,
  kr as T,
  ls as ne,
  lt as E,
  ms as D,
  ns as O,
  ps as k,
  qo as A,
  rs as j,
  ts as M,
  us as N,
  vr as P,
} from "./use-boot-in-app-chat-t-J_VjKS.js";
var F = 1e3 * 60 * 5,
  I = {
    list: (e) => C([`hostAuthenticationTokens`, `list`], e),
    listRunnerSCMIntegrations: (e, t) => C([`listRunnerSCMIntegrations`, e], t),
    listAllRunnerSCMIntegrations: (e) => C([`listAllRunnerSCMIntegrations`, e]),
    listRunnerLLMIntegrations: (e) => C([`listRunnerLLMIntegrations`, e]),
    listRunnerEnvironmentClasses: (e) => C([`listRunnerEnvironmentClasses`, e]),
    getEnvironmentClass: (e) => C([`getEnvironmentClass`, e]),
    onboardingEnvironmentClass: (e) => C([`environment-classes`, `onboarding`, e]),
    getRunnerConfigurationSchema: (e) => C([`getRunnerConfigurationSchema`, e]),
  },
  L = 1e3 * 60 * 5,
  R = 300 * 1e3,
  z = async (e, t, n) => {
    await Promise.all([
      t.invalidateQueries({ queryKey: I.list() }),
      t.invalidateQueries({ queryKey: C([`integration-validation`]) }),
    ]);
  },
  B = () => {
    let e = a(),
      t = n();
    return i({
      mutationFn: async (n) => {
        let i = t.getQueryData(_.getAuthenticatedUserQueryKey());
        if (!i) throw Error(`User not authenticated`);
        let a = (
          await g(
            (t) => e.runnerConfigurationService.listHostAuthenticationTokens(t),
            r(M, { filter: { userId: i.id, runnerId: n.runnerId } }),
            (e) => e.tokens,
          )
        ).find((e) => e.host === n.scmHost);
        a && (await e.runnerConfigurationService.deleteHostAuthenticationToken({ id: a.id }));
        let { token: o } = await e.runnerConfigurationService.createHostAuthenticationToken(
          r(s, { userId: i.id, runnerId: n.runnerId, host: n.scmHost, token: n.pat, source: d.PAT }),
        );
        try {
          await e.runnerService.parseContextURL({ contextUrl: n.repoUrl, runnerId: n.runnerId });
        } catch (t) {
          throw (o && (await e.runnerConfigurationService.deleteHostAuthenticationToken({ id: o.id })), t);
        }
        return o;
      },
      onSuccess: () => {
        t.invalidateQueries({ queryKey: I.list() }).catch((e) => console.error(e));
      },
    });
  },
  V = ({ headers: e }) => {
    let t = a(),
      o = n();
    return i({
      mutationFn: async (n) => {
        let i = r(s, {
          runnerId: n.runnerId,
          host: n.host,
          token: n.pat,
          source: d.PAT,
          subject: { id: e.serviceAccountId, principal: ee.SERVICE_ACCOUNT },
        });
        await t.runnerConfigurationService.createHostAuthenticationToken(i, { headers: e.headers });
      },
      onSuccess: () => {
        o.invalidateQueries({ queryKey: I.list(x(e.serviceAccountId)) }).catch((e) => console.error(e));
      },
    });
  },
  H = () => {
    let e = a(),
      t = n();
    return i({
      mutationFn: async (n) => {
        let i = t.getQueryData(_.getAuthenticatedUserQueryKey());
        if (!i) throw Error(`User not authenticated`);
        let a = (
          await g(
            (t) => e.runnerConfigurationService.listHostAuthenticationTokens(t),
            r(M, { filter: { userId: i.id, runnerId: n.runnerId } }),
            (e) => e.tokens,
          )
        ).find((e) => e.host === n.scmHost);
        a && (await e.runnerConfigurationService.deleteHostAuthenticationToken({ id: a.id }));
      },
    });
  },
  U = (e) => {
    let t = a(),
      r = n();
    return i({
      onMutate: async (t) => {
        let n = I.list(e?.headers?.serviceAccountId ? x(e.headers.serviceAccountId) : void 0);
        await r.cancelQueries({ queryKey: n });
        let i = r.getQueryData(n);
        return (_e(r, { tokenId: t.tokenId, headers: e?.headers }), { previousTokens: i, queryKey: n });
      },
      mutationFn: async (e) => {
        if (!r.getQueryData(_.getAuthenticatedUserQueryKey())) throw Error(`User not authenticated`);
        await t.runnerConfigurationService.deleteHostAuthenticationToken({ id: e.tokenId });
      },
      onError: (e, t, n) => {
        n?.previousTokens !== void 0 && r.setQueryData(n.queryKey, n.previousTokens);
      },
      onSettled: (e, t, n, i) => {
        i?.queryKey && r.invalidateQueries({ queryKey: i.queryKey });
      },
    });
  },
  W = ({ enabled: e = !0, headers: n }) => {
    let i = a(),
      { data: o } = E();
    return t({
      queryKey: I.list(n?.serviceAccountId ? x(n.serviceAccountId) : void 0),
      queryFn: async () => {
        if (!o) throw Error(`User not authenticated`);
        return {
          tokens: (
            await g(
              (e) => i.runnerConfigurationService.listHostAuthenticationTokens(e, n ? { headers: n.headers } : void 0),
              r(M, { filter: { subjectId: n?.serviceAccountId ?? o.id } }),
              (e) => e.tokens,
            )
          ).map((e) => e),
        };
      },
      enabled: e && !!o,
      staleTime: F,
      refetchOnWindowFocus: !1,
      refetchOnReconnect: !1,
    });
  },
  G = (t) => (T({ resourceType: u.HOST_AUTHENTICATION_TOKEN }), e(W(t))),
  K = (e) => {
    let n = a(),
      { data: i } = E();
    return t({
      queryKey: I.getRunnerConfigurationSchema(e || `no-runner`),
      queryFn: async () => {
        if (!i) throw Error(`User not authenticated`);
        let { schema: t } = await n.runnerConfigurationService.getRunnerConfigurationSchema(r(te, { runnerId: e }));
        return t;
      },
      enabled: !!i && !!e,
      staleTime: 500,
    });
  },
  q = (t) => e(K(t)),
  J = (e, t) => {
    let o = a(),
      s = n();
    return i({
      mutationFn: async (n) => {
        if (!s.getQueryData(_.getAuthenticatedUserQueryKey())) throw Error(`User not authenticated`);
        let { result: i } = await o.runnerConfigurationService.validateRunnerConfiguration(
          r(w, {
            runnerId: e,
            config: {
              case: `scmIntegration`,
              value: r(S, {
                host: n.host,
                pat: n.pat,
                scmId: n.scmId,
                oauthClientId: n.oauth?.clientId,
                oauthClientSecret: n.oauth?.clientSecret
                  ? { case: `oauthPlaintextClientSecret`, value: n.oauth?.clientSecret }
                  : void 0,
                issuerUrl: n.oauth?.issuerUrl,
                virtualDirectory: n.virtualDirectory,
              }),
            },
          }),
        );
        if (i.case === `scmIntegration` && !i.value.valid) return i.value;
        if (!t) {
          let { id: t } = await o.runnerConfigurationService.createSCMIntegration(
            r(m, {
              runnerId: e,
              host: n.host,
              pat: n.pat,
              scmId: n.scmId,
              oauthClientId: n.oauth?.clientId,
              oauthPlaintextClientSecret: n.oauth?.clientSecret,
              issuerUrl: n.oauth?.issuerUrl,
              virtualDirectory: n.virtualDirectory,
            }),
          );
          return (Z(s, e, r(N, { id: t, ...n })), r(v, { valid: !0 }));
        }
        await o.runnerConfigurationService.updateSCMIntegration(
          r(D, {
            id: t,
            pat: n.pat,
            oauthClientId: n.oauth?.clientId ?? ``,
            oauthPlaintextClientSecret: n.oauth?.clientSecret ? n.oauth?.clientSecret : void 0,
            issuerUrl: n.oauth?.issuerUrl,
            virtualDirectory: n.virtualDirectory,
          }),
        );
        let a = r(N, {
          id: t,
          runnerId: e,
          host: n.host,
          pat: n.pat,
          scmId: n.scmId,
          virtualDirectory: n.virtualDirectory,
        });
        return (
          n.oauth &&
            (a.oauth = r(ne, {
              clientId: n.oauth.clientId,
              encryptedClientSecret: n.oauth.encryptedClientSecret,
              issuerUrl: n.oauth.issuerUrl,
            })),
          me(s, e, a),
          r(v, { valid: !0 })
        );
      },
    });
  },
  Y = () => {
    let e = a(),
      t = n();
    return i({
      mutationFn: async (n) => {
        if (!t.getQueryData(_.getAuthenticatedUserQueryKey())) throw Error(`User not authenticated`);
        let { result: i } = await e.runnerConfigurationService.validateRunnerConfiguration(
          r(w, { runnerId: n.runnerId, config: { case: `environmentClass`, value: n } }),
        );
        return i.case === `environmentClass` && !i.value.valid ? i.value : r(c, { valid: !0 });
      },
    });
  },
  re = (e) => {
    let t = a(),
      o = n();
    return i({
      mutationFn: async (n) => {
        if (!o.getQueryData(_.getAuthenticatedUserQueryKey())) throw Error(`User not authenticated`);
        let { id: i } = await t.runnerConfigurationService.createEnvironmentClass(r(p, { runnerId: e, ...n }));
        ge(o, r(A, { id: i, runnerId: e, enabled: !0, ...n }));
      },
    });
  },
  X = (e) => {
    let t = a(),
      o = n();
    return i({
      mutationFn: async (n) => {
        if (!o.getQueryData(_.getAuthenticatedUserQueryKey())) throw Error(`User not authenticated`);
        let i = r(A, { ...e, displayName: n.displayName, description: n.description }),
          { result: a } = await t.runnerConfigurationService.validateRunnerConfiguration(
            r(w, { runnerId: e.runnerId, config: { case: `environmentClass`, value: i } }),
          );
        return a.case === `environmentClass` && !a.value.valid
          ? a.value
          : (await t.runnerConfigurationService.updateEnvironmentClass(
              r(b, { environmentClassId: e.id, displayName: i.displayName, description: i.description }),
            ),
            $(o, i),
            r(c, { valid: !0 }));
      },
    });
  },
  ie = (e) => {
    let t = a(),
      o = n();
    return i({
      mutationFn: async (n) => {
        if (!o.getQueryData(_.getAuthenticatedUserQueryKey())) throw Error(`User not authenticated`);
        let i = r(A, { ...e, enabled: n.enabled });
        (await t.runnerConfigurationService.updateEnvironmentClass(
          r(b, {
            environmentClassId: e.id,
            displayName: i.displayName,
            description: i.description,
            enabled: i.enabled,
          }),
        ),
          $(o, i));
      },
    });
  },
  ae = (e) => {
    let t = a(),
      o = n();
    return i({
      mutationFn: async (n) => {
        if (!o.getQueryData(_.getAuthenticatedUserQueryKey())) throw Error(`User not authenticated`);
        (await t.runnerConfigurationService.deleteSCMIntegration(r(l, { id: n })), he(o, e, n));
      },
    });
  },
  oe = (e, { enabled: n = !0, headers: i } = {}) => {
    let o = a(),
      { data: s } = E();
    return t({
      queryKey: I.listRunnerSCMIntegrations(e, i ? x(i?.serviceAccountId) : void 0),
      queryFn: async () => {
        if (!s) throw Error(`User not authenticated`);
        return e
          ? await g(
              (e) => o.runnerConfigurationService.listSCMIntegrations(e, i ? { headers: i.headers } : void 0),
              r(j, { filter: { runnerIds: [e] } }),
              (e) => e.integrations,
            )
          : [];
      },
      enabled: !!s && !!e && n,
      staleTime: R,
      refetchOnWindowFocus: !1,
      refetchOnReconnect: !1,
    });
  },
  se = (t, n = {}) => e(oe(t, n)),
  ce = (e) => {
    let n = a(),
      { data: i } = E();
    return t({
      queryKey: I.listAllRunnerSCMIntegrations(e ?? []),
      queryFn: async () => {
        if (!i) throw Error(`User not authenticated`);
        let t = await g(
          (e) => n.runnerConfigurationService.listSCMIntegrations(e),
          r(j, {}),
          (e) => e.integrations,
        );
        return e && e.length > 0 ? t.filter((t) => e.includes(t.runnerId)) : t;
      },
      enabled: !!i,
      staleTime: R,
      refetchOnWindowFocus: !1,
      refetchOnReconnect: !1,
    });
  },
  le = (t) => e(ce(t)),
  ue = (e) => {
    let n = a(),
      { data: i } = E();
    return t({
      queryKey: I.listRunnerEnvironmentClasses(e),
      queryFn: async () => {
        if (!i) throw Error(`User not authenticated`);
        return e
          ? await g(
              (e) => n.runnerConfigurationService.listEnvironmentClasses(e),
              r(y, { filter: { runnerIds: [e] } }),
              (e) => e.environmentClasses,
            )
          : [];
      },
      enabled: !!i && !!e,
      staleTime: 500,
    });
  },
  de = (t) => (T({ resourceType: u.ENVIRONMENT_CLASS }), e(ue(t))),
  fe = (e) => {
    let n = a(),
      { data: i } = E();
    return t({
      queryKey: I.getEnvironmentClass(e),
      queryFn: async () => {
        if (!i) throw Error(`User not authenticated`);
        if (!e) return;
        let { environmentClass: t } = await n.runnerConfigurationService.getEnvironmentClass(
          r(h, { environmentClassId: e }),
        );
        return t;
      },
      enabled: !!i && !!e,
      staleTime: 500,
    });
  },
  pe = (t) => e(fe(t));
function me(e, t, n) {
  (e.setQueryData(I.listRunnerSCMIntegrations(t), (e) => {
    let t = !1,
      r = e?.map((e) => (e.id === n.id ? ((t = !0), n) : e)) || [];
    return (t || r.push(n), r);
  }),
    Q(e));
}
function he(e, t, n) {
  (e.setQueryData(I.listRunnerSCMIntegrations(t), (e) => e?.filter((e) => e.id !== n) || []), Q(e));
}
function Z(e, t, n) {
  (e.setQueryData(I.listRunnerSCMIntegrations(t), (e) => (e ? [n, ...e] : [n])), Q(e));
}
function Q(e) {
  e.invalidateQueries({ queryKey: I.listAllRunnerSCMIntegrations([]).slice(0, -1) });
}
function $(e, t) {
  e.setQueryData(I.listRunnerEnvironmentClasses(t.runnerId), (e) => e.map((e) => (e.id === t.id ? t : e)));
}
function ge(e, t) {
  e.setQueryData(I.listRunnerEnvironmentClasses(t.runnerId), (e) => [t, ...e]);
}
function _e(e, { tokenId: t, headers: n }) {
  e.setQueryData(I.list(n?.serviceAccountId ? x(n.serviceAccountId) : void 0), (e) =>
    e ? { tokens: e.tokens.filter((e) => e.id !== t) } : { tokens: [] },
  );
}
var ve = (e, { enabled: n = !0 } = {}) => {
    let i = a(),
      { data: o } = E();
    return t({
      queryKey: I.listRunnerLLMIntegrations(e),
      queryFn: async () => {
        if (!o) throw Error(`User not authenticated`);
        if (!e) return { integrations: [], llmManagedByOna: !1, onaIntelligenceProviders: [] };
        let t = await P(
          (e) => i.runnerConfigurationService.listLLMIntegrations(e),
          r(O, { filter: { runnerIds: [e] } }),
        );
        return {
          integrations: t.flatMap((e) => e.integrations),
          llmManagedByOna: t[0]?.llmManagedByOna || !1,
          onaIntelligenceProviders: t[0]?.onaIntelligenceProviders || [],
        };
      },
      enabled: !!o && !!e && n,
      staleTime: L,
      refetchOnReconnect: !1,
      refetchOnWindowFocus: !1,
    });
  },
  ye = (t, n = {}) => e(ve(t, n)),
  be = (e) => {
    let t = a(),
      o = n();
    return i({
      mutationFn: async (n) => {
        if (!o.getQueryData(_.getAuthenticatedUserQueryKey())) throw Error(`User not authenticated`);
        let i = await t.runnerConfigurationService.createLLMIntegration(
          r(f, {
            runnerId: e,
            models: n.models,
            endpoint: n.endpoint,
            apiKey: n.apiKey,
            maxTokens: n.maxTokens ? BigInt(n.maxTokens) : void 0,
          }),
        );
        return (await o.invalidateQueries({ queryKey: I.listRunnerLLMIntegrations(e) }), i);
      },
    });
  },
  xe = (e) => {
    let t = a(),
      o = n();
    return i({
      mutationFn: async (n) => {
        if (!o.getQueryData(_.getAuthenticatedUserQueryKey())) throw Error(`User not authenticated`);
        (await t.runnerConfigurationService.updateLLMIntegration(
          r(k, {
            id: n.integrationId,
            models: n.models,
            endpoint: n.endpoint,
            apiKey: n.apiKey,
            maxTokens: n.maxTokens ? BigInt(n.maxTokens) : void 0,
            phase: n.phase,
          }),
        ),
          await o.invalidateQueries({ queryKey: I.listRunnerLLMIntegrations(e) }));
      },
    });
  },
  Se = (e) => {
    let t = a(),
      s = n();
    return i({
      mutationFn: async ({ integrationId: n, force: i = !1 }) => {
        if (!s.getQueryData(_.getAuthenticatedUserQueryKey())) throw Error(`User not authenticated`);
        (await t.runnerConfigurationService.deleteLLMIntegration(r(o, { id: n, force: i })),
          await s.invalidateQueries({ queryKey: I.listRunnerLLMIntegrations(e) }));
      },
    });
  };
export {
  Y as S,
  se as _,
  V as a,
  X as b,
  U as c,
  ae as d,
  pe as f,
  ye as g,
  de as h,
  re as i,
  H as l,
  G as m,
  I as n,
  be as o,
  le as p,
  B as r,
  J as s,
  z as t,
  Se as u,
  q as v,
  xe as x,
  ie as y,
};
