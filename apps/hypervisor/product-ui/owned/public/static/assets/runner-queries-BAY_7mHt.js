import { a as e } from "./rolldown-runtime-CGYlQKCx.js";
import { n as t } from "./@mux-DLaEVubF.js";
import {
  $g as n,
  Kh as r,
  Xh as i,
  Yh as a,
  Zh as o,
  __ as s,
  eg as c,
  g_ as l,
  qh as u,
  sg as d,
} from "./vendor-DAwbZtf0.js";
import {
  Dr as f,
  Ir as p,
  Li as m,
  Lr as h,
  Ns as g,
  Sr as _,
  _r as v,
  br as y,
  cs as b,
  ct as x,
  gr as S,
  hr as C,
  kr as ee,
  lt as w,
  ss as T,
  vn as te,
  xr as E,
  yr as ne,
} from "./use-boot-in-app-chat-t-J_VjKS.js";
import {
  a as re,
  d as D,
  f as O,
  h as k,
  i as A,
  l as j,
  o as M,
  p as ie,
  r as ae,
  s as N,
  t as oe,
} from "./runner_manager_pb-BYgy9Ytq.js";
import { n as P } from "./runner-configuration-queries-CSQ6BmaB.js";
var F = {
    listAvailable: () => C([`runnerManagers`, `available`]),
    placeholders: () => C([`runnerManagers`, `placeholders`]),
  },
  se = ({ enabled: e = !0 } = {}) => {
    let t = f(),
      { data: n } = w();
    return a({
      queryKey: F.listAvailable(),
      queryFn: async () => {
        if (!n) throw Error(`User not authenticated`);
        return (
          await v(
            (e) => t.runnerManagerService.listAvailableRunnerManagers(e),
            l(oe),
            (e) => e.runnerManagers,
          )
        ).map((e) => ({ runnerManagerId: e.runnerManagerId, name: e.name, region: e.region }));
      },
      throwOnError: _,
      retry: E,
      enabled: e && !!n,
      gcTime: 1e3 * 60 * 60,
      staleTime: 1e3 * 60 * 5,
      refetchOnReconnect: `always`,
      refetchOnWindowFocus: `always`,
      refetchIntervalInBackground: !0,
      refetchInterval: y,
    });
  },
  I = ({ enabled: e = !0 } = {}) => {
    let t = i(se({ enabled: e }));
    return { ...t, availableRunnerManagers: t.data || [] };
  },
  L = (e, t) => {
    let n = new Set(t.filter((e) => e.provider === b.MANAGED && e.runnerManagerId).map((e) => e.runnerManagerId));
    return e
      .filter((e) => !n.has(e.runnerManagerId))
      .map((e) => ({
        runnerManagerId: e.runnerManagerId,
        region: e.region,
        name: e.name,
        provider: `IOI_HOSTED`,
        isPlaceholder: !0,
      }));
  },
  R = ({ availableRunnerManagers: e, allRunners: t, enabled: n }) => {
    let r = t
      .filter((e) => e.provider === b.MANAGED && e.runnerManagerId)
      .map((e) => e.runnerManagerId)
      .sort();
    return a({
      queryKey: [...F.placeholders(), { availableManagers: e.map((e) => e.runnerManagerId).sort(), usedManagerIds: r }],
      queryFn: () => L(e, t),
      throwOnError: _,
      retry: E,
      staleTime: 1e3 * 60 * 5,
      gcTime: 1e3 * 60 * 60,
      enabled: n,
      refetchOnReconnect: `always`,
      refetchOnWindowFocus: `always`,
      refetchIntervalInBackground: !0,
      refetchInterval: y,
    });
  },
  z = () => {
    let { availableRunnerManagers: e, isLoading: t, error: n, isError: r } = I(),
      { runners: a, isLoading: o, error: s, isError: c } = Y({}),
      l = i(R({ availableRunnerManagers: e, allRunners: a, enabled: !t && !o && !r && !c }));
    return { ...l, isLoading: l.isLoading || t || o, error: l.error || n || s, runnerPlaceholders: l.data || [] };
  },
  B = e(t(), 1),
  V = {
    list: (e, t) => C([`runners`, `list`, e], t),
    isUserAuthenticatedWithRunner: (e, t, n, r) =>
      C([`runners`, `isUserAuthenticated`, { runnerId: e, repoURL: t, sessionId: n, serviceAccountId: r }]),
    parseContext: (e, t, n, r) =>
      C([`runners`, `parseContext`, e || `global`, { contextUrl: t, tokenId: n, keepOriginalError: r }]),
    get: (e) => C([`runners`, { runnerId: e }]),
    listRunnerPolicies: (e) => C([`runners`, `policies`, { runnerId: e }]),
    exchangeToken: (e) => C([`runners`, `exchangeToken`, { runnerId: e }]),
    logsToken: (e) => C([`runners`, `logsToken`, { runnerId: e }]),
    ensureOnboardingRunner: () => C([`runners`, `suitableOnboardingRunner`]),
    searchRepositories: (e, t) => C([`runners`, `searchRepositories`, e || `global`, { query: t }]),
    scmOrganizations: (e, t, n) => C([`scmOrganizations`, e, t, { query: n ?? `` }]),
  },
  H = 1e3 * 60 * 5,
  U = async (e, t, n) => {
    if (
      (console.debug(`[EventHandler] Runner event:`, { operation: n.operation, resourceId: n.resourceId }),
      n.operation === p.UPDATE)
    ) {
      let r = await W(e, n.resourceId);
      r
        ? (J(t, n.resourceId, r), console.debug(`[EventHandler] Runner ${n.resourceId} updated in cache`))
        : (console.info(`[EventHandler] Runner ${n.resourceId} not found during update, removing from cache`),
          J(t, n.resourceId, void 0));
    } else if (n.operation === p.CREATE) {
      let e = V.list({}).slice(0, -1);
      (await t.invalidateQueries({ queryKey: e }),
        console.debug(`[EventHandler] Runner ${n.resourceId} created, lists invalidated`));
    } else
      n.operation === p.DELETE &&
        (J(t, n.resourceId, void 0), console.debug(`[EventHandler] Runner ${n.resourceId} deleted from cache`));
  },
  W = async (e, t) => {
    try {
      let { runner: n } = await e.runnerService.getRunner({ runnerId: t });
      return n;
    } catch (e) {
      (e instanceof n && e.code === s.NotFound) || console.error(`Failed to refetch runner`, t);
    }
  };
function G(e, t, r) {
  let i = f();
  return a({
    queryKey: V.parseContext(e, t, r?.tokenId),
    queryFn: async () => {
      if (!t) throw Error(`Context URL expected`);
      try {
        let n = await i.runnerService.parseContextURL({ contextUrl: t, runnerId: e });
        if (!n) throw Error(`Error parsing context URL`);
        return n;
      } catch (e) {
        if (
          e instanceof n &&
          e.code === s.FailedPrecondition &&
          ![`runner is not active`, `legal reasons`].some((t) => e.message.includes(t))
        ) {
          let t = e.findDetails(j);
          throw new n(
            `Authentication required`,
            s.Unauthenticated,
            new Headers(),
            t.map((e) => ({ desc: j, value: e })),
          );
        }
        throw e;
      }
    },
    throwOnError: !1,
    retry: E,
    gcTime: 1e3 * 60 * 60 * 24,
    staleTime: 1e3 * 60 * 1,
    enabled: !!t && (r?.enabled ?? !0),
  });
}
function K(e, t, n) {
  let r = i(G(e, t, n));
  return { ...r, isLoading: r.isLoading || r.isFetching || r.isPending };
}
var ce = () => {
  let e = f(),
    t = c();
  return u({
    mutationFn: async ({ contextUrl: n, runnerId: r }) => {
      if (!t.getQueryData(x.getAuthenticatedUserQueryKey())) throw Error(`User not authenticated`);
      try {
        let t = await e.runnerService.parseContextURL({ contextUrl: n, runnerId: r });
        if (!t) throw Error(`Error parsing context URL`);
        return t;
      } catch (e) {
        throw e instanceof Error ? e : Error(`Unknown error parsing context URL`);
      }
    },
  });
};
function le(e, t, n) {
  let r = i(q(f(), c(), e, t, void 0, n));
  return { ...r, isLoading: r.isLoading || r.isFetching || r.isPending };
}
function ue(e, t, n) {
  let r = i(q(f(), c(), e, void 0, t, n));
  return { ...r, isLoading: r.isLoading || r.isFetching || r.isPending };
}
function q(e, t, r, i, a, o) {
  let c = a;
  if (i)
    try {
      c = new URL(i).host;
    } catch {}
  return {
    queryKey: V.isUserAuthenticatedWithRunner(r, i || a, o?.sessionId, o?.headers?.serviceAccountId),
    queryFn: async () => {
      if (!i && !a) throw Error(`Context URL or SCM host expected`);
      try {
        let n = await e.runnerService.checkAuthenticationForHost(
          { host: c, runnerId: r },
          { headers: o?.headers?.headers },
        );
        if (n.authenticated)
          return (
            t.invalidateQueries({ queryKey: V.searchRepositories(r ?? `global`).slice(0, -1) }),
            t.invalidateQueries({ queryKey: V.parseContext(r ?? `global`).slice(0, -1) }),
            { type: `Authenticated`, scmName: n.scmName }
          );
        let i = n;
        return {
          type: `AuthenticationRequired`,
          url: i.authenticationUrl,
          patAuth: i.supportsPat,
          scmId: i.scmId,
          scmName: i.scmName,
        };
      } catch (e) {
        if (!(e instanceof n) || e.code !== s.Unimplemented) throw e;
      }
      return { type: `Authenticated`, scmName: `Source Control` };
    },
    refetchInterval: (e) =>
      o?.refetchUntilAuthenticated && e?.state?.data?.type === `AuthenticationRequired` ? 2e3 : !1,
    retry(e, t) {
      if (t instanceof n)
        switch (t.code) {
          case s.DeadlineExceeded:
            return !0;
          case s.Unauthenticated:
          case s.PermissionDenied:
          case s.NotFound:
          case s.InvalidArgument:
          case s.FailedPrecondition:
          case s.Internal:
            return !!o?.retryOnFailedPrecondition;
        }
      return e < 5;
    },
    enabled: !!r && !!c && (o?.enabled ?? !0),
  };
}
function de(e, t, n) {
  let r = f(),
    i = c();
  return o({
    queries:
      t?.map((t) => {
        let a = n?.refetchConditions?.[t] || !1;
        return q(r, i, e, void 0, t, { enabled: !!e, refetchUntilAuthenticated: a, retryOnFailedPrecondition: !0 });
      }) ?? [],
    combine: (e) => e.reduce((e, n, r) => ((e[t?.[r] ?? ``] = n), e), {}),
  });
}
function J(e, t, n) {
  e.setQueryData(V.get(t), n);
  let r = V.list({}).slice(0, -1);
  (e.setQueriesData(
    { queryKey: r },
    (e) => e && (n ? e?.map((e) => (e.runnerId === t ? n : e)) : e?.filter((e) => e.runnerId !== t)),
  ),
    e.invalidateQueries({ queryKey: P.listRunnerEnvironmentClasses(t) }).catch((e) => console.error(e)),
    e.invalidateQueries({ queryKey: P.listRunnerSCMIntegrations(t) }).catch((e) => console.error(e)),
    e.invalidateQueries({ queryKey: P.getRunnerConfigurationSchema(t) }).catch((e) => console.error(e)));
}
var fe = ({ kind: e, creatorId: t, provider: n, enabled: r = !0, headers: i }) => {
    let o = f(),
      { data: s } = w();
    return a({
      queryKey: V.list({ kind: e, creatorId: t, provider: n }, i?.serviceAccountId ? S(i.serviceAccountId) : void 0),
      queryFn: async () => {
        if (!s) throw Error(`User not authenticated`);
        return await v(
          (e) => o.runnerService.listRunners(e, i ? { headers: i.headers } : void 0),
          l(M, {
            filter: l(N, { kinds: e ? [e] : [T.REMOTE], creatorIds: t ? [t] : void 0, providers: n ? [n] : void 0 }),
          }),
          (e) => e.runners,
        );
      },
      throwOnError: _,
      retry: E,
      enabled: r && !!s,
      gcTime: 1e3 * 60 * 60 * 24,
      staleTime: 1e3 * 60 * 1,
      refetchOnReconnect: `always`,
      refetchOnWindowFocus: !0,
    });
  },
  Y = (e) => {
    ee({ resourceType: h.RUNNER });
    let t = i(fe(e));
    return { ...t, runners: t.data || [] };
  },
  pe = (e = !0) => {
    let t = f(),
      { data: n } = w();
    return a({
      queryKey: V.list({ provider: b.DEV_AGENT }),
      queryFn: async () => {
        if (!n) throw Error(`User not authenticated`);
        return await v(
          (e) => t.runnerService.listRunners(e),
          l(M, { filter: l(N, { providers: [b.DEV_AGENT] }) }),
          (e) => e.runners,
        );
      },
      throwOnError: _,
      retry: E,
      enabled: e && !!n,
      staleTime: 1e3 * 30,
      refetchOnReconnect: `always`,
      refetchOnWindowFocus: !0,
      refetchInterval: 1e3 * 30,
    });
  },
  me = (e = !0) => {
    let t = i(pe(e));
    return { ...t, devRunners: t.data || [] };
  },
  he = (e) => {
    let t = f();
    return a({
      queryKey: V.get(e),
      queryFn: async () => {
        if (!e) throw Error(`No runnerId provided`);
        let { runner: n } = await t.runnerService.getRunner({ runnerId: e });
        if (!n) throw Error(`Error fetching runner`);
        return n;
      },
      enabled: !!e,
      staleTime: 1e3 * 60 * 5,
    });
  },
  ge = (e) => i(he(e)),
  _e = () => {
    let e = c(),
      t = f();
    return u({
      mutationFn: async ({ name: e, region: n, provider: r, variant: i }) => {
        let a = { region: n, autoUpdate: !0, releaseChannel: O.STABLE };
        (r === b.AWS_EC2 || r === b.GCP) && (a.devcontainerImageCacheEnabled = !0);
        let { runner: o } = await t.runnerService.createRunner({
          name: e,
          spec: { configuration: a, variant: i },
          provider: r,
        });
        if (!o) throw Error(`Error creating runner`);
        return { runner: o };
      },
      onSuccess: async () => {
        let t = V.list({}).slice(0, -1);
        await e.invalidateQueries({ queryKey: t });
      },
    });
  },
  ve = (e, t) => {
    let n = f(),
      { data: r } = w();
    return a({
      queryKey: V.exchangeToken(e),
      queryFn: async () => {
        if (!r) throw Error(`User not authenticated`);
        let { exchangeToken: t } = await n.runnerService.createRunnerToken({ runnerId: e });
        return { exchangeToken: t };
      },
      enabled: t?.enabled ?? !0,
      staleTime: 1e3 * 60 * 60,
      refetchOnWindowFocus: !1,
      retry: E,
      throwOnError: _,
    });
  },
  ye = (e, t) => i(ve(e, t)),
  be = (e) => {
    let t = f(),
      n = 1e3 * 60 * 45;
    return a({
      queryKey: V.logsToken(e),
      queryFn: async () => {
        if (!e) throw Error(`No runner ID provided`);
        let { accessToken: n } = await t.runnerService.createRunnerLogsToken({ runnerId: e });
        if (!n) throw Error(`No token provided`);
        return n;
      },
      staleTime: n,
      gcTime: n,
      enabled: !!e,
    });
  },
  xe = (e) => i(be(e)),
  Se = () => {
    let e = f(),
      t = c();
    return u({
      mutationFn: async (n) => {
        if (!t.getQueryData(x.getAuthenticatedUserQueryKey())) throw Error(`User not authenticated`);
        let { exchangeToken: r } = await e.runnerService.createRunnerToken({ runnerId: n });
        return { exchangeToken: r };
      },
    });
  },
  X = () => {
    let e = f(),
      t = c();
    return u({
      mutationFn: async ({ runnerManagerId: n, name: r, region: i }) => {
        if (!t.getQueryData(x.getAuthenticatedUserQueryKey())) throw Error(`User not authenticated`);
        let a = { region: i, autoUpdate: !1, releaseChannel: O.STABLE, devcontainerImageCacheEnabled: !0 },
          o = await e.runnerService.createRunner({
            name: r,
            provider: b.MANAGED,
            runnerManagerId: n,
            spec: { configuration: a, variant: k.STANDARD },
          });
        if (!o.runner) throw Error(`Failed to create managed runner`);
        return o.runner;
      },
      onSuccess: async () => {
        await t.invalidateQueries({ queryKey: V.list({}) });
      },
      onError: (e) => {
        console.error(`Failed to create managed runner:`, e);
      },
    });
  },
  Z = () => {
    let e = c(),
      t = f();
    return u({
      mutationFn: async ({ runnerId: n, name: r, spec: i }) => {
        if (!e.getQueryData(x.getAuthenticatedUserQueryKey())) throw Error(`User not authenticated`);
        await t.runnerService.updateRunner({ runnerId: n, name: r, spec: i });
        let { runner: a } = await t.runnerService.getRunner({ runnerId: n });
        if (!a) throw Error(`Error fetching runner after update`);
        J(e, n, a);
      },
    });
  },
  Ce = () => {
    let e = c(),
      t = f();
    return u({
      mutationFn: async ({ runnerId: n, force: r }) => {
        if (!e.getQueryData(x.getAuthenticatedUserQueryKey())) throw Error(`User not authenticated`);
        return await t.runnerService.deleteRunner({ runnerId: n, force: r });
      },
      onSuccess: async () => {
        let t = V.list({}).slice(0, -1);
        await e.invalidateQueries({ queryKey: t });
      },
    });
  },
  we = (e) => {
    let t = f(),
      { data: n } = w();
    return a({
      queryKey: V.listRunnerPolicies(e),
      queryFn: async () => {
        if (!n) throw Error(`User not authenticated`);
        return {
          policies: await v(
            (e) => t.runnerService.listRunnerPolicies(e),
            l(re, { runnerId: e }),
            (e) => e.policies,
          ),
        };
      },
      throwOnError: _,
      retry: E,
      enabled: !!n,
      staleTime: H,
      refetchOnReconnect: !1,
      refetchOnWindowFocus: !1,
    });
  },
  Te = (e) => i(we(e)),
  Ee = (e) => {
    let t = f(),
      n = c();
    return u({
      mutationFn: async ({ setting: r, groupId: i }) => {
        if (!n.getQueryData(x.getAuthenticatedUserQueryKey())) throw Error(`User not authenticated`);
        r === `only-me`
          ? await t.runnerService.deleteRunnerPolicy(l(A, { runnerId: e, groupId: i }))
          : r === `anyone-in-org` &&
            (await t.runnerService.createRunnerPolicy(l(ae, { runnerId: e, groupId: i, role: ie.USER })));
      },
      onSettled: async () => {
        await n.invalidateQueries({ queryKey: V.listRunnerPolicies(e) });
      },
    });
  },
  Q = `us-east-1`,
  $ = `eu-central-1`;
function De() {
  let e = Intl.DateTimeFormat().resolvedOptions().timeZone;
  return e.startsWith(`America`)
    ? Q
    : e.startsWith(`Europe`) || e.startsWith(`Africa`)
      ? $
      : e.startsWith(`Asia`) || e.startsWith(`Pacific`) || e.startsWith(`Australia`)
        ? Q
        : (e.startsWith(`Indian`) || e.startsWith(`Antarctica`), $);
}
var Oe = ({ enabled: e = !0 }) => {
    let { data: t } = Y({ kind: T.REMOTE, enabled: e }),
      r = X(),
      { availableRunnerManagers: a, isPending: o } = I({ enabled: e }),
      c = De(),
      { data: l } = te(),
      u = f(),
      d = (0, B.useRef)(0),
      p = i({
        queryKey: V.ensureOnboardingRunner(),
        queryFn: async () => {
          if (!t) return;
          let e = t.find((e) => e.provider === b.MANAGED && e.spec?.configuration?.region === c);
          if (!e) {
            if (a.length === 0 || l?.tier === m.ENTERPRISE)
              throw Error(`No available runner managers to create a managed runner`);
            {
              let e = a.find((e) => e.region === c) ?? a[0];
              try {
                return await r.mutateAsync({ name: e.name, region: e.region, runnerManagerId: e.runnerManagerId });
              } catch (r) {
                if (r instanceof n && r.code === s.AlreadyExists)
                  return t.find((t) => t?.status?.phase === D.ACTIVE && t.spec?.configuration?.region === e.region);
                throw r;
              }
            }
          }
          let i = t.find((e) => e?.status?.phase === D.ACTIVE);
          if (!e && !i) throw Error(`No suitable runner found. Please create one manually to proceed.`);
          return e ?? i;
        },
        enabled: !!t && !!l && e && !o,
        staleTime: 1e3 * 60 * 5,
        retry: !1,
      }),
      {
        data: h,
        isLoading: g,
        error: _,
      } = i({
        queryKey: V.get(p.data?.runnerId),
        queryFn: async () => {
          if (d.current > 10) throw Error(`timed out when waiting for runner to be ready`);
          let e = p.data?.runnerId;
          if (!e) throw Error(`No runnerId provided`);
          let { runner: t } = await u.runnerService.getRunner({ runnerId: e });
          if (!t) throw Error(`GetRunner rpc call returned no runner`);
          return ((d.current += 1), t);
        },
        refetchInterval: (e) => (e.state.data?.status?.phase === D.ACTIVE ? !1 : 500),
        enabled: !!p.data?.runnerId && e,
      });
    return { data: h?.status?.phase === D.ACTIVE ? h : null, isLoading: p.isLoading || g, error: p.error ?? _ ?? null };
  },
  ke = ({ runnerId: e, query: t, limit: n, scmHost: r, searchMode: i, enabled: o = !0 }) => {
    let s = f();
    return a({
      queryKey: V.searchRepositories(e, t),
      queryFn: r
        ? async () => {
            let { repositories: a } = await s.runnerService.searchRepositories(
              { runnerId: e, searchString: t, limit: n, scmHost: r, searchMode: i },
              { timeoutMs: 30 * 1e3 },
            );
            return a;
          }
        : d,
      enabled: !!e && !!r && o,
    });
  },
  Ae = ({ runnerId: e, query: t, scmHost: n, searchMode: i, enabled: a = !0, pageSize: o = 50 }) => {
    let s = f();
    return r({
      queryKey: [...V.searchRepositories(e, t), { scmHost: n, searchMode: i, pageSize: o }],
      queryFn: async ({ pageParam: r, signal: a }) => {
        let c = await s.runnerService.searchRepositories(
            { runnerId: e, searchString: t, scmHost: n, searchMode: i, pagination: l(g, { pageSize: o, token: r }) },
            { timeoutMs: 3e4, signal: a },
          ),
          u = ne(c.pagination?.nextToken);
        return {
          repositories: c.repositories,
          nextToken: c.pagination?.nextToken || null,
          totalCount: u?.totalCount ?? -1,
          totalPages: u?.totalPages ?? -1,
        };
      },
      initialPageParam: ``,
      getNextPageParam: (e) => e.nextToken || void 0,
      enabled: !!e && !!n && a,
      staleTime: t ? 3e4 : 6e4,
    });
  },
  je = 25,
  Me = ({ runnerId: e, host: t, scmId: n, query: i, enabled: a = !0 }) => {
    let o = f(),
      s = n === `gitlab`,
      c = s && i.length >= 3 ? i : ``,
      u = r({
        queryKey: V.scmOrganizations(e, t, c),
        initialPageParam: ``,
        queryFn: async ({ pageParam: n, signal: r }) => {
          let i = await o.runnerService.listSCMOrganizations(
            { runnerId: e, scmHost: t, query: c, pagination: l(g, { pageSize: je, token: n ?? `` }) },
            { signal: r },
          );
          return {
            organizations: i.organizations.map((e) => ({ name: e.name, url: e.url })),
            nextToken: i.pagination?.nextToken ?? ``,
          };
        },
        getNextPageParam: (e) => (e.nextToken ? e.nextToken : void 0),
        enabled: a && !!e && !!t,
        staleTime: 3e4,
        refetchOnWindowFocus: !1,
      }),
      d = (0, B.useMemo)(() => (u.data?.pages ?? []).flatMap((e) => e.organizations), [u.data]),
      p = u.data?.pages.length ?? 0,
      m = u.fetchNextPage,
      h = u.hasNextPage,
      _ = u.isFetchingNextPage;
    return (
      (0, B.useEffect)(() => {
        s || !h || _ || m();
      }, [s, h, _, m, p]),
      {
        organizations: d,
        fetchNextPage: u.fetchNextPage,
        hasNextPage: u.hasNextPage,
        isLoading: u.isLoading,
        isFetchingNextPage: u.isFetchingNextPage,
        error: u.error ?? null,
      }
    );
  };
export {
  Ee as C,
  Z as S,
  z as T,
  K as _,
  _e as a,
  Ae as b,
  Ce as c,
  ue as d,
  me as f,
  ce as g,
  Me as h,
  X as i,
  Oe as l,
  Y as m,
  U as n,
  Se as o,
  Te as p,
  de as r,
  xe as s,
  q as t,
  le as u,
  ge as v,
  I as w,
  ke as x,
  ye as y,
};
