import { a as e } from "./rolldown-runtime-CGYlQKCx.js";
import { n as t } from "./@mux-DLaEVubF.js";
import {
  Al as n,
  Bd as r,
  Dl as i,
  Dm as a,
  Fm as o,
  Ld as s,
  Lu as c,
  Ml as l,
  Nd as u,
  Ol as d,
  Pd as f,
  Qd as p,
  Rl as m,
  Rm as h,
  Tm as g,
  Vd as _,
  bd as v,
  e_ as y,
  eg as b,
  g_ as x,
  jl as S,
  jm as C,
  kl as w,
  km as T,
  qh as ee,
  t_ as E,
  xd as D,
  xg as te,
  zd as O,
} from "./vendor-DAwbZtf0.js";
import {
  $a as ne,
  $n as re,
  Ba as k,
  Dr as ie,
  F as ae,
  Ja as A,
  Ka as oe,
  R as se,
  Tt as ce,
  Ua as le,
  Va as ue,
  Wa as de,
  Ya as fe,
  c as pe,
  do as me,
  er as he,
  f as ge,
  fa as _e,
  fo as ve,
  fr as ye,
  go as be,
  it as xe,
  l as Se,
  lt as j,
  no as Ce,
  oa as M,
  oo as we,
  ot as Te,
  po as Ee,
  qa as De,
  so as Oe,
  tn as ke,
  to as Ae,
  tr as je,
  wt as Me,
} from "./use-boot-in-app-chat-t-J_VjKS.js";
import { n as Ne, t as N } from "./toast-axaLeIzZ.js";
import { n as P } from "./utils-C9bSuXia.js";
import { R as Pe, g as Fe, h as Ie, l as Le, o as Re, z as ze } from "./agent-queries-CGWy3JAw.js";
import {
  _ as Be,
  a as Ve,
  h as He,
  n as Ue,
  o as F,
  q as We,
  r as Ge,
  x as Ke,
} from "./environment-queries-zpiLcWfm.js";
import { r as qe, t as I, x as Je } from "./project-queries-BMZ3qCU_.js";
import { t as Ye } from "./repo-url-BreAEtzd.js";
import { h as Xe, l as Ze } from "./agent-mode-ClxEfnvU.js";
import { t as Qe } from "./preferred-agent-preference-CSuiiQW5.js";
import { a as $e, d as et, f as tt, i as nt, o as L, r as rt } from "./codex-settings-BPKiMIhT.js";
import { n as it, r as at } from "./use-context-url-DkIqxP6c.js";
import { t as ot } from "./details-url-BbcIdGZp.js";
import { r as st } from "./runner-capabilities-BaYicdCV.js";
var R = e(t(), 1),
  ct = (e) => {
    let t = Fe();
    return {
      copyAgentExecutionId: (0, R.useCallback)(async () => {
        if (!e?.id) {
          N({ title: `No session ID available to copy` });
          return;
        }
        (await navigator.clipboard.writeText(e.id), N({ title: `Session ID copied to clipboard` }));
      }, [e?.id]),
      handleStopAgentExecution: (0, R.useCallback)(async () => {
        if (!e?.id) {
          N({ title: `No session ID available to stop` });
          return;
        }
        try {
          await t.mutateAsync({ agentExecutionId: e.id });
        } catch (e) {
          N({ title: `Failed to stop session`, description: je(e) });
        }
      }, [e?.id, t]),
      isStopPending: t.isPending,
    };
  },
  z = typeof indexedDB < `u`;
function lt(e) {
  return { id: e.id, data: e.data, name: e.name, mimeType: e.mimeType };
}
function ut(e) {
  let t = new Uint8Array(e.data),
    n = new Blob([t], { type: e.mimeType });
  return { id: e.id, data: t, preview: URL.createObjectURL(n), name: e.name, mimeType: e.mimeType };
}
async function dt(e, t) {
  if (z)
    try {
      t.length === 0 ? await g(e) : await T(e, t.map(lt));
    } catch (e) {
      console.warn(`Failed to save images to IndexedDB:`, e);
    }
}
async function ft(e) {
  if (!z) return [];
  try {
    let t = await a(e);
    return !t || t.length === 0 ? [] : t.map(ut);
  } catch (e) {
    return (console.warn(`Failed to load images from IndexedDB:`, e), []);
  }
}
async function pt(e) {
  if (z)
    try {
      await g(e);
    } catch (e) {
      console.warn(`Failed to clear images from IndexedDB:`, e);
    }
}
function mt(e) {
  switch (e.kind) {
    case `pr`:
    case `issue`:
    case `repo`:
    case `git-tag`:
    case `git-commit`:
      return e.url;
    case `project`:
      return F(e.project.initializer) ?? ``;
    case `scratch`:
      return ``;
    default:
      return ``;
  }
}
function ht(e, t) {
  if (e.kind === `project` || e.kind === `scratch`) return !1;
  let n = e.ownerName === t.ownerName && e.repoName === t.repoName;
  if (n && t.url && `url` in e)
    try {
      return new URL(e.url).hostname === new URL(t.url).hostname;
    } catch {
      return n;
    }
  return n;
}
var B = {
    automateEnvSetup: `automate-env-setup`,
    fixBug: `fix-bug`,
    boostTestCoverage: `boost-test-coverage`,
    roastAgents: `roast-agents`,
    securityReview: `security-review`,
    fixTodo: `fix-todo`,
  },
  V = {
    [B.fixBug]: {
      taskName: B.fixBug,
      Icon: D,
      iconColor: `text-content-destructive`,
      iconBackgroundColor: `#FFDED4`,
      title: `Find a critical bug and fix it.`,
      description: `Find a bug in the codebase that looks important and fix it.`,
      prompt: `Scan through the codebase to identify bugs that look important or impactful. Focus on issues that could affect functionality, performance, or user experience. Once you find a significant bug, create a new branch, implement a fix, write or update tests as needed, and commit the changes with a clear description.`,
    },
    [B.boostTestCoverage]: {
      taskName: B.boostTestCoverage,
      Icon: w,
      iconColor: `text-content-brand-accent-01`,
      iconBackgroundColor: `#EFD4FF`,
      title: `Improve test coverage of core business logic.`,
      description: `Find key areas to cover with new and smarter tests.`,
      prompt: `Scan the codebase to understand its main business logic. Then identify ONE untested function related to this business logic and write a single focused, useful unit test for it. Cover the main execution path and follow existing test patterns. Ensure the test passes.`,
    },
    [B.automateEnvSetup]: {
      taskName: B.automateEnvSetup,
      Icon: n,
      iconColor: `text-content-brand`,
      iconBackgroundColor: `#CAD7FA`,
      title: `Automate env setup`,
      description: `Create a fully working dev environment as code configuration.`,
      prompt: `Set up this repository's development environment as code using the built-in devcontainer-setup skill.

Inspect the repository, classify the current setup as missing, stale, or already suitable, make only the needed .devcontainer and .ioi/automations.yaml changes, validate them, rebuild with the available rebuild tool, and check IOI task/service status after the rebuild resumes.

If the setup is already suitable, do not edit files. Do not create unrelated documentation files.`,
    },
  },
  gt = {
    [B.roastAgents]: {
      taskName: B.roastAgents,
      Icon: d,
      iconColor: `text-content-warning`,
      iconBackgroundColor: `#FFDED4`,
      title: `Roast my AGENTS.md and improve it`,
      description: `Review and improve your agent configuration.`,
      prompt: `1. Read AGENTS.md. If missing, create one.
2. Read any agent skill files (e.g. .ioi/skills/, .cursor/rules/).
3. List what's good, what's missing, and what's wrong.
4. Write a concrete improvement spec and save it as AGENTS-IMPROVEMENT-SPEC.md.`,
    },
    [B.securityReview]: {
      taskName: B.securityReview,
      Icon: i,
      iconColor: `text-content-brand-accent-01`,
      iconBackgroundColor: `#EFD4FF`,
      title: `Security review — fix the scariest issue`,
      description: `Audit for vulnerabilities and fix the worst one.`,
      prompt: `1. Scan for: hardcoded secrets, injection flaws (SQL/XSS), insecure deps, missing auth checks, unsafe deserialization.
2. Rank findings by severity.
3. Fix the #1 issue: implement the fix and add tests if needed.`,
    },
    [B.fixTodo]: {
      taskName: B.fixTodo,
      Icon: c,
      iconColor: `text-content-success`,
      iconBackgroundColor: `#CAD7FA`,
      title: `Find a TODO and resolve it`,
      description: `Find and resolve a TODO left in the code.`,
      prompt: `1. Search the codebase for TODO/FIXME/HACK comments.
2. Pick one that describes a real missing feature or fix.
3. Implement what the comment asks for.
4. Remove the TODO comment, add tests if appropriate.`,
    },
  },
  H = {
    getStartedWithTasks: `get-started-with-tasks`,
    connectToScm: `connect-to-github`,
    selectRepository: `select-your-repository`,
    createProject: `create-a-project`,
    writeFirstPrompt: `write-your-first-prompt`,
  },
  _t = {
    [H.connectToScm]: { index: 1, slug: H.connectToScm },
    [H.selectRepository]: { index: 2, slug: H.selectRepository },
    [H.getStartedWithTasks]: { index: 3, slug: H.getStartedWithTasks },
    [H.createProject]: { index: 2, slug: H.createProject },
    [H.writeFirstPrompt]: { index: 3, slug: H.writeFirstPrompt },
  },
  vt = { predefined: `predefined`, custom: `custom` },
  yt = C.object({
    currentStep: C.nativeEnum(H),
    taskMode: C.nativeEnum(vt),
    selectedTasks: C.array(C.nativeEnum(B)).nonempty(),
    customTaskPrompt: C.string(),
    selectedRepositoryUrl: C.string().nullable(),
    lastSelectedScmAuthHost: C.string().nullable().optional(),
  }),
  bt = [B.roastAgents],
  xt = {
    "explain-codebase": B.roastAgents,
    "fix-bug": B.roastAgents,
    "boost-test-coverage": B.securityReview,
    "automate-env-setup": B.fixTodo,
  };
function St(e) {
  if (typeof e != `object` || !e) return e;
  let t = e;
  return (
    Array.isArray(t.selectedTasks) &&
      (t.selectedTasks = t.selectedTasks.map((e) => (typeof e == `string` && e in xt ? xt[e] : e))),
    t
  );
}
var U = f(() => {
    let e = localStorage.getItem(`onboarding-state`),
      t;
    try {
      let n = e ? JSON.parse(e) : null;
      t = n ? yt.safeParse(St(n)) : null;
    } catch {
      t = null;
    }
    return t?.success
      ? {
          currentStep: _t[t.data.currentStep],
          taskMode: t.data.taskMode,
          selectedTasks: t.data.selectedTasks,
          customTaskPrompt: t.data.customTaskPrompt,
          environmentClass: { type: `pending` },
          onboardingRunner: { type: `pending` },
          scmAuthStatuses: {},
          selectedRepositoryUrl: t.data.selectedRepositoryUrl ?? null,
          parsedRepositoryUrl: null,
          lastSelectedScmAuthHost: t.data.lastSelectedScmAuthHost ?? null,
        }
      : {
          currentStep: _t[H.connectToScm],
          taskMode: vt.predefined,
          selectedTasks: bt,
          customTaskPrompt: ``,
          environmentClass: { type: `pending` },
          onboardingRunner: { type: `pending` },
          scmAuthStatuses: {},
          selectedRepositoryUrl: null,
          parsedRepositoryUrl: null,
          lastSelectedScmAuthHost: null,
        };
  }),
  Ct = _(
    (e) => e(U).customTaskPrompt,
    (e, t, n) => {
      t(U, { ...e(U), customTaskPrompt: n });
    },
  );
_(
  (e) => e(U).selectedTasks,
  (e, t, n) => {
    t(U, { ...e(U), selectedTasks: n });
  },
);
var wt = _(
    (e) => e(U).taskMode,
    (e, t, n) => {
      t(U, { ...e(U), taskMode: n });
    },
  ),
  Tt = _(
    (e) => e(U).currentStep,
    (e, t, n) => {
      t(U, { ...e(U), currentStep: n });
    },
  ),
  W = _(
    (e) => e(U).environmentClass,
    (e, t, n) => {
      t(U, { ...e(U), environmentClass: n });
    },
  ),
  Et = _(
    (e) => e(U).scmAuthStatuses,
    (e, t, n) => {
      t(U, { ...e(U), scmAuthStatuses: n });
    },
  ),
  Dt = (e, t) => e[t] || { type: `pending` },
  Ot = _(
    (e) => e(U).lastSelectedScmAuthHost,
    (e, t, n) => {
      t(U, { ...e(U), lastSelectedScmAuthHost: n });
    },
  ),
  kt = _(
    (e) => e(U).onboardingRunner,
    (e, t, n) => {
      t(U, { ...e(U), onboardingRunner: n });
    },
  ),
  At = _(
    (e) => e(U).selectedRepositoryUrl,
    (e, t, n) => {
      t(U, { ...e(U), selectedRepositoryUrl: n });
    },
  ),
  jt = _(
    (e) => e(U).parsedRepositoryUrl,
    (e, t, n) => {
      t(U, { ...e(U), parsedRepositoryUrl: n });
    },
  ),
  Mt = _((e) => {
    let t = e(W),
      n = e(kt),
      r = e(Et),
      i = [];
    (t.type === `error` && i.push(t.error), n.type === `error` && i.push(n.error));
    for (let e of Object.values(r)) e.type === `error` && i.push(e.error);
    return i.length > 0 ? i : null;
  }),
  Nt = _((e) => {
    let t = e(Ct),
      n = e(W);
    return t && n.type === `success` ? { contexts: [], prompts: [t], environmentClass: n.data } : null;
  }),
  Pt = _((e) => {
    let t = e(Ct),
      n = e(W),
      r = e(At),
      i = e(jt);
    return !t || n.type !== `success`
      ? { type: `pending` }
      : r
        ? i?.git
          ? {
              type: `success`,
              data: {
                prompts: [t],
                contexts: [
                  {
                    kind: `repo`,
                    url: i.originalContextUrl,
                    branchName: i.git.branch,
                    repoName: i.git.repo,
                    ownerName: i.git.owner,
                  },
                ],
                environmentClass: n.data,
              },
            }
          : { type: `pending` }
        : { type: `success`, data: { prompts: [t], contexts: [{ kind: `scratch` }], environmentClass: n.data } };
  });
function Ft() {
  let e = m((e) => {
    let t = {
      currentStep: e.currentStep.slug,
      taskMode: e.taskMode,
      selectedTasks: e.selectedTasks,
      customTaskPrompt: e.customTaskPrompt,
      selectedRepositoryUrl: e.selectedRepositoryUrl,
      lastSelectedScmAuthHost: e.lastSelectedScmAuthHost,
    };
    localStorage.setItem(`onboarding-state`, JSON.stringify(t));
  }, 1e3);
  s(
    (0, R.useMemo)(
      () =>
        l((t) => {
          e(t(U));
        }),
      [e],
    ),
  );
}
var It = [
    {
      taskName: B.automateEnvSetup,
      Icon: P(S),
      iconColor: `text-content-brand`,
      iconBackgroundColor: `#CAD7FA`,
      title: `Automate env setup`,
      description: `Create a fully working dev environment as code configuration.`,
      prompt: V[B.automateEnvSetup].prompt,
    },
    {
      taskName: B.fixBug,
      Icon: P(v),
      iconColor: `text-content-destructive`,
      iconBackgroundColor: `#FFDED4`,
      title: `Fix a bug`,
      description: `Find a bug in the codebase that looks important and fix it.`,
      prompt: V[B.fixBug].prompt,
    },
    {
      taskName: B.boostTestCoverage,
      Icon: P(w),
      iconColor: `text-content-brand-accent-01`,
      iconBackgroundColor: `#EFD4FF`,
      title: `Boost your test coverage`,
      description: `Find key areas to cover with new and smarter tests.`,
      prompt: V[B.boostTestCoverage].prompt,
    },
  ],
  Lt = `onboarding-pending-submission`,
  Rt = (e) => `${Lt}-${e}`,
  zt = (e) => {
    let t = localStorage.getItem(Rt(e));
    return t
      ? JSON.parse(t, (e, t) => (typeof t == `string` && /^\d+n$/.test(t) ? BigInt(t.substring(0, t.length - 1)) : t))
      : null;
  },
  Bt = (e, t) => {
    localStorage.setItem(
      Rt(t),
      JSON.stringify(e, (e, t) => (typeof t == `bigint` ? t.toString() + `n` : t)),
    );
  },
  Vt = (e) => {
    localStorage.removeItem(Rt(e));
  },
  Ht = () => {
    let e = localStorage.getItem(`onboarding-state`) !== null;
    return (localStorage.removeItem(`onboarding-state`), e);
  };
function Ut(e) {
  return e.kind === `project`
    ? {
        kind: `project`,
        projectId: e.project.id,
        projectName: e.project.metadata?.name ?? ``,
        environmentClassIds: e.environmentClasses.map((e) => e.clazz.id),
      }
    : e;
}
function G(e) {
  return e.kind === `project` && `projectId` in e;
}
function Wt(e) {
  return {
    kind: `project-unresolved`,
    projectId: e.projectId,
    projectName: e.projectName,
    environmentClassIds: e.environmentClassIds,
  };
}
var Gt = `prompt-box-state-home`,
  Kt = `CODEX_SETTINGS`,
  qt = `conversation-input-home`;
function Jt() {
  return { prompt: ``, contexts: [], environmentClass: null };
}
function Yt(e) {
  let t = L(e),
    n = {};
  return (
    t.model !== rt && (n.model = t.model),
    t.reasoningEffort !== nt && (n.reasoningEffort = t.reasoningEffort),
    t.serviceTier !== $e && (n.serviceTier = t.serviceTier),
    Object.keys(n).length > 0 ? n : void 0
  );
}
function Xt(e) {
  let t = L(e);
  return et(t.model) ? t : L({ ...t, model: rt });
}
function Zt(e) {
  return JSON.stringify(E(k, L(e)));
}
function Qt(e) {
  if (e)
    try {
      return L(y(k, JSON.parse(e)));
    } catch {
      return;
    }
}
function $t(e) {
  let t = K(e).codexSettings;
  if (t) return Zt(Xt(t));
}
function en(e) {
  return !e.prompt && e.contexts.length === 0 && !e.environmentClass && !e.codexSettings;
}
function tn(e) {
  let t = `${qt}_${e}`;
  localStorage.removeItem(t);
}
function K(e) {
  let t = `${Gt}_${e}`,
    n = localStorage.getItem(t);
  if ((tn(e), n))
    try {
      return JSON.parse(n);
    } catch {
      localStorage.removeItem(t);
    }
  return Jt();
}
function q(e, t) {
  let n = `${Gt}_${e}`;
  if (en(t)) localStorage.removeItem(n);
  else
    try {
      localStorage.setItem(n, JSON.stringify(t));
    } catch {
      console.warn(`Failed to save prompt input state to localStorage - quota may be exceeded`);
    }
}
function nn(e, t) {
  q(e, { prompt: ``, contexts: [], environmentClass: null, codexSettings: t ? Yt(t) : void 0 });
}
var rn = `prompt-box-images-home`;
function J(e) {
  return `${rn}_${e}`;
}
var an = _(!1),
  on = _(!1),
  sn = _([]),
  cn = _(null),
  ln = {
    none: `none`,
    context: `context`,
    contextAssociatedProjectSelector: `contextAssociatedProjectSelector`,
    projectSelector: `projectSelector`,
    urlSelector: `repoSelector`,
    environmentClassSelector: `environmentClassSelector`,
    repositoryBrowser: `repositoryBrowser`,
  },
  un = _(0),
  dn = _([...It]),
  fn = _(ln.none),
  pn = _(0),
  mn = _([]),
  Y = _(null),
  X = _([]),
  hn = _((e) => e(X).find((e) => e.kind === `project`)),
  Z = _(null);
_(null);
var gn = _(!1),
  Q = _([]),
  _n = _(!1),
  vn = _(null),
  yn = u((e) => f(() => (typeof window < `u` ? K(e).prompt : ``))),
  $ = u((e) => {
    let t = f(() => (typeof window < `u` ? Xt(K(e).codexSettings) : L()));
    return _(
      (e) => e(t),
      (n, r, i) => {
        let a = L(i);
        (r(t, a), typeof window < `u` && q(e, { ...K(e), codexSettings: Yt(a) }));
      },
    );
  }),
  bn = () => {
    let { data: e } = j();
    if (!e) throw Error(`User not authenticated`);
    let t = e.organizationId,
      n = yn(t),
      r = $(t);
    return (0, R.useMemo)(
      () =>
        _(
          (e) => e(n),
          (e, i, a) => {
            (i(n, a), a || nn(t, e(r)));
          },
        ),
      [r, n, t],
    );
  },
  xn = () => {
    let { data: e } = j();
    if (!e) throw Error(`User not authenticated`);
    let t = e.organizationId,
      n = (0, R.useMemo)(() => $(t), [t]),
      { data: i, isFetched: a } = xe(Kt),
      { mutateAsync: o } = Te(),
      s = r(),
      c = (0, R.useRef)(void 0);
    return (
      (0, R.useEffect)(() => {
        if (i?.value === void 0 || i.value === c.current) return;
        let e = Qt(i.value);
        e && ((c.current = i.value), s.set(n, e));
      }, [n, i?.value, s]),
      (0, R.useEffect)(() => {
        if (!a || i?.value !== void 0 || c.current) return;
        let e = $t(t);
        e &&
          ((c.current = e),
          o({ key: Kt, value: e }).catch((e) => {
            console.error(`Failed to persist Codex settings preference`, e);
          }));
      }, [i?.value, a, t, o]),
      (0, R.useMemo)(
        () =>
          _(
            (e) => e(n),
            (e, t, r) => {
              let i = L(r),
                a = Zt(i);
              (t(n, i),
                (c.current = a),
                o({ key: Kt, value: a }).catch((e) => {
                  console.error(`Failed to persist Codex settings preference`, e);
                }));
            },
          ),
        [n, o],
      )
    );
  };
function Sn() {
  let e = O(vn),
    t = bn(),
    n = r();
  return (0, R.useCallback)(
    (r) => {
      let i = n.get(t);
      (e({ ...r, originalText: i }), n.set(t, r.cleanedText));
    },
    [e, n, t],
  );
}
var Cn = () => {
    let { data: e } = j();
    if (!e) throw Error(`User not authenticated`);
    let t = e.organizationId,
      n = O(yn(t)),
      i = O(X),
      a = O(Z),
      o = O(Q),
      s = O(Y),
      c = $(t),
      l = r();
    return (0, R.useCallback)(() => {
      let e = l.get(c);
      (i([]), a(null), s(null), n(``));
      let r = l.get(Q);
      for (let e of r) URL.revokeObjectURL(e.preview);
      (o([]), nn(t, e), pt(J(t)));
    }, [n, i, a, s, o, c, l, t]);
  },
  wn = () => {
    let { data: e } = j();
    if (!e) throw Error(`User not authenticated`);
    let t = e.organizationId,
      n = yn(t),
      r = $(t),
      i = m((e) => {
        q(t, e);
      }, 500),
      a = m((e) => {
        dt(J(t), e);
      }, 500);
    (0, R.useEffect)(
      () => () => {
        (i.cancel(), a.cancel());
      },
      [i, a],
    );
    let o = (0, R.useCallback)(
      (e) => {
        if (!e(on)) return;
        let o = e(n),
          s = e(X),
          c = e(Z),
          l = e(Q),
          u = e(r),
          d = {
            prompt: o,
            contexts: s.map(Ut),
            environmentClass: c ? { id: c.clazz.id, displayName: c.clazz.displayName } : null,
            codexSettings: Yt(u),
          };
        (en(d) ? (i.cancel(), nn(t)) : i(d), l.length === 0 ? (a.cancel(), pt(J(t))) : a(l));
      },
      [n, r, i, a, t],
    );
    s((0, R.useMemo)(() => l(o), [o]));
  },
  Tn = wn,
  En = ({
    api: e,
    queryClient: t,
    environmentClassMap: n,
    isEnvironmentClassMapLoading: r,
    onFailedProjects: i,
    onFailedEnvironmentClass: a,
  }) => {
    let { data: o } = j(),
      s = o?.organizationId,
      c = O(X),
      l = O(Z),
      u = O(Q),
      d = O(an),
      f = O(on),
      p = O(sn),
      m = O(cn),
      h = (0, R.useRef)(!1),
      g = (0, R.useRef)(!1),
      _ = (0, R.useRef)(!1),
      v = (0, R.useRef)(void 0);
    ((0, R.useEffect)(() => {
      s !== v.current &&
        ((h.current = !1),
        (g.current = !1),
        (_.current = !1),
        f(!1),
        c([]),
        l(null),
        u([]),
        p([]),
        m(null),
        d(!1),
        (v.current = s));
    }, [s, f, c, l, u, p, m, d]),
      (0, R.useEffect)(() => {
        !s ||
          _.current ||
          ((_.current = !0),
          ft(J(s)).then((e) => {
            e.length > 0 && u(e);
          }));
      }, [s, u]),
      (0, R.useEffect)(() => {
        if (!s || g.current) return;
        let e = K(s),
          t = e.contexts.length > 0,
          n = !!e.environmentClass;
        if (!t && !n) {
          ((g.current = !0), (h.current = !0), f(!0));
          return;
        }
        let r = e.contexts.filter(G),
          i = e.contexts.filter((e) => !G(e));
        (i.length > 0 && c(i), n && m(e.environmentClass), r.length > 0 && (p(r.map(Wt)), d(!0)), (g.current = !0));
      }, [s, c, m, p, d, f]),
      (0, R.useEffect)(() => {
        if (!s || h.current || r || !g.current) return;
        let o = K(s),
          u = !!o.environmentClass,
          _ = o.contexts.filter(G),
          v = o.contexts.filter((e) => !G(e)),
          y = null;
        if (
          (u && n[o.environmentClass.id]
            ? ((y = n[o.environmentClass.id]), l(y), m(null))
            : u && (m(null), a?.(o.environmentClass.displayName)),
          _.length === 0)
        ) {
          (u &&
            !y &&
            q(s, { prompt: o.prompt, contexts: v.map(Ut), environmentClass: null, codexSettings: o.codexSettings }),
            (h.current = !0),
            f(!0));
          return;
        }
        (async () => {
          let r = [...v],
            a = [];
          for (let i of _)
            try {
              let a = I(e, i.projectId),
                o = await t.fetchQuery(a),
                s = i.environmentClassIds.map((e) => n[e]).filter(Boolean);
              r.push({ kind: `project`, project: o, environmentClasses: s });
            } catch (e) {
              (console.warn(`Failed to resolve stored project context: ${i.projectId}`, e),
                a.push(i.projectName || i.projectId));
            }
          (c(r),
            p([]),
            m(null),
            d(!1),
            (h.current = !0),
            f(!0),
            a.length > 0 && i?.(a),
            (a.length > 0 || (u && !y)) &&
              q(s, {
                prompt: o.prompt,
                contexts: r.map(Ut),
                environmentClass: y ? { id: y.clazz.id, displayName: y.clazz.displayName } : null,
                codexSettings: o.codexSettings,
              }));
        })();
      }, [s, n, r, e, t, c, l, d, f, p, m, i, a]));
  },
  Dn = u((e) => {
    let t = _(null, (n, r, i) => {
      (r(t, i),
        i ? (r(e, i.prompts[0]), r(X, i.contexts), r(Z, i.environmentClass)) : (r(e, ``), r(X, []), r(Z, null)));
    });
    return t;
  }),
  On = () => {
    let { data: e } = j(),
      t = bn(),
      n = (0, R.useCallback)(() => {
        (e?.organizationId && Vt(e.organizationId), Dn.remove(t));
      }, [e, t]);
    return { pendingSubmissionAtom: Dn(t), clearPendingSubmission: n };
  };
async function kn(e, t) {
  let { projectName: n, contextURL: r, git: i, environmentClassId: a } = e,
    o = await t.createProject.mutateAsync({
      name: n,
      contextURL: r,
      gitConfig: i
        ? {
            remoteUrl: i.cloneUrl,
            ref: i.branch || i.tag || i.commit || ``,
            upstreamRemoteUrl: i.upstreamRemoteUrl || void 0,
          }
        : void 0,
    });
  return (
    a &&
      (await t.updateProjectEnvironmentClasses.mutateAsync({
        projectId: o.id,
        projectEnvironmentClasses: [x(M, { environmentClass: { case: `environmentClassId`, value: a }, order: 0 })],
      })),
    { project: o }
  );
}
var An = (e) => {
    let { showToast: t = !0 } = e ?? {},
      n = qe(),
      r = Je(),
      { toast: i } = Ne();
    return {
      createProject: (0, R.useCallback)(
        async (e) => {
          let a = await kn(e, { createProject: n, updateProjectEnvironmentClasses: r });
          return (
            t &&
              i({
                title: `New project created`,
                description: `Configure settings, secrets, prebuilds and more in project settings.`,
                link: { label: `Go to project settings`, href: `/projects/${a.project.id}/settings` },
                duration: 1e4,
              }),
            a
          );
        },
        [n, r, i, t],
      ),
    };
  },
  jn = `(max-width: 767px)`,
  Mn = `(prefers-reduced-motion: reduce)`;
function Nn(e, t, n, r, i) {
  let a = window.matchMedia(jn).matches,
    o = window.matchMedia(Mn).matches,
    s = `startViewTransition` in document,
    c = document.documentElement.classList.contains(`view-transition-active`),
    l = s && !o && !c && (a || i?.includeDesktop),
    u = (r) => {
      (n?.(), r ? e(t, r) : e(t));
    };
  if (l) {
    let e = [`view-transition-active`];
    (i?.activeClassName && e.push(i.activeClassName),
      document.documentElement.classList.add(...e),
      document
        .startViewTransition(() => {
          u({ ...r, flushSync: !0 });
        })
        .finished.catch(() => void 0)
        .finally(() => {
          document.documentElement.classList.remove(...e);
        }));
  } else u(r);
}
var Pn = `mcr.microsoft.com/devcontainers/universal:4.0.1-noble`;
function Fn(e) {
  return e
    .filter((e) => e.kind !== `project` && e.kind !== `scratch`)
    .map(mt)
    .filter((e) => e !== ``);
}
var In = !1;
function Ln(e) {
  let { onPromptValidationError: t, onBeforeNavigate: n } = e ?? {},
    i = He(),
    a = Be(),
    s = Le(),
    c = Ie(),
    l = Ke(),
    { toast: u } = Ne(),
    d = te(),
    [, f] = h(`ioi-onboarding`, o.withDefault(!1)),
    { data: m } = ke(),
    g = ce(),
    { contextUrls: _ } = it(),
    v = at(),
    { value: y } = Se(),
    { value: S } = pe(),
    { preferredAgentId: C } = Qe(y),
    w = C ?? (y ? Pe.InEnvironmentCodexAppAgent.id : void 0),
    { value: T } = ae(),
    { value: E } = se(),
    { value: D } = ge(),
    O = ie(),
    k = r(),
    { createProject: xe } = An(),
    j = (0, R.useCallback)(
      ({ agentMode: e, selectedAgentId: t, devRunnerId: n, envClass: r }) => {
        let i = e
          ? Ze({ agentMode: e, selectedAgentId: t, defaultAgentId: w })
          : { selectedAgentId: t, defaultAgentId: w ?? void 0 };
        return Re({
          selectedAgentId: i.selectedAgentId,
          defaultAgentId: i.defaultAgentId,
          devRunnerId: n,
          rsaEnabled: T,
          rsaCapable: r?.runner ? st(r.runner) : !1,
          runnerId: r?.runner?.runnerId,
        });
      },
      [w, T],
    ),
    M = (0, R.useCallback)(() => {
      if (!m?.defaultEnvironmentImage) return x(Ee, { defaultDevcontainerImage: Pn });
    }, [m?.defaultEnvironmentImage]),
    Te = (0, R.useCallback)(
      async (e) => {
        let t = k.get(Y);
        if (!t) return null;
        let { project: n } = await xe({
          projectName: t.projectName,
          contextURL: t.contextUrl,
          git: t.git,
          environmentClassId: e?.clazz.id,
        });
        return (k.set(Y, null), { kind: `project`, project: n, environmentClasses: e ? [e] : [] });
      },
      [xe, k],
    ),
    N = (0, R.useCallback)(
      (e, t, n, r) => {
        let o = null,
          s = ``,
          c = ``,
          l = ``;
        for (let t of e)
          switch (t.kind) {
            case `project`:
              o = t;
              break;
            case `issue`:
              ((c = t.branchName), (l = t.url));
              break;
            case `pr`:
              ((c = t.fromBranchName), (l = t.url));
              break;
            case `git-commit`:
              ((s = t.commitHash), (l = t.url));
              break;
            case `repo`:
              l = t.url;
              break;
            case `scratch`:
              l = ``;
              break;
          }
        let u = M();
        if (o) {
          let e = t?.clazz.id;
          return s
            ? a.mutateAsync({
                project: o.project,
                gitInitializerParams: { ref: s, refType: `commit` },
                environmentClassId: e,
                devcontainerConfig: u,
                annotations: n,
                sessionId: r,
              })
            : c
              ? a.mutateAsync({
                  project: o.project,
                  gitInitializerParams: { ref: c, refType: `branch` },
                  environmentClassId: e,
                  devcontainerConfig: u,
                  annotations: n,
                  sessionId: r,
                })
              : a.mutateAsync({
                  project: o.project,
                  environmentClassId: e,
                  devcontainerConfig: u,
                  annotations: n,
                  sessionId: r,
                });
        }
        if (!t) throw Error(`environment class must be selected for non-project context!`);
        return l
          ? i.mutateAsync({
              type: `contextUrl`,
              contextURL: l,
              classID: t.clazz.id,
              devcontainerConfig: u,
              annotations: n,
              sessionId: r,
            })
          : i.mutateAsync({ type: `blank`, classID: t.clazz.id, devcontainerConfig: u, annotations: n, sessionId: r });
      },
      [i, a, M],
    ),
    P = (0, R.useCallback)(
      async (e, t, n, r, i, a, o, l, u, d, f) => {
        let { agentId: m, runnerId: h } = j({ agentMode: o, selectedAgentId: l, devRunnerId: i, envClass: a }),
          g = ze(m) && d ? tt(d) : void 0,
          { agentExecutionId: _ } = await s.mutateAsync({
            agentId: m,
            codeContext: x(_e, { context: { case: `environmentId`, value: t.id } }),
            name: n,
            runnerId: h,
            sessionId: u,
            codexSettings: g,
            annotations: f,
          }),
          v = [x(A, { input: { case: `text`, value: x(fe, { content: e }) } })];
        for (let e of r ?? [])
          v.push(x(A, { input: { case: `image`, value: x(De, { data: e.data, mimeType: e.mimeType }) } }));
        let y = p();
        return (
          await c.mutateAsync(
            x(le, {
              agentExecutionId: _,
              input: { case: `userInput`, value: x(oe, { id: y, inputs: v }) },
              codexSettings: g,
              turnOptions: S ? Xe(o) : void 0,
            }),
          ),
          { agentExecutionId: _, userInputBlockId: y }
        );
      },
      [S, j, c, s],
    ),
    Fe = (0, R.useCallback)(
      async (e, t) => {
        try {
          await l.mutateAsync({ environmentId: e.id, force: !1 });
        } catch (n) {
          console.error(`Environment cleanup failed after conversation failure`, {
            environmentId: e.id,
            originalError: t,
            cleanupError: n,
          });
        }
      },
      [l],
    ),
    F = Me(),
    qe = We(),
    I = b(),
    { mutateAsync: Je, isPending: Ye } = ee({
      mutationFn: async (e) => {
        let {
            prompt: t,
            contexts: n,
            envClass: r,
            templateTitle: i,
            images: a,
            devRunnerId: o,
            agentMode: s,
            selectedAgentId: c,
            codexSettings: l,
            agentAnnotations: u,
          } = e,
          d = null,
          f = ``,
          m = ``,
          h = ``;
        for (let e of n)
          switch (e.kind) {
            case `project`:
              d = e;
              break;
            case `issue`:
              ((m = e.branchName), (h = e.url));
              break;
            case `pr`:
              ((m = e.fromBranchName), (h = e.url));
              break;
            case `git-commit`:
              ((f = e.commitHash), (h = e.url));
              break;
            case `repo`:
              h = e.url;
              break;
            case `scratch`:
              h = ``;
              break;
          }
        let g = M(),
          _ = (e) => {
            let t = x(me, { desiredPhase: Oe.RUNNING });
            return (g && (t.devcontainer = g), e && (t.machine = x(be, { class: e })), t);
          },
          v;
        if (d) {
          let e = _(r?.clazz.id);
          if (f || m) {
            let t = f || m,
              n = f ? `commit` : `branch`,
              r = Ve(d.project, { ref: t, refType: n });
            if (!r.initializer) throw new Ue(`No git initializer found`);
            e.content = x(ve, { initializer: r.initializer });
          }
          v = { case: `createEnvironmentFromProject`, value: x(Ae, { projectId: d.project.id, spec: e }) };
        } else {
          if (!r) throw Error(`environment class must be selected for non-project context!`);
          let e = _(r.clazz.id);
          (h
            ? (e.content = x(ve, {
                session: p(),
                initializer: { specs: [x(we, { spec: { case: `contextUrl`, value: x(ne, { url: h }) } })] },
              }))
            : (e.content = x(ve, { session: p(), initializer: { specs: [] } })),
            (v = { case: `createEnvironment`, value: x(Ce, { spec: e }) }));
        }
        let { agentId: y, runnerId: b } = j({ agentMode: s, selectedAgentId: c, devRunnerId: o, envClass: r }),
          C = ze(y) && l ? tt(l) : void 0,
          w = x(de, {
            agentId: y,
            name: i ?? ``,
            runnerId: b ?? ``,
            codexSettings: C,
            turnOptions: S ? Xe(s) : void 0,
            annotations: u,
          }),
          T = [x(A, { input: { case: `text`, value: x(fe, { content: t }) } })];
        for (let e of a ?? [])
          T.push(x(A, { input: { case: `image`, value: x(De, { data: e.data, mimeType: e.mimeType }) } }));
        let ee = p(),
          E = x(oe, { id: ee, inputs: T }),
          D = await O.agentService.createAgentSession(x(ue, { environment: v, agent: w, initialInput: E }));
        if (!D.environment) throw Error(`CreateAgentSession did not return an environment`);
        return { environment: D.environment, agentExecutionId: D.agentExecutionId, userInputBlockId: ee };
      },
      onSettled: (e, t) => {
        t
          ? F(`Environment Create Failed`, { error: re(t) })
          : F(`Environment Create Succeeded`, { environmentId: e?.environment?.id });
      },
      onSuccess: async () => {
        (await Promise.all([
          I.invalidateQueries({ queryKey: Ge.list().slice(0, -1) }),
          I.invalidateQueries({ queryKey: Ge.listInventory({}).slice(0, -1) }),
          I.invalidateQueries({ queryKey: Ge.runnerEnvironments(``).slice(0, -1) }),
        ]).catch((e) => console.error(e)),
          qe());
      },
      meta: { method: `AgentService.CreateAgentSession` },
    }),
    $e = (0, R.useCallback)(
      async (e, t, n, r, i, a, o, s, c, l) => {
        if (D)
          return Je({
            prompt: e,
            contexts: t,
            envClass: n,
            templateTitle: r,
            images: i,
            devRunnerId: a,
            agentMode: o,
            selectedAgentId: s,
            codexSettings: c,
            agentAnnotations: l,
          });
        let u = null;
        try {
          let d;
          if (E) {
            let { session: e } = await O.sessionService.createSession({});
            if (!e?.id) throw Error(`Failed to create session: no session ID returned`);
            d = e.id;
          }
          u = await N(t, n, void 0, d);
          let { agentExecutionId: f, userInputBlockId: p } = await P(e, u, r, i, a, n, o, s, d, c, l);
          return { environment: u, agentExecutionId: f, userInputBlockId: p };
        } catch (e) {
          throw (u && Fe(u, e), e);
        }
      },
      [Fe, Je, D, N, P, E, O.sessionService],
    );
  return {
    submitPrompts: (0, R.useCallback)(
      async ({
        prompts: e,
        contexts: r,
        environmentClass: i,
        shouldNavigate: a = !0,
        templateTitles: o,
        images: s,
        devRunnerId: c,
        agentMode: l,
        selectedAgentId: p,
        codexSettings: m,
        agentAnnotations: h,
        onSuccess: y,
      }) => {
        if (In) return (console.warn(`duplicate prompt submission - ignoring`), !0);
        try {
          In = !0;
          let f = r;
          try {
            let e = await Te(i);
            e && (f = [...r, e]);
          } catch (e) {
            return (u({ title: `Failed to create project`, description: je(e) }), !0);
          }
          let b = await Promise.allSettled(
              e.map((e, t) => {
                let n = o?.[t];
                return $e(e, f, i, n, t === 0 ? s : void 0, c, l, p, m, h);
              }),
            ),
            x = b.reduce((e, t) => (t.status === `fulfilled` ? e + 1 : e), 0),
            S = b.length - x,
            C = S === b.length,
            w = null,
            T;
          for (let t = 0; t < b.length; t++) {
            let n = b[t];
            switch (n.status) {
              case `fulfilled`:
                n.value && !w && ((w = n.value), (T = e[t]));
                break;
              case `rejected`:
                g(`prompt_submission_error`, n.reason);
                break;
            }
          }
          if (x > 0) {
            let e = Fn(r);
            (e.length > 0 && v([...e, ...(_ || []).filter((t) => !e.includes(t))]),
              !a && w && y?.(w),
              w &&
                a &&
                Nn(d, ot({ environment: w.environment }), n, {
                  state: {
                    preferredAgentExecutionId: w.agentExecutionId,
                    pendingMessageId: w.userInputBlockId,
                    pendingMessageContent: T,
                  },
                }));
          }
          if (S === b.length) {
            let e = `Could not start any sessions. Please try again.`,
              n = Error(e);
            for (let t of b)
              if (t.status === `rejected`) {
                ((e = je(t.reason)), (n = t.reason));
                break;
              }
            let r = he(n);
            r && t ? t(r) : ye(n) || u({ title: `Failed to start executions`, description: e });
          }
          return C;
        } finally {
          ((In = !1), f(!1));
        }
      },
      [f, Te, $e, g, u, d, _, v, t, n],
    ),
    isSubmittingPrompts: Ye || i.isPending || a.isPending || s.isPending || c.isPending,
  };
}
var Rn = `Please help configure this repository using [Dev Container](https://ioi.com/docs/ioi/configuration/devcontainer/overview) and [Automations](https://ioi.com/docs/ioi/configuration/tasks-and-services/overview).

Use the built-in \`devcontainer-setup\` skill to inspect the repository, classify the setup as missing, stale, or already suitable, and make only the configuration changes needed for future environments to start, rebuild, install dependencies, and run services reproducibly.

Open a draft PR using the built-in Dev Container Setup PR Template once the setup has been completed successfully.`,
  zn = `Dev Container setup`;
function Bn(e) {
  let t = Ye(e);
  if (t)
    return {
      kind: `repo`,
      url: F(e.spec?.content?.initializer) ?? t.repoUrl,
      branchName: e.status?.content?.git?.branch ?? ``,
      repoName: t.repo,
      ownerName: t.account,
    };
}
export {
  Et as $,
  Sn as A,
  vt as B,
  sn as C,
  xn as D,
  Cn as E,
  Bt as F,
  W as G,
  B as H,
  It as I,
  Mt as J,
  Dt as K,
  _t as L,
  Ht as M,
  Vt as N,
  On as O,
  zt as P,
  Pt as Q,
  H as R,
  cn as S,
  wn as T,
  Tt as U,
  V,
  Ct as W,
  U as X,
  kt as Y,
  jt as Z,
  vn as _,
  Nn as a,
  ht as at,
  Q as b,
  mn as c,
  z as ct,
  gn as d,
  At as et,
  _n as f,
  un as g,
  hn as h,
  Ln as i,
  mt as it,
  En as j,
  bn as k,
  fn as l,
  lt,
  Y as m,
  zn as n,
  wt as nt,
  An as o,
  pt as ot,
  an as p,
  Ot as q,
  Bn as r,
  Ft as rt,
  ln as s,
  ut as st,
  Rn as t,
  Nt as tt,
  pn as u,
  ct as ut,
  X as v,
  Tn as w,
  dn as x,
  Z as y,
  gt as z,
};
