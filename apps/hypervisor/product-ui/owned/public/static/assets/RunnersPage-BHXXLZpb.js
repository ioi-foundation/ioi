import { a as e } from "./rolldown-runtime-CGYlQKCx.js";
import { At as t, Lt as n, ft as r, kt as i, nt as a, pt as o, vn as s } from "./SegmentProvider-CXCNBY9U.js";
import { n as c } from "./@mux-DLaEVubF.js";
import { _p as l, dm as u, v_ as d, xg as f } from "./vendor-DAwbZtf0.js";
import {
  Dt as p,
  Li as m,
  Lr as h,
  cs as g,
  hn as _,
  lt as v,
  ss as y,
  tr as b,
  vn as x,
  wt as S,
} from "./use-boot-in-app-chat-t-J_VjKS.js";
import { d as C, h as w } from "./runner_manager_pb-BYgy9Ytq.js";
import { n as T } from "./toast-axaLeIzZ.js";
import { a as E, t as D } from "./button-6YP03Qf2.js";
import { t as O } from "./cn-DppMFCU8.js";
import { m as k } from "./group-queries-DjQDBYRu.js";
import { t as A } from "./dialog-BtjFqa-w.js";
import { t as ee } from "./use-membership-CcV5kGny.js";
import { t as te } from "./banner-CFcSGYsz.js";
import { n as ne } from "./utils-C9bSuXia.js";
import { r as re } from "./headings-CM9JBOhQ.js";
import { t as j } from "./input-C42Z_4fO.js";
import { t as M } from "./tooltip-6hqVQbwq.js";
import { t as N } from "./Pill-99RRpZf2.js";
import "./pill-AA_qJIlm.js";
import { t as P } from "./text-fFCFeCas.js";
import { t as F } from "./select-Ceshp72e.js";
import { t as ie } from "./use-resource-permission-Dd1Jv7de.js";
import { p as ae } from "./runner-configuration-queries-CSQ6BmaB.js";
import { T as I, a as L, i as R, m as z, w as oe } from "./runner-queries-BAY_7mHt.js";
import { t as B } from "./external-link-BKbp1Q22.js";
import { t as V } from "./label-5ATlPnPj.js";
import { t as H } from "./empty-state-D7Bh3L9e.js";
import { a as se, c as U, l as W, n as ce, p as le, t as ue } from "./RunnerActionsDropdown-2h_vxF-o.js";
import { t as de } from "./use-role-assignments-by-resource-eixFv-mR.js";
var G = e(c(), 1),
  K = d(),
  fe = ({ className: e }) =>
    (0, K.jsx)(`svg`, {
      className: e,
      width: `32`,
      height: `35`,
      viewBox: `0 0 32 35`,
      fill: `none`,
      xmlns: `http://www.w3.org/2000/svg`,
      children: (0, K.jsx)(`path`, {
        d: `M15.1403 24.5388C16.9484 24.2166 18.7563 23.8934 20.564 23.5689L20.615 23.558L17.8251 20.2051C16.2908 18.361 15.0354 16.8451 15.0354 16.8365C15.0354 16.8199 17.9161 8.80464 17.9323 8.77607C17.9377 8.76662 19.8981 12.1863 22.6844 17.0659C25.293 21.6341 27.4437 25.4006 27.4637 25.4359L27.5 25.5L18.6339 25.4988L9.7677 25.4976L15.1403 24.5388ZM4.5 23.5163C4.5 23.5116 5.81453 21.206 7.4212 18.3927L10.3424 13.2776L13.7467 10.3911C15.619 8.80346 17.156 7.50243 17.1622 7.50006C17.1683 7.4977 17.1437 7.56028 17.1074 7.63915C17.0712 7.71814 15.4077 11.3231 13.4108 15.6503L9.78009 23.518L7.14004 23.5215C5.68809 23.5234 4.5 23.521 4.5 23.5163Z`,
        fill: `currentColor`,
      }),
    });
function pe(e, t) {
  let n = 1,
    r = t.filter((t) => t.name?.startsWith(e)).map((e) => e.name);
  for (; r?.includes(`${e} ${n}`); ) n++;
  return `${e} ${n}`;
}
function q({ baseName: e, provider: t }) {
  let [n, r] = (0, G.useState)(null),
    { data: i, isLoading: a, isPending: o } = z({ provider: t }),
    s = (0, G.useMemo)(() => (a || o ? `` : pe(e, i || [])), [i, a, o, e]);
  return {
    name: n ?? s,
    isLoading: a || o,
    setName: (e) => {
      r(e);
    },
  };
}
var J = [
    { label: `EU (Frankfurt)`, value: `eu-central-1` },
    { label: `EU (Ireland)`, value: `eu-west-1` },
    { label: `EU (London)`, value: `eu-west-2` },
    { label: `EU (Paris)`, value: `eu-west-3` },
    { label: `EU (Spain)`, value: `eu-south-2` },
    { label: `US East (N. Virginia)`, value: `us-east-1` },
    { label: `US East (Ohio)`, value: `us-east-2` },
    { label: `US West (N. California)`, value: `us-west-1` },
    { label: `US West (Oregon)`, value: `us-west-2` },
    { label: `Canada (Central)`, value: `ca-central-1` },
    { label: `São Paulo (South America)`, value: `sa-east-1` },
    { label: `Asia Pacific (Mumbai)`, value: `ap-south-1` },
    { label: `Asia Pacific (Singapore)`, value: `ap-southeast-1` },
    { label: `Asia Pacific (Sydney)`, value: `ap-southeast-2` },
    { label: `Asia Pacific (Tokyo)`, value: `ap-northeast-1` },
    { label: `Middle East (Tel Aviv)`, value: `il-central-1` },
  ],
  me = ({ formId: e, onDisabledChange: t, className: n, onSubmit: r }) => {
    let { data: i, isLoading: a, isPending: o } = x(),
      s = (0, G.useId)(),
      c = (0, G.useId)(),
      [l, u] = (0, G.useState)(J[0]?.value),
      d = J.find((e) => e.value === l)?.label,
      { name: f, setName: p, isLoading: m } = q({ baseName: d ? `AWS ${d}` : `AWS Runner`, provider: g.AWS_EC2 });
    (0, G.useEffect)(() => {
      t(!f);
    }, [f, t]);
    let h = (0, G.useCallback)(
        (e) => {
          u(e);
        },
        [u],
      ),
      _ = (0, G.useCallback)(
        async (e) => {
          (e.preventDefault(), !(!i || !f) && (await r({ name: f, region: l })));
        },
        [i, f, l, r],
      );
    return a || o
      ? (0, K.jsx)(K.Fragment, {})
      : (0, K.jsx)(`form`, {
          name: e,
          id: e,
          onSubmit: _,
          children: (0, K.jsxs)(`div`, {
            className: O(`flex flex-col gap-2`, n),
            children: [
              (0, K.jsxs)(`div`, {
                className: `flex flex-row gap-4 space-y-1`,
                children: [
                  (0, K.jsx)(`div`, {
                    className: `flex-shrink-0 p-4`,
                    children: (0, K.jsx)(W, { className: `size-12` }),
                  }),
                  (0, K.jsxs)(`div`, {
                    className: `flex grow flex-col gap-2`,
                    children: [
                      (0, K.jsx)(`div`, {
                        className: `text-sm`,
                        children: `Run environments for your organization on an EC2 instance. We will help you setup your CloudFormation stack.`,
                      }),
                      (0, K.jsx)(`div`, {
                        children: (0, K.jsx)(D, {
                          variant: `primary`,
                          asChild: !0,
                          children: (0, K.jsx)(B, {
                            href: `https://ioi.com/docs/ioi/runners/aws/overview`,
                            iconSize: `sm`,
                            children: (0, K.jsx)(`span`, { children: `View Documentation` }),
                          }),
                        }),
                      }),
                    ],
                  }),
                ],
              }),
              (0, K.jsxs)(`div`, {
                className: `space-y-1`,
                children: [
                  (0, K.jsx)(V, { htmlFor: c, children: `AWS region` }),
                  (0, K.jsxs)(F, {
                    name: `aws_region`,
                    value: l || ``,
                    onValueChange: h,
                    id: c,
                    placeholder: `Select a region`,
                    children: [
                      (0, K.jsx)(F.Value, { children: l }),
                      J.map((e) =>
                        (0, K.jsx)(
                          F.Item,
                          {
                            value: e.value,
                            children: (0, K.jsxs)(`div`, {
                              className: `flex w-full flex-row items-center justify-between pr-10`,
                              children: [
                                (0, K.jsx)(`div`, { children: e.label }),
                                (0, K.jsx)(`div`, { children: e.value }),
                              ],
                            }),
                          },
                          e.value,
                        ),
                      ),
                    ],
                  }),
                ],
              }),
              (0, K.jsxs)(`div`, {
                className: `space-y-1`,
                children: [
                  (0, K.jsxs)(`div`, {
                    className: `flex items-center gap-2`,
                    children: [
                      (0, K.jsx)(V, { htmlFor: s, children: `Name` }),
                      m && (0, K.jsx)(E, { size: `sm`, className: `animate-spin` }),
                    ],
                  }),
                  (0, K.jsx)(j, {
                    id: s,
                    type: `text`,
                    name: `runner_name`,
                    value: f,
                    onChange: (e) => p(e.target.value),
                    disabled: m,
                    className: `max-w-full`,
                  }),
                ],
              }),
              (0, K.jsx)(`div`, {
                className: `mt-4 text-xs`,
                children: `Please note: AWS infrastructure usage for runners will appear on your regular AWS billing statement.`,
              }),
            ],
          }),
        });
  },
  he = ({ formId: e, onDisabledChange: t, className: n, onSubmit: r }) => {
    let { name: i, setName: a, isLoading: o } = q({ baseName: `GCP`, provider: g.GCP });
    (0, G.useEffect)(() => {
      t(!i);
    }, [i, t]);
    let s = (0, G.useCallback)(
      async (e) => {
        (e.preventDefault(), i && (await r({ name: i })));
      },
      [i, r],
    );
    return o
      ? (0, K.jsx)(K.Fragment, {})
      : (0, K.jsx)(`form`, {
          name: e,
          id: e,
          onSubmit: s,
          children: (0, K.jsxs)(`div`, {
            className: O(`flex flex-col gap-4`, n),
            children: [
              (0, K.jsxs)(`div`, {
                className: `flex items-start gap-4 rounded-lg bg-surface-secondary p-4`,
                children: [
                  (0, K.jsx)(`div`, { className: `flex-shrink-0`, children: (0, K.jsx)(U, { className: `size-12` }) }),
                  (0, K.jsxs)(`div`, {
                    className: `flex grow flex-col gap-3`,
                    children: [
                      (0, K.jsxs)(`div`, {
                        children: [
                          (0, K.jsx)(P, { className: `text-base font-semibold`, children: `GCP Runner` }),
                          (0, K.jsx)(P, {
                            className: `text-sm text-content-secondary`,
                            children: `Deploy a runner on Google Cloud Platform using Terraform for scalable environment execution.`,
                          }),
                        ],
                      }),
                      (0, K.jsxs)(`div`, {
                        className: `space-y-2`,
                        children: [
                          (0, K.jsx)(P, { className: `text-sm`, children: `Best suited for:` }),
                          (0, K.jsxs)(`ul`, {
                            className: `list-disc space-y-1 pl-4 text-sm text-content-secondary`,
                            children: [
                              (0, K.jsx)(`li`, { children: `Teams using Google Cloud Platform` }),
                              (0, K.jsx)(`li`, { children: `Infrastructure as Code with Terraform` }),
                              (0, K.jsx)(`li`, { children: `Scalable production workloads` }),
                              (0, K.jsx)(`li`, { children: `Integration with GCP services` }),
                            ],
                          }),
                        ],
                      }),
                      (0, K.jsx)(`div`, {
                        children: (0, K.jsx)(D, {
                          variant: `secondary`,
                          size: `sm`,
                          asChild: !0,
                          children: (0, K.jsx)(B, {
                            href: `https://registry.terraform.io/modules/ioi-io/ioi-runner/google/latest`,
                            iconSize: `sm`,
                            children: (0, K.jsx)(`span`, { children: `View Terraform Module` }),
                          }),
                        }),
                      }),
                    ],
                  }),
                ],
              }),
              (0, K.jsxs)(`div`, {
                className: `space-y-1`,
                children: [
                  (0, K.jsx)(V, { htmlFor: `name`, children: `Name` }),
                  (0, K.jsx)(j, {
                    id: `name`,
                    type: `text`,
                    name: `runner_name`,
                    value: i,
                    onChange: (e) => a(e.target.value),
                    className: `max-w-full`,
                    placeholder: `e.g., gcp-production-runner`,
                  }),
                ],
              }),
            ],
          }),
        });
  },
  Y = ({ name: e, Logo: t, label: n, onClick: r, href: i, variant: a = `secondary`, "data-tracking-id": o }) => {
    let s = !r && !i,
      c = S(),
      [l, u] = (0, G.useState)(!1),
      d = (0, G.useCallback)(() => {
        (c(`waitlist_joined`, { feature: `Runner - ${e}`, provider: e, type: `infrastructure` }), u(!0));
      }, [c, u, e]),
      f = l ? `Joined waitlist` : `Join waitlist`;
    return (0, K.jsxs)(`div`, {
      className: `flex items-center justify-between rounded-xl border border-border-light p-2`,
      children: [
        (0, K.jsxs)(`div`, {
          className: `flex items-center`,
          children: [
            (0, K.jsx)(t, { className: O(`mr-3 size-8`, s && `grayscale`) }),
            (0, K.jsx)(`div`, { className: `text-base font-medium text-content-secondary`, children: e }),
          ],
        }),
        i
          ? (0, K.jsx)(D, {
              variant: a,
              onClick: r,
              "aria-label": `${n} Provider: ${e}`,
              "data-tracking-id": o,
              asChild: !0,
              children: (0, K.jsx)(B, {
                href: i,
                className: `text-base font-medium text-content-primary`,
                children: n,
              }),
            })
          : r
            ? (0, K.jsx)(D, {
                variant: a,
                onClick: r,
                "aria-label": `${n} Provider: ${e}`,
                "data-tracking-id": o,
                children: n,
              })
            : (0, K.jsx)(D, {
                variant: `link`,
                size: `md`,
                className: `disabled:bg-transparent disabled:text-content-success`,
                "aria-label": `${n}: ${e}`,
                disabled: l,
                onClick: d,
                "data-tracking-id": o,
                children: f,
              }),
      ],
    });
  },
  ge = ({ open: e, onClose: t }) => {
    let n = f(),
      { toast: r } = T(),
      i = S(),
      { data: a } = x(),
      o = L(),
      [s, c] = (0, G.useState)(!1),
      [l, u] = (0, G.useState)({ screen: `provider-selection` });
    (0, G.useEffect)(() => {
      e && u({ screen: `provider-selection` });
    }, [e]);
    let d = (0, G.useCallback)(
        (e) => {
          e || t();
        },
        [t],
      ),
      h = a?.tier === m.ENTERPRISE,
      _ = a?.tier === m.FREE_ONA || a?.tier === m.FREE || a?.tier === m.CORE,
      v = (0, G.useCallback)(
        (e) => {
          if (_) {
            (i(`trial_requested`, { provider: e, tier: a?.tier }),
              r({
                title: `Enterprise trial requested`,
                description: `Your request for an Enterprise trial has been submitted. We'll be in touch soon!`,
              }),
              t());
            return;
          }
          e === g.AWS_EC2 && h
            ? u({ screen: `configuration`, selectedProvider: e, selectedTemplate: `enterprise` })
            : u({ screen: `configuration`, selectedProvider: e });
        },
        [_, h, a?.tier, i, r, t],
      ),
      y = (0, G.useCallback)(() => {
        u({ screen: `provider-selection` });
      }, []),
      C = (0, G.useCallback)(
        async ({ name: e, region: t, provider: i }) => {
          let a;
          (i === g.AWS_EC2 || i === g.GCP) && (a = w.ENTERPRISE);
          try {
            let r = { name: e, provider: i, variant: a };
            t && (r.region = t);
            let { runner: s } = await o.mutateAsync(r);
            n(`/settings/runners/${s.runnerId}?showOnboarding=true`);
          } catch (e) {
            r({ title: `Failed to create a runner`, description: b(e) });
          }
        },
        [o, n, r],
      );
    return (0, K.jsx)(A, {
      open: e,
      onOpenChange: d,
      children: (0, K.jsxs)(A.Content, {
        className: `max-w-[600px]`,
        "data-track-location": p.NewRunnerModal,
        children: [
          (0, K.jsxs)(A.Header, {
            children: [
              (0, K.jsx)(A.Title, {
                children: ((e) => {
                  if (e.screen === `provider-selection`) return `Add a runner`;
                  switch (e.selectedProvider) {
                    case g.AWS_EC2:
                      return `Create AWS Enterprise runner`;
                    case g.GCP:
                      return `Create GCP runner`;
                    default:
                      return ``;
                  }
                })(l),
              }),
              (0, K.jsx)(A.Description, {
                children: ((e) => {
                  switch (e.screen) {
                    case `provider-selection`:
                      return `Choose which provider to use for running your environments`;
                    default:
                      return ``;
                  }
                })(l),
              }),
            ],
          }),
          (0, K.jsxs)(A.Body, {
            children: [
              l.screen === `provider-selection` &&
                (0, K.jsxs)(`div`, {
                  className: `flex flex-col gap-2`,
                  children: [
                    (0, K.jsx)(Y, {
                      name: `AWS`,
                      Logo: W,
                      label: _ ? `Request Enterprise Trial` : `Select`,
                      onClick: () => v(g.AWS_EC2),
                      "data-tracking-id": `select-aws-provider-option`,
                    }),
                    (0, K.jsx)(Y, {
                      name: `GCP`,
                      Logo: U,
                      label: _ ? `Request Enterprise Trial` : `Select`,
                      onClick: () => v(g.GCP),
                      "data-tracking-id": `select-gcp-provider-option`,
                    }),
                    (0, K.jsx)(Y, {
                      name: `Azure`,
                      Logo: fe,
                      label: `Join waitlist`,
                      "data-tracking-id": `join-azure-waitlist-provider-option`,
                    }),
                  ],
                }),
              l.screen === `configuration` &&
                l.selectedProvider === g.AWS_EC2 &&
                (0, K.jsx)(me, {
                  formId: `new-runner-form`,
                  onSubmit: (e) => C({ ...e, provider: g.AWS_EC2 }),
                  onDisabledChange: c,
                }),
              l.screen === `configuration` &&
                l.selectedProvider === g.GCP &&
                (0, K.jsx)(he, {
                  formId: `new-runner-form`,
                  onSubmit: (e) => C({ ...e, provider: g.GCP }),
                  onDisabledChange: c,
                }),
            ],
          }),
          l.screen === `configuration` &&
            (0, K.jsx)(A.Footer, {
              children: (0, K.jsxs)(`div`, {
                className: `flex w-full flex-col gap-2 sm:flex-row sm:justify-between`,
                children: [
                  (0, K.jsx)(`div`, {
                    children: (0, K.jsx)(D, {
                      variant: `outline`,
                      type: `button`,
                      onClick: y,
                      "data-tracking-id": `back-new-runner-modal`,
                      children: `Back`,
                    }),
                  }),
                  (0, K.jsx)(`div`, {
                    className: `flex flex-col gap-2 sm:flex-row sm:justify-end`,
                    children: (0, K.jsx)(D, {
                      loading: o.isPending,
                      autoFocus: !0,
                      "aria-label": `create`,
                      type: `submit`,
                      "data-testid": `create`,
                      form: `new-runner-form`,
                      disabled: s,
                      "data-tracking-id": `confirm-create-runner-new-runner-modal`,
                      children: `Create`,
                    }),
                  }),
                ],
              }),
            }),
        ],
      }),
    });
  },
  _e = ({ runner: e }) =>
    (0, K.jsxs)(P, {
      className: `text-sm text-content-primary`,
      children: [`Created `, (0, K.jsx)(o, { timestamp: e.createdAt })],
    }),
  ve = ({ runner: e }) => {
    let { data: t } = v(),
      { member: n } = r(t?.id),
      { member: i } = r(e.creator?.id),
      a = (0, G.useMemo)(() => (n?.userId === i?.userId ? `You` : i?.fullName || `Unknown`), [i, n]);
    if (!(!n || !i))
      return (0, K.jsx)(`div`, {
        "data-testid": `creator`,
        className: `text-sm text-content-primary`,
        children: (0, K.jsxs)(`span`, { children: [`by `, (0, K.jsx)(`span`, { children: a })] }),
      });
  },
  X = ({ runner: e, className: t }) => {
    let n = O(`h-8 w-8 text-content-primary`, t);
    if (!e) return (0, K.jsx)(l, { className: n });
    switch (e.provider) {
      case g.AWS_EC2:
        return (0, K.jsx)(W, { className: n });
      case g.GCP:
        return (0, K.jsx)(U, { className: n });
      case g.MANAGED:
        return (0, K.jsx)(l, { className: n });
      default:
        return (0, K.jsx)(l, { className: n });
    }
  },
  Z = ({ name: e, className: t }) =>
    (0, K.jsx)(M, {
      content: e,
      children: (0, K.jsx)(P, {
        className: O(`min-w-0 flex-shrink truncate text-base font-bold text-content-primary`, t),
        children: e,
      }),
    }),
  ye = ({ provider: e }) =>
    (0, K.jsx)(`div`, {
      className: `flex grow text-sm text-content-primary`,
      children: (0, G.useMemo)(() => t(e), [e]),
    }),
  be = ({ runner: e, integrations: t, isPhasedOut: n = !1 }) => {
    let r = f(),
      i = e.kind === y.REMOTE,
      a = t && t.length === 0,
      o = e.status?.phase === C.ACTIVE || e.status?.phase === C.DEGRADED,
      s = (0, G.useCallback)(() => {
        i && r(`/settings/runners/${e.runnerId}`);
      }, [i, r, e.runnerId]),
      c = (0, G.useCallback)(
        (e) => {
          i && (e.key === `Enter` || e.key === ` `) && (e.preventDefault(), s());
        },
        [i, s],
      );
    return (0, K.jsxs)(`div`, {
      "data-testid": `runner-` + e.runnerId,
      role: i ? `button` : void 0,
      tabIndex: i ? 0 : void 0,
      onClick: s,
      onKeyDown: c,
      className: O(
        `flex flex-col gap-2 rounded-xl border-0.5 border-solid border-border-base bg-surface-glass px-5 py-4 text-left text-xs`,
        i
          ? `cursor-pointer hover:outline hover:outline-1 hover:outline-border-brand focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-border-brand`
          : `cursor-default`,
      ),
      "aria-label": i ? `View details for ${e.name}` : void 0,
      "data-tracking-id": `view-runner-details-runner-card`,
      children: [
        (0, K.jsx)(`div`, {
          className: `flex grow`,
          children: (0, K.jsxs)(`div`, {
            className: `flex grow flex-col gap-0.5`,
            children: [
              (0, K.jsxs)(`div`, {
                className: `flex flex-row`,
                children: [
                  (0, K.jsx)(`div`, { className: `grow`, children: (0, K.jsx)(X, { runner: e }) }),
                  (0, K.jsx)(`div`, { children: (0, K.jsx)(ue, { runner: e, showViewDetails: !0 }) }),
                ],
              }),
              (0, K.jsxs)(`div`, {
                className: `flex items-center gap-2`,
                children: [
                  (0, K.jsx)(Z, { name: e.name, className: `max-w-48` }),
                  n &&
                    (0, K.jsx)(M, {
                      content: `This runner can still start existing environments, but cannot create new ones`,
                      children: (0, K.jsx)(N, { variant: `warning`, size: `sm`, children: `Phasing Out` }),
                    }),
                ],
              }),
            ],
          }),
        }),
        (0, K.jsxs)(`div`, {
          className: `flex flex-row gap-2`,
          children: [(0, K.jsx)(se, { runner: e }), a && o && (0, K.jsx)(Ce, {})],
        }),
        (0, K.jsxs)(`div`, {
          className: `flex flex-col gap-1`,
          children: [
            (0, K.jsxs)(`div`, {
              className: `flex flex-col`,
              children: [(0, K.jsx)(_e, { runner: e }), (0, K.jsx)(ve, { runner: e })],
            }),
            (0, K.jsx)(we, { runnerId: e.runnerId }),
          ],
        }),
      ],
    });
  },
  xe = ({ setShowNewRunnerModal: e }) =>
    (0, K.jsx)(`div`, {
      "data-testid": `add-new-runner-card`,
      className: `min-h-40 rounded-lg text-content-secondary`,
      children: (0, K.jsxs)(D, {
        variant: `ghost`,
        className: `flex size-full flex-col gap-0 border-0.5 border-border-light bg-surface-primary text-content-secondary hover:bg-surface-hover`,
        onClick: () => e(!0),
        "data-tracking-id": `open-runner-card-actions`,
        children: [(0, K.jsx)(s, { size: `base` }), `Set up a new runner`],
      }),
    }),
  Se = ({ placeholder: e }) => {
    let t = R(),
      { toast: n } = T(),
      r = (0, G.useCallback)(async () => {
        try {
          (await t.mutateAsync({ runnerManagerId: e.runnerManagerId, name: e.name, region: e.region }),
            n({ title: `Runner enabled`, description: `${e.name} is being set up` }));
        } catch (e) {
          n({ title: `Failed to enable runner`, description: e instanceof Error ? e.message : `Please try again` });
        }
      }, [e, t, n]);
    return (0, K.jsxs)(`div`, {
      "data-testid": `placeholder-` + e.runnerManagerId,
      className: O(
        `flex flex-col gap-2 rounded-xl border-0.5 border-solid border-border-base bg-surface-glass px-5 py-4 text-left text-xs`,
        `cursor-default`,
      ),
      "aria-label": `Available Runner Manager`,
      children: [
        (0, K.jsx)(`div`, {
          className: `flex grow`,
          children: (0, K.jsxs)(`div`, {
            className: `flex grow flex-col gap-0.5`,
            children: [
              (0, K.jsxs)(`div`, {
                className: `flex flex-row`,
                children: [
                  (0, K.jsx)(`div`, {
                    className: `grow opacity-60`,
                    children: (0, K.jsx)(X, { runner: { provider: g.MANAGED } }),
                  }),
                  (0, K.jsx)(`div`, {
                    children: (0, K.jsx)(D, {
                      variant: `secondary`,
                      size: `sm`,
                      onClick: r,
                      disabled: t.isPending,
                      loading: t.isPending,
                      "data-tracking-id": `enable-runner-runner-card`,
                      children: `Enable`,
                    }),
                  }),
                ],
              }),
              (0, K.jsx)(`div`, {
                className: `opacity-60`,
                children: (0, K.jsx)(Z, { name: e.name, className: `max-w-48` }),
              }),
              (0, K.jsx)(`div`, { className: `opacity-60`, children: (0, K.jsx)(ye, { provider: g.MANAGED }) }),
            ],
          }),
        }),
        (0, K.jsx)(`div`, {
          className: `flex flex-row gap-2`,
          children: (0, K.jsx)(N, { variant: `default`, children: `Disabled` }),
        }),
        (0, K.jsxs)(`div`, {
          className: `flex flex-col`,
          children: [
            (0, K.jsxs)(`div`, { className: `text-xs text-content-tertiary`, children: [`Region: `, e.region] }),
            (0, K.jsx)(`div`, { className: `text-xs text-content-tertiary`, children: `by IOI` }),
          ],
        }),
      ],
    });
  },
  Ce = () =>
    (0, K.jsx)(N, {
      tooltip: (0, K.jsxs)(`div`, {
        children: [
          (0, K.jsx)(`div`, { children: `Source control is not configured for this runner.` }),
          (0, K.jsx)(`div`, {
            children: `Please, configure a repository provider (GitHub, GitLab, Bitbucket or Azure DevOps) to access your repo.`,
          }),
        ],
      }),
      variant: `warning`,
      children: `No repo access`,
    }),
  we = ({ runnerId: e }) => {
    let { data: t, isLoading: n } = de(h.RUNNER, e),
      r = (0, G.useMemo)(
        () => (t ? [...new Set(t.filter((e) => !e.derivedFromOrgRole).map((e) => e.groupId))] : []),
        [t],
      ),
      { groups: i, isLoading: a } = k(r);
    return n || a || r.map((e) => i.get(e)).filter((e) => !!e).length === 0
      ? null
      : (0, K.jsxs)(`div`, {
          className: `flex items-center gap-2`,
          children: [
            (0, K.jsx)(`span`, { className: `text-xs text-content-tertiary`, children: `Shared with:` }),
            (0, K.jsx)(ce, { runnerId: e, maxVisible: 3 }),
          ],
        });
  },
  Q = (0, G.memo)(({ placeholders: e }) =>
    (0, K.jsx)(K.Fragment, { children: e.map((e) => (0, K.jsx)(Se, { placeholder: e }, e.runnerManagerId)) }),
  );
Q.displayName = `PlaceholderCards`;
var $ = (0, G.memo)(({ runner: e, integrations: t, isPhasedOut: n }) =>
  (0, K.jsx)(be, { runner: e, integrations: t, isPhasedOut: n }),
);
$.displayName = `RunnerCardItem`;
var Te = (e) =>
    e.length === 1
      ? e[0]
      : e.length === 2
        ? `${e[0]} and ${e[1]}`
        : `${e.slice(0, -1).join(`, `)}, and ${e[e.length - 1]}`,
  Ee = ({ filter: e, excludeProvider: n, emptyStateMessage: r, placeholders: o = [], title: s }) => {
    let { isPending: c } = v(),
      { data: l, isPending: d } = z(e),
      { availableRunnerManagers: f, isPending: p } = oe(),
      m = (0, G.useMemo)(() => new Set(f.map((e) => e.runnerManagerId)), [f]),
      [b, x] = (0, G.useState)(!1),
      [S, C] = (0, G.useState)(``),
      w = (0, G.useMemo)(
        () => (l || []).filter((e) => !(e.provider === g.LINUX_HOST || (n && e.provider === n))),
        [l, n],
      ),
      { members: T } = _((0, G.useMemo)(() => w.map((e) => e.creator?.id).filter(Boolean), [w])),
      E = (0, G.useMemo)(() => {
        if (!S.trim()) return w;
        let e = S.toLowerCase();
        return w.filter((n) => {
          let r = n.creator?.id ? T.get(n.creator.id)?.fullName : void 0,
            a =
              n.spec?.configuration?.region ||
              n.status?.region ||
              n.status?.additionalInfo?.find((e) => e.key === `region`)?.value;
          return [n.name, i(n).label, t(n.provider), r, a].some((t) => t?.toLowerCase().includes(e));
        });
      }, [w, S, T]),
      { membership: k } = ee(),
      { hasPermission: A, isLoading: j } = ie(h.ORGANIZATION, k?.organizationId || ``, `runner:create_remote`),
      { data: M, isPending: N } = ae(w.map((e) => e.runnerId)),
      P = (0, G.useMemo)(() => {
        let e = new Map();
        for (let t of M || []) {
          let n = t.runnerId,
            r = e.get(n) || [];
          (r.push(t), e.set(n, r));
        }
        return e;
      }, [M]),
      F = (0, G.useMemo)(() => le(w), [w]),
      I = c || d || N || p || j,
      L = e.kind === y.REMOTE && A;
    if (I) return null;
    if (w.length === 0 && o.length === 0 && !L)
      return (0, K.jsx)(H, {
        title: r ? `No Runners` : `No Runners Available`,
        description:
          r ||
          `There are currently no runners set up for this organization. Please contact your organization admin to set up runners.`,
        "data-testid": `no-runners-available`,
      });
    let R = w.length > 1;
    return (0, K.jsxs)(K.Fragment, {
      children: [
        (0, K.jsxs)(`div`, {
          className: `flex justify-between`,
          children: [
            (0, K.jsx)(re, { children: s }),
            (0, K.jsx)(D, {
              size: `sm`,
              LeadingIcon: ne(u),
              onClick: () => x(!0),
              className: O(`hidden`, { "inline-flex": L && w.length > 0 }),
              "data-tracking-id": `new-runner-runners-list`,
              children: `New runner`,
            }),
          ],
        }),
        F.map(({ domain: e, runners: t }) =>
          (0, K.jsx)(
            te,
            {
              variant: `warning`,
              "data-testid": `duplicate-proxy-domain-warning-${e}`,
              text: (0, K.jsxs)(`span`, {
                children: [
                  `Runners `,
                  Te(t.map((e) => e.name)),
                  ` share the same proxy domain`,
                  ` `,
                  (0, K.jsx)(`strong`, { children: e }),
                  `. Each Runner must have an exclusive proxy domain.`,
                ],
              }),
            },
            e,
          ),
        ),
        R &&
          (0, K.jsx)(`div`, {
            className: `flex items-center justify-between gap-4`,
            children: (0, K.jsx)(a, {
              wrapperClassName: `w-full`,
              className: `max-w-none`,
              placeholder: `Search runners`,
              value: S,
              onChange: (e) => C(e.target.value),
              onClear: () => C(``),
              "data-testid": `runner-search-input`,
            }),
          }),
        (0, K.jsx)(`div`, {
          "data-testid": `runners-list`,
          children:
            E.length === 0 && S.trim()
              ? (0, K.jsx)(H, {
                  title: `No matching runners`,
                  description: `No runners match your search. Try a different search term.`,
                  "data-testid": `no-matching-runners-empty-state`,
                })
              : (0, K.jsxs)(`div`, {
                  className: `grid grid-cols-1 gap-4 lg:grid-cols-2 xl:grid-cols-3`,
                  children: [
                    E.map((e) => {
                      let t = e.provider === g.MANAGED && !!e.runnerManagerId && !m.has(e.runnerManagerId);
                      return (0, K.jsx)(
                        $,
                        { runner: e, integrations: P.get(e.runnerId) || [], isPhasedOut: t },
                        e.runnerId,
                      );
                    }),
                    (0, K.jsx)(Q, { placeholders: o }),
                    L && w.length === 0 && (0, K.jsx)(xe, { setShowNewRunnerModal: x }),
                  ],
                }),
        }),
        (0, K.jsx)(ge, { open: b, onClose: () => x(!1) }),
      ],
    });
  },
  De = () => {
    let { data: e, isLoading: t } = x();
    return { value: e?.tier === m.FREE_ONA || e?.tier === m.CORE, loading: t };
  },
  Oe = { provider: g.MANAGED },
  ke = { kind: y.REMOTE },
  Ae = () => {
    n(`Runners`);
    let { value: e } = De(),
      { runnerPlaceholders: t } = I();
    return (0, K.jsxs)(`div`, {
      className: `flex flex-col gap-6`,
      children: [
        (0, K.jsx)(P, {
          className: `text-base text-content-secondary`,
          children: `Manage where environments run for your organization.`,
        }),
        (0, K.jsx)(Ee, { title: `Self-hosted runners`, filter: ke, excludeProvider: g.MANAGED }),
        e &&
          (0, K.jsx)(Ee, {
            title: `Hosted by IOI Cloud`,
            filter: Oe,
            emptyStateMessage: `No hosted runners yet. Enable IOI Cloud from the onboarding flow to get started.`,
            placeholders: t,
          }),
      ],
    });
  };
export { Ae as RunnersPage };
