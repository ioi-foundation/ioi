import { a as e } from "./rolldown-runtime-CGYlQKCx.js";
import { Kt as t } from "./SegmentProvider-CXCNBY9U.js";
import { n } from "./@mux-DLaEVubF.js";
import {
  Df as r,
  Ef as i,
  Kf as a,
  Yf as o,
  e_ as s,
  gp as c,
  hd as l,
  hp as u,
  it as d,
  kp as f,
  md as p,
  op as m,
  rt as h,
  up as g,
  v_ as _,
} from "./vendor-DAwbZtf0.js";
import { tr as v } from "./use-boot-in-app-chat-t-J_VjKS.js";
import { r as y } from "./workflow_pb-DOR6D5WK.js";
import { t as b } from "./toast-axaLeIzZ.js";
import { t as x } from "./button-6YP03Qf2.js";
import { t as S } from "./cn-DppMFCU8.js";
import { t as C } from "./banner-CFcSGYsz.js";
import { t as w } from "./use-temporary-value-Bpxt61FD.js";
import { t as T } from "./tooltip-6hqVQbwq.js";
import { t as E } from "./text-fFCFeCas.js";
import { t as D } from "./scroll-area-DiWW0x8z.js";
import { t as O } from "./ImageLightbox-B7vf0zHI.js";
import { f as k, m as A, p as j } from "./automation-edit-form-data-CvP3_1II.js";
import { n as M, t as N } from "./StepListContainer-yN6PVsKT.js";
var P = e(n(), 1),
  F = _(),
  I = ({
    src: e,
    alt: t,
    onClick: n,
    className: r,
    showLabel: i,
    "data-tracking-id": a = `image-thumbnail-view`,
    fit: o = `contain`,
  }) => {
    let [s, c] = (0, P.useState)(!1);
    return s
      ? null
      : (0, F.jsxs)(`button`, {
          type: `button`,
          onClick: n,
          className: S(
            `flex flex-col overflow-hidden rounded-lg border border-border-subtle transition-opacity hover:opacity-80 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-content-link`,
            r,
          ),
          "aria-label": `View image: ${t || `uploaded image`}`,
          "data-tracking-id": a,
          children: [
            (0, F.jsx)(`img`, {
              src: e,
              alt: t,
              className: S(`min-h-0 flex-1`, o === `cover` ? `size-full object-cover` : `object-contain object-left`),
              onError: () => c(!0),
            }),
            i &&
              t &&
              (0, F.jsx)(`span`, {
                className: `w-full truncate border-t border-border-subtle bg-surface-secondary px-2 py-1 text-left text-xs text-content-secondary`,
                children: t,
              }),
          ],
        });
  },
  L = /^[a-zA-Z][a-zA-Z0-9+.-]*:/,
  R = /^(.*?)(?::([1-9]\d*))?$/,
  z = /^\/workspaces?\/[^/]+\/(.+)$/;
function B(e) {
  let t = e.trim();
  if (!t || t.startsWith(`#`) || L.test(t)) return null;
  let n = z.exec(t);
  if (n) t = n[1];
  else if (t.startsWith(`/`)) return null;
  let r = t.split(`#`, 1)[0].split(`?`, 1)[0];
  if (!r || r.endsWith(`/`) || r === `.` || r === `..`) return null;
  let i = R.exec(r);
  if (!i) return null;
  let a = i[1];
  return a ? { filePath: a, ...(i[2] ? { lineNumber: Number(i[2]) } : {}) } : null;
}
var V = ({ children: e, className: t, ...n }) => {
    let [r, i] = w(!1, 2e3),
      a = (0, P.useCallback)(async () => {
        let t = typeof e == `string` ? e : H(e);
        try {
          (await navigator.clipboard.writeText(t), i(!0));
        } catch (e) {
          (i(!1), b({ title: `Failed to copy to clipboard`, description: v(e) }));
        }
      }, [i, e]);
    return (0, F.jsxs)(`div`, {
      className: `relative`,
      children: [
        (0, F.jsx)(`pre`, {
          className: S(`peer`, t),
          ...n,
          children: (0, F.jsx)(D, { orientation: `horizontal`, children: e }),
        }),
        (0, F.jsx)(`div`, {
          className: `absolute right-2 top-2 opacity-0 transition-opacity focus-within:opacity-100 hover:opacity-100 peer-hover:opacity-100`,
          children: (0, F.jsx)(T, {
            content: `Copy to clipboard`,
            children: (0, F.jsx)(x, {
              variant: `ghost`,
              type: `button`,
              size: `xs`,
              LeadingIcon: () =>
                r ? (0, F.jsx)(f, { className: `text-content-success`, size: 16 }) : (0, F.jsx)(u, { size: 16 }),
              onClick: a,
              "aria-label": `Copy to clipboard`,
              title: `Copy to clipboard`,
              "data-tracking-id": `copy-to-clipboard-markdown`,
            }),
          }),
        }),
      ],
    });
  },
  H = (e) =>
    typeof e == `string`
      ? e
      : Array.isArray(e)
        ? e.map(H).join(``)
        : P.isValidElement(e) && e.props.children
          ? H(e.props.children)
          : ``,
  U = ({ size: e, ...t }) => (0, F.jsx)(c, { size: 16, ...t }),
  W = ({ size: e, ...t }) => (0, F.jsx)(g, { size: 16, ...t }),
  G = ({ content: e, className: n = `` }) => {
    let s = (0, P.useRef)(null),
      [c, l] = (0, P.useState)(!1),
      [u, f] = (0, P.useState)(!1),
      [p, h] = (0, P.useState)(null),
      [g, _] = (0, P.useState)(null),
      [v, y] = (0, P.useState)(1),
      [b, x] = (0, P.useState)(!1);
    (0, P.useEffect)(() => {
      d.initialize({
        startOnLoad: !1,
        suppressErrorRendering: !0,
        theme: `base`,
        themeVariables: {
          primaryColor: `#3b82f6`,
          primaryTextColor: `#1f2937`,
          primaryBorderColor: `#d1d5db`,
          lineColor: `#6b7280`,
          secondaryColor: `#f3f4f6`,
          tertiaryColor: `#ffffff`,
        },
        flowchart: { useMaxWidth: !0, htmlLabels: !0 },
        sequence: { useMaxWidth: !0 },
        gantt: { useMaxWidth: !0 },
      });
    }, []);
    let w = async () => {
        if (!(!e || g))
          try {
            (f(!0), h(null));
            let t = `mermaid-${Math.random().toString(36).substr(2, 9)}`,
              { svg: n } = await d.render(t, e);
            _(n);
          } catch (e) {
            (console.error(`Mermaid rendering error:`, e),
              h(e instanceof Error ? e.message : `Failed to render diagram`));
          } finally {
            f(!1);
          }
      },
      T = () => {
        (!c && !g && !p && w(), l(!c));
      };
    return (
      (0, P.useEffect)(() => {
        let e = () => {
          x(!!document.fullscreenElement);
        };
        return (
          document.addEventListener(`fullscreenchange`, e),
          () => document.removeEventListener(`fullscreenchange`, e)
        );
      }, []),
      (0, F.jsx)(`div`, {
        className: S(`my-4`, n),
        ref: s,
        children: (0, F.jsxs)(t, {
          value: c ? `preview` : `code`,
          onValueChange: (e) => {
            e === `preview` ? T() : l(!1);
          },
          className: `w-full`,
          children: [
            (0, F.jsxs)(t.List, {
              className: `w-fit`,
              children: [
                (0, F.jsx)(t.Trigger, { value: `code`, LeadingIcon: U, children: `Code` }),
                (0, F.jsxs)(t.Trigger, {
                  value: `preview`,
                  LeadingIcon: W,
                  children: [
                    `Preview`,
                    u &&
                      (0, F.jsx)(`span`, {
                        className: `ml-1 inline-block h-3 w-3 animate-spin rounded-full border-2 border-current border-t-transparent`,
                      }),
                  ],
                }),
              ],
            }),
            (0, F.jsx)(`div`, {
              className: `mt-3 rounded-md border border-border-subtle bg-surface-muted`,
              children: c
                ? (0, F.jsx)(`div`, {
                    className: `p-4`,
                    children: p
                      ? (0, F.jsx)(C, {
                          variant: `danger`,
                          text: `Diagram Error: ${p}`,
                          action: {
                            text: `Show Code`,
                            onClick: () => l(!1),
                            "data-tracking-id": `show-code-mermaid-error-banner`,
                          },
                        })
                      : g
                        ? (0, F.jsxs)(`div`, {
                            className: `space-y-3`,
                            children: [
                              (0, F.jsxs)(`div`, {
                                className: `flex items-center justify-between`,
                                children: [
                                  (0, F.jsxs)(`div`, {
                                    className: `flex items-center gap-1 rounded-md bg-surface-primary p-1`,
                                    children: [
                                      (0, F.jsx)(`button`, {
                                        onClick: () => {
                                          y(1);
                                        },
                                        className: `hover:bg-surface-subtle rounded px-2 py-1 text-xs`,
                                        title: `Reset view`,
                                        "data-tracking-id": `fittoscreen-mermaid-code-preview`,
                                        children: (0, F.jsx)(m, { size: 16 }),
                                      }),
                                      (0, F.jsx)(`div`, { className: `h-4 w-px bg-border-subtle` }),
                                      (0, F.jsx)(`button`, {
                                        onClick: () => {
                                          y((e) => Math.max(e - 0.25, 0.25));
                                        },
                                        className: `hover:bg-surface-subtle rounded px-2 py-1 text-xs`,
                                        title: `Zoom out`,
                                        "data-tracking-id": `zoomout-mermaid-code-preview`,
                                        children: (0, F.jsx)(i, { size: 16 }),
                                      }),
                                      (0, F.jsx)(`button`, {
                                        onClick: () => {
                                          y((e) => Math.min(e + 0.25, 4.5));
                                        },
                                        className: `hover:bg-surface-subtle rounded px-2 py-1 text-xs`,
                                        title: `Zoom in`,
                                        "data-tracking-id": `zoomin-mermaid-code-preview`,
                                        children: (0, F.jsx)(r, { size: 16 }),
                                      }),
                                      (0, F.jsx)(`div`, { className: `h-4 w-px bg-border-subtle` }),
                                      (0, F.jsx)(`button`, {
                                        onClick: () => {
                                          s.current &&
                                            (b
                                              ? document.exitFullscreen && document.exitFullscreen()
                                              : s.current.requestFullscreen && s.current.requestFullscreen(),
                                            x(!b));
                                        },
                                        className: `hover:bg-surface-subtle rounded px-2 py-1 text-xs`,
                                        title: b ? `Exit fullscreen` : `Fullscreen`,
                                        "data-tracking-id": `fullscreen-mermaid-code-preview`,
                                        children: b ? (0, F.jsx)(a, { size: 16 }) : (0, F.jsx)(o, { size: 16 }),
                                      }),
                                    ],
                                  }),
                                  (0, F.jsxs)(`div`, {
                                    className: `text-xs text-content-muted`,
                                    children: [Math.round(v * 100), `%`],
                                  }),
                                ],
                              }),
                              (0, F.jsxs)(`div`, {
                                className: `mermaid-scroll-container overflow-auto rounded-md border border-border-subtle bg-white`,
                                style: { scrollbarWidth: `thin`, scrollbarColor: `rgba(0, 0, 0, 0.3) transparent` },
                                children: [
                                  (0, F.jsx)(`style`, {
                                    dangerouslySetInnerHTML: {
                                      __html: `
                                                .mermaid-scroll-container::-webkit-scrollbar {
                                                    width: 6px;
                                                    height: 6px;
                                                }
                                                .mermaid-scroll-container::-webkit-scrollbar-track {
                                                    background: transparent;
                                                }
                                                .mermaid-scroll-container::-webkit-scrollbar-thumb {
                                                    background-color: rgba(0, 0, 0, 0.3);
                                                    border-radius: 6px;
                                                    border: 3px solid transparent;
                                                }
                                                .dark .mermaid-scroll-container::-webkit-scrollbar-thumb {
                                                    background-color: rgba(200, 200, 200, 0.3);
                                                }
                                                .mermaid-scroll-container::-webkit-scrollbar-corner {
                                                    background: transparent;
                                                }
                                                @media (prefers-color-scheme: dark) {
                                                    .mermaid-scroll-container {
                                                        scrollbar-color: rgba(200, 200, 200, 0.3) transparent;
                                                    }
                                                }
                                            `,
                                    },
                                  }),
                                  (0, F.jsx)(`div`, {
                                    className: `mermaid-container mermaid-scroll-container`,
                                    style: {
                                      transform: `scale(${v})`,
                                      transformOrigin: `top left`,
                                      minHeight: `200px`,
                                    },
                                    dangerouslySetInnerHTML: { __html: g },
                                  }),
                                ],
                              }),
                            ],
                          })
                        : u
                          ? (0, F.jsx)(`div`, {
                              className: `flex items-center justify-center py-8`,
                              children: (0, F.jsxs)(`div`, {
                                className: `flex items-center space-x-2 text-content-muted`,
                                children: [
                                  (0, F.jsx)(`div`, {
                                    className: `h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent`,
                                  }),
                                  (0, F.jsx)(`span`, { children: `Rendering diagram...` }),
                                ],
                              }),
                            })
                          : (0, F.jsx)(`div`, {
                              className: `flex items-center justify-center py-8 text-content-muted`,
                              children: (0, F.jsx)(`span`, { children: `Click Preview to render diagram` }),
                            }),
                  })
                : (0, F.jsx)(V, {
                    className: `px-4 py-3 font-mono text-sm`,
                    children: (0, F.jsx)(`code`, { className: `language-mermaid`, children: e }),
                  }),
            }),
          ],
        }),
      })
    );
  },
  K = ({ content: e, className: t }) => {
    let n = (0, P.useMemo)(() => {
      try {
        let t = h.load(e);
        if (!t || typeof t != `object`) return null;
        let n = s(y, t),
          r = n.action ? A(n.action) : [],
          i = n.triggers?.[0] ? k(n.triggers)[0] : void 0,
          a = j(n.action);
        return {
          name: n.name || `Untitled Workflow`,
          description: n.description || ``,
          steps: r,
          trigger: i,
          limits: a,
        };
      } catch {
        return null;
      }
    }, [e]);
    return n
      ? (0, F.jsxs)(`div`, {
          className: S(`rounded-lg border border-border-base bg-surface-secondary`, t),
          children: [
            (0, F.jsxs)(`div`, {
              className: `border-b border-border-base px-4 py-3`,
              children: [
                (0, F.jsx)(E, { className: `text-base font-semibold text-content-primary`, children: n.name }),
                n.description &&
                  (0, F.jsx)(E, { className: `mt-0.5 text-sm text-content-secondary`, children: n.description }),
              ],
            }),
            n.steps.length > 0
              ? (0, F.jsx)(N, {
                  children: (0, F.jsx)(`div`, {
                    className: `flex w-full max-w-screen-xl flex-row items-start justify-center gap-4`,
                    children: (0, F.jsx)(M, { trigger: n.trigger, limits: n.limits, steps: n.steps }),
                  }),
                })
              : (0, F.jsx)(`div`, {
                  className: `flex items-center justify-center p-6`,
                  children: (0, F.jsx)(E, { className: `text-sm text-content-muted`, children: `No steps defined` }),
                }),
          ],
        })
      : (0, F.jsx)(`div`, {
          className: S(`flex items-center justify-center rounded-lg border border-border-base p-6`, t),
          children: (0, F.jsx)(E, {
            className: `text-sm text-content-muted`,
            children: `Unable to parse workflow YAML`,
          }),
        });
  },
  q = ({ size: e, ...t }) => (0, F.jsx)(c, { size: 16, ...t }),
  J = ({ size: e, ...t }) => (0, F.jsx)(g, { size: 16, ...t }),
  Y = ({ content: e, className: n = `` }) => {
    let [r, i] = (0, P.useState)(!0);
    return (0, F.jsx)(`div`, {
      className: S(`my-4`, n),
      children: (0, F.jsxs)(t, {
        value: r ? `preview` : `code`,
        onValueChange: (e) => i(e === `preview`),
        className: `w-full`,
        children: [
          (0, F.jsxs)(t.List, {
            className: `w-fit`,
            children: [
              (0, F.jsx)(t.Trigger, { value: `code`, LeadingIcon: q, children: `Code` }),
              (0, F.jsx)(t.Trigger, { value: `preview`, LeadingIcon: J, children: `Preview` }),
            ],
          }),
          (0, F.jsx)(`div`, {
            className: `mt-3 rounded-md border border-border-subtle bg-surface-muted`,
            children: r
              ? (0, F.jsx)(K, { content: e })
              : (0, F.jsx)(V, {
                  className: `px-4 py-3 font-mono text-sm`,
                  children: (0, F.jsx)(`code`, { className: `language-yaml`, children: e }),
                }),
          }),
        ],
      }),
    });
  };
function X(e) {
  return !e || !/https?:/i.test(e)
    ? e
    : Z(e)
        .map((e) => (e.isCodeBlock ? e.content : Q(e.content)))
        .join(``);
}
function Z(e) {
  let t = [],
    n = 0,
    r = (n, r, i) => {
      n < r && t.push({ content: e.slice(n, r), isCodeBlock: i });
    };
  for (; n < e.length; ) {
    let t = e.indexOf("`", n);
    if (t === -1) {
      r(n, e.length, !1);
      break;
    }
    if ((r(n, t, !1), e.startsWith("```", t))) {
      let i = e.indexOf("```", t + 3);
      if (i !== -1) (r(t, i + 3, !0), (n = i + 3));
      else {
        r(t, e.length, !1);
        break;
      }
    } else {
      let i = e.indexOf("`", t + 1);
      i === -1 ||
      e.slice(t + 1, i).includes(`
`)
        ? (r(t, t + 1, !1), (n = t + 1))
        : (r(t, i + 1, !0), (n = i + 1));
    }
  }
  return t;
}
function Q(e) {
  let t = new RegExp([`(?<!\\]\\()`, `(https?:\\/\\/`, `[^\\s<>\\[\\]{}]+?)`, `(?=[.!?;,)]*(?:\\s|$))`].join(``), `gi`);
  return e.replace(t, (e) => `[${e}](${e})`);
}
var $ = [
  `[[data-completed]_.markdown-container>&:last-child]:after:transition-colors [[data-completed]_.markdown-container>&:last-child]:after:[transition-duration:300ms] [[data-completed]_.markdown-container>&:last-child]:after:content-[' '] [[data-completed]_.markdown-container>&:last-child]:after:inline-block [[data-completed]_.markdown-container>&:last-child]:after:h-[0.8lh] [[data-completed]_.markdown-container>&:last-child]:after:ml-[1px] [[data-completed]_.markdown-container>&:last-child]:after:w-[6px] [[data-completed]_.markdown-container>&:last-child]:after:rounded-sm [[data-completed]_.markdown-container>&:last-child]:after:align-text-top`,
  `[[data-completed=true]_.markdown-container>&:last-child]:after:bg-transparent`,
  `[[data-completed=false]_.markdown-container>&:last-child]:after:bg-content-secondary [[data-completed=false]_.markdown-container>&:last-child]:after:animate-blink [[data-completed=false]_.markdown-container>&:last-child]:after:delay-300`,
].join(` `);
function ee(e) {
  return [...e.replace(/```[\s\S]*?```/g, ``).matchAll(/!\[([^\]]*)\]\(([^)]+)\)/g)].map((e) => ({
    alt: e[1] || ``,
    src: e[2],
  }));
}
var te = ({ images: e }) => {
    let [t, n] = (0, P.useState)(-1),
      r = t >= 0,
      i = (0, P.useCallback)((e) => {
        e || n(-1);
      }, []);
    return e.length === 0
      ? null
      : (0, F.jsxs)(F.Fragment, {
          children: [
            (0, F.jsx)(`div`, {
              className: S(
                `my-2 grid gap-2`,
                e.length === 1 ? `grid-cols-1` : e.length === 2 ? `grid-cols-2` : `grid-cols-2 sm:grid-cols-3`,
              ),
              children: e.map((e, t) =>
                (0, F.jsx)(
                  I,
                  { src: e.src, alt: e.alt, onClick: () => n(t), className: `h-32 w-full`, showLabel: !0 },
                  `${e.src}-${t}`,
                ),
              ),
            }),
            (0, F.jsx)(O, { images: e, currentIndex: r ? t : 0, onIndexChange: n, open: r, onOpenChange: i }),
          ],
        });
  },
  ne = [p],
  re = {
    h1: ({ children: e, ...t }) =>
      (0, F.jsx)(`h1`, { className: S(`mb-3 mt-6 text-2xl font-semibold first:mt-0`, $), ...t, children: e }),
    h2: ({ children: e, ...t }) =>
      (0, F.jsx)(`h2`, { className: S(`mb-2 mt-5 text-xl font-semibold first:mt-0`, $), ...t, children: e }),
    h3: ({ children: e, ...t }) =>
      (0, F.jsx)(`h3`, { className: S(`mb-2 mt-4 text-lg font-medium first:mt-0`, $), ...t, children: e }),
    h4: ({ children: e, ...t }) =>
      (0, F.jsx)(`h4`, { className: S(`mb-1.5 mt-3 text-md font-medium first:mt-0`, $), ...t, children: e }),
    ul: ({ children: e, ...t }) => (0, F.jsx)(`ul`, { className: S(`mb-4 list-disc pl-8`, $), ...t, children: e }),
    ol: ({ children: e, ...t }) =>
      (0, F.jsx)(`ol`, { className: S(`mb-4 list-decimal pl-8 last:mb-0`, $), ...t, children: e }),
    li: ({ children: e, ...t }) => (0, F.jsx)(`li`, { className: S(`mb-1`, $), ...t, children: e }),
    a: ({ children: e, href: t, ...n }) => {
      let r = !!t && !!B(t);
      return (0, F.jsx)(`a`, {
        className: S(`text-content-link hover:underline [&_code]:text-content-link [&_code]:hover:underline`, $),
        href: t,
        target: r ? void 0 : `_blank`,
        rel: r ? void 0 : `noopener noreferrer`,
        "data-tracking-id": `markdown-link`,
        ...n,
        children: e,
      });
    },
    blockquote: ({ children: e, ...t }) =>
      (0, F.jsx)(`blockquote`, {
        className: S(`mb-4 border-l-4 border-border-base py-1 pl-4 text-content-muted`, $),
        ...t,
        children: e,
      }),
    table: ({ children: e, ...t }) =>
      (0, F.jsx)(`div`, {
        className: `mb-4 overflow-hidden overflow-x-auto rounded-lg border border-border-subtle [overflow-wrap:normal] [word-break:normal]`,
        children: (0, F.jsx)(`table`, { className: `min-w-full`, ...t, children: e }),
      }),
    thead: ({ children: e, ...t }) =>
      (0, F.jsx)(`thead`, { className: `border-b border-border-subtle bg-surface-muted`, ...t, children: e }),
    th: ({ children: e, ...t }) =>
      (0, F.jsx)(`th`, {
        className: S(`whitespace-nowrap px-4 py-2 text-left text-sm font-semibold`, $),
        ...t,
        children: e,
      }),
    td: ({ children: e, ...t }) =>
      (0, F.jsx)(`td`, {
        className: S(`max-w-xs break-words border-t border-border-subtle px-4 py-2 text-sm`, $),
        ...t,
        children: e,
      }),
    p: ({ node: e, children: t, ...n }) => {
      let r = e?.children;
      return r?.length > 0 && r.every((e) => e.tagName === `img` || (e.type === `text` && !e.value?.trim()))
        ? null
        : (0, F.jsx)(`p`, { className: S(`mb-4 last:mb-0`, $), ...n, children: t });
    },
    code: ({ children: e, ...t }) =>
      (0, F.jsx)(`code`, {
        className: S(`rounded-sm bg-surface-muted px-0.5 font-mono text-content-muted`, $),
        ...t,
        children: e,
      }),
    pre: ({ children: e, ...t }) => {
      let n = e?.props,
        r = n?.className?.replace(`language-`, ``) || ``,
        i = n?.children;
      return r === `mermaid` && typeof i == `string`
        ? (0, F.jsx)(G, { content: i, className: $ })
        : r === `yaml-automation` && typeof i == `string`
          ? (0, F.jsx)(Y, { content: i, className: $ })
          : (0, F.jsx)(V, {
              className: S(
                `mb-4 flex rounded-md border border-border-subtle bg-surface-muted px-2 pb-1 pt-2 font-mono text-sm last:mb-0 [.ona_&_code]:bg-transparent`,
                `[.user-message_&]:border-1 [.user-message_&]:rounded-lg [.user-message_&]:border-border-subtle [.user-message_&]:bg-surface-primary`,
                $,
              ),
              ...t,
              children: e,
            });
    },
    img: () => null,
    hr: () => (0, F.jsx)(`hr`, { className: `my-6 border-t border-border-strong` }),
    strong: ({ children: e, ...t }) =>
      (0, F.jsx)(`strong`, { className: S(`font-semibold text-content-primary`, $), ...t, children: e }),
    em: ({ children: e, ...t }) => (0, F.jsx)(`em`, { className: S(`italic`, $), ...t, children: e }),
  },
  ie = (0, P.memo)(
    ({ content: e, className: t = ``, showImageGallery: n = !1, ...r }) => {
      let i = (0, P.useMemo)(() => (n && e ? ee(e) : []), [n, e]);
      if (!e) return null;
      let a = X(e);
      return (0, F.jsxs)(`div`, {
        className: S(
          `markdown-container`,
          `[word-break:break-word]`,
          `[overflow-wrap:anywhere]`,
          `[&>*:last-child]:mb-0`,
          t,
        ),
        children: [
          (0, F.jsx)(l, { components: re, remarkPlugins: ne, ...r, children: a }),
          i.length > 0 && (0, F.jsx)(te, { images: i }),
        ],
      });
    },
    (e, t) => e.content === t.content && e.showImageGallery === t.showImageGallery,
  );
export { B as n, I as r, ie as t };
