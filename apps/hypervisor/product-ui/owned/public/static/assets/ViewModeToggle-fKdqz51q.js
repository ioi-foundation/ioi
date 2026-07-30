import { a as e } from "./rolldown-runtime-CGYlQKCx.js";
import { n as t } from "./@mux-DLaEVubF.js";
import {
  Au as n,
  Ld as r,
  Lh as i,
  Pu as a,
  Sh as o,
  Wp as s,
  _ as c,
  hd as l,
  md as u,
  nh as d,
  v_ as f,
  vc as p,
  yc as m,
  yd as h,
  zf as g,
} from "./vendor-DAwbZtf0.js";
import { l as _, lt as v, wt as y } from "./use-boot-in-app-chat-t-J_VjKS.js";
import { t as b } from "./use-theme-DWCPVAsU.js";
import { t as x } from "./button-6YP03Qf2.js";
import { t as S } from "./cn-DppMFCU8.js";
import { n as C } from "./haptic-tWxzGXjs.js";
import { n as w } from "./strings-C6LrS0GJ.js";
import { n as T } from "./utils-C9bSuXia.js";
import { t as E } from "./use-temporary-value-Bpxt61FD.js";
import { t as D } from "./Pill-99RRpZf2.js";
import "./pill-AA_qJIlm.js";
import { t as O } from "./text-fFCFeCas.js";
import { n as k, r as A, t as j } from "./dropdown-menu-D3UmjGpQ.js";
import { p as M } from "./ui-state-C-W85cTH.js";
import { t as N } from "./avatar-CjN22mGB.js";
import { t as P } from "./IOILettermark-D8gLTlP3.js";
import { t as F } from "./textarea-65aCrC5K.js";
import { t as I } from "./use-local-storage-6BcdMm3K.js";
import { t as L } from "./IconCheck-CjhQLbZQ.js";
import { t as R } from "./Markdown-DJPLghlF.js";
import "./register-Cy3DR9hT.js";
var z = e(t(), 1),
  ee = (e) => {
    let t = [];
    for (let n of e) {
      let e = n.body.split(`
`);
      for (let n = 0; n < e.length; n++) {
        let r = e[n];
        if (r === `` && n === e.length - 1) continue;
        let i = r === `` ? ` ` : r[0],
          a = r === `` ? `` : r.slice(1);
        (i === `+` || i === ` `) && t.push(a);
      }
    }
    return t.join(`
`);
  },
  te = (e, t) => {
    if (e.length === 0) return ``;
    let n = [`diff --git a/${t} b/${t}`, `--- a/${t}`, `+++ b/${t}`];
    for (let t of e) {
      let e = t.originalStartLine,
        r = t.originalLines,
        i = t.newStartLine,
        a = t.newLines,
        o = [],
        s = t.body.split(`
`);
      for (let e = 0; e < s.length; e++) {
        let t = s[e];
        (t === `` && e === s.length - 1) || o.push(t === `` ? ` ` : t);
      }
      (r === 0 || a === 0) && (o.unshift(` `), r++, a++, (e = Math.max(1, e - 1)), (i = Math.max(1, i - 1)));
      let c = `@@ -${e},${r} +${i},${a} @@${t.section ? ` ${t.section}` : ``}`;
      (n.push(c), n.push(...o));
    }
    return n.join(`
`);
  },
  B = (e) => {
    let t = 5381;
    for (let n = 0; n < e.length; n++) t = (t * 33) ^ e.charCodeAt(n);
    return (t >>> 0).toString(16);
  },
  ne = (e, t, n, r = `additions`) => {
    let i = [];
    for (let a of e) {
      let e = a.body.split(`
`),
        o = a.newStartLine,
        s = a.originalStartLine;
      for (let a = 0; a < e.length; a++) {
        let c = e[a];
        if (c === `` && a === e.length - 1) continue;
        let l = c === `` ? ` ` : c[0],
          u = c === `` ? `` : c.slice(1);
        r === `additions`
          ? (l === `+` || l === ` `) && (o >= t && o <= n && i.push(u), o++)
          : (l === `-` || l === ` `) && (s >= t && s <= n && i.push(u), s++);
      }
    }
    return i.length === 0
      ? null
      : B(
          i.join(`
`),
        );
  },
  V = (e, t, n) => {
    if (e === ``) return null;
    let r = e
      .split(
        `
`,
      )
      .slice(t - 1, n);
    return r.length === 0
      ? null
      : B(
          r.join(`
`),
        );
  },
  H = (e) =>
    e === ``
      ? 0
      : e.split(`
`).length,
  U = (e) => e.toLowerCase().endsWith(`.mdx`),
  W = (e) => {
    let t = e.toLowerCase();
    return t.endsWith(`.md`) || t.endsWith(`.markdown`) || U(e);
  },
  re = (e) => e.toLowerCase().endsWith(`.svg`),
  G = (e, t) => t.some((t) => e >= t.startLine && e <= t.endLine),
  ie = (e, t, n = `additions`) => {
    if (t < 1) return !1;
    for (let r of e) {
      let e = r.body.split(`
`),
        i = r.newStartLine,
        a = r.originalStartLine;
      for (let r = 0; r < e.length; r++) {
        let o = e[r];
        if (o === `` && r === e.length - 1) continue;
        let s = o === `` ? ` ` : o[0];
        if (n === `additions`) {
          if (s === `+` || s === ` `) {
            if (i === t) return !0;
            i++;
          }
          s === `-` && a++;
          continue;
        }
        if (s === `-` || s === ` `) {
          if (a === t) return !0;
          a++;
        }
        s === `+` && i++;
      }
    }
    return !1;
  },
  K = (e, t) => {
    let n = e.side ?? `additions`,
      r = e.endSide ?? n;
    return t(e.start, n) && t(e.end, r);
  },
  q = f(),
  ae = ({ size: e, className: t, ...n }) => {
    switch (e) {
      case `sm`:
        return (0, q.jsxs)(`svg`, {
          className: t,
          ...n,
          width: `16`,
          height: `16`,
          viewBox: `0 0 16 16`,
          fill: `none`,
          xmlns: `http://www.w3.org/2000/svg`,
          children: [
            (0, q.jsxs)(`g`, {
              clipPath: `url(#clip0_458_1095)`,
              children: [
                (0, q.jsx)(`path`, {
                  d: `M10.9167 9.16669V2.16669`,
                  stroke: `currentColor`,
                  strokeWidth: `1.15`,
                  strokeLinecap: `round`,
                  strokeLinejoin: `round`,
                }),
                (0, q.jsx)(`path`, {
                  d: `M6.25 11.57L6.83333 9.16669H3.4325C3.25138 9.16669 3.07275 9.12452 2.91075 9.04352C2.74875 8.96252 2.60784 8.84492 2.49917 8.70002C2.3905 8.55513 2.31705 8.38692 2.28465 8.20872C2.25225 8.03052 2.26179 7.84723 2.3125 7.67335L3.67167 3.00669C3.74235 2.76435 3.88972 2.55148 4.09167 2.40002C4.29361 2.24856 4.53924 2.16669 4.79167 2.16669H12.6667C12.9761 2.16669 13.2728 2.2896 13.4916 2.5084C13.7104 2.72719 13.8333 3.02393 13.8333 3.33335V8.00002C13.8333 8.30944 13.7104 8.60619 13.4916 8.82498C13.2728 9.04377 12.9761 9.16669 12.6667 9.16669H11.0567C10.8396 9.1668 10.6269 9.22746 10.4424 9.34185C10.258 9.45624 10.1091 9.61981 10.0125 9.81419L8 13.8334C7.72491 13.8299 7.45415 13.7644 7.20795 13.6417C6.96174 13.5189 6.74646 13.3421 6.57818 13.1245C6.4099 12.9068 6.29298 12.654 6.23615 12.3848C6.17933 12.1156 6.18406 11.8371 6.25 11.57Z`,
                  stroke: `currentColor`,
                  strokeWidth: `1.15`,
                  strokeLinecap: `round`,
                  strokeLinejoin: `round`,
                }),
              ],
            }),
            (0, q.jsx)(`defs`, {
              children: (0, q.jsx)(`clipPath`, {
                id: `clip0_458_1095`,
                children: (0, q.jsx)(`rect`, { width: `14`, height: `14`, fill: `white`, transform: `translate(1 1)` }),
              }),
            }),
          ],
        });
      case `base`:
        return (0, q.jsxs)(`svg`, {
          className: t,
          ...n,
          width: `20`,
          height: `20`,
          viewBox: `0 0 20 20`,
          fill: `none`,
          xmlns: `http://www.w3.org/2000/svg`,
          children: [
            (0, q.jsxs)(`g`, {
              clipPath: `url(#clip0_458_1099)`,
              children: [
                (0, q.jsx)(`path`, {
                  d: `M13.3333 11.3333V3.33331`,
                  stroke: `currentColor`,
                  strokeWidth: `1.25`,
                  strokeLinecap: `round`,
                  strokeLinejoin: `round`,
                }),
                (0, q.jsx)(`path`, {
                  d: `M8 14.08L8.66667 11.3333H4.78C4.57301 11.3333 4.36886 11.2851 4.18372 11.1925C3.99857 11.1 3.83753 10.9656 3.71333 10.8C3.58914 10.6344 3.5052 10.4421 3.46817 10.2385C3.43115 10.0348 3.44204 9.82536 3.5 9.62665L5.05333 4.29331C5.13411 4.01636 5.30254 3.77308 5.53333 3.59998C5.76413 3.42688 6.04484 3.33331 6.33333 3.33331H15.3333C15.687 3.33331 16.0261 3.47379 16.2761 3.72384C16.5262 3.97389 16.6667 4.31302 16.6667 4.66665V9.99998C16.6667 10.3536 16.5262 10.6927 16.2761 10.9428C16.0261 11.1928 15.687 11.3333 15.3333 11.3333H13.4933C13.2453 11.3334 13.0022 11.4028 12.7914 11.5335C12.5806 11.6642 12.4104 11.8512 12.3 12.0733L10 16.6666C9.68562 16.6628 9.37617 16.5879 9.0948 16.4476C8.81342 16.3073 8.56738 16.1052 8.37506 15.8565C8.18275 15.6078 8.04912 15.3188 7.98418 15.0112C7.91923 14.7036 7.92464 14.3852 8 14.08Z`,
                  stroke: `currentColor`,
                  strokeWidth: `1.25`,
                  strokeLinecap: `round`,
                  strokeLinejoin: `round`,
                }),
              ],
            }),
            (0, q.jsx)(`defs`, {
              children: (0, q.jsx)(`clipPath`, {
                id: `clip0_458_1099`,
                children: (0, q.jsx)(`rect`, { width: `16`, height: `16`, fill: `white`, transform: `translate(2 2)` }),
              }),
            }),
          ],
        });
      case `lg`:
        return (0, q.jsxs)(`svg`, {
          className: t,
          ...n,
          width: `24`,
          height: `24`,
          viewBox: `0 0 24 24`,
          fill: `none`,
          xmlns: `http://www.w3.org/2000/svg`,
          children: [
            (0, q.jsxs)(`g`, {
              clipPath: `url(#clip0_458_1103)`,
              children: [
                (0, q.jsx)(`path`, {
                  d: `M15.75 13.5V4.5`,
                  stroke: `currentColor`,
                  strokeWidth: `1.3`,
                  strokeLinecap: `round`,
                  strokeLinejoin: `round`,
                }),
                (0, q.jsx)(`path`, {
                  d: `M9.75 16.59L10.5 13.5H6.1275C5.89463 13.5 5.66496 13.4458 5.45668 13.3416C5.2484 13.2375 5.06722 13.0863 4.9275 12.9C4.78778 12.7137 4.69335 12.4974 4.65169 12.2683C4.61004 12.0392 4.6223 11.8036 4.6875 11.58L6.435 5.58C6.52588 5.26843 6.71536 4.99473 6.975 4.8C7.23464 4.60527 7.55044 4.5 7.875 4.5H18C18.3978 4.5 18.7794 4.65804 19.0607 4.93934C19.342 5.22064 19.5 5.60218 19.5 6V12C19.5 12.3978 19.342 12.7794 19.0607 13.0607C18.7794 13.342 18.3978 13.5 18 13.5H15.93C15.6509 13.5001 15.3774 13.5781 15.1403 13.7252C14.9031 13.8723 14.7117 14.0826 14.5875 14.3325L12 19.5C11.6463 19.4956 11.2982 19.4114 10.9816 19.2536C10.6651 19.0957 10.3883 18.8684 10.1719 18.5886C9.95559 18.3088 9.80526 17.9837 9.7322 17.6376C9.65913 17.2915 9.66522 16.9334 9.75 16.59Z`,
                  stroke: `currentColor`,
                  strokeWidth: `1.3`,
                  strokeLinecap: `round`,
                  strokeLinejoin: `round`,
                }),
              ],
            }),
            (0, q.jsx)(`defs`, {
              children: (0, q.jsx)(`clipPath`, {
                id: `clip0_458_1103`,
                children: (0, q.jsx)(`rect`, { width: `18`, height: `18`, fill: `white`, transform: `translate(3 3)` }),
              }),
            }),
          ],
        });
    }
  },
  oe = ({ size: e, className: t, ...n }) => {
    switch (e) {
      case `sm`:
        return (0, q.jsxs)(`svg`, {
          className: t,
          ...n,
          width: `16`,
          height: `16`,
          viewBox: `0 0 16 16`,
          fill: `none`,
          xmlns: `http://www.w3.org/2000/svg`,
          children: [
            (0, q.jsxs)(`g`, {
              clipPath: `url(#clip0_458_1067)`,
              children: [
                (0, q.jsx)(`path`, {
                  d: `M5.08333 6.83331V13.8333`,
                  stroke: `currentColor`,
                  strokeWidth: `1.15`,
                  strokeLinecap: `round`,
                  strokeLinejoin: `round`,
                }),
                (0, q.jsx)(`path`, {
                  d: `M9.75 4.43002L9.16667 6.83335H12.5675C12.7486 6.83335 12.9273 6.87552 13.0893 6.95652C13.2513 7.03752 13.3922 7.15513 13.5008 7.30002C13.6095 7.44492 13.683 7.61312 13.7154 7.79132C13.7478 7.96952 13.7382 8.15281 13.6875 8.32669L12.3283 12.9934C12.2577 13.2357 12.1103 13.4486 11.9083 13.6C11.7064 13.7515 11.4608 13.8334 11.2083 13.8334H3.33334C3.02392 13.8334 2.72717 13.7104 2.50838 13.4916C2.28959 13.2729 2.16667 12.9761 2.16667 12.6667V8.00002C2.16667 7.6906 2.28959 7.39386 2.50838 7.17506C2.72717 6.95627 3.02392 6.83335 3.33334 6.83335H4.94334C5.16039 6.83324 5.3731 6.77258 5.55756 6.65819C5.74202 6.5438 5.89092 6.38023 5.98751 6.18585L8 2.16669C8.27509 2.17009 8.54585 2.23562 8.79206 2.35837C9.03826 2.48112 9.25355 2.65792 9.42182 2.87556C9.5901 3.09319 9.70702 3.34605 9.76385 3.61522C9.82068 3.8844 9.81595 4.16293 9.75 4.43002Z`,
                  stroke: `currentColor`,
                  strokeWidth: `1.15`,
                  strokeLinecap: `round`,
                  strokeLinejoin: `round`,
                }),
              ],
            }),
            (0, q.jsx)(`defs`, {
              children: (0, q.jsx)(`clipPath`, {
                id: `clip0_458_1067`,
                children: (0, q.jsx)(`rect`, { width: `14`, height: `14`, fill: `white`, transform: `translate(1 1)` }),
              }),
            }),
          ],
        });
      case `base`:
        return (0, q.jsxs)(`svg`, {
          className: t,
          ...n,
          width: `20`,
          height: `20`,
          viewBox: `0 0 20 20`,
          fill: `none`,
          xmlns: `http://www.w3.org/2000/svg`,
          children: [
            (0, q.jsxs)(`g`, {
              clipPath: `url(#clip0_458_1072)`,
              children: [
                (0, q.jsx)(`path`, {
                  d: `M6.66667 8.66669V16.6667`,
                  stroke: `currentColor`,
                  strokeWidth: `1.25`,
                  strokeLinecap: `round`,
                  strokeLinejoin: `round`,
                }),
                (0, q.jsx)(`path`, {
                  d: `M12 5.91998L11.3333 8.66665H15.22C15.427 8.66665 15.6311 8.71484 15.8163 8.80741C16.0014 8.89998 16.1625 9.03439 16.2867 9.19998C16.4109 9.36557 16.4948 9.55781 16.5318 9.76147C16.5688 9.96512 16.558 10.1746 16.5 10.3733L14.9467 15.7066C14.8659 15.9836 14.6975 16.2269 14.4667 16.4C14.2359 16.5731 13.9552 16.6666 13.6667 16.6666H4.66666C4.31304 16.6666 3.9739 16.5262 3.72385 16.2761C3.4738 16.0261 3.33333 15.6869 3.33333 15.3333V9.99998C3.33333 9.64636 3.4738 9.30722 3.72385 9.05717C3.9739 8.80712 4.31304 8.66665 4.66666 8.66665H6.50666C6.75472 8.66651 6.99782 8.59719 7.20863 8.46646C7.41944 8.33573 7.58961 8.14879 7.7 7.92665L10 3.33331C10.3144 3.33721 10.6238 3.41209 10.9052 3.55238C11.1866 3.69266 11.4326 3.89472 11.6249 4.14345C11.8172 4.39218 11.9509 4.68115 12.0158 4.98878C12.0808 5.29641 12.0754 5.61474 12 5.91998Z`,
                  stroke: `currentColor`,
                  strokeWidth: `1.25`,
                  strokeLinecap: `round`,
                  strokeLinejoin: `round`,
                }),
              ],
            }),
            (0, q.jsx)(`defs`, {
              children: (0, q.jsx)(`clipPath`, {
                id: `clip0_458_1072`,
                children: (0, q.jsx)(`rect`, { width: `16`, height: `16`, fill: `white`, transform: `translate(2 2)` }),
              }),
            }),
          ],
        });
      case `lg`:
        return (0, q.jsxs)(`svg`, {
          className: t,
          ...n,
          width: `24`,
          height: `24`,
          viewBox: `0 0 24 24`,
          fill: `none`,
          xmlns: `http://www.w3.org/2000/svg`,
          children: [
            (0, q.jsxs)(`g`, {
              clipPath: `url(#clip0_458_1077)`,
              children: [
                (0, q.jsx)(`path`, {
                  d: `M8.25 10.5V19.5`,
                  stroke: `currentColor`,
                  strokeWidth: `1.3`,
                  strokeLinecap: `round`,
                  strokeLinejoin: `round`,
                }),
                (0, q.jsx)(`path`, {
                  d: `M14.25 7.41L13.5 10.5H17.8725C18.1054 10.5 18.335 10.5542 18.5433 10.6584C18.7516 10.7625 18.9328 10.9137 19.0725 11.1C19.2122 11.2863 19.3066 11.5026 19.3483 11.7317C19.39 11.9608 19.3777 12.1964 19.3125 12.42L17.565 18.42C17.4741 18.7316 17.2846 19.0053 17.025 19.2C16.7654 19.3947 16.4496 19.5 16.125 19.5H6C5.60218 19.5 5.22064 19.342 4.93934 19.0607C4.65804 18.7794 4.5 18.3978 4.5 18V12C4.5 11.6022 4.65804 11.2206 4.93934 10.9393C5.22064 10.658 5.60218 10.5 6 10.5H8.07C8.34906 10.4999 8.62255 10.4219 8.85972 10.2748C9.09688 10.1277 9.28832 9.91741 9.4125 9.6675L12 4.5C12.3537 4.50438 12.7018 4.58863 13.0184 4.74645C13.3349 4.90427 13.6117 5.13158 13.8281 5.4114C14.0444 5.69122 14.1947 6.01632 14.2678 6.3624C14.3409 6.70848 14.3348 7.0666 14.25 7.41Z`,
                  stroke: `currentColor`,
                  strokeWidth: `1.3`,
                  strokeLinecap: `round`,
                  strokeLinejoin: `round`,
                }),
              ],
            }),
            (0, q.jsx)(`defs`, {
              children: (0, q.jsx)(`clipPath`, {
                id: `clip0_458_1077`,
                children: (0, q.jsx)(`rect`, { width: `18`, height: `18`, fill: `white`, transform: `translate(3 3)` }),
              }),
            }),
          ],
        });
    }
  };
function se(e) {
  let t = e ? `Agent` : `IOI`;
  return {
    sendTarget: t,
    sendToTarget: `Send to ${t}`,
    sendCommentToTarget: `Send comment to ${t}`,
    sendAllCommentsToTarget: `Send all comments to ${t}`,
    sendCommentsToTarget: (e) => `Send ${w(e, !1, `comment`)} to ${t}`,
  };
}
function ce() {
  let { value: e } = _();
  return se(e);
}
var le = T(n),
  ue = T(a),
  de = T(g),
  fe = (e) => e === document.body || e === document || e === window,
  J = (0, z.memo)(
    ({
      defaultEditable: e = !1,
      defaultComment: t = ``,
      startLine: n,
      endLine: a,
      isOutdated: c = !1,
      author: l,
      commentId: u,
      filePath: f,
      thumbsUp: p = !1,
      thumbsDown: m = !1,
      onSubmit: g,
      onCancel: _,
      onDelete: v,
      onThumbsUp: b,
      onThumbsDown: C,
      onSendComment: w,
      onSendAllComments: T,
      allCommentsCount: N,
      isSendDisabled: P,
      onSendToIOI: I,
    }) => {
      let { sendToTarget: ee, sendCommentToTarget: te, sendAllCommentsToTarget: B } = ce(),
        [ne, V] = (0, z.useState)(!0),
        [H, U] = (0, z.useState)(e),
        [W, re] = (0, z.useState)(t),
        [G, ie] = E(!1, 2e3),
        [K, se] = E(!1, 2e3),
        J = (0, z.useRef)(null),
        Y = (0, z.useRef)(null),
        X = (0, z.useRef)(null),
        Z = (0, z.useRef)(e),
        me = y(),
        [he, ge] = r(M),
        _e = (0, z.useRef)(u);
      ((0, z.useEffect)(() => {
        u !== _e.current && ((_e.current = u), re(t), U(e), V(!0), (Z.current = e));
      }, [u, t, e]),
        (0, z.useEffect)(() => {
          he && he === u && (V(!0), (Z.current = !0), U(!0), ge(null));
        }, [he, u, ge]),
        (0, z.useEffect)(() => {
          if (!H || !Z.current) return;
          let e = requestAnimationFrame(() => {
            Z.current && ((Z.current = !1), X.current?.focus({ preventScroll: !0 }));
          });
          return () => cancelAnimationFrame(e);
        }, [H]),
        (0, z.useEffect)(() => {
          if (!H) return;
          let e = (e) => {
            let t = X.current;
            !t ||
              !t.isConnected ||
              document.activeElement !== document.body ||
              !fe(e.target) ||
              (e.key === `Backspace` && e.preventDefault(), t.focus({ preventScroll: !0 }));
          };
          return (
            document.addEventListener(`keydown`, e, { capture: !0 }),
            () => document.removeEventListener(`keydown`, e, { capture: !0 })
          );
        }, [H]));
      let ve = { isExpanded: ne, onExpandedChange: V, isDisabled: H },
        ye = s(ve),
        { buttonProps: be, panelProps: xe } = d(ve, ye, Y),
        { buttonProps: Se } = o(be, J),
        Ce = () => {
          W.trim() && ((Z.current = !1), U(!1), g(W.trim()));
        },
        Q = () => {
          (H && ((Z.current = !1), U(!1)), _());
        },
        we = () => {
          W.trim() && I && (I(W.trim()), Q());
        },
        Te = (e) => {
          e.key === `Enter` && (e.metaKey || e.ctrlKey) ? (e.preventDefault(), Ce()) : e.key === `Escape` && Q();
        },
        Ee = () => {
          (V(!0), (Z.current = !0), U(!0));
        },
        De = () => {
          p
            ? b?.(!1)
            : (ie(!0),
              m && C && (se(!1), C(!1)),
              b?.(!0),
              me(`agent_comment_voted`, { vote: `up`, comment_id: u, file_path: f, start_line: n, end_line: a }));
        },
        Oe = () => {
          m
            ? C?.(!1)
            : (se(!0),
              ie(!1),
              C?.(!0),
              me(`agent_comment_voted`, { vote: `down`, comment_id: u, file_path: f, start_line: n, end_line: a }));
        };
      return (0, q.jsx)(`div`, {
        className: `p-2 font-sans`,
        onMouseDown: (e) => {
          e.stopPropagation();
        },
        onFocus: (e) => {
          e.stopPropagation();
        },
        onBlur: (e) => {
          e.stopPropagation();
        },
        children: (0, q.jsxs)(`div`, {
          className: `max-w-xl overflow-clip rounded-md border border-border-base bg-surface-primary shadow-sm`,
          children: [
            (0, q.jsxs)(`div`, {
              className: S(`flex select-none items-center`, { "border-b border-border-subtle": ye.isExpanded }),
              children: [
                (0, q.jsxs)(x, {
                  variant: `ghost`,
                  size: `xs`,
                  ref: J,
                  ...i(Se),
                  className: `my-0.5 ml-0.5 flex grow items-center gap-0.5 rounded rounded-t-md py-0.5 pl-0.5 enabled:hover:bg-surface-hover disabled:opacity-100`,
                  children: [
                    (0, q.jsx)(`span`, {
                      className: `flex size-5 items-center justify-center`,
                      children: (0, q.jsx)(h, {
                        size: `base`,
                        className: S(
                          `size-3.5 text-content-primary transition-transform`,
                          ye.isExpanded && `rotate-90`,
                        ),
                      }),
                    }),
                    (0, q.jsxs)(O, {
                      className: `flex grow items-center gap-1 text-sm`,
                      children: [
                        (0, q.jsx)(`span`, {
                          className: `translate-y-[0.5px] text-content-secondary`,
                          children: a === n ? `Comment on line` : `Comment on lines`,
                        }),
                        (0, q.jsx)(`span`, { className: `font-medium`, children: a === n ? n : `${n}-${a}` }),
                        c && (0, q.jsx)(D, { variant: `warning`, size: `sm`, className: `ml-1`, children: `Outdated` }),
                      ],
                    }),
                  ],
                }),
                !H &&
                  (0, q.jsxs)(j, {
                    triggerButton: (0, q.jsx)(x, {
                      variant: `ghost`,
                      className: `m-1 size-5 rounded`,
                      "aria-label": `More actions`,
                      LeadingIcon: k,
                    }),
                    children: [
                      (0, q.jsx)(A.Item, {
                        LeadingIcon: ue,
                        onClick: Ee,
                        "data-tracking-id": `edit-comment-inline-comment-annotation-dropdown-actions`,
                        children: `Edit comment`,
                      }),
                      w &&
                        (0, q.jsx)(A.Item, {
                          LeadingIcon: de,
                          onClick: w,
                          disabled: P,
                          "data-tracking-id": `send-comment-to-ioi-inline-dropdown`,
                          children: te,
                        }),
                      T &&
                        N != null &&
                        N > 1 &&
                        (0, q.jsx)(A.Item, {
                          LeadingIcon: de,
                          onClick: T,
                          disabled: P,
                          "data-tracking-id": `send-all-comments-to-ioi-inline-dropdown`,
                          children: B,
                        }),
                      (0, q.jsx)(A.Separator, {}),
                      (0, q.jsx)(A.Item, {
                        variant: `destructive`,
                        LeadingIcon: le,
                        onClick: v,
                        "data-tracking-id": `delete-comment-inline-comment-annotation-dropdown-actions`,
                        children: `Dismiss comment`,
                      }),
                    ],
                  }),
              ],
            }),
            (0, q.jsxs)(`div`, {
              ref: Y,
              ...i(xe, { hidden: !ne }),
              children: [
                H
                  ? (0, q.jsx)(`div`, {
                      className: `p-2`,
                      children: (0, q.jsx)(F, {
                        "aria-label": `Comment`,
                        ref: X,
                        className: `border-border-subtle px-[13px] py-[9px] focus-within:ring-0 focus:px-3 focus:py-2 focus-visible:border-2 focus-visible:border-border-brand focus-visible:ring-0`,
                        minHeight: 80,
                        maxHeight: 240,
                        onChange: (e) => re(e.target.value),
                        onKeyDown: Te,
                        placeholder: `Add your comment...`,
                        value: W,
                      }),
                    })
                  : (0, q.jsxs)(`div`, {
                      className: `p-3`,
                      children: [
                        l && (0, q.jsx)(pe, { author: l }),
                        (0, q.jsx)(`div`, {
                          className: `text-wrap break-all text-base text-content-primary`,
                          children: (0, q.jsx)(R, { content: W }),
                        }),
                        l === `agent` &&
                          (0, q.jsxs)(`div`, {
                            className: `-ml-1 mt-1 flex items-center gap-1`,
                            children: [
                              (0, q.jsx)(x, {
                                variant: `ghost`,
                                size: `xs`,
                                className: S(`size-6 rounded p-0`, {
                                  "text-green-500": p && !G,
                                  "disabled:text-green-500": G,
                                }),
                                onClick: De,
                                disabled: G,
                                "aria-label": `Thumbs up`,
                                "data-tracking-id": `thumbs-up-agent-comment`,
                                children: G
                                  ? (0, q.jsx)(L, { size: `sm` })
                                  : (0, q.jsx)(oe, { size: `sm`, className: p ? `` : `text-content-secondary` }),
                              }),
                              (0, q.jsx)(x, {
                                variant: `ghost`,
                                size: `xs`,
                                className: S(`size-6 rounded p-0`, {
                                  "text-content-destructive": m && !K,
                                  "disabled:text-green-500": K,
                                }),
                                onClick: Oe,
                                disabled: K,
                                "aria-label": `Thumbs down`,
                                "data-tracking-id": `thumbs-down-agent-comment`,
                                children: K
                                  ? (0, q.jsx)(L, { size: `sm` })
                                  : (0, q.jsx)(ae, { size: `sm`, className: m ? `` : `text-content-secondary` }),
                              }),
                            ],
                          }),
                      ],
                    }),
                H &&
                  (0, q.jsxs)(`div`, {
                    className: `flex items-center justify-between border-t border-border-subtle p-2`,
                    children: [
                      (0, q.jsx)(x, {
                        variant: `ghost`,
                        className: `rounded`,
                        size: `xs`,
                        onClick: Q,
                        "data-tracking-id": `cancel-inline-comment`,
                        children: `Cancel`,
                      }),
                      (0, q.jsxs)(`div`, {
                        className: `flex gap-2`,
                        children: [
                          I &&
                            (0, q.jsx)(x, {
                              variant: `outline`,
                              className: `rounded`,
                              size: `xs`,
                              onClick: we,
                              disabled: !W.trim() || P,
                              "data-tracking-id": `send-to-ioi-inline-comment`,
                              children: ee,
                            }),
                          (0, q.jsx)(x, {
                            size: `xs`,
                            className: `rounded`,
                            onClick: Ce,
                            disabled: !W.trim(),
                            "data-tracking-id": `add-inline-comment`,
                            children: t === `` ? `Add comment` : `Update comment`,
                          }),
                        ],
                      }),
                    ],
                  }),
              ],
            }),
          ],
        }),
      });
    },
  );
J.displayName = `InlineCommentAnnotation`;
var pe = ({ author: e }) => {
  let { data: t } = v(),
    n = e === `agent`,
    r = n ? `IOI` : `You`,
    i = n ? `IOI` : t?.name || `You`,
    a = n ? void 0 : t?.avatarUrl;
  return (0, q.jsxs)(`div`, {
    className: `mb-1.5 flex select-none items-center gap-1.5`,
    children: [
      n
        ? (0, q.jsx)(P, { width: 16, height: 16, className: `shrink-0 text-content-primary` })
        : (0, q.jsxs)(N, {
            size: 16,
            children: [
              a && (0, q.jsx)(N.Image, { src: a }),
              (0, q.jsx)(N.Fallback, { children: (0, q.jsx)(N.Initials, { name: i, size: 16 }) }),
            ],
          }),
      (0, q.jsx)(O, { className: `text-base font-medium`, children: r }),
    ],
  });
};
function Y(e) {
  let { createAnnotation: t, fallbackSelection: n = null } = e,
    [r, i] = (0, z.useState)(null),
    [a, o] = (0, z.useState)(null),
    [s, c] = (0, z.useState)(null),
    [l, u] = (0, z.useState)(null),
    d = (0, z.useRef)(a);
  d.current = a;
  let f = (0, z.useRef)(l);
  f.current = l;
  let p = (0, z.useRef)(t);
  p.current = t;
  let m = (0, z.useCallback)((e) => {
      (i(p.current(e)), o(null), c(null));
    }, []),
    h = (0, z.useCallback)(
      (e) => {
        if (e && d.current && C()) {
          let t = {
            start: d.current.start,
            end: e.start,
            side: d.current.side,
            endSide: e.side === d.current.side ? void 0 : e.side,
          };
          (o(null), u(t), m(t));
        } else C() || c(e);
      },
      [m],
    ),
    g = (0, z.useCallback)((e) => {
      C() || c(e);
    }, []),
    _ = (0, z.useCallback)(
      (e) => {
        if (C()) {
          f.current ? m(f.current) : d.current && !e ? m(d.current) : e && o(e);
          return;
        }
        e ? m(e) : c(null);
      },
      [m],
    ),
    v = (0, z.useCallback)(() => {
      (i(null), o(null), c(null), u(null));
    }, []),
    y = v,
    b;
  return (
    (b = a || s || l || (r ? void 0 : n)),
    {
      pendingAnnotation: r,
      selectedLines: b,
      handleLineSelectionStart: h,
      handleLineSelectionChange: g,
      handleLineSelectionEnd: _,
      handleCommentCancel: y,
      clearSelection: v,
      setPendingAnnotation: i,
    }
  );
}
var X = `
    [data-interactive-line-numbers] [data-column-number] { touch-action: none; }
    [data-utility-button] {
        background-color: rgb(var(--surface-primary-inverted));
        color: rgb(var(--content-primary-inverted));
        border-radius: 6px;
        font-family: var(--font-family-mono);
        font-size: 16px;
        font-weight: 500;
    }
    @media (hover: none) and (pointer: coarse) {
        [data-interactive-line-numbers] [data-column-number] { touch-action: pan-x; }
    }
`,
  Z = ({ onPress: e }) =>
    (0, q.jsx)(`button`, {
      type: `button`,
      "data-utility-button": ``,
      "data-tracking-id": `add-comment-on-line`,
      "aria-label": `Add comment on line`,
      className: `relative z-10 flex size-5 items-center justify-center rounded-md bg-surface-primary-inverted font-mono text-base font-medium leading-none text-content-primary-inverted`,
      onPointerDown: (e) => {
        (e.preventDefault(), e.stopPropagation());
      },
      onClick: (t) => {
        (t.preventDefault(), t.stopPropagation(), e());
      },
      children: `+`,
    }),
  me = ({
    hunks: e,
    filePath: t = `file`,
    expandUnchanged: n = !1,
    comments: r,
    onAddComment: i,
    onUpdateComment: a,
    onDeleteComment: o,
    onSetCommentThumbsUp: s,
    onSetCommentThumbsDown: c,
    onSendComment: l,
    onSendAllComments: u,
    allCommentsCount: d,
    isSendDisabled: f,
    onSendToIOI: m,
  }) => {
    let { effectiveTheme: h } = b(),
      g = (0, z.useMemo)(() => te(e, t), [e, t]),
      _ = (0, z.useCallback)(
        (e) => ({
          side: e.endSide ?? e.side ?? `additions`,
          lineNumber: e.end,
          metadata: { startLine: e.start, endLine: e.end },
        }),
        [],
      ),
      {
        pendingAnnotation: v,
        selectedLines: y,
        handleLineSelectionStart: x,
        handleLineSelectionChange: S,
        handleLineSelectionEnd: C,
        handleCommentCancel: w,
        clearSelection: T,
        setPendingAnnotation: E,
      } = Y({ createAnnotation: _ }),
      D = (0, z.useMemo)(() => (y == null || K(y, (t, n) => ie(e, t, n)) ? y : null), [e, y]),
      O = (0, z.useMemo)(() => {
        let e = [];
        if (r)
          for (let t of r)
            e.push({
              side: t.side ?? `additions`,
              lineNumber: t.endLine,
              metadata: { reviewComment: t, startLine: t.startLine, endLine: t.endLine },
            });
        return (v && e.push(v), e);
      }, [r, v]),
      k = (0, z.useCallback)(
        (t) => {
          if (v?.metadata) {
            let { startLine: n, endLine: r } = v.metadata,
              a = v.side,
              o = ne(e, n, r, a) ?? void 0;
            (i?.(t, n, r, a, o), T());
          }
        },
        [T, v, e, i],
      ),
      A = (0, z.useCallback)(
        (e) => (t) => {
          a?.(e, t);
        },
        [a],
      ),
      j = (0, z.useCallback)(
        (e) => () => {
          o?.(e);
        },
        [o],
      ),
      M = (0, z.useCallback)(
        (n) => {
          let { startLine: r, endLine: i, reviewComment: a } = n.metadata,
            o = !1;
          if (a?.contentHash) {
            let t = ne(e, r, i, a.side ?? `additions`);
            o = t !== null && t !== a.contentHash;
          }
          return (0, q.jsx)(J, {
            startLine: r,
            endLine: i,
            defaultComment: a?.content ?? ``,
            defaultEditable: !a,
            isOutdated: o,
            author: a?.author,
            commentId: a?.id,
            filePath: t,
            thumbsUp: a?.thumbsUp,
            thumbsDown: a?.thumbsDown,
            onSubmit: a ? A(a) : k,
            onCancel: w,
            onDelete: a ? j(a) : void 0,
            onThumbsUp: a && s ? (e) => s(a, e) : void 0,
            onThumbsDown: a && c ? (e) => c(a, e) : void 0,
            onSendComment: a && l ? () => l(a) : void 0,
            onSendAllComments: u,
            allCommentsCount: d,
            isSendDisabled: f,
            onSendToIOI: m ? (e) => m(e, r, i) : void 0,
          });
        },
        [d, t, w, j, k, A, e, f, u, l, m, c, s],
      ),
      N = !!i,
      P = y != null || !!v,
      F = i ? C : void 0,
      I = (0, z.useMemo)(
        () => ({
          theme: { dark: `ioi-dark`, light: `ioi-light` },
          themeType: h,
          diffStyle: `unified`,
          diffIndicators: `bars`,
          hunkSeparators: `simple`,
          expandUnchanged: n,
          disableFileHeader: !0,
          overflow: `scroll`,
          enableLineSelection: N,
          enableGutterUtility: N,
          onLineSelectionStart: x,
          onLineSelectionChange: S,
          onLineSelectionEnd: F,
          unsafeCSS: X,
        }),
        [h, n, N, x, S, F],
      ),
      L = (0, z.useMemo)(
        () =>
          N
            ? (e) =>
                !P &&
                (0, q.jsx)(Z, {
                  onPress: () => {
                    let t = e();
                    t && E(_({ start: t.lineNumber, end: t.lineNumber, side: t.side ?? `additions` }));
                  },
                })
            : void 0,
        [_, N, P, E],
      ),
      R = (0, z.useMemo)(() => ({ "--diffs-font-family": `var(--font-family-mono)`, "--diffs-gap-block": `0px` }), []);
    return g
      ? (0, q.jsx)(p, {
          patch: g,
          options: I,
          selectedLines: D,
          lineAnnotations: O,
          renderAnnotation: M,
          renderGutterUtility: L,
          style: R,
        })
      : null;
  },
  he = ({
    originalContent: e,
    newContent: t,
    filePath: n = `file`,
    hunks: r,
    expandUnchanged: i = !1,
    comments: a,
    onAddComment: o,
    onUpdateComment: s,
    onDeleteComment: c,
    onSetCommentThumbsUp: l,
    onSetCommentThumbsDown: u,
    onSendComment: d,
    onSendAllComments: f,
    allCommentsCount: p,
    isSendDisabled: h,
    onSendToIOI: g,
  }) => {
    let { effectiveTheme: _ } = b(),
      v = (0, z.useMemo)(() => ({ name: n, contents: e, cacheKey: `${n}:old:${e.length}:${B(e)}` }), [n, e]),
      y = (0, z.useMemo)(() => ({ name: n, contents: t, cacheKey: `${n}:new:${t.length}:${B(t)}` }), [n, t]),
      x = (0, z.useCallback)(
        (e) => ({
          side: e.endSide ?? e.side ?? `additions`,
          lineNumber: e.end,
          metadata: { startLine: e.start, endLine: e.end },
        }),
        [],
      ),
      {
        pendingAnnotation: S,
        selectedLines: C,
        handleLineSelectionStart: w,
        handleLineSelectionChange: T,
        handleLineSelectionEnd: E,
        handleCommentCancel: D,
        clearSelection: O,
        setPendingAnnotation: k,
      } = Y({ createAnnotation: x }),
      A = (0, z.useCallback)(
        (n) => {
          if (S?.metadata) {
            let { startLine: r, endLine: i } = S.metadata,
              a = S.side,
              s = V(a === `deletions` ? e : t, r, i) ?? void 0;
            (o?.(n, r, i, a, s), O());
          }
        },
        [O, S, t, o, e],
      ),
      j = (0, z.useMemo)(() => {
        let e = [];
        if (a)
          for (let t of a)
            e.push({
              side: t.side ?? `additions`,
              lineNumber: t.endLine,
              metadata: { reviewComment: t, startLine: t.startLine, endLine: t.endLine },
            });
        return (S && e.push(S), e);
      }, [a, S]),
      M = (0, z.useCallback)(
        (e) => (t) => {
          s?.(e, t);
        },
        [s],
      ),
      N = (0, z.useCallback)(
        (e) => () => {
          c?.(e);
        },
        [c],
      ),
      P = (0, z.useCallback)(
        (r) => {
          let { startLine: i, endLine: a, reviewComment: o } = r.metadata,
            s = !1;
          if (o?.contentHash) {
            let n = V(o.side === `deletions` ? e : t, i, a);
            s = n !== null && n !== o.contentHash;
          }
          return (0, q.jsx)(J, {
            startLine: i,
            endLine: a,
            defaultComment: o?.content ?? ``,
            defaultEditable: !o,
            isOutdated: s,
            author: o?.author,
            commentId: o?.id,
            filePath: n,
            thumbsUp: o?.thumbsUp,
            thumbsDown: o?.thumbsDown,
            onSubmit: o ? M(o) : A,
            onCancel: D,
            onDelete: o ? N(o) : void 0,
            onThumbsUp: o && l ? (e) => l(o, e) : void 0,
            onThumbsDown: o && u ? (e) => u(o, e) : void 0,
            onSendComment: o && d ? () => d(o) : void 0,
            onSendAllComments: f,
            allCommentsCount: p,
            isSendDisabled: h,
            onSendToIOI: g ? (e) => g(e, i, a) : void 0,
          });
        },
        [p, n, D, N, A, M, h, t, f, d, g, u, l, e],
      ),
      F = (0, z.useMemo)(() => {
        if (!a || a.length === 0) return !1;
        let e = r.map((e) => ({ startLine: e.newStartLine, endLine: e.newStartLine + e.newLines - 1 }));
        return a.some((t) => {
          for (let n = t.startLine; n <= t.endLine; n++) if (!G(n, e)) return !0;
          return !1;
        });
      }, [a, r]),
      I = (0, z.useMemo)(() => {
        if (C == null) return C;
        let n = i || F;
        return K(C, (i, a) => {
          if (!n) return ie(r, i, a);
          let o = H(a === `deletions` ? e : t);
          return i >= 1 && i <= o;
        })
          ? C
          : null;
      }, [i, F, r, t, e, C]),
      L = !!o,
      R = C != null || !!S,
      ee = o ? E : void 0;
    return (0, q.jsx)(m, {
      oldFile: v,
      newFile: y,
      options: (0, z.useMemo)(
        () => ({
          theme: { dark: `ioi-dark`, light: `ioi-light` },
          themeType: _,
          diffStyle: `unified`,
          diffIndicators: `bars`,
          hunkSeparators: `line-info`,
          expandUnchanged: i || F,
          disableFileHeader: !0,
          overflow: `scroll`,
          enableLineSelection: L,
          enableGutterUtility: L,
          onLineSelectionStart: w,
          onLineSelectionChange: T,
          onLineSelectionEnd: ee,
          unsafeCSS: X,
        }),
        [_, i, F, L, w, T, ee],
      ),
      selectedLines: I,
      lineAnnotations: j,
      renderAnnotation: P,
      renderGutterUtility: (0, z.useMemo)(
        () =>
          L
            ? (e) =>
                !R &&
                (0, q.jsx)(Z, {
                  onPress: () => {
                    let t = e();
                    t && k(x({ start: t.lineNumber, end: t.lineNumber, side: t.side ?? `additions` }));
                  },
                })
            : void 0,
        [x, L, R, k],
      ),
      style: (0, z.useMemo)(() => ({ "--diffs-font-family": `var(--font-family-mono)` }), []),
    });
  },
  ge = `mdxJsxFlowElement`,
  _e = `mdxJsxTextElement`,
  ve = `mdxFlowExpression`,
  ye = `mdxTextExpression`,
  be = `mdxjsEsm`;
function xe(e) {
  let t = [];
  for (let n of e) {
    let e = n.type;
    if (e === be || e === ve || e === ye) continue;
    if (e === ge || e === _e) {
      let e = n;
      e.children && e.children.length > 0 && t.push(...xe(e.children));
      continue;
    }
    let r = n;
    (r.children && Array.isArray(r.children) && (r.children = xe(r.children)), t.push(n));
  }
  return t;
}
var Se = () => (e) => {
    e.children = xe(e.children);
  },
  Ce = (0, z.createContext)(!1),
  Q = `data-md-preview-root`,
  we = ({ onPress: e, startLine: t }) =>
    (0, q.jsx)(`button`, {
      ref: (0, z.useCallback)((e) => {
        if (!e) return;
        let t = e.closest(`[${Q}]`);
        if (!t || !e.offsetParent) return;
        let n = t.getBoundingClientRect().left,
          r = e.offsetParent.getBoundingClientRect().left;
        e.style.left = `${n - r}px`;
      }, []),
      type: `button`,
      onClick: e,
      "data-tracking-id": `markdown-preview-add-comment`,
      className: `absolute top-0.5 flex size-5 select-none items-center justify-center rounded-md bg-surface-primary-inverted font-mono text-base text-content-primary-inverted opacity-0 group-hover/commentable:opacity-100`,
      "aria-label": `Add comment on line ${t}`,
      children: `+`,
    }),
  Te = (e, t, n) => e.filter((e) => e.startLine <= n && e.endLine >= t),
  Ee = ({ node: e, children: t, className: n, ctxRef: r }) => {
    if ((0, z.useContext)(Ce)) return (0, q.jsx)(`div`, { className: n, children: t });
    let i = r.current,
      a = e?.position?.start?.line ?? 0,
      o = e?.position?.end?.line ?? 0;
    return (0, q.jsx)(Ce.Provider, {
      value: !0,
      children: (0, q.jsx)(De, { startLine: a, endLine: o, className: n, ctxRef: r, ctx: i, children: t }),
    });
  },
  De = ({ startLine: e, endLine: t, children: n, className: r, ctxRef: i, ctx: a }) => {
    let o = (0, z.useMemo)(() => (e > 0 ? Te(a.comments, e, t) : []), [a.comments, e, t]),
      s = a.pendingComment !== null && a.pendingComment.startLine === e && a.pendingComment.endLine === t,
      c = (0, z.useCallback)(() => {
        e > 0 && i.current.onStartComment(e, t);
      }, [e, t, i]),
      l = (0, z.useCallback)(
        (e) => {
          if (!e || !a.enableAddComment) return;
          let t = e.closest(`[${Q}]`);
          if (!t) return;
          let n = t.getBoundingClientRect().left,
            r = e.getBoundingClientRect().left - n;
          r > 0 && e.style.setProperty(`--gutter-offset`, `${r}px`);
        },
        [a.enableAddComment],
      ),
      u = o.length > 0 || s;
    return (0, q.jsxs)(q.Fragment, {
      children: [
        (0, q.jsxs)(`div`, {
          ref: a.enableAddComment ? l : void 0,
          className: S(
            `group/commentable relative`,
            a.enableAddComment &&
              `before:absolute before:inset-y-0 before:right-full before:w-[var(--gutter-offset,1.75rem)]`,
            r,
          ),
          "data-source-start": e || void 0,
          "data-source-end": t || void 0,
          children: [a.enableAddComment && e > 0 && (0, q.jsx)(we, { onPress: c, startLine: e }), n],
        }),
        u &&
          (0, q.jsxs)(`div`, {
            className: `my-1`,
            children: [
              o.map((e) =>
                (0, q.jsx)(
                  J,
                  {
                    startLine: e.startLine,
                    endLine: e.endLine,
                    defaultComment: e.content,
                    defaultEditable: !1,
                    isOutdated: !1,
                    author: e.author,
                    commentId: e.id,
                    filePath: e.filePath,
                    thumbsUp: e.thumbsUp,
                    thumbsDown: e.thumbsDown,
                    onSubmit: (t) => a.onUpdateComment?.(e, t),
                    onCancel: a.onCancelComment,
                    onDelete: () => a.onDeleteComment?.(e),
                    onThumbsUp: a.onSetCommentThumbsUp ? (t) => a.onSetCommentThumbsUp(e, t) : void 0,
                    onThumbsDown: a.onSetCommentThumbsDown ? (t) => a.onSetCommentThumbsDown(e, t) : void 0,
                    onSendComment: a.onSendComment ? () => a.onSendComment(e) : void 0,
                    onSendAllComments: a.onSendAllComments,
                    allCommentsCount: a.allCommentsCount,
                    isSendDisabled: a.isSendDisabled,
                    onSendToIOI: a.onSendToIOI ? (t) => a.onSendToIOI(t, e.startLine, e.endLine) : void 0,
                  },
                  e.id,
                ),
              ),
              s &&
                (0, q.jsx)(J, {
                  startLine: a.pendingComment.startLine,
                  endLine: a.pendingComment.endLine,
                  defaultComment: ``,
                  defaultEditable: !0,
                  onSubmit: a.onSubmitComment,
                  onCancel: a.onCancelComment,
                  onSendToIOI: a.onSendToIOI
                    ? (e) => a.onSendToIOI(e, a.pendingComment.startLine, a.pendingComment.endLine)
                    : void 0,
                  isSendDisabled: a.isSendDisabled,
                }),
            ],
          }),
      ],
    });
  },
  Oe = ({
    content: e,
    className: t,
    isMdx: n = !1,
    comments: r = [],
    onAddComment: i,
    onUpdateComment: a,
    onDeleteComment: o,
    onSetCommentThumbsUp: s,
    onSetCommentThumbsDown: c,
    onSendComment: u,
    onSendAllComments: d,
    allCommentsCount: f,
    isSendDisabled: p,
    onSendToIOI: m,
  }) => {
    let [h, g] = (0, z.useState)(null),
      _ = (0, z.useCallback)((e, t) => {
        g({ startLine: e, endLine: t });
      }, []),
      v = (0, z.useCallback)(
        (e) => {
          (h && i && i(e, h.startLine, h.endLine, `additions`), g(null));
        },
        [h, i],
      ),
      y = (0, z.useCallback)(() => {
        g(null);
      }, []),
      b = !!i,
      x = b || r.length > 0,
      C = (0, z.useRef)({
        comments: r,
        pendingComment: h,
        enableAddComment: b,
        onStartComment: _,
        onSubmitComment: v,
        onCancelComment: y,
        onUpdateComment: a,
        onDeleteComment: o,
        onSetCommentThumbsUp: s,
        onSetCommentThumbsDown: c,
        onSendComment: u,
        onSendAllComments: d,
        allCommentsCount: f,
        isSendDisabled: p,
        onSendToIOI: m,
      });
    C.current = {
      comments: r,
      pendingComment: h,
      enableAddComment: b,
      onStartComment: _,
      onSubmitComment: v,
      onCancelComment: y,
      onUpdateComment: a,
      onDeleteComment: o,
      onSetCommentThumbsUp: s,
      onSetCommentThumbsDown: c,
      onSendComment: u,
      onSendAllComments: d,
      allCommentsCount: f,
      isSendDisabled: p,
      onSendToIOI: m,
    };
    let w = (0, z.useMemo)(() => {
      if (!x) return $;
      let e = (e) => {
        let t = (t) => {
          let { node: n } = t;
          return (0, q.jsx)(Ee, { node: n, ctxRef: C, children: e(t) });
        };
        return ((t.displayName = `Commentable(${e.name || `Anonymous`})`), t);
      };
      return {
        h1: e(({ children: e, node: t, ...n }) =>
          (0, q.jsx)(`h1`, { className: `pb-2 text-xl font-medium`, ...n, children: e }),
        ),
        h2: e(({ children: e, node: t, ...n }) =>
          (0, q.jsx)(`h2`, { className: `pb-1 text-lg font-medium`, ...n, children: e }),
        ),
        h3: e(({ children: e, node: t, ...n }) =>
          (0, q.jsx)(`h3`, { className: `pb-2 text-md font-medium`, ...n, children: e }),
        ),
        ul: $.ul,
        ol: $.ol,
        li: e(({ children: e, node: t, ...n }) => (0, q.jsx)(`li`, { className: `mb-1`, ...n, children: e })),
        a: $.a,
        blockquote: e(({ children: e, node: t, ...n }) =>
          (0, q.jsx)(`blockquote`, {
            className: `mb-4 border-l-4 border-border-base py-1 pl-4 text-content-muted`,
            ...n,
            children: e,
          }),
        ),
        table: e(({ children: e, node: t, ...n }) =>
          (0, q.jsx)(`div`, {
            className: `mb-4 overflow-hidden overflow-x-auto rounded-lg border border-border-subtle [overflow-wrap:normal] [word-break:normal]`,
            children: (0, q.jsx)(`table`, { className: `w-full`, ...n, children: e }),
          }),
        ),
        thead: $.thead,
        th: $.th,
        td: $.td,
        p: e(({ node: e, children: t, ...n }) => {
          let r = e?.children;
          return r?.[0]?.tagName === `img` && r.length === 1
            ? (0, q.jsx)(q.Fragment, { children: t })
            : (0, q.jsx)(`p`, { className: `mb-4`, ...n, children: t });
        }),
        code: $.code,
        pre: e(({ children: e, node: t, ...n }) =>
          (0, q.jsx)(`pre`, {
            className: `mb-4 overflow-x-auto rounded-md border border-border-subtle bg-surface-muted px-2 pb-1 pt-2 font-mono text-sm`,
            ...n,
            children: e,
          }),
        ),
        img: $.img,
        hr: e(() => (0, q.jsx)(`hr`, { className: `my-6 border-t border-border-strong` })),
        strong: $.strong,
        em: $.em,
      };
    }, [x]);
    return e
      ? (0, q.jsx)(`div`, {
          [Q]: ``,
          className: S(`[word-break:break-word]`, `[overflow-wrap:anywhere]`, x && `pl-7`, t),
          children: (0, q.jsx)(l, { components: w, remarkPlugins: n ? Ae : ke, children: e }),
        })
      : null;
  },
  ke = [u],
  Ae = [c, Se, u],
  $ = {
    h1: ({ children: e, node: t, ...n }) =>
      (0, q.jsx)(`h1`, { className: `pb-2 text-xl font-medium`, ...n, children: e }),
    h2: ({ children: e, node: t, ...n }) =>
      (0, q.jsx)(`h2`, { className: `pb-1 text-lg font-medium`, ...n, children: e }),
    h3: ({ children: e, node: t, ...n }) =>
      (0, q.jsx)(`h3`, { className: `pb-2 text-md font-medium`, ...n, children: e }),
    ul: ({ children: e, node: t, ...n }) => (0, q.jsx)(`ul`, { className: `mb-4 list-disc pl-8`, ...n, children: e }),
    ol: ({ children: e, node: t, ...n }) =>
      (0, q.jsx)(`ol`, { className: `mb-4 list-decimal pl-8 last:mb-0`, ...n, children: e }),
    li: ({ children: e, node: t, ...n }) => (0, q.jsx)(`li`, { className: `mb-1`, ...n, children: e }),
    a: ({ children: e, node: t, ...n }) =>
      (0, q.jsx)(`a`, {
        className: `text-content-link hover:underline`,
        target: `_blank`,
        rel: `noopener noreferrer`,
        ...n,
        children: e,
      }),
    blockquote: ({ children: e, node: t, ...n }) =>
      (0, q.jsx)(`blockquote`, {
        className: `mb-4 border-l-4 border-border-base py-1 pl-4 text-content-muted`,
        ...n,
        children: e,
      }),
    table: ({ children: e, node: t, ...n }) =>
      (0, q.jsx)(`div`, {
        className: `mb-4 overflow-hidden overflow-x-auto rounded-lg border border-border-subtle [overflow-wrap:normal] [word-break:normal]`,
        children: (0, q.jsx)(`table`, { className: `w-full`, ...n, children: e }),
      }),
    thead: ({ children: e, node: t, ...n }) =>
      (0, q.jsx)(`thead`, { className: `border-b border-border-subtle bg-surface-muted`, ...n, children: e }),
    th: ({ children: e, node: t, ...n }) =>
      (0, q.jsx)(`th`, { className: `whitespace-nowrap px-4 py-2 text-left text-sm font-semibold`, ...n, children: e }),
    td: ({ children: e, node: t, ...n }) =>
      (0, q.jsx)(`td`, { className: `border-t border-border-subtle px-4 py-2 text-sm`, ...n, children: e }),
    p: ({ node: e, children: t, ...n }) => {
      let r = e?.children;
      return r?.[0]?.tagName === `img` && r.length === 1
        ? (0, q.jsx)(q.Fragment, { children: t })
        : (0, q.jsx)(`p`, { className: `mb-4 last:mb-0`, ...n, children: t });
    },
    code: ({ children: e, node: t, ...n }) =>
      (0, q.jsx)(`code`, {
        className: `rounded-sm bg-surface-muted px-0.5 font-mono text-content-muted`,
        ...n,
        children: e,
      }),
    pre: ({ children: e, node: t, ...n }) =>
      (0, q.jsx)(`pre`, {
        className: `mb-4 overflow-x-auto rounded-md border border-border-subtle bg-surface-muted px-2 pb-1 pt-2 font-mono text-sm last:mb-0`,
        ...n,
        children: e,
      }),
    img: ({ node: e, ...t }) =>
      (0, q.jsx)(`img`, { className: `my-2 h-auto max-w-full rounded-md`, ...t, alt: t.alt || `` }),
    hr: () => (0, q.jsx)(`hr`, { className: `my-6 border-t border-border-strong` }),
    strong: ({ children: e, node: t, ...n }) => (0, q.jsx)(`strong`, { className: `font-semibold`, ...n, children: e }),
    em: ({ children: e, node: t, ...n }) => (0, q.jsx)(`em`, { className: `italic`, ...n, children: e }),
  },
  je = (0, z.memo)(
    Oe,
    (e, t) =>
      e.content === t.content &&
      e.className === t.className &&
      e.isMdx === t.isMdx &&
      e.comments === t.comments &&
      e.onAddComment === t.onAddComment &&
      e.onUpdateComment === t.onUpdateComment &&
      e.onDeleteComment === t.onDeleteComment &&
      e.onSetCommentThumbsUp === t.onSetCommentThumbsUp &&
      e.onSetCommentThumbsDown === t.onSetCommentThumbsDown,
  ),
  Me = {
    destructive: {
      border: `border-content-destructive/50`,
      bg: `bg-surface-destructive-subtle/20`,
      text: `text-content-destructive`,
    },
    success: { border: `border-content-success/50`, bg: `bg-surface-success-subtle/20`, text: `text-content-success` },
  },
  Ne = ({ src: e, alt: t, label: n, variant: r, className: i }) => {
    let a = Me[r];
    return (0, q.jsxs)(`div`, {
      className: S(`flex flex-col items-center gap-2 border p-3`, a.border, a.bg, i),
      children: [
        (0, q.jsx)(O, { className: S(`select-none text-xs font-medium`, a.text), children: n }),
        (0, q.jsx)(`img`, {
          src: e,
          alt: t,
          className: `max-h-96 select-none rounded border border-border-base object-contain`,
        }),
      ],
    });
  },
  Pe = ({ original: e, updated: t }) => {
    let n = !!e,
      r = !!t;
    return (0, q.jsxs)(`div`, {
      className: `flex items-start justify-center gap-1 p-4`,
      children: [
        n &&
          (0, q.jsx)(Ne, {
            src: e,
            alt: `Original version`,
            label: r ? `Original` : `Deleted`,
            variant: `destructive`,
            className: r ? `rounded-l-lg rounded-r` : `rounded-lg`,
          }),
        r &&
          (0, q.jsx)(Ne, {
            src: t,
            alt: `Updated version`,
            label: n ? `Updated` : `Added`,
            variant: `success`,
            className: n ? `rounded-l rounded-r-lg` : `rounded-lg`,
          }),
      ],
    });
  },
  Fe = ({ content: e, className: t }) => {
    let n = (0, z.useMemo)(() => `data:image/svg+xml,${encodeURIComponent(e)}`, [e]);
    return (0, q.jsx)(`div`, {
      className: S(`flex items-center justify-center rounded-lg border border-border-base bg-surface-secondary p-6`, t),
      children: (0, q.jsx)(`img`, { src: n, alt: `SVG preview`, className: `max-h-[600px] max-w-full object-contain` }),
    });
  },
  Ie = `preview-file-view-mode`,
  Le = `preview`,
  Re = () => {
    let { storedValue: e, setValue: t } = I(Ie, Le);
    return {
      viewMode: e === `diff` ? `diff` : `preview`,
      setViewMode: (0, z.useCallback)(
        (e) => {
          t(e);
        },
        [t],
      ),
    };
  },
  ze = [
    { value: `diff`, label: `Code` },
    { value: `preview`, label: `Preview` },
  ],
  Be = ({ viewMode: e, onChange: t, stopPropagation: n = !1, className: r }) => {
    let i = (0, z.useCallback)(
      (e, r) => {
        (n && e.stopPropagation(), t(r));
      },
      [t, n],
    );
    return (0, q.jsx)(`div`, {
      className: S(`flex h-6 rounded-md border border-border-base bg-surface-button-tab-base text-sm`, r),
      role: `group`,
      "aria-label": `View mode`,
      children: ze.map(({ value: t, label: n }, r) => {
        let a = e === t,
          o = r === 0,
          s = r === ze.length - 1;
        return (0, q.jsx)(
          `button`,
          {
            type: `button`,
            "data-tracking-id": `file-view-mode-${t}`,
            onClick: (e) => i(e, t),
            "aria-pressed": a,
            className: S(
              `h-full px-2 transition-colors`,
              o && `rounded-l-md`,
              s && `rounded-r-md`,
              `focus-visible:outline focus-visible:outline-1 focus-visible:outline-offset-1 focus-visible:animate-focus-pulse motion-reduce:animate-none focus-visible:outline-border-brand`,
              a
                ? `bg-surface-button-tab-primary text-content-primary shadow-sm`
                : `text-content-secondary hover:text-content-primary`,
            ),
            children: n,
          },
          t,
        );
      }),
    });
  };
export {
  W as _,
  je as a,
  me as c,
  J as d,
  ce as f,
  H as g,
  ee as h,
  Pe as i,
  X as l,
  V as m,
  Re as n,
  he as o,
  K as p,
  Fe as r,
  Z as s,
  Be as t,
  Y as u,
  U as v,
  re as y,
};
