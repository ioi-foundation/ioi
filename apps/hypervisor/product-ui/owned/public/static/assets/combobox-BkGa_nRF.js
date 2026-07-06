import { a as e } from "./rolldown-runtime-CGYlQKCx.js";
import { n as t } from "./@mux-DLaEVubF.js";
import {
  Fh as n,
  Hp as r,
  Jp as i,
  Ld as a,
  Ml as o,
  Qp as s,
  Rd as c,
  Sh as l,
  Vd as u,
  Xm as d,
  Yg as f,
  Ym as p,
  Yp as ee,
  ch as te,
  cm as m,
  dh as h,
  ef as g,
  el as ne,
  fh as _,
  lh as re,
  sh as ie,
  v_ as v,
  xh as y,
  zd as ae,
} from "./vendor-DAwbZtf0.js";
import { a as oe } from "./button-6YP03Qf2.js";
import { t as b } from "./cn-DppMFCU8.js";
import { t as x } from "./text-fFCFeCas.js";
import { t as S } from "./checkbox-nHTWcF6W.js";
import { t as C } from "./error-message-Az-KJctk.js";
import { t as se } from "./use-scroll-end-Cl4hHgS9.js";
var w = e(t(), 1),
  ce = e(f(), 1),
  T = v(),
  le = `Combobox.Value`,
  E = `Combobox.List`,
  ue = `Combobox.Popover`,
  D = `Combobox.Loading`,
  O = `Combobox.Empty`,
  k = `Combobox.SearchBox`,
  A = `Combobox.ListItemLeadingIcon`,
  j = `Combobox.ListItemTitle`,
  M = `Combobox.ListItemDescription`,
  N = `Combobox.Error`,
  P = `Combobox.Footer`,
  F = `Combobox.MultiValue`,
  I = `Combobox.SelectAll`,
  L = [`ArrowDown`, `ArrowUp`, `Home`, `End`, `Enter`],
  de = (0, w.createContext)(null);
function R(e) {
  let t = (0, w.useContext)(de);
  if (!t) throw Error(`${e} must be used within a Combobox`);
  return t;
}
var z = (e) => e.type.displayName;
function fe(e) {
  if (z(e) === `Combobox.ListItem`) return e.props.value;
}
function pe(e) {
  return z(e) === `Combobox.ListItem` ? e.props.disabled === !0 : !1;
}
function me(e, t) {
  return e && t instanceof Set;
}
function he(e, t) {
  return e && typeof t == `function`;
}
function ge(e, t) {
  return !e && typeof t == `string`;
}
function _e(e, t) {
  return !e && typeof t == `function`;
}
function ve(e) {
  let t = {
    selectedValueSlot: null,
    listElement: null,
    popoverElement: null,
    loadingComponent: null,
    loadingLabel: null,
    emptyComponent: null,
    errorComponent: null,
    footerComponent: null,
  };
  return (
    w.Children.forEach(e, (e) => {
      if ((0, w.isValidElement)(e))
        switch (z(e)) {
          case le:
          case F:
            t.selectedValueSlot = e;
            break;
          case E:
            t.listElement = e;
            break;
          case D:
            ((t.loadingComponent = e), (t.loadingLabel = e.props.children || `Loading…`));
            break;
          case ue:
            ((t.popoverElement = e),
              w.Children.forEach(e.props.children, (e) => {
                if (!(0, w.isValidElement)(e)) return;
                let n = z(e);
                (n === E && (t.listElement = e), n === D && (t.loadingLabel = e.props.children || `Loading…`));
              }));
            break;
          case O:
            t.emptyComponent = e;
            break;
          case N:
            t.errorComponent = e;
            break;
          case P:
            t.footerComponent = e;
            break;
        }
    }),
    t
  );
}
var B = ({
    children: e,
    onOpenChange: t,
    filterPlaceholder: a = `Search`,
    loading: o = !1,
    disabled: f = !1,
    multiple: m = !1,
    defaultValue: h,
    value: g,
    onValueChange: _,
    className: re,
    "aria-label": ie,
  }) => {
    let v = (0, w.useMemo)(() => ({ filterAtom: u(``) }), []),
      y = ae(v.filterAtom),
      x = c(v.filterAtom),
      S = ve(e),
      {
        listElement: C,
        popoverElement: se,
        loadingComponent: ce,
        loadingLabel: le,
        emptyComponent: E,
        errorComponent: ue,
        footerComponent: D,
      } = S,
      O = S.selectedValueSlot ?? (0, T.jsx)(Ce, {}),
      k = C ? C.props : void 0,
      A = k?.children,
      j = (0, w.useMemo)(() => {
        let e = k?.items ?? [],
          t = k?.searchKeys ?? [],
          n = k?.disableFiltering ?? !1;
        return !x || n ? e : x.split(` `).reduceRight((e, n) => ne(e, n, { keys: t }), e);
      }, [x, k?.items, k?.searchKeys, k?.disableFiltering]),
      {
        itemKeys: M,
        renderedItems: N,
        disabledKeys: P,
      } = (0, w.useMemo)(() => {
        let e = [],
          t = new Map(),
          n = new Set();
        for (let r of j) {
          if (!A) continue;
          let i = A(r);
          if ((0, w.isValidElement)(i)) {
            let r = fe(i);
            r !== void 0 && (e.push(r), t.set(r, i), pe(i) && n.add(r));
          }
        }
        return { itemKeys: e, renderedItems: t, disabledKeys: n };
      }, [j, A]),
      F = (0, w.useMemo)(() => M.map((e) => (0, T.jsx)(te, { textValue: e, children: e }, e)), [M]),
      I = (0, w.useRef)(null),
      L = (0, w.useRef)(null),
      R = (0, w.useRef)(null),
      z = (0, w.useRef)(void 0),
      B = (0, w.useCallback)(
        (e) => {
          e || y(``);
          let n = I.current?.closest(`[role='dialog']`);
          (n &&
            (e
              ? ((z.current = n.style.overflow), (n.style.overflow = `visible`))
              : ((n.style.overflow = z.current ?? ``), (z.current = void 0))),
            t?.(e));
        },
        [t, y],
      ),
      ye = me(m, g) ? g : void 0,
      be = me(m, h) ? h : void 0,
      U = he(m, _) ? _ : void 0,
      W = i({ onOpenChange: B }),
      G = ee({
        children: F,
        selectionMode: `multiple`,
        selectedKeys: ye ?? new Set(),
        defaultSelectedKeys: be,
        disabledKeys: P,
        onSelectionChange: (e) => {
          U && U(e === `all` ? new Set(M) : new Set(Array.from(e).map(String)));
        },
      }),
      K = ge(m, g) ? g : void 0,
      q = ge(m, h) ? h : void 0,
      xe = _e(m, _) ? _ : void 0,
      J = r({
        children: F,
        selectedKey: K,
        defaultSelectedKey: q,
        disabledKeys: P,
        onSelectionChange: (e) => {
          (e != null && xe?.(String(e)), J.close());
        },
        onOpenChange: B,
      }),
      Se = m ? G : J,
      Y = m ? W.isOpen : J.isOpen,
      X = (0, w.useCallback)(() => {
        m ? W.open() : J.setOpen(!0);
      }, [m, W, J]),
      Q = (0, w.useCallback)(() => {
        m ? W.close() : J.setOpen(!1);
      }, [m, W, J]),
      $ = (0, w.useCallback)(() => {
        Y ? Q() : X();
      }, [Y, X, Q]),
      we = ie ?? a ?? (!m && typeof g == `string` ? g : void 0) ?? `Select an option`,
      Te = d({ "aria-label": we, isDisabled: o || f }, J, I),
      Ee = m
        ? { onPress: $, isDisabled: o || f, "aria-haspopup": `listbox`, "aria-expanded": Y, "aria-label": we }
        : {
            ...Object.fromEntries(
              Object.entries(Te.triggerProps).filter(([e]) => e !== `onPress` && e !== `onPressStart`),
            ),
            onPress: $,
          },
      De = m ? {} : Te.valueProps,
      Oe = m ? { "aria-label": we } : Te.menuProps,
      { buttonProps: ke } = l(Ee, I);
    n({
      ref: I,
      isDisabled: !Y,
      onInteractOutside: (e) => {
        L.current?.contains(e.target) || Q();
      },
    });
    let Ae;
    return (
      (Ae = se || (0, T.jsxs)(V, { children: [(0, T.jsx)(H, { placeholder: a }), ce, ue, E, C, D] })),
      (0, T.jsxs)(de.Provider, {
        value: {
          atoms: v,
          state: Se,
          triggerRef: I,
          popoverRef: L,
          listBoxRef: R,
          renderedItems: N,
          onOpenChange: (e) => (e ? X() : Q()),
          filterPlaceholder: a,
          valueProps: De,
          menuProps: Oe,
          multiple: m,
          itemKeys: M,
          disabledKeys: P,
          filterValue: x,
        },
        children: [
          !m && (0, T.jsx)(p, { state: J, triggerRef: I }),
          (0, T.jsxs)(`button`, {
            ...ke,
            ref: I,
            className: b(
              `flex h-9 min-w-40 items-center justify-between gap-2 rounded-lg border border-border-input-default bg-surface-input px-3`,
              `transition-all duration-150 ease-out`,
              `outline-none`,
              `focus:border-border-input-active focus:ring-1 focus:ring-border-brand focus:ring-offset-1`,
              `aria-expanded:border-border-input-active aria-expanded:ring-4 aria-expanded:ring-ring-default aria-expanded:ring-offset-0`,
              { "cursor-not-allowed opacity-50": o || f },
              re,
            ),
            children: [
              (0, T.jsx)(`span`, { className: `truncate`, children: o ? (0, T.jsx)(Z, { children: le }) : O }),
              o
                ? (0, T.jsx)(oe, { className: `animate-spin text-content-primary`, size: `sm` })
                : (0, T.jsx)(s, { size: 20, "aria-hidden": `true` }),
            ],
          }),
          Y && Ae,
        ],
      })
    );
  },
  V = ({ children: e, className: t, sameWidth: n = !0, flip: r = !0, placement: i = `bottom start` }) => {
    let a = R(`ComboboxPopover`),
      { overlayProps: o } = _({
        targetRef: a.triggerRef,
        overlayRef: a.popoverRef,
        placement: i,
        offset: 4,
        isOpen: !0,
        shouldFlip: r,
        shouldUpdatePosition: !0,
        onClose: null,
      }),
      s = a.triggerRef.current?.offsetWidth,
      c = !1;
    w.Children.forEach(e, (e) => {
      (0, w.isValidElement)(e) && z(e) === k && (c = !0);
    });
    let l = a.triggerRef.current?.closest(`[role='dialog']`) ?? document.body;
    return (0, ce.createPortal)(
      (0, T.jsx)(y, {
        restoreFocus: !0,
        children: (0, T.jsxs)(`div`, {
          ...o,
          ref: a.popoverRef,
          role: `presentation`,
          style: {
            ...o.style,
            "--popover-anchor-width": s == null ? void 0 : `${s}px`,
            ...(n && s ? { width: s } : {}),
          },
          className: b(
            `z-[999]`,
            `overflow-auto rounded-lg border border-border-base bg-surface-popover shadow`,
            `origin-top`,
            t,
          ),
          onMouseDown: (e) => {
            e.target.tagName !== `INPUT` && e.preventDefault();
          },
          children: [
            (0, T.jsx)(h, { onDismiss: () => a.onOpenChange(!1) }),
            !c && (0, T.jsx)(H, { placeholder: a.filterPlaceholder }),
            e,
            (0, T.jsx)(h, { onDismiss: () => a.onOpenChange(!1) }),
          ],
        }),
      }),
      l,
    );
  };
V.displayName = ue;
var H = ({ placeholder: e, onValueChanged: t, loading: n = !1, className: r }) => {
  let { atoms: i, listBoxRef: s, filterPlaceholder: c, onOpenChange: l } = R(`ComboboxSearchBox`),
    [d, f] = a(i.filterAtom),
    p = e ?? c,
    ee = (0, w.useCallback)((e) => {
      e?.focus({ preventScroll: !0 });
    }, []);
  return (
    a(
      (0, w.useMemo)(
        () =>
          t
            ? o((e) => {
                t(e(i.filterAtom));
              })
            : u(null),
        [i.filterAtom, t],
      ),
    ),
    (0, T.jsxs)(`div`, {
      className: `relative flex h-9 w-full items-center gap-2 border-b border-border-base px-2.5`,
      children: [
        (0, T.jsx)(g, { className: `-translate-y-[0.5px] text-content-muted`, size: 20 }),
        (0, T.jsx)(`input`, {
          ref: ee,
          type: `text`,
          value: d,
          onChange: (e) => f(e.target.value),
          onKeyDown: (e) => {
            if (e.key === `Escape`) {
              (e.stopPropagation(), l(!1));
              return;
            }
            if (L.includes(e.key)) {
              (e.key !== `Enter` && e.preventDefault(), e.stopPropagation());
              let t = s.current;
              if (!t) return;
              e.key === `Enter`
                ? (t.querySelector(`[data-active-item='true']`) ?? t).dispatchEvent(
                    new KeyboardEvent(e.nativeEvent.type, e.nativeEvent),
                  )
                : t.dispatchEvent(new KeyboardEvent(e.nativeEvent.type, e.nativeEvent));
            }
          },
          placeholder: p,
          className: b(
            `h-9 w-full max-w-full -translate-y-px bg-transparent py-3 text-base text-content-primary placeholder:translate-y-px placeholder:text-base placeholder:text-content-muted focus:outline-none focus:ring-0`,
            n ? `pr-8` : ``,
            r,
          ),
        }),
        (0, T.jsx)(`span`, {
          className: b(`absolute right-2.5 transition-opacity duration-150 ease-in`, n ? `opacity-100` : `opacity-0`),
          children: (0, T.jsx)(oe, { className: `animate-spin text-content-muted`, size: `sm` }),
        }),
      ],
    })
  );
};
H.displayName = k;
var ye = ({ node: e, renderedContent: t }) => {
  let { state: n, multiple: r } = R(`ComboboxOption`),
    i = (0, w.useRef)(null),
    {
      optionProps: a,
      isSelected: o,
      isFocused: s,
      isDisabled: c,
    } = ie({ key: e.key, shouldUseVirtualFocus: !0 }, n, i),
    l = null;
  return (
    (0, w.isValidElement)(t) && (l = be(t.props)),
    (0, T.jsx)(`li`, {
      ...a,
      ref: i,
      "data-active-item": s || void 0,
      className: b(
        `group/combobox-item flex cursor-pointer select-none items-center justify-between pb-1 text-base text-content-primary first:pt-0 last:pb-0 scroll-mt-1 last:scroll-mb-1`,
        c && `cursor-not-allowed opacity-50`,
      ),
      children: (0, T.jsxs)(`div`, {
        className: b(
          `flex w-full items-center justify-between gap-2 rounded px-2 py-1.5`,
          s && `bg-surface-hover`,
          `group-hover/combobox-item:bg-surface-hover`,
        ),
        children: [
          r &&
            (0, T.jsx)(S, { checked: o, className: `pointer-events-none flex-none`, tabIndex: -1, "aria-hidden": !0 }),
          (0, T.jsx)(`div`, { className: `min-w-0 flex-1`, children: l }),
          !r && o && (0, T.jsx)(`span`, { className: `flex-none`, children: (0, T.jsx)(m, { className: `size-4` }) }),
        ],
      }),
    })
  );
};
function be(e) {
  let { children: t, title: n } = e;
  if (t) {
    let e = null,
      n = null,
      r = null;
    return (
      w.Children.forEach(t, (t) => {
        if ((0, w.isValidElement)(t))
          switch (z(t)) {
            case A:
              t.props.children && (e = t);
              break;
            case j:
              n = t;
              break;
            case M:
              r = t;
              break;
          }
      }),
      n && r
        ? (0, T.jsxs)(`div`, {
            className: `flex items-center`,
            children: [e, (0, T.jsxs)(`div`, { className: `flex flex-col`, children: [n, r] })],
          })
        : e && n
          ? (0, T.jsxs)(`div`, {
              className: `flex min-w-0 items-center gap-1.5`,
              children: [e, (0, T.jsx)(`div`, { className: `min-w-0 flex-1`, children: n })],
            })
          : t
    );
  }
  return n && typeof n == `string` ? (0, T.jsx)(G, { children: n }) : null;
}
var U = ({ noMatchesComponent: e, onScrollEnd: t, scrollEndThreshold: n = 100, className: r }) => {
  let { state: i, renderedItems: a, menuProps: o, listBoxRef: s } = R(`ComboboxList`),
    c = (0, w.useRef)(null),
    { listBoxProps: l } = re({ ...o, autoFocus: `first`, shouldUseVirtualFocus: !0, shouldFocusOnHover: !0 }, i, c),
    { scrollContainerRef: u, onScroll: d } = se({ onScrollEnd: t, threshold: n }),
    f = [...i.collection],
    p = f.length === 0;
  return (0, T.jsx)(`ul`, {
    ...l,
    ref: (e) => {
      ((c.current = e), (s.current = e), (u.current = e));
    },
    className: b(`h-auto max-h-[320px] overflow-auto`, p ? `p-0` : `p-1`, r),
    onScroll: d,
    children: p ? e || null : f.map((e) => (0, T.jsx)(ye, { node: e, renderedContent: a.get(String(e.key)) }, e.key)),
  });
};
U.displayName = E;
var W = (e) => null;
W.displayName = `Combobox.ListItem`;
var G = ({ children: e, className: t, ...n }) =>
  (0, T.jsx)(x, { className: b(`truncate text-content-primary`, t), ...n, children: e });
G.displayName = j;
var K = ({ children: e, className: t, ...n }) =>
  (0, T.jsx)(x, { className: b(`text-sm text-content-secondary`, t), ...n, children: e });
K.displayName = M;
var q = ({ children: e, className: t, ...n }) =>
  e ? (0, T.jsx)(`span`, { className: b(`mr-2`, t), ...n, children: e }) : null;
q.displayName = A;
var xe = ({ children: e, className: t, ...n }) =>
  (0, T.jsx)(x, {
    className: b(`select-none px-3 py-2 text-base text-content-secondary`, t),
    ...n,
    children: e || `No options found`,
  });
xe.displayName = O;
var J = ({ error: e, className: t }) =>
  (0, T.jsx)(`div`, { className: b(`select-none px-3 py-2`, t), children: (0, T.jsx)(C, { error: e }) });
J.displayName = N;
var Se = ({ children: e, className: t, ...n }) =>
  (0, T.jsx)(x, {
    className: b(`select-none px-3 py-2 text-base text-content-secondary`, t),
    ...n,
    children: e || `Loading…`,
  });
Se.displayName = D;
var Ce = (e) => {
    let { state: t, multiple: n } = R(`ComboboxDefaultValue`);
    if (n) {
      let n = t.selectionManager.selectedKeys.size,
        r = n === 0 ? `None selected` : `${n} selected`;
      return (0, T.jsx)(Z, { ...e, children: r });
    }
    let r = `selectedKey` in t && t.selectedKey != null ? String(t.selectedKey) : ``;
    return (0, T.jsx)(Z, { ...e, children: r });
  },
  Y = ({ children: e, ...t }) => {
    let { state: n, multiple: r } = R(`ComboboxValue`);
    if (r)
      throw Error(
        "Combobox.Value cannot be used inside a Combobox with `multiple` set to true. Use Combobox.MultiValue instead.",
      );
    let i = `selectedKey` in n && n.selectedKey != null ? String(n.selectedKey) : ``;
    return e ? (typeof e == `function` ? e(i) : e) : (0, T.jsx)(Z, { ...t, children: i });
  };
Y.displayName = le;
var X = ({ children: e, ...t }) => {
  let { state: n, multiple: r } = R(`ComboboxMultiValue`);
  if (!r) throw Error("Combobox.MultiValue can only be used inside a Combobox with `multiple` set to true.");
  let i = n.selectionManager.selectedKeys,
    a = new Set(Array.from(i).map(String));
  if (!e) {
    let e = a.size,
      n = e === 0 ? `None selected` : `${e} selected`;
    return (0, T.jsx)(Z, { ...t, children: n });
  }
  return typeof e == `function` ? e(a) : e;
};
X.displayName = F;
var Z = ({ children: e, className: t, ...n }) =>
  (0, T.jsx)(`span`, { className: b(`truncate text-base text-content-primary`, t), ...n, children: e });
Z.displayName = `Combobox.ValueLabel`;
var Q = ({ children: e, className: t, ...n }) =>
  (0, T.jsx)(`div`, { className: b(`border-t border-border-base px-3 py-2`, t), ...n, children: e });
Q.displayName = P;
var $ = ({ className: e }) => {
  let { state: t, itemKeys: n, disabledKeys: r, filterValue: i } = R(`ComboboxSelectAll`),
    a = t.selectionManager.selectedKeys,
    o = (0, w.useMemo)(() => n.filter((e) => !r.has(e)), [n, r]),
    s = o.filter((e) => a.has(e)).length,
    c = o.length > 0 && s === o.length,
    l = c ? !0 : s === 0 ? !1 : `indeterminate`,
    u = i.length > 0,
    d = u ? `Select matches` : `Select all`,
    f = u ? `Deselect matches` : `Deselect all`,
    p = () => {
      if (c) {
        let e = new Set(a);
        for (let t of o) e.delete(t);
        t.selectionManager.setSelectedKeys(e);
      } else {
        let e = new Set(a);
        for (let t of o) e.add(t);
        t.selectionManager.setSelectedKeys(e);
      }
    };
  return (0, T.jsxs)(`label`, {
    className: b(`flex cursor-pointer items-center gap-2`, e),
    onClick: (e) => {
      (e.preventDefault(), p());
    },
    "data-tracking-id": `default-tracking-id`,
    children: [
      (0, T.jsx)(S, {
        checked: l,
        onKeyDown: (e) => {
          e.key === `Enter` && (e.preventDefault(), p());
        },
      }),
      (0, T.jsx)(`span`, { className: `text-base text-content-primary`, children: c ? f : d }),
    ],
  });
};
(($.displayName = I),
  (B.Popover = V),
  (B.List = U),
  (B.ListItem = W),
  (B.ListItemTitle = G),
  (B.ListItemDescription = K),
  (B.ListItemLeadingIcon = q),
  (B.Empty = xe),
  (B.Error = J),
  (B.Value = Y),
  (B.MultiValue = X),
  (B.ValueLabel = Z),
  (B.Loading = Se),
  (B.SearchBox = H),
  (B.Footer = Q),
  (B.SelectAll = $));
export { B as t };
