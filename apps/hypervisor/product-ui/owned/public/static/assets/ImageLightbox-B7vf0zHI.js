import { a as e } from "./rolldown-runtime-CGYlQKCx.js";
import { n as t } from "./@mux-DLaEVubF.js";
import { Cm as n, Sm as r, bm as i, v_ as a, vm as o, xm as s, ym as c } from "./vendor-DAwbZtf0.js";
import { t as l } from "./radix-body-pointer-events-DJX9Yyw0.js";
import { t as u } from "./IconChevronRight-DCrLr53u.js";
var d = e(t(), 1),
  f = a(),
  p = ({ images: e, currentIndex: t, onIndexChange: a, open: p, onOpenChange: m }) => {
    let h = l({ open: p, onOpenChange: m }),
      g = t > 0,
      _ = t < e.length - 1,
      v = (0, d.useCallback)(() => {
        g && a(t - 1);
      }, [g, t, a]),
      y = (0, d.useCallback)(() => {
        _ && a(t + 1);
      }, [_, t, a]);
    (0, d.useEffect)(() => {
      if (!p) return;
      let e = (e) => {
        e.key === `ArrowLeft` ? (e.preventDefault(), v()) : e.key === `ArrowRight` && (e.preventDefault(), y());
      };
      return (window.addEventListener(`keydown`, e), () => window.removeEventListener(`keydown`, e));
    }, [p, v, y]);
    let b = e[t];
    return b
      ? (0, f.jsx)(r, {
          open: p,
          onOpenChange: h,
          children: (0, f.jsxs)(s, {
            children: [
              (0, f.jsx)(i, {
                className: `fixed inset-0 z-50 bg-black/80 data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0`,
              }),
              (0, f.jsxs)(o, {
                className: `fixed inset-0 z-50 flex items-center justify-center p-8 focus:outline-none`,
                "aria-label": `Image preview`,
                "data-tracking-id": `image-lightbox-overlay`,
                onClick: () => m(!1),
                children: [
                  (0, f.jsxs)(`div`, {
                    className: `absolute left-0 right-0 top-0 z-10 flex items-center justify-between px-4 py-3`,
                    onClick: (e) => e.stopPropagation(),
                    children: [
                      (0, f.jsx)(n, {
                        className: `truncate text-sm font-medium text-white`,
                        children: b.alt || `Image`,
                      }),
                      e.length > 1 &&
                        (0, f.jsxs)(c, {
                          className: `shrink-0 text-sm text-white/70`,
                          children: [t + 1, ` of `, e.length],
                        }),
                      e.length <= 1 && (0, f.jsx)(c, { className: `sr-only`, children: `Image preview` }),
                    ],
                  }),
                  g &&
                    (0, f.jsx)(`button`, {
                      onClick: (e) => {
                        (e.stopPropagation(), v());
                      },
                      className: `absolute left-4 z-10 flex size-10 items-center justify-center rounded-full bg-surface-primary/80 text-content-primary shadow-md transition-colors hover:bg-surface-primary`,
                      "aria-label": `Previous image`,
                      "data-tracking-id": `image-lightbox-previous`,
                      children: (0, f.jsx)(u, { size: `base`, className: `rotate-180` }),
                    }),
                  (0, f.jsx)(`img`, {
                    src: b.src,
                    alt: b.alt,
                    className: `max-h-full max-w-full rounded-lg object-contain`,
                    "data-tracking-id": `image-lightbox-image`,
                    onClick: (e) => e.stopPropagation(),
                  }),
                  _ &&
                    (0, f.jsx)(`button`, {
                      onClick: (e) => {
                        (e.stopPropagation(), y());
                      },
                      className: `absolute right-4 z-10 flex size-10 items-center justify-center rounded-full bg-surface-primary/80 text-content-primary shadow-md transition-colors hover:bg-surface-primary`,
                      "aria-label": `Next image`,
                      "data-tracking-id": `image-lightbox-next`,
                      children: (0, f.jsx)(u, { size: `base` }),
                    }),
                ],
              }),
            ],
          }),
        })
      : null;
  };
export { p as t };
