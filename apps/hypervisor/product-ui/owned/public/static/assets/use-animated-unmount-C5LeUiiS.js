import { a as e } from "./rolldown-runtime-CGYlQKCx.js";
import { n as t } from "./@mux-DLaEVubF.js";
import { Pg as n } from "./vendor-DAwbZtf0.js";
var r = {
    all: `transform-gpu transition-all duration-200 ease-out`,
    transform: `transform-gpu transition-transform duration-200 ease-out`,
    opacity: `transform-gpu transition-opacity duration-200 ease-out`,
    fastOpacity: `transform-gpu transition-opacity duration-100 ease-out`,
    list: `transform-gpu transition-[height,opacity] duration-200 ease-out`,
  },
  i = r.all;
(r.list, r.fastOpacity);
var a = n(`flex flex-row items-center rounded-lg`, {
    variants: {
      design: { new: `h-8 min-w-0` },
      state: { active: `bg-surface-hover`, default: `hover:bg-surface-hover` },
    },
    defaultVariants: { design: `new`, state: `default` },
  }),
  o = n(`relative`, { variants: { design: { new: `h-8 w-8 shrink-0` } }, defaultVariants: { design: `new` } }),
  s = n(r.transform, {
    variants: { design: { new: `flex size-full items-center justify-center` } },
    defaultVariants: { design: `new` },
  }),
  c = n(`flex-grow text-start text-base`, {
    variants: {
      design: { new: [`min-w-0 overflow-hidden whitespace-nowrap`, r.opacity] },
      visibility: { hidden: `w-0 opacity-0`, visible: `opacity-100` },
    },
    defaultVariants: { design: `new`, visibility: `visible` },
  }),
  l = e(t(), 1),
  u = ({ duration: e, isHidden: t, onAnimationComplete: n }) => {
    let [r, i] = (0, l.useState)(!t),
      [a, o] = (0, l.useState)(!1),
      s = (0, l.useRef)(),
      c = (0, l.useRef)(n);
    c.current = n;
    let u = (0, l.useCallback)(() => {
      c.current?.();
    }, []);
    return (
      (0, l.useEffect)(
        () => (
          s.current && clearTimeout(s.current),
          o(!0),
          t
            ? (s.current = setTimeout(() => {
                (i(!1), o(!1), u());
              }, e))
            : (i(!0),
              (s.current = setTimeout(() => {
                (o(!1), u());
              }, e))),
          () => {
            s.current && clearTimeout(s.current);
          }
        ),
        [t, e, u],
      ),
      { shouldRender: r, isAnimating: a }
    );
  };
export { c as a, s as i, i as n, a as o, o as r, u as t };
