import { a as e } from "./rolldown-runtime-CGYlQKCx.js";
import { n as t } from "./@mux-DLaEVubF.js";
import { v_ as n } from "./vendor-DAwbZtf0.js";
import { t as r } from "./Pill-99RRpZf2.js";
import "./pill-AA_qJIlm.js";
var i = e(t(), 1),
  a = n(),
  o = ({ phase: e }) => {
    let t = (0, i.useMemo)(() => {
      switch (e) {
        case `unspecified`:
          return { label: `Unspecified`, variant: `neutral` };
        case `stopped`:
          return { label: `Stopped`, variant: `neutral` };
        case `deleted`:
          return { label: `Deleted`, variant: `neutral` };
        case `stopping`:
          return { label: `Stopping`, variant: `warning` };
        case `starting`:
          return { label: `Starting`, variant: `warning` };
        case `running`:
          return { label: `Running`, variant: `success` };
        case `failed`:
          return { label: `Failed`, variant: `danger` };
        case `succeeded`:
          return { label: `Succeeded`, variant: `success` };
      }
    }, [e]);
    return t ? (0, a.jsx)(r, { size: `sm`, variant: t.variant, children: t.label }) : null;
  };
export { o as t };
