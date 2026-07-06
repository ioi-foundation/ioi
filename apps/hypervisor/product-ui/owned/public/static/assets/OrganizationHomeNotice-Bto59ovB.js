import { U as e, Vn as t } from "./SegmentProvider-CXCNBY9U.js";
import { v_ as n } from "./vendor-DAwbZtf0.js";
import { Yt as r } from "./use-boot-in-app-chat-t-J_VjKS.js";
var i = n(),
  a = ({ message: e, testId: n = `organization-home-notice` }) =>
    (0, i.jsx)(`div`, {
      "data-testid": n,
      className: `flex min-h-9 w-full shrink-0 items-center justify-center border-b border-border-subtle bg-surface-secondary px-4 py-2 text-sm`,
      children: (0, i.jsxs)(`div`, {
        className: `flex w-full flex-wrap items-center justify-center gap-x-2 gap-y-1 text-center`,
        children: [
          (0, i.jsx)(`span`, {
            className: `rounded-full bg-surface-muted px-2 py-0.5 text-xs font-medium text-content-secondary`,
            children: `Notice`,
          }),
          (0, i.jsx)(`span`, {
            className: `text-content-secondary`,
            children: (0, i.jsx)(t, { content: e, className: `text-inherit` }),
          }),
        ],
      }),
    }),
  o = () => {
    let { data: t, isLoading: n } = r(),
      o = e();
    return n || !t?.enabled || !t?.message || o ? null : (0, i.jsx)(a, { message: t.message });
  };
export { a as n, o as t };
