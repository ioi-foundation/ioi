import { Xh as e } from "./vendor-DAwbZtf0.js";
import { Bn as t, Dr as n, _r as r, hr as i, vn as a } from "./use-boot-in-app-chat-t-J_VjKS.js";
import { t as o } from "./group-queries-DjQDBYRu.js";
function s(e, t) {
  return `${e}:${t}`;
}
function c(e) {
  let t = e.indexOf(`:`);
  return { resourceType: Number(e.slice(0, t)), resourceId: e.slice(t + 1) };
}
var l = (e) =>
    t(async (t) => {
      let n = new Map(),
        i = t.map(c),
        a = [...new Set(i.map((e) => e.resourceId))],
        o = [...new Set(i.map((e) => e.resourceType))],
        l = await r(
          (t) => e.groupService.listRoleAssignments({ ...t, filter: { resourceIds: a, resourceTypes: o } }),
          {},
          (e) => e.assignments,
          100,
        );
      for (let e of l) {
        let t = s(e.resourceType, e.resourceId),
          r = n.get(t);
        (r || ((r = []), n.set(t, r)), r.push(e));
      }
      for (let e of t) n.has(e) || n.set(e, []);
      return n;
    }, 25),
  u = null,
  d = (e, t) => (
    (!u || u.organizationId !== t || u.api !== e) && (u = { loader: l(e), organizationId: t, api: e }),
    u.loader
  ),
  f = (e, t) => i([`groups`, `roleAssignments`, `byResource`, s(e, t)]);
function p(t, r) {
  let i = n(),
    { data: c } = a(),
    l = c?.id ? d(i, c.id) : void 0,
    u = s(t, r),
    { data: p, isLoading: m } = e({ queryKey: f(t, r), queryFn: () => l.load(u), enabled: !!l && !!r, staleTime: o });
  return { data: p ?? void 0, isLoading: m };
}
export { p as t };
