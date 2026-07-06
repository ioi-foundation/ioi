import { a as e } from "./rolldown-runtime-CGYlQKCx.js";
import { n as t } from "./@mux-DLaEVubF.js";
import { v_ as n } from "./vendor-DAwbZtf0.js";
import { Dt as r, tr as i } from "./use-boot-in-app-chat-t-J_VjKS.js";
import { n as a } from "./toast-axaLeIzZ.js";
import { t as o } from "./button-6YP03Qf2.js";
import { t as s } from "./dialog-BtjFqa-w.js";
import { t as c } from "./input-C42Z_4fO.js";
import { t as l } from "./label-5ATlPnPj.js";
import { S as u, h as d, p as f } from "./main-DLKYFe1Y.js";
import { t as p } from "./MemberSelectionList-CQO7HBhs.js";
var m = e(t(), 1),
  h = n(),
  g = ({ open: e, onClose: t, team: n }) => {
    let { toast: i } = a(),
      c = f(),
      [l, u] = (0, m.useState)(new Map()),
      [d, g] = (0, m.useState)(!1),
      _ = (0, m.useCallback)(async () => {
        if (l.size !== 0) {
          g(!0);
          try {
            let e = Array.from(l.values()),
              r = 0,
              a = [];
            for (let t of e)
              try {
                (await c.mutateAsync({ teamId: n.id, userId: t.id }), r++);
              } catch {
                a.push(t.id);
              }
            (a.length > 0
              ? i({
                  title: `Some members could not be added`,
                  description: `Added ${r} member${r === 1 ? `` : `s`} to "${n.name}", but ${a.length} failed.`,
                })
              : i({ title: `Members added`, description: `${r} member${r === 1 ? `` : `s`} added to "${n.name}".` }),
              u(new Map()),
              t());
          } finally {
            g(!1);
          }
        }
      }, [l, n.id, n.name, c, i, t]);
    return (0, h.jsx)(s, {
      open: e,
      onOpenChange: (0, m.useCallback)(
        (e) => {
          e || (u(new Map()), t());
        },
        [t],
      ),
      children: (0, h.jsxs)(s.Content, {
        "data-testid": `add-team-members-dialog`,
        "data-track-location": r.SettingsTeamAddMembers,
        className: `flex h-[35rem] max-h-[90vh] max-w-2xl flex-col overflow-hidden`,
        children: [
          (0, h.jsxs)(s.Header, {
            children: [
              (0, h.jsx)(s.Title, { children: `Add members` }),
              (0, h.jsxs)(s.Description, {
                children: [
                  `Add organization members to`,
                  ` `,
                  (0, h.jsx)(`span`, { className: `break-all font-medium text-content-primary`, children: n.name }),
                  `.`,
                ],
              }),
            ],
          }),
          (0, h.jsx)(s.Body, {
            className: `flex min-h-0 flex-1 flex-col space-y-4 overflow-hidden`,
            children: (0, h.jsx)(p, {
              excludeMembersInAnyTeam: !0,
              selectedSubjects: l,
              onChangeSelection: u,
              showSearch: !0,
              showServiceAccounts: !1,
              className: `flex min-h-0 flex-1 flex-col space-y-2`,
            }),
          }),
          (0, h.jsxs)(s.Footer, {
            children: [
              (0, h.jsx)(s.Close, {
                asChild: !0,
                children: (0, h.jsx)(o, {
                  variant: `outline`,
                  "data-testid": `add-team-members-dialog-cancel`,
                  children: `Cancel`,
                }),
              }),
              (0, h.jsx)(o, {
                onClick: _,
                variant: `primary`,
                disabled: l.size === 0 || d,
                loading: d,
                "data-testid": `add-team-members-dialog-add`,
                "data-tracking-id": `add-team-members-dialog-add`,
                children: `Add`,
              }),
            ],
          }),
        ],
      }),
    });
  },
  _ = ({ open: e, onClose: t, team: n }) =>
    (0, h.jsx)(s, {
      open: e,
      onOpenChange: (0, m.useCallback)(
        (e) => {
          e || t();
        },
        [t],
      ),
      children: (0, h.jsx)(s.Content, {
        "data-testid": `edit-team-dialog`,
        "data-track-location": r.SettingsTeamEdit,
        children: (0, h.jsx)(v, { team: n, onClose: t }),
      }),
    }),
  v = ({ team: e, onClose: t }) => {
    let { toast: n } = a(),
      r = u(),
      [d, f] = (0, m.useState)(e.name),
      p = (0, m.useCallback)(
        async (a) => {
          if ((a.preventDefault(), d.trim()))
            try {
              (await r.mutateAsync({ teamId: e.id, name: d.trim() }),
                n({ title: `Team updated`, description: `Team "${d}" has been updated successfully.` }),
                t());
            } catch (e) {
              n({ title: `Failed to update team`, description: i(e) });
            }
        },
        [d, e.id, r, n, t],
      ),
      g = d.trim().length >= 3 && d.trim().length <= 80,
      _ = d !== e.name;
    return (0, h.jsxs)(h.Fragment, {
      children: [
        (0, h.jsx)(s.Header, { children: (0, h.jsx)(s.Title, { children: `Edit team` }) }),
        (0, h.jsx)(s.Body, {
          children: (0, h.jsx)(`form`, {
            id: `edit-team-form`,
            onSubmit: p,
            className: `flex flex-col gap-4`,
            children: (0, h.jsxs)(`div`, {
              className: `flex flex-col gap-2`,
              children: [
                (0, h.jsx)(l, { htmlFor: `team-name`, className: `font-medium`, children: `Name` }),
                (0, h.jsx)(c, {
                  id: `team-name`,
                  "data-testid": `team-name-input`,
                  name: `teamName`,
                  value: d,
                  onChange: (e) => f(e.target.value),
                  placeholder: `Backend Team`,
                  autoFocus: !0,
                  required: !0,
                  minLength: 3,
                  maxLength: 80,
                }),
              ],
            }),
          }),
        }),
        (0, h.jsxs)(s.Footer, {
          children: [
            (0, h.jsx)(s.Close, {
              asChild: !0,
              children: (0, h.jsx)(o, {
                variant: `outline`,
                "data-testid": `edit-team-dialog-cancel`,
                children: `Cancel`,
              }),
            }),
            (0, h.jsx)(o, {
              type: `submit`,
              form: `edit-team-form`,
              variant: `primary`,
              disabled: !g || !_ || r.isPending,
              loading: r.isPending,
              "data-testid": `edit-team-dialog-save`,
              "data-tracking-id": `edit-team-dialog-save`,
              children: `Update`,
            }),
          ],
        }),
      ],
    });
  },
  y = ({ open: e, onOpenChange: t, team: n, onSuccess: c }) => {
    let { toast: l } = a(),
      u = d(),
      f = (0, m.useCallback)(async () => {
        try {
          (await u.mutateAsync(n.id),
            l({ title: `Team deleted`, description: `${n.name} has been deleted successfully.` }),
            t(!1),
            c?.());
        } catch (e) {
          l({ title: `Failed to delete team`, description: i(e) });
        }
      }, [u, n.id, n.name, l, t, c]);
    return (0, h.jsx)(s, {
      open: e,
      onOpenChange: t,
      children: (0, h.jsxs)(s.Content, {
        "data-track-location": r.SettingsTeamDelete,
        className: `max-w-[600px]`,
        children: [
          (0, h.jsxs)(s.Header, {
            children: [
              (0, h.jsx)(s.Title, { children: `Delete team` }),
              (0, h.jsxs)(s.Description, {
                children: [
                  (0, h.jsxs)(`span`, {
                    className: `mb-1 block`,
                    children: [
                      `Are you sure you want to delete`,
                      ` `,
                      (0, h.jsx)(`span`, { className: `break-all font-medium text-content-primary`, children: n.name }),
                      `?`,
                    ],
                  }),
                  (0, h.jsx)(`span`, { children: `This will permanently remove the team and all its memberships.` }),
                ],
              }),
            ],
          }),
          (0, h.jsxs)(s.Footer, {
            children: [
              (0, h.jsx)(s.Close, {
                asChild: !0,
                children: (0, h.jsx)(o, { variant: `outline`, disabled: u.isPending, children: `Cancel` }),
              }),
              (0, h.jsx)(o, {
                variant: `destructive`,
                onClick: f,
                loading: u.isPending,
                disabled: u.isPending,
                "data-tracking-id": `delete`,
                children: `Delete`,
              }),
            ],
          }),
        ],
      }),
    });
  };
export { _ as n, g as r, y as t };
