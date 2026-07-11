// Shared surface chrome (functional-runtime wave) — the pixel-certified GLOBAL RAIL every ported
// shell renders, moved VERBATIM out of serve-product-ui.mjs (which now imports it, as do the
// extracted surface modules). The rail is aligned ONCE and certified in every port's shell —
// treat this file as pixel-frozen: changes here move every certified surface at once.
import { bpIcon, AIP_GRADIENT_SVG_RAIL } from "../scripts/bp-icons.mjs";
import { escHtml } from "./kit.mjs";

const CX_ESC = escHtml; // local alias so the moved block stays byte-identical to its serve original

// ---- SHARED pixel-aligned GLOBAL RAIL (the reference Foundry-shell left chrome, reproduced to the
// measured spec: 230px · rgb(37,42,49) · items y61 @32px pitch · APPLICATIONS section y369 · active app
// row h36 with the extracted app-icon chip · bottom cluster AIP/Support/Account y794/826/858). Used by
// every shell-pixel-certified port (schema #41, approvals #42, …) so the rail is aligned ONCE.
function ioiGlobalRailHtml(active) {
  // Per-reference rail variant: each certified surface reproduces ITS reference capture's rail state
  // (badges / View-all / star / gradient AIP / account-chip style differ across captures). Defaults
  // keep the schema/approvals-certified rail untouched.
  const gi = (icon, label, opts = {}) => {
    const kbd = opts.kbd ? `<kbd class="og-gkbd">${opts.kbd.split("+").map((k) => `<span>${k.trim()}</span>`).join("<span>+</span>")}</kbd>` : "";
    const ico = icon === "@aip-grad" ? AIP_GRADIENT_SVG_RAIL : bpIcon(icon);
    const inner = `<span class="og-gico">${ico}${opts.badge ? '<span class="og-gbadge"></span>' : ""}</span><span class="og-glabel">${CX_ESC(label)}</span>${kbd}`;
    return opts.href ? `<a class="og-gitem${opts.ctx ? " ctx" : ""}" href="${opts.href}">${inner}</a>` : `<span class="og-gitem muted">${inner}</span>`;
  };
  return `<aside class="og-grail${active.railVariant ? " " + active.railVariant : ""}">
    <div class="og-gtop"><span class="og-gmark">◗</span><span class="og-gmenu">${bpIcon("menu-closed")}</span></div>
    ${gi("home", "Home", { href: "/ai" })}
    ${gi("search", "Search…", { kbd: "ctrl + J" })}
    ${gi("notifications", "Notifications", { badge: active.badges })}
    ${gi("whatsnew-gift", "What's New", { badge: active.badges })}
    <div class="og-gdiv"></div>
    ${gi("history", "Recent", {})}
    ${gi("folder-open", "Files", {})}
    ${gi("cubes", "Ontology", { href: "/__ioi/odk", ctx: active.hiliteNav === "Ontology" })}
    ${gi("layout-grid", "Applications", { href: "/__ioi/home" })}
    <div class="og-gsecrow"><span class="og-gsec">APPLICATIONS</span>${active.viewAll === false ? "" : `<a class="og-gviewall" href="/__ioi/home">View all</a>`}</div>
    <a class="og-gitem on" href="${active.href}"><span class="og-gappico" style="background-image:url('${active.iconUri}')"></span><span class="og-glabel og-strong">${CX_ESC(active.label)}</span>${active.star === false ? "" : `<span class="og-gstar">${bpIcon("star-empty")}</span>`}</a>
    <div class="og-gspacer"></div>
    ${gi(active.aipGradient ? "@aip-grad" : "aip-logo", "AIP Assist", { kbd: "ctrl + shift + U" })}
    ${gi("help", "Support", {})}
    <span class="og-gitem muted og-gaccount"><span class="og-gavatar${active.acctMuted ? " alt" : ""}">LJ</span><span class="og-glabel">Account</span></span>
  </aside>`;
}
const IOI_GRAIL_CSS = `
    .og-grail{flex:0 0 230px;width:230px;height:100vh;background:#252a31;color:#f6f7f9;display:flex;flex-direction:column;padding:0 12px 10px;overflow:hidden;font:14px/1.28581 Source-Sans-Pro,Helvetica,sans-serif}
    .og-gtop{height:61px;display:flex;align-items:center;justify-content:space-between;padding:0 19px 0 6px;flex:0 0 61px}
    .og-gmark{font-size:20px;color:#f6f7f9}
    .og-gmenu{display:inline-flex;color:#abb3bf}
    .og-gappico{width:24px;height:24px;flex:0 0 24px;margin:-4px -4px -4px -4px;border-radius:3px;background-color:rgba(102,158,255,.1);background-position:center;background-size:16px;background-repeat:no-repeat}
    .og-strong{font-weight:600}
    .og-gstar{display:inline-flex;color:#abb3bf;width:16px;flex:0 0 16px}
    .og-gitem{display:flex;align-items:center;gap:12px;height:32px;padding:0 8px 0 5px;border-radius:6px;color:#f6f7f9;font-size:14px;font-weight:400}
    .og-gitem:hover{background:#2f353d;color:#fff}.og-gitem.on{background:#2f353d;color:#fff;font-weight:600;height:36px}
    .og-gitem.muted{color:#f6f7f9;cursor:default}.og-gitem.muted:hover{background:transparent}
    .og-gico{display:inline-flex;align-items:center;justify-content:center;width:16px;height:16px;color:#abb3bf;flex:0 0 16px;position:relative}
    .og-gbadge{position:absolute;left:9px;top:-3px;width:8px;height:8px;background:#fbb360;border:1px solid #2f343c;border-radius:50%}
    .og-gavatar.alt{background:rgba(45,114,210,.2);color:#8abbff;border-radius:50%;margin-left:-2px;margin-right:-2px}
    .og-gitem.ctx{background:#2f353d;color:#fff;font-weight:600}.og-gitem.ctx .og-gico{color:#f6f7f9}
    .rv-pipe .og-gitem.on{background:#1c2127;margin:0 -12px;padding:0 20px 0 17px;border-radius:0}
    .rv-pipe .og-gkbd{gap:0;margin-right:-2px}
    .rv-pipe .og-gkbd span:nth-child(even){display:inline-flex;justify-content:center;width:16px;margin:0}
    .rv-pipe .og-gsecrow{padding-top:31.3px;padding-bottom:6.3px}
    .rv-pipe .og-gsec{letter-spacing:0}
    .og-gitem.on .og-gico{color:#f6f7f9}
    .og-glabel{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;flex:1 1 auto}
    .og-gkbd{display:inline-flex;align-items:center;gap:3px;font-size:14px;color:#abb3bf;font-family:inherit;margin-right:4px}
    .og-gdiv{height:21px}
    .og-gsecrow{display:flex;align-items:center;justify-content:space-between;padding:30px 8px 5px 5px}
    .og-gsec{font-size:12px;letter-spacing:.02em;color:#abb3bf;font-weight:600}
    .og-gviewall{font-size:14px;color:#abb3bf;font-weight:400}
    .og-gavatar{display:inline-flex;align-items:center;justify-content:center;width:20px;height:20px;margin-left:0;margin-right:-4px;border-radius:3px;background:#1e6ba1;color:#8abbff;font-size:12px;font-weight:600;flex:0 0 20px}
    .og-gspacer{flex:1 1 auto;min-height:14px}`;

export { ioiGlobalRailHtml, IOI_GRAIL_CSS };
