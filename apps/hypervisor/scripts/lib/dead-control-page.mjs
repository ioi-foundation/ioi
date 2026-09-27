// The page side of the dead-control censuses (check:dead-controls, check:adopted-dead-controls): functions
// that run IN THE BROWSER. Kept apart from dead-control-census.mjs, whose classifier must reach no browser,
// file, clock or network (so it can judge a census somebody else captured).
// Runs IN THE BROWSER: raw facts about every element that could be a control. The classifier —
// not this function — decides which of them are.
export const ENUMERATE = () => {
  const ROLES = ["button", "link", "tab", "menuitem", "menuitemcheckbox", "menuitemradio", "checkbox", "switch", "option", "radio", "treeitem", "combobox"];
  const CONTROL = 'a[href],button,[role=button],[role=link],[role=tab],[role=menuitem],summary';
  const cssPath = (el) => {
    const parts = [];
    for (let n = el; n && n.nodeType === 1 && n !== document.documentElement; n = n.parentElement) {
      if (n.id && document.querySelectorAll(`#${CSS.escape(n.id)}`).length === 1) { parts.unshift(`#${CSS.escape(n.id)}`); break; }
      const sib = [...n.parentElement.children].filter((c) => c.tagName === n.tagName);
      parts.unshift(`${n.tagName.toLowerCase()}${sib.length > 1 ? `:nth-of-type(${sib.indexOf(n) + 1})` : ""}`);
    }
    return parts.join(" > ");
  };
  const out = [];
  for (const el of document.querySelectorAll("body *")) {
    const role = el.getAttribute("role");
    const cs = getComputedStyle(el);
    const maybe = el.matches("a,button,input,select,textarea,summary,[onclick],[contenteditable]") || (role && ROLES.includes(role)) || cs.cursor === "pointer";
    if (!maybe) continue;
    const r = el.getBoundingClientRect();
    const form = el.form || el.closest("form");
    const submit = form ? [...form.querySelectorAll('button:not([type]),button[type=submit],input[type=submit]')].find((b) => !b.disabled) : null;
    const href = el.getAttribute("href");
    out.push({
      css: cssPath(el), tag: el.tagName, type: el.tagName === "INPUT" ? (el.getAttribute("type") || "") : null, role, href,
      visible: r.width > 1 && r.height > 1 && cs.visibility !== "hidden" && cs.display !== "none" && Number(cs.opacity) > 0.05,
      declared: !!el.closest('[aria-disabled="true"],[disabled],[inert]'),
      onclick: el.hasAttribute("onclick"), contentEditable: el.getAttribute("contenteditable") === "true",
      cursor: cs.cursor, parentCursor: el.parentElement ? getComputedStyle(el.parentElement).cursor : "auto",
      nestedInControl: !!el.parentElement?.closest(CONTROL),
      formCanSubmit: !!submit,
      readOnly: el.readOnly === true,
      // the words around a control that has none of its own (a facet checkbox's row: "Function 0")
      contextText: (el.parentElement?.parentElement?.innerText || "").trim().replace(/\s+/gu, " ").slice(0, 40),
      fragmentTargetExists: href && href.startsWith("#") && href.length > 1 ? !!document.getElementById(decodeURIComponent(href.slice(1))) : null,
      inMenu: !!el.closest('[role="menu"]'), targetBlank: el.getAttribute("target") === "_blank",
      current: el.getAttribute("aria-current") === "page" || el.getAttribute("aria-selected") === "true" || (el.getAttribute("role") === "tab" && el.getAttribute("data-state") === "active"),
      selfLink: !!href && !href.startsWith("#") && (() => { try { const u = new URL(href, location.href); return u.origin === location.origin && u.pathname === location.pathname && u.search === location.search; } catch { return false; } })(),
      text: (el.innerText || el.getAttribute("aria-label") || el.getAttribute("title") || el.getAttribute("placeholder") || "").trim().replace(/\s+/gu, " ").slice(0, 50),
      cls: String(el.className?.baseVal ?? el.className ?? "").slice(0, 60),
    });
  }
  return out;
};
