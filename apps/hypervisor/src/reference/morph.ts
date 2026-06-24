// Minimal DOM morph (no dependency) used to navigate between verbatim captures the way
// a real SPA does: instead of remounting the whole page (which flashes the sidebar and
// resets state), we update the live DOM in place toward the target capture. Nodes that
// are unchanged — the sidebar, persistent chrome — keep their identity; only what differs
// (the content pane, the active-nav highlight) is touched. This restores the persistent-
// shell feel without modelling each layout explicitly.

function syncAttributes(from: Element, to: Element) {
  for (const a of Array.from(from.attributes)) {
    if (!to.hasAttribute(a.name)) from.removeAttribute(a.name);
  }
  for (const a of Array.from(to.attributes)) {
    if (from.getAttribute(a.name) !== a.value) from.setAttribute(a.name, a.value);
  }
}

function morphNode(from: Node, to: Node) {
  if (from.nodeType !== to.nodeType || from.nodeName !== to.nodeName) {
    from.parentNode?.replaceChild(to.cloneNode(true), from);
    return;
  }
  if (from.nodeType === Node.TEXT_NODE || from.nodeType === Node.COMMENT_NODE) {
    if (from.textContent !== to.textContent) from.textContent = to.textContent;
    return;
  }
  if (from.nodeType === Node.ELEMENT_NODE) {
    syncAttributes(from as Element, to as Element);
    morphChildren(from as Element, to as Element);
  }
}

function morphChildren(from: Element, to: Element) {
  const fromNodes = Array.from(from.childNodes);
  const toNodes = Array.from(to.childNodes);
  const max = Math.max(fromNodes.length, toNodes.length);
  for (let i = 0; i < max; i++) {
    const f = fromNodes[i];
    const t = toNodes[i];
    if (!t) {
      f.parentNode?.removeChild(f);
      continue;
    }
    if (!f) {
      from.appendChild(t.cloneNode(true));
      continue;
    }
    morphNode(f, t);
  }
}

/** Morph `root`'s children toward the parsed `html`, preserving unchanged nodes. */
export function morphInto(root: HTMLElement, html: string) {
  const target = document.createElement("div");
  target.innerHTML = html;
  morphChildren(root, target);
}
