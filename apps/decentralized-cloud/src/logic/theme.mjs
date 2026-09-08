// THE THEME — light, dark, or the system's, this browser only.
//
// A console people leave open at night wants a dark theme, and the token file already
// has the onyx steps. The choice is kept in localStorage under one key and applied as
// `data-theme` on the document element; absent, the stylesheet follows
// prefers-color-scheme. It is a preference of this browser and nothing else: it is
// never sent anywhere and it changes no meaning — green is still live evidence, red is
// still expired or failed, on either ground.
const KEY = "dc.theme";
export const THEMES = ["system", "light", "dark"];

const storage = () => {
  try { return typeof localStorage === "undefined" ? null : localStorage; } catch { return null; }
};

export const readTheme = () => {
  const s = storage();
  const v = s ? s.getItem(KEY) : null;
  return THEMES.includes(v) ? v : "system";
};

export const applyTheme = (theme) => {
  if (typeof document === "undefined") return;
  const root = document.documentElement;
  if (theme === "light" || theme === "dark") root.setAttribute("data-theme", theme);
  else root.removeAttribute("data-theme");
};

export const saveTheme = (theme) => {
  const s = storage();
  if (!s) return;
  try {
    if (theme === "system") s.removeItem(KEY);
    else s.setItem(KEY, theme);
  } catch { /* a preference that cannot be kept is still applied for this page */ }
};

// What the page is actually showing, resolving "system" through the media query.
export const effectiveTheme = (theme) => {
  if (theme === "light" || theme === "dark") return theme;
  if (typeof window === "undefined" || !window.matchMedia) return "light";
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
};

export const nextTheme = (theme) => {
  // Cycle: system → dark → light → system, so one press from the default gives the
  // thing most people press it for.
  const order = ["system", "dark", "light"];
  return order[(order.indexOf(theme) + 1) % order.length];
};
