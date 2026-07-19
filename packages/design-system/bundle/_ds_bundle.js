const React = window.React;
/* @ds-bundle: {"format":3,"namespace":"IoiDesignSystem","components":[{"name":"Button","sourcePath":"components/actions/Button.jsx"},{"name":"TextLink","sourcePath":"components/actions/TextLink.jsx"},{"name":"Logo","sourcePath":"components/brand/Logo.jsx"},{"name":"Wordmark","sourcePath":"components/brand/Wordmark.jsx"},{"name":"ByIOI","sourcePath":"components/brand/Wordmark.jsx"},{"name":"Badge","sourcePath":"components/content/Badge.jsx"},{"name":"Card","sourcePath":"components/content/Card.jsx"},{"name":"Eyebrow","sourcePath":"components/content/Eyebrow.jsx"},{"name":"Stat","sourcePath":"components/content/Stat.jsx"},{"name":"Input","sourcePath":"components/forms/Input.jsx"}],"sourceHashes":{"components/actions/Button.jsx":"a8a80badf47a","components/actions/TextLink.jsx":"d910ff1720c7","components/brand/Logo.jsx":"8dadb13a568a","components/brand/Wordmark.jsx":"ae6be788a70e","components/content/Badge.jsx":"941b8942b138","components/content/Card.jsx":"c23b56b15149","components/content/Eyebrow.jsx":"eecd1cc9c67e","components/content/Stat.jsx":"5502ab3d9ada","components/forms/Input.jsx":"af051b52cca5","site/AutomationsFleets.jsx":"ed21581763e9","site/BackgroundWork.jsx":"eb3c89e61c5d","site/Chrome.jsx":"1e5bbe943e31","site/CodeModernization.jsx":"f87c48ded280","site/CodeReview.jsx":"545c0a4b9fd8","site/Developers.jsx":"2a3585c5c43e","site/Docs.jsx":"ee5e7e737b0c","site/HomeSections.jsx":"ea0fb57fa54f","site/HvDepthField.jsx":"5525da9fe9df","site/HvDiagrams.jsx":"f602cbe1888a","site/HvDots.jsx":"3ccf7b862a19","site/HvOcta.jsx":"ab6db8e62f51","site/Platform.jsx":"3454b4de9eb3","site/PlatformApp.jsx":"f868f039c4f3","site/Pricing.jsx":"95f903c6d7d4","site/ProductData.jsx":"e091683a5ee1","site/ProductPage.jsx":"913150b73f87","site/RevealDiagram.jsx":"b2e97247e7d5","site/RuntimeSecurity.jsx":"e6026e0a8a42","site/Solutions.jsx":"7050c6794cd4","site/WorkerTraining.jsx":"0353ca8d3b7c","site/WorkersMotion.jsx":"dd42a6701587","site/tweaks-panel.jsx":"6591467622ed","ui_kits/website/BlogScreen.jsx":"74e661d40655","ui_kits/website/DotMatrix.jsx":"5affd8c0ba9d","ui_kits/website/HomeScreen.jsx":"02dff1da81f9","ui_kits/website/PricingScreen.jsx":"9e7cb0a96c51","ui_kits/website/SiteChrome.jsx":"7b0e44ce5305"},"inlinedExternals":[],"unexposedExports":[]} */

(() => {

const __ds_ns = (window.IoiDesignSystem = window.IoiDesignSystem || {});

const __ds_scope = {};

(__ds_ns.__errors = __ds_ns.__errors || []);

// components/actions/Button.jsx
try { (() => {
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
/**
 * IOI Button — pill-ish rounded button used across marketing and product.
 * Solid onyx for primary, light grey for secondary, outline for tertiary.
 */
function Button({
  children,
  variant = "fill",
  // "fill" | "outline"
  theme = "onyx",
  // "onyx" | "grey" | "white"
  size = "md",
  // "sm" | "md"
  href,
  iconRight,
  disabled = false,
  onClick,
  style,
  ...rest
}) {
  const pad = size === "sm" ? "0.5rem 0.75rem" : "0.6875rem 0.875rem";
  const fontSize = size === "sm" ? "0.875rem" : "1rem";
  const themes = {
    onyx: {
      bg: "var(--color-onyx-black)",
      fg: "var(--color-white)",
      bd: "var(--color-onyx-black)"
    },
    grey: {
      bg: "var(--color-grey-400)",
      fg: "var(--color-onyx-black)",
      bd: "var(--color-grey-400)"
    },
    white: {
      bg: "var(--color-white)",
      fg: "var(--color-onyx-black)",
      bd: "var(--color-grey-500)"
    }
  };
  const t = themes[theme] || themes.onyx;
  const base = {
    display: "inline-flex",
    alignItems: "center",
    justifyContent: "center",
    gap: "0.5rem",
    fontFamily: "var(--font-sans)",
    fontSize,
    lineHeight: 1,
    fontWeight: 400,
    padding: pad,
    borderRadius: "var(--radius-lg)",
    border: "1px solid",
    cursor: disabled ? "not-allowed" : "pointer",
    textDecoration: "none",
    whiteSpace: "nowrap",
    transition: "background var(--dur) var(--ease-out), border-color var(--dur) var(--ease-out), opacity var(--dur)",
    opacity: disabled ? 0.45 : 1,
    ...(variant === "outline" ? {
      background: "transparent",
      color: theme === "onyx" ? "var(--color-onyx-black)" : t.fg,
      borderColor: theme === "onyx" ? "var(--color-onyx-black)" : t.bd
    } : {
      background: t.bg,
      color: t.fg,
      borderColor: t.bd
    }),
    ...style
  };
  const content = /*#__PURE__*/React.createElement(React.Fragment, null, children, iconRight && /*#__PURE__*/React.createElement("span", {
    "aria-hidden": "true",
    style: {
      transition: "transform var(--dur-fast) var(--ease-out)"
    }
  }, iconRight));
  if (href && !disabled) return /*#__PURE__*/React.createElement("a", _extends({
    href: href,
    style: base,
    onClick: onClick
  }, rest), content);
  return /*#__PURE__*/React.createElement("button", _extends({
    type: "button",
    style: base,
    disabled: disabled,
    onClick: onClick
  }, rest), content);
}
Object.assign(__ds_scope, { Button });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/actions/Button.jsx", error: String((e && e.message) || e) }); }

// components/actions/TextLink.jsx
try { (() => {
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
/**
 * IOI TextLink — inline green link with an optional sliding arrow.
 * Used for "See how agents work →" style affordances.
 */
function TextLink({
  children,
  href = "#",
  arrow = true,
  size = "md",
  style,
  ...rest
}) {
  const fontSize = size === "sm" ? "0.9375rem" : "1.0625rem";
  return /*#__PURE__*/React.createElement("a", _extends({
    href: href,
    style: {
      display: "inline-flex",
      alignItems: "center",
      gap: "0.375rem",
      fontFamily: "var(--font-sans)",
      fontSize,
      lineHeight: 0.98,
      letterSpacing: "-0.011em",
      color: "var(--color-link-green)",
      textDecoration: "none",
      width: "fit-content",
      transition: "opacity var(--dur) var(--ease-out)",
      ...style
    }
  }, rest), children, arrow && /*#__PURE__*/React.createElement("span", {
    "aria-hidden": "true"
  }, "\u2192"));
}
Object.assign(__ds_scope, { TextLink });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/actions/TextLink.jsx", error: String((e && e.message) || e) }); }

// components/brand/Logo.jsx
try { (() => {
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
const PATHS = ["M295.299 434.631L295.299 654.116 485.379 544.373z", "M500 535.931L697.39 421.968 500 308.005 302.61 421.968z", "M514.621 544.373L704.701 654.115 704.701 434.631z", "M280.678 662.557L280.678 425.086 123.957 695.903 145.513 740.594z", "M719.322 662.557L854.487 740.594 876.043 695.903 719.322 425.085z", "M287.988 675.22L151.883 753.8 164.878 780.741 470.757 780.741 287.988 675.22z", "M712.012 675.219L529.242 780.741 835.122 780.741 848.117 753.8 712.012 675.219z", "M492.689 295.343L492.689 104.779 466.038 104.779 287.055 414.066z", "M507.31 295.342L712.945 414.066 533.962 104.779 507.31 104.779z", "M302.61 666.778L500 780.741 500 552.815z", "M500 552.815L500 780.741 697.39 666.778z"];

/**
 * ioi mark — the outline octahedron. Strokes in currentColor, so it takes the
 * inherited text color (dark on light surfaces, white on dark).
 */
function Logo({
  size = 24,
  title = "ioi",
  style,
  ...rest
}) {
  return /*#__PURE__*/React.createElement("svg", _extends({
    xmlns: "http://www.w3.org/2000/svg",
    viewBox: "108.97 89.47 781.56 706.06",
    fill: "none",
    width: size,
    height: size,
    role: "img",
    "aria-label": title,
    style: style
  }, rest), /*#__PURE__*/React.createElement("g", {
    stroke: "currentColor",
    strokeWidth: "12",
    strokeLinejoin: "round",
    strokeLinecap: "round"
  }, PATHS.map((d, i) => /*#__PURE__*/React.createElement("path", {
    key: i,
    d: d
  }))));
}
Object.assign(__ds_scope, { Logo });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/brand/Logo.jsx", error: String((e && e.message) || e) }); }

// components/brand/Wordmark.jsx
try { (() => {
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
/**
 * Brand lockup for the "Hypervisor" product wordmark, set in the IOI display
 * face. By default the wordmark stands alone (`mark={false}`); pass `mark` to
 * prepend the outline ioi octahedron. Sizes follow `height`. Uses currentColor.
 */
function Wordmark({
  height = 24,
  label = "Hypervisor",
  mark = false,
  style,
  ...rest
}) {
  return /*#__PURE__*/React.createElement("span", _extends({
    style: {
      display: "inline-flex",
      alignItems: "center",
      gap: height * 0.38,
      color: "currentColor",
      ...style
    }
  }, rest), mark ? /*#__PURE__*/React.createElement(__ds_scope.Logo, {
    size: height
  }) : null, /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: 'var(--font-brand, "IOI Display"), var(--font-sans)',
      fontSize: height * 0.92,
      lineHeight: 1,
      letterSpacing: "0.01em",
      whiteSpace: "nowrap"
    }
  }, label));
}

/**
 * Endorsement signature — small "◇ By IOI" lockup that marks Hypervisor as an
 * IOI product. The octahedron mark sits at cap-height of the label; muted by
 * default so it reads as a signature, not a competing logo.
 */
function ByIOI({
  height = 13,
  style,
  ...rest
}) {
  return /*#__PURE__*/React.createElement("span", _extends({
    style: {
      display: "inline-flex",
      alignItems: "center",
      gap: height * 0.5,
      color: "var(--color-grey-700)",
      fontFamily: "var(--font-sans)",
      fontSize: height,
      lineHeight: 1,
      letterSpacing: "0.01em",
      whiteSpace: "nowrap",
      ...style
    }
  }, rest), /*#__PURE__*/React.createElement("span", {
    style: {
      opacity: 0.85
    }
  }, "By"), /*#__PURE__*/React.createElement(__ds_scope.Logo, {
    size: height * 1.15,
    title: "IOI"
  }), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: 'var(--font-brand, "IOI Display"), var(--font-sans)',
      fontWeight: 500,
      letterSpacing: "0.02em"
    }
  }, "IOI"));
}
Object.assign(__ds_scope, { Wordmark, ByIOI });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/brand/Wordmark.jsx", error: String((e && e.message) || e) }); }

// components/content/Badge.jsx
try { (() => {
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
/**
 * IOI Badge / pill — small rounded label.
 * "soft" = grey-400 chip ("Since 2025"); "green" = pistachio status; "solid" = onyx.
 */
function Badge({
  children,
  tone = "soft",
  style,
  ...rest
}) {
  const tones = {
    soft: {
      bg: "var(--color-grey-400)",
      fg: "var(--color-grey-900)",
      bd: "transparent"
    },
    green: {
      bg: "var(--color-pistachio-green)",
      fg: "var(--color-moss-green)",
      bd: "transparent"
    },
    solid: {
      bg: "var(--color-onyx-black)",
      fg: "var(--color-white)",
      bd: "transparent"
    },
    outline: {
      bg: "transparent",
      fg: "var(--color-grey-800)",
      bd: "var(--color-grey-500)"
    }
  };
  const t = tones[tone] || tones.soft;
  return /*#__PURE__*/React.createElement("span", _extends({
    style: {
      display: "inline-flex",
      alignItems: "center",
      gap: "0.375rem",
      fontFamily: "var(--font-mono)",
      fontSize: "var(--text-micro)",
      letterSpacing: "0.01em",
      lineHeight: 1,
      padding: "0.375rem 0.625rem",
      borderRadius: "var(--radius-md)",
      background: t.bg,
      color: t.fg,
      border: `1px solid ${t.bd}`,
      whiteSpace: "nowrap",
      ...style
    }
  }, rest), children);
}
Object.assign(__ds_scope, { Badge });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/content/Badge.jsx", error: String((e && e.message) || e) }); }

// components/content/Card.jsx
try { (() => {
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
/**
 * IOI Card — white surface, signature hairline border + 20px radius.
 * "subtle" tints to porcelain; "inverse" flips to onyx for dark feature blocks.
 */
function Card({
  children,
  tone = "default",
  padding = "1.5rem",
  radius = "var(--radius-card)",
  style,
  ...rest
}) {
  const tones = {
    default: {
      bg: "var(--color-white)",
      fg: "var(--color-onyx-black)",
      bd: "var(--color-grey-500)"
    },
    subtle: {
      bg: "var(--color-porcelain-grey)",
      fg: "var(--color-onyx-black)",
      bd: "var(--color-grey-500)"
    },
    inverse: {
      bg: "var(--color-onyx-black)",
      fg: "var(--color-white)",
      bd: "rgba(255,255,255,0.12)"
    }
  };
  const t = tones[tone] || tones.default;
  return /*#__PURE__*/React.createElement("div", _extends({
    style: {
      background: t.bg,
      color: t.fg,
      border: `0.5px solid ${t.bd}`,
      borderRadius: radius,
      padding,
      ...style
    }
  }, rest), children);
}
Object.assign(__ds_scope, { Card });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/content/Card.jsx", error: String((e && e.message) || e) }); }

// components/content/Eyebrow.jsx
try { (() => {
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
/** IOI Eyebrow — mono, uppercase, tracked-out section label. */
function Eyebrow({
  children,
  color = "var(--color-grey-700)",
  style,
  ...rest
}) {
  return /*#__PURE__*/React.createElement("div", _extends({
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: "var(--text-micro)",
      textTransform: "uppercase",
      letterSpacing: "0.08em",
      color,
      ...style
    }
  }, rest), children);
}
Object.assign(__ds_scope, { Eyebrow });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/content/Eyebrow.jsx", error: String((e && e.message) || e) }); }

// components/content/Stat.jsx
try { (() => {
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
/**
 * IOI Stat — oversized serif metric over a muted label.
 * Used in proof strips: "4x productivity increase", "83% of PRs co-authored".
 */
function Stat({
  value,
  label,
  style,
  ...rest
}) {
  return /*#__PURE__*/React.createElement("div", _extends({
    style: {
      display: "flex",
      flexDirection: "column",
      gap: "0.5rem",
      ...style
    }
  }, rest), /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "var(--text-3xl)",
      lineHeight: 1,
      letterSpacing: "-0.02em",
      color: "var(--color-onyx-black)"
    }
  }, value), /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "var(--text-base)",
      color: "var(--color-grey-800)",
      maxWidth: "18ch"
    }
  }, label));
}
Object.assign(__ds_scope, { Stat });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/content/Stat.jsx", error: String((e && e.message) || e) }); }

// components/forms/Input.jsx
try { (() => {
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
/**
 * IOI Input — calm text field, hairline border, grey-400 focus surface.
 * Optional label and trailing slot (e.g. an inline button).
 */
function Input({
  label,
  hint,
  type = "text",
  trailing,
  style,
  id,
  ...rest
}) {
  const inputId = id || (label ? `in-${label.replace(/\s+/g, "-").toLowerCase()}` : undefined);
  return /*#__PURE__*/React.createElement("label", {
    htmlFor: inputId,
    style: {
      display: "flex",
      flexDirection: "column",
      gap: "0.5rem",
      fontFamily: "var(--font-sans)"
    }
  }, label && /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: "var(--text-sm)",
      color: "var(--color-grey-900)"
    }
  }, label), /*#__PURE__*/React.createElement("span", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: "0.5rem",
      background: "var(--color-white)",
      border: "1px solid var(--color-grey-500)",
      borderRadius: "var(--radius-lg)",
      padding: "0.625rem 0.75rem",
      transition: "border-color var(--dur) var(--ease-out)"
    }
  }, /*#__PURE__*/React.createElement("input", _extends({
    id: inputId,
    type: type,
    style: {
      flex: 1,
      minWidth: 0,
      border: "none",
      outline: "none",
      background: "transparent",
      fontFamily: "var(--font-sans)",
      fontSize: "var(--text-base)",
      color: "var(--color-onyx-black)",
      ...style
    }
  }, rest)), trailing), hint && /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: "var(--text-xs)",
      color: "var(--color-grey-700)"
    }
  }, hint));
}
Object.assign(__ds_scope, { Input });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/forms/Input.jsx", error: String((e && e.message) || e) }); }

// site/AutomationsFleets.jsx
try { (() => {
// hypervisor.com — Automations & Fleets solution page.
const AFNS = window.IoiDesignSystem;
const {
  Button: AfButton,
  TextLink: AfLink,
  Eyebrow: AfEyebrow,
  Logo: AfLogo
} = AFNS;
const afwrap = {
  maxWidth: "75rem",
  margin: "0 auto",
  padding: "0 2.5rem"
};
const INK = "var(--color-onyx-black)";
const HAIR = "var(--color-grey-500)";
const ACC = "var(--color-link-green)";

/* ====================== dark workflow builder mockup ====================== */
function BuilderIcon({
  d
}) {
  return /*#__PURE__*/React.createElement("svg", {
    width: "18",
    height: "18",
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: "1.6",
    strokeLinecap: "round",
    strokeLinejoin: "round"
  }, /*#__PURE__*/React.createElement("path", {
    d: d
  }));
}
const SIDEBAR_ICONS = ["M12 2 a7 7 0 1 0 0 14 a7 7 0 0 0 0 -14 M19.5 19.5 L15.5 15.5", "M3 12 a9 9 0 1 0 18 0 a9 9 0 0 0 -18 0 M12 7 v5 l3 3", "M3 3 h7 v7 H3 Z M14 3 h7 v7 h-7 Z M3 14 h7 v7 H3 Z M14 14 h7 v7 h-7 Z", "M12 3 L19 6 V11 C19 16 15.5 19.5 12 21 C8.5 19.5 5 16 5 11 V6 Z", "M12 3 a9 9 0 1 0 0 18 M12 8 v8 M8 12 h8"];
function WorkflowBlock({
  kind,
  accent,
  label,
  desc,
  active,
  done,
  t
}) {
  const borderCol = accent ? ACC : "rgba(255,255,255,0.12)";
  const spin = t * 1440 % 360;
  return /*#__PURE__*/React.createElement("div", {
    style: {
      background: accent ? "rgba(80,200,120,0.08)" : "rgba(255,255,255,0.05)",
      border: `1px solid ${borderCol}`,
      borderRadius: 10,
      padding: "12px 14px",
      position: "relative"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 8,
      marginBottom: 8
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      display: "inline-flex",
      alignItems: "center",
      gap: 5,
      background: "rgba(255,255,255,0.09)",
      borderRadius: 5,
      padding: "2px 8px",
      fontFamily: "var(--font-mono)",
      fontSize: 10.5,
      color: accent ? ACC : "rgba(255,255,255,0.55)"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 5,
      height: 5,
      borderRadius: "50%",
      background: accent ? ACC : "rgba(255,255,255,0.4)"
    }
  }), kind), /*#__PURE__*/React.createElement("span", {
    style: {
      marginLeft: "auto",
      display: "flex",
      alignItems: "center",
      gap: 5
    }
  }, done && /*#__PURE__*/React.createElement("svg", {
    width: "14",
    height: "14",
    viewBox: "0 0 12 12",
    fill: "none"
  }, /*#__PURE__*/React.createElement("circle", {
    cx: "6",
    cy: "6",
    r: "6",
    fill: ACC
  }), /*#__PURE__*/React.createElement("path", {
    d: "M3 6.2 L5.2 8.2 L9 3.8",
    stroke: "#fff",
    strokeWidth: "1.5",
    strokeLinecap: "round",
    strokeLinejoin: "round"
  })), active && /*#__PURE__*/React.createElement("svg", {
    width: "14",
    height: "14",
    viewBox: "0 0 18 18",
    style: {
      transform: `rotate(${spin}deg)`
    }
  }, /*#__PURE__*/React.createElement("circle", {
    cx: "9",
    cy: "9",
    r: "7",
    fill: "none",
    stroke: ACC,
    strokeWidth: "2",
    strokeDasharray: "11 33",
    strokeLinecap: "round"
  })), /*#__PURE__*/React.createElement("svg", {
    width: "14",
    height: "14",
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "rgba(255,255,255,0.3)",
    strokeWidth: "1.8",
    strokeLinecap: "round"
  }, /*#__PURE__*/React.createElement("circle", {
    cx: "12",
    cy: "5",
    r: "1",
    fill: "rgba(255,255,255,0.3)",
    stroke: "none"
  }), /*#__PURE__*/React.createElement("circle", {
    cx: "12",
    cy: "12",
    r: "1",
    fill: "rgba(255,255,255,0.3)",
    stroke: "none"
  }), /*#__PURE__*/React.createElement("circle", {
    cx: "12",
    cy: "19",
    r: "1",
    fill: "rgba(255,255,255,0.3)",
    stroke: "none"
  })))), /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: 13.5,
      color: "rgba(255,255,255,0.9)",
      marginBottom: 4
    }
  }, label), /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 11.5,
      color: "rgba(255,255,255,0.42)",
      lineHeight: 1.45,
      whiteSpace: "nowrap",
      overflow: "hidden",
      textOverflow: "ellipsis"
    }
  }, desc));
}
function WorkflowBuilderDemo() {
  const [t, setT] = React.useState(0);
  React.useEffect(() => {
    const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduce) {
      setT(0.7);
      return;
    }
    let raf,
      start = null;
    const PERIOD = 9000;
    const tick = ts => {
      if (start == null) start = ts;
      setT((ts - start) % PERIOD / PERIOD);
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, []);
  const steps = [{
    kind: "Trigger",
    label: "Manual trigger",
    desc: "Runs across · 0 projects",
    accent: false,
    at: 0
  }, {
    kind: "Prompt",
    label: "Research {CVE_ID}: what is the vulnerability, whic…",
    desc: "Research the CVE and identify affected repos",
    accent: false,
    at: 0.18
  }, {
    kind: "Prompt",
    label: "Check if this repository has the vulnerable library. L…",
    desc: "Verify presence in current dependency tree",
    accent: false,
    at: 0.36
  }, {
    kind: "Shell Script",
    label: "Run fix and test suite",
    desc: "npm audit fix || yarn audit fix && npm test",
    accent: false,
    at: 0.54
  }, {
    kind: "Pull Request",
    label: "Open PR with fix",
    desc: "Create pull request with CVE details and evidence",
    accent: true,
    at: 0.72
  }];
  const activeIdx = Math.min(steps.length - 1, Math.floor(t * (steps.length + 0.6)));
  const concurrent = Math.floor(3 + t * 7);
  const total = Math.floor(10 + t * 90);
  return /*#__PURE__*/React.createElement("div", {
    style: {
      width: "100%",
      maxWidth: 720,
      margin: "0 auto",
      background: "#111115",
      borderRadius: 14,
      overflow: "hidden",
      boxShadow: "0 32px 80px rgba(0,0,0,0.55), 0 0 0 1px rgba(255,255,255,0.08)",
      fontFamily: "var(--font-sans)"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 6,
      padding: "13px 16px",
      borderBottom: "1px solid rgba(255,255,255,0.07)"
    }
  }, ["#ff5f57", "#ffbd2e", "#28c840"].map((c, i) => /*#__PURE__*/React.createElement("span", {
    key: i,
    style: {
      width: 10,
      height: 10,
      borderRadius: "50%",
      background: c
    }
  })), /*#__PURE__*/React.createElement("span", {
    style: {
      margin: "0 auto",
      fontFamily: "var(--font-sans)",
      fontSize: 12.5,
      color: "rgba(255,255,255,0.35)"
    }
  }, "Hypervisor \xB7 Automations")), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      height: 520
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      width: 48,
      flex: "none",
      borderRight: "1px solid rgba(255,255,255,0.07)",
      display: "flex",
      flexDirection: "column",
      alignItems: "center",
      paddingTop: 16,
      gap: 6
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      width: 28,
      height: 28,
      borderRadius: 7,
      background: "rgba(255,255,255,0.1)",
      display: "grid",
      placeItems: "center",
      color: "#fff"
    }
  }, /*#__PURE__*/React.createElement(AfLogo, {
    size: 14
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: 8,
      display: "flex",
      flexDirection: "column",
      gap: 4
    }
  }, SIDEBAR_ICONS.map((d, i) => /*#__PURE__*/React.createElement("span", {
    key: i,
    style: {
      width: 32,
      height: 32,
      borderRadius: 7,
      display: "grid",
      placeItems: "center",
      color: i === 2 ? "rgba(255,255,255,0.85)" : "rgba(255,255,255,0.28)",
      background: i === 2 ? "rgba(255,255,255,0.1)" : "transparent",
      cursor: "pointer"
    }
  }, /*#__PURE__*/React.createElement(BuilderIcon, {
    d: d
  }))))), /*#__PURE__*/React.createElement("div", {
    style: {
      flex: 1,
      display: "flex",
      flexDirection: "column",
      overflow: "hidden"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      justifyContent: "space-between",
      padding: "13px 18px",
      borderBottom: "1px solid rgba(255,255,255,0.07)"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 8,
      fontFamily: "var(--font-sans)",
      fontSize: 12.5
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      color: "rgba(255,255,255,0.4)"
    }
  }, "Automations"), /*#__PURE__*/React.createElement("span", {
    style: {
      color: "rgba(255,255,255,0.3)"
    }
  }, "\u203A"), /*#__PURE__*/React.createElement("span", {
    style: {
      color: "rgba(255,255,255,0.85)"
    }
  }, "CVE mitigation and version updates")), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      gap: 7
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      padding: "5px 12px",
      borderRadius: 6,
      border: "1px solid rgba(255,255,255,0.15)",
      color: "rgba(255,255,255,0.5)",
      fontSize: 12,
      cursor: "pointer"
    }
  }, "Cancel"), /*#__PURE__*/React.createElement("span", {
    style: {
      padding: "5px 12px",
      borderRadius: 6,
      background: "rgba(255,255,255,0.92)",
      color: "#111",
      fontSize: 12,
      fontWeight: 600,
      cursor: "pointer"
    }
  }, "Create"))), /*#__PURE__*/React.createElement("div", {
    style: {
      padding: "10px 18px",
      borderBottom: "1px solid rgba(255,255,255,0.07)",
      fontFamily: "var(--font-sans)",
      fontSize: 11.5,
      color: "rgba(255,255,255,0.35)",
      lineHeight: 1.4
    }
  }, "Analyzes a specific CVE, determines if the repository is affected, and if so, automatically remediates the vulnerability by updating dependencies, migrating code to new APIs, running tests, and creating a pull request with the complete fix."), /*#__PURE__*/React.createElement("div", {
    style: {
      flex: 1,
      overflow: "hidden",
      padding: "16px 18px",
      display: "flex",
      flexDirection: "column",
      gap: 0,
      WebkitMaskImage: "linear-gradient(180deg, #000 70%, transparent)",
      maskImage: "linear-gradient(180deg, #000 70%, transparent)"
    }
  }, steps.map((s, i) => /*#__PURE__*/React.createElement(React.Fragment, {
    key: i
  }, i > 0 && /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      justifyContent: "flex-start",
      paddingLeft: 18,
      height: 24,
      alignItems: "center"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      width: 1.5,
      height: 24,
      background: i <= activeIdx ? ACC : "rgba(255,255,255,0.14)",
      transition: "background 0.4s"
    }
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      opacity: i <= activeIdx ? 1 : 0.38,
      transition: "opacity 0.4s"
    }
  }, /*#__PURE__*/React.createElement(WorkflowBlock, {
    kind: s.kind,
    label: s.label,
    desc: s.desc,
    accent: s.accent,
    active: i === activeIdx,
    done: i < activeIdx,
    t: t
  })))))), /*#__PURE__*/React.createElement("div", {
    style: {
      width: 260,
      flex: "none",
      borderLeft: "1px solid rgba(255,255,255,0.07)",
      padding: "16px 16px",
      display: "flex",
      flexDirection: "column",
      gap: 16,
      overflowY: "auto"
    }
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 10.5,
      letterSpacing: "0.06em",
      textTransform: "uppercase",
      color: "rgba(255,255,255,0.35)",
      marginBottom: 10
    }
  }, "Runs on"), ["Projects", "Repositories"].map((opt, i) => /*#__PURE__*/React.createElement("label", {
    key: opt,
    style: {
      display: "flex",
      alignItems: "center",
      gap: 8,
      marginBottom: 8,
      cursor: "pointer"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 14,
      height: 14,
      borderRadius: "50%",
      border: `1.5px solid ${i === 1 ? ACC : "rgba(255,255,255,0.25)"}`,
      display: "grid",
      placeItems: "center"
    }
  }, i === 1 && /*#__PURE__*/React.createElement("span", {
    style: {
      width: 6,
      height: 6,
      borderRadius: "50%",
      background: ACC
    }
  })), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: 12.5,
      color: "rgba(255,255,255,0.7)"
    }
  }, opt)))), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 6,
      padding: "8px 10px",
      borderRadius: 7,
      border: "1px solid rgba(255,255,255,0.12)",
      background: "rgba(255,255,255,0.05)",
      justifyContent: "space-between"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 11,
      color: "rgba(255,255,255,0.6)"
    }
  }, "Small 2 vCPU / 8 GiB / 45 GiB disk"), /*#__PURE__*/React.createElement("svg", {
    width: "12",
    height: "12",
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "rgba(255,255,255,0.4)",
    strokeWidth: "2",
    strokeLinecap: "round"
  }, /*#__PURE__*/React.createElement("path", {
    d: "M6 9 L12 15 L18 9"
  })))), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "1fr 1fr",
      gap: 10
    }
  }, [["Max concurrent actions", concurrent], ["Max total actions", total]].map(([label, val]) => /*#__PURE__*/React.createElement("div", {
    key: label
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 10,
      letterSpacing: "0.05em",
      textTransform: "uppercase",
      color: "rgba(255,255,255,0.35)",
      marginBottom: 6,
      lineHeight: 1.3
    }
  }, label), /*#__PURE__*/React.createElement("div", {
    style: {
      padding: "7px 10px",
      borderRadius: 7,
      border: "1px solid rgba(255,255,255,0.12)",
      background: "rgba(255,255,255,0.05)",
      fontFamily: "var(--font-mono)",
      fontSize: 13,
      color: "rgba(255,255,255,0.8)"
    }
  }, val)))), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 10.5,
      letterSpacing: "0.06em",
      textTransform: "uppercase",
      color: "rgba(255,255,255,0.35)",
      marginBottom: 8
    }
  }, "Run Automation as"), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      justifyContent: "space-between",
      padding: "8px 10px",
      borderRadius: 7,
      border: "1px solid rgba(255,255,255,0.12)",
      background: "rgba(255,255,255,0.05)"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: 12.5,
      color: "rgba(255,255,255,0.35)"
    }
  }, "Select identity"), /*#__PURE__*/React.createElement("svg", {
    width: "12",
    height: "12",
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "rgba(255,255,255,0.3)",
    strokeWidth: "2",
    strokeLinecap: "round"
  }, /*#__PURE__*/React.createElement("path", {
    d: "M6 9 L12 15 L18 9"
  })))), /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: "auto",
      display: "flex",
      gap: 7
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      flex: 1,
      padding: "7px 12px",
      borderRadius: 6,
      border: "1px solid rgba(255,255,255,0.15)",
      color: "rgba(255,255,255,0.5)",
      fontSize: 12,
      textAlign: "center",
      cursor: "pointer"
    }
  }, "Cancel"), /*#__PURE__*/React.createElement("span", {
    style: {
      flex: 1,
      padding: "7px 12px",
      borderRadius: 6,
      background: "rgba(255,255,255,0.92)",
      color: "#111",
      fontSize: 12,
      fontWeight: 600,
      textAlign: "center",
      cursor: "pointer"
    }
  }, "Update")))));
}

/* ====================== feature rows ====================== */
function FeatureRow({
  eyebrow,
  heading,
  body,
  link,
  diagram,
  flip
}) {
  return /*#__PURE__*/React.createElement("div", {
    style: {
      background: "var(--color-white)",
      border: `0.5px solid ${HAIR}`,
      borderRadius: "var(--radius-card)",
      padding: "3rem 3.25rem",
      display: "grid",
      gridTemplateColumns: "1fr 1fr",
      gap: "3rem",
      alignItems: "center"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      order: flip ? 2 : 1
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      display: "inline-block",
      fontFamily: "var(--font-mono)",
      fontSize: 11,
      letterSpacing: "0.08em",
      textTransform: "uppercase",
      color: ACC,
      marginBottom: "0.875rem"
    }
  }, eyebrow), /*#__PURE__*/React.createElement("h3", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.625rem",
      letterSpacing: "-0.02em",
      lineHeight: 1.12,
      margin: 0,
      color: INK
    }
  }, heading), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.0625rem",
      color: "var(--color-grey-800)",
      marginTop: "1rem",
      lineHeight: 1.5,
      maxWidth: "42ch"
    }
  }, body), link && /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: "1.5rem"
    }
  }, /*#__PURE__*/React.createElement(AfLink, {
    href: link[1]
  }, link[0]))), /*#__PURE__*/React.createElement("div", {
    style: {
      order: flip ? 1 : 2,
      display: "flex",
      justifyContent: "center"
    }
  }, diagram));
}

/* -- trigger pills diagram -- */
function TriggerDiagram() {
  const [t, setT] = React.useState(0);
  React.useEffect(() => {
    const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduce) {
      setT(0.5);
      return;
    }
    let raf,
      start = null;
    const PERIOD = 5600;
    const tick = ts => {
      if (start == null) start = ts;
      setT((ts - start) % PERIOD / PERIOD);
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, []);
  const items = [["PR opened", "scope:vcs.pr"], ["Scheduled · daily", "scope:cron"], ["Webhook", "scope:webhook"], ["Manual", "scope:cli"]];
  const active = Math.min(items.length - 1, Math.floor(t * (items.length + 0.4)));
  const spin = t * 1440 % 360;
  return /*#__PURE__*/React.createElement("div", {
    style: {
      width: "100%",
      maxWidth: 380,
      display: "flex",
      flexDirection: "column",
      gap: 12
    }
  }, items.map(([label, scope], i) => {
    const fired = i < active,
      firing = i === active;
    return /*#__PURE__*/React.createElement("div", {
      key: label,
      style: {
        background: "var(--color-porcelain-grey)",
        border: `0.5px solid ${fired || firing ? ACC : HAIR}`,
        borderRadius: 999,
        padding: "14px 22px",
        display: "flex",
        alignItems: "center",
        gap: 13,
        transform: firing ? "scale(1.02)" : "scale(1)",
        boxShadow: firing ? "var(--shadow-md)" : "var(--shadow-xs)",
        transition: "all 0.3s"
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        width: 20,
        height: 20,
        flex: "none",
        display: "grid",
        placeItems: "center"
      }
    }, fired ? /*#__PURE__*/React.createElement("span", {
      style: {
        width: 18,
        height: 18,
        borderRadius: "50%",
        background: ACC,
        display: "grid",
        placeItems: "center"
      }
    }, /*#__PURE__*/React.createElement("svg", {
      width: "10",
      height: "10",
      viewBox: "0 0 12 12",
      fill: "none"
    }, /*#__PURE__*/React.createElement("path", {
      d: "M2.5 6.3 L5 8.5 L9.5 3.7",
      stroke: "#fff",
      strokeWidth: "1.8",
      strokeLinecap: "round",
      strokeLinejoin: "round"
    }))) : firing ? /*#__PURE__*/React.createElement("svg", {
      width: "18",
      height: "18",
      viewBox: "0 0 18 18",
      style: {
        transform: `rotate(${spin}deg)`
      }
    }, /*#__PURE__*/React.createElement("circle", {
      cx: "9",
      cy: "9",
      r: "7",
      fill: "none",
      stroke: ACC,
      strokeWidth: "2",
      strokeDasharray: "11 33",
      strokeLinecap: "round"
    })) : /*#__PURE__*/React.createElement("svg", {
      width: "18",
      height: "18",
      viewBox: "0 0 18 18"
    }, /*#__PURE__*/React.createElement("circle", {
      cx: "9",
      cy: "9",
      r: "7",
      fill: "none",
      stroke: HAIR,
      strokeWidth: "1.5",
      strokeDasharray: "0.5 3.5",
      strokeLinecap: "round"
    }))), /*#__PURE__*/React.createElement("span", {
      style: {
        fontFamily: "var(--font-sans)",
        fontSize: "1rem",
        color: INK
      }
    }, label), /*#__PURE__*/React.createElement("span", {
      style: {
        marginLeft: "auto",
        fontFamily: "var(--font-mono)",
        fontSize: 10.5,
        color: "var(--color-grey-700)",
        background: "var(--color-white)",
        border: `0.5px solid ${HAIR}`,
        borderRadius: 6,
        padding: "2px 8px"
      }
    }, scope));
  }));
}

/* -- scale / fleet diagram -- */
function FleetDiagram() {
  const [t, setT] = React.useState(0);
  React.useEffect(() => {
    const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduce) {
      setT(0.7);
      return;
    }
    let raf,
      start = null;
    const PERIOD = 7000;
    const tick = ts => {
      if (start == null) start = ts;
      setT((ts - start) % PERIOD / PERIOD);
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, []);
  const repos = ["billing-api", "web-dashboard", "auth-service", "payments-core", "notifications"];
  const prog = i => Math.max(0, Math.min(1, (t - (0.15 + i * 0.1)) / 0.4));
  const merged = repos.filter((_, i) => prog(i) >= 1).length;
  return /*#__PURE__*/React.createElement("div", {
    style: {
      width: "100%",
      maxWidth: 380,
      background: "var(--color-white)",
      border: `0.5px solid ${HAIR}`,
      borderRadius: 14,
      overflow: "hidden",
      boxShadow: "var(--shadow-sm)"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      justifyContent: "space-between",
      padding: "13px 18px",
      borderBottom: `0.5px solid ${HAIR}`
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 7,
      fontFamily: "var(--font-sans)",
      fontSize: 13.5,
      color: INK
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 8,
      height: 8,
      borderRadius: "50%",
      background: ACC
    }
  }), "Fleet running"), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 11.5,
      color: merged === repos.length ? ACC : "var(--color-grey-700)"
    }
  }, merged, "/", repos.length, " merged")), /*#__PURE__*/React.createElement("div", {
    style: {
      padding: "6px 0"
    }
  }, repos.map((r, i) => {
    const p = prog(i);
    const done = p >= 1;
    return /*#__PURE__*/React.createElement("div", {
      key: r,
      style: {
        display: "flex",
        alignItems: "center",
        gap: 11,
        padding: "10px 18px"
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        width: 14,
        height: 14,
        borderRadius: "50%",
        flex: "none",
        background: done ? ACC : "transparent",
        border: done ? "none" : `1.5px solid ${p > 0 ? ACC : HAIR}`,
        display: "grid",
        placeItems: "center"
      }
    }, done && /*#__PURE__*/React.createElement("svg", {
      width: "8",
      height: "8",
      viewBox: "0 0 12 12",
      fill: "none"
    }, /*#__PURE__*/React.createElement("path", {
      d: "M2.5 6.3 L5 8.5 L9.5 3.7",
      stroke: "#fff",
      strokeWidth: "1.8",
      strokeLinecap: "round",
      strokeLinejoin: "round"
    })), !done && p > 0 && /*#__PURE__*/React.createElement("span", {
      style: {
        width: 5,
        height: 5,
        borderRadius: "50%",
        background: ACC
      }
    })), /*#__PURE__*/React.createElement("span", {
      style: {
        fontFamily: "var(--font-mono)",
        fontSize: 12.5,
        color: INK,
        width: 120,
        flex: "none"
      }
    }, r), /*#__PURE__*/React.createElement("span", {
      style: {
        flex: 1,
        height: 4,
        borderRadius: 2,
        background: "var(--color-porcelain-grey)",
        overflow: "hidden"
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        display: "block",
        height: "100%",
        width: `${p * 100}%`,
        background: done ? ACC : "var(--color-grey-700)",
        borderRadius: 2,
        transition: "width 0.15s"
      }
    })), /*#__PURE__*/React.createElement("span", {
      style: {
        fontFamily: "var(--font-mono)",
        fontSize: 10.5,
        color: done ? ACC : "var(--color-grey-700)",
        width: 46,
        textAlign: "right",
        flex: "none"
      }
    }, done ? "merged" : p > 0 ? "running" : "queued"));
  })));
}

/* ====================== page ====================== */
function AfHero() {
  return /*#__PURE__*/React.createElement("section", {
    style: {
      ...afwrap,
      paddingTop: "4rem"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "0.7fr 1.3fr",
      gap: "4rem",
      alignItems: "center"
    }
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement(AfEyebrow, {
    color: ACC
  }, "Solutions \xB7 Automations & Fleets"), /*#__PURE__*/React.createElement("h1", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "3.25rem",
      lineHeight: 1.06,
      letterSpacing: "-0.02em",
      margin: "1.25rem 0 0",
      color: INK
    }
  }, "Turn any engineering task into a repeatable workflow"), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.1rem",
      color: "var(--color-grey-800)",
      marginTop: "1.25rem",
      lineHeight: 1.55,
      maxWidth: "40ch"
    }
  }, "Define workflows from prompts, scripts, and integrations. Trigger them from events, schedules, or PRs. Run them across one repo or thousands."), /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: "2rem"
    }
  }, /*#__PURE__*/React.createElement(AfLink, {
    href: "#"
  }, "Browse automation templates"))), /*#__PURE__*/React.createElement("div", {
    style: {
      position: "relative"
    }
  }, /*#__PURE__*/React.createElement(WorkflowBuilderDemo, null))));
}
function AfFeatures() {
  return /*#__PURE__*/React.createElement("section", {
    style: {
      ...afwrap,
      paddingTop: "6rem",
      display: "flex",
      flexDirection: "column",
      gap: "1.5rem"
    }
  }, /*#__PURE__*/React.createElement(FeatureRow, {
    eyebrow: "Build",
    heading: "Compose workflows from prompts, scripts, and tools",
    body: "Combine prompts, shell scripts, and API calls into versioned, reusable automations. Wire in any tool your team already uses \u2014 GitHub, Jira, Slack, CI.",
    link: ["Explore the builder", "docs.html"],
    flip: false,
    diagram: /*#__PURE__*/React.createElement("div", {
      style: {
        width: "100%",
        maxWidth: 380
      }
    }, [{
      kind: "Trigger",
      label: "PR opened",
      dot: ACC
    }, {
      kind: "Prompt",
      label: "Review for correctness and test coverage"
    }, {
      kind: "Shell Script",
      label: "npm test && npm run lint"
    }, {
      kind: "Pull Request",
      label: "Post review comment and suggest fix"
    }].map(({
      kind,
      label,
      dot
    }, i) => /*#__PURE__*/React.createElement(React.Fragment, {
      key: i
    }, i > 0 && /*#__PURE__*/React.createElement("div", {
      style: {
        width: 1.5,
        height: 16,
        background: HAIR,
        margin: "0 auto 0 16px"
      }
    }), /*#__PURE__*/React.createElement("div", {
      style: {
        background: "var(--color-porcelain-grey)",
        border: `0.5px solid ${HAIR}`,
        borderRadius: 10,
        padding: "11px 14px"
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        display: "inline-flex",
        alignItems: "center",
        gap: 5,
        background: "var(--color-white)",
        border: `0.5px solid ${HAIR}`,
        borderRadius: 5,
        padding: "2px 8px",
        fontFamily: "var(--font-mono)",
        fontSize: 10.5,
        color: "var(--color-grey-700)",
        marginBottom: 6
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        width: 5,
        height: 5,
        borderRadius: "50%",
        background: dot || "var(--color-grey-600)"
      }
    }), kind), /*#__PURE__*/React.createElement("div", {
      style: {
        fontFamily: "var(--font-sans)",
        fontSize: 13.5,
        color: INK
      }
    }, label)))))
  }), /*#__PURE__*/React.createElement(FeatureRow, {
    eyebrow: "Trigger",
    heading: "Fire from any event in your dev workflow",
    body: "Wire automations to pull requests, webhooks, cron schedules, or manual dispatch. Nothing waits for a human to hit run \u2014 but every action is still receipted.",
    flip: true,
    diagram: /*#__PURE__*/React.createElement(TriggerDiagram, null)
  }), /*#__PURE__*/React.createElement(FeatureRow, {
    eyebrow: "Scale",
    heading: "Run a fleet across your entire codebase",
    body: "One configuration fans out into a governed fleet. Parallel workers, tracked progress, merged results \u2014 the same automation that covers one repo covers five hundred.",
    flip: false,
    diagram: /*#__PURE__*/React.createElement(FleetDiagram, null)
  }));
}
function AfCTA() {
  return /*#__PURE__*/React.createElement("section", {
    style: {
      ...afwrap,
      paddingTop: "8rem",
      textAlign: "center"
    }
  }, /*#__PURE__*/React.createElement("h2", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "3rem",
      letterSpacing: "-0.02em",
      margin: 0,
      color: INK
    }
  }, "Build your first automation"), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      gap: "0.5rem",
      justifyContent: "center",
      marginTop: "1.75rem"
    }
  }, /*#__PURE__*/React.createElement(AfButton, {
    iconRight: /*#__PURE__*/React.createElement("span", null, "\u2192")
  }, "Get started"), /*#__PURE__*/React.createElement(AfLink, {
    href: "solutions.html"
  }, "Back to solutions")));
}
function HvPage() {
  return /*#__PURE__*/React.createElement("main", null, /*#__PURE__*/React.createElement(AfHero, null), /*#__PURE__*/React.createElement(AfFeatures, null), /*#__PURE__*/React.createElement(AfCTA, null));
}
window.HvPage = HvPage;
window.HvPageActive = "Solutions";
})(); } catch (e) { __ds_ns.__errors.push({ path: "site/AutomationsFleets.jsx", error: String((e && e.message) || e) }); }

// site/BackgroundWork.jsx
try { (() => {
// hypervisor.com — Background Work solution (under Solutions).
const BNS = window.IoiDesignSystem;
const {
  Button: BgButton,
  Badge: BgBadge,
  TextLink: BgLink,
  Eyebrow: BgEyebrow,
  Wordmark: BgWordmark,
  Logo: BgLogo
} = BNS;
const bawrap = {
  maxWidth: "75rem",
  margin: "0 auto",
  padding: "0 2.5rem"
};
const INK = "var(--color-onyx-black)";
const HAIR = "var(--color-grey-500)";
const ACC = "var(--color-link-green)";

/* ---- tiny tab glyphs ---- */
const tg = paths => /*#__PURE__*/React.createElement("svg", {
  width: "17",
  height: "17",
  viewBox: "0 0 24 24",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: "1.6",
  strokeLinecap: "round",
  strokeLinejoin: "round"
}, paths);
const ICONS = {
  parallel: tg(/*#__PURE__*/React.createElement("g", null, /*#__PURE__*/React.createElement("rect", {
    x: "3",
    y: "4",
    width: "7",
    height: "7",
    rx: "1.5"
  }), /*#__PURE__*/React.createElement("rect", {
    x: "14",
    y: "4",
    width: "7",
    height: "7",
    rx: "1.5"
  }), /*#__PURE__*/React.createElement("rect", {
    x: "3",
    y: "13",
    width: "7",
    height: "7",
    rx: "1.5"
  }), /*#__PURE__*/React.createElement("rect", {
    x: "14",
    y: "13",
    width: "7",
    height: "7",
    rx: "1.5"
  }))),
  decoupled: tg(/*#__PURE__*/React.createElement("g", null, /*#__PURE__*/React.createElement("rect", {
    x: "3",
    y: "5",
    width: "18",
    height: "11",
    rx: "1.5"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M2 20 H22"
  }))),
  sandbox: tg(/*#__PURE__*/React.createElement("g", null, /*#__PURE__*/React.createElement("rect", {
    x: "4",
    y: "4",
    width: "16",
    height: "16",
    rx: "2.5"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M9 12 L11 14 L15 9.5"
  }))),
  edit: tg(/*#__PURE__*/React.createElement("g", null, /*#__PURE__*/React.createElement("path", {
    d: "M4 20 H20"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M14.5 5.5 L18.5 9.5 L9 19 L5 20 L6 16 Z"
  }))),
  trigger: tg(/*#__PURE__*/React.createElement("g", null, /*#__PURE__*/React.createElement("path", {
    d: "M13 2 L4 14 H11 L10 22 L20 9 H13 Z"
  })))
};
const TABS = [{
  icon: "parallel",
  label: "Runs in parallel",
  demo: "parallel",
  heading: "One intent, every repo.",
  body: ["One repo is a coding agent task. Five hundred is a fleet task.", "Hypervisor spins up the same sandbox across every repo that needs the change. Parallel runs, tracked progress, merged results. One person's productivity becomes the whole org's throughput."]
}, {
  icon: "decoupled",
  label: "Decoupled from your laptop",
  demo: "decoupled",
  heading: "Your laptop stays fast. Hypervisor does the work.",
  body: ["A coding agent needs your machine and your attention. A background agent needs neither.", "Start one from your laptop. Check the result from your phone. Close the lid, join a meeting, go offline. Hypervisor compiles, tests, and fixes failures without you."]
}, {
  icon: "sandbox",
  label: "Sandboxed execution",
  demo: "sandbox",
  heading: "Every agent gets its own computer.",
  body: ["Each agent runs in its own short-lived environment: full toolchain, test suite, scoped credentials.", "No shared state. No leaked secrets. No cascade when one fails. The environment is destroyed after use."]
}, {
  icon: "edit",
  label: "Edit alongside Hypervisor",
  demo: "edit",
  heading: "On the loop, not in the loop.",
  body: ["You don't steer it. You don't watch it. But you can.", "Open the same environment Hypervisor used. Edit its work, change direction, or take over — VS Code in the browser or your desktop editor. Pick up where Hypervisor left off."]
}, {
  icon: "trigger",
  label: "Triggered automatically",
  demo: "trigger",
  heading: "Take the human out of the trigger.",
  body: ["If every run starts with someone typing a prompt, you automated the work but not the workflow.", "Hypervisor fires from PRs, webhooks, schedules, or Slack. A vulnerability lands. A PR opens. A ticket stalls. Hypervisor is already on it."]
}];

/* ========================= demos ========================= */
const PANEL = {
  background: "var(--color-porcelain-grey)",
  border: `0.5px solid ${HAIR}`,
  borderRadius: "var(--radius-card)",
  height: 480,
  padding: "2rem",
  position: "relative",
  overflow: "hidden"
};
const card = {
  background: "var(--color-white)",
  border: `0.5px solid ${HAIR}`,
  borderRadius: 14,
  boxShadow: "var(--shadow-sm)"
};
function PromptCard({
  title
}) {
  return /*#__PURE__*/React.createElement("div", {
    style: {
      ...card,
      padding: "18px 18px 14px"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.0625rem",
      color: INK
    }
  }, title), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 10,
      marginTop: 28,
      paddingTop: 12,
      borderTop: `0.5px solid ${HAIR}`
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 26,
      height: 26,
      borderRadius: 7,
      border: `0.5px solid ${HAIR}`,
      display: "grid",
      placeItems: "center",
      color: "var(--color-grey-700)"
    }
  }, /*#__PURE__*/React.createElement("svg", {
    width: "13",
    height: "13",
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: "1.8",
    strokeLinecap: "round"
  }, /*#__PURE__*/React.createElement("path", {
    d: "M21 12.5 L12.5 21 a5 5 0 0 1 -7 -7 L14 5.5 a3.2 3.2 0 0 1 4.5 4.5 L10 18.5 a1.4 1.4 0 0 1 -2 -2 L16 8.5"
  }))), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: 14,
      color: "var(--color-grey-800)"
    }
  }, "Intercom"), /*#__PURE__*/React.createElement("svg", {
    width: "12",
    height: "12",
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "var(--color-grey-700)",
    strokeWidth: "2",
    strokeLinecap: "round"
  }, /*#__PURE__*/React.createElement("path", {
    d: "M6 9 L12 15 L18 9"
  })), /*#__PURE__*/React.createElement("span", {
    style: {
      marginLeft: "auto",
      width: 30,
      height: 30,
      borderRadius: 8,
      background: INK,
      display: "grid",
      placeItems: "center"
    }
  }, /*#__PURE__*/React.createElement("svg", {
    width: "13",
    height: "13",
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "#fff",
    strokeWidth: "2",
    strokeLinecap: "round",
    strokeLinejoin: "round"
  }, /*#__PURE__*/React.createElement("path", {
    d: "M9 5 L4 5 L4 14 a3 3 0 0 0 3 3 H17"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M13 12 L17 16 L13 20"
  })))));
}
function ParallelDemo() {
  const [t, setT] = React.useState(0);
  React.useEffect(() => {
    const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduce) {
      setT(0.85);
      return;
    }
    let raf,
      start = null;
    const PERIOD = 7200;
    const tick = ts => {
      if (start == null) start = ts;
      setT((ts - start) % PERIOD / PERIOD);
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, []);
  const fullTitle = "Fix Pending State Issue";
  const typeStart = 0.05,
    typeEnd = 0.24;
  const typed = t < typeStart ? "" : fullTitle.slice(0, Math.round(Math.min(1, (t - typeStart) / (typeEnd - typeStart)) * fullTitle.length));
  const caretOn = Math.sin(t * Math.PI * 2 * 7) > 0;
  const composerOpacity = t < 0.30 ? 1 : Math.max(0, 1 - (t - 0.30) / 0.05);
  const tasks = [{
    title: "Fix Pending State Issue",
    meta: "7 seconds ago \u00b7 Intercom",
    tone: "run",
    at: 0.33
  }, {
    title: "Refactor blog item page",
    meta: "17 seconds ago \u00b7 Intercom",
    tone: "run",
    at: 0.46
  }, {
    title: "Check code and suggest improvements",
    meta: "40 seconds ago \u00b7 Netflix",
    tone: "done",
    at: 0.57
  }];
  const fade = t > 0.94 ? 1 - (t - 0.94) / 0.06 : 1;
  return /*#__PURE__*/React.createElement("div", {
    style: {
      ...PANEL,
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      position: "relative"
    }
  }, t < 0.37 && /*#__PURE__*/React.createElement("div", {
    style: {
      position: "absolute",
      left: "7%",
      right: "7%",
      opacity: composerOpacity,
      transition: "opacity 0.15s"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      ...card,
      minHeight: 124,
      padding: "18px 18px 14px",
      display: "flex",
      flexDirection: "column"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.25rem",
      color: INK,
      flex: 1,
      lineHeight: 1.3
    }
  }, typed, /*#__PURE__*/React.createElement("span", {
    style: {
      opacity: caretOn && typed.length < fullTitle.length ? 0.7 : 0,
      color: INK
    }
  }, "|")), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 10,
      marginTop: 16
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 28,
      height: 28,
      borderRadius: 8,
      border: `0.5px solid ${HAIR}`,
      display: "grid",
      placeItems: "center",
      color: "var(--color-grey-700)"
    }
  }, /*#__PURE__*/React.createElement("svg", {
    width: "14",
    height: "14",
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: "1.8",
    strokeLinecap: "round"
  }, /*#__PURE__*/React.createElement("path", {
    d: "M21 12.5 L12.5 21 a5 5 0 0 1 -7 -7 L14 5.5 a3.2 3.2 0 0 1 4.5 4.5 L10 18.5 a1.4 1.4 0 0 1 -2 -2 L16 8.5"
  }))), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: 14,
      color: "var(--color-grey-700)"
    }
  }, "Intercom"), /*#__PURE__*/React.createElement("svg", {
    width: "12",
    height: "12",
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "var(--color-grey-600)",
    strokeWidth: "2",
    strokeLinecap: "round"
  }, /*#__PURE__*/React.createElement("path", {
    d: "M6 9 L12 15 L18 9"
  })), /*#__PURE__*/React.createElement("span", {
    style: {
      marginLeft: "auto",
      width: 32,
      height: 32,
      borderRadius: 9,
      background: INK,
      display: "grid",
      placeItems: "center"
    }
  }, /*#__PURE__*/React.createElement("svg", {
    width: "14",
    height: "14",
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "#fff",
    strokeWidth: "2",
    strokeLinecap: "round",
    strokeLinejoin: "round"
  }, /*#__PURE__*/React.createElement("path", {
    d: "M9 5 L4 5 L4 14 a3 3 0 0 0 3 3 H17"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M13 12 L17 16 L13 20"
  })))))), /*#__PURE__*/React.createElement("div", {
    style: {
      width: "88%",
      display: "flex",
      flexDirection: "column",
      gap: 12,
      opacity: fade
    }
  }, tasks.map((task, i) => {
    const vis = t >= task.at;
    const op = vis ? Math.min(1, (t - task.at) / 0.06) : 0;
    const tone = task.tone === "done" ? ACC : "var(--color-red-500)";
    const tint = task.tone === "done" ? "color-mix(in srgb, var(--color-pistachio-green) 45%, var(--color-white))" : "color-mix(in srgb, var(--color-red-500) 15%, var(--color-white))";
    return /*#__PURE__*/React.createElement("div", {
      key: i,
      style: {
        ...card,
        padding: "15px 18px",
        display: "flex",
        alignItems: "center",
        gap: 15,
        opacity: op,
        transform: vis ? "translateY(0)" : "translateY(12px)",
        transition: "opacity 0.35s, transform 0.35s"
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        width: 52,
        height: 52,
        borderRadius: 14,
        flex: "none",
        background: tint,
        display: "grid",
        placeItems: "center"
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        width: 9,
        height: 9,
        borderRadius: "50%",
        background: tone
      }
    })), /*#__PURE__*/React.createElement("div", {
      style: {
        minWidth: 0
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        fontFamily: "var(--font-sans)",
        fontSize: "1.0625rem",
        color: INK,
        lineHeight: 1.25
      }
    }, task.title), /*#__PURE__*/React.createElement("div", {
      style: {
        fontFamily: "var(--font-sans)",
        fontSize: "0.875rem",
        color: "var(--color-grey-600)",
        marginTop: 3
      }
    }, task.meta)));
  })));
}
function DecoupledDemo() {
  const [t, setT] = React.useState(0);
  React.useEffect(() => {
    const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduce) {
      setT(0.9);
      return;
    }
    let raf,
      start = null;
    const PERIOD = 8200;
    const tick = ts => {
      if (start == null) start = ts;
      setT((ts - start) % PERIOD / PERIOD);
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, []);
  const todos = ["Check recent merged PRs and commits", "Analyze closed issues and PRs", "Identify files with most churn", "Check for any releases or tags", "Draft the weekly digest"];
  const done = Math.max(0, Math.min(todos.length, Math.floor((t - 0.42) / 0.09)));
  const enter = Math.max(0, Math.min(1, t / 0.12));
  const exit = t > 0.95 ? 1 - (t - 0.95) / 0.05 : 1;
  const reveal = (s, d) => {
    const p = Math.max(0, Math.min(1, (t - s) / (d || 0.06)));
    return {
      opacity: p,
      transform: `translateY(${(1 - p) * 10}px)`
    };
  };
  return /*#__PURE__*/React.createElement("div", {
    style: {
      ...PANEL,
      background: "color-mix(in srgb, var(--color-pistachio-green) 45%, var(--color-porcelain-grey))",
      padding: 0,
      display: "flex",
      justifyContent: "center",
      alignItems: "flex-start"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      width: 300,
      marginTop: 34,
      background: "var(--color-white)",
      border: "6px solid var(--color-onyx-black)",
      borderBottom: "none",
      borderRadius: "34px 34px 0 0",
      overflow: "hidden",
      boxShadow: "var(--shadow-lg)",
      opacity: enter * exit,
      transform: `translateY(${(1 - enter) * 70}px)`
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      padding: "16px 18px 12px"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      display: "flex",
      color: INK
    }
  }, /*#__PURE__*/React.createElement(BgWordmark, {
    height: 16
  })), /*#__PURE__*/React.createElement("span", {
    style: {
      marginLeft: "auto",
      display: "flex",
      flexDirection: "column",
      gap: 3
    }
  }, [0, 1, 2].map(i => /*#__PURE__*/React.createElement("span", {
    key: i,
    style: {
      width: 16,
      height: 1.6,
      background: INK,
      borderRadius: 1
    }
  })))), /*#__PURE__*/React.createElement("div", {
    style: {
      margin: "0 14px",
      padding: "8px 12px",
      border: `0.5px solid ${HAIR}`,
      borderRadius: 9,
      display: "flex",
      alignItems: "center",
      gap: 7,
      fontFamily: "var(--font-sans)",
      fontSize: 12.5,
      color: "var(--color-grey-700)"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      color: ACC
    }
  }, "+"), "Add command pallets", /*#__PURE__*/React.createElement("svg", {
    width: "11",
    height: "11",
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: "2",
    strokeLinecap: "round",
    style: {
      marginLeft: "auto"
    }
  }, /*#__PURE__*/React.createElement("path", {
    d: "M6 9 L12 15 L18 9"
  }))), /*#__PURE__*/React.createElement("div", {
    style: {
      padding: "14px 14px 0"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      marginLeft: "auto",
      width: "86%",
      background: "var(--color-porcelain-grey)",
      border: `0.5px solid ${HAIR}`,
      borderRadius: 12,
      padding: "10px 12px",
      fontFamily: "var(--font-sans)",
      fontSize: 12.5,
      lineHeight: 1.45,
      color: INK,
      ...reveal(0.16)
    }
  }, "Good morning \u2014 give me a weekly digest of everything merged, closed, or released since yesterday, including the files with the most churn."), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: 12.5,
      lineHeight: 1.5,
      color: "var(--color-grey-900)",
      margin: "14px 0 0",
      ...reveal(0.26)
    }
  }, "I'll analyze the recent activity in the repository to produce a comprehensive weekly digest."), /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 10.5,
      color: "var(--color-grey-700)",
      margin: "8px 0 12px",
      ...reveal(0.30)
    }
  }, "\u203A Adding ", todos.length, " todo items")), /*#__PURE__*/React.createElement("div", {
    style: {
      margin: "0 14px 0",
      borderTop: `0.5px solid ${HAIR}`,
      paddingTop: 11,
      ...reveal(0.36)
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 8,
      marginBottom: 10
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 7,
      height: 7,
      borderRadius: "50%",
      background: ACC
    }
  }), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: 12.5,
      color: INK
    }
  }, "Processing todos\u2026"), /*#__PURE__*/React.createElement("span", {
    style: {
      marginLeft: "auto",
      fontFamily: "var(--font-mono)",
      fontSize: 11,
      color: "var(--color-grey-700)"
    }
  }, Math.min(done + (done < todos.length ? 1 : 0), todos.length), "/", todos.length), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 10.5,
      color: "var(--color-grey-700)",
      border: `0.5px solid ${HAIR}`,
      borderRadius: 5,
      padding: "2px 6px"
    }
  }, "Stop")), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      flexDirection: "column",
      gap: 9,
      paddingBottom: 18
    }
  }, todos.map((todo, i) => {
    const isDone = i < done;
    const active = i === done;
    return /*#__PURE__*/React.createElement("div", {
      key: todo,
      style: {
        display: "flex",
        alignItems: "center",
        gap: 9,
        opacity: i <= done ? 1 : 0.45
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        fontFamily: "var(--font-mono)",
        fontSize: 11,
        color: "var(--color-grey-600)",
        width: 10,
        flex: "none"
      }
    }, i + 1, "."), /*#__PURE__*/React.createElement("span", {
      style: {
        fontFamily: "var(--font-sans)",
        fontSize: 12,
        color: INK,
        flex: 1,
        whiteSpace: "nowrap",
        overflow: "hidden",
        textOverflow: "ellipsis"
      }
    }, todo), /*#__PURE__*/React.createElement("span", {
      style: {
        width: 15,
        height: 15,
        borderRadius: "50%",
        flex: "none",
        display: "grid",
        placeItems: "center",
        background: isDone ? ACC : "transparent",
        border: isDone ? "none" : `1.5px solid ${active ? ACC : "var(--color-grey-500)"}`
      }
    }, isDone && /*#__PURE__*/React.createElement("svg", {
      width: "9",
      height: "9",
      viewBox: "0 0 12 12",
      fill: "none"
    }, /*#__PURE__*/React.createElement("path", {
      d: "M2.5 6.3 L5 8.5 L9.5 3.7",
      stroke: "#fff",
      strokeWidth: "1.8",
      strokeLinecap: "round",
      strokeLinejoin: "round"
    })), active && /*#__PURE__*/React.createElement("span", {
      style: {
        width: 5,
        height: 5,
        borderRadius: "50%",
        background: ACC
      }
    })));
  })))));
}
function SandboxDemo() {
  const [t, setT] = React.useState(0);
  React.useEffect(() => {
    const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduce) {
      setT(0.7);
      return;
    }
    let raf,
      start = null;
    const PERIOD = 5200;
    const tick = ts => {
      if (start == null) start = ts;
      setT((ts - start) % PERIOD / PERIOD);
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, []);
  const inP = Math.min(1, t / 0.16);
  const outP = t > 0.78 ? Math.min(1, (t - 0.78) / 0.14) : 0;
  const vis = Math.max(0, inP - outP);
  const scale = 0.86 + 0.14 * vis;
  const blur = (1 - vis) * 9;
  const pulse = (Math.sin(t * Math.PI * 2 * 2) + 1) / 2; // 0..1
  const halo = 4 + pulse * 8;
  return /*#__PURE__*/React.createElement("div", {
    style: {
      ...PANEL,
      background: "var(--color-porcelain-grey)",
      padding: 0,
      position: "relative",
      overflow: "hidden"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      position: "absolute",
      inset: 0,
      display: "grid",
      placeItems: "center",
      opacity: vis,
      filter: `blur(${blur}px)`,
      transform: `scale(${scale})`
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      position: "absolute",
      inset: 22,
      borderRadius: 42,
      background: "color-mix(in srgb, var(--color-pistachio-green) 46%, var(--color-white))"
    }
  }), /*#__PURE__*/React.createElement("div", {
    style: {
      ...card,
      position: "relative",
      width: "80%",
      padding: "20px 22px",
      display: "flex",
      alignItems: "center",
      gap: 16
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 50,
      height: 50,
      borderRadius: 13,
      flex: "none",
      background: "color-mix(in srgb, var(--color-pistachio-green) 55%, var(--color-white))",
      display: "grid",
      placeItems: "center"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 14,
      height: 14,
      borderRadius: "50%",
      background: ACC,
      boxShadow: `0 0 0 ${halo}px color-mix(in srgb, ${ACC} 26%, transparent)`
    }
  })), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.125rem",
      color: INK
    }
  }, "Development Environment"), /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1rem",
      color: "var(--color-grey-600)",
      marginTop: 3
    }
  }, "Started")))));
}
function EditDemo() {
  const [t, setT] = React.useState(0);
  React.useEffect(() => {
    const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduce) {
      setT(0.6);
      return;
    }
    let raf,
      start = null;
    const PERIOD = 6800;
    const tick = ts => {
      if (start == null) start = ts;
      setT((ts - start) % PERIOD / PERIOD);
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, []);
  const caretOn = Math.sin(t * Math.PI * 2 * 5) > 0;
  const ap = Math.max(0, Math.min(1, (t - 0.08) / 0.30));
  const retract = t > 0.85 ? Math.max(0, Math.min(1, (t - 0.85) / 0.12)) : 0;
  const prog = ap * (1 - retract);
  const selOp = Math.max(0, Math.min(1, (prog - 0.55) / 0.3));
  const GREY = "var(--color-grey-700)",
    RED = "var(--color-red-500)";
  const lineH = 30,
    humanIdx = 2,
    agentIdx = 5;
  const ax = 54 + prog * 78;
  const ay = 6 + prog * (humanIdx * lineH + 4);
  const lines = [/*#__PURE__*/React.createElement("span", null, /*#__PURE__*/React.createElement("span", {
    style: {
      color: GREY
    }
  }, "function"), " deleteContext() {"), /*#__PURE__*/React.createElement("span", null, "  setSelectedContext(", /*#__PURE__*/React.createElement("span", {
    style: {
      color: GREY
    }
  }, "null"), ")"), /*#__PURE__*/React.createElement("span", null, "  setContextAssoc(id)"), /*#__PURE__*/React.createElement("span", null, "}"), /*#__PURE__*/React.createElement("span", null, "\u00a0"), /*#__PURE__*/React.createElement("span", null, /*#__PURE__*/React.createElement("span", {
    style: {
      color: RED
    }
  }, "return"), " ("), /*#__PURE__*/React.createElement("span", null, "  <", /*#__PURE__*/React.createElement("span", {
    style: {
      color: ACC
    }
  }, "Chip"), " icon={Git}>"), /*#__PURE__*/React.createElement("span", null, "    {context.owner}")];
  return /*#__PURE__*/React.createElement("div", {
    style: {
      ...PANEL,
      background: "var(--color-white)",
      padding: 0,
      position: "relative",
      overflow: "hidden",
      display: "flex",
      flexDirection: "column"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 6,
      padding: "0 16px",
      borderBottom: `0.5px solid ${HAIR}`,
      height: 44,
      flex: "none"
    }
  }, [0, 1, 2].map(i => /*#__PURE__*/React.createElement("span", {
    key: i,
    style: {
      width: 9,
      height: 9,
      borderRadius: "50%",
      background: "#e1e1e1"
    }
  })), /*#__PURE__*/React.createElement("span", {
    style: {
      marginLeft: 10,
      fontFamily: "var(--font-mono)",
      fontSize: 12,
      color: "var(--color-grey-700)"
    }
  }, "context.tsx"), /*#__PURE__*/React.createElement("span", {
    style: {
      marginLeft: "auto",
      display: "flex",
      alignItems: "center",
      gap: 7
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      display: "flex"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 17,
      height: 17,
      borderRadius: "50%",
      background: ACC,
      border: "1.5px solid var(--color-white)"
    }
  }), /*#__PURE__*/React.createElement("span", {
    style: {
      width: 17,
      height: 17,
      borderRadius: "50%",
      background: INK,
      border: "1.5px solid var(--color-white)",
      marginLeft: -6
    }
  })), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 11,
      color: "var(--color-grey-700)"
    }
  }, "2 editing"))), /*#__PURE__*/React.createElement("div", {
    style: {
      flex: 1,
      display: "flex",
      alignItems: "center"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      position: "relative",
      width: "100%",
      fontFamily: "var(--font-mono)",
      fontSize: 13.5
    }
  }, lines.map((code, i) => {
    const isAgent = i === agentIdx,
      isHuman = i === humanIdx;
    return /*#__PURE__*/React.createElement("div", {
      key: i,
      style: {
        position: "relative",
        height: lineH,
        display: "flex",
        alignItems: "center",
        padding: "0 22px",
        whiteSpace: "pre",
        color: INK,
        background: isAgent ? `color-mix(in srgb, ${ACC} 13%, transparent)` : isHuman ? `rgba(90,90,90,${0.16 * selOp})` : "transparent",
        boxShadow: isAgent ? `inset 3px 0 0 ${ACC}` : "none"
      }
    }, code, isAgent && /*#__PURE__*/React.createElement("span", {
      style: {
        display: "inline-block",
        width: 2,
        height: 14,
        marginLeft: 1,
        background: ACC,
        opacity: caretOn ? 0.9 : 0,
        verticalAlign: "middle"
      }
    }), isAgent && /*#__PURE__*/React.createElement("span", {
      style: {
        position: "absolute",
        left: 20,
        top: -8,
        fontFamily: "var(--font-sans)",
        fontSize: 10,
        color: "#fff",
        background: ACC,
        borderRadius: 4,
        padding: "2px 7px",
        whiteSpace: "nowrap",
        zIndex: 4
      }
    }, "Hypervisor"));
  }), /*#__PURE__*/React.createElement("svg", {
    width: "18",
    height: "18",
    viewBox: "0 0 24 24",
    "aria-hidden": "true",
    style: {
      position: "absolute",
      left: ax,
      top: ay,
      filter: "drop-shadow(0 1.5px 2px rgba(0,0,0,0.28))",
      zIndex: 5
    }
  }, /*#__PURE__*/React.createElement("path", {
    d: "M5 3 L19 12 L12.2 13.2 L15.8 20.4 L12.9 21.7 L9.3 14.4 L5 18.2 Z",
    fill: "#fff",
    stroke: INK,
    strokeWidth: "1.3",
    strokeLinejoin: "round"
  })), /*#__PURE__*/React.createElement("span", {
    style: {
      position: "absolute",
      left: ax + 13,
      top: ay + 15,
      fontFamily: "var(--font-sans)",
      fontSize: 9.5,
      color: "#fff",
      background: INK,
      borderRadius: 4,
      padding: "2px 6px",
      opacity: selOp,
      zIndex: 5,
      whiteSpace: "nowrap"
    }
  }, "You"))));
}
function TriggerDemo() {
  const [t, setT] = React.useState(0);
  React.useEffect(() => {
    const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduce) {
      setT(0.6);
      return;
    }
    let raf,
      start = null;
    const PERIOD = 5600;
    const tick = ts => {
      if (start == null) start = ts;
      setT((ts - start) % PERIOD / PERIOD);
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, []);
  const items = ["Webhooks", "Scheduled", "Pull Requests", "Manual"];
  const active = Math.min(items.length - 1, Math.floor(t * (items.length + 0.4)));
  const spin = t * 1440 % 360;
  return /*#__PURE__*/React.createElement("div", {
    style: {
      ...PANEL,
      background: "color-mix(in srgb, var(--color-pistachio-green) 38%, var(--color-white))",
      display: "flex",
      flexDirection: "column",
      justifyContent: "center",
      alignItems: "center",
      gap: 14
    }
  }, items.map((label, i) => {
    const fired = i < active;
    const firing = i === active;
    return /*#__PURE__*/React.createElement("div", {
      key: label,
      style: {
        ...card,
        width: "84%",
        borderRadius: 999,
        padding: "15px 22px",
        display: "flex",
        alignItems: "center",
        gap: 13,
        transform: firing ? "scale(1.02)" : "scale(1)",
        boxShadow: firing ? "var(--shadow-md)" : "var(--shadow-xs)",
        transition: "transform 0.3s, box-shadow 0.3s"
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        width: 20,
        height: 20,
        flex: "none",
        display: "grid",
        placeItems: "center"
      }
    }, fired ? /*#__PURE__*/React.createElement("span", {
      style: {
        width: 18,
        height: 18,
        borderRadius: "50%",
        background: ACC,
        display: "grid",
        placeItems: "center"
      }
    }, /*#__PURE__*/React.createElement("svg", {
      width: "10",
      height: "10",
      viewBox: "0 0 12 12",
      fill: "none"
    }, /*#__PURE__*/React.createElement("path", {
      d: "M2.5 6.3 L5 8.5 L9.5 3.7",
      stroke: "#fff",
      strokeWidth: "1.8",
      strokeLinecap: "round",
      strokeLinejoin: "round"
    }))) : firing ? /*#__PURE__*/React.createElement("svg", {
      width: "18",
      height: "18",
      viewBox: "0 0 18 18",
      style: {
        transform: `rotate(${spin}deg)`
      }
    }, /*#__PURE__*/React.createElement("circle", {
      cx: "9",
      cy: "9",
      r: "7",
      fill: "none",
      stroke: ACC,
      strokeWidth: "2",
      strokeDasharray: "11 33",
      strokeLinecap: "round"
    })) : /*#__PURE__*/React.createElement("svg", {
      width: "18",
      height: "18",
      viewBox: "0 0 18 18"
    }, /*#__PURE__*/React.createElement("circle", {
      cx: "9",
      cy: "9",
      r: "7",
      fill: "none",
      stroke: "var(--color-grey-500)",
      strokeWidth: "1.5",
      strokeDasharray: "0.5 3.5",
      strokeLinecap: "round"
    }))), /*#__PURE__*/React.createElement("span", {
      style: {
        fontFamily: "var(--font-sans)",
        fontSize: "1.0625rem",
        color: INK
      }
    }, label));
  }));
}
const DEMOS = {
  parallel: ParallelDemo,
  decoupled: DecoupledDemo,
  sandbox: SandboxDemo,
  edit: EditDemo,
  trigger: TriggerDemo
};

/* ========================= page ========================= */
function BgHero() {
  return /*#__PURE__*/React.createElement("section", {
    style: {
      ...bawrap,
      paddingTop: "4rem",
      textAlign: "center",
      display: "flex",
      flexDirection: "column",
      alignItems: "center"
    }
  }, /*#__PURE__*/React.createElement(BgEyebrow, {
    color: "var(--color-link-green)"
  }, "Solutions \xB7 Background work"), /*#__PURE__*/React.createElement("h1", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "3.5rem",
      lineHeight: 1.05,
      letterSpacing: "-0.02em",
      margin: "1.25rem 0 0",
      maxWidth: "20ch",
      color: INK
    }
  }, "Fleets of agents, working while you don't"), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.1875rem",
      color: "var(--color-grey-800)",
      marginTop: "1.25rem",
      maxWidth: "54ch",
      lineHeight: 1.5
    }
  }, "Task in, pull request out. Delegate work to autonomous agents that run on Hypervisor's infrastructure \u2014 sandboxed, governed, and receipted \u2014 across one repo or five hundred."));
}
function FeatureBlock() {
  const [active, setActive] = React.useState(0);
  const tab = TABS[active];
  const Demo = DEMOS[tab.demo];
  return /*#__PURE__*/React.createElement("section", {
    style: {
      ...bawrap,
      paddingTop: "5rem"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      background: "var(--color-white)",
      border: `0.5px solid ${HAIR}`,
      borderRadius: "var(--radius-card)",
      padding: "2.5rem",
      display: "grid",
      gridTemplateColumns: "16rem 1fr",
      gap: "2.5rem",
      alignItems: "start"
    }
  }, /*#__PURE__*/React.createElement("ul", {
    style: {
      listStyle: "none",
      margin: 0,
      padding: 0,
      display: "flex",
      flexDirection: "column",
      gap: 4
    }
  }, TABS.map((t, i) => {
    const on = i === active;
    return /*#__PURE__*/React.createElement("li", {
      key: t.label
    }, /*#__PURE__*/React.createElement("button", {
      onClick: () => setActive(i),
      style: {
        width: "100%",
        textAlign: "left",
        display: "flex",
        alignItems: "center",
        gap: 11,
        padding: "12px 14px",
        borderRadius: "var(--radius-lg)",
        border: "none",
        cursor: "pointer",
        background: on ? "var(--color-porcelain-grey)" : "transparent",
        color: on ? INK : "var(--color-grey-800)",
        fontFamily: "var(--font-sans)",
        fontSize: "0.9375rem",
        fontWeight: on ? 500 : 400
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        color: on ? ACC : "var(--color-grey-600)",
        display: "grid",
        placeItems: "center"
      }
    }, ICONS[t.icon]), t.label));
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "1fr 1.15fr",
      gap: "2.5rem",
      alignItems: "center"
    }
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("h2", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "2.25rem",
      letterSpacing: "-0.02em",
      lineHeight: 1.1,
      margin: 0,
      color: INK
    }
  }, tab.heading), tab.body.map((p, i) => /*#__PURE__*/React.createElement("p", {
    key: i,
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.0625rem",
      color: "var(--color-grey-800)",
      marginTop: i === 0 ? "1.25rem" : "1rem",
      lineHeight: 1.5,
      maxWidth: "40ch"
    }
  }, p))), /*#__PURE__*/React.createElement(Demo, null))));
}

/* ===================== What teams automate first ===================== */
const AUTO_ICON = {
  cve: /*#__PURE__*/React.createElement("svg", {
    width: "17",
    height: "17",
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: "1.6",
    strokeLinecap: "round",
    strokeLinejoin: "round"
  }, /*#__PURE__*/React.createElement("path", {
    d: "M12 3 L19 6 V11 C19 16 15.5 19.5 12 21 C8.5 19.5 5 16 5 11 V6 Z"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M9 12 L11 14 L15 9.5"
  })),
  review: /*#__PURE__*/React.createElement("svg", {
    width: "17",
    height: "17",
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: "1.6",
    strokeLinecap: "round",
    strokeLinejoin: "round"
  }, /*#__PURE__*/React.createElement("path", {
    d: "M21 11.5 a8.5 8.5 0 1 1 -4.5 -7.5 L21 4"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M21 4 V8 H17"
  })),
  modernize: /*#__PURE__*/React.createElement("svg", {
    width: "17",
    height: "17",
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: "1.6",
    strokeLinecap: "round",
    strokeLinejoin: "round"
  }, /*#__PURE__*/React.createElement("path", {
    d: "M3 8 H15 a4 4 0 0 1 0 8 H9"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M6 5 L3 8 L6 11"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M18 19 L21 16 L18 13"
  }))
};
function useClock(period) {
  const [t, setT] = React.useState(0);
  React.useEffect(() => {
    const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduce) {
      setT(0.7);
      return;
    }
    let raf,
      start = null;
    const tick = ts => {
      if (start == null) start = ts;
      setT((ts - start) % period / period);
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, []);
  return t;
}
function CVEDemo() {
  const t = useClock(7000);
  const steps = [["Scheduled scan", "Run on a schedule or trigger manually for specific repositories.", true], ["Scan dependencies", "Run security scanners to identify CVEs and outdated packages."], ["Apply updates", "Update vulnerable or outdated dependencies. Handle breaking changes."], ["Run tests", "Execute the test suite to validate the updates."], ["Open PR with fix", "Create a pull request with dependency updates and CVE details."]];
  const active = Math.min(steps.length - 1, Math.floor(t * (steps.length + 0.6)));
  return /*#__PURE__*/React.createElement("div", {
    style: {
      ...PANEL,
      background: "var(--color-porcelain-grey)",
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      padding: "0 26px"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      width: "100%",
      display: "flex",
      flexDirection: "column",
      gap: 8
    }
  }, steps.map(([title, desc, trig], i) => {
    const done = i < active;
    const on = i === active;
    return /*#__PURE__*/React.createElement("div", {
      key: i,
      style: {
        ...card,
        padding: "13px 16px",
        opacity: on || done ? 1 : Math.max(0.45, 0.95 - (i - active) * 0.16),
        boxShadow: on ? "var(--shadow-md)" : "var(--shadow-xs)",
        transform: on ? "scale(1.015)" : "scale(1)",
        transition: "opacity 0.3s, transform 0.3s, box-shadow 0.3s"
      }
    }, trig && /*#__PURE__*/React.createElement("span", {
      style: {
        display: "inline-flex",
        alignItems: "center",
        gap: 5,
        background: "color-mix(in srgb, var(--color-pistachio-green) 55%, var(--color-white))",
        color: "var(--color-green-700, #1f7a4d)",
        borderRadius: 6,
        padding: "2px 8px",
        fontFamily: "var(--font-mono)",
        fontSize: 10.5,
        marginBottom: 7
      }
    }, /*#__PURE__*/React.createElement("svg", {
      width: "10",
      height: "10",
      viewBox: "0 0 24 24",
      fill: "none",
      stroke: "currentColor",
      strokeWidth: "2"
    }, /*#__PURE__*/React.createElement("circle", {
      cx: "12",
      cy: "12",
      r: "9"
    }), /*#__PURE__*/React.createElement("path", {
      d: "M10 8 L16 12 L10 16 Z",
      fill: "currentColor",
      stroke: "none"
    })), "Trigger"), /*#__PURE__*/React.createElement("div", {
      style: {
        display: "flex",
        alignItems: "center",
        gap: 9
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        fontFamily: "var(--font-sans)",
        fontSize: "1.0625rem",
        color: INK
      }
    }, title), done && /*#__PURE__*/React.createElement("span", {
      style: {
        marginLeft: "auto",
        width: 16,
        height: 16,
        borderRadius: "50%",
        background: ACC,
        display: "grid",
        placeItems: "center",
        flex: "none"
      }
    }, /*#__PURE__*/React.createElement("svg", {
      width: "9",
      height: "9",
      viewBox: "0 0 12 12",
      fill: "none"
    }, /*#__PURE__*/React.createElement("path", {
      d: "M2.5 6.3 L5 8.5 L9.5 3.7",
      stroke: "#fff",
      strokeWidth: "1.8",
      strokeLinecap: "round",
      strokeLinejoin: "round"
    }))), on && /*#__PURE__*/React.createElement("span", {
      style: {
        marginLeft: "auto",
        width: 17,
        height: 17,
        viewBox: "0 0 18 18",
        flex: "none"
      }
    }, /*#__PURE__*/React.createElement("svg", {
      width: "17",
      height: "17",
      viewBox: "0 0 18 18",
      style: {
        transform: `rotate(${t * 1440 % 360}deg)`
      }
    }, /*#__PURE__*/React.createElement("circle", {
      cx: "9",
      cy: "9",
      r: "7",
      fill: "none",
      stroke: ACC,
      strokeWidth: "2",
      strokeDasharray: "11 33",
      strokeLinecap: "round"
    })))), on && /*#__PURE__*/React.createElement("div", {
      style: {
        fontFamily: "var(--font-sans)",
        fontSize: "0.8125rem",
        color: "var(--color-grey-700)",
        marginTop: 5,
        lineHeight: 1.4
      }
    }, desc));
  })));
}
function ModernizeDemo() {
  const t = useClock(7000);
  const rows = [["JAVA 8 \u2192 JAVA 17", "Repository 01 \u00b7 1 min ago"], ["COBOL \u2192 JAVA", "Repository 02 \u00b7 30 sec ago"], ["JAVA 8 \u2192 JAVA 17", "AetherNet \u00b7 started 10s ago"], ["JAVA 8 \u2192 JAVA 17", "Project Phoenix \u00b7 started 9s ago"], ["JAVA 8 \u2192 JAVA 17", "InfernoCore \u00b7 started 8s ago"], ["JAVA 8 \u2192 JAVA 17", "PyroLink \u00b7 started 7s ago"]];
  const done = Math.max(0, Math.min(rows.length, Math.floor((t - 0.12) / 0.12)));
  const count = 1 + done + Math.floor(t * 9);
  const spin = t * 1440 % 360;
  return /*#__PURE__*/React.createElement("div", {
    style: {
      ...PANEL,
      background: "color-mix(in srgb, var(--color-pistachio-green) 30%, var(--color-porcelain-grey))",
      padding: 0,
      overflow: "hidden"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 9,
      padding: "16px 18px",
      borderBottom: `0.5px solid ${HAIR}`
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 8,
      height: 8,
      borderRadius: "50%",
      background: ACC,
      flex: "none"
    }
  }), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: 14,
      color: INK
    }
  }, "Migration in progress\u2026"), /*#__PURE__*/React.createElement("span", {
    style: {
      marginLeft: "auto",
      fontFamily: "var(--font-mono)",
      fontSize: 12,
      color: "var(--color-grey-700)",
      background: "var(--color-white)",
      border: `0.5px solid ${HAIR}`,
      borderRadius: 999,
      padding: "3px 10px"
    }
  }, count, "/210")), /*#__PURE__*/React.createElement("div", {
    style: {
      padding: "6px 0",
      WebkitMaskImage: "linear-gradient(180deg, #000 60%, transparent)",
      maskImage: "linear-gradient(180deg, #000 60%, transparent)"
    }
  }, rows.map(([title, meta], i) => {
    const ok = i < done;
    const active = i === done;
    return /*#__PURE__*/React.createElement("div", {
      key: i,
      style: {
        display: "flex",
        alignItems: "center",
        gap: 12,
        padding: "11px 18px",
        opacity: i <= done ? 1 : Math.max(0.2, 0.85 - (i - done) * 0.22)
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        fontFamily: "var(--font-mono)",
        fontSize: 13,
        color: "var(--color-grey-600)",
        width: 16,
        flex: "none"
      }
    }, i + 1, "."), /*#__PURE__*/React.createElement("div", {
      style: {
        flex: 1,
        minWidth: 0
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        fontFamily: "var(--font-sans)",
        fontSize: "0.9375rem",
        color: INK,
        whiteSpace: "nowrap"
      }
    }, title), /*#__PURE__*/React.createElement("div", {
      style: {
        fontFamily: "var(--font-sans)",
        fontSize: "0.75rem",
        color: "var(--color-grey-600)",
        marginTop: 2,
        whiteSpace: "nowrap",
        overflow: "hidden",
        textOverflow: "ellipsis"
      }
    }, meta)), /*#__PURE__*/React.createElement("span", {
      style: {
        width: 18,
        height: 18,
        flex: "none",
        display: "grid",
        placeItems: "center"
      }
    }, ok ? /*#__PURE__*/React.createElement("span", {
      style: {
        width: 18,
        height: 18,
        borderRadius: "50%",
        background: ACC,
        display: "grid",
        placeItems: "center"
      }
    }, /*#__PURE__*/React.createElement("svg", {
      width: "10",
      height: "10",
      viewBox: "0 0 12 12",
      fill: "none"
    }, /*#__PURE__*/React.createElement("path", {
      d: "M2.5 6.3 L5 8.5 L9.5 3.7",
      stroke: "#fff",
      strokeWidth: "1.8",
      strokeLinecap: "round",
      strokeLinejoin: "round"
    }))) : active ? /*#__PURE__*/React.createElement("svg", {
      width: "17",
      height: "17",
      viewBox: "0 0 18 18",
      style: {
        transform: `rotate(${spin}deg)`
      }
    }, /*#__PURE__*/React.createElement("circle", {
      cx: "9",
      cy: "9",
      r: "7",
      fill: "none",
      stroke: ACC,
      strokeWidth: "2",
      strokeDasharray: "11 33",
      strokeLinecap: "round"
    })) : /*#__PURE__*/React.createElement("svg", {
      width: "17",
      height: "17",
      viewBox: "0 0 18 18"
    }, /*#__PURE__*/React.createElement("circle", {
      cx: "9",
      cy: "9",
      r: "7",
      fill: "none",
      stroke: "var(--color-grey-500)",
      strokeWidth: "1.5",
      strokeDasharray: "0.5 3.5",
      strokeLinecap: "round"
    }))));
  })));
}
function ReviewDemo() {
  const t = useClock(6500);
  const rv = (s, d) => Math.max(0, Math.min(1, (t - s) / (d || 0.08)));
  const diff = ["export async function up(knex: Knex) {", "  await knex.schema.alterTable('users', t => {", "    t.index(['org_id', 'last_active']);\u2026", "  });\u2026"];
  return /*#__PURE__*/React.createElement("div", {
    style: {
      ...PANEL,
      background: "color-mix(in srgb, var(--color-pistachio-green) 26%, var(--color-white))",
      padding: 0,
      display: "flex",
      flexDirection: "column",
      overflow: "hidden"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 6,
      padding: "0 16px",
      height: 40,
      flex: "none",
      borderBottom: `0.5px solid ${HAIR}`,
      background: "var(--color-white)"
    }
  }, [0, 1, 2].map(i => /*#__PURE__*/React.createElement("span", {
    key: i,
    style: {
      width: 9,
      height: 9,
      borderRadius: "50%",
      background: "#dcdcdc"
    }
  })), /*#__PURE__*/React.createElement("span", {
    style: {
      margin: "0 auto",
      fontFamily: "var(--font-mono)",
      fontSize: 11.5,
      color: "var(--color-grey-700)"
    }
  }, "Hypervisor Code Review")), /*#__PURE__*/React.createElement("div", {
    style: {
      flex: 1,
      background: "var(--color-white)",
      margin: "14px",
      borderRadius: 12,
      border: `0.5px solid ${HAIR}`,
      padding: "16px 18px",
      display: "flex",
      flexDirection: "column",
      opacity: rv(0.05)
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 10
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 28,
      height: 28,
      borderRadius: 8,
      background: INK,
      display: "grid",
      placeItems: "center",
      flex: "none",
      color: "#fff"
    }
  }, /*#__PURE__*/React.createElement(BgLogo, {
    size: 16
  })), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: 13.5,
      color: INK,
      fontWeight: 600
    }
  }, "Hypervisor Automations"), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: 12.5,
      color: "var(--color-grey-600)"
    }
  }, "commented 30 min ago")), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      marginTop: 14,
      opacity: rv(0.18)
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 11.5,
      color: INK
    }
  }, "db/migrations/add_users_org_id_index.ts"), /*#__PURE__*/React.createElement("span", {
    style: {
      marginLeft: "auto",
      fontFamily: "var(--font-mono)",
      fontSize: 11.5,
      color: ACC
    }
  }, "+4")), /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: 8,
      borderRadius: 8,
      overflow: "hidden",
      border: `0.5px solid ${HAIR}`,
      opacity: rv(0.28)
    }
  }, diff.map((c, i) => /*#__PURE__*/React.createElement("div", {
    key: i,
    style: {
      display: "flex",
      gap: 8,
      padding: "3px 10px",
      background: "color-mix(in srgb, var(--color-pistachio-green) 16%, var(--color-white))",
      fontFamily: "var(--font-mono)",
      fontSize: 11,
      color: "var(--color-green-700, #1f7a4d)",
      whiteSpace: "nowrap",
      overflow: "hidden"
    }
  }, /*#__PURE__*/React.createElement("span", null, "+"), c)), /*#__PURE__*/React.createElement("div", {
    style: {
      padding: "4px 10px",
      fontFamily: "var(--font-mono)",
      fontSize: 10.5,
      color: "var(--color-grey-600)",
      background: "var(--color-white)"
    }
  }, "-- migrate: add index for user lookup")), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: 13,
      color: "var(--color-grey-900)",
      lineHeight: 1.5,
      marginTop: 14,
      opacity: rv(0.42)
    }
  }, "This query runs without an index on ", /*#__PURE__*/React.createElement("span", {
    style: {
      background: "var(--color-porcelain-grey)",
      borderRadius: 4,
      padding: "1px 5px",
      fontFamily: "var(--font-mono)",
      fontSize: 12
    }
  }, "user_id"), " \u2014 causes full table scans in production. Added index and updated the migration."), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: 13,
      color: INK,
      marginTop: 10,
      opacity: rv(0.55),
      display: "flex",
      alignItems: "center",
      gap: 7
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 15,
      height: 15,
      borderRadius: "50%",
      background: ACC,
      display: "grid",
      placeItems: "center"
    }
  }, /*#__PURE__*/React.createElement("svg", {
    width: "9",
    height: "9",
    viewBox: "0 0 12 12",
    fill: "none"
  }, /*#__PURE__*/React.createElement("path", {
    d: "M2.5 6.3 L5 8.5 L9.5 3.7",
    stroke: "#fff",
    strokeWidth: "1.8",
    strokeLinecap: "round",
    strokeLinejoin: "round"
  }))), "Tests pass.")));
}
const AUTO_TABS = [{
  icon: "cve",
  label: "CVE remediation",
  demo: CVEDemo,
  heading: "CVE remediation",
  body: ["Scanners find vulnerabilities. Hypervisor patches them across your codebase, in parallel.", "Scan, apply updates, run tests, and open a PR with the fix — every step scoped and receipted."]
}, {
  icon: "review",
  label: "Code review on every PR",
  demo: ReviewDemo,
  heading: "Code review on every PR",
  body: ["Hypervisor clones, compiles, runs tests, and fixes issues before your team opens the diff.", "It comments with evidence and a working change — not just a flag."]
}, {
  icon: "modernize",
  label: "Code modernization",
  demo: ModernizeDemo,
  heading: "Code modernization",
  body: ["Migrations that sat in backlogs for years — done in days across hundreds of repos.", "One intent fans out into a tracked fleet: JAVA 8 to 17, COBOL to JAVA, framework upgrades."]
}];
function WhatTeamsAutomate() {
  const [active, setActive] = React.useState(0);
  const tab = AUTO_TABS[active];
  const Demo = tab.demo;
  return /*#__PURE__*/React.createElement("section", {
    style: {
      ...bawrap,
      paddingTop: "8rem"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      justifyContent: "space-between",
      alignItems: "flex-end",
      flexWrap: "wrap",
      gap: "1rem",
      marginBottom: "2.5rem"
    }
  }, /*#__PURE__*/React.createElement("h2", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "2.5rem",
      letterSpacing: "-0.02em",
      lineHeight: 1.08,
      margin: 0,
      color: INK
    }
  }, "What teams automate first"), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.0625rem",
      color: "var(--color-grey-700)",
      margin: 0,
      maxWidth: "30ch",
      textAlign: "right"
    }
  }, "Start with repetitive, well-scoped tasks where the blast radius is small.")), /*#__PURE__*/React.createElement("div", {
    style: {
      background: "var(--color-white)",
      border: `0.5px solid ${HAIR}`,
      borderRadius: "var(--radius-card)",
      padding: "2.5rem",
      display: "grid",
      gridTemplateColumns: "16rem 1fr",
      gap: "2.5rem",
      alignItems: "start"
    }
  }, /*#__PURE__*/React.createElement("ul", {
    style: {
      listStyle: "none",
      margin: 0,
      padding: 0,
      display: "flex",
      flexDirection: "column",
      gap: 4
    }
  }, AUTO_TABS.map((tb, i) => {
    const on = i === active;
    return /*#__PURE__*/React.createElement("li", {
      key: tb.label
    }, /*#__PURE__*/React.createElement("button", {
      onClick: () => setActive(i),
      style: {
        width: "100%",
        textAlign: "left",
        display: "flex",
        alignItems: "flex-start",
        gap: 11,
        padding: "14px",
        borderRadius: "var(--radius-lg)",
        border: "none",
        cursor: "pointer",
        background: on ? "var(--color-porcelain-grey)" : "transparent"
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        color: on ? ACC : "var(--color-grey-600)",
        display: "grid",
        placeItems: "center",
        marginTop: 1
      }
    }, AUTO_ICON[tb.icon]), /*#__PURE__*/React.createElement("span", null, /*#__PURE__*/React.createElement("span", {
      style: {
        display: "block",
        fontFamily: "var(--font-sans)",
        fontSize: "0.9375rem",
        fontWeight: on ? 600 : 500,
        color: INK
      }
    }, tb.heading), /*#__PURE__*/React.createElement("span", {
      style: {
        display: "block",
        fontFamily: "var(--font-sans)",
        fontSize: "0.8125rem",
        color: "var(--color-grey-700)",
        marginTop: 3,
        lineHeight: 1.4
      }
    }, tb.body[0]), on && /*#__PURE__*/React.createElement("span", {
      style: {
        display: "inline-block",
        marginTop: 8
      }
    }, /*#__PURE__*/React.createElement(BgLink, {
      href: "#"
    }, "Learn more")))));
  })), /*#__PURE__*/React.createElement(Demo, null)));
}
function HandoffOutro() {
  const t = useClock(6000);
  const lidP = Math.max(0, Math.min(1, (Math.sin(t * Math.PI * 2 - Math.PI / 2) + 1) / 2)); // 0 open → 1 closed
  const closed = lidP > 0.55;
  const pulse = (Math.sin(t * Math.PI * 2 * 2) + 1) / 2;
  const stats = [["10x", "More tasks in parallel"], ["0%", "Local compute used"], ["24/7", "Runs while you sleep"]];
  return /*#__PURE__*/React.createElement("section", {
    style: {
      ...bawrap,
      paddingTop: "8rem"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "0.85fr 1.15fr",
      gap: "4rem",
      alignItems: "center"
    }
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("h2", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "2.5rem",
      letterSpacing: "-0.02em",
      lineHeight: 1.08,
      margin: 0,
      color: INK
    }
  }, "Hand off work, walk away"), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.0625rem",
      color: "var(--color-grey-800)",
      marginTop: "1.25rem",
      lineHeight: 1.55,
      maxWidth: "42ch"
    }
  }, "Hand off a task and close your laptop as Hypervisor runs in its own cloud environment with the full toolchain, test suite, and dependencies. You can even pick up the work from your phone."), /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: "1.75rem"
    }
  }, /*#__PURE__*/React.createElement(BgLink, {
    href: "#"
  }, "Browse automation templates"))), /*#__PURE__*/React.createElement("div", {
    style: {
      background: "color-mix(in srgb, var(--color-pistachio-green) 22%, var(--color-porcelain-grey))",
      border: `0.5px solid ${HAIR}`,
      borderRadius: "var(--radius-card)",
      height: 320,
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      gap: 46,
      overflow: "hidden"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      width: 150,
      display: "flex",
      flexDirection: "column",
      alignItems: "center"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      width: 132,
      height: 84,
      position: "relative",
      perspective: 460
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      position: "absolute",
      inset: 0,
      ...card,
      borderRadius: 8,
      display: "grid",
      placeItems: "center",
      overflow: "hidden"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 10,
      color: "var(--color-grey-600)",
      opacity: 1 - lidP
    }
  }, "handing off\u2026")), /*#__PURE__*/React.createElement("div", {
    style: {
      position: "absolute",
      inset: 0,
      background: "var(--color-onyx-black)",
      borderRadius: 8,
      transformOrigin: "bottom",
      transform: `rotateX(${-90 + lidP * 90}deg)`,
      opacity: 0.96
    }
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      width: 150,
      height: 7,
      borderRadius: "0 0 6px 6px",
      background: "var(--color-grey-400)"
    }
  }), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 10.5,
      color: "var(--color-grey-700)",
      marginTop: 10
    }
  }, closed ? "lid closed" : "you, leaving")), /*#__PURE__*/React.createElement("svg", {
    width: "64",
    height: "40",
    viewBox: "0 0 64 40",
    fill: "none",
    "aria-hidden": "true"
  }, /*#__PURE__*/React.createElement("path", {
    d: "M2 30 Q32 2 62 30",
    stroke: ACC,
    strokeWidth: "1.5",
    strokeDasharray: "3 5",
    strokeLinecap: "round",
    opacity: closed ? 1 : 0.4
  }), /*#__PURE__*/React.createElement("circle", {
    cx: 2 + 60 * lidP,
    cy: 30 - Math.sin(lidP * Math.PI) * 28,
    r: "3.5",
    fill: ACC,
    opacity: closed ? 1 : 0
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      ...card,
      padding: "16px 18px",
      display: "flex",
      alignItems: "center",
      gap: 13
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 40,
      height: 40,
      borderRadius: 11,
      flex: "none",
      background: "color-mix(in srgb, var(--color-pistachio-green) 55%, var(--color-white))",
      display: "grid",
      placeItems: "center"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 11,
      height: 11,
      borderRadius: "50%",
      background: ACC,
      boxShadow: `0 0 0 ${4 + pulse * 6}px color-mix(in srgb, ${ACC} 24%, transparent)`
    }
  })), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: 14,
      color: INK
    }
  }, "Running on Hypervisor"), /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 11,
      color: "var(--color-grey-700)",
      marginTop: 2
    }
  }, "3 sessions \xB7 cloud"))))), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "repeat(3, 1fr)",
      gap: "1.25rem",
      marginTop: "2.5rem"
    }
  }, stats.map(([value, label]) => /*#__PURE__*/React.createElement("div", {
    key: label,
    style: {
      background: "var(--color-porcelain-grey)",
      border: `0.5px solid ${HAIR}`,
      borderRadius: "var(--radius-card)",
      padding: "2.25rem 2rem",
      display: "flex",
      flexDirection: "column",
      gap: "0.625rem"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "3rem",
      lineHeight: 1,
      letterSpacing: "-0.02em",
      color: INK
    }
  }, value), /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "0.9375rem",
      color: "var(--color-grey-700)"
    }
  }, label)))));
}
function BgCTA() {
  return /*#__PURE__*/React.createElement("section", {
    style: {
      ...bawrap,
      paddingTop: "8rem",
      textAlign: "center"
    }
  }, /*#__PURE__*/React.createElement("h2", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "3rem",
      letterSpacing: "-0.02em",
      margin: 0,
      color: INK
    }
  }, "Put a fleet to work"), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      gap: "0.5rem",
      justifyContent: "center",
      marginTop: "1.75rem"
    }
  }, /*#__PURE__*/React.createElement(BgButton, {
    iconRight: /*#__PURE__*/React.createElement("span", null, "\u2192")
  }, "Get started"), /*#__PURE__*/React.createElement(BgLink, {
    href: "solutions.html"
  }, "Back to solutions")));
}
function HvPage() {
  return /*#__PURE__*/React.createElement("main", null, /*#__PURE__*/React.createElement(BgHero, null), /*#__PURE__*/React.createElement(FeatureBlock, null), /*#__PURE__*/React.createElement(WhatTeamsAutomate, null), /*#__PURE__*/React.createElement(HandoffOutro, null), /*#__PURE__*/React.createElement(BgCTA, null));
}
window.HvPage = HvPage;
window.HvPageActive = "Solutions";
})(); } catch (e) { __ds_ns.__errors.push({ path: "site/BackgroundWork.jsx", error: String((e && e.message) || e) }); }

// site/Chrome.jsx
try { (() => {
// hypervisor.com chrome — header nav + footer. Composes the DS Wordmark + Button.
const {
  Button: HvButton,
  Wordmark: HvWordmark,
  Logo: HvLogo,
  ByIOI: HvByIOI
} = window.IoiDesignSystem;
const NAV = [["Platform", "platform.html"], ["Solutions", "solutions.html"], ["Developers", "developers.html"], ["Pricing", "pricing.html"], ["Docs", "docs.html"]];
function Header({
  active
} = {}) {
  const [open, setOpen] = React.useState(false);
  return /*#__PURE__*/React.createElement("header", {
    style: {
      position: "sticky",
      top: 0,
      zIndex: 20,
      background: "rgba(255,255,255,0.9)",
      backdropFilter: "saturate(180%) blur(12px)",
      WebkitBackdropFilter: "saturate(180%) blur(12px)",
      borderBottom: "0.5px solid var(--color-grey-500)"
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "hv-header-inner",
    style: {
      maxWidth: "75rem",
      margin: "0 auto",
      display: "flex",
      alignItems: "center",
      gap: "1.25rem",
      padding: "1rem 2.5rem"
    }
  }, /*#__PURE__*/React.createElement("a", {
    href: "index.html",
    "aria-label": "Hypervisor",
    style: {
      display: "flex",
      flexShrink: 0,
      color: "var(--color-onyx-black)",
      textDecoration: "none"
    }
  }, /*#__PURE__*/React.createElement(HvWordmark, {
    height: 24
  })), /*#__PURE__*/React.createElement("ul", {
    className: "hv-nav-links",
    style: {
      display: "flex",
      listStyle: "none",
      margin: "0 0 0 1.5rem",
      padding: 0,
      gap: "0.25rem"
    }
  }, NAV.map(([label, href]) => {
    const on = active === label;
    return /*#__PURE__*/React.createElement("li", {
      key: label,
      style: {
        display: "flex"
      }
    }, /*#__PURE__*/React.createElement("a", {
      href: href,
      style: {
        display: "inline-flex",
        alignItems: "center",
        gap: 4,
        padding: "0.6875rem 0.625rem",
        fontFamily: "var(--font-sans)",
        fontSize: "0.9375rem",
        color: on ? "var(--color-onyx-black)" : "var(--color-grey-800)",
        fontWeight: on ? 500 : 400,
        textDecoration: "none"
      }
    }, label));
  })), /*#__PURE__*/React.createElement("div", {
    className: "hv-nav-cta",
    style: {
      marginLeft: "auto",
      display: "flex",
      gap: "0.5rem",
      alignItems: "center"
    }
  }, /*#__PURE__*/React.createElement(HvButton, {
    theme: "grey",
    size: "md"
  }, "Sign in"), /*#__PURE__*/React.createElement(HvButton, {
    size: "md"
  }, "Get started")), /*#__PURE__*/React.createElement("button", {
    className: "hv-navtoggle",
    "aria-label": "Menu",
    "aria-expanded": open,
    onClick: () => setOpen(o => !o),
    style: {
      marginLeft: "auto",
      width: 40,
      height: 40,
      alignItems: "center",
      justifyContent: "center",
      background: "none",
      border: "0.5px solid var(--color-grey-500)",
      borderRadius: 8,
      color: "var(--color-onyx-black)",
      cursor: "pointer",
      padding: 0
    }
  }, /*#__PURE__*/React.createElement("svg", {
    width: "18",
    height: "18",
    viewBox: "0 0 18 18",
    fill: "none",
    "aria-hidden": "true"
  }, open ? /*#__PURE__*/React.createElement("path", {
    d: "M4 4l10 10M14 4L4 14",
    stroke: "currentColor",
    strokeWidth: "1.6",
    strokeLinecap: "round"
  }) : /*#__PURE__*/React.createElement("path", {
    d: "M2.5 5h13M2.5 9h13M2.5 13h13",
    stroke: "currentColor",
    strokeWidth: "1.6",
    strokeLinecap: "round"
  })))), open && /*#__PURE__*/React.createElement("div", {
    className: "hv-mobile-menu",
    style: {
      borderTop: "0.5px solid var(--color-grey-500)",
      padding: "0.5rem 1.25rem 1.25rem",
      flexDirection: "column"
    }
  }, NAV.map(([label, href]) => {
    const on = active === label;
    return /*#__PURE__*/React.createElement("a", {
      key: label,
      href: href,
      style: {
        display: "block",
        padding: "0.875rem 0.25rem",
        fontFamily: "var(--font-sans)",
        fontSize: "1.0625rem",
        color: on ? "var(--color-onyx-black)" : "var(--color-grey-800)",
        fontWeight: on ? 500 : 400,
        textDecoration: "none",
        borderBottom: "0.5px solid var(--color-grey-500)"
      }
    }, label);
  }), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      gap: "0.5rem",
      marginTop: "1rem"
    }
  }, /*#__PURE__*/React.createElement(HvButton, {
    theme: "grey",
    size: "md"
  }, "Sign in"), /*#__PURE__*/React.createElement(HvButton, {
    size: "md"
  }, "Get started"))));
}
function FCol({
  title,
  links
}) {
  return /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      flexDirection: "column",
      gap: "0.875rem"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: "0.6875rem",
      letterSpacing: "0.08em",
      textTransform: "uppercase",
      color: "var(--color-grey-700)"
    }
  }, title), /*#__PURE__*/React.createElement("ul", {
    style: {
      listStyle: "none",
      margin: 0,
      padding: 0,
      display: "flex",
      flexDirection: "column",
      gap: "0.625rem"
    }
  }, links.map(l => {
    const [label, href] = Array.isArray(l) ? l : [l, null];
    return /*#__PURE__*/React.createElement("li", {
      key: label
    }, /*#__PURE__*/React.createElement("a", {
      href: href || "#",
      onClick: href ? undefined : e => e.preventDefault(),
      style: {
        fontFamily: "var(--font-sans)",
        fontSize: "0.9375rem",
        color: "var(--color-grey-800)",
        textDecoration: "none"
      }
    }, label));
  })));
}
function Footer() {
  return /*#__PURE__*/React.createElement("footer", {
    style: {
      borderTop: "0.5px solid var(--color-grey-500)",
      marginTop: "8rem"
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "hv-footer-grid",
    style: {
      maxWidth: "75rem",
      margin: "0 auto",
      padding: "3.5rem 2.5rem",
      display: "grid",
      gridTemplateColumns: "1.6fr repeat(4, 1fr)",
      gap: "2rem"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      color: "var(--color-onyx-black)"
    }
  }, /*#__PURE__*/React.createElement(HvWordmark, {
    height: 26
  }), /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: "0.75rem"
    }
  }, /*#__PURE__*/React.createElement(HvByIOI, {
    height: 13
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: "1.25rem",
      display: "flex",
      gap: 8,
      flexWrap: "wrap"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: "0.6875rem",
      color: "var(--color-grey-700)",
      border: "0.5px solid var(--color-grey-500)",
      borderRadius: 6,
      padding: "5px 9px"
    }
  }, "SOC 2"), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: "0.6875rem",
      color: "var(--color-grey-700)",
      border: "0.5px solid var(--color-grey-500)",
      borderRadius: 6,
      padding: "5px 9px"
    }
  }, "GDPR"), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: "0.6875rem",
      color: "var(--color-grey-700)",
      border: "0.5px solid var(--color-grey-500)",
      borderRadius: 6,
      padding: "5px 9px"
    }
  }, "Web4")), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "0.9375rem",
      color: "var(--color-grey-800)",
      marginTop: "1.5rem",
      lineHeight: 1.5,
      maxWidth: "30ch"
    }
  }, "The open operating environment for autonomous systems.")), /*#__PURE__*/React.createElement(FCol, {
    title: "Platform",
    links: [["Hypervisor App", "hv-app.html"], ["Web", "hv-web.html"], ["CLI", "hv-cli.html"], ["MCP gateway", "hv-mcp.html"], ["HypervisorOS", "hv-os.html"], ["Embodied Runtime", "hv-embodied.html"]]
  }), /*#__PURE__*/React.createElement(FCol, {
    title: "Solutions",
    links: [["Background work", "background-work.html"], ["Automations", "automations-fleets.html"], ["Modernization", "code-modernization.html"], ["Security agents", "runtime-security.html"]]
  }), /*#__PURE__*/React.createElement(FCol, {
    title: "Developers",
    links: [["Docs", "docs.html"], ["SDK", "hv-sdk.html"], ["ADK", "hv-adk.html"], ["ODK", "hv-odk.html"], "API reference", "Changelog"]
  }), /*#__PURE__*/React.createElement(FCol, {
    title: "Company",
    links: ["About", "Careers", "Security", "Contact"]
  })), /*#__PURE__*/React.createElement("div", {
    className: "hv-footer-bar",
    style: {
      maxWidth: "75rem",
      margin: "0 auto",
      padding: "1.5rem 2.5rem 3rem",
      borderTop: "0.5px solid var(--color-grey-500)",
      display: "flex",
      gap: "1.5rem",
      flexWrap: "wrap",
      alignItems: "center"
    }
  }, ["Terms", "Privacy", "Trust", "Status"].map(l => /*#__PURE__*/React.createElement("a", {
    key: l,
    href: "#",
    onClick: e => e.preventDefault(),
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "0.8125rem",
      color: "var(--color-grey-700)",
      textDecoration: "none"
    }
  }, l)), /*#__PURE__*/React.createElement("span", {
    style: {
      marginLeft: "auto",
      fontFamily: "var(--font-mono)",
      fontSize: "0.75rem",
      color: "var(--color-grey-700)"
    }
  }, "\xA9 2026 IOI, Inc. \xB7 hypervisor.com")));
}
window.HvHeader = Header;
window.HvFooter = Footer;
})(); } catch (e) { __ds_ns.__errors.push({ path: "site/Chrome.jsx", error: String((e && e.message) || e) }); }

// site/CodeModernization.jsx
try { (() => {
// hypervisor.com — Code Modernization solution page.
const CMNS = window.IoiDesignSystem;
const {
  Button: CmButton,
  TextLink: CmLink,
  Eyebrow: CmEyebrow,
  Logo: CmLogo
} = CMNS;
const cmwrap = {
  maxWidth: "75rem",
  margin: "0 auto",
  padding: "0 2.5rem"
};
const INK = "var(--color-onyx-black)";
const HAIR = "var(--color-grey-500)";
const ACC = "var(--color-link-green)";
const RED = "var(--color-red-500)";
function cmClock(period) {
  const [t, setT] = React.useState(0);
  React.useEffect(() => {
    const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduce) {
      setT(0.82);
      return;
    }
    let raf,
      start = null;
    const tick = ts => {
      if (start == null) start = ts;
      setT((ts - start) % period / period);
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, []);
  return t;
}
function CmSpinner({
  t,
  on,
  done
}) {
  const spin = t * 1440 % 360;
  if (done) return /*#__PURE__*/React.createElement("span", {
    style: {
      width: 17,
      height: 17,
      borderRadius: "50%",
      background: ACC,
      display: "grid",
      placeItems: "center",
      flex: "none"
    }
  }, /*#__PURE__*/React.createElement("svg", {
    width: "9",
    height: "9",
    viewBox: "0 0 12 12",
    fill: "none"
  }, /*#__PURE__*/React.createElement("path", {
    d: "M2.5 6.3 L5 8.5 L9.5 3.7",
    stroke: "#fff",
    strokeWidth: "1.8",
    strokeLinecap: "round",
    strokeLinejoin: "round"
  })));
  if (on) return /*#__PURE__*/React.createElement("svg", {
    width: "17",
    height: "17",
    viewBox: "0 0 18 18",
    style: {
      flex: "none",
      transform: `rotate(${spin}deg)`
    }
  }, /*#__PURE__*/React.createElement("circle", {
    cx: "9",
    cy: "9",
    r: "7",
    fill: "none",
    stroke: ACC,
    strokeWidth: "2",
    strokeDasharray: "11 33",
    strokeLinecap: "round"
  }));
  return /*#__PURE__*/React.createElement("svg", {
    width: "17",
    height: "17",
    viewBox: "0 0 18 18",
    style: {
      flex: "none"
    }
  }, /*#__PURE__*/React.createElement("circle", {
    cx: "9",
    cy: "9",
    r: "7",
    fill: "none",
    stroke: "var(--color-grey-500)",
    strokeWidth: "1.5",
    strokeDasharray: "0.5 3.5",
    strokeLinecap: "round"
  }));
}

/* ============================================================ *
 * Hero showcase — migration fleet dashboard (the "at scale" story)
 * ============================================================ */
function MigrationFleet() {
  const t = cmClock(11000);
  const TOTAL = 210;
  const pct = Math.min(0.92, 0.34 + t * 0.62);
  const merged = Math.round(pct * TOTAL);
  const ringR = 52,
    ringC = 2 * Math.PI * ringR;
  const repos = [["billing-api", "JAVA 8 → 17", 0.0], ["web-dashboard", "JAVA 8 → 17", 0.06], ["ledger-core", "COBOL → JAVA", 0.13], ["auth-service", "JAVA 8 → 17", 0.22], ["payments-core", "JAVA 8 → 17", 0.32], ["notifications", "JS → TS", 0.44], ["search-index", "JAVA 8 → 17", 0.58], ["risk-engine", "COBOL → JAVA", 0.72]];
  const rstate = start => {
    const p = (t - start) / 0.26;
    if (p >= 1) return {
      k: "merged",
      p: 1
    };
    if (p > 0) return {
      k: "building",
      p: Math.max(0.08, p)
    };
    return {
      k: "queued",
      p: 0
    };
  };
  return /*#__PURE__*/React.createElement("div", {
    style: {
      width: "100%",
      maxWidth: 1060,
      margin: "0 auto",
      position: "relative"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      position: "absolute",
      inset: -2,
      borderRadius: 18,
      background: `linear-gradient(135deg, color-mix(in srgb, var(--color-pistachio-green) 75%, var(--color-white)), color-mix(in srgb, var(--color-link-green) 35%, var(--color-white)) 50%, var(--color-porcelain-grey))`,
      zIndex: 0
    }
  }), /*#__PURE__*/React.createElement("div", {
    style: {
      position: "relative",
      zIndex: 1,
      margin: 6,
      background: "#0d0d10",
      borderRadius: 14,
      overflow: "hidden",
      boxShadow: "0 40px 90px rgba(0,0,0,0.4)"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 11,
      padding: "16px 22px",
      borderBottom: "1px solid rgba(255,255,255,0.07)"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 30,
      height: 30,
      borderRadius: 8,
      background: "rgba(255,255,255,0.08)",
      display: "grid",
      placeItems: "center",
      color: "#fff"
    }
  }, /*#__PURE__*/React.createElement(CmLogo, {
    size: 15
  })), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: 14,
      color: "#fff"
    }
  }, "Modernization fleet"), /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 11,
      color: "rgba(255,255,255,0.4)",
      marginTop: 1
    }
  }, "automation \xB7 legacy-java-uplift")), /*#__PURE__*/React.createElement("span", {
    style: {
      marginLeft: "auto",
      display: "flex",
      alignItems: "center",
      gap: 6,
      fontFamily: "var(--font-mono)",
      fontSize: 11,
      color: ACC,
      border: `1px solid color-mix(in srgb, ${ACC} 40%, transparent)`,
      borderRadius: 6,
      padding: "4px 10px"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 6,
      height: 6,
      borderRadius: "50%",
      background: ACC
    }
  }), "running")), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "0.78fr 1.22fr",
      minHeight: 392
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      borderRight: "1px solid rgba(255,255,255,0.07)",
      padding: "26px 24px",
      display: "flex",
      flexDirection: "column",
      alignItems: "center"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      position: "relative",
      width: 140,
      height: 140
    }
  }, /*#__PURE__*/React.createElement("svg", {
    width: "140",
    height: "140",
    viewBox: "0 0 140 140"
  }, /*#__PURE__*/React.createElement("circle", {
    cx: "70",
    cy: "70",
    r: ringR,
    fill: "none",
    stroke: "rgba(255,255,255,0.1)",
    strokeWidth: "10"
  }), /*#__PURE__*/React.createElement("circle", {
    cx: "70",
    cy: "70",
    r: ringR,
    fill: "none",
    stroke: ACC,
    strokeWidth: "10",
    strokeLinecap: "round",
    strokeDasharray: ringC,
    strokeDashoffset: ringC * (1 - pct),
    transform: "rotate(-90 70 70)",
    style: {
      transition: "stroke-dashoffset 0.2s linear"
    }
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      position: "absolute",
      inset: 0,
      display: "flex",
      flexDirection: "column",
      alignItems: "center",
      justifyContent: "center"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: 34,
      color: "#fff",
      lineHeight: 1
    }
  }, merged), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 11,
      color: "rgba(255,255,255,0.4)",
      marginTop: 3
    }
  }, "of ", TOTAL, " repos"))), /*#__PURE__*/React.createElement("div", {
    style: {
      width: "100%",
      marginTop: 26,
      display: "flex",
      flexDirection: "column",
      gap: 10
    }
  }, [["Merged", merged, ACC], ["Building", Math.max(0, Math.min(8, TOTAL - merged)), "#fff"], ["Tests passing", "100%", ACC]].map(([k, v, col]) => /*#__PURE__*/React.createElement("div", {
    key: k,
    style: {
      display: "flex",
      alignItems: "center",
      justifyContent: "space-between",
      padding: "10px 13px",
      background: "rgba(255,255,255,0.04)",
      borderRadius: 9,
      border: "1px solid rgba(255,255,255,0.06)"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: 12.5,
      color: "rgba(255,255,255,0.55)"
    }
  }, k), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 13,
      color: col
    }
  }, v))))), /*#__PURE__*/React.createElement("div", {
    style: {
      padding: "10px 0",
      overflow: "hidden",
      WebkitMaskImage: "linear-gradient(180deg,#000 86%,transparent)",
      maskImage: "linear-gradient(180deg,#000 86%,transparent)"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      padding: "8px 22px 12px",
      fontFamily: "var(--font-mono)",
      fontSize: 10,
      letterSpacing: "0.07em",
      textTransform: "uppercase",
      color: "rgba(255,255,255,0.3)"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      flex: 1
    }
  }, "Repository"), /*#__PURE__*/React.createElement("span", {
    style: {
      width: 110
    }
  }, "Migration"), /*#__PURE__*/React.createElement("span", {
    style: {
      width: 90,
      textAlign: "right"
    }
  }, "Status")), repos.map(([name, transform, start]) => {
    const s = rstate(start);
    return /*#__PURE__*/React.createElement("div", {
      key: name,
      style: {
        display: "flex",
        alignItems: "center",
        gap: 12,
        padding: "11px 22px",
        borderTop: "1px solid rgba(255,255,255,0.04)"
      }
    }, /*#__PURE__*/React.createElement(CmSpinner, {
      t: t,
      on: s.k === "building",
      done: s.k === "merged"
    }), /*#__PURE__*/React.createElement("span", {
      style: {
        flex: 1,
        minWidth: 0,
        fontFamily: "var(--font-mono)",
        fontSize: 12.5,
        color: "rgba(255,255,255,0.82)",
        whiteSpace: "nowrap",
        overflow: "hidden",
        textOverflow: "ellipsis"
      }
    }, name), /*#__PURE__*/React.createElement("span", {
      style: {
        width: 110,
        flex: "none",
        fontFamily: "var(--font-mono)",
        fontSize: 11,
        color: "rgba(255,255,255,0.45)"
      }
    }, transform), /*#__PURE__*/React.createElement("span", {
      style: {
        width: 90,
        flex: "none",
        textAlign: "right",
        fontFamily: "var(--font-mono)",
        fontSize: 10.5,
        color: s.k === "merged" ? ACC : s.k === "building" ? "rgba(255,255,255,0.6)" : "rgba(255,255,255,0.3)"
      }
    }, s.k === "merged" ? "merged" : s.k === "building" ? "building" : "queued"));
  })))));
}

/* ===================== feature row ===================== */
function CmFeatureRow({
  eyebrow,
  heading,
  body,
  link,
  diagram,
  flip
}) {
  return /*#__PURE__*/React.createElement("div", {
    style: {
      background: "var(--color-white)",
      border: `0.5px solid ${HAIR}`,
      borderRadius: "var(--radius-card)",
      padding: "3rem 3.25rem",
      display: "grid",
      gridTemplateColumns: "1fr 1fr",
      gap: "3rem",
      alignItems: "center"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      order: flip ? 2 : 1
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      display: "inline-block",
      fontFamily: "var(--font-mono)",
      fontSize: 11,
      letterSpacing: "0.08em",
      textTransform: "uppercase",
      color: ACC,
      marginBottom: "0.875rem"
    }
  }, eyebrow), /*#__PURE__*/React.createElement("h3", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.625rem",
      letterSpacing: "-0.02em",
      lineHeight: 1.12,
      margin: 0,
      color: INK
    }
  }, heading), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.0625rem",
      color: "var(--color-grey-800)",
      marginTop: "1rem",
      lineHeight: 1.5,
      maxWidth: "42ch"
    }
  }, body), link && /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: "1.5rem"
    }
  }, /*#__PURE__*/React.createElement(CmLink, {
    href: link[1]
  }, link[0]))), /*#__PURE__*/React.createElement("div", {
    style: {
      order: flip ? 1 : 2,
      display: "flex",
      justifyContent: "center"
    }
  }, diagram));
}

/* ---- automation pipeline (define once) ---- */
function PipelineDiagram() {
  const t = cmClock(8000);
  const steps = [["Trigger", "Manual · runs across 210 repos", ACC], ["Prompt", "Identify Java 8 APIs and replacements", "var(--color-grey-600)"], ["Shell Script", "mvn -q compile && mvn test", "var(--color-grey-600)"], ["Pull Request", "Open PR per repo with the migration", ACC]];
  const active = Math.min(steps.length, Math.floor(t * (steps.length + 1)));
  return /*#__PURE__*/React.createElement("div", {
    style: {
      width: "100%",
      maxWidth: 380,
      display: "flex",
      flexDirection: "column"
    }
  }, steps.map(([kind, label, dot], i) => {
    const done = i < active,
      on = i === active;
    return /*#__PURE__*/React.createElement(React.Fragment, {
      key: i
    }, i > 0 && /*#__PURE__*/React.createElement("span", {
      style: {
        width: 1.5,
        height: 16,
        background: i <= active ? ACC : HAIR,
        margin: "0 auto",
        transition: "background 0.3s"
      }
    }), /*#__PURE__*/React.createElement("div", {
      style: {
        background: "var(--color-white)",
        border: `0.5px solid ${HAIR}`,
        borderRadius: 12,
        boxShadow: on ? "var(--shadow-md)" : "var(--shadow-xs)",
        padding: "13px 16px",
        opacity: i <= active ? 1 : 0.45,
        transform: on ? "scale(1.015)" : "scale(1)",
        transition: "all 0.35s"
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        display: "flex",
        alignItems: "center",
        gap: 8
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        display: "inline-flex",
        alignItems: "center",
        gap: 5,
        background: "var(--color-porcelain-grey)",
        borderRadius: 6,
        padding: "2px 8px",
        fontFamily: "var(--font-mono)",
        fontSize: 10.5,
        color: INK
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        width: 6,
        height: 6,
        borderRadius: "50%",
        background: dot
      }
    }), kind), done && /*#__PURE__*/React.createElement("span", {
      style: {
        marginLeft: "auto"
      }
    }, /*#__PURE__*/React.createElement(CmSpinner, {
      t: t,
      done: true
    })), on && /*#__PURE__*/React.createElement("span", {
      style: {
        marginLeft: "auto"
      }
    }, /*#__PURE__*/React.createElement(CmSpinner, {
      t: t,
      on: true
    }))), /*#__PURE__*/React.createElement("div", {
      style: {
        fontFamily: kind === "Shell Script" ? "var(--font-mono)" : "var(--font-sans)",
        fontSize: kind === "Shell Script" ? "0.8125rem" : "1rem",
        color: INK,
        marginTop: 8,
        whiteSpace: "nowrap",
        overflow: "hidden",
        textOverflow: "ellipsis"
      }
    }, label)));
  }));
}

/* ---- verified by build & test (before/after + green build) ---- */
function VerifyDiagram() {
  const t = cmClock(7600);
  const building = t > 0.34,
    green = t > 0.6;
  const after = [["", "var(--color-grey-700)", "// migrated to java.time"], ["-", RED, "Date d = new Date();"], ["+", ACC, "LocalDate d = LocalDate.now();"], ["-", RED, "cal.add(Calendar.DAY, 1);"], ["+", ACC, "d = d.plusDays(1);"]];
  return /*#__PURE__*/React.createElement("div", {
    style: {
      width: "100%",
      maxWidth: 380,
      display: "flex",
      flexDirection: "column",
      gap: 14
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      background: "var(--color-white)",
      border: `0.5px solid ${HAIR}`,
      borderRadius: 14,
      overflow: "hidden",
      boxShadow: "var(--shadow-sm)"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 8,
      padding: "12px 16px",
      borderBottom: `0.5px solid ${HAIR}`
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 11.5,
      color: "var(--color-grey-700)"
    }
  }, "DateUtil.java"), /*#__PURE__*/React.createElement("span", {
    style: {
      marginLeft: "auto",
      fontFamily: "var(--font-mono)",
      fontSize: 11,
      color: ACC
    }
  }, "JAVA 8 \u2192 17")), /*#__PURE__*/React.createElement("div", {
    style: {
      padding: "12px 16px",
      fontFamily: "var(--font-mono)",
      fontSize: 12,
      lineHeight: 1.9
    }
  }, after.map(([sign, c, code], i) => /*#__PURE__*/React.createElement("div", {
    key: i,
    style: {
      display: "flex",
      gap: 9,
      margin: "0 -16px",
      padding: "0 16px",
      background: sign === "+" ? `color-mix(in srgb, ${ACC} 9%, transparent)` : sign === "-" ? `color-mix(in srgb, ${RED} 8%, transparent)` : "transparent"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      color: c,
      width: 8,
      flex: "none"
    }
  }, sign || " "), /*#__PURE__*/React.createElement("span", {
    style: {
      color: sign === "" ? "var(--color-grey-600)" : INK,
      whiteSpace: "pre",
      overflow: "hidden",
      textOverflow: "ellipsis"
    }
  }, code))))), /*#__PURE__*/React.createElement("div", {
    style: {
      background: green ? `color-mix(in srgb, ${ACC} 9%, var(--color-white))` : "var(--color-white)",
      border: `0.5px solid ${green ? "transparent" : HAIR}`,
      borderRadius: 12,
      padding: "13px 16px",
      display: "flex",
      alignItems: "center",
      gap: 11,
      transition: "background 0.4s"
    }
  }, /*#__PURE__*/React.createElement(CmSpinner, {
    t: t,
    on: building && !green,
    done: green
  }), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: 13.5,
      color: INK
    }
  }, green ? "Build green · 243 tests passing" : building ? "Running mvn test…" : "Compiling…"), green && /*#__PURE__*/React.createElement("span", {
    style: {
      marginLeft: "auto",
      fontFamily: "var(--font-mono)",
      fontSize: 11,
      color: ACC
    }
  }, "verified")));
}

/* ===================== page ===================== */
function CmHero() {
  return /*#__PURE__*/React.createElement("section", {
    style: {
      ...cmwrap,
      paddingTop: "5rem"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      textAlign: "center",
      maxWidth: "42rem",
      margin: "0 auto 3.75rem"
    }
  }, /*#__PURE__*/React.createElement(CmEyebrow, {
    color: ACC
  }, "Solutions \xB7 Code modernization"), /*#__PURE__*/React.createElement("h1", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "3.75rem",
      lineHeight: 1.03,
      letterSpacing: "-0.02em",
      margin: "1.25rem 0 0",
      color: INK
    }
  }, "Code migration &", /*#__PURE__*/React.createElement("br", null), "modernization at scale"), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.1875rem",
      color: "var(--color-grey-800)",
      marginTop: "1.25rem",
      lineHeight: 1.5
    }
  }, "Migrations that sat in backlogs for years, done in days. Fleets of agents migrate your entire codebase \u2014 every change built, tested, and verified, not just rewritten."), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      gap: "0.5rem",
      justifyContent: "center",
      marginTop: "2rem"
    }
  }, /*#__PURE__*/React.createElement(CmButton, {
    iconRight: /*#__PURE__*/React.createElement("span", null, "\u2192")
  }, "Get started"), /*#__PURE__*/React.createElement(CmButton, {
    variant: "outline"
  }, "Request a demo"))), /*#__PURE__*/React.createElement(MigrationFleet, null));
}
function CmBacklogSection() {
  return /*#__PURE__*/React.createElement("section", {
    style: {
      ...cmwrap,
      paddingTop: "8rem"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "0.9fr 1.1fr",
      gap: "4rem",
      alignItems: "center"
    }
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("h2", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "2.5rem",
      letterSpacing: "-0.02em",
      lineHeight: 1.08,
      margin: 0,
      color: INK
    }
  }, "Migrations that sat in backlogs for years, done in days"), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.0625rem",
      color: "var(--color-grey-800)",
      marginTop: "1.25rem",
      lineHeight: 1.55,
      maxWidth: "44ch"
    }
  }, "Fleets of agents run the migration end to end across your entire codebase, each in its own isolated environment that builds the code and runs the tests \u2014 so every change is verified rather than just rewritten."), /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: "1.75rem"
    }
  }, /*#__PURE__*/React.createElement(CmLink, {
    href: "automations-fleets.html"
  }, "Browse automation templates"))), /*#__PURE__*/React.createElement(PipelineDiagram, null)));
}
function CmFeatures() {
  return /*#__PURE__*/React.createElement("section", {
    style: {
      ...cmwrap,
      paddingTop: "6rem",
      display: "flex",
      flexDirection: "column",
      gap: "1.5rem"
    }
  }, /*#__PURE__*/React.createElement(CmFeatureRow, {
    eyebrow: "Verified, not rewritten",
    heading: "Every change builds and passes tests",
    body: "An agent doesn't just rewrite code \u2014 it compiles the project and runs the suite in an isolated environment. A migration only lands when the build is green, so you review working changes, not guesses.",
    flip: false,
    diagram: /*#__PURE__*/React.createElement(VerifyDiagram, null)
  }));
}
function CmStats() {
  const stats = [["210", "Repos migrated in one run"], ["Years → days", "Backlog cleared"], ["100%", "Changes built & tested"]];
  return /*#__PURE__*/React.createElement("section", {
    style: {
      ...cmwrap,
      paddingTop: "6rem"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "repeat(3, 1fr)",
      gap: "1.25rem"
    }
  }, stats.map(([value, label]) => /*#__PURE__*/React.createElement("div", {
    key: label,
    style: {
      background: "var(--color-porcelain-grey)",
      border: `0.5px solid ${HAIR}`,
      borderRadius: "var(--radius-card)",
      padding: "2.25rem 2rem"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "2.75rem",
      lineHeight: 1.05,
      letterSpacing: "-0.02em",
      color: INK
    }
  }, value), /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "0.9375rem",
      color: "var(--color-grey-700)",
      marginTop: "0.625rem"
    }
  }, label)))));
}
function CmCTA() {
  return /*#__PURE__*/React.createElement("section", {
    style: {
      ...cmwrap,
      paddingTop: "8rem",
      textAlign: "center"
    }
  }, /*#__PURE__*/React.createElement("h2", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "3rem",
      letterSpacing: "-0.02em",
      margin: 0,
      color: INK
    }
  }, "Clear the migration backlog"), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      gap: "0.5rem",
      justifyContent: "center",
      marginTop: "1.75rem"
    }
  }, /*#__PURE__*/React.createElement(CmButton, {
    iconRight: /*#__PURE__*/React.createElement("span", null, "\u2192")
  }, "Get started"), /*#__PURE__*/React.createElement(CmLink, {
    href: "solutions.html"
  }, "Back to solutions")));
}
function HvPage() {
  return /*#__PURE__*/React.createElement("main", null, /*#__PURE__*/React.createElement(CmHero, null), /*#__PURE__*/React.createElement(CmBacklogSection, null), /*#__PURE__*/React.createElement(CmFeatures, null), /*#__PURE__*/React.createElement(CmStats, null), /*#__PURE__*/React.createElement(CmCTA, null));
}
window.HvPage = HvPage;
window.HvPageActive = "Solutions";
})(); } catch (e) { __ds_ns.__errors.push({ path: "site/CodeModernization.jsx", error: String((e && e.message) || e) }); }

// site/CodeReview.jsx
try { (() => {
// hypervisor.com — AI code review solution (under Solutions).
const CNS = window.IoiDesignSystem;
const {
  Button: CrButton,
  Badge: CrBadge,
  TextLink: CrLink,
  Eyebrow: CrEyebrow,
  Logo: CrLogo
} = CNS;
const crwrap = {
  maxWidth: "75rem",
  margin: "0 auto",
  padding: "0 2.5rem"
};
const INK = "var(--color-onyx-black)";
const HAIR = "var(--color-grey-500)";
const ACC = "var(--color-link-green)";
const RED = "var(--color-red-500)";
const PANEL = {
  background: "color-mix(in srgb, var(--color-pistachio-green) 30%, var(--color-white))",
  border: `0.5px solid ${HAIR}`,
  borderRadius: "var(--radius-card)",
  height: 480,
  padding: "2rem",
  position: "relative",
  overflow: "hidden"
};
const cr_card = {
  background: "var(--color-white)",
  border: `0.5px solid ${HAIR}`,
  borderRadius: 14,
  boxShadow: "var(--shadow-sm)"
};
function crClock(period) {
  const [t, setT] = React.useState(0);
  React.useEffect(() => {
    const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduce) {
      setT(0.85);
      return;
    }
    let raf,
      start = null;
    const tick = ts => {
      if (start == null) start = ts;
      setT((ts - start) % period / period);
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, []);
  return t;
}
const cg = paths => /*#__PURE__*/React.createElement("svg", {
  width: "17",
  height: "17",
  viewBox: "0 0 24 24",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: "1.6",
  strokeLinecap: "round",
  strokeLinejoin: "round"
}, paths);
const CR_ICON = {
  env: cg(/*#__PURE__*/React.createElement("g", null, /*#__PURE__*/React.createElement("rect", {
    x: "3",
    y: "4",
    width: "18",
    height: "14",
    rx: "2"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M3 8 H21"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M7 13 L9 15 L7 17"
  }))),
  rules: cg(/*#__PURE__*/React.createElement("g", null, /*#__PURE__*/React.createElement("path", {
    d: "M5 4 H15 L19 8 V20 H5 Z"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M14 4 V8 H19"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M8 13 L10.5 15.5 L16 10"
  }))),
  fixes: cg(/*#__PURE__*/React.createElement("g", null, /*#__PURE__*/React.createElement("path", {
    d: "M14 6 a3.5 3.5 0 0 0 -5 5 L4 16 v4 h4 l5 -5 a3.5 3.5 0 0 0 5 -5 l-2.5 2.5 L17 14 l-3 -3 1.5 -1.5 Z"
  }))),
  pr: cg(/*#__PURE__*/React.createElement("g", null, /*#__PURE__*/React.createElement("circle", {
    cx: "6",
    cy: "6",
    r: "2.4"
  }), /*#__PURE__*/React.createElement("circle", {
    cx: "6",
    cy: "18",
    r: "2.4"
  }), /*#__PURE__*/React.createElement("circle", {
    cx: "18",
    cy: "18",
    r: "2.4"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M6 8.4 V15.6"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M18 15.6 V12 a4 4 0 0 0 -4 -4 H9"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M11 6 L9 8 L11 10"
  }))),
  audit: cg(/*#__PURE__*/React.createElement("g", null, /*#__PURE__*/React.createElement("path", {
    d: "M12 3 L19 6 V11 C19 16 15.5 19.5 12 21 C8.5 19.5 5 16 5 11 V6 Z"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M9.5 12 L11 13.5 L14.5 10"
  })))
};
function Spinner({
  t,
  on,
  done
}) {
  const spin = t * 1440 % 360;
  if (done) return /*#__PURE__*/React.createElement("span", {
    style: {
      width: 18,
      height: 18,
      borderRadius: "50%",
      background: ACC,
      display: "grid",
      placeItems: "center",
      flex: "none"
    }
  }, /*#__PURE__*/React.createElement("svg", {
    width: "10",
    height: "10",
    viewBox: "0 0 12 12",
    fill: "none"
  }, /*#__PURE__*/React.createElement("path", {
    d: "M2.5 6.3 L5 8.5 L9.5 3.7",
    stroke: "#fff",
    strokeWidth: "1.8",
    strokeLinecap: "round",
    strokeLinejoin: "round"
  })));
  if (on) return /*#__PURE__*/React.createElement("svg", {
    width: "18",
    height: "18",
    viewBox: "0 0 18 18",
    style: {
      flex: "none",
      transform: `rotate(${spin}deg)`
    }
  }, /*#__PURE__*/React.createElement("circle", {
    cx: "9",
    cy: "9",
    r: "7",
    fill: "none",
    stroke: ACC,
    strokeWidth: "2",
    strokeDasharray: "11 33",
    strokeLinecap: "round"
  }));
  return /*#__PURE__*/React.createElement("svg", {
    width: "18",
    height: "18",
    viewBox: "0 0 18 18",
    style: {
      flex: "none"
    }
  }, /*#__PURE__*/React.createElement("circle", {
    cx: "9",
    cy: "9",
    r: "7",
    fill: "none",
    stroke: "var(--color-grey-500)",
    strokeWidth: "1.5",
    strokeDasharray: "0.5 3.5",
    strokeLinecap: "round"
  }));
}

/* ---- 1. Reviews in a real environment ---- */
function EnvDemo() {
  const t = crClock(6800);
  const steps = ["Cloned repo and compiled project", "Ran 243 tests \u2014 all passing", "Reviewed 12 files, 3 issues fixed"];
  const active = Math.min(steps.length, Math.floor(t * (steps.length + 1.2)));
  return /*#__PURE__*/React.createElement("div", {
    style: {
      ...PANEL,
      display: "flex",
      flexDirection: "column",
      justifyContent: "center",
      gap: 22
    }
  }, steps.map((s, i) => {
    const done = i < active,
      on = i === active;
    return /*#__PURE__*/React.createElement("div", {
      key: i,
      style: {
        ...cr_card,
        borderRadius: 999,
        padding: "20px 26px",
        display: "flex",
        alignItems: "center",
        gap: 14,
        opacity: i <= active ? 1 : 0.5,
        transform: on ? "scale(1.015)" : "scale(1)",
        transition: "opacity 0.4s, transform 0.4s"
      }
    }, /*#__PURE__*/React.createElement(Spinner, {
      t: t,
      on: on,
      done: done
    }), /*#__PURE__*/React.createElement("span", {
      style: {
        fontFamily: "var(--font-mono)",
        fontSize: "1.0625rem",
        color: INK,
        letterSpacing: "-0.01em"
      }
    }, s));
  }));
}

/* ---- 2. Your rules, your standards ---- */
function RulesDemo() {
  const t = crClock(7000);
  const rules = [["No raw SQL in handlers", "ok"], ["Require tests for new endpoints", "ok"], ["No secrets in source", "ok"], ["Public APIs must be documented", "warn"], ["Use the design-system tokens", "ok"]];
  const checked = Math.min(rules.length, Math.floor((t - 0.1) / 0.14));
  return /*#__PURE__*/React.createElement("div", {
    style: {
      ...PANEL,
      display: "flex",
      alignItems: "center",
      justifyContent: "center"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      ...cr_card,
      width: "92%",
      overflow: "hidden"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 9,
      padding: "15px 18px",
      borderBottom: `0.5px solid ${HAIR}`
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 26,
      height: 26,
      borderRadius: 7,
      background: "var(--color-porcelain-grey)",
      display: "grid",
      placeItems: "center",
      color: INK
    }
  }, CR_ICON.rules), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 12.5,
      color: INK
    }
  }, "review-policy.yaml"), /*#__PURE__*/React.createElement("span", {
    style: {
      marginLeft: "auto",
      fontFamily: "var(--font-mono)",
      fontSize: 11,
      color: "var(--color-grey-700)"
    }
  }, Math.min(checked, rules.length), "/", rules.length)), /*#__PURE__*/React.createElement("div", {
    style: {
      padding: "8px 0"
    }
  }, rules.map(([label, kind], i) => {
    const ok = i < checked;
    const warn = ok && kind === "warn";
    return /*#__PURE__*/React.createElement("div", {
      key: i,
      style: {
        display: "flex",
        alignItems: "center",
        gap: 12,
        padding: "11px 18px",
        opacity: i <= checked ? 1 : 0.4
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        width: 17,
        height: 17,
        flex: "none",
        display: "grid",
        placeItems: "center"
      }
    }, ok ? /*#__PURE__*/React.createElement("span", {
      style: {
        width: 17,
        height: 17,
        borderRadius: "50%",
        background: warn ? "var(--color-amber-500, #d98a1f)" : ACC,
        display: "grid",
        placeItems: "center"
      }
    }, warn ? /*#__PURE__*/React.createElement("span", {
      style: {
        width: 2.4,
        height: 8,
        background: "#fff",
        borderRadius: 2
      }
    }) : /*#__PURE__*/React.createElement("svg", {
      width: "9",
      height: "9",
      viewBox: "0 0 12 12",
      fill: "none"
    }, /*#__PURE__*/React.createElement("path", {
      d: "M2.5 6.3 L5 8.5 L9.5 3.7",
      stroke: "#fff",
      strokeWidth: "1.8",
      strokeLinecap: "round",
      strokeLinejoin: "round"
    }))) : /*#__PURE__*/React.createElement("span", {
      style: {
        width: 13,
        height: 13,
        borderRadius: "50%",
        border: `1.5px solid var(--color-grey-500)`
      }
    })), /*#__PURE__*/React.createElement("span", {
      style: {
        fontFamily: "var(--font-sans)",
        fontSize: "0.9375rem",
        color: INK
      }
    }, label), warn && /*#__PURE__*/React.createElement("span", {
      style: {
        marginLeft: "auto",
        fontFamily: "var(--font-mono)",
        fontSize: 10.5,
        color: "var(--color-grey-700)"
      }
    }, "flagged"));
  }))));
}

/* ---- 3. Iterates until the build is green ---- */
function FixesDemo() {
  const t = crClock(8200);
  const rv = (s, d) => Math.max(0, Math.min(1, (t - s) / (d || 0.05)));
  // phase clock: run1 → fail → fix → run2 → pass → green
  const failed = t > 0.16,
    fixing = t > 0.34,
    rerun = t > 0.52,
    passed = t > 0.7;
  const green = t > 0.82;
  const status = green ? "build green" : passed ? "all tests passing" : rerun ? "re-running tests…" : fixing ? "applying fix…" : failed ? "2 tests failing" : "running tests…";
  const statColor = passed || green ? ACC : failed && !fixing ? RED : "var(--color-grey-700)";
  const rows = [{
    txt: "Attempt 1 · ran 243 tests",
    tone: failed ? "fail" : "run",
    show: rv(0.06)
  }, {
    txt: "FAIL  resolver pending-state path",
    tone: "fail",
    show: failed ? rv(0.16) : 0
  }, {
    txt: "Fix applied · == → ===, return retry",
    tone: "fix",
    show: fixing ? rv(0.34) : 0
  }, {
    txt: "Attempt 2 · re-running 243 tests",
    tone: rerun && !passed ? "run" : "pass",
    show: rerun ? rv(0.52) : 0
  }, {
    txt: "PASS  243 passed, 0 failing",
    tone: "pass",
    show: passed ? rv(0.7) : 0
  }];
  const toneColor = {
    fail: RED,
    fix: INK,
    run: "var(--color-grey-700)",
    pass: ACC
  };
  return /*#__PURE__*/React.createElement("div", {
    style: {
      ...PANEL,
      display: "flex",
      flexDirection: "column",
      justifyContent: "center",
      gap: 16
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      ...cr_card,
      overflow: "hidden"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 8,
      padding: "13px 16px",
      borderBottom: `0.5px solid ${HAIR}`
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      display: "flex",
      gap: 5
    }
  }, [0, 1, 2].map(i => /*#__PURE__*/React.createElement("span", {
    key: i,
    style: {
      width: 8,
      height: 8,
      borderRadius: "50%",
      background: "#dcdcdc"
    }
  }))), /*#__PURE__*/React.createElement("span", {
    style: {
      marginLeft: 4,
      fontFamily: "var(--font-mono)",
      fontSize: 11.5,
      color: "var(--color-grey-700)"
    }
  }, "CI \xB7 resolver.ts"), /*#__PURE__*/React.createElement("span", {
    style: {
      marginLeft: "auto",
      display: "flex",
      alignItems: "center",
      gap: 7,
      fontFamily: "var(--font-sans)",
      fontSize: 12,
      color: statColor
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 8,
      height: 8,
      borderRadius: "50%",
      background: statColor,
      boxShadow: green ? `0 0 0 3px color-mix(in srgb, ${ACC} 28%, transparent)` : "none"
    }
  }), status)), /*#__PURE__*/React.createElement("div", {
    style: {
      padding: "10px 0",
      fontFamily: "var(--font-mono)",
      fontSize: 12,
      minHeight: 188
    }
  }, rows.map((r, i) => /*#__PURE__*/React.createElement("div", {
    key: i,
    style: {
      display: "flex",
      alignItems: "center",
      gap: 11,
      padding: "8px 16px",
      opacity: r.show,
      transform: `translateY(${(1 - r.show) * 6}px)`,
      transition: "opacity 0.3s, transform 0.3s"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 15,
      flex: "none",
      display: "grid",
      placeItems: "center"
    }
  }, r.tone === "pass" ? /*#__PURE__*/React.createElement("svg", {
    width: "13",
    height: "13",
    viewBox: "0 0 12 12",
    fill: "none"
  }, /*#__PURE__*/React.createElement("circle", {
    cx: "6",
    cy: "6",
    r: "6",
    fill: ACC
  }), /*#__PURE__*/React.createElement("path", {
    d: "M3 6.2 L5.2 8.2 L9 3.8",
    stroke: "#fff",
    strokeWidth: "1.5",
    strokeLinecap: "round",
    strokeLinejoin: "round"
  })) : r.tone === "fail" ? /*#__PURE__*/React.createElement("svg", {
    width: "13",
    height: "13",
    viewBox: "0 0 12 12",
    fill: "none"
  }, /*#__PURE__*/React.createElement("circle", {
    cx: "6",
    cy: "6",
    r: "6",
    fill: RED
  }), /*#__PURE__*/React.createElement("path", {
    d: "M4 4 L8 8 M8 4 L4 8",
    stroke: "#fff",
    strokeWidth: "1.5",
    strokeLinecap: "round"
  })) : r.tone === "fix" ? /*#__PURE__*/React.createElement("span", {
    style: {
      width: 7,
      height: 7,
      borderRadius: 2,
      background: INK,
      transform: "rotate(45deg)"
    }
  }) : /*#__PURE__*/React.createElement("span", {
    style: {
      width: 9,
      height: 9,
      borderRadius: "50%",
      border: `1.5px solid var(--color-grey-500)`
    }
  })), /*#__PURE__*/React.createElement("span", {
    style: {
      color: toneColor[r.tone],
      whiteSpace: "nowrap"
    }
  }, r.txt))))), /*#__PURE__*/React.createElement("div", {
    style: {
      ...cr_card,
      padding: "13px 16px",
      display: "flex",
      alignItems: "center",
      gap: 11,
      opacity: rv(0.84),
      background: green ? `color-mix(in srgb, ${ACC} 9%, var(--color-white))` : "var(--color-white)"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 26,
      height: 26,
      borderRadius: 8,
      background: INK,
      display: "grid",
      placeItems: "center",
      flex: "none",
      color: "#fff"
    }
  }, /*#__PURE__*/React.createElement(CrLogo, {
    size: 14
  })), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: 13,
      color: "var(--color-grey-900)",
      lineHeight: 1.4
    }
  }, "Iterated twice \u2014 fixed the logic, reran the suite. ", /*#__PURE__*/React.createElement("span", {
    style: {
      color: INK,
      fontWeight: 600
    }
  }, "Build is green."), " PR ready to review.")));
}

/* ---- 4. Triggered on every PR ---- */
function EveryPRDemo() {
  const t = crClock(7600);
  const steps = [["PR opened", "Triggered when a pull request is opened or marked ready for review.", true], ["Gather context", "Fetch PR description, commit messages, comments, and code diff against main."], ["Review code changes", "Analyze diff for correctness, performance, test coverage, consistency."], ["Run test suite", "Execute tests in an isolated environment to validate the changes."], ["Post review", "Submit inline comments for medium and high severity issues."]];
  const active = Math.min(steps.length - 1, Math.floor(t * (steps.length + 0.7)));
  return /*#__PURE__*/React.createElement("div", {
    style: {
      ...PANEL,
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      padding: "0 24px"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      width: "100%",
      display: "flex",
      flexDirection: "column",
      gap: 9
    }
  }, steps.map(([title, desc, trig], i) => {
    const done = i < active,
      on = i === active;
    const depth = Math.max(0, i - active);
    return /*#__PURE__*/React.createElement("div", {
      key: i,
      style: {
        ...cr_card,
        padding: "13px 16px",
        opacity: i <= active ? 1 : Math.max(0.4, 0.92 - depth * 0.18),
        transform: on ? "scale(1.015)" : `scale(${1 - depth * 0.012})`,
        boxShadow: on ? "var(--shadow-md)" : "var(--shadow-xs)",
        transition: "opacity 0.35s, transform 0.35s, box-shadow 0.35s"
      }
    }, trig && /*#__PURE__*/React.createElement("span", {
      style: {
        display: "inline-flex",
        alignItems: "center",
        gap: 5,
        background: "color-mix(in srgb, var(--color-pistachio-green) 55%, var(--color-white))",
        color: "var(--color-green-700, #1f7a4d)",
        borderRadius: 6,
        padding: "2px 8px",
        fontFamily: "var(--font-mono)",
        fontSize: 10.5,
        marginBottom: 8
      }
    }, /*#__PURE__*/React.createElement("svg", {
      width: "10",
      height: "10",
      viewBox: "0 0 24 24",
      fill: "none",
      stroke: "currentColor",
      strokeWidth: "2"
    }, /*#__PURE__*/React.createElement("circle", {
      cx: "12",
      cy: "12",
      r: "9"
    }), /*#__PURE__*/React.createElement("path", {
      d: "M10 8 L16 12 L10 16 Z",
      fill: "currentColor",
      stroke: "none"
    })), "Trigger"), /*#__PURE__*/React.createElement("div", {
      style: {
        display: "flex",
        alignItems: "center",
        gap: 9
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        fontFamily: "var(--font-sans)",
        fontSize: "1.0625rem",
        color: INK
      }
    }, title), done && /*#__PURE__*/React.createElement("span", {
      style: {
        marginLeft: "auto",
        width: 16,
        height: 16,
        borderRadius: "50%",
        background: ACC,
        display: "grid",
        placeItems: "center",
        flex: "none"
      }
    }, /*#__PURE__*/React.createElement("svg", {
      width: "9",
      height: "9",
      viewBox: "0 0 12 12",
      fill: "none"
    }, /*#__PURE__*/React.createElement("path", {
      d: "M2.5 6.3 L5 8.5 L9.5 3.7",
      stroke: "#fff",
      strokeWidth: "1.8",
      strokeLinecap: "round",
      strokeLinejoin: "round"
    }))), on && /*#__PURE__*/React.createElement("span", {
      style: {
        marginLeft: "auto",
        flex: "none"
      }
    }, /*#__PURE__*/React.createElement("svg", {
      width: "17",
      height: "17",
      viewBox: "0 0 18 18",
      style: {
        transform: `rotate(${t * 1440 % 360}deg)`
      }
    }, /*#__PURE__*/React.createElement("circle", {
      cx: "9",
      cy: "9",
      r: "7",
      fill: "none",
      stroke: ACC,
      strokeWidth: "2",
      strokeDasharray: "11 33",
      strokeLinecap: "round"
    })))), (on || done) && /*#__PURE__*/React.createElement("div", {
      style: {
        fontFamily: "var(--font-sans)",
        fontSize: "0.8125rem",
        color: "var(--color-grey-700)",
        marginTop: 5,
        lineHeight: 1.4
      }
    }, desc));
  })));
}

/* ---- 5. Every review is logged and traceable ---- */
function AuditDemo() {
  const t = crClock(8000);
  const logs = [["1:21:08", "Creating VM"], ["1:21:08", "VM configuration · cores=8 mem=16G"], ["1:21:08", "nested virtualization enabled"], ["1:21:08", "Starting VM"], ["1:21:09", "Starting registry cache proxy"], ["1:21:10", "using SSH port=65304"], ["1:21:11", "Connecting to registry cache port=60"], ["1:21:11", "Successfully established registry cache"], ["1:21:11", "using supervisor port=65303"], ["1:21:12", "using root port=65311"]];
  const shown = Math.min(logs.length, Math.max(0, Math.floor((t - 0.08) / 0.072)));
  return /*#__PURE__*/React.createElement("div", {
    style: {
      ...PANEL,
      padding: 0,
      display: "flex",
      flexDirection: "column",
      overflow: "hidden"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      background: "var(--color-white)",
      borderRadius: "calc(var(--radius-card) - 2px) calc(var(--radius-card) - 2px) 0 0",
      margin: "14px 14px 0",
      border: `0.5px solid ${HAIR}`,
      borderBottom: "none",
      flex: 1,
      display: "flex",
      flexDirection: "column",
      overflow: "hidden"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      padding: "16px 20px",
      borderBottom: `0.5px solid ${HAIR}`
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.375rem",
      color: INK
    }
  }, "Logs"), /*#__PURE__*/React.createElement("span", {
    style: {
      marginLeft: "auto",
      display: "flex",
      alignItems: "center",
      gap: 7,
      fontFamily: "var(--font-mono)",
      fontSize: 11,
      color: ACC
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 7,
      height: 7,
      borderRadius: "50%",
      background: ACC
    }
  }), "recording")), /*#__PURE__*/React.createElement("div", {
    style: {
      flex: 1,
      overflow: "hidden"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 8,
      padding: "11px 18px",
      background: "var(--color-porcelain-grey)",
      fontFamily: "var(--font-sans)",
      fontSize: 13.5,
      color: INK
    }
  }, /*#__PURE__*/React.createElement("svg", {
    width: "13",
    height: "13",
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: "2",
    strokeLinecap: "round"
  }, /*#__PURE__*/React.createElement("path", {
    d: "M6 9 L12 15 L18 9"
  })), "Creating virtual machine"), /*#__PURE__*/React.createElement("div", {
    style: {
      padding: "10px 18px",
      fontFamily: "var(--font-mono)",
      fontSize: 12.5,
      lineHeight: 2
    }
  }, logs.slice(0, shown).map(([ts, msg], i) => /*#__PURE__*/React.createElement("div", {
    key: i,
    style: {
      display: "flex",
      gap: 10,
      whiteSpace: "nowrap",
      overflow: "hidden"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      color: ACC,
      flex: "none"
    }
  }, ts, /*#__PURE__*/React.createElement("span", {
    style: {
      color: "var(--color-grey-600)",
      marginLeft: 4
    }
  }, "PM")), /*#__PURE__*/React.createElement("span", {
    style: {
      color: INK,
      overflow: "hidden",
      textOverflow: "ellipsis"
    }
  }, msg))), shown < logs.length && /*#__PURE__*/React.createElement("span", {
    style: {
      display: "inline-block",
      width: 7,
      height: 14,
      background: ACC,
      opacity: Math.sin(t * Math.PI * 2 * 6) > 0 ? 0.8 : 0
    }
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 8,
      padding: "11px 18px",
      borderTop: `0.5px solid ${HAIR}`,
      fontFamily: "var(--font-sans)",
      fontSize: 13.5,
      color: "var(--color-grey-700)"
    }
  }, /*#__PURE__*/React.createElement("svg", {
    width: "13",
    height: "13",
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: "2",
    strokeLinecap: "round"
  }, /*#__PURE__*/React.createElement("path", {
    d: "M9 6 L15 12 L9 18"
  })), "System logs"))));
}
const CR_TABS = [{
  icon: "env",
  label: "Reviews in a real environment",
  demo: EnvDemo,
  heading: "Reviews by running your app, like an engineer",
  body: ["Instead of comparing a diff, Hypervisor runs your application in an isolated environment and reviews it the way an engineer would, catching integration breaks and logic errors static tools miss."]
}, {
  icon: "rules",
  label: "Your rules, your standards",
  demo: RulesDemo,
  heading: "Your rules, your standards",
  body: ["Encode your team's conventions as policy. Hypervisor checks every PR against the standards you define \u2014 style, security, testing, docs \u2014 and flags what falls short."]
}, {
  icon: "fixes",
  label: "Fixes, not just flags",
  demo: FixesDemo,
  heading: "Iterates until the build is green",
  body: ["When Hypervisor finds an issue it fixes the code, reruns the tests, and keeps iterating until the build passes. PRs arrive ready to review, not ready to debug."]
}, {
  icon: "pr",
  label: "Every PR, every repo",
  demo: EveryPRDemo,
  heading: "Triggered on every PR, or before you open one",
  body: ["Runs automatically on every PR across your org with no per-repo setup \u2014 or let developers trigger a review before they push, while they're still in context."]
}, {
  icon: "audit",
  label: "Audit ready by design",
  demo: AuditDemo,
  heading: "Every review is logged and traceable",
  body: ["Each review runs in an isolated environment with scoped credentials and full logging, so what was checked, flagged, and approved is recorded automatically for compliance."]
}];
function CrHero() {
  return /*#__PURE__*/React.createElement("section", {
    style: {
      ...crwrap,
      paddingTop: "4rem",
      textAlign: "center",
      display: "flex",
      flexDirection: "column",
      alignItems: "center"
    }
  }, /*#__PURE__*/React.createElement(CrEyebrow, {
    color: "var(--color-link-green)"
  }, "Solutions \xB7 AI code review"), /*#__PURE__*/React.createElement("h1", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "3.5rem",
      lineHeight: 1.05,
      letterSpacing: "-0.02em",
      margin: "1.25rem 0 0",
      maxWidth: "18ch",
      color: INK
    }
  }, "Review that runs your code, not just reads it"), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.1875rem",
      color: "var(--color-grey-800)",
      marginTop: "1.25rem",
      maxWidth: "54ch",
      lineHeight: 1.5
    }
  }, "Hypervisor reviews pull requests the way an engineer would \u2014 in an isolated environment, running real tests, fixing what it finds, and carrying a receipt for every action."));
}
function CrFeatureBlock() {
  const [active, setActive] = React.useState(0);
  const tab = CR_TABS[active];
  const Demo = tab.demo;
  return /*#__PURE__*/React.createElement("section", {
    style: {
      ...crwrap,
      paddingTop: "5rem"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      background: "var(--color-white)",
      border: `0.5px solid ${HAIR}`,
      borderRadius: "var(--radius-card)",
      padding: "2.5rem",
      display: "grid",
      gridTemplateColumns: "16rem 1fr",
      gap: "2.5rem",
      alignItems: "start"
    }
  }, /*#__PURE__*/React.createElement("ul", {
    style: {
      listStyle: "none",
      margin: 0,
      padding: 0,
      display: "flex",
      flexDirection: "column",
      gap: 4
    }
  }, CR_TABS.map((tb, i) => {
    const on = i === active;
    return /*#__PURE__*/React.createElement("li", {
      key: tb.label
    }, /*#__PURE__*/React.createElement("button", {
      onClick: () => setActive(i),
      style: {
        width: "100%",
        textAlign: "left",
        display: "flex",
        alignItems: "center",
        gap: 11,
        padding: "12px 14px",
        borderRadius: "var(--radius-lg)",
        border: "none",
        cursor: "pointer",
        background: on ? "var(--color-porcelain-grey)" : "transparent",
        color: on ? INK : "var(--color-grey-800)",
        fontFamily: "var(--font-sans)",
        fontSize: "0.9375rem",
        fontWeight: on ? 500 : 400,
        lineHeight: 1.3
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        color: on ? ACC : "var(--color-grey-600)",
        display: "grid",
        placeItems: "center",
        flex: "none"
      }
    }, CR_ICON[tb.icon]), tb.label));
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "1fr 1.15fr",
      gap: "2.5rem",
      alignItems: "center"
    }
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("h2", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "2.125rem",
      letterSpacing: "-0.02em",
      lineHeight: 1.12,
      margin: 0,
      color: INK
    }
  }, tab.heading), tab.body.map((p, i) => /*#__PURE__*/React.createElement("p", {
    key: i,
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.0625rem",
      color: "var(--color-grey-800)",
      marginTop: "1.25rem",
      lineHeight: 1.5,
      maxWidth: "42ch"
    }
  }, p))), /*#__PURE__*/React.createElement(Demo, null))));
}
function CrCTA() {
  return /*#__PURE__*/React.createElement("section", {
    style: {
      ...crwrap,
      paddingTop: "8rem",
      textAlign: "center"
    }
  }, /*#__PURE__*/React.createElement("h2", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "3rem",
      letterSpacing: "-0.02em",
      margin: 0,
      color: INK
    }
  }, "Put a reviewer on every PR"), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      gap: "0.5rem",
      justifyContent: "center",
      marginTop: "1.75rem"
    }
  }, /*#__PURE__*/React.createElement(CrButton, {
    iconRight: /*#__PURE__*/React.createElement("span", null, "\u2192")
  }, "Get started"), /*#__PURE__*/React.createElement(CrLink, {
    href: "solutions.html"
  }, "Back to solutions")));
}
function HvPage() {
  return /*#__PURE__*/React.createElement("main", null, /*#__PURE__*/React.createElement(CrHero, null), /*#__PURE__*/React.createElement(CrFeatureBlock, null), /*#__PURE__*/React.createElement(CrCTA, null));
}
window.HvPage = HvPage;
window.HvPageActive = "Solutions";
})(); } catch (e) { __ds_ns.__errors.push({ path: "site/CodeReview.jsx", error: String((e && e.message) || e) }); }

// site/Developers.jsx
try { (() => {
// hypervisor.com — Developers page.
const DNS = window.IoiDesignSystem;
const {
  Button: DgButton,
  Badge: DgBadge,
  Card: DgCard,
  TextLink: DgLink,
  Eyebrow: DgEyebrow
} = DNS;
const dwrap = {
  maxWidth: "75rem",
  margin: "0 auto",
  padding: "0 2.5rem"
};
const SURFACES = [["CLI / Headless", "The operator, scripting, CI, and node-ops client. A TUI is an optional presentation of the same controls — never a separate runtime."], ["SDK", "The low-level protocol/client library. Drive runs, read receipts, and integrate the daemon API into your own tools."], ["ADK", "The autonomous-system builder framework. Compose workers, workflows, and policies as deployable packages."], ["Daemon API", "The public runtime surface: projects, GoalRuns, Automations, Sessions, delegated work queues, adapter targets, and short-lived access tokens."], ["AIIP", "The semantic interop protocol for bounded autonomous-work handoffs between independently governed systems; same-system work stays on native L0 coordination."], ["Worker packages", "Ship workers as benchmarked, manifested, installable packages routed through Mixture of Workers."]];
const CODE = `# install the runtime + clients
npm install
cargo check --workspace

# run the local operator surface
npm run dev:hypervisor-app

# delegate work under a scoped authority
hv run "modernize payments-api" \\
  --scope prim:fs.write,scope:repo.write \\
  --receipt --replay`;
const dvINK = "var(--color-onyx-black)";
const dvHAIR = "var(--color-grey-500)";
const dvACC = "var(--color-link-green)";
const dvPANEL = {
  background: "color-mix(in srgb, var(--color-pistachio-green) 28%, var(--color-white))",
  border: `0.5px solid ${dvHAIR}`,
  borderRadius: "var(--radius-card)",
  height: 460,
  padding: "2rem",
  position: "relative",
  overflow: "hidden"
};
const dvCard = {
  background: "var(--color-white)",
  border: `0.5px solid ${dvHAIR}`,
  borderRadius: 14,
  boxShadow: "var(--shadow-sm)"
};
function dvClock(period) {
  const [t, setT] = React.useState(0);
  React.useEffect(() => {
    const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduce) {
      setT(0.85);
      return;
    }
    let raf,
      start = null;
    const tick = ts => {
      if (start == null) start = ts;
      setT((ts - start) % period / period);
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, []);
  return t;
}
function DvSpinner({
  t,
  on,
  done
}) {
  const spin = t * 1440 % 360;
  if (done) return /*#__PURE__*/React.createElement("span", {
    style: {
      width: 17,
      height: 17,
      borderRadius: "50%",
      background: dvACC,
      display: "grid",
      placeItems: "center",
      flex: "none"
    }
  }, /*#__PURE__*/React.createElement("svg", {
    width: "9",
    height: "9",
    viewBox: "0 0 12 12",
    fill: "none"
  }, /*#__PURE__*/React.createElement("path", {
    d: "M2.5 6.3 L5 8.5 L9.5 3.7",
    stroke: "#fff",
    strokeWidth: "1.8",
    strokeLinecap: "round",
    strokeLinejoin: "round"
  })));
  if (on) return /*#__PURE__*/React.createElement("svg", {
    width: "17",
    height: "17",
    viewBox: "0 0 18 18",
    style: {
      flex: "none",
      transform: `rotate(${spin}deg)`
    }
  }, /*#__PURE__*/React.createElement("circle", {
    cx: "9",
    cy: "9",
    r: "7",
    fill: "none",
    stroke: dvACC,
    strokeWidth: "2",
    strokeDasharray: "11 33",
    strokeLinecap: "round"
  }));
  return /*#__PURE__*/React.createElement("svg", {
    width: "17",
    height: "17",
    viewBox: "0 0 18 18",
    style: {
      flex: "none"
    }
  }, /*#__PURE__*/React.createElement("circle", {
    cx: "9",
    cy: "9",
    r: "7",
    fill: "none",
    stroke: "var(--color-grey-500)",
    strokeWidth: "1.5",
    strokeDasharray: "0.5 3.5",
    strokeLinecap: "round"
  }));
}

/* ---- 1. Build custom workflows (pipeline) ---- */
function dvWorkflowDemo() {
  const t = dvClock(8000);
  const steps = [["Trigger", "Daily schedule", "Runs at 9 AM on weekdays.", dvACC], ["Prompt", "Fetch and select issue from Jira", "Fetch first feasible issues from the current sprint. Sort by priority and due date.", "var(--color-grey-700)"], ["Shell Script", "Run tests", "npm test || go test ./... || yarn test || echo \"done\"", "var(--color-grey-700)"], ["Pull Request", "Open draft PR", "Create a draft pull request linked to the Jira issue.", dvACC]];
  const active = Math.min(steps.length, Math.floor(t * (steps.length + 1.1)));
  return /*#__PURE__*/React.createElement("div", {
    style: {
      ...dvPANEL,
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      padding: "0 24px"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      width: "100%",
      display: "flex",
      flexDirection: "column"
    }
  }, steps.map(([kind, title, desc, c], i) => {
    const done = i < active,
      on = i === active;
    return /*#__PURE__*/React.createElement(React.Fragment, {
      key: i
    }, i > 0 && /*#__PURE__*/React.createElement("span", {
      style: {
        width: 1.5,
        height: 16,
        background: i <= active ? dvACC : dvHAIR,
        margin: "0 auto",
        transition: "background 0.3s"
      }
    }), /*#__PURE__*/React.createElement("div", {
      style: {
        ...dvCard,
        padding: "13px 16px",
        opacity: i <= active ? 1 : 0.45,
        transform: on ? "scale(1.015)" : "scale(1)",
        boxShadow: on ? "var(--shadow-md)" : "var(--shadow-xs)",
        transition: "opacity 0.35s, transform 0.35s, box-shadow 0.35s"
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        display: "flex",
        alignItems: "center",
        gap: 8
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        display: "inline-flex",
        alignItems: "center",
        gap: 5,
        background: "var(--color-porcelain-grey)",
        borderRadius: 6,
        padding: "2px 8px",
        fontFamily: "var(--font-mono)",
        fontSize: 10.5,
        color: dvINK
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        width: 6,
        height: 6,
        borderRadius: "50%",
        background: c
      }
    }), kind), done && /*#__PURE__*/React.createElement("span", {
      style: {
        marginLeft: "auto"
      }
    }, /*#__PURE__*/React.createElement(DvSpinner, {
      t: t,
      done: true
    })), on && /*#__PURE__*/React.createElement("span", {
      style: {
        marginLeft: "auto"
      }
    }, /*#__PURE__*/React.createElement(DvSpinner, {
      t: t,
      on: true
    }))), /*#__PURE__*/React.createElement("div", {
      style: {
        fontFamily: "var(--font-sans)",
        fontSize: "1rem",
        color: dvINK,
        marginTop: 8
      }
    }, title), /*#__PURE__*/React.createElement("div", {
      style: {
        fontFamily: kind === "Shell Script" ? "var(--font-mono)" : "var(--font-sans)",
        fontSize: kind === "Shell Script" ? "0.75rem" : "0.8125rem",
        color: "var(--color-grey-700)",
        marginTop: 4,
        lineHeight: 1.4,
        whiteSpace: "nowrap",
        overflow: "hidden",
        textOverflow: "ellipsis"
      }
    }, desc)));
  })));
}

/* ---- 2. Trigger from any event (pills) ---- */
function dvTriggerDemo() {
  const t = dvClock(5600);
  const items = ["Webhooks", "Scheduled", "Pull Requests", "Manual"];
  const active = Math.min(items.length - 1, Math.floor(t * (items.length + 0.4)));
  return /*#__PURE__*/React.createElement("div", {
    style: {
      ...dvPANEL,
      display: "flex",
      flexDirection: "column",
      justifyContent: "center",
      alignItems: "center",
      gap: 16
    }
  }, items.map((label, i) => {
    const fired = i < active,
      firing = i === active;
    return /*#__PURE__*/React.createElement("div", {
      key: label,
      style: {
        ...dvCard,
        width: "82%",
        borderRadius: 999,
        padding: "15px 24px",
        display: "flex",
        alignItems: "center",
        gap: 14,
        transform: firing ? "scale(1.02)" : "scale(1)",
        boxShadow: firing ? "var(--shadow-md)" : "var(--shadow-xs)",
        transition: "transform 0.3s, box-shadow 0.3s"
      }
    }, /*#__PURE__*/React.createElement(DvSpinner, {
      t: t,
      on: firing,
      done: fired
    }), /*#__PURE__*/React.createElement("span", {
      style: {
        fontFamily: "var(--font-sans)",
        fontSize: "1.0625rem",
        color: dvINK
      }
    }, label));
  }));
}

/* ---- 3. Execute across thousands of repos (migration list) ---- */
function dvScaleDemo() {
  const t = dvClock(7000);
  const rows = [["JAVA 8 \u2192 JAVA 17", "Repository 01 \u00b7 1 min ago"], ["COBOL \u2192 JAVA", "Repository 02 \u00b7 30 sec ago"], ["JAVA 8 \u2192 JAVA 17", "AetherNet \u00b7 started 10s ago"], ["JAVA 8 \u2192 JAVA 17", "Project Phoenix \u00b7 started 9s ago"], ["JAVA 8 \u2192 JAVA 17", "InfernoCore \u00b7 started 8s ago"], ["JAVA 8 \u2192 JAVA 17", "PyroLink \u00b7 started 7s ago"]];
  const done = Math.max(0, Math.min(rows.length, Math.floor((t - 0.12) / 0.12)));
  const count = 1 + done + Math.floor(t * 9);
  return /*#__PURE__*/React.createElement("div", {
    style: {
      ...dvPANEL,
      padding: 0,
      overflow: "hidden"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      ...dvCard,
      margin: 16,
      borderRadius: 14,
      overflow: "hidden",
      boxShadow: "var(--shadow-md)"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 9,
      padding: "14px 18px",
      borderBottom: `0.5px solid ${dvHAIR}`
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 8,
      height: 8,
      borderRadius: "50%",
      background: dvACC,
      flex: "none"
    }
  }), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: 14,
      color: dvINK
    }
  }, "Migration in progress\u2026"), /*#__PURE__*/React.createElement("span", {
    style: {
      marginLeft: "auto",
      fontFamily: "var(--font-mono)",
      fontSize: 12,
      color: "var(--color-grey-700)",
      background: "var(--color-porcelain-grey)",
      border: `0.5px solid ${dvHAIR}`,
      borderRadius: 999,
      padding: "3px 10px"
    }
  }, count, "/210")), /*#__PURE__*/React.createElement("div", {
    style: {
      padding: "6px 0",
      WebkitMaskImage: "linear-gradient(180deg, #000 62%, transparent)",
      maskImage: "linear-gradient(180deg, #000 62%, transparent)"
    }
  }, rows.map(([title, meta], i) => {
    const ok = i < done,
      on = i === done;
    return /*#__PURE__*/React.createElement("div", {
      key: i,
      style: {
        display: "flex",
        alignItems: "center",
        gap: 12,
        padding: "11px 18px",
        opacity: i <= done ? 1 : Math.max(0.2, 0.85 - (i - done) * 0.22)
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        fontFamily: "var(--font-mono)",
        fontSize: 13,
        color: "var(--color-grey-600)",
        width: 16,
        flex: "none"
      }
    }, i + 1, "."), /*#__PURE__*/React.createElement("div", {
      style: {
        flex: 1,
        minWidth: 0
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        fontFamily: "var(--font-sans)",
        fontSize: "0.9375rem",
        color: dvINK,
        whiteSpace: "nowrap"
      }
    }, title), /*#__PURE__*/React.createElement("div", {
      style: {
        fontFamily: "var(--font-sans)",
        fontSize: "0.75rem",
        color: "var(--color-grey-600)",
        marginTop: 2,
        whiteSpace: "nowrap",
        overflow: "hidden",
        textOverflow: "ellipsis"
      }
    }, meta)), /*#__PURE__*/React.createElement(DvSpinner, {
      t: t,
      on: on,
      done: ok
    }));
  }))));
}
const DV_TABS = [{
  label: "Build custom workflows",
  sub: "Combine prompts, scripts, and integrations into reusable automations.",
  demo: dvWorkflowDemo
}, {
  label: "Trigger from any event",
  sub: "Run from webhooks, pull requests, schedules, or on demand.",
  demo: dvTriggerDemo
}, {
  label: "Execute across thousands of repos",
  sub: "Run across one repo or thousands — no extra configuration.",
  demo: dvScaleDemo
}];
function DvAutomations() {
  const [active, setActive] = React.useState(0);
  const tab = DV_TABS[active];
  const Demo = tab.demo;
  return /*#__PURE__*/React.createElement("section", {
    style: {
      ...dwrap,
      paddingTop: "6rem"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "1fr 1.1fr",
      gap: "3.5rem",
      alignItems: "center"
    }
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("h2", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "2.5rem",
      letterSpacing: "-0.02em",
      lineHeight: 1.08,
      margin: 0,
      color: dvINK
    }
  }, "Powered by automations"), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.0625rem",
      color: "var(--color-grey-800)",
      marginTop: "1rem",
      lineHeight: 1.5,
      maxWidth: "38ch"
    }
  }, "Repeatable workflows that combine prompts and scripts. Triggered from webhooks, PRs, schedules."), /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: "1.25rem"
    }
  }, /*#__PURE__*/React.createElement(DgLink, {
    href: "docs.html"
  }, "Start automating")), /*#__PURE__*/React.createElement("ul", {
    style: {
      listStyle: "none",
      margin: "2.25rem 0 0",
      padding: 0,
      display: "flex",
      flexDirection: "column",
      gap: 6
    }
  }, DV_TABS.map((tb, i) => {
    const on = i === active;
    return /*#__PURE__*/React.createElement("li", {
      key: tb.label
    }, /*#__PURE__*/React.createElement("button", {
      onClick: () => setActive(i),
      style: {
        width: "100%",
        textAlign: "left",
        display: "flex",
        alignItems: "flex-start",
        gap: 12,
        padding: "14px 16px",
        borderRadius: "var(--radius-lg)",
        border: "none",
        cursor: "pointer",
        background: on ? "var(--color-porcelain-grey)" : "transparent"
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        flex: 1
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        display: "block",
        fontFamily: "var(--font-sans)",
        fontSize: "1rem",
        fontWeight: on ? 600 : 500,
        color: dvINK
      }
    }, tb.label), /*#__PURE__*/React.createElement("span", {
      style: {
        display: "block",
        fontFamily: "var(--font-sans)",
        fontSize: "0.875rem",
        color: "var(--color-grey-700)",
        marginTop: 3,
        lineHeight: 1.4
      }
    }, tb.sub)), on && /*#__PURE__*/React.createElement("span", {
      style: {
        marginTop: 2
      }
    }, /*#__PURE__*/React.createElement(DvSpinner, {
      t: 0,
      on: true
    }))));
  }))), /*#__PURE__*/React.createElement(Demo, null)));
}
function HvPage() {
  return /*#__PURE__*/React.createElement("main", null, /*#__PURE__*/React.createElement("section", {
    style: {
      ...dwrap,
      paddingTop: "4rem",
      display: "grid",
      gridTemplateColumns: "1fr 1fr",
      gap: "3rem",
      alignItems: "center"
    }
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement(DgEyebrow, {
    color: "var(--color-link-green)"
  }, "Developers"), /*#__PURE__*/React.createElement("h1", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "3.25rem",
      lineHeight: 1.05,
      letterSpacing: "-0.02em",
      margin: "1.25rem 0 0",
      color: "var(--color-onyx-black)"
    }
  }, "Build on the runtime substrate"), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.125rem",
      color: "var(--color-grey-800)",
      marginTop: "1.25rem",
      maxWidth: "42ch",
      lineHeight: 1.5
    }
  }, "One execution substrate. No separate SDK, GUI, CLI, or harness owns consequential execution semantics \u2014 they all bind to the daemon."), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      gap: "0.5rem",
      marginTop: "2rem"
    }
  }, /*#__PURE__*/React.createElement(DgButton, {
    iconRight: /*#__PURE__*/React.createElement("span", null, "\u2192")
  }, "Read the docs"), /*#__PURE__*/React.createElement(DgButton, {
    variant: "outline"
  }, "API reference"))), /*#__PURE__*/React.createElement("div", {
    style: {
      background: "var(--color-onyx-black)",
      borderRadius: "var(--radius-card)",
      padding: "1.5rem 1.75rem",
      overflow: "hidden"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      gap: 6,
      marginBottom: "1rem"
    }
  }, ["#e1e1e1", "#cecece", "#818181"].map((c, i) => /*#__PURE__*/React.createElement("span", {
    key: i,
    style: {
      width: 11,
      height: 11,
      borderRadius: "50%",
      background: c,
      opacity: 0.5
    }
  }))), /*#__PURE__*/React.createElement("pre", {
    style: {
      margin: 0,
      fontFamily: "var(--font-mono)",
      fontSize: 12.5,
      lineHeight: 1.6,
      color: "var(--color-grey-600)",
      whiteSpace: "pre-wrap"
    }
  }, CODE))), /*#__PURE__*/React.createElement("section", {
    style: {
      ...dwrap,
      paddingTop: "6rem"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      maxWidth: "44rem"
    }
  }, /*#__PURE__*/React.createElement(DgEyebrow, null, "Surfaces"), /*#__PURE__*/React.createElement("h2", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "2.5rem",
      letterSpacing: "-0.02em",
      margin: "1rem 0 0"
    }
  }, "Clients, frameworks, and protocols")), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "repeat(3, 1fr)",
      gap: "1.25rem",
      marginTop: "2.5rem"
    }
  }, SURFACES.map(([t, d]) => /*#__PURE__*/React.createElement(DgCard, {
    key: t,
    style: {
      padding: "1.5rem 1.75rem"
    }
  }, /*#__PURE__*/React.createElement("h3", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: "1rem",
      margin: 0,
      color: "var(--color-onyx-black)"
    }
  }, t), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "0.9375rem",
      color: "var(--color-grey-800)",
      marginTop: "0.625rem",
      lineHeight: 1.45
    }
  }, d))))), /*#__PURE__*/React.createElement("section", {
    style: {
      ...dwrap,
      paddingTop: "6rem"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      background: "var(--color-porcelain-grey)",
      border: "0.5px solid var(--color-grey-500)",
      borderRadius: "var(--radius-card)",
      padding: "3rem",
      display: "grid",
      gridTemplateColumns: "1fr 1fr",
      gap: "2.5rem",
      alignItems: "center"
    }
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement(DgEyebrow, null, "The boundary"), /*#__PURE__*/React.createElement("h2", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "2rem",
      letterSpacing: "-0.02em",
      lineHeight: 1.1,
      margin: "1rem 0 0"
    }
  }, "Tool calls are requests, not grants"), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1rem",
      color: "var(--color-grey-800)",
      marginTop: "1rem",
      lineHeight: 1.5
    }
  }, "Raw model output is never authority for consequential action. The runtime collapses intent into a deterministic decision: allowed, denied, escalated, receipted, and replayable."), /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: "1.5rem"
    }
  }, /*#__PURE__*/React.createElement(DgLink, {
    href: "docs.html"
  }, "Read the conformance invariants"))), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      flexDirection: "column",
      gap: 8
    }
  }, [["prim:*", "what the runtime may execute"], ["scope:*", "what a wallet or tenant may authorize"], ["receipt", "legible, replayable evidence of every effect"]].map(([k, v]) => /*#__PURE__*/React.createElement("div", {
    key: k,
    style: {
      display: "flex",
      alignItems: "baseline",
      gap: 12,
      background: "var(--color-white)",
      border: "0.5px solid var(--color-grey-500)",
      borderRadius: "var(--radius-lg)",
      padding: "13px 15px"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 13,
      color: "var(--color-link-green)",
      minWidth: 72
    }
  }, k), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: 14,
      color: "var(--color-grey-900)"
    }
  }, v)))))), /*#__PURE__*/React.createElement(DvAutomations, null), /*#__PURE__*/React.createElement("section", {
    style: {
      ...dwrap,
      paddingTop: "8rem",
      textAlign: "center"
    }
  }, /*#__PURE__*/React.createElement("h2", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "3rem",
      letterSpacing: "-0.02em",
      margin: 0
    }
  }, "Start building"), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      gap: "0.5rem",
      justifyContent: "center",
      marginTop: "1.75rem"
    }
  }, /*#__PURE__*/React.createElement(DgButton, {
    iconRight: /*#__PURE__*/React.createElement("span", null, "\u2192")
  }, "Read the docs"), /*#__PURE__*/React.createElement(DgLink, {
    href: "docs.html"
  }, "Browse SDK reference"))));
}
window.HvPage = HvPage;
})(); } catch (e) { __ds_ns.__errors.push({ path: "site/Developers.jsx", error: String((e && e.message) || e) }); }

// site/Docs.jsx
try { (() => {
// hypervisor.com — Docs (Mintlify-style, IOI copy) with search + Ask Assistant.
const DkNS = window.IoiDesignSystem;
const {
  Button: DkButton,
  Wordmark: DkWordmark
} = DkNS;
const NAV = [["Get Started", [["Overview", true], ["Quickstart", false], ["Architecture map", false], ["Changelog", false]]], ["Foundations", [["Web4 & the IOI stack", false], ["Verifiable bounded agency", false], ["Mixture of Workers", false], ["Worker training lifecycle", false], ["Domain ontologies & data recipes", false], ["Common objects & envelopes", false]]], ["Runtime", [["Hypervisor Daemon", false], ["Agentgres", false], ["wallet.network", false], ["HarnessProfiles", false], ["HypervisorOS", false]]], ["Clients & SDK", [["Hypervisor App / Web", false], ["CLI & TUI", false], ["SDK reference", false], ["ADK", false], ["Adapter targets", false]]], ["Domains", [["aiagent.xyz marketplace", false], ["sas.xyz services", false], ["ioi.ai outcomes", false], ["Hypervisor Foundry", false]]], ["Operate", [["Providers & environments", false], ["Private workspace & cTEE", false], ["Policy & approvals", false], ["Settlement on IOI L1", false]]], ["Conformance", [["CIRC — intent resolution", false], ["CEC — completion evidence", false], ["Events, receipts & replay", false]]]];
const TOC = [["the-boundary", "The execution boundary"], ["not-is", "What Hypervisor is"], ["the-stack", "The stack"], ["authority", "Authority is explicit"], ["lifecycle", "The worker lifecycle"], ["whats-included", "What you get"], ["next", "Next steps"]];
const SEARCH_RESULTS = [["Quickstart", "Get Started", "Install the daemon and delegate your first task"], ["How receipts work", "Runtime", "Logs become receipts — legible, replayable evidence"], ["prim:* vs scope:*", "Foundations", "Primitive execution capability vs authority scope"], ["Deploy in your VPC", "Operate", "Run the substrate inside your own perimeter"], ["Mixture of Workers", "Foundations", "Routing consequential labor across bounded workers"]];
const SUGGESTIONS = ["How do receipts work?", "What's the difference between a prim and a scope?", "How do I deploy in my own VPC?", "Quickstart for the CLI"];

/* ---------------- Topbar ---------------- */
function DocsTopbar({
  onSearch,
  onAssistant,
  assistantOpen
}) {
  const [tip, setTip] = React.useState(false);
  return /*#__PURE__*/React.createElement("header", {
    style: {
      position: "sticky",
      top: 0,
      zIndex: 30,
      background: "rgba(255,255,255,0.85)",
      backdropFilter: "saturate(180%) blur(12px)",
      WebkitBackdropFilter: "saturate(180%) blur(12px)",
      borderBottom: "0.5px solid var(--color-grey-500)"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: "1rem",
      height: 64,
      padding: "0 1.5rem"
    }
  }, /*#__PURE__*/React.createElement("a", {
    href: "index.html",
    style: {
      display: "flex",
      color: "var(--color-onyx-black)",
      textDecoration: "none"
    }
  }, /*#__PURE__*/React.createElement(DkWordmark, {
    height: 24
  })), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 12,
      color: "var(--color-grey-700)",
      border: "0.5px solid var(--color-grey-500)",
      borderRadius: 6,
      padding: "3px 8px"
    }
  }, "docs"), /*#__PURE__*/React.createElement("button", {
    onClick: onSearch,
    style: {
      marginLeft: "0.75rem",
      flex: "1 1 auto",
      maxWidth: 540,
      display: "flex",
      alignItems: "center",
      gap: 8,
      height: 38,
      padding: "0 12px",
      borderRadius: "var(--radius-lg)",
      border: "1px solid var(--color-grey-500)",
      background: "var(--color-white)",
      cursor: "text",
      color: "var(--color-grey-700)",
      fontFamily: "var(--font-sans)",
      fontSize: 14
    }
  }, /*#__PURE__*/React.createElement("svg", {
    width: "16",
    height: "16",
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: "2",
    strokeLinecap: "round"
  }, /*#__PURE__*/React.createElement("circle", {
    cx: "11",
    cy: "11",
    r: "8"
  }), /*#__PURE__*/React.createElement("path", {
    d: "m21 21-4.3-4.3"
  })), /*#__PURE__*/React.createElement("span", {
    style: {
      flex: 1,
      textAlign: "left"
    }
  }, "Search or ask, e.g., 'Configure SSO'"), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 11,
      border: "0.5px solid var(--color-grey-500)",
      borderRadius: 5,
      padding: "2px 6px"
    }
  }, "\u2318K")), /*#__PURE__*/React.createElement("div", {
    style: {
      position: "relative"
    },
    onMouseEnter: () => setTip(true),
    onMouseLeave: () => setTip(false)
  }, /*#__PURE__*/React.createElement("button", {
    onClick: onAssistant,
    style: {
      display: "inline-flex",
      alignItems: "center",
      gap: 7,
      height: 38,
      padding: "0 13px",
      borderRadius: "var(--radius-lg)",
      border: assistantOpen ? "1px solid var(--color-grey-600)" : "1px solid var(--color-grey-500)",
      background: assistantOpen ? "var(--color-grey-400)" : "var(--color-white)",
      cursor: "pointer",
      fontFamily: "var(--font-sans)",
      fontSize: 14,
      whiteSpace: "nowrap",
      flexShrink: 0,
      color: "var(--color-grey-900)"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      color: "var(--color-link-green)",
      display: "inline-flex"
    }
  }, /*#__PURE__*/React.createElement(Sparkle, null)), "Ask Assistant"), tip && /*#__PURE__*/React.createElement("div", {
    style: {
      position: "absolute",
      top: "calc(100% + 8px)",
      left: "50%",
      transform: "translateX(-50%)",
      whiteSpace: "nowrap",
      background: "var(--color-onyx-black)",
      color: "#fff",
      fontFamily: "var(--font-sans)",
      fontSize: 12.5,
      padding: "7px 11px",
      borderRadius: 8,
      display: "flex",
      alignItems: "center",
      gap: 7,
      boxShadow: "var(--shadow-md)"
    }
  }, "Toggle assistant panel", /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 10.5,
      background: "rgba(255,255,255,0.15)",
      borderRadius: 4,
      padding: "2px 5px"
    }
  }, "\u2318 I"))), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: "1.125rem",
      marginLeft: "auto"
    }
  }, /*#__PURE__*/React.createElement("a", {
    href: "#",
    onClick: e => e.preventDefault(),
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: 14,
      color: "var(--color-grey-800)",
      textDecoration: "none"
    }
  }, "Sign in"), /*#__PURE__*/React.createElement(DkButton, {
    size: "sm"
  }, "Get started"), /*#__PURE__*/React.createElement("button", {
    "aria-label": "Toggle theme",
    style: {
      width: 30,
      height: 30,
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      border: "none",
      background: "transparent",
      cursor: "pointer",
      color: "var(--color-grey-700)"
    }
  }, /*#__PURE__*/React.createElement("svg", {
    width: "16",
    height: "16",
    viewBox: "0 0 16 16",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: "1.4",
    strokeLinecap: "round",
    strokeLinejoin: "round"
  }, /*#__PURE__*/React.createElement("path", {
    d: "M14 8.6A5.4 5.4 0 1 1 7.4 2a4.2 4.2 0 0 0 6.6 6.6Z"
  }))))));
}
function Sparkle({
  animate
}) {
  return /*#__PURE__*/React.createElement("svg", {
    width: "16",
    height: "16",
    viewBox: "0 0 18 18",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: "1.5",
    strokeLinecap: "round",
    strokeLinejoin: "round",
    "aria-hidden": "true",
    className: animate ? "hv-sparkle-anim" : undefined,
    style: {
      transformOrigin: "center"
    }
  }, /*#__PURE__*/React.createElement("path", {
    d: "M5.66 2.99L4.4 2.57L3.97 1.31C3.84 0.9 3.16 0.9 3.02 1.31L2.6 2.57L1.34 2.99C1.14 3.06 1 3.25 1 3.46C1 3.68 1.14 3.87 1.34 3.94L2.6 4.36L3.02 5.62C3.09 5.83 3.28 5.96 3.5 5.96C3.71 5.96 3.91 5.83 3.97 5.62L4.4 4.36L5.66 3.94C5.86 3.87 6 3.68 6 3.46C6 3.25 5.86 3.06 5.66 2.99Z",
    fill: "currentColor",
    stroke: "none"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M9.5 2.75L11.41 7.59L16.25 9.5L11.41 11.41L9.5 16.25L7.59 11.41L2.75 9.5L7.59 7.59L9.5 2.75Z"
  }));
}

/* ---------------- Search modal ---------------- */
function SearchModal({
  onClose
}) {
  const [q, setQ] = React.useState("");
  const ref = React.useRef(null);
  React.useEffect(() => {
    if (ref.current) ref.current.focus();
  }, []);
  const results = SEARCH_RESULTS.filter(r => (r[0] + r[2]).toLowerCase().includes(q.toLowerCase()));
  return /*#__PURE__*/React.createElement("div", {
    onClick: onClose,
    style: {
      position: "fixed",
      inset: 0,
      zIndex: 60,
      background: "rgba(10,14,25,0.32)",
      display: "flex",
      justifyContent: "center",
      alignItems: "flex-start",
      paddingTop: "10vh"
    }
  }, /*#__PURE__*/React.createElement("div", {
    onClick: e => e.stopPropagation(),
    style: {
      width: "min(620px, 92vw)",
      background: "var(--color-white)",
      borderRadius: "var(--radius-card)",
      border: "0.5px solid var(--color-grey-500)",
      boxShadow: "var(--shadow-lg)",
      overflow: "hidden"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 10,
      padding: "1rem 1.25rem",
      borderBottom: "0.5px solid var(--color-grey-500)"
    }
  }, /*#__PURE__*/React.createElement("svg", {
    width: "18",
    height: "18",
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "var(--color-grey-700)",
    strokeWidth: "2",
    strokeLinecap: "round"
  }, /*#__PURE__*/React.createElement("circle", {
    cx: "11",
    cy: "11",
    r: "8"
  }), /*#__PURE__*/React.createElement("path", {
    d: "m21 21-4.3-4.3"
  })), /*#__PURE__*/React.createElement("input", {
    ref: ref,
    value: q,
    onChange: e => setQ(e.target.value),
    placeholder: "Search or ask a question\u2026",
    style: {
      flex: 1,
      border: "none",
      outline: "none",
      background: "transparent",
      fontFamily: "var(--font-sans)",
      fontSize: 16,
      color: "var(--color-onyx-black)"
    }
  }), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 11,
      color: "var(--color-grey-700)",
      border: "0.5px solid var(--color-grey-500)",
      borderRadius: 5,
      padding: "2px 6px"
    }
  }, "esc")), /*#__PURE__*/React.createElement("div", {
    style: {
      padding: "0.5rem",
      maxHeight: "48vh",
      overflowY: "auto"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 10.5,
      letterSpacing: "0.08em",
      textTransform: "uppercase",
      color: "var(--color-grey-700)",
      padding: "0.5rem 0.75rem"
    }
  }, q ? "Results" : "Popular"), results.map(r => /*#__PURE__*/React.createElement("a", {
    key: r[0],
    href: "#",
    onClick: e => e.preventDefault(),
    style: {
      display: "flex",
      alignItems: "center",
      gap: 12,
      padding: "10px 12px",
      borderRadius: "var(--radius-lg)",
      textDecoration: "none"
    },
    onMouseEnter: e => e.currentTarget.style.background = "var(--color-grey-400)",
    onMouseLeave: e => e.currentTarget.style.background = "transparent"
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 10,
      color: "var(--color-link-green)",
      border: "0.5px solid var(--color-grey-500)",
      borderRadius: 5,
      padding: "3px 7px",
      flexShrink: 0
    }
  }, r[1]), /*#__PURE__*/React.createElement("span", {
    style: {
      minWidth: 0
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: 14,
      color: "var(--color-onyx-black)"
    }
  }, r[0]), /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: 12.5,
      color: "var(--color-grey-800)",
      overflow: "hidden",
      textOverflow: "ellipsis",
      whiteSpace: "nowrap"
    }
  }, r[2])))), !results.length && /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: 14,
      color: "var(--color-grey-700)",
      padding: "1.5rem 0.75rem",
      textAlign: "center"
    }
  }, "No matches. Try Ask Assistant for a written answer."))));
}

/* ---------------- Assistant panel ---------------- */
function AssistantPanel({
  onClose
}) {
  const [msgs, setMsgs] = React.useState([]);
  const [draft, setDraft] = React.useState("");
  const ask = text => {
    const t = (text || draft).trim();
    if (!t) return;
    const answer = "Authority in Hypervisor is explicit: prim:* says what the runtime may execute, scope:* says what a wallet or tenant authorizes. Tool calls are requests, not grants — every consequential effect is brokered by wallet.network, receipted by Agentgres, and replayable. See Authority is explicit and the wallet.network doctrine.";
    setMsgs(m => [...m, {
      role: "user",
      text: t
    }, {
      role: "assistant",
      text: answer
    }]);
    setDraft("");
  };
  return /*#__PURE__*/React.createElement("aside", {
    style: {
      position: "fixed",
      top: 0,
      right: 0,
      bottom: 0,
      width: 380,
      maxWidth: "92vw",
      zIndex: 50,
      background: "var(--color-white)",
      borderLeft: "0.5px solid var(--color-grey-500)",
      boxShadow: "var(--shadow-lg)",
      display: "flex",
      flexDirection: "column"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 9,
      height: 64,
      flexShrink: 0,
      boxSizing: "border-box",
      padding: "0 1.25rem",
      borderBottom: "0.5px solid var(--color-grey-500)"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      color: "var(--color-link-green)"
    }
  }, /*#__PURE__*/React.createElement(Sparkle, null)), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: 15,
      fontWeight: 700,
      color: "var(--color-onyx-black)"
    }
  }, "Ask Assistant"), /*#__PURE__*/React.createElement("button", {
    onClick: onClose,
    "aria-label": "Close",
    style: {
      marginLeft: "auto",
      width: 28,
      height: 28,
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      border: "none",
      background: "transparent",
      cursor: "pointer",
      color: "var(--color-grey-700)",
      borderRadius: 6
    }
  }, /*#__PURE__*/React.createElement("svg", {
    width: "16",
    height: "16",
    viewBox: "0 0 16 16",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: "1.5",
    strokeLinecap: "round"
  }, /*#__PURE__*/React.createElement("path", {
    d: "M4 4l8 8M12 4l-8 8"
  })))), /*#__PURE__*/React.createElement("div", {
    style: {
      flex: 1,
      overflowY: "auto",
      padding: "1.25rem"
    }
  }, msgs.length === 0 ? /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: 14,
      color: "var(--color-grey-800)",
      lineHeight: 1.55,
      margin: "0 0 1.25rem"
    }
  }, "Ask anything about Hypervisor \u2014 the runtime, the authority model, the SDK, or settlement. Answers cite the docs."), /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 10.5,
      letterSpacing: "0.08em",
      textTransform: "uppercase",
      color: "var(--color-grey-700)",
      marginBottom: "0.75rem"
    }
  }, "Suggested"), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      flexDirection: "column",
      gap: 8
    }
  }, SUGGESTIONS.map(s => /*#__PURE__*/React.createElement("button", {
    key: s,
    onClick: () => ask(s),
    style: {
      textAlign: "left",
      fontFamily: "var(--font-sans)",
      fontSize: 13.5,
      color: "var(--color-onyx-black)",
      border: "0.5px solid var(--color-grey-500)",
      borderRadius: "var(--radius-lg)",
      padding: "10px 12px",
      background: "var(--color-white)",
      cursor: "pointer"
    }
  }, s)))) : /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      flexDirection: "column",
      gap: 14
    }
  }, msgs.map((m, i) => m.role === "user" ? /*#__PURE__*/React.createElement("div", {
    key: i,
    style: {
      alignSelf: "flex-end",
      maxWidth: "85%",
      background: "var(--color-grey-400)",
      borderRadius: "12px 12px 3px 12px",
      padding: "8px 12px",
      fontFamily: "var(--font-sans)",
      fontSize: 13.5,
      color: "var(--color-onyx-black)",
      lineHeight: 1.45
    }
  }, m.text) : /*#__PURE__*/React.createElement("div", {
    key: i,
    style: {
      display: "flex",
      gap: 9
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      color: "var(--color-link-green)",
      flexShrink: 0,
      marginTop: 1
    }
  }, /*#__PURE__*/React.createElement(Sparkle, null)), /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: 13.5,
      color: "var(--color-grey-900)",
      lineHeight: 1.55
    }
  }, m.text))))), /*#__PURE__*/React.createElement("div", {
    style: {
      padding: "0.875rem 1rem 1.125rem",
      borderTop: "0.5px solid var(--color-grey-500)"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 8,
      border: "1px solid var(--color-grey-500)",
      borderRadius: "var(--radius-lg)",
      padding: "0 8px 0 12px",
      background: "var(--color-white)"
    }
  }, /*#__PURE__*/React.createElement("input", {
    value: draft,
    onChange: e => setDraft(e.target.value),
    onKeyDown: e => {
      if (e.key === "Enter") ask();
    },
    placeholder: "Ask a question\u2026",
    style: {
      flex: 1,
      height: 40,
      border: "none",
      outline: "none",
      background: "transparent",
      fontFamily: "var(--font-sans)",
      fontSize: 14,
      color: "var(--color-onyx-black)"
    }
  }), /*#__PURE__*/React.createElement("button", {
    onClick: () => ask(),
    "aria-label": "Send",
    style: {
      width: 30,
      height: 30,
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      border: "none",
      borderRadius: 6,
      background: draft.trim() ? "var(--color-onyx-black)" : "var(--color-grey-400)",
      color: draft.trim() ? "#fff" : "var(--color-grey-700)",
      cursor: draft.trim() ? "pointer" : "default"
    }
  }, /*#__PURE__*/React.createElement("svg", {
    width: "15",
    height: "15",
    viewBox: "0 0 16 16",
    fill: "none"
  }, /*#__PURE__*/React.createElement("path", {
    d: "M8 13V3M8 3l-4 4M8 3l4 4",
    stroke: "currentColor",
    strokeWidth: "1.5",
    strokeLinecap: "round",
    strokeLinejoin: "round"
  })))), /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 10.5,
      color: "var(--color-grey-700)",
      marginTop: 8,
      textAlign: "center"
    }
  }, "Answers are generated and cite the docs.")));
}

/* ---------------- Sidebar ---------------- */
function Sidebar() {
  return /*#__PURE__*/React.createElement("nav", {
    style: {
      width: 280,
      flexShrink: 0,
      position: "sticky",
      top: 64,
      alignSelf: "flex-start",
      height: "calc(100vh - 64px)",
      overflowY: "auto",
      padding: "2rem 1rem 4rem 1.5rem"
    }
  }, NAV.map(([group, items]) => /*#__PURE__*/React.createElement("div", {
    key: group,
    style: {
      marginBottom: "1.75rem"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 11,
      letterSpacing: "0.08em",
      textTransform: "uppercase",
      color: "var(--color-grey-700)",
      padding: "0 0 0 0.75rem",
      marginBottom: "0.625rem"
    }
  }, group), /*#__PURE__*/React.createElement("ul", {
    style: {
      listStyle: "none",
      margin: 0,
      padding: 0,
      display: "flex",
      flexDirection: "column",
      gap: 1
    }
  }, items.map(([label, active]) => /*#__PURE__*/React.createElement("li", {
    key: label
  }, /*#__PURE__*/React.createElement("a", {
    href: "#",
    onClick: e => e.preventDefault(),
    style: {
      display: "block",
      fontFamily: "var(--font-sans)",
      fontSize: 14,
      lineHeight: 1.3,
      textDecoration: "none",
      padding: "6px 12px",
      borderRadius: "var(--radius-lg)",
      background: active ? "var(--color-pistachio-green)" : "transparent",
      color: active ? "var(--color-moss-green)" : "var(--color-grey-800)",
      fontWeight: active ? 500 : 400
    }
  }, label)))))));
}
function H2({
  id,
  children
}) {
  return /*#__PURE__*/React.createElement("h2", {
    id: id,
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.5rem",
      letterSpacing: "-0.015em",
      margin: "2.75rem 0 1rem",
      scrollMarginTop: 84
    }
  }, children);
}
function P({
  children
}) {
  return /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.0625rem",
      lineHeight: 1.65,
      color: "var(--color-grey-900)",
      margin: "0 0 1.25rem"
    }
  }, children);
}
function Code({
  children
}) {
  return /*#__PURE__*/React.createElement("code", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: "0.9em",
      background: "var(--color-grey-400)",
      padding: "1px 6px",
      borderRadius: 4
    }
  }, children);
}

/* ---------------- Content ---------------- */
function Content() {
  const doctrine = ["Hypervisor Daemon executes.", "wallet.network authorizes.", "Agentgres remembers.", "Storage backends preserve bytes.", "MoW routes.", "IOI L1 settles.", "Clients compose.", "Evidence proves."];
  const notIs = [["A chatbot", "Execution-boundary alignment & verifiable bounded agency"], ["A model marketplace", "Worker routing through receipts and benchmarks"], ["A wallet bolted to an LLM", "Authority-scoped credentials and approvals"], ["A workflow toy", "Canonical operational state and replay"], ["A chain with AI bolted on", "Settlement for completed machine labor"]];
  const lifecycle = ["Intent", "Task decomposition", "Worker selection", "Capability & policy check", "Execution", "Verification", "ContributionReceipts", "Settlement"];
  const included = [["Governed sessions", "Run workers across local, cloud, VPC, cTEE, and DePIN compute under one authority model."], ["Receipts & replay", "Every consequential action emits legible, replayable evidence — accountability by default."], ["Bring your own models", "Mount any model as a cognition backend. Workers are installed as accountable actors."], ["Workflow Compositor", "Shape directed workflows, step contracts, review points, and reusable templates."], ["Foundry training", "Turn workflows, traces, and corrections into deployable specialist workers."], ["No plaintext custody", "cTEE private workspaces keep protected data out of provider-rooted memory."]];
  return /*#__PURE__*/React.createElement("article", {
    style: {
      flex: 1,
      minWidth: 0,
      maxWidth: "46rem",
      padding: "2.5rem 3rem 6rem"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 8,
      fontFamily: "var(--font-mono)",
      fontSize: 12,
      color: "var(--color-grey-700)"
    }
  }, /*#__PURE__*/React.createElement("span", null, "Get Started"), /*#__PURE__*/React.createElement("span", null, "/"), /*#__PURE__*/React.createElement("span", {
    style: {
      color: "var(--color-grey-900)"
    }
  }, "Overview")), /*#__PURE__*/React.createElement("h1", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "3rem",
      letterSpacing: "-0.02em",
      lineHeight: 1.05,
      margin: "1rem 0 0",
      color: "var(--color-onyx-black)"
    }
  }, "What is Hypervisor"), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.25rem",
      lineHeight: 1.55,
      color: "var(--color-grey-800)",
      margin: "1.25rem 0 0"
    }
  }, "Hypervisor is the open operating environment for autonomous systems \u2014 build, run, govern, verify, improve, package, and trade autonomous work across any machine, model, or provider, without surrendering runtime truth or authority to one vendor."), /*#__PURE__*/React.createElement(H2, {
    id: "the-boundary"
  }, "The execution boundary"), /*#__PURE__*/React.createElement(P, null, "Autonomous software is beginning to operate browsers, files, APIs, wallets, credentials, models, tools, and other workers. Traditional cybersecurity protects systems from malicious software. Hypervisor protects systems from authorized-but-unbounded autonomous software."), /*#__PURE__*/React.createElement(P, null, "Most agent frameworks give a model tools. Hypervisor gives autonomous work a deterministic execution boundary: every consequential action is canonicalized, policy-checked, authority-scoped, approval-gated when necessary, receipted, replayable, and settleable."), /*#__PURE__*/React.createElement("div", {
    style: {
      background: "var(--color-pistachio-green)",
      borderRadius: "var(--radius-lg)",
      padding: "1rem 1.25rem",
      margin: "0 0 1.5rem",
      display: "flex",
      gap: 12
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 11,
      letterSpacing: "0.08em",
      color: "var(--color-moss-green)",
      paddingTop: 2
    }
  }, "NOTE"), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1rem",
      color: "var(--color-moss-green)",
      lineHeight: 1.5
    }
  }, "The model can be fuzzy. The consequences cannot.")), /*#__PURE__*/React.createElement(H2, {
    id: "not-is"
  }, "What Hypervisor is"), /*#__PURE__*/React.createElement("div", {
    style: {
      border: "0.5px solid var(--color-grey-500)",
      borderRadius: "var(--radius-lg)",
      overflow: "hidden",
      margin: "0 0 1.5rem"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "1fr 1.4fr",
      background: "var(--color-grey-400)",
      borderBottom: "0.5px solid var(--color-grey-500)"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      padding: "10px 16px",
      fontFamily: "var(--font-mono)",
      fontSize: 11,
      letterSpacing: "0.08em",
      color: "var(--color-grey-700)"
    }
  }, "NOT"), /*#__PURE__*/React.createElement("div", {
    style: {
      padding: "10px 16px",
      fontFamily: "var(--font-mono)",
      fontSize: 11,
      letterSpacing: "0.08em",
      color: "var(--color-link-green)",
      borderLeft: "0.5px solid var(--color-grey-500)"
    }
  }, "IS")), notIs.map((r, i) => /*#__PURE__*/React.createElement("div", {
    key: i,
    style: {
      display: "grid",
      gridTemplateColumns: "1fr 1.4fr",
      borderBottom: i < notIs.length - 1 ? "0.5px solid var(--color-grey-500)" : "none"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      padding: "13px 16px",
      fontFamily: "var(--font-sans)",
      fontSize: 14,
      color: "var(--color-grey-700)"
    }
  }, r[0]), /*#__PURE__*/React.createElement("div", {
    style: {
      padding: "13px 16px",
      fontFamily: "var(--font-sans)",
      fontSize: 14,
      color: "var(--color-onyx-black)",
      borderLeft: "0.5px solid var(--color-grey-500)"
    }
  }, r[1])))), /*#__PURE__*/React.createElement(H2, {
    id: "the-stack"
  }, "The stack"), /*#__PURE__*/React.createElement(P, null, "The stack is edge-in. Work starts near the user, device, data, and runtime boundary, then projects only the commitments that need public trust into settlement."), /*#__PURE__*/React.createElement("div", {
    style: {
      background: "var(--color-onyx-black)",
      borderRadius: "var(--radius-lg)",
      padding: "1.25rem 1.5rem",
      margin: "0 0 1.5rem"
    }
  }, doctrine.map((l, i) => {
    const idx = l.lastIndexOf(" ");
    return /*#__PURE__*/React.createElement("div", {
      key: i,
      style: {
        fontFamily: "var(--font-mono)",
        fontSize: 13,
        lineHeight: 1.95,
        color: "var(--color-grey-600)"
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        color: "#fff"
      }
    }, l.slice(0, idx)), " ", l.slice(idx + 1));
  })), /*#__PURE__*/React.createElement(H2, {
    id: "authority"
  }, "Authority is explicit"), /*#__PURE__*/React.createElement(P, null, /*#__PURE__*/React.createElement(Code, null, "prim:*"), " describes what the runtime may execute; ", /*#__PURE__*/React.createElement(Code, null, "scope:*"), " describes what a wallet, provider, user, or tenant may authorize. Tool calls are requests, not grants \u2014 raw model output is never authority for consequential action, and credentials are never cognition."), /*#__PURE__*/React.createElement("div", {
    style: {
      background: "var(--color-onyx-black)",
      borderRadius: "var(--radius-lg)",
      padding: "1.25rem 1.5rem",
      margin: "0 0 1.5rem"
    }
  }, /*#__PURE__*/React.createElement("pre", {
    style: {
      margin: 0,
      fontFamily: "var(--font-mono)",
      fontSize: 13,
      lineHeight: 1.7,
      color: "var(--color-grey-600)",
      whiteSpace: "pre-wrap"
    }
  }, `hv run "patch CVE-2026-1188" \\
  --scope prim:fs.write,scope:repo.write \\
  --gate on-push --receipt --replay`)), /*#__PURE__*/React.createElement(H2, {
    id: "lifecycle"
  }, "The worker lifecycle"), /*#__PURE__*/React.createElement(P, null, "The Internet of Intelligence is not a single monolithic model. It is a routed supply chain of specialized, bounded workers. Mixture of Workers routes consequential labor across independently accountable actors."), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      flexWrap: "wrap",
      gap: "0.5rem 0.625rem",
      alignItems: "center",
      margin: "0 0 1.5rem"
    }
  }, lifecycle.map((s, i) => /*#__PURE__*/React.createElement(React.Fragment, {
    key: s
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 12.5,
      color: "var(--color-grey-900)",
      border: "0.5px solid var(--color-grey-500)",
      borderRadius: "var(--radius-md)",
      padding: "6px 10px"
    }
  }, s), i < lifecycle.length - 1 && /*#__PURE__*/React.createElement("span", {
    style: {
      color: "var(--color-grey-600)"
    }
  }, "\u2192")))), /*#__PURE__*/React.createElement(H2, {
    id: "whats-included"
  }, "What you get"), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "1fr 1fr",
      gap: "1rem",
      margin: "0.25rem 0 0"
    }
  }, included.map(([t, d]) => /*#__PURE__*/React.createElement("div", {
    key: t,
    style: {
      border: "0.5px solid var(--color-grey-500)",
      borderRadius: "var(--radius-lg)",
      padding: "1.125rem 1.25rem"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "0.9375rem",
      fontWeight: 700,
      color: "var(--color-onyx-black)"
    }
  }, t), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "0.875rem",
      color: "var(--color-grey-800)",
      margin: "0.5rem 0 0",
      lineHeight: 1.45
    }
  }, d)))), /*#__PURE__*/React.createElement(H2, {
    id: "next"
  }, "Next steps"), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "1fr 1fr",
      gap: "1rem",
      marginTop: "0.5rem"
    }
  }, [["Quickstart", "Install the daemon and delegate your first task in 5 minutes."], ["Architecture map", "The source-of-truth index for every runtime subject."], ["SDK reference", "Drive runs and read receipts from your own tools."], ["Conformance", "CIRC and CEC — the invariants every runtime upholds."]].map(([t, d]) => /*#__PURE__*/React.createElement("a", {
    key: t,
    href: "#",
    onClick: e => e.preventDefault(),
    style: {
      display: "block",
      textDecoration: "none",
      border: "0.5px solid var(--color-grey-500)",
      borderRadius: "var(--radius-lg)",
      padding: "1.25rem 1.5rem"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 6
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1rem",
      fontWeight: 700,
      color: "var(--color-onyx-black)"
    }
  }, t), /*#__PURE__*/React.createElement("span", {
    style: {
      color: "var(--color-link-green)"
    }
  }, "\u2192")), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "0.875rem",
      color: "var(--color-grey-800)",
      margin: "0.5rem 0 0",
      lineHeight: 1.45
    }
  }, d)))), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      justifyContent: "flex-end",
      marginTop: "3.5rem",
      paddingTop: "1.5rem",
      borderTop: "0.5px solid var(--color-grey-500)"
    }
  }, /*#__PURE__*/React.createElement("a", {
    href: "#",
    onClick: e => e.preventDefault(),
    style: {
      textAlign: "right",
      textDecoration: "none"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 11,
      color: "var(--color-grey-700)",
      letterSpacing: "0.06em"
    }
  }, "NEXT"), /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.0625rem",
      color: "var(--color-link-green)",
      marginTop: 4
    }
  }, "Quickstart \u2192"))));
}
function Toc() {
  return /*#__PURE__*/React.createElement("aside", {
    style: {
      width: 220,
      flexShrink: 0,
      position: "sticky",
      top: 64,
      alignSelf: "flex-start",
      height: "calc(100vh - 64px)",
      overflowY: "auto",
      padding: "2.75rem 1.5rem",
      display: "flex",
      flexDirection: "column",
      gap: "0.75rem"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 11,
      letterSpacing: "0.08em",
      textTransform: "uppercase",
      color: "var(--color-grey-700)"
    }
  }, "On this page"), TOC.map(([id, label], i) => /*#__PURE__*/React.createElement("a", {
    key: id,
    href: `#${id}`,
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: 13.5,
      color: i === 0 ? "var(--color-link-green)" : "var(--color-grey-800)",
      textDecoration: "none",
      lineHeight: 1.4
    }
  }, label)));
}
function HvDocs() {
  const [search, setSearch] = React.useState(false);
  const [assistant, setAssistant] = React.useState(false);
  React.useEffect(() => {
    const onKey = e => {
      const meta = e.metaKey || e.ctrlKey;
      if (meta && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setSearch(s => !s);
      } else if (meta && e.key.toLowerCase() === "i") {
        e.preventDefault();
        setAssistant(a => !a);
      } else if (e.key === "Escape") {
        setSearch(false);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);
  return /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    style: {
      paddingRight: assistant ? 380 : 0,
      transition: "padding-right 220ms var(--ease-out)"
    }
  }, /*#__PURE__*/React.createElement(DocsTopbar, {
    onSearch: () => setSearch(true),
    onAssistant: () => setAssistant(a => !a),
    assistantOpen: assistant
  }), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      maxWidth: "90rem",
      margin: "0 auto",
      alignItems: "flex-start"
    }
  }, /*#__PURE__*/React.createElement(Sidebar, null), /*#__PURE__*/React.createElement("div", {
    style: {
      flex: 1,
      minWidth: 0,
      display: "flex",
      justifyContent: "center",
      borderLeft: "0.5px solid var(--color-grey-500)",
      borderRight: "0.5px solid var(--color-grey-500)"
    }
  }, /*#__PURE__*/React.createElement(Content, null)), /*#__PURE__*/React.createElement(Toc, null))), search && /*#__PURE__*/React.createElement(SearchModal, {
    onClose: () => setSearch(false)
  }), assistant && /*#__PURE__*/React.createElement(AssistantPanel, {
    onClose: () => setAssistant(false)
  }));
}
window.HvDocs = HvDocs;
})(); } catch (e) { __ds_ns.__errors.push({ path: "site/Docs.jsx", error: String((e && e.message) || e) }); }

// site/HomeSections.jsx
try { (() => {
// hypervisor.com — homepage sections. Real product copy from the spec.
const NS = window.IoiDesignSystem;
const {
  Button: SButton,
  Badge: SBadge,
  Card: SCard,
  Stat: SStat,
  TextLink: SLink,
  Eyebrow: SEyebrow
} = NS;
const wrap = {
  maxWidth: "75rem",
  margin: "0 auto",
  padding: "0 2.5rem"
};
function GreenCheck() {
  return /*#__PURE__*/React.createElement("svg", {
    width: "16",
    height: "16",
    viewBox: "0 0 16 16",
    fill: "none",
    style: {
      flexShrink: 0,
      marginTop: 2
    }
  }, /*#__PURE__*/React.createElement("path", {
    d: "M3 8.5l3.2 3.2L13 5",
    stroke: "var(--color-link-green)",
    strokeWidth: "1.5",
    strokeLinecap: "round",
    strokeLinejoin: "round"
  }));
}

/* ---------------- Hero ---------------- */
function Hero() {
  return /*#__PURE__*/React.createElement("section", {
    id: "top",
    className: "hv-hero",
    style: {
      ...wrap,
      paddingTop: "4.5rem",
      display: "grid",
      gridTemplateColumns: "1.05fr 0.95fr",
      gap: "3.5rem",
      alignItems: "center"
    }
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement(SEyebrow, {
    color: "var(--color-link-green)"
  }, "Web4 \xB7 Governed autonomy"), /*#__PURE__*/React.createElement("h1", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "3.75rem",
      lineHeight: 1.04,
      letterSpacing: "-0.02em",
      margin: "1.25rem 0 0",
      color: "var(--color-onyx-black)"
    }
  }, "The operating environment for autonomous systems"), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.1875rem",
      color: "var(--color-grey-800)",
      marginTop: "1.5rem",
      maxWidth: "46ch",
      lineHeight: 1.5
    }
  }, "Build, run, govern, and verify autonomous work across any machine, model, or provider \u2014 without surrendering runtime truth or authority to one vendor."), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      gap: "0.5rem",
      marginTop: "2rem"
    }
  }, /*#__PURE__*/React.createElement(SButton, {
    iconRight: /*#__PURE__*/React.createElement("span", null, "\u2192")
  }, "Get started"), /*#__PURE__*/React.createElement(SButton, {
    variant: "outline"
  }, "Request a demo")), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      gap: "1.5rem",
      marginTop: "2.25rem",
      flexWrap: "wrap"
    }
  }, ["Deterministic runtime", "Scoped authority", "Receipts on every action"].map(t => /*#__PURE__*/React.createElement("span", {
    key: t,
    style: {
      display: "inline-flex",
      alignItems: "center",
      gap: 7,
      fontFamily: "var(--font-sans)",
      fontSize: "0.9375rem",
      color: "var(--color-grey-800)"
    }
  }, /*#__PURE__*/React.createElement(GreenCheck, null), t)))), /*#__PURE__*/React.createElement(HeroPanel, null));
}

/* ---------------- Proof bar (credibility strip under hero) ---------------- */
function ProofBar() {
  const badges = [["soc-2", "SOC 2 Type II"], ["gdpr", "GDPR compliant"], ["fortune-500", "Fortune 500 trusted"]];
  const proofs = ["Runs in your VPC", "Deterministic replay"];
  return /*#__PURE__*/React.createElement("div", {
    className: "hv-proofbar",
    style: {
      ...wrap,
      marginTop: "3.25rem"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      flexWrap: "wrap",
      gap: "1.25rem 2rem",
      padding: "1.25rem 0",
      borderTop: "0.5px solid var(--color-grey-500)",
      borderBottom: "0.5px solid var(--color-grey-500)"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: "0.6875rem",
      letterSpacing: "0.1em",
      textTransform: "uppercase",
      color: "var(--color-grey-700)"
    }
  }, "Proven in production"), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      flexWrap: "wrap",
      gap: "1.25rem 1.75rem",
      marginLeft: "auto"
    }
  }, badges.map(([f, label]) => /*#__PURE__*/React.createElement("span", {
    key: f,
    style: {
      display: "inline-flex",
      alignItems: "center",
      gap: 8
    }
  }, /*#__PURE__*/React.createElement("img", {
    src: `assets/badges/${f}.svg`,
    alt: "",
    width: "28",
    height: "28"
  }), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "0.875rem",
      color: "var(--color-grey-800)"
    }
  }, label))), /*#__PURE__*/React.createElement("span", {
    style: {
      width: "0.5px",
      height: 20,
      background: "var(--color-grey-500)"
    }
  }), proofs.map(p => /*#__PURE__*/React.createElement("span", {
    key: p,
    style: {
      display: "inline-flex",
      alignItems: "center",
      gap: 7,
      fontFamily: "var(--font-sans)",
      fontSize: "0.875rem",
      color: "var(--color-grey-800)"
    }
  }, /*#__PURE__*/React.createElement(GreenCheck, null), p)))));
}
function HeroPanel() {
  const rows = [["fs.write", "src/billing/*.ts", "prim:fs.write"], ["proc.exec", "pnpm test — 312 passing", "prim:proc.exec"], ["vcs.pr", "open PR #4471", "scope:repo.write"]];
  return /*#__PURE__*/React.createElement("div", {
    style: {
      position: "relative"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      position: "absolute",
      inset: "-8% -6%",
      background: "url(/assets/textures/pistachio-noise.png) center/cover",
      borderRadius: "var(--radius-card)",
      opacity: 0.9
    }
  }), /*#__PURE__*/React.createElement(SCard, {
    style: {
      position: "relative",
      padding: 0,
      overflow: "hidden",
      boxShadow: "var(--shadow-lg)"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 8,
      padding: "12px 16px",
      borderBottom: "0.5px solid var(--color-grey-500)"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 22,
      height: 22,
      color: "var(--color-onyx-black)"
    }
  }, /*#__PURE__*/React.createElement(NS.Logo, {
    size: 22
  })), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 12,
      color: "var(--color-grey-800)"
    }
  }, "session \xB7 modernize-billing"), /*#__PURE__*/React.createElement("span", {
    style: {
      marginLeft: "auto"
    }
  }, /*#__PURE__*/React.createElement(SBadge, {
    tone: "green"
  }, "Running"))), /*#__PURE__*/React.createElement("div", {
    style: {
      padding: "16px",
      display: "flex",
      flexDirection: "column",
      gap: 10
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 11,
      letterSpacing: "0.08em",
      textTransform: "uppercase",
      color: "var(--color-grey-700)"
    }
  }, "Receipts"), rows.map((r, i) => /*#__PURE__*/React.createElement("div", {
    key: i,
    style: {
      display: "flex",
      alignItems: "center",
      gap: 10,
      border: "0.5px solid var(--color-grey-500)",
      borderRadius: "var(--radius-lg)",
      padding: "10px 12px",
      background: "var(--color-white)"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 7,
      height: 7,
      borderRadius: "50%",
      background: "var(--color-green-600)",
      flexShrink: 0
    }
  }), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 12.5,
      color: "var(--color-onyx-black)"
    }
  }, r[0]), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: 13,
      color: "var(--color-grey-800)",
      overflow: "hidden",
      textOverflow: "ellipsis",
      whiteSpace: "nowrap"
    }
  }, r[1]), /*#__PURE__*/React.createElement("span", {
    style: {
      marginLeft: "auto",
      fontFamily: "var(--font-mono)",
      fontSize: 11,
      color: "var(--color-grey-700)"
    }
  }, r[2]))), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 10,
      border: "1px solid var(--color-onyx-black)",
      borderRadius: "var(--radius-lg)",
      padding: "11px 12px",
      marginTop: 2
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 11,
      letterSpacing: "0.06em",
      color: "var(--color-link-green)"
    }
  }, "AUTHORITY GATE"), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: 13,
      color: "var(--color-onyx-black)"
    }
  }, "Approve push & open PR"), /*#__PURE__*/React.createElement("span", {
    style: {
      marginLeft: "auto",
      display: "flex",
      gap: 6
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: 12,
      background: "var(--color-onyx-black)",
      color: "#fff",
      borderRadius: 6,
      padding: "4px 9px"
    }
  }, "Allow"), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: 12,
      border: "1px solid var(--color-grey-500)",
      color: "var(--color-grey-800)",
      borderRadius: 6,
      padding: "4px 9px"
    }
  }, "Deny"))))));
}

/* ---------------- Problem framing (status quo → the turn) ---------------- */
function Problem() {
  const fails = [["Run in shared clouds", "Your workloads sit next to everyone else's, on infrastructure you don't control."], ["Stream your code to third parties", "Source, secrets, and context leave your boundary the moment work begins."], ["Can't be audited or controlled", "No receipts, no scoped authority, no way to prove what an agent actually did."]];
  return /*#__PURE__*/React.createElement("section", {
    className: "hv-section",
    style: {
      ...wrap,
      paddingTop: "8rem"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      maxWidth: "44rem"
    }
  }, /*#__PURE__*/React.createElement(SEyebrow, {
    color: "var(--color-red-500)"
  }, "The status quo"), /*#__PURE__*/React.createElement("h2", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "2.75rem",
      letterSpacing: "-0.02em",
      lineHeight: 1.08,
      margin: "1rem 0 0",
      color: "var(--color-onyx-black)"
    }
  }, "Most agents aren't enterprise-ready")), /*#__PURE__*/React.createElement("div", {
    className: "hv-grid-3",
    style: {
      display: "grid",
      gridTemplateColumns: "repeat(3, 1fr)",
      gap: "1.5rem",
      marginTop: "2.5rem"
    }
  }, fails.map(([t, b]) => /*#__PURE__*/React.createElement("div", {
    key: t,
    style: {
      borderTop: "1px solid var(--color-grey-500)",
      paddingTop: "1.25rem"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 9
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 18,
      height: 18,
      borderRadius: "50%",
      background: "var(--color-red-500)",
      display: "grid",
      placeItems: "center",
      flex: "none"
    }
  }, /*#__PURE__*/React.createElement("svg", {
    width: "9",
    height: "9",
    viewBox: "0 0 12 12",
    fill: "none"
  }, /*#__PURE__*/React.createElement("path", {
    d: "M3 3 L9 9 M9 3 L3 9",
    stroke: "#fff",
    strokeWidth: "1.8",
    strokeLinecap: "round"
  }))), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.0625rem",
      fontWeight: 700,
      color: "var(--color-onyx-black)"
    }
  }, t)), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "0.9375rem",
      color: "var(--color-grey-800)",
      marginTop: "0.75rem",
      lineHeight: 1.45
    }
  }, b)))), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "baseline",
      gap: "1.5rem",
      flexWrap: "wrap",
      marginTop: "2.75rem",
      paddingTop: "1.75rem",
      borderTop: "1px solid var(--color-onyx-black)"
    }
  }, /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.1875rem",
      color: "var(--color-onyx-black)",
      margin: 0,
      maxWidth: "52ch",
      lineHeight: 1.5
    }
  }, "Hypervisor is deployed ", /*#__PURE__*/React.createElement("strong", {
    style: {
      fontWeight: 700
    }
  }, "inside your VPC"), ", governed by ", /*#__PURE__*/React.createElement("strong", {
    style: {
      fontWeight: 700
    }
  }, "your policies"), ", and ", /*#__PURE__*/React.createElement("strong", {
    style: {
      fontWeight: 700
    }
  }, "auditable by design"), "."), /*#__PURE__*/React.createElement("span", {
    style: {
      marginLeft: "auto"
    }
  }, /*#__PURE__*/React.createElement(SLink, {
    href: "platform.html"
  }, "Why a browser plugin isn't enough"))));
}

/* ---------------- Capability cards (scannable overview · OpenRouter-style) ---------------- */
function CapabilityCards() {
  const D = window.HvDiagrams;
  const [cfg, setCfg] = React.useState(() => ({
    variant: "A",
    spotlight: false,
    ...(window.__capCfg || {})
  }));
  React.useEffect(() => {
    const h = () => setCfg({
      variant: "A",
      spotlight: false,
      ...(window.__capCfg || {})
    });
    window.addEventListener("capcfg", h);
    return () => window.removeEventListener("capcfg", h);
  }, []);
  const items = [{
    diagram: /*#__PURE__*/React.createElement(D.DiagHub, null),
    designW: 460,
    designH: 338,
    eyebrow: "Any model",
    title: "Runs inside your VPC",
    desc: "Code and secrets never cross your boundary. Mount any model, seal every agent."
  }, {
    diagram: /*#__PURE__*/React.createElement(D.DiagCollab, null),
    designW: 460,
    designH: 300,
    eyebrow: "Collaboration",
    title: "Work together, not in turns",
    desc: "Autonomous loops with instant human handoff \u2014 review, approve, or step in."
  }, {
    diagram: /*#__PURE__*/React.createElement(D.DiagAccess, null),
    designW: 460,
    designH: 340,
    eyebrow: "Auditability",
    title: "Every action receipted",
    desc: "Scoped, approval-gated, and logged \u2014 traceable across your whole org."
  }];
  const cardBase = {
    display: "flex",
    flexDirection: "column",
    background: "var(--color-white)",
    border: "0.5px solid var(--color-grey-500)",
    borderRadius: "var(--radius-card)",
    overflow: "hidden"
  };
  const titleS = {
    fontFamily: "var(--font-sans)",
    fontSize: "1.1875rem",
    letterSpacing: "-0.015em",
    lineHeight: 1.15,
    margin: 0,
    color: "var(--color-onyx-black)"
  };
  const descS = {
    fontFamily: "var(--font-sans)",
    fontSize: "0.9375rem",
    color: "var(--color-grey-800)",
    margin: "10px 0 0",
    lineHeight: 1.5,
    textWrap: "pretty"
  };
  const eb = color => ({
    display: "inline-block",
    fontFamily: "var(--font-mono)",
    fontSize: 11,
    letterSpacing: "0.09em",
    textTransform: "uppercase",
    color,
    marginBottom: 10
  });
  function Fit({
    designW,
    designH,
    children
  }) {
    const outer = React.useRef(null);
    const [s, setS] = React.useState(0);
    React.useLayoutEffect(() => {
      const measure = () => {
        if (!outer.current) return;
        const ow = outer.current.clientWidth,
          oh = outer.current.clientHeight;
        if (ow && oh) setS(Math.min(ow / designW, oh / designH, 1));
      };
      measure();
      const ro = new ResizeObserver(measure);
      ro.observe(outer.current);
      return () => ro.disconnect();
    }, [designW, designH]);
    return /*#__PURE__*/React.createElement("div", {
      ref: outer,
      style: {
        width: "100%",
        height: "100%",
        position: "relative"
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        width: designW,
        height: designH,
        position: "absolute",
        left: "50%",
        top: "50%",
        transform: s ? `translate(-50%, -50%) scale(${s})` : "translate(-50%, -50%)",
        transformOrigin: "center",
        visibility: s ? "visible" : "hidden"
      }
    }, children));
  }
  function Well({
    bg,
    children
  }) {
    return /*#__PURE__*/React.createElement("div", {
      style: {
        position: "relative",
        height: 300,
        overflow: "hidden",
        background: bg,
        padding: "1rem 0.5rem"
      }
    }, children);
  }
  function renderCard(c, i) {
    const featured = cfg.spotlight && i === 0;
    if (cfg.variant === "B") {
      return /*#__PURE__*/React.createElement("div", {
        key: i,
        style: cardBase
      }, /*#__PURE__*/React.createElement(Well, {
        bg: "var(--color-white)"
      }, /*#__PURE__*/React.createElement(Fit, {
        designW: c.designW,
        designH: c.designH
      }, c.diagram)), /*#__PURE__*/React.createElement("div", {
        style: {
          borderTop: "0.5px solid var(--color-grey-500)",
          padding: "1.375rem 1.5rem 1.625rem"
        }
      }, /*#__PURE__*/React.createElement("span", {
        style: eb("var(--color-link-green)")
      }, c.eyebrow), /*#__PURE__*/React.createElement("h3", {
        style: titleS
      }, c.title), /*#__PURE__*/React.createElement("p", {
        style: descS
      }, c.desc)));
    }
    return /*#__PURE__*/React.createElement("div", {
      key: i,
      style: {
        ...cardBase,
        border: featured ? "1px solid var(--color-onyx-black)" : "0.5px solid var(--color-grey-500)"
      }
    }, /*#__PURE__*/React.createElement(Well, {
      bg: featured ? "color-mix(in srgb, var(--color-pistachio-green) 26%, var(--color-white))" : "var(--color-porcelain-grey)"
    }, /*#__PURE__*/React.createElement(Fit, {
      designW: c.designW,
      designH: c.designH
    }, c.diagram)), /*#__PURE__*/React.createElement("div", {
      style: {
        borderTop: featured ? "1px solid var(--color-onyx-black)" : "0.5px solid var(--color-grey-500)",
        padding: "1.375rem 1.5rem 1.625rem"
      }
    }, cfg.variant === "C" && /*#__PURE__*/React.createElement("span", {
      style: eb(featured ? "var(--color-link-green)" : "var(--color-grey-700)")
    }, c.eyebrow), /*#__PURE__*/React.createElement("h3", {
      style: titleS
    }, c.title), /*#__PURE__*/React.createElement("p", {
      style: descS
    }, c.desc)));
  }
  return /*#__PURE__*/React.createElement("section", {
    className: "hv-section",
    style: {
      ...wrap,
      paddingTop: "8rem"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      maxWidth: "40rem",
      marginBottom: "2.75rem"
    }
  }, /*#__PURE__*/React.createElement(SEyebrow, null, "How it fits your world"), /*#__PURE__*/React.createElement("h2", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "2.75rem",
      letterSpacing: "-0.02em",
      lineHeight: 1.08,
      margin: "1rem 0 0"
    }
  }, "Built for enterprise, deployed in your infra")), /*#__PURE__*/React.createElement("div", {
    className: "hv-cap-grid",
    style: {
      display: "grid",
      gridTemplateColumns: "repeat(3, 1fr)",
      gap: "1.5rem"
    }
  }, items.map(renderCard)));
}

/* ---------------- Doctrine pipeline (inverse band) ---------------- */
function Doctrine() {
  const steps = [["Daemon", "executes"], ["wallet.network", "authorizes"], ["Agentgres", "remembers"], ["IOI L1", "settles"]];
  return /*#__PURE__*/React.createElement("section", {
    className: "hv-section hv-doctrine",
    style: {
      ...wrap,
      paddingTop: "8rem"
    }
  }, /*#__PURE__*/React.createElement(SCard, {
    tone: "inverse",
    style: {
      padding: "3rem 3rem 3.25rem",
      borderRadius: "var(--radius-card)",
      position: "relative",
      overflow: "hidden"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      position: "absolute",
      top: "50%",
      right: "-2.5rem",
      transform: "translateY(-50%)",
      width: "26rem",
      height: "26rem",
      opacity: 0.9,
      pointerEvents: "none",
      WebkitMaskImage: "radial-gradient(120% 120% at 80% 50%, #000 38%, transparent 72%)",
      maskImage: "radial-gradient(120% 120% at 80% 50%, #000 38%, transparent 72%)"
    }
  }, /*#__PURE__*/React.createElement(HvDots, {
    inverse: true,
    cols: 13,
    rows: 13,
    gap: 28,
    dot: 6,
    seed: 3
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      position: "relative"
    }
  }, /*#__PURE__*/React.createElement(SEyebrow, {
    color: "var(--color-pistachio-green)"
  }, "The runtime doctrine"), /*#__PURE__*/React.createElement("h2", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "2.25rem",
      letterSpacing: "-0.02em",
      lineHeight: 1.12,
      margin: "1rem 0 0",
      color: "#fff",
      maxWidth: "26ch"
    }
  }, "The model can be fuzzy. The consequences cannot."), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.0625rem",
      color: "var(--color-grey-600)",
      marginTop: "1rem",
      maxWidth: "60ch",
      lineHeight: 1.5
    }
  }, "Every consequential action is canonicalized, policy-checked, authority-scoped, approval-gated when necessary, receipted, and replayable. Probabilistic reasoning in; deterministic, accountable execution out."), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      flexWrap: "wrap",
      gap: "0.75rem 1rem",
      alignItems: "center",
      marginTop: "2rem"
    }
  }, steps.map(([k, v], i) => /*#__PURE__*/React.createElement(React.Fragment, {
    key: k
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      display: "inline-flex",
      alignItems: "baseline",
      gap: 8,
      border: "1px solid rgba(255,255,255,0.16)",
      borderRadius: "var(--radius-lg)",
      padding: "9px 13px"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 13,
      color: "#fff"
    }
  }, k), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: 13,
      color: "var(--color-grey-600)"
    }
  }, v)), i < steps.length - 1 && /*#__PURE__*/React.createElement("span", {
    style: {
      color: "var(--color-grey-700)"
    }
  }, "\u2192")))))));
}

/* ---------------- Feature band (alternating split + line-art diagrams) ---------------- */
function Features() {
  const D = window.HvDiagrams;
  const rows = [{
    diagram: /*#__PURE__*/React.createElement(D.DiagToolStack, null),
    flip: false,
    reveal: true,
    revealOrder: "code",
    eyebrow: "Meets you where you build",
    title: "Works in the tools you already use",
    body: "Drive sessions from the CLI, SDK, or your editor — Cursor, VS Code, JetBrains, and terminals. Review scoped tasks and jump in seamlessly, with full context and receipts on every action.",
    link: ["Explore the SDK", "developers.html"]
  }, {
    diagram: /*#__PURE__*/React.createElement(D.DiagPrivacy, null),
    flip: true,
    reveal: true,
    revealOrder: "stack",
    eyebrow: "Privacy-first by design",
    title: "Your data is never training data",
    body: "Connect your own private or fine-tuned models. Every action is logged, traced, and replayable — but nothing you run is captured for training, streamed to third parties, or retained beyond your policy.",
    link: ["Read the security model", "#lifecycle"]
  }, {
    diagram: /*#__PURE__*/React.createElement(D.DiagAgentTree, null),
    flip: false,
    reveal: true,
    revealOrder: "tree",
    eyebrow: "Run at scale",
    title: "Run Hypervisor, or any agent, at scale",
    body: "Compose specialized workers from git, memory, testing, reasoning, and more. Run thousands in parallel inside ephemeral, isolated environments — provisioning, isolation, and policy enforcement handled for you.",
    link: ["Explore workers", "developers.html"]
  }];
  return /*#__PURE__*/React.createElement("section", {
    className: "hv-section",
    style: {
      ...wrap,
      paddingTop: "8rem"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      textAlign: "center",
      maxWidth: "40rem",
      margin: "0 auto 3.5rem"
    }
  }, /*#__PURE__*/React.createElement(SEyebrow, null, "A closer look"), /*#__PURE__*/React.createElement("h2", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "2.75rem",
      letterSpacing: "-0.02em",
      lineHeight: 1.08,
      margin: "1rem 0 0"
    }
  }, "How teams build with Hypervisor")), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      flexDirection: "column",
      gap: "1.5rem"
    }
  }, rows.map(r => /*#__PURE__*/React.createElement("div", {
    key: r.title,
    className: "hv-feat-row",
    style: {
      background: "var(--color-white)",
      border: "0.5px solid var(--color-grey-500)",
      borderRadius: "var(--radius-card)",
      padding: "3rem 3.25rem",
      display: "grid",
      gridTemplateColumns: "1fr 1fr",
      gap: "3rem",
      alignItems: "center"
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "hv-feat-text",
    style: {
      order: r.flip ? 2 : 1
    }
  }, /*#__PURE__*/React.createElement(SEyebrow, null, r.eyebrow), /*#__PURE__*/React.createElement("h3", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.625rem",
      letterSpacing: "-0.02em",
      lineHeight: 1.12,
      margin: "0.875rem 0 0",
      color: "var(--color-onyx-black)"
    }
  }, r.title), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.0625rem",
      color: "var(--color-grey-800)",
      marginTop: "1rem",
      lineHeight: 1.5,
      maxWidth: "42ch"
    }
  }, r.body), /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: "1.5rem"
    }
  }, /*#__PURE__*/React.createElement(SLink, {
    href: r.link[1]
  }, r.link[0]))), /*#__PURE__*/React.createElement("div", {
    className: "hv-feat-media",
    style: {
      order: r.flip ? 1 : 2,
      display: "flex",
      justifyContent: "center"
    }
  }, r.reveal && window.RevealDiagram ? /*#__PURE__*/React.createElement(window.RevealDiagram.Reveal, {
    order: r.revealOrder || "radial"
  }, r.diagram) : r.diagram)))));
}

/* ---------------- Governance / security ---------------- */
function Govern() {
  const WM = window.WorkersMotion;
  const govStats = [{
    to: 1.2,
    decimals: 1,
    suffix: "M+",
    label: "sessions under scoped authority"
  }, {
    to: 100,
    decimals: 0,
    suffix: "%",
    label: "consequential actions receipted"
  }, {
    to: 6,
    decimals: 0,
    suffix: "",
    label: "controls between intent and effect"
  }];
  const govNum = {
    fontFamily: "var(--font-serif)",
    fontWeight: 300,
    fontSize: "2.5rem",
    lineHeight: 1,
    letterSpacing: "-0.02em",
    color: "var(--color-link-green)",
    fontVariantNumeric: "tabular-nums"
  };
  const points = [["Authority is explicit", "prim:* describes what the runtime may execute; scope:* what a wallet or tenant may authorize."], ["Credentials are never cognition", "wallet.network brokers secrets, approvals, and scoped authority — the worker never holds raw keys."], ["Logs become receipts", "Every run emits legible events, receipts, traces, stop reasons, and replayable evidence."], ["No plaintext custody", "cTEE private workspaces keep protected data out of provider-rooted memory."]];
  return /*#__PURE__*/React.createElement("section", {
    id: "lifecycle",
    className: "hv-section",
    style: {
      ...wrap,
      paddingTop: "8rem"
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "hv-grid-2",
    style: {
      display: "grid",
      gridTemplateColumns: "1fr 1fr",
      gap: "3.5rem",
      alignItems: "start"
    }
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement(SEyebrow, {
    color: "var(--color-link-green)"
  }, "Governance & security"), /*#__PURE__*/React.createElement("h2", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "2.75rem",
      letterSpacing: "-0.02em",
      lineHeight: 1.08,
      margin: "1rem 0 0",
      maxWidth: "16ch"
    }
  }, "Bounded agency, not blind trust"), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.0625rem",
      color: "var(--color-grey-800)",
      marginTop: "1.25rem",
      lineHeight: 1.5,
      maxWidth: "44ch"
    }
  }, "Traditional security protects systems from malicious software. Hypervisor protects systems from authorized-but-unbounded autonomous software."), /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: "2rem"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: "0.6875rem",
      letterSpacing: "0.1em",
      textTransform: "uppercase",
      color: "var(--color-grey-700)"
    }
  }, "Production telemetry \xB7 trailing 30 days"), /*#__PURE__*/React.createElement("div", {
    className: "hv-gov-stats",
    style: {
      display: "grid",
      gridTemplateColumns: "repeat(3, 1fr)",
      marginTop: "1rem",
      borderTop: "0.5px solid var(--color-grey-500)"
    }
  }, govStats.map((s, i) => /*#__PURE__*/React.createElement("div", {
    key: s.label,
    style: {
      padding: "1.25rem 1.25rem 0",
      paddingLeft: i ? "1.25rem" : 0,
      borderLeft: i ? "0.5px solid var(--color-grey-500)" : "none",
      display: "flex",
      flexDirection: "column",
      gap: "0.4rem"
    }
  }, WM ? /*#__PURE__*/React.createElement(WM.CountStat, {
    to: s.to,
    decimals: s.decimals,
    suffix: s.suffix,
    style: govNum
  }) : /*#__PURE__*/React.createElement("div", {
    style: govNum
  }, s.to, s.suffix), /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: "0.6875rem",
      letterSpacing: "0.04em",
      lineHeight: 1.4,
      textTransform: "uppercase",
      color: "var(--color-grey-700)"
    }
  }, s.label)))))), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      flexDirection: "column",
      gap: "1rem"
    }
  }, points.map(([t, b]) => /*#__PURE__*/React.createElement(SCard, {
    key: t,
    style: {
      display: "flex",
      gap: 14,
      padding: "1.25rem 1.5rem"
    }
  }, /*#__PURE__*/React.createElement(GreenCheck, null), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1rem",
      fontWeight: 700,
      color: "var(--color-onyx-black)"
    }
  }, t), /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "0.9375rem",
      color: "var(--color-grey-800)",
      marginTop: 5,
      lineHeight: 1.45
    }
  }, b)))))));
}

/* ---------------- CTA ---------------- */
function CTA() {
  return /*#__PURE__*/React.createElement("section", {
    className: "hv-section",
    style: {
      ...wrap,
      paddingTop: "8rem",
      textAlign: "center"
    }
  }, /*#__PURE__*/React.createElement("h2", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "3.25rem",
      letterSpacing: "-0.02em",
      lineHeight: 1.05,
      margin: 0,
      color: "var(--color-onyx-black)"
    }
  }, "Put autonomous work", /*#__PURE__*/React.createElement("br", null), "under authority"), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.125rem",
      color: "var(--color-grey-800)",
      marginTop: "1.25rem"
    }
  }, "The layer that governs above any machine, model, or provider. Start in minutes."), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      gap: "0.5rem",
      justifyContent: "center",
      marginTop: "2rem"
    }
  }, /*#__PURE__*/React.createElement(SButton, {
    iconRight: /*#__PURE__*/React.createElement("span", null, "\u2192")
  }, "Get started"), /*#__PURE__*/React.createElement(SButton, {
    variant: "outline"
  }, "Talk to engineering")));
}
function Home() {
  return /*#__PURE__*/React.createElement("main", null, /*#__PURE__*/React.createElement(Hero, null), /*#__PURE__*/React.createElement(ProofBar, null), /*#__PURE__*/React.createElement(Problem, null), /*#__PURE__*/React.createElement(CapabilityCards, null), /*#__PURE__*/React.createElement(Features, null), /*#__PURE__*/React.createElement(Govern, null), /*#__PURE__*/React.createElement(CTA, null));
}
window.HvHome = Home;
})(); } catch (e) { __ds_ns.__errors.push({ path: "site/HomeSections.jsx", error: String((e && e.message) || e) }); }

// site/HvDepthField.jsx
try { (() => {
// hypervisor.com — atmospheric depth field for faceted (triangle-accent) panels.
// Layered parallax lattice + depth-of-field blur + fog. The "Whisper" preset:
// it adds immersive depth BEHIND content without reading as a graphic. Drop it
// in place of an inverse `HvDots cover` background — same family, more dimension.
//
// Scope: only for dark containers that already use the triangle accent. Fills
// its parent (give the parent position + the radial mask, as before).
function HvDepthField({
  seed = 0,
  intensity = 1,
  interactive = true
}) {
  const ref = React.useRef(null);
  const cur = React.useRef({
    mx: 0.5,
    my: 0.5,
    cx: 0.5,
    cy: 0.5
  });
  React.useEffect(function () {
    const canvas = ref.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const GREEN = "219,239,219";

    // baked "Whisper" preset
    const CFG = {
      layers: 4,
      parallax: 14,
      blur: 3,
      fog: 82,
      edge: 7 * intensity,
      drift: reduce ? 0 : 22,
      accent: 2
    };
    function fit() {
      const w = canvas.clientWidth || 1,
        h = canvas.clientHeight || 1;
      canvas.width = Math.round(w * dpr);
      canvas.height = Math.round(h * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    }
    fit();
    const ro = new ResizeObserver(fit);
    ro.observe(canvas);
    function hash(x, y) {
      const v = Math.sin(x * 127.1 + y * 311.7) * 43758.5453;
      return v - Math.floor(v);
    }
    function buildLayer(cols, rows, sd) {
      function pt(c, r) {
        const edge = c === 0 || r === 0 || c === cols || r === rows;
        const j = edge ? 0 : 0.42 / cols;
        return [c / cols + (hash(c + sd, r) - 0.5) * j, r / rows + (hash(c + 7.3, r + 4.1 + sd) - 0.5) * j];
      }
      const tris = [];
      for (let r = 0; r < rows; r++) for (let c = 0; c < cols; c++) {
        const a = pt(c, r),
          b = pt(c + 1, r),
          d = pt(c, r + 1),
          e = pt(c + 1, r + 1);
        tris.push({
          p: [a, b, e],
          f: hash(c + sd, r)
        });
        tris.push({
          p: [a, e, d],
          f: hash(c + sd + 0.5, r + 0.3)
        });
      }
      return tris;
    }
    const POOL = [buildLayer(7, 5, 1 + seed), buildLayer(8, 6, 4 + seed), buildLayer(9, 6, 8 + seed), buildLayer(10, 7, 12 + seed), buildLayer(11, 8, 16 + seed)];
    function onMove(e) {
      const r = canvas.getBoundingClientRect();
      let x = (e.clientX - r.left) / r.width,
        y = (e.clientY - r.top) / r.height;
      if (x < -0.6 || x > 1.6 || y < -0.6 || y > 1.6) {
        x = 0.5;
        y = 0.5;
      }
      cur.current.mx = x;
      cur.current.my = y;
    }
    if (interactive) window.addEventListener("pointermove", onMove, {
      passive: true
    });
    function draw(t) {
      const W = canvas.clientWidth,
        H = canvas.clientHeight;
      if (!W || !H) return;
      ctx.clearRect(0, 0, W, H);
      const cc = cur.current;
      cc.cx += (cc.mx - cc.cx) * 0.05;
      cc.cy += (cc.my - cc.cy) * 0.05;
      const N = CFG.layers;
      const cover = Math.max(W, H) * 1.5;
      const ox0 = W / 2 - cover / 2,
        oy0 = H / 2 - cover / 2;
      for (let i = 0; i < N; i++) {
        const tris = POOL[i];
        const near = N > 1 ? i / (N - 1) : 1;
        const pw = 0.35 + near * 0.65;
        const drift = CFG.drift * (1 - near * 0.5);
        const px = (cc.cx - 0.5) * -CFG.parallax * pw + Math.sin(t * 0.00012 + i) * drift;
        const py = (cc.cy - 0.5) * -CFG.parallax * pw + Math.cos(t * 0.00010 + i * 1.7) * drift * 0.6;
        const sc = cover * (0.92 + near * 0.16);
        const ox = ox0 + (cover - sc) / 2 + px,
          oy = oy0 + (cover - sc) / 2 + py;
        const blur = CFG.blur * (1 - near);
        const aMul = 0.45 + near * 0.55;
        const edgeA = CFG.edge / 100 * aMul;
        const fillA = edgeA * 0.9;
        ctx.save();
        if (blur > 0.05) ctx.filter = "blur(" + blur.toFixed(2) + "px)";
        ctx.lineWidth = 0.7;
        ctx.lineJoin = "round";
        ctx.strokeStyle = "rgba(255,255,255," + edgeA.toFixed(3) + ")";
        ctx.beginPath();
        for (let k = 0; k < tris.length; k++) {
          const tp = tris[k].p;
          ctx.moveTo(ox + tp[0][0] * sc, oy + tp[0][1] * sc);
          ctx.lineTo(ox + tp[1][0] * sc, oy + tp[1][1] * sc);
          ctx.lineTo(ox + tp[2][0] * sc, oy + tp[2][1] * sc);
          ctx.closePath();
        }
        ctx.stroke();
        const accentThresh = CFG.accent / 100;
        for (let j = 0; j < tris.length; j++) {
          const tf = tris[j].f,
            tpp = tris[j].p;
          const isAcc = tf < accentThresh,
            isWhite = !isAcc && tf < accentThresh + 0.12;
          if (!isAcc && !isWhite) continue;
          ctx.beginPath();
          ctx.moveTo(ox + tpp[0][0] * sc, oy + tpp[0][1] * sc);
          ctx.lineTo(ox + tpp[1][0] * sc, oy + tpp[1][1] * sc);
          ctx.lineTo(ox + tpp[2][0] * sc, oy + tpp[2][1] * sc);
          ctx.closePath();
          ctx.fillStyle = isAcc ? "rgba(" + GREEN + "," + (fillA * 1.7).toFixed(3) + ")" : "rgba(255,255,255," + (fillA * 0.7).toFixed(3) + ")";
          ctx.fill();
        }
        ctx.restore();
      }
      const f = CFG.fog / 100;
      if (f > 0) {
        const g = ctx.createRadialGradient(W * 0.5, H * 0.42, Math.min(W, H) * 0.12, W * 0.5, H * 0.5, Math.max(W, H) * 0.72);
        g.addColorStop(0, "rgba(10,12,20," + (0.55 * f).toFixed(3) + ")");
        g.addColorStop(0.55, "rgba(9,10,16," + (0.2 * f).toFixed(3) + ")");
        g.addColorStop(1, "rgba(8,9,15," + (0.95 * f).toFixed(3) + ")");
        ctx.fillStyle = g;
        ctx.fillRect(0, 0, W, H);
      }
    }

    // driver: rAF, falling back to interval where rAF is paused
    let ticked = false,
      rafId = 0,
      intId = 0;
    function loop() {
      draw(performance.now());
      ticked = true;
      rafId = requestAnimationFrame(loop);
    }
    rafId = requestAnimationFrame(loop);
    const wd = setTimeout(function () {
      if (!ticked) intId = setInterval(function () {
        draw(performance.now());
      }, 1000 / 40);
    }, 450);
    return function () {
      ro.disconnect();
      clearTimeout(wd);
      if (rafId) cancelAnimationFrame(rafId);
      if (intId) clearInterval(intId);
      if (interactive) window.removeEventListener("pointermove", onMove);
    };
  }, [seed, intensity, interactive]);
  return /*#__PURE__*/React.createElement("canvas", {
    ref: ref,
    "aria-hidden": "true",
    style: {
      position: "absolute",
      inset: 0,
      width: "100%",
      height: "100%",
      display: "block",
      pointerEvents: "none"
    }
  });
}
window.HvDepthField = HvDepthField;
})(); } catch (e) { __ds_ns.__errors.push({ path: "site/HvDepthField.jsx", error: String((e && e.message) || e) }); }

// site/HvDiagrams.jsx
try { (() => {
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
// hypervisor.com — line-art product diagrams (site-scoped).
// On-brand: hairline strokes, IOI mark as the recurring node, green accent
// reserved for the single "live / verified" highlight. Chips are HTML (crisp
// type, directly editable); connectors are an SVG layer in matching aspect.
const DGS = window.IoiDesignSystem;
const MarkLogo = DGS.Logo;
const INK = "var(--color-onyx-black)";
const LINE = "var(--color-grey-600)";
const HAIR = "var(--color-grey-500)";
const ACC = "var(--color-link-green)";
const RED = "var(--color-red-500)";
// One dotted identity across every diagram: fine round dots, 0.5pt tick / 6pt gap.
// Period = 6.5 — the marching/orbit keyframes step by this for a seamless loop.
const DOT_DASH = "0.5 6";

/* ---- shared frame: SVG connector layer (meet, matching aspect) + HTML chips ---- */
function Frame({
  W,
  H,
  svg,
  children
}) {
  return /*#__PURE__*/React.createElement("div", {
    style: {
      position: "relative",
      width: "100%",
      maxWidth: W,
      aspectRatio: `${W} / ${H}`,
      margin: "0 auto"
    }
  }, /*#__PURE__*/React.createElement("svg", {
    viewBox: `0 0 ${W} ${H}`,
    width: "100%",
    height: "100%",
    preserveAspectRatio: "xMidYMid meet",
    style: {
      position: "absolute",
      inset: 0,
      overflow: "visible"
    },
    "aria-hidden": "true"
  }, svg), children);
}

// position helper → percentage so HTML chips track the SVG viewBox exactly
const at = (x, y, W, H) => ({
  position: "absolute",
  left: `${x / W * 100}%`,
  top: `${y / H * 100}%`,
  transform: "translate(-50%, -50%)"
});
function Box({
  size = 46,
  accent = false,
  style,
  children
}) {
  return /*#__PURE__*/React.createElement("div", {
    style: {
      width: size,
      height: size,
      borderRadius: 13,
      background: "var(--color-white)",
      border: `0.5px solid ${accent ? ACC : HAIR}`,
      boxShadow: "var(--shadow-sm)",
      display: "grid",
      placeItems: "center",
      ...style
    }
  }, children);
}

/* ---------- glyphs (simple geometric marks — no third-party logos) ---------- */
const g = (paths, {
  s = 22,
  sw = 1.5,
  fill = "none",
  stroke = INK
} = {}) => /*#__PURE__*/React.createElement("svg", {
  width: s,
  height: s,
  viewBox: "0 0 24 24",
  fill: fill,
  stroke: stroke,
  strokeWidth: sw,
  strokeLinecap: "round",
  strokeLinejoin: "round"
}, paths);
const Sparkle = ({
  s,
  c = INK
} = {}) => g(/*#__PURE__*/React.createElement("path", {
  d: "M12 3 L13.6 9.6 L20 12 L13.6 14.4 L12 21 L10.4 14.4 L4 12 L10.4 9.6 Z",
  fill: c,
  stroke: "none"
}), {
  s
});
const Burst = ({
  s
} = {}) => g(/*#__PURE__*/React.createElement("g", null, /*#__PURE__*/React.createElement("line", {
  x1: "12",
  y1: "3",
  x2: "12",
  y2: "21"
}), /*#__PURE__*/React.createElement("line", {
  x1: "3",
  y1: "12",
  x2: "21",
  y2: "12"
}), /*#__PURE__*/React.createElement("line", {
  x1: "5.5",
  y1: "5.5",
  x2: "18.5",
  y2: "18.5"
}), /*#__PURE__*/React.createElement("line", {
  x1: "18.5",
  y1: "5.5",
  x2: "5.5",
  y2: "18.5"
})), {
  s,
  stroke: ACC
});
const Rings = ({
  s
} = {}) => g(/*#__PURE__*/React.createElement("g", null, /*#__PURE__*/React.createElement("circle", {
  cx: "12",
  cy: "12",
  r: "3"
}), /*#__PURE__*/React.createElement("circle", {
  cx: "12",
  cy: "12",
  r: "7"
}), /*#__PURE__*/React.createElement("circle", {
  cx: "12",
  cy: "12",
  r: "10.5"
})), {
  s
});
const Graph = ({
  s
} = {}) => g(/*#__PURE__*/React.createElement("g", null, /*#__PURE__*/React.createElement("circle", {
  cx: "6",
  cy: "7",
  r: "2.2"
}), /*#__PURE__*/React.createElement("circle", {
  cx: "18",
  cy: "7",
  r: "2.2"
}), /*#__PURE__*/React.createElement("circle", {
  cx: "12",
  cy: "17",
  r: "2.2"
}), /*#__PURE__*/React.createElement("line", {
  x1: "7.6",
  y1: "8.4",
  x2: "11",
  y2: "15"
}), /*#__PURE__*/React.createElement("line", {
  x1: "16.4",
  y1: "8.4",
  x2: "13",
  y2: "15"
}), /*#__PURE__*/React.createElement("line", {
  x1: "8",
  y1: "7",
  x2: "16",
  y2: "7"
})), {
  s
});
const Brackets = ({
  s
} = {}) => g(/*#__PURE__*/React.createElement("g", null, /*#__PURE__*/React.createElement("path", {
  d: "M9 6 L4 12 L9 18"
}), /*#__PURE__*/React.createElement("path", {
  d: "M15 6 L20 12 L15 18"
})), {
  s
});
const Shield = ({
  s
} = {}) => g(/*#__PURE__*/React.createElement("path", {
  d: "M12 3 L19 6 V11 C19 16 15.5 19.5 12 21 C8.5 19.5 5 16 5 11 V6 Z"
}), {
  s
});
const Lock = ({
  s = 22
} = {}) => /*#__PURE__*/React.createElement("svg", {
  width: s,
  height: s,
  viewBox: "0 0 24 24",
  fill: "none",
  stroke: INK,
  strokeWidth: "1.5",
  strokeLinecap: "round",
  strokeLinejoin: "round"
}, /*#__PURE__*/React.createElement("rect", {
  x: "5",
  y: "10.5",
  width: "14",
  height: "9.5",
  rx: "2.2"
}), /*#__PURE__*/React.createElement("path", {
  d: "M8 10.5 V7.5 a4 4 0 0 1 8 0 V10.5"
}), /*#__PURE__*/React.createElement("circle", {
  cx: "12",
  cy: "15",
  r: "1.4",
  fill: INK,
  stroke: "none"
}));
const Person = ({
  s = 20,
  c = INK
} = {}) => /*#__PURE__*/React.createElement("svg", {
  width: s,
  height: s,
  viewBox: "0 0 24 24",
  fill: "none",
  stroke: c,
  strokeWidth: "1.5",
  strokeLinecap: "round",
  strokeLinejoin: "round"
}, /*#__PURE__*/React.createElement("circle", {
  cx: "12",
  cy: "8",
  r: "3.4"
}), /*#__PURE__*/React.createElement("path", {
  d: "M5.5 19 a6.5 6.5 0 0 1 13 0"
}));
const Badge = ({
  ok
}) => /*#__PURE__*/React.createElement("span", {
  style: {
    position: "absolute",
    top: -4,
    right: -4,
    width: 16,
    height: 16,
    borderRadius: "50%",
    background: ok ? ACC : RED,
    display: "grid",
    placeItems: "center",
    boxShadow: "0 0 0 2px var(--color-white)"
  }
}, ok ? /*#__PURE__*/React.createElement("svg", {
  width: "10",
  height: "10",
  viewBox: "0 0 12 12",
  fill: "none"
}, /*#__PURE__*/React.createElement("path", {
  d: "M2.5 6.3 L5 8.5 L9.5 3.7",
  stroke: "#fff",
  strokeWidth: "1.6",
  strokeLinecap: "round",
  strokeLinejoin: "round"
})) : /*#__PURE__*/React.createElement("svg", {
  width: "9",
  height: "9",
  viewBox: "0 0 12 12",
  fill: "none"
}, /*#__PURE__*/React.createElement("path", {
  d: "M3 3 L9 9 M9 3 L3 9",
  stroke: "#fff",
  strokeWidth: "1.6",
  strokeLinecap: "round"
})));

/* ============================================================= *
 * DiagHub — deployed in your cloud: IOI mark at center, pluggable
 * model marks below, your stack / policy nodes to the sides.
 * ============================================================= */
function DiagHub() {
  const W = 460,
    H = 338,
    cx = 230,
    cy = 150;
  const dotted = {
    stroke: HAIR,
    strokeWidth: 1,
    fill: "none",
    strokeDasharray: DOT_DASH,
    strokeLinecap: "round"
  };
  const mx = [122, 192, 262, 332];
  const models = [["claude", /*#__PURE__*/React.createElement("img", {
    src: "assets/logos/models/claude.png",
    alt: "",
    width: "26",
    height: "26",
    style: {
      objectFit: "contain"
    }
  })], ["openai", /*#__PURE__*/React.createElement("img", {
    src: "assets/logos/models/openai.png",
    alt: "",
    width: "28",
    height: "28",
    style: {
      objectFit: "contain",
      borderRadius: "50%"
    }
  })], ["bedrock", /*#__PURE__*/React.createElement("img", {
    src: "assets/logos/models/bedrock.png",
    alt: "",
    width: "28",
    height: "28",
    style: {
      objectFit: "contain",
      borderRadius: "50%"
    }
  })], ["custom", /*#__PURE__*/React.createElement(Rings, {
    s: 20
  })]];
  return /*#__PURE__*/React.createElement(Frame, {
    W: W,
    H: H,
    svg: /*#__PURE__*/React.createElement("g", null, /*#__PURE__*/React.createElement("rect", {
      "data-vpc-border": true,
      x: "46",
      y: "20",
      width: "368",
      height: "200",
      rx: "22",
      stroke: HAIR,
      strokeWidth: "1",
      fill: "none",
      strokeDasharray: DOT_DASH,
      strokeLinecap: "round"
    }), /*#__PURE__*/React.createElement("text", {
      x: "66",
      y: "40",
      fontFamily: "var(--font-mono)",
      fontSize: "11",
      letterSpacing: "0.12em",
      fill: "var(--color-grey-600)"
    }, "your VPC"), /*#__PURE__*/React.createElement("circle", _extends({
      cx: cx,
      cy: cy,
      r: "50"
    }, dotted)), /*#__PURE__*/React.createElement("circle", _extends({
      cx: cx,
      cy: cy,
      r: "66"
    }, dotted, {
      opacity: "0.6"
    })), /*#__PURE__*/React.createElement("circle", _extends({
      cx: "100",
      cy: cy,
      r: "33"
    }, dotted)), /*#__PURE__*/React.createElement("circle", _extends({
      cx: "360",
      cy: cy,
      r: "33"
    }, dotted)), /*#__PURE__*/React.createElement("g", {
      stroke: LINE,
      strokeWidth: "1.25",
      fill: "none",
      strokeLinecap: "round"
    }, /*#__PURE__*/React.createElement("line", {
      x1: cx,
      y1: "120",
      x2: cx,
      y2: "82"
    }), /*#__PURE__*/React.createElement("line", {
      x1: "200",
      y1: cy,
      x2: "126",
      y2: cy
    }), /*#__PURE__*/React.createElement("line", {
      x1: "260",
      y1: cy,
      x2: "334",
      y2: cy
    }), /*#__PURE__*/React.createElement("line", {
      x1: cx,
      y1: "184",
      x2: cx,
      y2: "232"
    }), /*#__PURE__*/React.createElement("line", {
      x1: mx[0],
      y1: "232",
      x2: mx[3],
      y2: "232"
    }), mx.map(x => /*#__PURE__*/React.createElement("line", {
      key: x,
      x1: x,
      y1: "232",
      x2: x,
      y2: "266"
    }))))
  }, /*#__PURE__*/React.createElement(Box, {
    size: 64,
    accent: true,
    style: {
      ...at(cx, cy, W, H),
      borderRadius: 17
    }
  }, /*#__PURE__*/React.createElement("img", {
    src: "assets/brand/ioi-logo.svg",
    alt: "IOI",
    width: "34",
    height: "34"
  })), /*#__PURE__*/React.createElement(Box, {
    size: 46,
    style: at(cx, 56, W, H)
  }, /*#__PURE__*/React.createElement(Sparkle, {
    s: 22
  })), /*#__PURE__*/React.createElement(Box, {
    size: 50,
    style: at(100, cy, W, H)
  }, /*#__PURE__*/React.createElement(Brackets, {
    s: 22
  })), /*#__PURE__*/React.createElement(Box, {
    size: 50,
    style: at(360, cy, W, H)
  }, /*#__PURE__*/React.createElement(Shield, {
    s: 22
  })), models.map(([label, gl], i) => /*#__PURE__*/React.createElement("div", {
    key: label,
    style: {
      ...at(mx[i], 296, W, H),
      display: "flex",
      flexDirection: "column",
      alignItems: "center",
      gap: 6
    }
  }, /*#__PURE__*/React.createElement(Box, {
    size: 44
  }, gl), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 11,
      color: "var(--color-grey-700)",
      whiteSpace: "nowrap"
    }
  }, label))));
}

/* ============================================================= *
 * DiagCollab — work together, not in turns.
 * ============================================================= */
function pill(label, glyph) {
  return /*#__PURE__*/React.createElement("span", {
    style: {
      display: "inline-flex",
      alignItems: "center",
      gap: 7,
      background: INK,
      color: "#fff",
      borderRadius: 999,
      padding: "9px 15px 9px 12px",
      fontFamily: "var(--font-sans)",
      fontSize: 14,
      whiteSpace: "nowrap",
      boxShadow: "var(--shadow-md)"
    }
  }, glyph, label);
}
const ChatBubble = ({
  s = 13,
  c = "var(--color-grey-600)"
} = {}) => /*#__PURE__*/React.createElement("svg", {
  width: s,
  height: s,
  viewBox: "0 0 16 16",
  fill: c,
  "aria-hidden": "true"
}, /*#__PURE__*/React.createElement("path", {
  d: "M3 2.5 H13 a2 2 0 0 1 2 2 V9 a2 2 0 0 1 -2 2 H7 L4 13.5 V11 H3 a2 2 0 0 1 -2 -2 V4.5 a2 2 0 0 1 2 -2 Z"
}));
// AI agent + Developer fused into one pinched shape — "together, not in turns".
// Gooey metaball: two INK blobs (filtered) merge with a liquid bridge; crisp
// text rides on top. Base style = merged end-state; the reveal animates from apart.
function JoinedPills() {
  const W = 214,
    Hh = 40,
    leftW = 116,
    rightW = 122,
    rightX = W - rightW; // 92
  const blob = {
    position: "absolute",
    top: 0,
    height: Hh,
    background: INK
  };
  const text = {
    position: "absolute",
    top: 0,
    height: Hh,
    display: "inline-flex",
    alignItems: "center",
    justifyContent: "center",
    gap: 7,
    color: "#fff",
    fontFamily: "var(--font-sans)",
    fontSize: 14,
    whiteSpace: "nowrap"
  };
  return /*#__PURE__*/React.createElement("div", {
    "data-rv": "joined",
    style: {
      position: "relative",
      width: W,
      height: Hh
    }
  }, /*#__PURE__*/React.createElement("svg", {
    width: "0",
    height: "0",
    style: {
      position: "absolute"
    },
    "aria-hidden": "true"
  }, /*#__PURE__*/React.createElement("filter", {
    id: "collabGoo"
  }, /*#__PURE__*/React.createElement("feGaussianBlur", {
    in: "SourceGraphic",
    stdDeviation: "6",
    result: "b"
  }), /*#__PURE__*/React.createElement("feColorMatrix", {
    in: "b",
    type: "matrix",
    values: "1 0 0 0 0  0 1 0 0 0  0 0 1 0 0  0 0 0 20 -9"
  }))), /*#__PURE__*/React.createElement("div", {
    "data-rv": "goo-layer",
    style: {
      position: "absolute",
      inset: 0,
      filter: "url(#collabGoo) drop-shadow(0 2px 6px rgba(0,0,0,0.18))"
    }
  }, /*#__PURE__*/React.createElement("span", {
    "data-rv": "goo-left",
    style: {
      ...blob,
      left: 0,
      width: leftW,
      borderRadius: 999
    }
  }), /*#__PURE__*/React.createElement("span", {
    "data-rv": "goo-bridge",
    style: {
      ...blob,
      left: 84,
      width: 46,
      top: 9,
      height: 22
    }
  }), /*#__PURE__*/React.createElement("span", {
    "data-rv": "goo-right",
    style: {
      ...blob,
      left: rightX,
      width: rightW,
      borderRadius: 999
    }
  })), /*#__PURE__*/React.createElement("span", {
    "data-rv": "goo-tl",
    style: {
      ...text,
      left: 0,
      width: leftW
    }
  }, /*#__PURE__*/React.createElement(Sparkle, {
    s: 15,
    c: "#fff"
  }), "AI agent"), /*#__PURE__*/React.createElement("span", {
    "data-rv": "goo-tr",
    style: {
      ...text,
      left: rightX,
      width: rightW
    }
  }, /*#__PURE__*/React.createElement(Person, {
    s: 14,
    c: "#fff"
  }), "Developer"));
}
function TaskCard({
  rows
}) {
  return /*#__PURE__*/React.createElement("div", {
    style: {
      width: 116,
      background: "var(--color-white)",
      border: `0.5px solid ${HAIR}`,
      borderRadius: 12,
      boxShadow: "var(--shadow-sm)",
      padding: "11px 12px"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 5,
      marginBottom: 9
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 6,
      height: 6,
      borderRadius: "50%",
      background: "var(--color-grey-600)"
    }
  }), /*#__PURE__*/React.createElement("span", {
    style: {
      height: 4,
      width: 34,
      borderRadius: 2,
      background: "var(--color-grey-500)"
    }
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      flexDirection: "column",
      gap: 8
    }
  }, rows.map((r, i) => /*#__PURE__*/React.createElement("div", {
    key: i,
    style: {
      display: "flex",
      alignItems: "center",
      gap: 7
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      height: 4,
      width: r.w,
      borderRadius: 2,
      background: "var(--color-grey-450)",
      flex: "none"
    }
  }), r.s === "chat" ? /*#__PURE__*/React.createElement("span", {
    style: {
      marginLeft: "auto",
      display: "grid",
      placeItems: "center",
      flex: "none"
    }
  }, /*#__PURE__*/React.createElement(ChatBubble, {
    s: 13
  })) : /*#__PURE__*/React.createElement("span", {
    style: {
      marginLeft: "auto",
      width: 13,
      height: 13,
      borderRadius: "50%",
      background: r.s === "ok" ? ACC : r.s === "no" ? RED : "var(--color-grey-600)",
      display: "grid",
      placeItems: "center",
      flex: "none"
    }
  }, r.s === "ok" && /*#__PURE__*/React.createElement("svg", {
    width: "8",
    height: "8",
    viewBox: "0 0 12 12",
    fill: "none"
  }, /*#__PURE__*/React.createElement("path", {
    d: "M2.5 6.3 L5 8.5 L9.5 3.7",
    stroke: "#fff",
    strokeWidth: "1.8",
    strokeLinecap: "round",
    strokeLinejoin: "round"
  })), r.s === "no" && /*#__PURE__*/React.createElement("svg", {
    width: "7",
    height: "7",
    viewBox: "0 0 12 12",
    fill: "none"
  }, /*#__PURE__*/React.createElement("path", {
    d: "M3 3 L9 9 M9 3 L3 9",
    stroke: "#fff",
    strokeWidth: "1.8",
    strokeLinecap: "round"
  })))))));
}
function DiagCollab() {
  const W = 460,
    H = 300;
  const cardX = [102, 230, 358];
  return /*#__PURE__*/React.createElement(Frame, {
    W: W,
    H: H,
    svg: /*#__PURE__*/React.createElement("g", {
      stroke: LINE,
      strokeWidth: "1.25",
      fill: "none",
      strokeLinecap: "round"
    }, /*#__PURE__*/React.createElement("line", {
      x1: "230",
      y1: "70",
      x2: "230",
      y2: "104"
    }), /*#__PURE__*/React.createElement("path", {
      d: "M102 132 V116 H358 V132"
    }), /*#__PURE__*/React.createElement("line", {
      x1: "230",
      y1: "104",
      x2: "230",
      y2: "116"
    }))
  }, /*#__PURE__*/React.createElement("div", {
    style: at(230, 46, W, H)
  }, /*#__PURE__*/React.createElement(JoinedPills, null)), /*#__PURE__*/React.createElement("div", {
    style: at(cardX[0], 196, W, H)
  }, /*#__PURE__*/React.createElement(TaskCard, {
    rows: [{
      w: 40,
      s: "ok"
    }, {
      w: 30,
      s: "chat"
    }, {
      w: 46,
      s: "ok"
    }, {
      w: 26,
      s: "no"
    }]
  })), /*#__PURE__*/React.createElement("div", {
    style: at(cardX[1], 196, W, H)
  }, /*#__PURE__*/React.createElement(TaskCard, {
    rows: [{
      w: 34,
      s: "ok"
    }, {
      w: 44,
      s: "chat"
    }, {
      w: 28,
      s: "ok"
    }, {
      w: 38,
      s: "no"
    }]
  })), /*#__PURE__*/React.createElement("div", {
    style: at(cardX[2], 196, W, H)
  }, /*#__PURE__*/React.createElement(TaskCard, {
    rows: [{
      w: 44,
      s: "ok"
    }, {
      w: 30,
      s: "ok"
    }, {
      w: 40,
      s: "chat"
    }, {
      w: 26,
      s: "ok"
    }]
  })));
}

/* ============================================================= *
 * DiagToolStack — works in the tools you already use.
 * ============================================================= */
function DiagToolStack() {
  const code = [[/*#__PURE__*/React.createElement("span", {
    style: {
      color: "var(--color-grey-700)"
    }
  }, "import"), " { useIOI } ", /*#__PURE__*/React.createElement("span", {
    style: {
      color: "var(--color-grey-700)"
    }
  }, "from"), /*#__PURE__*/React.createElement("span", {
    style: {
      color: ACC
    }
  }, " \"@ioi/sdk\"")], [], [/*#__PURE__*/React.createElement("span", {
    style: {
      color: "var(--color-grey-700)"
    }
  }, "const"), " { stepIn, review } = ", /*#__PURE__*/React.createElement("span", {
    style: {
      color: INK
    }
  }, "useIOI"), "();"], [], [/*#__PURE__*/React.createElement("span", {
    style: {
      color: "var(--color-grey-700)"
    }
  }, "async"), " () => {"], ["  ", /*#__PURE__*/React.createElement("span", {
    style: {
      color: "var(--color-grey-700)"
    }
  }, "await"), " review(", /*#__PURE__*/React.createElement("span", {
    style: {
      color: ACC
    }
  }, "\"scoped\""), ");"], ["  ", /*#__PURE__*/React.createElement("span", {
    style: {
      color: "var(--color-grey-700)"
    }
  }, "await"), " stepIn();", /*#__PURE__*/React.createElement("span", {
    style: {
      color: "var(--color-grey-600)"
    }
  }, "  // full context")], ["}"]];
  return /*#__PURE__*/React.createElement("div", {
    style: {
      position: "relative",
      width: "100%",
      maxWidth: 440,
      margin: "0 auto"
    }
  }, /*#__PURE__*/React.createElement("div", {
    "data-rv": "editor",
    style: {
      border: `0.5px solid ${HAIR}`,
      borderRadius: 14,
      overflow: "hidden",
      boxShadow: "var(--shadow-md)",
      background: "var(--color-white)"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 6,
      padding: "11px 14px",
      borderBottom: `0.5px solid ${HAIR}`
    }
  }, ["#e1e1e1", "#e1e1e1", "#e1e1e1"].map((c, i) => /*#__PURE__*/React.createElement("span", {
    key: i,
    style: {
      width: 9,
      height: 9,
      borderRadius: "50%",
      background: c
    }
  })), /*#__PURE__*/React.createElement("span", {
    style: {
      marginLeft: 8,
      fontFamily: "var(--font-mono)",
      fontSize: 11.5,
      color: "var(--color-grey-700)"
    }
  }, "session.ts")), /*#__PURE__*/React.createElement("div", {
    style: {
      padding: "14px 16px",
      fontFamily: "var(--font-mono)",
      fontSize: 12.5,
      lineHeight: 1.85
    }
  }, code.map((ln, i) => /*#__PURE__*/React.createElement("div", {
    key: i,
    "data-rv": "codeline",
    style: {
      display: "flex",
      gap: 14,
      background: i === 6 ? "color-mix(in srgb, var(--color-link-green) 9%, transparent)" : "transparent",
      margin: "0 -16px",
      padding: "0 16px"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      color: "var(--color-grey-600)",
      width: 14,
      textAlign: "right",
      flex: "none",
      userSelect: "none"
    }
  }, i + 1), /*#__PURE__*/React.createElement("span", {
    style: {
      color: INK,
      whiteSpace: "pre"
    }
  }, ln.length ? ln.map((seg, j) => /*#__PURE__*/React.createElement(React.Fragment, {
    key: j
  }, seg)) : "\u00a0"))))), /*#__PURE__*/React.createElement("svg", {
    "data-rv": "cursor",
    width: "17",
    height: "17",
    viewBox: "0 0 24 24",
    "aria-hidden": "true",
    style: {
      position: "absolute",
      top: 196,
      left: 188,
      filter: "drop-shadow(0 1.5px 1.5px rgba(0,0,0,0.25))"
    }
  }, /*#__PURE__*/React.createElement("path", {
    d: "M5 3 L19 12 L12.2 13.2 L15.8 20.4 L12.9 21.7 L9.3 14.4 L5 18.2 Z",
    fill: "#fff",
    stroke: INK,
    strokeWidth: "1.3",
    strokeLinejoin: "round"
  })), /*#__PURE__*/React.createElement("div", {
    "data-rv": "tools",
    style: {
      position: "absolute",
      top: -16,
      right: 18,
      display: "flex"
    }
  }, [/*#__PURE__*/React.createElement("img", {
    src: "assets/logos/tools/vscode.svg",
    alt: "",
    width: "20",
    height: "20"
  }), /*#__PURE__*/React.createElement("img", {
    src: "assets/logos/tools/cursor.svg",
    alt: "",
    width: "20",
    height: "20"
  }), /*#__PURE__*/React.createElement("img", {
    src: "assets/logos/tools/jetbrains.svg",
    alt: "",
    width: "20",
    height: "20"
  }), /*#__PURE__*/React.createElement(MarkLogo, {
    size: 20
  })].map((gl, i) => /*#__PURE__*/React.createElement(Box, {
    key: i,
    size: 40,
    style: {
      marginLeft: i ? -10 : 0,
      borderRadius: 11,
      zIndex: 4 - i,
      boxShadow: "var(--shadow-md)"
    }
  }, gl))));
}

/* ============================================================= *
 * DiagPrivacy — your data is never training data (stacked windows,
 * front one verified / accent).
 * ============================================================= */
function WinCard({
  accent,
  lines,
  code,
  style
}) {
  return /*#__PURE__*/React.createElement("div", {
    style: {
      position: "absolute",
      width: 250,
      height: 158,
      background: "var(--color-white)",
      border: `${accent ? "1px" : "0.5px"} solid ${accent ? ACC : HAIR}`,
      borderRadius: 12,
      boxShadow: accent ? "var(--shadow-md)" : "var(--shadow-xs)",
      padding: "12px 14px",
      ...style
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 6,
      marginBottom: 13
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 7,
      height: 7,
      borderRadius: "50%",
      background: accent ? ACC : "var(--color-grey-600)"
    }
  }), /*#__PURE__*/React.createElement("span", {
    style: {
      height: 4,
      width: 56,
      borderRadius: 2,
      background: "var(--color-grey-500)"
    }
  })), code && /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      flexDirection: "column",
      gap: 11
    }
  }, code.map((w, i) => /*#__PURE__*/React.createElement("div", {
    key: i,
    "data-rv": "wincode",
    style: {
      display: "flex",
      alignItems: "center",
      gap: 10
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 10,
      color: "var(--color-grey-600)",
      width: 8
    }
  }, i + 1), /*#__PURE__*/React.createElement("span", {
    style: {
      height: 4,
      width: w,
      borderRadius: 2,
      background: "var(--color-grey-450)"
    }
  })))));
}
function DiagPrivacy() {
  return /*#__PURE__*/React.createElement("div", {
    style: {
      position: "relative",
      width: "100%",
      maxWidth: 380,
      aspectRatio: "380 / 300",
      margin: "0 auto"
    }
  }, /*#__PURE__*/React.createElement(WinCard, {
    style: {
      right: 0,
      top: 4
    }
  }), /*#__PURE__*/React.createElement(WinCard, {
    style: {
      right: 30,
      top: 30
    }
  }), /*#__PURE__*/React.createElement(WinCard, {
    style: {
      right: 60,
      top: 56
    }
  }), /*#__PURE__*/React.createElement("svg", {
    viewBox: "0 0 380 300",
    width: "100%",
    height: "100%",
    preserveAspectRatio: "none",
    style: {
      position: "absolute",
      inset: 0,
      overflow: "visible",
      pointerEvents: "none"
    },
    "aria-hidden": "true"
  }, /*#__PURE__*/React.createElement("path", {
    d: "M96 116 H64 a8 8 0 0 0 -8 8 V176",
    fill: "none",
    stroke: ACC,
    strokeWidth: "1.5",
    strokeLinecap: "round"
  }), /*#__PURE__*/React.createElement("circle", {
    cx: "96",
    cy: "116",
    r: "3.5",
    fill: ACC
  })), /*#__PURE__*/React.createElement(WinCard, {
    accent: true,
    style: {
      left: 40,
      top: 86
    }
  }), /*#__PURE__*/React.createElement(WinCard, {
    code: [120, 96, 134, 78],
    style: {
      left: 0,
      bottom: 0
    }
  }));
}

/* ============================================================= *
 * DiagAccess — enterprise access & auditability: users (RBAC,
 * verified/denied) AND agents (governed actors) around a shield.
 * ============================================================= */
function ShieldLock({
  size = 66
}) {
  return /*#__PURE__*/React.createElement("svg", {
    width: size,
    height: size,
    viewBox: "0 0 64 64",
    "aria-hidden": "true",
    style: {
      filter: "drop-shadow(0 5px 12px rgba(0,0,0,0.14))"
    }
  }, /*#__PURE__*/React.createElement("path", {
    d: "M32 5 L54 13 V30 C54 44.5 44 53.5 32 59 C20 53.5 10 44.5 10 30 V13 Z",
    fill: INK
  }), /*#__PURE__*/React.createElement("circle", {
    cx: "32",
    cy: "27.5",
    r: "4.6",
    fill: "#fff"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M30 30.5 L34 30.5 L35.4 42 L28.6 42 Z",
    fill: "#fff"
  }));
}
function DiagAccess() {
  const W = 460,
    H = 340,
    cx = 230,
    cy = 182;
  const dotted = {
    stroke: HAIR,
    strokeWidth: 1,
    fill: "none",
    strokeDasharray: DOT_DASH,
    strokeLinecap: "round"
  };
  // [x, y, kind, ok] — kind: "user" | "agent"
  const nodes = [[230, 54, "user", true], [104, 104, "user", true], [352, 96, "user", false], [120, 274, "agent"], [232, 296, "agent"], [340, 256, "agent"]];
  return /*#__PURE__*/React.createElement(Frame, {
    W: W,
    H: H,
    svg: /*#__PURE__*/React.createElement("g", null, /*#__PURE__*/React.createElement("g", {
      "data-orbit": true,
      style: {
        transformBox: "fill-box",
        transformOrigin: "center"
      }
    }, /*#__PURE__*/React.createElement("circle", _extends({
      cx: cx,
      cy: cy,
      r: "48"
    }, dotted)), /*#__PURE__*/React.createElement("circle", _extends({
      cx: cx,
      cy: cy,
      r: "64"
    }, dotted, {
      opacity: "0.55"
    }))), /*#__PURE__*/React.createElement("circle", _extends({
      cx: "120",
      cy: "274",
      r: "28"
    }, dotted, {
      opacity: "0.7"
    })), /*#__PURE__*/React.createElement("circle", _extends({
      cx: "120",
      cy: "274",
      r: "38"
    }, dotted, {
      opacity: "0.4"
    })), /*#__PURE__*/React.createElement("circle", _extends({
      cx: "340",
      cy: "256",
      r: "28"
    }, dotted, {
      opacity: "0.7"
    })), /*#__PURE__*/React.createElement("circle", _extends({
      cx: "340",
      cy: "256",
      r: "38"
    }, dotted, {
      opacity: "0.4"
    })), /*#__PURE__*/React.createElement("g", {
      stroke: LINE,
      strokeWidth: "1.25",
      fill: "none",
      strokeLinecap: "round"
    }, /*#__PURE__*/React.createElement("line", {
      x1: cx,
      y1: "150",
      x2: cx,
      y2: "78"
    }), /*#__PURE__*/React.createElement("line", {
      x1: "204",
      y1: "170",
      x2: "124",
      y2: "116"
    }), /*#__PURE__*/React.createElement("line", {
      x1: "256",
      y1: "168",
      x2: "334",
      y2: "110"
    }), /*#__PURE__*/React.createElement("line", {
      x1: "208",
      y1: "202",
      x2: "140",
      y2: "264"
    }), /*#__PURE__*/React.createElement("line", {
      x1: cx,
      y1: "214",
      x2: cx,
      y2: "280"
    }), /*#__PURE__*/React.createElement("line", {
      x1: "254",
      y1: "200",
      x2: "322",
      y2: "244"
    })))
  }, /*#__PURE__*/React.createElement("div", {
    style: at(cx, cy, W, H)
  }, /*#__PURE__*/React.createElement(ShieldLock, {
    size: 66
  })), nodes.map(([x, y, kind, ok], i) => /*#__PURE__*/React.createElement(Box, {
    key: i,
    size: kind === "user" ? 46 : 44,
    style: {
      ...at(x, y, W, H),
      position: "absolute"
    }
  }, kind === "user" ? /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement(Person, {
    s: 20
  }), /*#__PURE__*/React.createElement(Badge, {
    ok: ok
  })) : /*#__PURE__*/React.createElement(Sparkle, {
    s: 20
  }))));
}

/* ============================================================= *
 * DiagAgentTree — run any agent at scale (composable workers).
 * ============================================================= */
// meaningful per-capability line icons (13px, fine stroke)
const gi13 = paths => g(paths, {
  s: 13,
  sw: 1.35
});
const TREE_ICON = {
  git: gi13(/*#__PURE__*/React.createElement("g", null, /*#__PURE__*/React.createElement("circle", {
    cx: "6",
    cy: "6",
    r: "2.3"
  }), /*#__PURE__*/React.createElement("circle", {
    cx: "6",
    cy: "18",
    r: "2.3"
  }), /*#__PURE__*/React.createElement("circle", {
    cx: "17",
    cy: "10",
    r: "2.3"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M6 8.3 V15.7 M7.8 7.4 a7 7 0 0 1 7.4 3.4"
  }))),
  memory: gi13(/*#__PURE__*/React.createElement("g", null, /*#__PURE__*/React.createElement("ellipse", {
    cx: "12",
    cy: "6",
    rx: "7",
    ry: "2.6"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M5 6 V18 c0 1.4 3.1 2.6 7 2.6 s7 -1.2 7 -2.6 V6 M5 12 c0 1.4 3.1 2.6 7 2.6 s7 -1.2 7 -2.6"
  }))),
  code_parse: gi13(/*#__PURE__*/React.createElement("g", null, /*#__PURE__*/React.createElement("rect", {
    x: "6.5",
    y: "6.5",
    width: "11",
    height: "11",
    rx: "2"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M9.5 2 V4.5 M14.5 2 V4.5 M9.5 19.5 V22 M14.5 19.5 V22 M2 9.5 H4.5 M2 14.5 H4.5 M19.5 9.5 H22 M19.5 14.5 H22"
  }))),
  testing: gi13(/*#__PURE__*/React.createElement("g", null, /*#__PURE__*/React.createElement("path", {
    d: "M9.5 3 H14.5 M10.5 3 V9 L5.5 18.5 c-0.6 1.1 0.2 2.5 1.5 2.5 H17 c1.3 0 2.1 -1.4 1.5 -2.5 L13.5 9 V3"
  }))),
  sdk: gi13(/*#__PURE__*/React.createElement("g", null, /*#__PURE__*/React.createElement("path", {
    d: "M12 3 L20 7.5 V16.5 L12 21 L4 16.5 V7.5 Z"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M4 7.5 L12 12 L20 7.5 M12 12 V21"
  }))),
  context: gi13(/*#__PURE__*/React.createElement("g", null, /*#__PURE__*/React.createElement("path", {
    d: "M4 5.5 H20 M9 12 H20 M9 18.5 H20"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M4.5 11 L6 12 L4.5 13 M4.5 17.5 L6 18.5 L4.5 19.5"
  }))),
  version_control: gi13(/*#__PURE__*/React.createElement("g", null, /*#__PURE__*/React.createElement("circle", {
    cx: "6",
    cy: "5",
    r: "1.9"
  }), /*#__PURE__*/React.createElement("circle", {
    cx: "6",
    cy: "12",
    r: "1.9"
  }), /*#__PURE__*/React.createElement("circle", {
    cx: "6",
    cy: "19",
    r: "1.9"
  }), /*#__PURE__*/React.createElement("circle", {
    cx: "17",
    cy: "6",
    r: "1.9"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M6 6.9 V10.1 M6 13.9 V17.1 M8 12 H13 c2.2 0 4 -1.8 4 -4 V7.9"
  }))),
  reasoning: gi13(/*#__PURE__*/React.createElement("g", null, /*#__PURE__*/React.createElement("circle", {
    cx: "6",
    cy: "7",
    r: "2.1"
  }), /*#__PURE__*/React.createElement("circle", {
    cx: "18",
    cy: "7",
    r: "2.1"
  }), /*#__PURE__*/React.createElement("circle", {
    cx: "12",
    cy: "17",
    r: "2.1"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M7.7 8.3 L10.6 15 M16.3 8.3 L13.4 15 M8.1 7 H15.9"
  }))),
  guardrails: gi13(/*#__PURE__*/React.createElement("path", {
    d: "M12 3 L19 6 V11 C19 16 15.5 19.5 12 21 C8.5 19.5 5 16 5 11 V6 Z"
  })),
  debugging: gi13(/*#__PURE__*/React.createElement("g", null, /*#__PURE__*/React.createElement("ellipse", {
    cx: "12",
    cy: "13.5",
    rx: "4.6",
    ry: "5.6"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M12 7.9 V4 M9.4 5.2 L10.8 7.6 M14.6 5.2 L13.2 7.6 M7.4 10.6 L3.8 9.4 M16.6 10.6 L20.2 9.4 M7 13.5 H3.3 M17 13.5 H20.7 M7.4 16.6 L3.8 18 M16.6 16.6 L20.2 18"
  }))),
  code_synthesis: gi13(/*#__PURE__*/React.createElement("g", null, /*#__PURE__*/React.createElement("path", {
    d: "M9 6 L4 12 L9 18 M15 6 L20 12 L15 18"
  }))),
  data_analysis: gi13(/*#__PURE__*/React.createElement("g", null, /*#__PURE__*/React.createElement("path", {
    d: "M4 3.5 V20.5 H21"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M8 17 V12 M12.5 17 V8 M17 17 V5"
  }))),
  doc_gen: gi13(/*#__PURE__*/React.createElement("g", null, /*#__PURE__*/React.createElement("path", {
    d: "M7 3 H13.5 L18 7.5 V20 c0 0.6 -0.4 1 -1 1 H7 c-0.6 0 -1 -0.4 -1 -1 V4 c0 -0.6 0.4 -1 1 -1 Z M13.5 3 V7.5 H18 M9 12.5 H15 M9 16.5 H15"
  }))),
  fm_endpoint: gi13(/*#__PURE__*/React.createElement("g", null, /*#__PURE__*/React.createElement("circle", {
    cx: "12",
    cy: "12",
    r: "3"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M12 4 V9 M12 15 V20 M4 12 H9 M15 12 H20 M6.3 6.3 L9.5 9.5 M14.5 14.5 L17.7 17.7 M17.7 6.3 L14.5 9.5 M9.5 14.5 L6.3 17.7"
  }))),
  project_mgmt: gi13(/*#__PURE__*/React.createElement("g", null, /*#__PURE__*/React.createElement("rect", {
    x: "3.5",
    y: "4",
    width: "17",
    height: "16",
    rx: "2"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M8 4 V20 M14 4 V20 M8 9 H14 M8 14 H14"
  })))
};
function CapPill({
  label
}) {
  return /*#__PURE__*/React.createElement("span", {
    style: {
      display: "inline-flex",
      alignItems: "center",
      gap: 7,
      background: "var(--color-white)",
      border: `0.5px solid ${HAIR}`,
      borderRadius: 999,
      padding: "7px 13px",
      fontFamily: "var(--font-mono)",
      fontSize: 12.5,
      color: "var(--color-grey-900)",
      boxShadow: "var(--shadow-xs)",
      whiteSpace: "nowrap"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      display: "grid",
      placeItems: "center",
      opacity: 0.85
    }
  }, TREE_ICON[label] || /*#__PURE__*/React.createElement(Rings, {
    s: 13
  })), label);
}
function DiagAgentTree({
  compact
}) {
  const rows = compact ? [["git", "memory"], ["testing", "reasoning"], ["sdk", "context"]] : [["git", "fm_endpoint", "memory", "code_parse", "doc_gen", "testing"], ["context", "version_control", "sdk", "project_mgmt", "reasoning"], ["guardrails", "debugging", "code_synthesis", "data_analysis"]];
  return /*#__PURE__*/React.createElement("div", {
    style: {
      width: "100%",
      maxWidth: 460,
      margin: "0 auto",
      display: "flex",
      flexDirection: "column",
      alignItems: "center"
    }
  }, /*#__PURE__*/React.createElement("span", {
    "data-rv": "agent",
    style: {
      display: "inline-flex",
      alignItems: "center",
      gap: 8,
      background: INK,
      color: "#fff",
      borderRadius: 999,
      padding: "9px 16px",
      fontFamily: "var(--font-mono)",
      fontSize: 13,
      boxShadow: "var(--shadow-md)"
    }
  }, /*#__PURE__*/React.createElement(Sparkle, {
    s: 15,
    c: "#fff"
  }), "your_agent"), /*#__PURE__*/React.createElement("svg", {
    "data-rv": "branch",
    width: "160",
    height: "26",
    viewBox: "0 0 160 26",
    "aria-hidden": "true",
    style: {
      display: "block"
    }
  }, /*#__PURE__*/React.createElement("path", {
    d: "M80 0 V8 M14 26 V18 a4 4 0 0 1 4 -4 H142 a4 4 0 0 1 4 4 V26 M80 8 H80",
    fill: "none",
    stroke: LINE,
    strokeWidth: "1.25",
    strokeLinecap: "round"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M14 26 V20 M80 26 V14 M146 26 V20",
    fill: "none",
    stroke: LINE,
    strokeWidth: "1.25",
    strokeLinecap: "round"
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      flexDirection: "column",
      gap: 11,
      alignItems: "center"
    }
  }, rows.map((row, ri) => /*#__PURE__*/React.createElement("div", {
    key: ri,
    "data-rv": "caprow",
    style: {
      display: "flex",
      flexWrap: "wrap",
      gap: 9,
      justifyContent: "center"
    }
  }, row.map(c => /*#__PURE__*/React.createElement("span", {
    key: c,
    "data-rv": "cap"
  }, /*#__PURE__*/React.createElement(CapPill, {
    label: c
  })))))));
}
window.HvDiagrams = {
  DiagHub,
  DiagCollab,
  DiagToolStack,
  DiagPrivacy,
  DiagAccess,
  DiagAgentTree
};
})(); } catch (e) { __ds_ns.__errors.push({ path: "site/HvDiagrams.jsx", error: String((e && e.message) || e) }); }

// site/HvDots.jsx
try { (() => {
// Faceted-polygon illustration (site-scoped) — a low-poly triangular lattice
// inspired by the facets of the ioi octahedron mark. Outlined triangles with a
// sparse scatter of lit/accent facets. Greyscale on light; luminous on dark
// (inverse). Pass `interactive` for cursor-proximity lighting + a subtle ambient
// shimmer (reduced-motion aware) — reserve it for large hero/doctrine panels.
function hvBuildFacets(cols, rows, gap, seed, inverse) {
  const fills = inverse ? ["transparent", "rgba(255,255,255,0.05)", "rgba(255,255,255,0.13)", "var(--color-pistachio-green)"] : ["transparent", "#ECECEC", "#D4D4D4", "var(--color-link-green)"];
  const stroke = inverse ? "rgba(255,255,255,0.15)" : "rgba(0,0,0,0.12)";
  const sw = Math.max(0.6, gap * 0.04);
  const hash = (x, y) => {
    const v = Math.sin(x * 127.1 + y * 311.7 + seed * 13.17) * 43758.5453;
    return v - Math.floor(v);
  };
  const pt = (c, r) => {
    const edge = c === 0 || r === 0 || c === cols || r === rows;
    const j = edge ? 0 : gap * 0.42;
    return [c * gap + (hash(c, r) - 0.5) * j, r * gap + (hash(c + 7.3, r + 4.1) - 0.5) * j];
  };
  const shade = (c, r, h) => {
    const v = hash(c * 2 + h * 0.5 + 0.3, r * 2 + 0.7);
    return v < 0.05 ? 3 : v < 0.15 ? 2 : v < 0.4 ? 1 : 0;
  };
  const tris = [];
  for (let r = 0; r < rows; r++) {
    for (let c = 0; c < cols; c++) {
      const a = pt(c, r),
        b = pt(c + 1, r),
        d = pt(c, r + 1),
        e = pt(c + 1, r + 1);
      [[[a, b, e], shade(c, r, 0)], [[a, e, d], shade(c, r, 1)]].forEach(([tp, si]) => {
        tris.push({
          points: tp.map(p => `${p[0]},${p[1]}`).join(" "),
          fill: fills[si],
          cx: (tp[0][0] + tp[1][0] + tp[2][0]) / 3,
          cy: (tp[0][1] + tp[1][1] + tp[2][1]) / 3
        });
      });
    }
  }
  return {
    tris,
    stroke,
    sw,
    accent: inverse ? "var(--color-pistachio-green)" : "var(--color-link-green)"
  };
}
function HvDots({
  cols = 11,
  rows = 11,
  gap = 22,
  dot = 7,
  seed = 0,
  inverse = false,
  interactive = false,
  cover = false
}) {
  const svgRef = React.useRef(null);
  const elsRef = React.useRef([]);
  const geom = React.useMemo(() => hvBuildFacets(cols, rows, gap, seed, inverse), [cols, rows, gap, seed, inverse]);
  React.useEffect(() => {
    if (!interactive) return;
    const svg = svgRef.current;
    if (!svg) return;
    const tris = geom.tris,
      els = elsRef.current,
      accent = geom.accent;
    const R = gap * 2.6;
    const state = new Float32Array(tris.length);
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    let mx = null,
      my = null,
      raf = 0;
    const t0 = performance.now();
    function frame(now) {
      raf = requestAnimationFrame(frame);
      let ux = null,
        uy = null;
      if (mx != null) {
        const ctm = svg.getScreenCTM();
        if (ctm) {
          const p = svg.createSVGPoint();
          p.x = mx;
          p.y = my;
          const u = p.matrixTransform(ctm.inverse());
          ux = u.x;
          uy = u.y;
        }
      }
      const ph = (now - t0) / 1000;
      for (let i = 0; i < tris.length; i++) {
        const t = tris[i];
        let inf = 0;
        if (ux != null) {
          const dd = Math.hypot(ux - t.cx, uy - t.cy);
          inf = Math.max(0, 1 - dd / R);
          inf *= inf;
        }
        if (!reduce) {
          const w = Math.sin((t.cx + t.cy) * 0.012 - ph * 0.9);
          inf = Math.max(inf, Math.max(0, w) * 0.13);
        }
        if (Math.abs(inf - state[i]) < 0.01) continue;
        state[i] = inf;
        const el = els[i];
        if (!el) continue;
        if (inf <= 0.01) {
          el.style.fill = "";
          el.style.fillOpacity = "";
          el.style.stroke = "";
          el.style.strokeOpacity = "";
        } else {
          el.style.fill = accent;
          el.style.fillOpacity = (0.08 + inf * 0.62).toFixed(3);
          el.style.stroke = accent;
          el.style.strokeOpacity = (0.18 + inf * 0.55).toFixed(3);
        }
      }
    }
    const onMove = e => {
      mx = e.clientX;
      my = e.clientY;
    };
    const onLeave = () => {
      mx = null;
      my = null;
    };
    window.addEventListener("pointermove", onMove, {
      passive: true
    });
    window.addEventListener("blur", onLeave);
    raf = requestAnimationFrame(frame);
    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("blur", onLeave);
    };
  }, [interactive, geom, gap]);
  return /*#__PURE__*/React.createElement("svg", {
    ref: svgRef,
    viewBox: `0 0 ${cols * gap} ${rows * gap}`,
    width: "100%",
    height: "100%",
    preserveAspectRatio: cover ? "xMidYMid slice" : "xMidYMid meet",
    "aria-hidden": "true",
    style: {
      display: "block"
    }
  }, /*#__PURE__*/React.createElement("g", {
    strokeLinejoin: "round"
  }, geom.tris.map((t, i) => /*#__PURE__*/React.createElement("polygon", {
    key: i,
    ref: el => {
      elsRef.current[i] = el;
    },
    points: t.points,
    fill: t.fill,
    stroke: geom.stroke,
    strokeWidth: geom.sw
  }))));
}
window.HvDots = HvDots;
})(); } catch (e) { __ds_ns.__errors.push({ path: "site/HvDots.jsx", error: String((e && e.message) || e) }); }

// site/HvOcta.jsx
try { (() => {
// hypervisor.com — volumetric octahedron (the brand mark, made solid).
// A hand-rolled 3D render of the ioi octahedron: 6 vertices, 8 lit faces,
// painter-sorted, edge-lit, with a faint green core glow. Greyscale-luminous
// for dark surfaces by default. Slow auto-rotation; drag to orbit.
//
// Driver note: requestAnimationFrame is paused in some embedded/preview
// contexts, so we start on rAF and fall back to setInterval if it never ticks.
function HvOcta({
  size = 130,
  interactive = true,
  glow = true,
  speed = 0.5,
  theme = "dark"
}) {
  const ref = React.useRef(null);
  const ang = React.useRef({
    x: 0.62,
    y: 0.5
  });
  const drag = React.useRef({
    active: false,
    lx: 0,
    ly: 0
  });
  React.useEffect(function () {
    const canvas = ref.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const dark = theme !== "light";
    function fit() {
      const w = canvas.clientWidth || size,
        h = canvas.clientHeight || size;
      canvas.width = Math.round(w * dpr);
      canvas.height = Math.round(h * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    }
    fit();
    const ro = new ResizeObserver(fit);
    ro.observe(canvas);

    // geometry
    const OV = [[1, 0, 0], [-1, 0, 0], [0, 1, 0], [0, -1, 0], [0, 0, 1], [0, 0, -1]];
    const OF = [];
    [0, 1].forEach(function (sx) {
      [2, 3].forEach(function (sy) {
        [4, 5].forEach(function (sz) {
          OF.push([sx, sy, sz]);
        });
      });
    });
    const L = function () {
      const a = [0.45, 0.7, 0.75],
        m = Math.hypot(a[0], a[1], a[2]);
      return [a[0] / m, a[1] / m, a[2] / m];
    }();
    const EDGE = dark ? "255,255,255" : "10,14,25";
    const GREEN = "219,239,219";
    function rotate(p, ax, ay) {
      const x = p[0],
        y = p[1],
        z = p[2];
      const cy = Math.cos(ay),
        sy = Math.sin(ay);
      const x1 = x * cy + z * sy,
        z1 = -x * sy + z * cy;
      const cx = Math.cos(ax),
        sx = Math.sin(ax);
      const y1 = y * cx - z1 * sx,
        z2 = y * sx + z1 * cx;
      return [x1, y1, z2];
    }
    function proj(p, cx, cy, s, camZ) {
      const k = camZ / (camZ - p[2]);
      return [cx + p[0] * s * k, cy - p[1] * s * k];
    }
    function nrm(a) {
      const m = Math.hypot(a[0], a[1], a[2]) || 1;
      return [a[0] / m, a[1] / m, a[2] / m];
    }
    function dot(a, b) {
      return a[0] * b[0] + a[1] * b[1] + a[2] * b[2];
    }
    let lastT = performance.now();
    function draw() {
      const now = performance.now();
      const dt = Math.min((now - lastT) / 1000, 0.05);
      lastT = now;
      if (!drag.current.active && !reduce) ang.current.y += dt * speed;
      const W = canvas.clientWidth || size,
        H = canvas.clientHeight || size;
      ctx.clearRect(0, 0, W, H);
      const cx = W / 2,
        cy = H / 2,
        s = Math.min(W, H) * 0.34;
      const ax = ang.current.x,
        ay = ang.current.y;
      const rv = OV.map(function (v) {
        return rotate(v, ax, ay);
      });
      if (glow) {
        const g = ctx.createRadialGradient(cx, cy, 0, cx, cy, s * 1.15);
        g.addColorStop(0, "rgba(" + GREEN + ",0.16)");
        g.addColorStop(1, "rgba(" + GREEN + ",0)");
        ctx.fillStyle = g;
        ctx.fillRect(0, 0, W, H);
      }
      const faces = OF.map(function (f) {
        const a = rv[f[0]],
          b = rv[f[1]],
          c = rv[f[2]];
        const cen = [(a[0] + b[0] + c[0]) / 3, (a[1] + b[1] + c[1]) / 3, (a[2] + b[2] + c[2]) / 3];
        const bright = Math.max(0, dot(nrm(cen), L));
        return {
          pts: [a, b, c],
          cz: cen[2],
          bright: bright,
          front: cen[2] > -0.02
        };
      });
      faces.sort(function (p, q) {
        return p.cz - q.cz;
      });
      for (let i = 0; i < faces.length; i++) {
        const fc = faces[i];
        const P = fc.pts.map(function (v) {
          return proj(v, cx, cy, s, 3.4);
        });
        ctx.beginPath();
        ctx.moveTo(P[0][0], P[0][1]);
        ctx.lineTo(P[1][0], P[1][1]);
        ctx.lineTo(P[2][0], P[2][1]);
        ctx.closePath();
        const fa = (fc.front ? 0.07 : 0.02) + fc.bright * (dark ? 0.5 : 0.34);
        ctx.fillStyle = (dark ? "rgba(255,255,255," : "rgba(10,14,25,") + fa.toFixed(3) + ")";
        ctx.fill();
        ctx.strokeStyle = "rgba(" + EDGE + "," + ((dark ? 0.22 : 0.3) + fc.bright * 0.55).toFixed(3) + ")";
        ctx.lineWidth = 1.1;
        ctx.lineJoin = "round";
        ctx.stroke();
      }
    }

    // hybrid driver
    let ticked = false,
      rafId = 0,
      intId = 0;
    function rafLoop() {
      draw();
      ticked = true;
      rafId = requestAnimationFrame(rafLoop);
    }
    rafId = requestAnimationFrame(rafLoop);
    const watchdog = setTimeout(function () {
      if (!ticked) {
        intId = setInterval(draw, 1000 / 40);
      }
    }, 450);

    // drag to orbit
    function onDown(e) {
      if (!interactive) return;
      drag.current.active = true;
      drag.current.lx = e.clientX;
      drag.current.ly = e.clientY;
      try {
        canvas.setPointerCapture(e.pointerId);
      } catch (x) {}
    }
    function onMove(e) {
      if (!drag.current.active) return;
      ang.current.y += (e.clientX - drag.current.lx) * 0.01;
      ang.current.x += (e.clientY - drag.current.ly) * 0.01;
      ang.current.x = Math.max(-1.2, Math.min(1.2, ang.current.x));
      drag.current.lx = e.clientX;
      drag.current.ly = e.clientY;
    }
    function onUp() {
      drag.current.active = false;
    }
    if (interactive) {
      canvas.addEventListener("pointerdown", onDown);
      canvas.addEventListener("pointermove", onMove);
      window.addEventListener("pointerup", onUp);
    }
    return function () {
      ro.disconnect();
      clearTimeout(watchdog);
      if (rafId) cancelAnimationFrame(rafId);
      if (intId) clearInterval(intId);
      if (interactive) {
        canvas.removeEventListener("pointerdown", onDown);
        canvas.removeEventListener("pointermove", onMove);
        window.removeEventListener("pointerup", onUp);
      }
    };
  }, [size, interactive, glow, speed, theme]);
  return /*#__PURE__*/React.createElement("canvas", {
    ref: ref,
    style: {
      width: size,
      height: size,
      display: "block",
      cursor: interactive ? "grab" : "default",
      touchAction: "none"
    }
  });
}
window.HvOcta = HvOcta;
})(); } catch (e) { __ds_ns.__errors.push({ path: "site/HvOcta.jsx", error: String((e && e.message) || e) }); }

// site/Platform.jsx
try { (() => {
// hypervisor.com — Platform page.
const PNS = window.IoiDesignSystem;
const {
  Button: PgButton,
  Badge: PgBadge,
  Card: PgCard,
  TextLink: PgLink,
  Eyebrow: PgEyebrow
} = PNS;
const pwrap = {
  maxWidth: "75rem",
  margin: "0 auto",
  padding: "0 2.5rem"
};
function GreenCheck() {
  return /*#__PURE__*/React.createElement("svg", {
    width: "16",
    height: "16",
    viewBox: "0 0 16 16",
    fill: "none",
    style: {
      flexShrink: 0
    }
  }, /*#__PURE__*/React.createElement("path", {
    d: "M3 8.5l3.2 3.2L13 5",
    stroke: "var(--color-link-green)",
    strokeWidth: "1.5",
    strokeLinecap: "round",
    strokeLinejoin: "round"
  }));
}
function PgHero({
  eyebrow,
  title,
  sub,
  cta = true
}) {
  return /*#__PURE__*/React.createElement("section", {
    style: {
      ...pwrap,
      paddingTop: "4rem",
      textAlign: "center",
      display: "flex",
      flexDirection: "column",
      alignItems: "center"
    }
  }, /*#__PURE__*/React.createElement(PgEyebrow, {
    color: "var(--color-link-green)"
  }, eyebrow), /*#__PURE__*/React.createElement("h1", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "3.5rem",
      lineHeight: 1.05,
      letterSpacing: "-0.02em",
      margin: "1.25rem 0 0",
      maxWidth: "20ch",
      color: "var(--color-onyx-black)"
    }
  }, title), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.1875rem",
      color: "var(--color-grey-800)",
      marginTop: "1.25rem",
      maxWidth: "52ch",
      lineHeight: 1.5
    }
  }, sub), cta && /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      gap: "0.5rem",
      marginTop: "2rem"
    }
  }, /*#__PURE__*/React.createElement(PgButton, {
    iconRight: /*#__PURE__*/React.createElement("span", null, "\u2192")
  }, "Get started"), /*#__PURE__*/React.createElement(PgButton, {
    variant: "outline"
  }, "Request a demo")));
}
function SectionHead({
  eyebrow,
  title,
  sub
}) {
  return /*#__PURE__*/React.createElement("div", {
    style: {
      maxWidth: "44rem"
    }
  }, /*#__PURE__*/React.createElement(PgEyebrow, null, eyebrow), /*#__PURE__*/React.createElement("h2", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "2.5rem",
      letterSpacing: "-0.02em",
      lineHeight: 1.08,
      margin: "1rem 0 0"
    }
  }, title), sub && /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.0625rem",
      color: "var(--color-grey-800)",
      marginTop: "1rem",
      lineHeight: 1.5
    }
  }, sub));
}
const HvLogoMark = PNS.Logo;

// ---- premium hero visual: nine surfaces binding to one Core ----
function CoreConstellation() {
  const ring = [{
    label: "Clients",
    sub: "App · Web · CLI",
    x: "50%",
    y: "13%",
    tx: "-50%",
    ty: "0"
  }, {
    label: "Builder kits",
    sub: "SDK · ADK · ODK",
    x: "12%",
    y: "82%",
    tx: "0",
    ty: "-100%"
  }, {
    label: "Gateways & substrate",
    sub: "MCP · OS · Embodied",
    x: "88%",
    y: "82%",
    tx: "-100%",
    ty: "-100%"
  }];
  return /*#__PURE__*/React.createElement("div", {
    style: {
      position: "relative",
      aspectRatio: "1.04 / 1",
      borderRadius: "var(--radius-card)",
      overflow: "hidden",
      background: "radial-gradient(125% 120% at 50% 42%, #161a26 0%, #0c0e17 52%, #08090f 100%)"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      position: "absolute",
      inset: 0,
      opacity: 0.85,
      WebkitMaskImage: "radial-gradient(120% 110% at 50% 48%, transparent 22%, #000 64%)",
      maskImage: "radial-gradient(120% 110% at 50% 48%, transparent 22%, #000 64%)"
    },
    "aria-hidden": "true"
  }, window.HvDepthField ? /*#__PURE__*/React.createElement(window.HvDepthField, {
    seed: 6
  }) : /*#__PURE__*/React.createElement(window.HvDots, {
    inverse: true,
    interactive: true,
    cover: true,
    cols: 15,
    rows: 14,
    gap: 30,
    seed: 6
  })), /*#__PURE__*/React.createElement("svg", {
    viewBox: "0 0 100 100",
    preserveAspectRatio: "none",
    style: {
      position: "absolute",
      inset: 0,
      width: "100%",
      height: "100%",
      pointerEvents: "none"
    },
    "aria-hidden": "true"
  }, /*#__PURE__*/React.createElement("line", {
    x1: "50",
    y1: "48",
    x2: "50",
    y2: "20",
    stroke: "rgba(255,255,255,0.14)",
    strokeWidth: "0.4"
  }), /*#__PURE__*/React.createElement("line", {
    x1: "50",
    y1: "48",
    x2: "20",
    y2: "76",
    stroke: "rgba(255,255,255,0.14)",
    strokeWidth: "0.4"
  }), /*#__PURE__*/React.createElement("line", {
    x1: "50",
    y1: "48",
    x2: "80",
    y2: "76",
    stroke: "rgba(255,255,255,0.14)",
    strokeWidth: "0.4"
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      position: "absolute",
      left: "50%",
      top: "48%",
      transform: "translate(-50%,-50%)",
      display: "flex",
      flexDirection: "column",
      alignItems: "center",
      gap: 6
    }
  }, window.HvOcta ? /*#__PURE__*/React.createElement(window.HvOcta, {
    size: 132
  }) : /*#__PURE__*/React.createElement("div", {
    style: {
      width: 76,
      height: 76,
      borderRadius: "50%",
      border: "1px solid rgba(255,255,255,0.18)",
      display: "grid",
      placeItems: "center",
      background: "rgba(255,255,255,0.03)"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      color: "#fff",
      display: "inline-flex"
    }
  }, /*#__PURE__*/React.createElement(HvLogoMark, {
    size: 34
  }))), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 11,
      letterSpacing: "0.08em",
      textTransform: "uppercase",
      color: "var(--color-pistachio-green)"
    }
  }, "Hypervisor Core")), ring.map(r => /*#__PURE__*/React.createElement("div", {
    key: r.label,
    style: {
      position: "absolute",
      left: r.x,
      top: r.y,
      transform: `translate(${r.tx}, ${r.ty})`,
      display: "flex",
      flexDirection: "column",
      gap: 3,
      alignItems: "center",
      padding: "9px 13px",
      borderRadius: "var(--radius-lg)",
      border: "1px solid rgba(255,255,255,0.16)",
      background: "rgba(8,9,15,0.72)",
      backdropFilter: "blur(3px)",
      WebkitBackdropFilter: "blur(3px)",
      whiteSpace: "nowrap"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: 13.5,
      color: "#fff"
    }
  }, r.label), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 10.5,
      letterSpacing: "0.04em",
      color: "rgba(255,255,255,0.5)"
    }
  }, r.sub))));
}

// ---- soft-glow marketing visual for a platform product ----
function ProductVisual({
  kind,
  name
}) {
  const wrap = {
    width: "100%",
    aspectRatio: "1.25 / 1",
    borderRadius: 22,
    position: "relative",
    overflow: "hidden",
    display: "grid",
    placeItems: "center"
  };
  if (kind === "app") {
    return /*#__PURE__*/React.createElement("div", {
      style: {
        ...wrap,
        background: "radial-gradient(120% 110% at 50% 0%, #1a1a20, #0c0c0f)"
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        position: "absolute",
        inset: "16% 12%",
        borderRadius: 14,
        background: "rgba(255,255,255,0.04)",
        border: "1px solid rgba(255,255,255,0.09)",
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        gap: 16,
        padding: 24
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        color: "rgba(255,255,255,0.7)"
      }
    }, /*#__PURE__*/React.createElement(HvLogoMark, {
      size: 22
    })), /*#__PURE__*/React.createElement("div", {
      style: {
        width: "82%",
        height: 52,
        borderRadius: 11,
        background: "#161619",
        border: "1px solid rgba(255,255,255,0.1)"
      }
    }), /*#__PURE__*/React.createElement("div", {
      style: {
        display: "flex",
        gap: 8
      }
    }, [60, 44, 84].map((w, i) => /*#__PURE__*/React.createElement("span", {
      key: i,
      style: {
        width: w,
        height: 26,
        borderRadius: 999,
        background: "rgba(255,255,255,0.05)",
        border: "1px solid rgba(255,255,255,0.08)"
      }
    })))));
  }
  if (kind === "web") {
    return /*#__PURE__*/React.createElement("div", {
      style: {
        ...wrap,
        background: "linear-gradient(150deg, color-mix(in srgb, var(--color-pistachio-green) 50%, var(--color-white)), var(--color-porcelain-grey))"
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        position: "absolute",
        inset: "15% 12%",
        borderRadius: 14,
        background: "#0c0c0f",
        boxShadow: "0 24px 50px rgba(0,0,0,0.25)",
        overflow: "hidden"
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        display: "flex",
        alignItems: "center",
        gap: 6,
        padding: "11px 14px",
        borderBottom: "1px solid rgba(255,255,255,0.08)"
      }
    }, ["#ff5f57", "#ffbd2e", "#28c840"].map((c, i) => /*#__PURE__*/React.createElement("span", {
      key: i,
      style: {
        width: 9,
        height: 9,
        borderRadius: "50%",
        background: c
      }
    })), /*#__PURE__*/React.createElement("span", {
      style: {
        marginLeft: 8,
        width: "55%",
        height: 16,
        borderRadius: 6,
        background: "rgba(255,255,255,0.07)"
      }
    })), /*#__PURE__*/React.createElement("div", {
      style: {
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        gap: 13,
        height: "78%"
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        color: "rgba(255,255,255,0.7)"
      }
    }, /*#__PURE__*/React.createElement(HvLogoMark, {
      size: 20
    })), /*#__PURE__*/React.createElement("div", {
      style: {
        width: "70%",
        height: 40,
        borderRadius: 10,
        background: "rgba(255,255,255,0.05)",
        border: "1px solid rgba(255,255,255,0.1)"
      }
    }))));
  }
  if (kind === "cli") {
    return /*#__PURE__*/React.createElement("div", {
      style: {
        ...wrap,
        background: "radial-gradient(120% 110% at 50% 0%, #14181a, #0c0c0f)"
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        position: "absolute",
        inset: "16% 12%",
        borderRadius: 12,
        background: "#0c0c0f",
        border: "1px solid rgba(255,255,255,0.1)",
        boxShadow: "0 24px 50px rgba(0,0,0,0.3)",
        padding: "16px 18px",
        fontFamily: "var(--font-mono)",
        fontSize: 11.5,
        lineHeight: 2.1
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        color: "rgba(255,255,255,0.85)"
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        color: "rgba(255,255,255,0.35)"
      }
    }, "$ "), "hv run \"patch every CVE\""), /*#__PURE__*/React.createElement("div", {
      style: {
        color: "var(--color-link-green)"
      }
    }, "\u2713 session 9f2c1 \xB7 scoped"), /*#__PURE__*/React.createElement("div", {
      style: {
        color: "rgba(255,255,255,0.5)"
      }
    }, "\xB7 210 repos \xB7 187 PRs opened"), /*#__PURE__*/React.createElement("div", {
      style: {
        color: "#ff6b6b"
      }
    }, "\u2715 net.outbound blocked"), /*#__PURE__*/React.createElement("div", {
      style: {
        color: "var(--color-link-green)"
      }
    }, "\u2713 receipts signed")));
  }
  if (kind === "glow") {
    return /*#__PURE__*/React.createElement("div", {
      style: {
        ...wrap,
        background: "radial-gradient(circle at 50% 48%, #1d2a45 0%, #10131f 45%, #0a0a0d 100%)"
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        fontFamily: "var(--font-serif)",
        fontWeight: 300,
        fontSize: "1.875rem",
        color: "#fff",
        letterSpacing: "-0.01em",
        textShadow: "0 0 28px rgba(120,170,255,0.55), 0 0 60px rgba(120,170,255,0.3)"
      }
    }, name));
  }
  // light gradient
  return /*#__PURE__*/React.createElement("div", {
    style: {
      ...wrap,
      background: "linear-gradient(150deg, color-mix(in srgb, var(--color-pistachio-green) 55%, var(--color-white)), color-mix(in srgb, var(--color-link-green) 18%, var(--color-white)) 60%, var(--color-porcelain-grey))"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "1.875rem",
      color: "var(--color-onyx-black)",
      letterSpacing: "-0.01em"
    }
  }, name));
}
function ProductRow({
  name,
  role,
  desc,
  visual,
  flip,
  file
}) {
  return /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "1fr 1fr",
      gap: "4.5rem",
      alignItems: "center"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      order: flip ? 2 : 1
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 11,
      letterSpacing: "0.08em",
      textTransform: "uppercase",
      color: "var(--color-link-green)"
    }
  }, role), /*#__PURE__*/React.createElement("h3", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "2.5rem",
      letterSpacing: "-0.02em",
      lineHeight: 1.05,
      margin: "0.875rem 0 0",
      color: "var(--color-onyx-black)"
    }
  }, /*#__PURE__*/React.createElement("a", {
    href: file,
    style: {
      color: "inherit",
      textDecoration: "none"
    }
  }, name)), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.0625rem",
      color: "var(--color-grey-800)",
      marginTop: "1.25rem",
      lineHeight: 1.55,
      maxWidth: "40ch"
    }
  }, desc), /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: "1.5rem"
    }
  }, /*#__PURE__*/React.createElement(PgLink, {
    href: file
  }, "Explore ", name))), /*#__PURE__*/React.createElement("a", {
    href: file,
    style: {
      order: flip ? 1 : 2,
      textDecoration: "none",
      color: "inherit",
      display: "block"
    }
  }, visual));
}
const FAMILIES = [["Clients", "Operate the substrate", [["Hypervisor App", "Desktop · command center", "Start governed sessions, run automations, and supervise agents across projects, tools, and models — local-first.", "hv-app.html"], ["Hypervisor Web", "Browser · team client", "Shared projects, remote sessions, approvals, and run history for the whole team — without changing runtime truth.", "hv-web.html"], ["Hypervisor CLI", "Terminal · scripting · CI", "Script and supervise autonomous work from CI, shells, and servers with the same authority and receipts as the app.", "hv-cli.html"]]], ["Builder kits", "Extend and embed it", [["Hypervisor SDK", "Protocol library", "Integrate Hypervisor into products and agents without reimplementing runtime, authority, receipt, or state.", "hv-sdk.html"], ["Hypervisor ADK", "Autonomous-system kit", "Compose workers, harnesses, evals, and manifests into governed, deployable autonomous-system bundles.", "hv-adk.html"], ["Hypervisor ODK", "Ontology-aware kit", "Compile domain ontologies and data recipes into generated surfaces, domain apps, and marketplace packs.", "hv-odk.html"]]], ["Gateways & substrate", "Carry it outward and down to the metal", [["Hypervisor MCP", "Scoped external gateway", "Expose selected capabilities to external agents through revocable, auditable MCP profiles — never a master key.", "hv-mcp.html"], ["HypervisorOS", "Bare-metal node profile", "Run governed private agent compute on measured nodes — containers and microVMs under kernel-level policy.", "hv-os.html"], ["Embodied Runtime", "Physical autonomy profile", "Operate robot fleets, devices, sensors, and command queues under safety gates with attributed operator handoff.", "hv-embodied.html"]]]];
const ENVS = [["Local machines", "Your laptop or workstation, under a local daemon."], ["Cloud & VPC", "Hosted runtime or your own VPC — same substrate, your perimeter."], ["cTEE private workspace", "Plaintext-free custody; protected data never enters provider memory."], ["DePIN & provider nodes", "Akash compute, Filecoin storage, TEE-verified nodes — routed, receipted."]];

// ---- Reference layout: orients rather than converts ----
function RefFamilyMap() {
  return /*#__PURE__*/React.createElement("section", {
    style: {
      ...pwrap,
      paddingTop: "5rem"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "baseline",
      gap: "0.875rem",
      marginBottom: "2.5rem"
    }
  }, /*#__PURE__*/React.createElement(PgEyebrow, null, "The product map"), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "0.9375rem",
      color: "var(--color-grey-700)"
    }
  }, "Nine products \xB7 three roles \xB7 one Core")), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      flexDirection: "column",
      gap: "3.5rem"
    }
  }, FAMILIES.map(([family, note, items], fi) => /*#__PURE__*/React.createElement("div", {
    key: family
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "baseline",
      gap: "0.875rem",
      paddingBottom: "1.25rem",
      borderBottom: "1px solid var(--color-grey-500)"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 11,
      letterSpacing: "0.08em",
      textTransform: "uppercase",
      color: "var(--color-link-green)"
    }
  }, family), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "0.9375rem",
      color: "var(--color-grey-700)"
    }
  }, note)), /*#__PURE__*/React.createElement("div", {
    className: "hv-pm-grid",
    style: {
      display: "grid",
      gridTemplateColumns: "repeat(3, 1fr)",
      gap: "1.25rem",
      marginTop: "1.5rem"
    }
  }, items.map(([name, role, desc, file], i) => /*#__PURE__*/React.createElement("a", {
    key: name,
    href: file,
    className: "hv-pmcard",
    style: {
      position: "relative",
      display: "flex",
      flexDirection: "column",
      background: "var(--color-white)",
      border: "0.5px solid var(--color-grey-500)",
      borderRadius: "var(--radius-card)",
      padding: "1.75rem",
      textDecoration: "none",
      color: "inherit"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      justifyContent: "space-between"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 10.5,
      letterSpacing: "0.05em",
      textTransform: "uppercase",
      color: "var(--color-grey-700)"
    }
  }, role), /*#__PURE__*/React.createElement("span", {
    className: "hv-pmarrow",
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1rem",
      color: "var(--color-link-green)",
      opacity: 0,
      transform: "translateX(-4px)",
      transition: "opacity 200ms cubic-bezier(0.22,1,0.36,1), transform 200ms cubic-bezier(0.22,1,0.36,1)"
    }
  }, "\u2192")), /*#__PURE__*/React.createElement("h3", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "1.625rem",
      letterSpacing: "-0.02em",
      lineHeight: 1.1,
      margin: "0.75rem 0 0",
      color: "var(--color-onyx-black)"
    }
  }, name), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "0.9375rem",
      color: "var(--color-grey-800)",
      marginTop: "0.75rem",
      lineHeight: 1.5
    }
  }, desc))))))));
}
function ChipGlyph() {
  return /*#__PURE__*/React.createElement("svg", {
    width: "40",
    height: "40",
    viewBox: "0 0 40 40",
    fill: "none",
    stroke: "var(--color-onyx-black)",
    strokeWidth: "1.5",
    strokeLinecap: "round",
    strokeLinejoin: "round",
    "aria-hidden": "true"
  }, /*#__PURE__*/React.createElement("rect", {
    x: "11",
    y: "11",
    width: "18",
    height: "18",
    rx: "2.5"
  }), /*#__PURE__*/React.createElement("rect", {
    x: "16.5",
    y: "16.5",
    width: "7",
    height: "7",
    rx: "1"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M16 11 V7 M24 11 V7 M16 33 V29 M24 33 V29 M11 16 H7 M11 24 H7 M33 16 H29 M33 24 H29"
  }));
}
function StackGlyph() {
  return /*#__PURE__*/React.createElement("svg", {
    width: "40",
    height: "40",
    viewBox: "0 0 40 40",
    fill: "none",
    stroke: "var(--color-onyx-black)",
    strokeWidth: "1.5",
    strokeLinecap: "round",
    strokeLinejoin: "round",
    "aria-hidden": "true"
  }, /*#__PURE__*/React.createElement("rect", {
    x: "8",
    y: "23",
    width: "24",
    height: "8",
    rx: "2"
  }), /*#__PURE__*/React.createElement("rect", {
    x: "14",
    y: "13",
    width: "12",
    height: "8",
    rx: "2"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M20 23 V21"
  }));
}
function PgLineage() {
  const foundation = [{
    tag: "Type 2",
    sub: "Hosted",
    virt: "operating systems",
    ex: "VMware · VirtualBox · Parallels",
    glyph: /*#__PURE__*/React.createElement(StackGlyph, null)
  }, {
    tag: "Type 1",
    sub: "Bare metal",
    virt: "hardware",
    ex: "ESXi · Xen · KVM",
    glyph: /*#__PURE__*/React.createElement(ChipGlyph, null)
  }];
  return /*#__PURE__*/React.createElement("section", {
    style: {
      ...pwrap,
      paddingTop: "5.5rem"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      maxWidth: "46rem"
    }
  }, /*#__PURE__*/React.createElement(PgEyebrow, {
    color: "var(--color-link-green)"
  }, "The third hypervisor layer"), /*#__PURE__*/React.createElement("h2", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "2.5rem",
      letterSpacing: "-0.02em",
      lineHeight: 1.08,
      margin: "1rem 0 0"
    }
  }, "A new layer in the hypervisor lineage"), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.0625rem",
      color: "var(--color-grey-800)",
      marginTop: "1rem",
      maxWidth: "60ch",
      lineHeight: 1.55
    }
  }, "Type\xA01 virtualized hardware. Type\xA02 virtualized operating systems. Hypervisor virtualizes autonomy \u2014 isolating, scheduling, supervising, and governing autonomous workers across machines, models, tools, and providers.")), /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: "2.75rem"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      position: "relative",
      zIndex: 2,
      border: "1px solid var(--color-onyx-black)",
      borderRadius: "var(--radius-card)",
      background: "color-mix(in srgb, var(--color-pistachio-green) 24%, var(--color-white))",
      boxShadow: "var(--shadow-md)",
      padding: "1.625rem 1.875rem",
      display: "flex",
      alignItems: "center",
      gap: "1.5rem",
      flexWrap: "wrap"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 56,
      height: 56,
      borderRadius: 15,
      background: "var(--color-white)",
      border: "1px solid var(--color-onyx-black)",
      display: "grid",
      placeItems: "center",
      color: "var(--color-link-green)",
      flex: "none"
    }
  }, /*#__PURE__*/React.createElement(HvLogoMark, {
    size: 32
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      flex: "none"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 12,
      letterSpacing: "0.06em",
      textTransform: "uppercase",
      color: "var(--color-link-green)"
    }
  }, "The third layer \xB7 Hypervisor"), /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.375rem",
      letterSpacing: "-0.015em",
      color: "var(--color-onyx-black)",
      marginTop: 5
    }
  }, "Virtualizes ", /*#__PURE__*/React.createElement("strong", {
    style: {
      fontWeight: 700
    }
  }, "autonomy"))), /*#__PURE__*/React.createElement("div", {
    style: {
      marginLeft: "auto",
      textAlign: "right",
      maxWidth: "34ch"
    }
  }, /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "0.9375rem",
      color: "var(--color-grey-800)",
      margin: 0,
      lineHeight: 1.45
    }
  }, "Governs above any machine, model, or provider \u2014 and still provisions and isolates the layers beneath it."), /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 11.5,
      color: "var(--color-grey-700)",
      marginTop: 8
    }
  }, "machines \xB7 models \xB7 tools \xB7 providers"))), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      gap: 10,
      padding: "0.9rem 0"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 1,
      height: 18,
      background: "var(--color-grey-500)"
    }
  }), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 11,
      letterSpacing: "0.12em",
      textTransform: "uppercase",
      color: "var(--color-grey-700)"
    }
  }, "rests on & governs the substrate below"), /*#__PURE__*/React.createElement("span", {
    style: {
      width: 1,
      height: 18,
      background: "var(--color-grey-500)"
    }
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      width: "90%",
      margin: "0 auto",
      display: "flex",
      flexDirection: "column",
      gap: "0.75rem"
    }
  }, foundation.map(c => /*#__PURE__*/React.createElement("div", {
    key: c.tag,
    style: {
      display: "flex",
      alignItems: "center",
      gap: "1.25rem",
      border: "0.5px solid var(--color-grey-500)",
      borderRadius: "var(--radius-card)",
      background: "var(--color-porcelain-grey)",
      padding: "1.125rem 1.5rem",
      flexWrap: "wrap"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 46,
      height: 46,
      borderRadius: 12,
      background: "var(--color-white)",
      border: "0.5px solid var(--color-grey-500)",
      display: "grid",
      placeItems: "center",
      flex: "none"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      transform: "scale(0.78)"
    }
  }, c.glyph)), /*#__PURE__*/React.createElement("div", {
    style: {
      minWidth: 168,
      flex: "none"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 12,
      letterSpacing: "0.06em",
      textTransform: "uppercase",
      color: "var(--color-grey-700)"
    }
  }, c.tag, " \xB7 ", c.sub)), /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.125rem",
      letterSpacing: "-0.015em",
      color: "var(--color-onyx-black)"
    }
  }, "Virtualizes ", /*#__PURE__*/React.createElement("strong", {
    style: {
      fontWeight: 700
    }
  }, c.virt)), /*#__PURE__*/React.createElement("div", {
    style: {
      marginLeft: "auto",
      fontFamily: "var(--font-mono)",
      fontSize: 11.5,
      color: "var(--color-grey-700)"
    }
  }, c.ex))))), /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: "2.5rem",
      paddingTop: "1.75rem",
      borderTop: "1px solid var(--color-onyx-black)"
    }
  }, /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "1.875rem",
      letterSpacing: "-0.015em",
      lineHeight: 1.2,
      margin: 0,
      color: "var(--color-onyx-black)",
      maxWidth: "32ch"
    }
  }, "It doesn\u2019t replace Type\xA01 or Type\xA02 \u2014 it governs above them.")));
}
function LifecycleOrbit() {
  const stages = [["Build", "Compose workflows, train workers in Foundry, and wire tools, models, and connectors into governed pipelines."], ["Run & scale", "Execute sessions across local machines, cloud, VPC, cTEE, and DePIN compute — one substrate, any provider."], ["Govern", "Authority is explicit. Tool calls are requests, not grants. Scope every credential; gate every consequential action."], ["Observe & verify", "Logs become receipts. Inspect runs, replay deterministically, and carry proof of what happened."], ["Optimize", "Route work through Mixture of Workers. Improve via prompts, retrieval, policy, adapters, or fine-tuning."], ["Package & trade", "Ship workers and services as deployable, benchmarked packages. Settle completed machine labor on IOI L1."]];
  const N = stages.length;
  const ACC = "var(--color-link-green)";
  const MAXW = 760,
    ARH = 620 / 760;
  const geoOf = (w, h) => ({
    cx: w * 0.5,
    cy: h * 0.5,
    R: w * 0.305
  });
  const nodeAngle = i => -Math.PI / 2 + i * (2 * Math.PI / N);
  const [active, setActive] = React.useState(0);
  const [box, setBox] = React.useState({
    w: MAXW,
    h: MAXW * ARH
  });
  // center copy crossfade: fade out → swap → fade in (decoupled from the canvas frame loop)
  const [disp, setDisp] = React.useState(0);
  const [vis, setVis] = React.useState(true);
  React.useEffect(() => {
    if (disp === active) return;
    setVis(false);
    const t = setTimeout(() => {
      setDisp(active);
      setVis(true);
    }, 280);
    return () => clearTimeout(t);
  }, [active]);
  const {
    cx,
    cy,
    R
  } = geoOf(box.w, box.h);
  const wrapRef = React.useRef(null);
  const canvasRef = React.useRef(null);
  const pausedRef = React.useRef(false);
  const activeRef = React.useRef(0);
  const stRef = React.useRef({
    stepF: 0,
    stepTarget: 0,
    nextAdv: 0,
    last: 0,
    trail: [],
    colors: null,
    geo: null
  });

  // resolve CSS custom-prop colors to rgb triplets the canvas can blend with alpha
  React.useEffect(() => {
    const probe = cssColor => {
      const el = document.createElement("span");
      el.style.cssText = "position:absolute;visibility:hidden;color:" + cssColor;
      document.body.appendChild(el);
      const m = getComputedStyle(el).color.match(/[\d.]+/g) || [0, 0, 0];
      document.body.removeChild(el);
      return [Math.round(+m[0]), Math.round(+m[1]), Math.round(+m[2])];
    };
    stRef.current.colors = {
      green: probe("var(--color-link-green)"),
      pist: probe("var(--color-pistachio-green)"),
      hair: probe("var(--color-grey-500)"),
      white: probe("var(--color-white)")
    };
  }, []);

  // fit to container
  React.useEffect(() => {
    const fit = () => {
      if (wrapRef.current) {
        const w = Math.min(wrapRef.current.clientWidth, MAXW);
        setBox(p => Math.abs(p.w - w) < 0.5 ? p : {
          w,
          h: w * ARH
        });
      }
    };
    fit();
    const ro = new ResizeObserver(fit);
    if (wrapRef.current) ro.observe(wrapRef.current);
    return () => ro.disconnect();
  }, []);

  // size the backing store + run the animation loop
  React.useEffect(() => {
    const cv = canvasRef.current;
    if (!cv) return;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    cv.width = Math.round(box.w * dpr);
    cv.height = Math.round(box.h * dpr);
    const ctx = cv.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    const st = stRef.current;
    st.geo = geoOf(box.w, box.h);
    const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const DWELL = 3600,
      TWO = Math.PI * 2,
      SP = TWO / N;
    const rgba = (c, a) => `rgba(${c[0]},${c[1]},${c[2]},${a})`;
    const setA = i => {
      if (i !== activeRef.current) {
        activeRef.current = i;
        setActive(i);
      }
    };
    st.nextAdv = performance.now() + DWELL;
    st.last = 0;
    let raf;
    const draw = ts => {
      const C = st.colors;
      const {
        cx,
        cy,
        R
      } = st.geo;
      const w = box.w,
        h = box.h;
      ctx.clearRect(0, 0, w, h);
      if (!C) {
        raf = requestAnimationFrame(draw);
        return;
      }

      // advance + ease (clockwise, monotonic)
      if (!pausedRef.current && ts > st.nextAdv) {
        st.stepTarget += 1;
        st.nextAdv = ts + DWELL;
      }
      const dt = st.last ? Math.min(ts - st.last, 60) : 16;
      st.last = ts;
      st.stepF += (st.stepTarget - st.stepF) * (1 - Math.exp(-dt / 300));
      const headA = nodeAngle(0) + st.stepF * SP;
      const hx = cx + R * Math.cos(headA),
        hy = cy + R * Math.sin(headA);
      setA((Math.round(st.stepF) % N + N) % N);

      // faint hub spokes — everything binds to the core
      ctx.lineWidth = 1;
      for (let i = 0; i < N; i++) {
        const a = nodeAngle(i);
        ctx.strokeStyle = rgba(C.hair, 0.14);
        ctx.beginPath();
        ctx.moveTo(cx, cy);
        ctx.lineTo(cx + R * Math.cos(a), cy + R * Math.sin(a));
        ctx.stroke();
      }

      // track rail + slowly drifting dotted ring (the system's dotted identity)
      ctx.strokeStyle = rgba(C.hair, 0.72);
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.arc(cx, cy, R, 0, TWO);
      ctx.stroke();
      ctx.save();
      ctx.setLineDash([0.5, 6]);
      ctx.lineCap = "round";
      ctx.lineDashOffset = -(ts / 130);
      ctx.strokeStyle = rgba(C.hair, 0.42);
      ctx.beginPath();
      ctx.arc(cx, cy, R - 11, 0, TWO);
      ctx.stroke();
      ctx.restore();

      // tapered hairline tracer (no glow — a clean ink stroke that thins to nothing)
      st.trail.push([hx, hy]);
      if (st.trail.length > 22) st.trail.shift();
      ctx.lineCap = "round";
      for (let i = 1; i < st.trail.length; i++) {
        const t = i / st.trail.length;
        ctx.strokeStyle = rgba(C.green, 0.85 * t);
        ctx.lineWidth = 0.5 + 1.4 * t;
        ctx.beginPath();
        ctx.moveTo(st.trail[i - 1][0], st.trail[i - 1][1]);
        ctx.lineTo(st.trail[i][0], st.trail[i][1]);
        ctx.stroke();
      }

      // node marks — quiet neutral seats; the single tracer head is the only accent
      for (let i = 0; i < N; i++) {
        const a = nodeAngle(i),
          nx = cx + R * Math.cos(a),
          ny = cy + R * Math.sin(a);
        ctx.beginPath();
        ctx.arc(nx, ny, 3, 0, TWO);
        ctx.fillStyle = rgba(C.white, 1);
        ctx.fill();
        ctx.lineWidth = 1;
        ctx.strokeStyle = rgba(C.hair, 1);
        ctx.stroke();
      }

      // tracer head — small, crisp, lifted off the rail with a thin ring
      ctx.beginPath();
      ctx.arc(hx, hy, 5, 0, TWO);
      ctx.fillStyle = rgba(C.white, 1);
      ctx.fill();
      ctx.lineWidth = 1;
      ctx.strokeStyle = rgba(C.green, 0.9);
      ctx.stroke();
      ctx.beginPath();
      ctx.arc(hx, hy, 2.8, 0, TWO);
      ctx.fillStyle = rgba(C.green, 1);
      ctx.fill();
      raf = requestAnimationFrame(draw);
    };
    if (reduce) {
      st.stepF = st.stepTarget;
      const tick = () => {
        if (!pausedRef.current) {
          st.stepTarget += 1;
          st.stepF = st.stepTarget;
          setA((st.stepTarget % N + N) % N);
        }
      };
      const id = setInterval(tick, DWELL);
      raf = requestAnimationFrame(draw);
      return () => {
        clearInterval(id);
        cancelAnimationFrame(raf);
      };
    }
    raf = requestAnimationFrame(draw);
    return () => cancelAnimationFrame(raf);
  }, [box.w, box.h]);
  const focusStage = i => {
    pausedRef.current = true;
    const st = stRef.current;
    const cur = (Math.round(st.stepTarget) % N + N) % N;
    st.stepTarget = st.stepTarget + (i - cur + N) % N;
  };
  const blurStage = () => {
    pausedRef.current = false;
    stRef.current.nextAdv = performance.now() + 1400;
  };
  const labelPos = i => {
    const a = nodeAngle(i),
      lr = R + box.w * 0.034;
    return {
      lx: cx + lr * Math.cos(a),
      ly: cy + lr * Math.sin(a),
      c: Math.cos(a),
      s: Math.sin(a)
    };
  };
  return /*#__PURE__*/React.createElement("div", {
    style: {
      padding: "0.5rem 2.5rem 3.25rem"
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "hv-lc-ring",
    ref: wrapRef,
    style: {
      position: "relative",
      width: "100%"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      position: "relative",
      width: box.w,
      height: box.h,
      margin: "0 auto"
    }
  }, /*#__PURE__*/React.createElement("canvas", {
    ref: canvasRef,
    style: {
      position: "absolute",
      inset: 0,
      width: "100%",
      height: "100%"
    },
    "aria-hidden": "true"
  }), /*#__PURE__*/React.createElement("div", {
    style: {
      position: "absolute",
      left: "50%",
      top: "50%",
      transform: "translate(-50%, -50%)",
      width: 312,
      textAlign: "center",
      display: "flex",
      flexDirection: "column",
      alignItems: "center"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 46,
      height: 46,
      borderRadius: "50%",
      background: "var(--color-white)",
      border: "0.5px solid var(--color-grey-500)",
      boxShadow: "var(--shadow-sm)",
      display: "grid",
      placeItems: "center",
      color: ACC
    }
  }, /*#__PURE__*/React.createElement(HvLogoMark, {
    size: 23
  })), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 10.5,
      letterSpacing: "0.14em",
      textTransform: "uppercase",
      color: "var(--color-grey-600)",
      marginTop: 10
    }
  }, "Hypervisor Core"), /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: 16,
      transition: "opacity 300ms cubic-bezier(0.4, 0, 0.2, 1), transform 300ms cubic-bezier(0.4, 0, 0.2, 1)",
      opacity: vis ? 1 : 0,
      transform: vis ? "translateY(0)" : "translateY(3px)"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "baseline",
      justifyContent: "center",
      gap: 11
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "2.625rem",
      lineHeight: 1,
      letterSpacing: "-0.02em",
      color: ACC,
      fontVariantNumeric: "tabular-nums"
    }
  }, String(disp + 1).padStart(2, "0")), /*#__PURE__*/React.createElement("h3", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.4375rem",
      letterSpacing: "-0.02em",
      margin: 0,
      color: "var(--color-onyx-black)",
      whiteSpace: "nowrap"
    }
  }, stages[disp][0])), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "0.9375rem",
      color: "var(--color-grey-800)",
      margin: "12px auto 0",
      maxWidth: "30ch",
      lineHeight: 1.5,
      minHeight: "4.4em"
    }
  }, stages[disp][1]))), stages.map(([title], i) => {
    const {
        lx,
        ly,
        c,
        s
      } = labelPos(i),
      on = i === active;
    let tx = "-50%",
      talign = "center";
    if (c > 0.2) {
      tx = "0";
      talign = "left";
    } else if (c < -0.2) {
      tx = "-100%";
      talign = "right";
    }
    const ty = s > 0.2 ? "0" : s < -0.2 ? "-100%" : "-50%";
    return /*#__PURE__*/React.createElement("button", {
      key: title,
      type: "button",
      onMouseEnter: () => focusStage(i),
      onMouseLeave: blurStage,
      onFocus: () => focusStage(i),
      onBlur: blurStage,
      "aria-label": `Stage ${i + 1}: ${title}`,
      style: {
        position: "absolute",
        left: `${lx / box.w * 100}%`,
        top: `${ly / box.h * 100}%`,
        transform: `translate(${tx}, ${ty})`,
        textAlign: talign,
        background: "none",
        border: "none",
        padding: 4,
        margin: -4,
        cursor: "pointer",
        font: "inherit",
        whiteSpace: "nowrap"
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        fontFamily: "var(--font-mono)",
        fontSize: 10.5,
        letterSpacing: "0.06em",
        color: on ? ACC : "var(--color-grey-500)",
        transition: "color 220ms"
      }
    }, String(i + 1).padStart(2, "0")), /*#__PURE__*/React.createElement("div", {
      style: {
        fontFamily: "var(--font-sans)",
        fontSize: "1rem",
        letterSpacing: "-0.015em",
        marginTop: 2,
        fontWeight: on ? 600 : 400,
        color: on ? "var(--color-onyx-black)" : "var(--color-grey-700)",
        transition: "color 220ms"
      }
    }, title));
  }))), /*#__PURE__*/React.createElement("ol", {
    className: "hv-lc-list",
    style: {
      display: "none",
      listStyle: "none",
      margin: 0,
      padding: 0,
      flexDirection: "column"
    }
  }, stages.map(([title, body], i) => /*#__PURE__*/React.createElement("li", {
    key: title,
    style: {
      display: "grid",
      gridTemplateColumns: "auto 1fr",
      gap: "1rem",
      paddingBottom: i < N - 1 ? "1.5rem" : 0
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      flexDirection: "column",
      alignItems: "center"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 30,
      height: 30,
      borderRadius: "50%",
      display: "grid",
      placeItems: "center",
      fontFamily: "var(--font-mono)",
      fontSize: 12,
      background: "var(--color-white)",
      border: "0.5px solid var(--color-grey-500)",
      color: ACC,
      flex: "none"
    }
  }, String(i + 1).padStart(2, "0")), i < N - 1 && /*#__PURE__*/React.createElement("span", {
    style: {
      width: 1,
      flex: 1,
      marginTop: 6,
      borderLeft: "1px dashed var(--color-grey-500)"
    }
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      paddingTop: 3
    }
  }, /*#__PURE__*/React.createElement("h3", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.0625rem",
      letterSpacing: "-0.015em",
      margin: 0,
      color: "var(--color-onyx-black)"
    }
  }, title), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "0.9375rem",
      color: "var(--color-grey-800)",
      margin: "0.4rem 0 0",
      lineHeight: 1.45
    }
  }, body))))));
}
function ReferenceBody() {
  return /*#__PURE__*/React.createElement("main", null, /*#__PURE__*/React.createElement("section", {
    className: "hv-plat-hero",
    style: {
      ...pwrap,
      paddingTop: "4rem",
      display: "grid",
      gridTemplateColumns: "1.02fr 0.98fr",
      gap: "3.5rem",
      alignItems: "center"
    }
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement(PgEyebrow, {
    color: "var(--color-link-green)"
  }, "Platform overview"), /*#__PURE__*/React.createElement("h1", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "3.5rem",
      lineHeight: 1.04,
      letterSpacing: "-0.02em",
      margin: "1.25rem 0 0",
      maxWidth: "14ch",
      color: "var(--color-onyx-black)"
    }
  }, "Many surfaces, one truth"), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.1875rem",
      color: "var(--color-grey-800)",
      marginTop: "1.5rem",
      maxWidth: "46ch",
      lineHeight: 1.55
    }
  }, "Hypervisor is one governed substrate for autonomous work. Nine products bind to a single Hypervisor Core \u2014 clients operate it, builder kits extend it, gateways carry it outward and down to the metal. None of them owns runtime truth or authority; that stays yours."), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: "1.25rem",
      marginTop: "1.75rem",
      flexWrap: "wrap"
    }
  }, /*#__PURE__*/React.createElement(PgButton, {
    iconRight: /*#__PURE__*/React.createElement("span", null, "\u2192")
  }, "Get started"), /*#__PURE__*/React.createElement(PgLink, {
    href: "developers.html"
  }, "Read the architecture"))), /*#__PURE__*/React.createElement(CoreConstellation, null)), /*#__PURE__*/React.createElement(PgLineage, null), /*#__PURE__*/React.createElement(RefFamilyMap, null), /*#__PURE__*/React.createElement("section", {
    style: {
      ...pwrap,
      paddingTop: "6rem"
    }
  }, /*#__PURE__*/React.createElement(SectionHead, {
    eyebrow: "Run anywhere",
    title: "Edge-in, across any environment",
    sub: "Work starts near your user, device, and data. Only the commitments that need public trust project into settlement."
  }), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "repeat(2, 1fr)",
      gap: "1.25rem",
      marginTop: "2.5rem"
    }
  }, ENVS.map(([t, d]) => /*#__PURE__*/React.createElement(PgCard, {
    key: t,
    tone: "subtle",
    style: {
      padding: "1.5rem 1.75rem"
    }
  }, /*#__PURE__*/React.createElement("h3", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.0625rem",
      margin: 0
    }
  }, t), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "0.9375rem",
      color: "var(--color-grey-800)",
      marginTop: "0.5rem",
      lineHeight: 1.45
    }
  }, d))))), /*#__PURE__*/React.createElement("section", {
    style: {
      ...pwrap,
      paddingTop: "6.5rem"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      background: "var(--color-porcelain-grey)",
      borderRadius: "var(--radius-card)",
      overflow: "hidden"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      padding: "3rem 3rem 2.25rem"
    }
  }, /*#__PURE__*/React.createElement(PgEyebrow, {
    color: "var(--color-link-green)"
  }, "One substrate \xB7 full lifecycle"), /*#__PURE__*/React.createElement("h2", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "2.5rem",
      lineHeight: 1.1,
      letterSpacing: "-0.02em",
      margin: "1rem 0 0",
      color: "var(--color-onyx-black)"
    }
  }, "Everything autonomous work needs.", /*#__PURE__*/React.createElement("br", null), /*#__PURE__*/React.createElement("span", {
    style: {
      color: "var(--color-grey-700)"
    }
  }, "Behind one stable shell, owned by no single vendor."))), /*#__PURE__*/React.createElement(LifecycleOrbit, null))), /*#__PURE__*/React.createElement("section", {
    style: {
      ...pwrap,
      paddingTop: "6rem"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "baseline",
      justifyContent: "space-between",
      gap: "2rem",
      flexWrap: "wrap",
      paddingTop: "2.5rem",
      borderTop: "1px solid var(--color-grey-500)"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      maxWidth: "40ch"
    }
  }, /*#__PURE__*/React.createElement("h2", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "1.875rem",
      letterSpacing: "-0.02em",
      lineHeight: 1.1,
      margin: 0,
      color: "var(--color-onyx-black)"
    }
  }, "Put autonomous work under authority"), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1rem",
      color: "var(--color-grey-800)",
      marginTop: "0.75rem"
    }
  }, "Start in minutes. Bring your own models, providers, and infrastructure.")), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      gap: "0.5rem"
    }
  }, /*#__PURE__*/React.createElement(PgButton, {
    iconRight: /*#__PURE__*/React.createElement("span", null, "\u2192")
  }, "Get started")))));
}
window.HvPage = ReferenceBody;
window.HvPageActive = "Platform";
})(); } catch (e) { __ds_ns.__errors.push({ path: "site/Platform.jsx", error: String((e && e.message) || e) }); }

// site/PlatformApp.jsx
try { (() => {
// hypervisor.com — faithful recreations of Hypervisor client surfaces
// (App · Web · CLI), used as the Platform page hero showcase.
(function () {
  const NS = window.IoiDesignSystem;
  const AppLogo = NS.Logo;
  const ACC = "var(--color-link-green)";
  const ico = (d, sw) => /*#__PURE__*/React.createElement("svg", {
    width: "17",
    height: "17",
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: sw || 1.7,
    strokeLinecap: "round",
    strokeLinejoin: "round"
  }, d);
  const I = {
    plus: ico(/*#__PURE__*/React.createElement("path", {
      d: "M12 5 V19 M5 12 H19"
    })),
    home: ico(/*#__PURE__*/React.createElement("path", {
      d: "M4 11 L12 4 L20 11 V20 H4 Z M9 20 V14 H15 V20"
    })),
    projects: ico(/*#__PURE__*/React.createElement("g", null, /*#__PURE__*/React.createElement("rect", {
      x: "4",
      y: "4",
      width: "7",
      height: "7",
      rx: "1.4"
    }), /*#__PURE__*/React.createElement("rect", {
      x: "13",
      y: "4",
      width: "7",
      height: "7",
      rx: "1.4"
    }), /*#__PURE__*/React.createElement("rect", {
      x: "4",
      y: "13",
      width: "7",
      height: "7",
      rx: "1.4"
    }), /*#__PURE__*/React.createElement("rect", {
      x: "13",
      y: "13",
      width: "7",
      height: "7",
      rx: "1.4"
    }))),
    auto: ico(/*#__PURE__*/React.createElement("g", null, /*#__PURE__*/React.createElement("rect", {
      x: "3",
      y: "5",
      width: "18",
      height: "14",
      rx: "2"
    }), /*#__PURE__*/React.createElement("path", {
      d: "M8 10 L11 12.5 L8 15"
    }), /*#__PURE__*/React.createElement("path", {
      d: "M13 15 H16"
    }))),
    apps: ico(/*#__PURE__*/React.createElement("g", null, /*#__PURE__*/React.createElement("circle", {
      cx: "6.5",
      cy: "6.5",
      r: "2.4"
    }), /*#__PURE__*/React.createElement("circle", {
      cx: "17.5",
      cy: "6.5",
      r: "2.4"
    }), /*#__PURE__*/React.createElement("circle", {
      cx: "6.5",
      cy: "17.5",
      r: "2.4"
    }), /*#__PURE__*/React.createElement("circle", {
      cx: "17.5",
      cy: "17.5",
      r: "2.4"
    }))),
    sessions: ico(/*#__PURE__*/React.createElement("g", null, /*#__PURE__*/React.createElement("rect", {
      x: "3",
      y: "4",
      width: "18",
      height: "16",
      rx: "2"
    }), /*#__PURE__*/React.createElement("path", {
      d: "M3 9 H21"
    }), /*#__PURE__*/React.createElement("path", {
      d: "M7 14 L9.5 16.5"
    }))),
    chevR: ico(/*#__PURE__*/React.createElement("path", {
      d: "M9 6 L15 12 L9 18"
    }), 2),
    chevD: ico(/*#__PURE__*/React.createElement("path", {
      d: "M6 9 L12 15 L18 9"
    }), 2.2),
    gear: ico(/*#__PURE__*/React.createElement("g", null, /*#__PURE__*/React.createElement("circle", {
      cx: "12",
      cy: "12",
      r: "3.2"
    }), /*#__PURE__*/React.createElement("path", {
      d: "M12 2 V5 M12 19 V22 M2 12 H5 M19 12 H22 M5 5 L7 7 M17 17 L19 19 M19 5 L17 7 M7 17 L5 19"
    }))),
    sidebar: ico(/*#__PURE__*/React.createElement("g", null, /*#__PURE__*/React.createElement("rect", {
      x: "3",
      y: "4",
      width: "18",
      height: "16",
      rx: "2"
    }), /*#__PURE__*/React.createElement("path", {
      d: "M9 4 V20"
    }))),
    send: ico(/*#__PURE__*/React.createElement("path", {
      d: "M12 19 V5 M6 11 L12 5 L18 11"
    }), 2),
    target: ico(/*#__PURE__*/React.createElement("g", null, /*#__PURE__*/React.createElement("circle", {
      cx: "12",
      cy: "12",
      r: "8"
    }), /*#__PURE__*/React.createElement("circle", {
      cx: "12",
      cy: "12",
      r: "3"
    }), /*#__PURE__*/React.createElement("path", {
      d: "M12 1 V4 M12 20 V23 M1 12 H4 M20 12 H23"
    }))),
    bug: ico(/*#__PURE__*/React.createElement("g", null, /*#__PURE__*/React.createElement("rect", {
      x: "8",
      y: "9",
      width: "8",
      height: "10",
      rx: "4"
    }), /*#__PURE__*/React.createElement("path", {
      d: "M12 9 V6 M9 5 L10.5 7 M15 5 L13.5 7 M8 12 H4 M16 12 H20 M8 16 H4.5 M16 16 H19.5 M8 13 L5 11 M16 13 L19 11"
    }))),
    spark: ico(/*#__PURE__*/React.createElement("path", {
      d: "M12 3 L13.4 9 L19 11 L13.4 13 L12 19 L10.6 13 L5 11 L10.6 9 Z"
    }), 1.4)
  };
  function useClock(period) {
    const [t, setT] = React.useState(0);
    React.useEffect(() => {
      const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
      if (reduce) {
        setT(0.5);
        return;
      }
      let raf,
        start = null;
      const tick = ts => {
        if (start == null) start = ts;
        setT((ts - start) % period / period);
        raf = requestAnimationFrame(tick);
      };
      raf = requestAnimationFrame(tick);
      return () => cancelAnimationFrame(raf);
    }, []);
    return t;
  }
  function NavItem({
    icon,
    label,
    active,
    accent,
    badge,
    faint
  }) {
    return /*#__PURE__*/React.createElement("div", {
      style: {
        display: "flex",
        alignItems: "center",
        gap: 11,
        padding: "8px 11px",
        borderRadius: 8,
        background: active ? "rgba(255,255,255,0.07)" : "transparent",
        cursor: "pointer"
      }
    }, badge ? /*#__PURE__*/React.createElement("span", {
      style: {
        width: 21,
        height: 21,
        borderRadius: 6,
        flex: "none",
        background: badge,
        display: "grid",
        placeItems: "center",
        fontFamily: "var(--font-sans)",
        fontSize: 11,
        fontWeight: 700,
        color: "#fff"
      }
    }, label[0]) : /*#__PURE__*/React.createElement("span", {
      style: {
        color: active ? "#fff" : "rgba(255,255,255,0.55)",
        display: "grid",
        placeItems: "center",
        flex: "none"
      }
    }, icon), /*#__PURE__*/React.createElement("span", {
      style: {
        fontFamily: "var(--font-sans)",
        fontSize: 13.5,
        color: faint ? "rgba(255,255,255,0.4)" : active || accent ? "#fff" : "rgba(255,255,255,0.7)",
        fontWeight: accent ? 600 : 400
      }
    }, label));
  }

  // ---- shared command-center body (no outer frame) ----
  function AppBody({
    t,
    compact
  }) {
    const phrase = "Audit our dependencies and open PRs for every CVE";
    const typeStart = 0.08,
      typeEnd = 0.4,
      holdEnd = 0.82;
    let typed = "";
    if (t >= typeStart && t < typeEnd) typed = phrase.slice(0, Math.round((t - typeStart) / (typeEnd - typeStart) * phrase.length));else if (t >= typeEnd && t < holdEnd) typed = phrase;
    const hasText = typed.length > 0;
    const caretOn = Math.sin(t * Math.PI * 2 * 6) > 0;
    return /*#__PURE__*/React.createElement("div", {
      style: {
        display: "flex",
        height: compact ? 540 : 600,
        background: "#0c0c0f"
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        width: 248,
        flex: "none",
        borderRight: "1px solid rgba(255,255,255,0.07)",
        display: "flex",
        flexDirection: "column",
        padding: "14px 12px"
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        padding: "2px 6px 14px"
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        color: "rgba(255,255,255,0.85)"
      }
    }, /*#__PURE__*/React.createElement(AppLogo, {
      size: 18
    })), /*#__PURE__*/React.createElement("span", {
      style: {
        color: "rgba(255,255,255,0.4)"
      }
    }, I.sidebar)), /*#__PURE__*/React.createElement("div", {
      style: {
        display: "flex",
        alignItems: "center",
        gap: 10,
        padding: "9px 11px",
        borderRadius: 9,
        border: "1px solid rgba(255,255,255,0.12)",
        background: "rgba(255,255,255,0.03)",
        cursor: "pointer",
        marginBottom: 10
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        color: "rgba(255,255,255,0.8)"
      }
    }, I.plus), /*#__PURE__*/React.createElement("span", {
      style: {
        fontFamily: "var(--font-sans)",
        fontSize: 13.5,
        color: "rgba(255,255,255,0.92)"
      }
    }, "New Session"), /*#__PURE__*/React.createElement("span", {
      style: {
        marginLeft: "auto",
        display: "flex",
        gap: 4
      }
    }, ["Ctrl", "O"].map(k => /*#__PURE__*/React.createElement("span", {
      key: k,
      style: {
        fontFamily: "var(--font-mono)",
        fontSize: 10,
        color: "rgba(255,255,255,0.4)",
        background: "rgba(255,255,255,0.06)",
        borderRadius: 4,
        padding: "2px 5px"
      }
    }, k)))), /*#__PURE__*/React.createElement("div", {
      style: {
        display: "flex",
        flexDirection: "column",
        gap: 2
      }
    }, /*#__PURE__*/React.createElement(NavItem, {
      icon: I.home,
      label: "Home",
      active: true
    }), /*#__PURE__*/React.createElement(NavItem, {
      icon: I.projects,
      label: "Projects"
    }), /*#__PURE__*/React.createElement(NavItem, {
      icon: I.auto,
      label: "Automations"
    }), /*#__PURE__*/React.createElement(NavItem, {
      icon: I.apps,
      label: "Applications"
    })), /*#__PURE__*/React.createElement("div", {
      style: {
        height: 1,
        background: "rgba(255,255,255,0.07)",
        margin: "14px 6px"
      }
    }), /*#__PURE__*/React.createElement("div", {
      style: {
        padding: "2px 11px 8px",
        display: "flex",
        alignItems: "center",
        gap: 9
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        color: "rgba(255,255,255,0.4)"
      }
    }, I.apps), /*#__PURE__*/React.createElement("span", {
      style: {
        fontFamily: "var(--font-sans)",
        fontSize: 12,
        color: "rgba(255,255,255,0.4)"
      }
    }, "Applications")), /*#__PURE__*/React.createElement(NavItem, {
      label: "Resource Management",
      badge: "#14a085",
      accent: true
    }), /*#__PURE__*/React.createElement("div", {
      style: {
        display: "flex",
        alignItems: "center",
        gap: 9,
        padding: "12px 11px 8px"
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        color: "rgba(255,255,255,0.4)"
      }
    }, I.sessions), /*#__PURE__*/React.createElement("span", {
      style: {
        fontFamily: "var(--font-sans)",
        fontSize: 12,
        color: "rgba(255,255,255,0.4)"
      }
    }, "Sessions"), /*#__PURE__*/React.createElement("span", {
      style: {
        marginLeft: "auto",
        display: "flex",
        alignItems: "center",
        gap: 8
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        fontFamily: "var(--font-sans)",
        fontSize: 11.5,
        color: "rgba(255,255,255,0.35)"
      }
    }, "Project"), /*#__PURE__*/React.createElement("span", {
      style: {
        color: "rgba(255,255,255,0.35)",
        display: "flex"
      }
    }, /*#__PURE__*/React.createElement("svg", {
      width: "13",
      height: "13",
      viewBox: "0 0 24 24",
      fill: "none",
      stroke: "currentColor",
      strokeWidth: "1.8",
      strokeLinecap: "round",
      strokeLinejoin: "round"
    }, /*#__PURE__*/React.createElement("path", {
      d: "M7 4 V20 M7 4 L4.5 6.5 M7 4 L9.5 6.5 M17 20 V4 M17 20 L14.5 17.5 M17 20 L19.5 17.5"
    }))))), ["lol", "From scratch"].map(label => /*#__PURE__*/React.createElement("div", {
      key: label,
      style: {
        display: "flex",
        alignItems: "center",
        gap: 8,
        padding: "7px 11px",
        cursor: "pointer"
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        color: "rgba(255,255,255,0.4)"
      }
    }, I.chevR), /*#__PURE__*/React.createElement("span", {
      style: {
        fontFamily: "var(--font-sans)",
        fontSize: 13,
        color: "rgba(255,255,255,0.6)"
      }
    }, label))), /*#__PURE__*/React.createElement("div", {
      style: {
        marginTop: "auto",
        display: "flex",
        flexDirection: "column",
        gap: 4
      }
    }, /*#__PURE__*/React.createElement(NavItem, {
      icon: I.gear,
      label: "Organization settings"
    }), /*#__PURE__*/React.createElement("div", {
      style: {
        display: "flex",
        alignItems: "center",
        gap: 10,
        padding: "9px 8px",
        borderRadius: 9,
        marginTop: 4
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        width: 28,
        height: 28,
        borderRadius: 8,
        flex: "none",
        background: "#7c5cff",
        display: "grid",
        placeItems: "center",
        fontFamily: "var(--font-sans)",
        fontSize: 13,
        fontWeight: 700,
        color: "#fff"
      }
    }, "J"), /*#__PURE__*/React.createElement("div", {
      style: {
        minWidth: 0
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        fontFamily: "var(--font-sans)",
        fontSize: 12.5,
        color: "rgba(255,255,255,0.9)",
        whiteSpace: "nowrap",
        overflow: "hidden",
        textOverflow: "ellipsis"
      }
    }, "John Doe's Workspace"), /*#__PURE__*/React.createElement("div", {
      style: {
        fontFamily: "var(--font-sans)",
        fontSize: 11.5,
        color: "rgba(255,255,255,0.45)"
      }
    }, "John Doe")), /*#__PURE__*/React.createElement("span", {
      style: {
        marginLeft: "auto",
        color: "rgba(255,255,255,0.35)"
      }
    }, /*#__PURE__*/React.createElement("svg", {
      width: "13",
      height: "13",
      viewBox: "0 0 24 24",
      fill: "none",
      stroke: "currentColor",
      strokeWidth: "2",
      strokeLinecap: "round",
      strokeLinejoin: "round"
    }, /*#__PURE__*/React.createElement("path", {
      d: "M8 9 L12 5 L16 9 M8 15 L12 19 L16 15"
    })))))), /*#__PURE__*/React.createElement("div", {
      style: {
        flex: 1,
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        padding: "58px 52px 0",
        overflow: "hidden"
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        color: "rgba(255,255,255,0.7)",
        marginBottom: 20
      }
    }, /*#__PURE__*/React.createElement(AppLogo, {
      size: 26
    })), /*#__PURE__*/React.createElement("h2", {
      style: {
        fontFamily: "var(--font-sans)",
        fontSize: "1.9rem",
        fontWeight: 400,
        letterSpacing: "-0.02em",
        color: "#fff",
        margin: 0,
        textAlign: "center"
      }
    }, "What do you want to get done today?"), /*#__PURE__*/React.createElement("div", {
      style: {
        width: "100%",
        maxWidth: 560,
        marginTop: 34,
        background: "#161619",
        border: "1px solid rgba(255,255,255,0.1)",
        borderRadius: 14,
        padding: "16px 16px 12px",
        boxShadow: "0 12px 32px rgba(0,0,0,0.35)"
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        minHeight: 54,
        fontFamily: "var(--font-sans)",
        fontSize: 14.5,
        color: hasText ? "rgba(255,255,255,0.92)" : "rgba(255,255,255,0.4)",
        lineHeight: 1.5
      }
    }, hasText ? typed : "Describe your task or type / for commands", hasText && /*#__PURE__*/React.createElement("span", {
      style: {
        opacity: caretOn ? 0.8 : 0,
        color: ACC
      }
    }, "\u258D")), /*#__PURE__*/React.createElement("div", {
      style: {
        display: "flex",
        alignItems: "center",
        gap: 8,
        marginTop: 8
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        display: "inline-flex",
        alignItems: "center",
        gap: 7,
        padding: "7px 11px",
        borderRadius: 8,
        border: "1px solid rgba(255,255,255,0.12)",
        fontFamily: "var(--font-sans)",
        fontSize: 12.5,
        color: "rgba(255,255,255,0.7)",
        cursor: "pointer"
      }
    }, I.target, "Work in a project ", I.chevD), /*#__PURE__*/React.createElement("span", {
      style: {
        marginLeft: "auto",
        display: "flex",
        alignItems: "center",
        gap: 8
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        color: "rgba(255,255,255,0.5)"
      }
    }, I.plus), /*#__PURE__*/React.createElement("span", {
      style: {
        display: "inline-flex",
        alignItems: "center",
        gap: 6,
        padding: "7px 10px",
        borderRadius: 8,
        border: "1px solid rgba(255,255,255,0.12)",
        fontFamily: "var(--font-sans)",
        fontSize: 12.5,
        color: "rgba(255,255,255,0.7)",
        cursor: "pointer"
      }
    }, /*#__PURE__*/React.createElement(AppLogo, {
      size: 13
    }), "5.5 Medium ", I.chevD), /*#__PURE__*/React.createElement("span", {
      style: {
        width: 34,
        height: 34,
        borderRadius: 9,
        display: "grid",
        placeItems: "center",
        background: hasText ? ACC : "rgba(255,255,255,0.1)",
        color: hasText ? "#fff" : "rgba(255,255,255,0.5)",
        transition: "background 0.3s"
      }
    }, I.send)))), /*#__PURE__*/React.createElement("div", {
      style: {
        display: "flex",
        gap: 12,
        marginTop: 28,
        flexWrap: "wrap",
        justifyContent: "center"
      }
    }, [["Automate env setup", null], ["Fix a bug", "#ff6b6b"], ["Boost your test coverage", "#a98bff"]].map(([label, col]) => /*#__PURE__*/React.createElement("span", {
      key: label,
      style: {
        display: "inline-flex",
        alignItems: "center",
        gap: 8,
        padding: "10px 16px",
        borderRadius: 999,
        background: "rgba(255,255,255,0.04)",
        border: "1px solid rgba(255,255,255,0.09)",
        fontFamily: "var(--font-sans)",
        fontSize: 13,
        color: "rgba(255,255,255,0.85)",
        cursor: "pointer"
      }
    }, col ? /*#__PURE__*/React.createElement("span", {
      style: {
        color: col,
        display: "flex"
      }
    }, label === "Fix a bug" ? I.bug : I.spark) : null, label))), /*#__PURE__*/React.createElement("div", {
      style: {
        width: "100%",
        maxWidth: 560,
        marginTop: 40
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        fontFamily: "var(--font-sans)",
        fontSize: 13.5,
        color: "rgba(255,255,255,0.45)",
        marginBottom: 12
      }
    }, "Recent Sessions"), [["Design Post-Quantum Computing Website", "5d ago"], ["Write Parent Harness Evidence Boundary Doc", "1w ago"]].map(([title, ago]) => /*#__PURE__*/React.createElement("div", {
      key: title,
      style: {
        display: "flex",
        alignItems: "flex-start",
        gap: 12,
        padding: "9px 0"
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        width: 4,
        height: 4,
        borderRadius: "50%",
        background: "rgba(255,255,255,0.35)",
        marginTop: 7,
        flex: "none"
      }
    }), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
      style: {
        fontFamily: "var(--font-sans)",
        fontSize: 14,
        color: "rgba(255,255,255,0.88)"
      }
    }, title), /*#__PURE__*/React.createElement("div", {
      style: {
        fontFamily: "var(--font-sans)",
        fontSize: 12,
        color: "rgba(255,255,255,0.4)",
        marginTop: 2
      }
    }, ago)))))));
  }

  // ---- CLI / headless terminal view ----
  function CliView({
    t
  }) {
    const caretOn = Math.sin(t * Math.PI * 2 * 6) > 0;
    const lines = [{
      at: 0.04,
      c: "cmd",
      s: "hv session start --scope=fs.read,shell.exec,net.none"
    }, {
      at: 0.13,
      c: "ok",
      s: "session 9f2c1 ready · scoped credentials issued"
    }, {
      at: 0.22,
      c: "cmd",
      s: "hv run \"audit deps and open PRs for every CVE\""
    }, {
      at: 0.31,
      c: "log",
      s: "scanning 210 repositories…"
    }, {
      at: 0.41,
      c: "log",
      s: "billing-api    libfoo 1.4.2 → 1.4.7   tests ✓"
    }, {
      at: 0.50,
      c: "block",
      s: "BLOCKED net.outbound → registry.evil.sh (net.none)"
    }, {
      at: 0.59,
      c: "log",
      s: "web-dashboard  lodash 4.17.19 → 4.17.21 tests ✓"
    }, {
      at: 0.68,
      c: "log",
      s: "auth-service   openssl bump          tests ✓"
    }, {
      at: 0.78,
      c: "ok",
      s: "187 PRs opened · 1 action blocked · receipts signed"
    }, {
      at: 0.88,
      c: "cmd",
      s: "hv session end 9f2c1"
    }];
    const shown = lines.filter(l => t >= l.at);
    const col = {
      cmd: "rgba(255,255,255,0.92)",
      ok: ACC,
      log: "rgba(255,255,255,0.58)",
      block: "#ff6b6b"
    };
    return /*#__PURE__*/React.createElement("div", {
      style: {
        height: 600,
        background: "#0c0c0f",
        display: "flex",
        flexDirection: "column"
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        display: "flex",
        alignItems: "center",
        gap: 18,
        padding: "0 18px",
        height: 40,
        borderBottom: "1px solid rgba(255,255,255,0.07)"
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        fontFamily: "var(--font-mono)",
        fontSize: 11.5,
        color: "rgba(255,255,255,0.55)"
      }
    }, "hypervisor \u2014 headless \xB7 CI runner"), /*#__PURE__*/React.createElement("span", {
      style: {
        marginLeft: "auto",
        display: "flex",
        alignItems: "center",
        gap: 6,
        fontFamily: "var(--font-mono)",
        fontSize: 10.5,
        color: ACC
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        width: 6,
        height: 6,
        borderRadius: "50%",
        background: ACC
      }
    }), "governed")), /*#__PURE__*/React.createElement("div", {
      style: {
        flex: 1,
        padding: "22px 26px",
        fontFamily: "var(--font-mono)",
        fontSize: 13,
        lineHeight: 2.05,
        overflow: "hidden"
      }
    }, shown.map((l, i) => /*#__PURE__*/React.createElement("div", {
      key: i,
      style: {
        display: "flex",
        gap: 11,
        color: col[l.c]
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        flex: "none",
        width: 12,
        color: l.c === "block" ? "#ff6b6b" : l.c === "ok" ? ACC : l.c === "cmd" ? "rgba(255,255,255,0.35)" : "rgba(255,255,255,0.18)"
      }
    }, l.c === "block" ? "✕" : l.c === "ok" ? "✓" : l.c === "cmd" ? "$" : "·"), /*#__PURE__*/React.createElement("span", {
      style: {
        whiteSpace: "pre-wrap"
      }
    }, l.s))), shown.length < lines.length && /*#__PURE__*/React.createElement("span", {
      style: {
        display: "inline-block",
        width: 8,
        height: 16,
        background: "rgba(255,255,255,0.6)",
        opacity: caretOn ? 0.75 : 0,
        marginLeft: 23
      }
    })));
  }

  // ---- surface switcher (App / Web / CLI) ----
  const SURFACES = [["Hypervisor App", "app", "Desktop command center"], ["Web", "web", "Browser & team client"], ["CLI / Headless", "cli", "Terminal, scripting & CI"]];
  function SurfaceFrame({
    kind,
    t
  }) {
    if (kind === "cli") {
      return /*#__PURE__*/React.createElement("div", {
        style: {
          background: "#0c0c0f",
          borderRadius: 13,
          overflow: "hidden",
          boxShadow: "0 40px 90px rgba(0,0,0,0.42), 0 0 0 1px rgba(0,0,0,0.05)"
        }
      }, /*#__PURE__*/React.createElement("div", {
        style: {
          display: "flex",
          alignItems: "center",
          gap: 7,
          padding: "12px 15px",
          background: "#161a17",
          borderBottom: "1px solid rgba(255,255,255,0.06)"
        }
      }, ["#ff5f57", "#ffbd2e", "#28c840"].map((c, i) => /*#__PURE__*/React.createElement("span", {
        key: i,
        style: {
          width: 11,
          height: 11,
          borderRadius: "50%",
          background: c
        }
      })), /*#__PURE__*/React.createElement("span", {
        style: {
          margin: "0 auto",
          fontFamily: "var(--font-mono)",
          fontSize: 12,
          color: "rgba(255,255,255,0.3)"
        }
      }, "zsh \u2014 hv")), /*#__PURE__*/React.createElement(CliView, {
        t: t
      }));
    }
    if (kind === "web") {
      return /*#__PURE__*/React.createElement("div", {
        style: {
          background: "#0c0c0f",
          borderRadius: 13,
          overflow: "hidden",
          boxShadow: "0 40px 90px rgba(0,0,0,0.42), 0 0 0 1px rgba(0,0,0,0.05)"
        }
      }, /*#__PURE__*/React.createElement("div", {
        style: {
          display: "flex",
          alignItems: "center",
          gap: 8,
          padding: "11px 14px",
          background: "#17171c",
          borderBottom: "1px solid rgba(255,255,255,0.06)"
        }
      }, ["#ff5f57", "#ffbd2e", "#28c840"].map((c, i) => /*#__PURE__*/React.createElement("span", {
        key: i,
        style: {
          width: 11,
          height: 11,
          borderRadius: "50%",
          background: c
        }
      })), /*#__PURE__*/React.createElement("div", {
        style: {
          display: "flex",
          alignItems: "center",
          gap: 7,
          marginLeft: 10,
          background: "#0c0c0f",
          borderRadius: 7,
          padding: "5px 14px",
          border: "1px solid rgba(255,255,255,0.07)",
          flex: 1,
          maxWidth: 360
        }
      }, /*#__PURE__*/React.createElement("span", {
        style: {
          color: ACC,
          display: "flex"
        }
      }, /*#__PURE__*/React.createElement(AppLogo, {
        size: 12
      })), /*#__PURE__*/React.createElement("span", {
        style: {
          fontFamily: "var(--font-mono)",
          fontSize: 11.5,
          color: "rgba(255,255,255,0.5)"
        }
      }, "app.hypervisor.io")), /*#__PURE__*/React.createElement("span", {
        style: {
          marginLeft: "auto",
          display: "flex",
          gap: 5
        }
      }, [0, 1, 2].map(i => /*#__PURE__*/React.createElement("span", {
        key: i,
        style: {
          width: 5,
          height: 5,
          borderRadius: "50%",
          background: "rgba(255,255,255,0.25)"
        }
      })))), /*#__PURE__*/React.createElement(AppBody, {
        t: t,
        compact: true
      }));
    }
    // app — desktop window
    return /*#__PURE__*/React.createElement("div", {
      style: {
        background: "#0c0c0f",
        borderRadius: 13,
        overflow: "hidden",
        boxShadow: "0 40px 90px rgba(0,0,0,0.42), 0 0 0 1px rgba(0,0,0,0.05)"
      }
    }, /*#__PURE__*/React.createElement(AppBody, {
      t: t
    }));
  }
  function PlatformSurfaces() {
    const [active, setActive] = React.useState("app");
    const t = useClock(11000);
    return /*#__PURE__*/React.createElement("div", {
      style: {
        width: "100%",
        maxWidth: 1080,
        margin: "0 auto",
        position: "relative"
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        position: "absolute",
        inset: "-22px -22px -34px",
        borderRadius: 26,
        background: "radial-gradient(120% 120% at 50% 0%, color-mix(in srgb, var(--color-pistachio-green) 34%, var(--color-white)), var(--color-porcelain-grey))",
        zIndex: 0
      }
    }), /*#__PURE__*/React.createElement("div", {
      style: {
        position: "relative",
        zIndex: 1
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        display: "flex",
        justifyContent: "center",
        marginBottom: 22
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        display: "inline-flex",
        gap: 3,
        padding: 4,
        borderRadius: 12,
        background: "var(--color-white)",
        border: "0.5px solid var(--color-grey-500)",
        boxShadow: "var(--shadow-xs)"
      }
    }, SURFACES.map(([label, key, sub]) => {
      const on = active === key;
      return /*#__PURE__*/React.createElement("button", {
        key: key,
        onClick: () => setActive(key),
        title: sub,
        style: {
          display: "flex",
          flexDirection: "column",
          alignItems: "flex-start",
          gap: 1,
          padding: "8px 16px",
          borderRadius: 9,
          border: "none",
          cursor: "pointer",
          background: on ? "var(--color-onyx-black)" : "transparent",
          transition: "background 0.2s"
        }
      }, /*#__PURE__*/React.createElement("span", {
        style: {
          fontFamily: "var(--font-sans)",
          fontSize: 13.5,
          fontWeight: 500,
          color: on ? "#fff" : "var(--color-grey-900)"
        }
      }, label), /*#__PURE__*/React.createElement("span", {
        style: {
          fontFamily: "var(--font-sans)",
          fontSize: 11,
          color: on ? "rgba(255,255,255,0.55)" : "var(--color-grey-600)"
        }
      }, sub));
    }))), /*#__PURE__*/React.createElement(SurfaceFrame, {
      kind: active,
      t: t
    })));
  }
  window.PlatformSurfaces = PlatformSurfaces;
  window.PlatformAppMockup = PlatformSurfaces; // back-comat
})();
})(); } catch (e) { __ds_ns.__errors.push({ path: "site/PlatformApp.jsx", error: String((e && e.message) || e) }); }

// site/Pricing.jsx
try { (() => {
// hypervisor.com — Pricing page.
const PrNS = window.IoiDesignSystem;
const {
  Button: PrButton,
  Badge: PrBadge,
  TextLink: PrLink,
  Eyebrow: PrEyebrow
} = PrNS;
const prwrap = {
  maxWidth: "75rem",
  margin: "0 auto",
  padding: "0 2.5rem"
};
const CHECK = /*#__PURE__*/React.createElement("svg", {
  width: "16",
  height: "16",
  viewBox: "0 0 16 16",
  fill: "none",
  style: {
    flexShrink: 0,
    marginTop: 3
  }
}, /*#__PURE__*/React.createElement("path", {
  d: "M3 8.5l3.2 3.2L13 5",
  stroke: "var(--color-link-green)",
  strokeWidth: "1.5",
  strokeLinecap: "round",
  strokeLinejoin: "round"
}));
const TIERS = [{
  name: "Core",
  price: "$20",
  unit: "/ month",
  blurb: "For individuals running governed sessions on their own machines.",
  cta: "Get started",
  theme: "outline",
  feat: ["Local Hypervisor Daemon", "Background & ambient workers", "Bring your own models & keys", "Receipts & deterministic replay", "Community support"]
}, {
  name: "Team",
  price: "$80",
  unit: "/ seat · month",
  blurb: "For teams standardizing autonomous work with shared authority.",
  featured: true,
  cta: "Start free trial",
  theme: "fill",
  feat: ["Everything in Core", "Shared projects & automations", "wallet.network authority scopes", "Org policies & approvals", "SSO / SCIM", "Priority support"]
}, {
  name: "Enterprise",
  price: "Custom",
  unit: "",
  blurb: "For organizations running fleets under governance and settlement.",
  cta: "Talk to sales",
  theme: "outline",
  feat: ["Everything in Team", "Deploy in your VPC or cTEE", "HypervisorOS bare-metal nodes", "Audit trails & no-plaintext custody", "IOI L1 settlement", "Dedicated SLA & solutions"]
}];
const FAQ = [["What am I billed for?", "Usage — runtime time and authorized actions. Pricing scales with the autonomous work you run, not seats alone."], ["Can I bring my own models and infrastructure?", "Yes. Mount any model as a cognition backend and run on your own cloud, VPC, cTEE, or DePIN compute. No vendor lock on runtime truth."], ["What happens to my data?", "Operational truth lives in Agentgres under your control; cTEE private workspaces keep protected data out of provider memory. Credentials are brokered, never handed to workers."], ["Do receipts cost extra?", "No. Every consequential action is receipted and replayable by default — accountability is part of the runtime, not an add-on."]];
function HvPage() {
  return /*#__PURE__*/React.createElement("main", null, /*#__PURE__*/React.createElement("section", {
    style: {
      ...prwrap,
      paddingTop: "4rem",
      textAlign: "center",
      display: "flex",
      flexDirection: "column",
      alignItems: "center"
    }
  }, /*#__PURE__*/React.createElement(PrEyebrow, {
    color: "var(--color-link-green)"
  }, "Pricing"), /*#__PURE__*/React.createElement("h1", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "3.5rem",
      lineHeight: 1.05,
      letterSpacing: "-0.02em",
      margin: "1.25rem 0 0",
      maxWidth: "18ch",
      color: "var(--color-onyx-black)"
    }
  }, "Priced to scale with your autonomous work"), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.1875rem",
      color: "var(--color-grey-800)",
      marginTop: "1.25rem",
      maxWidth: "46ch",
      lineHeight: 1.5
    }
  }, "Start in minutes on your own machine. Move to your VPC, cTEE, or settlement when you're ready to run fleets.")), /*#__PURE__*/React.createElement("section", {
    style: {
      ...prwrap,
      paddingTop: "3.5rem"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "repeat(3, 1fr)",
      gap: "1.25rem",
      alignItems: "start"
    }
  }, TIERS.map(t => /*#__PURE__*/React.createElement("div", {
    key: t.name,
    style: {
      borderRadius: "var(--radius-card)",
      padding: "2.25rem",
      border: t.featured ? "1px solid var(--color-onyx-black)" : "0.5px solid var(--color-grey-500)",
      background: t.featured ? "var(--color-onyx-black)" : "var(--color-white)",
      color: t.featured ? "var(--color-white)" : "var(--color-onyx-black)"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 10
    }
  }, /*#__PURE__*/React.createElement("h2", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.25rem",
      margin: 0
    }
  }, t.name), t.featured && /*#__PURE__*/React.createElement(PrBadge, {
    tone: "green"
  }, "Most popular")), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "baseline",
      gap: 8,
      marginTop: "1.5rem"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "3rem",
      lineHeight: 1,
      letterSpacing: "-0.02em"
    }
  }, t.price), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "0.9375rem",
      color: t.featured ? "var(--color-grey-600)" : "var(--color-grey-700)"
    }
  }, t.unit)), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "0.9375rem",
      color: t.featured ? "var(--color-grey-600)" : "var(--color-grey-800)",
      marginTop: "1rem",
      lineHeight: 1.4,
      minHeight: 40
    }
  }, t.blurb), /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: "1.5rem"
    }
  }, /*#__PURE__*/React.createElement(PrButton, {
    variant: t.theme,
    theme: t.featured ? "white" : "onyx",
    style: {
      width: "100%"
    }
  }, t.cta)), /*#__PURE__*/React.createElement("ul", {
    style: {
      listStyle: "none",
      margin: "1.75rem 0 0",
      padding: "1.75rem 0 0",
      borderTop: t.featured ? "1px solid rgba(255,255,255,0.12)" : "0.5px solid var(--color-grey-500)",
      display: "flex",
      flexDirection: "column",
      gap: "0.75rem"
    }
  }, t.feat.map(f => /*#__PURE__*/React.createElement("li", {
    key: f,
    style: {
      display: "flex",
      gap: 10,
      fontFamily: "var(--font-sans)",
      fontSize: "0.875rem"
    }
  }, CHECK, /*#__PURE__*/React.createElement("span", {
    style: {
      color: t.featured ? "rgba(255,255,255,0.9)" : "var(--color-onyx-black)"
    }
  }, f)))))))), /*#__PURE__*/React.createElement("section", {
    style: {
      ...prwrap,
      paddingTop: "6rem"
    }
  }, /*#__PURE__*/React.createElement("h2", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "2.25rem",
      letterSpacing: "-0.02em",
      margin: "0 0 2rem",
      textAlign: "center"
    }
  }, "Questions"), /*#__PURE__*/React.createElement("div", {
    style: {
      maxWidth: "48rem",
      margin: "0 auto",
      display: "flex",
      flexDirection: "column"
    }
  }, FAQ.map(([q, a]) => /*#__PURE__*/React.createElement("div", {
    key: q,
    style: {
      padding: "1.5rem 0",
      borderTop: "0.5px solid var(--color-grey-500)"
    }
  }, /*#__PURE__*/React.createElement("h3", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.0625rem",
      margin: 0
    }
  }, q), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "0.9375rem",
      color: "var(--color-grey-800)",
      marginTop: "0.625rem",
      lineHeight: 1.5
    }
  }, a))))), /*#__PURE__*/React.createElement("section", {
    style: {
      ...prwrap,
      paddingTop: "7rem",
      textAlign: "center"
    }
  }, /*#__PURE__*/React.createElement("h2", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "3rem",
      letterSpacing: "-0.02em",
      margin: 0
    }
  }, "Start free today"), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      gap: "0.5rem",
      justifyContent: "center",
      marginTop: "1.75rem"
    }
  }, /*#__PURE__*/React.createElement(PrButton, {
    iconRight: /*#__PURE__*/React.createElement("span", null, "\u2192")
  }, "Get started"), /*#__PURE__*/React.createElement(PrButton, {
    variant: "outline"
  }, "Talk to sales"))));
}
window.HvPage = HvPage;
})(); } catch (e) { __ds_ns.__errors.push({ path: "site/Pricing.jsx", error: String((e && e.message) || e) }); }

// site/ProductData.jsx
try { (() => {
// hypervisor.com — platform product catalog.
// One record per Platform product; consumed by ProductPage.jsx to render each subpage.
window.HV_PRODUCTS = [{
  slug: "app",
  file: "hv-app.html",
  name: "Hypervisor App",
  category: "Client · Desktop command center",
  title: "Operate autonomous work from your machine",
  sub: "Start governed sessions, run automations, and supervise agents across projects, tools, models, and providers — with approvals, receipts, and replay in one local-first workspace.",
  visual: "app",
  capabilities: [["Local-first sessions", "A daemon on your machine holds runtime truth. Work starts where your data already is — no round trip to a vendor cloud to begin."], ["Approvals inline", "Consequential actions surface as requests, not faits accomplis. Approve, scope, or deny without leaving the run."], ["Replay any run", "Every session is a receipted, deterministic record. Scrub back through what happened and re-run it exactly."]],
  detail: {
    eyebrow: "Inside the app",
    heading: "Everything a run needs, in one window",
    sub: "The app is the operator's seat. Projects, tools, models, and providers compose behind a single command bar; authority and history stay visible the whole way.",
    points: [["Command bar", "Describe a task in plain language or type / for commands. Pick the project, model, and scope before a single action runs."], ["Projects & tools", "Group repos, connectors, and credentials into projects. Tools are declared, scoped, and revocable per session."], ["Sessions & history", "Every run lands in a searchable history with its receipts attached — nothing happens off the record."], ["Resource management", "Watch spend, leases, and live sessions across the workspace. Stop or re-scope anything in flight."]]
  },
  specs: [["Platform", "macOS · Linux · Windows"], ["Runtime", "Local daemon, offline-capable"], ["Authority", "Per-session scoped credentials"], ["Record", "Signed receipts · deterministic replay"]],
  related: ["web", "cli", "sdk"]
}, {
  slug: "web",
  file: "hv-web.html",
  name: "Hypervisor Web",
  category: "Client · Browser & teams",
  title: "Bring autonomous work to the whole team",
  sub: "Shared projects, remote sessions, approvals, and run history in the browser — without changing the runtime truth or where work actually executes.",
  visual: "web",
  capabilities: [["Shared projects", "Teams see the same projects, tools, and history. Roles and scopes decide who can start, approve, or merge."], ["Remote sessions", "Kick off a run from a laptop, check it from a phone. The session lives on the substrate, not your tab."], ["Approvals & audit", "Route consequential actions to reviewers. Every decision is attributed and receipted for the audit trail."]],
  detail: {
    eyebrow: "Built for teams",
    heading: "The same truth, accessible anywhere",
    sub: "Web is a client over the same Hypervisor Core the app and CLI use. It adds collaboration and access control — it never becomes a second source of truth.",
    points: [["Org & roles", "Invite members, assign roles, and scope access to projects and tools. Authority is explicit and revocable."], ["Live run view", "Follow sessions in progress, inspect tool calls, and step into the same environment an agent used."], ["Approval queues", "Pending consequential actions collect in a queue. Approve, deny, or re-scope with full context attached."], ["Shared history", "Receipts and lineage are visible to the whole team — proof of what ran, who approved it, and why."]]
  },
  specs: [["Access", "Browser · no install"], ["Collaboration", "Orgs, roles, shared projects"], ["Runtime", "Hosted or your VPC"], ["Audit", "Attributed approvals · signed receipts"]],
  related: ["app", "cli", "mcp"]
}, {
  slug: "cli",
  file: "hv-cli.html",
  name: "Hypervisor CLI",
  category: "Client · Terminal, scripting & CI",
  title: "Script and supervise from the shell",
  sub: "Drive autonomous work from CI, shells, and servers with the same authority, receipts, and replay as the app — headless, scriptable, and pipeline-native.",
  visual: "cli",
  capabilities: [["Headless by design", "No window, no human in the trigger. Start sessions from cron, CI steps, or a server and stream results to logs."], ["Scoped from the flag", "Declare scope at launch — fs.read, shell.exec, net.none. Anything outside the grant is blocked and receipted."], ["Pipeline-native", "Exit codes, JSON output, and signed receipts drop straight into CI gates and downstream automation."]],
  detail: {
    eyebrow: "From the terminal",
    heading: "Autonomy that fits in a pipeline",
    sub: "The CLI carries the full Hypervisor contract into headless environments. Same runtime truth, same authority model, same receipts — just no UI.",
    points: [["Sessions as commands", "hv session start, hv run, hv session end. Each command is scoped, logged, and replayable."], ["Streamed output", "Watch progress line by line, or pipe structured JSON into your own tooling and dashboards."], ["CI gates", "Block a merge on a failed receipt. Promote a build only when every action was in scope and tests passed."], ["Servers & cron", "Run recurring work on your own infrastructure with the same governance as an operator at a desk."]]
  },
  specs: [["Surface", "Terminal · headless · CI"], ["Output", "Streamed logs · structured JSON"], ["Authority", "Scope flags · blocked-by-default"], ["Record", "Signed receipts · exit codes"]],
  related: ["app", "sdk", "automations"]
}, {
  slug: "sdk",
  file: "hv-sdk.html",
  name: "Hypervisor SDK",
  category: "Builder · Protocol library",
  title: "Build on the substrate, not around it",
  sub: "Integrate Hypervisor into products, agents, and internal tools without reimplementing runtime, authority, receipt, or state semantics.",
  visual: "glow",
  capabilities: [["Runtime primitives", "Sessions, tool calls, leases, and receipts as first-class objects. The hard parts are library calls, not your problem."], ["Authority built in", "Scope, broker, and revoke credentials through the SDK. Your code never has to hold a raw key."], ["Typed & portable", "Stable, typed bindings across languages. The protocol contract is the same one the app and CLI speak."]],
  detail: {
    eyebrow: "For developers",
    heading: "The protocol, as a library",
    sub: "The SDK exposes Hypervisor Core directly: everything a client does, your code can do — under the same governance, with none of the reimplementation.",
    points: [["Sessions API", "Open, scope, drive, and close governed sessions programmatically. Stream events as they happen."], ["Tool & lease broker", "Request capabilities at runtime. The broker issues scoped, revocable leases — never standing access."], ["Receipts & state", "Read the canonical record of what ran. Verify receipts and replay accepted operations deterministically."], ["Embeddable", "Drop governed autonomy into an existing product without standing up your own runtime."]]
  },
  specs: [["Form", "Typed protocol bindings"], ["Languages", "TypeScript · Python · Go"], ["Authority", "Brokered leases · revocable"], ["Contract", "Same Core as App · Web · CLI"]],
  related: ["adk", "odk", "cli"]
}, {
  slug: "adk",
  file: "hv-adk.html",
  name: "Hypervisor ADK",
  category: "Builder · Autonomous-system kit",
  title: "Build and ship autonomous systems",
  sub: "Compose workers, harnesses, evals, manifests, and deployment profiles — packaged as governed autonomous-system bundles ready to run anywhere.",
  visual: "glow",
  capabilities: [["Workers & harnesses", "Define a worker's tools, policy, and behavior. Wrap it in a harness that bounds what it can ever do."], ["Evals as a gate", "Benchmark a worker against your own task suite. Promotion is earned by passing evals, not by hand-waving."], ["Deployment profiles", "Ship the same bundle to local, cloud, VPC, or DePIN with a profile — runtime stays consistent, perimeter changes."]],
  detail: {
    eyebrow: "Author the system",
    heading: "From a prompt to a packaged worker",
    sub: "The ADK turns ad-hoc agents into governed, benchmarked, deployable bundles — versioned artifacts you can trust in production.",
    points: [["Manifests", "Declare a worker's identity, tools, models, and policy in one manifest. The bundle is reproducible from it."], ["Harnesses", "Bound execution with a harness: allowed tools, scopes, and stop conditions enforced at runtime."], ["Eval packs", "Attach task suites and graders. Track regressions across versions before anything reaches production."], ["Bundle & deploy", "Package worker, harness, and evals into one artifact. Deploy by profile, govern by the same Core."]]
  },
  specs: [["Form", "Autonomous-system bundles"], ["Includes", "Workers · harnesses · evals · manifests"], ["Deploy", "Local · cloud · VPC · DePIN"], ["Trains with", "Foundry worker training"]],
  related: ["sdk", "odk", "worker-training"]
}, {
  slug: "odk",
  file: "hv-odk.html",
  name: "Hypervisor ODK",
  category: "Builder · Ontology-aware kit",
  title: "Turn domain knowledge into working surfaces",
  sub: "Compile ontologies and data recipes into generated surfaces, domain apps, eval packs, and marketplace-ready ontology packs.",
  visual: "glow",
  capabilities: [["Ontology as source", "Model your domain once — entities, relations, rules. Surfaces and apps generate from that single description."], ["Generated surfaces", "Forms, views, and flows fall out of the ontology. Change the model, regenerate the surface."], ["Marketplace packs", "Bundle an ontology with its evals and recipes into a shareable, versioned pack others can adopt."]],
  detail: {
    eyebrow: "Domain-driven",
    heading: "Knowledge in, software out",
    sub: "The ODK treats a domain ontology as the contract. Surfaces, domain apps, and eval packs are derived from it — not hand-built and left to drift.",
    points: [["Ontology modeling", "Describe entities, relations, and constraints. The model is the canonical source the rest derives from."], ["Data recipes", "Map real data onto the ontology with declarative recipes — ingestion, transforms, and validation as code."], ["Domain apps", "Generate focused apps and surfaces for operators in a domain, governed by the same runtime and authority."], ["Ontology packs", "Publish an ontology, its recipes, and its evals as a versioned pack to the marketplace."]]
  },
  specs: [["Source", "Domain ontology + data recipes"], ["Generates", "Surfaces · domain apps · eval packs"], ["Output", "Marketplace-ready ontology packs"], ["Builds on", "SDK runtime primitives"]],
  related: ["adk", "sdk", "app"]
}, {
  slug: "mcp",
  file: "hv-mcp.html",
  name: "Hypervisor MCP",
  category: "Gateway · Scoped external access",
  title: "Hand external agents a key, never the keyring",
  sub: "Expose selected capabilities to external agents through revocable, auditable MCP profiles — scoped access, every call receipted, never a master key.",
  visual: "light",
  capabilities: [["Scoped profiles", "Publish a narrow slice of capability per consumer. An external agent sees only what its profile allows."], ["Revocable access", "Grants are leases, not keys. Revoke a profile and access stops — no rotation scramble, no orphaned secrets."], ["Every call receipted", "External calls run through the same Core. What an outside agent did is on the record like everything else."]],
  detail: {
    eyebrow: "Outward-facing",
    heading: "A gateway, not a back door",
    sub: "MCP carries Hypervisor capability to agents you don't run — under profiles you control, with the same authority and audit as internal work.",
    points: [["Capability profiles", "Compose exactly which tools and scopes an external consumer receives. Default is nothing."], ["Brokered credentials", "The gateway brokers scoped, time-bound leases. External agents never touch raw secrets."], ["Rate & spend limits", "Bound how much an external consumer can do and spend. Limits are policy, enforced at the gateway."], ["Full audit", "Every external call is attributed and receipted. Revoke, inspect, and replay like any other session."]]
  },
  specs: [["Protocol", "MCP (Model Context Protocol)"], ["Access", "Scoped profiles · revocable leases"], ["Limits", "Rate · spend · capability"], ["Audit", "Attributed · receipted per call"]],
  related: ["sdk", "web", "os"]
}, {
  slug: "os",
  file: "hv-os.html",
  name: "HypervisorOS",
  category: "Substrate · Bare-metal node profile",
  title: "Governed private agent compute",
  sub: "Run agent workloads on measured nodes: tools, model runtimes, containers, and microVMs under kernel-level policy — your hardware, your perimeter.",
  visual: "light",
  capabilities: [["Measured boot", "Nodes attest their state before they join. Workloads run on hardware you can prove hasn't been tampered with."], ["Kernel-level policy", "Authority is enforced below the workload. A blocked syscall is blocked by the OS, not by a hopeful wrapper."], ["microVM isolation", "Each workload gets its own short-lived microVM. No shared state, no cascade, destroyed after use."]],
  detail: {
    eyebrow: "Down to the metal",
    heading: "The substrate, on your own nodes",
    sub: "HypervisorOS is a node profile that turns bare metal into governed agent compute — the same authority and receipts as the cloud, enforced at the kernel.",
    points: [["Node profile", "A measured, attested base image. Bring your own hardware; the profile makes it a trusted Hypervisor node."], ["Workload runtime", "Run tools, model runtimes, containers, and microVMs side by side under one policy plane."], ["Policy plane", "Scopes and leases enforced at the kernel. Consequential syscalls are requests, not grants."], ["Receipts at the edge", "Work runs near your data and stays there. Only commitments that need public trust project outward."]]
  },
  specs: [["Form", "Bare-metal node profile"], ["Isolation", "Containers · microVMs"], ["Trust", "Measured boot · attestation"], ["Policy", "Kernel-level scopes & leases"]],
  related: ["mcp", "embodied", "web"]
}, {
  slug: "embodied",
  file: "hv-embodied.html",
  name: "Embodied Runtime",
  category: "Substrate · Physical autonomy profile",
  title: "Autonomy that touches the physical world",
  sub: "Operate robot fleets, devices, sensors, command queues, and telemetry under safety gates — with operator handoff and the same receipts as software work.",
  visual: "light",
  capabilities: [["Safety gates", "Physical actions pass through hard gates before they execute. Out-of-envelope commands never reach an actuator."], ["Fleet command", "Queue, sequence, and supervise commands across a fleet. Telemetry streams back into the same run history."], ["Operator handoff", "A human can take control at any point. Handoff is explicit, attributed, and receipted like every other action."]],
  detail: {
    eyebrow: "Into the world",
    heading: "Governed autonomy, off the screen",
    sub: "The Embodied Runtime extends Hypervisor's authority model to devices and robots. The same scoping, receipts, and replay — now bounding physical action.",
    points: [["Device & sensor model", "Register devices, sensors, and actuators as governed resources. Capability is declared and scoped."], ["Command queues", "Sequence physical actions with dependencies and gates. Nothing executes outside its safety envelope."], ["Telemetry & replay", "Sensor streams and outcomes are recorded as receipts. Replay a run to see exactly what the fleet did."], ["Safety & handoff", "Hard limits bound every actuator. Operators can pause, override, or take the wheel — all on the record."]]
  },
  specs: [["Targets", "Robots · devices · sensors"], ["Control", "Command queues · safety gates"], ["Telemetry", "Streamed · receipted"], ["Handoff", "Attributed operator override"]],
  related: ["os", "mcp", "app"]
}];

// Cross-references that point at existing Solution pages rather than product subpages.
window.HV_EXT = {
  "automations": {
    name: "Automations & fleets",
    file: "automations-fleets.html"
  },
  "worker-training": {
    name: "Worker training",
    file: "worker-training.html"
  }
};
window.HV_PRODUCT_MAP = {};
window.HV_PRODUCTS.forEach(p => {
  window.HV_PRODUCT_MAP[p.slug] = p;
});
})(); } catch (e) { __ds_ns.__errors.push({ path: "site/ProductData.jsx", error: String((e && e.message) || e) }); }

// site/ProductPage.jsx
try { (() => {
// hypervisor.com — shared Platform product subpage template (install-focused).
// Each subpage sets window.HV_CURRENT_SLUG, loads ProductData.jsx + this, and gets window.HvPage.
(function () {
  const PNS = window.IoiDesignSystem;
  const {
    Button: PgButton,
    TextLink: PgLink,
    Eyebrow: PgEyebrow,
    Logo: PgLogo
  } = PNS;
  const wrap = {
    maxWidth: "75rem",
    margin: "0 auto",
    padding: "0 2.5rem"
  };
  const INK = "var(--color-onyx-black)";
  const HAIR = "var(--color-grey-500)";
  const ACC = "var(--color-link-green)";

  /* ---------- per-product install meta ---------- */
  const INSTALL = {
    app: {
      verb: "Install",
      lines: ["$ brew install --cask hypervisor", "==> Hypervisor.app installed", "$ open -a Hypervisor", "✓ daemon running · workspace ready"]
    },
    web: {
      verb: "Open Hypervisor Web",
      lines: ["> open https://app.hypervisor.io", "✓ signed in · org synced", "· shared projects loaded", "✓ ready — start a session"]
    },
    cli: {
      verb: "Install",
      lines: ["$ curl -fsSL https://get.hypervisor.io | sh", "✓ hv 1.0 installed", "$ hv login", "✓ authenticated · scoped credentials ready"]
    },
    sdk: {
      verb: "Install",
      lines: ["$ npm install @hypervisor/sdk", "added @hypervisor/sdk", "> import { Session } from \"@hypervisor/sdk\"", "✓ runtime primitives ready"]
    },
    adk: {
      verb: "Install",
      lines: ["$ npm install -g @hypervisor/adk", "✓ adk 1.0 installed", "$ hv adk init worker", "✓ manifest · harness · evals scaffolded"]
    },
    odk: {
      verb: "Install",
      lines: ["$ npm install -g @hypervisor/odk", "✓ odk 1.0 installed", "$ hv odk compile ontology.yaml", "✓ surfaces · domain app generated"]
    },
    mcp: {
      verb: "Create a profile",
      lines: ["$ hv mcp profile create reviewer", "✓ profile reviewer · scoped", "$ hv mcp grant --tools=code.read", "✓ revocable lease issued"]
    },
    os: {
      verb: "Provision a node",
      lines: ["$ curl -fsSL https://get.hypervisor.io/os | sh", "✓ measured boot · node attested", "$ hv node join", "✓ governed compute online"]
    },
    embodied: {
      verb: "Install",
      lines: ["$ npm install @hypervisor/embodied", "✓ runtime installed", "$ hv embodied register fleet.yaml", "✓ devices governed · safety gates armed"]
    }
  };

  /* ---------- inverse dot-matrix panel (matches Core band) ---------- */
  /* ---------- faceted panel (interactive, large dark surfaces) ---------- */
  function DotPanel({
    seed = 1
  }) {
    return /*#__PURE__*/React.createElement("div", {
      style: {
        position: "absolute",
        inset: 0,
        WebkitMaskImage: "radial-gradient(135% 110% at 50% 50%, transparent 28%, #000 66%)",
        maskImage: "radial-gradient(135% 110% at 50% 50%, transparent 28%, #000 66%)"
      },
      "aria-hidden": "true"
    }, window.HvDepthField ? /*#__PURE__*/React.createElement(window.HvDepthField, {
      seed: seed
    }) : /*#__PURE__*/React.createElement(window.HvDots, {
      inverse: true,
      interactive: true,
      cover: true,
      cols: 18,
      rows: 11,
      gap: 34,
      seed: seed
    }));
  }

  /* ---------- terminal window ---------- */
  function termLine(str, i) {
    let color = "rgba(255,255,255,0.55)",
      glyph = null;
    if (str.startsWith("$ ")) {
      color = "rgba(255,255,255,0.92)";
      glyph = /*#__PURE__*/React.createElement("span", {
        style: {
          color: "rgba(255,255,255,0.35)"
        }
      }, "$ ");
      str = str.slice(2);
    } else if (str.startsWith("> ")) {
      color = "#6f9bff";
      glyph = /*#__PURE__*/React.createElement("span", {
        style: {
          color: "rgba(255,255,255,0.35)"
        }
      }, "> ");
      str = str.slice(2);
    } else if (str.startsWith("✓")) {
      color = ACC;
    } else if (str.startsWith("✕")) {
      color = "#ff6b6b";
    } else if (str.startsWith("==>")) {
      color = "rgba(255,255,255,0.45)";
    }
    return /*#__PURE__*/React.createElement("div", {
      key: i,
      style: {
        color,
        whiteSpace: "pre-wrap"
      }
    }, glyph, str);
  }
  function Terminal({
    title,
    lines,
    accent
  }) {
    return /*#__PURE__*/React.createElement("div", {
      style: {
        background: "#0c0c0f",
        borderRadius: 13,
        overflow: "hidden",
        border: "1px solid rgba(255,255,255,0.1)",
        boxShadow: "0 40px 90px rgba(0,0,0,0.5)"
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        display: "flex",
        alignItems: "center",
        gap: 7,
        padding: "12px 15px",
        borderBottom: "1px solid rgba(255,255,255,0.07)"
      }
    }, ["#ff5f57", "#ffbd2e", "#28c840"].map((c, i) => /*#__PURE__*/React.createElement("span", {
      key: i,
      style: {
        width: 11,
        height: 11,
        borderRadius: "50%",
        background: c
      }
    })), /*#__PURE__*/React.createElement("span", {
      style: {
        margin: "0 auto",
        fontFamily: "var(--font-mono)",
        fontSize: 12,
        color: "rgba(255,255,255,0.32)"
      }
    }, title)), /*#__PURE__*/React.createElement("div", {
      style: {
        padding: "20px 24px",
        fontFamily: "var(--font-mono)",
        fontSize: 13,
        lineHeight: 2.05
      }
    }, lines.map((l, i) => termLine(l, i)), accent && /*#__PURE__*/React.createElement("span", {
      style: {
        display: "inline-block",
        width: 8,
        height: 15,
        background: ACC,
        marginTop: 4,
        verticalAlign: "middle",
        opacity: 0.8
      }
    })));
  }

  /* ---------- sections ---------- */
  function Hero({
    p,
    meta
  }) {
    return /*#__PURE__*/React.createElement("section", {
      style: {
        paddingTop: "4.5rem"
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        ...wrap,
        textAlign: "center",
        maxWidth: "44rem"
      }
    }, /*#__PURE__*/React.createElement(PgEyebrow, {
      color: ACC
    }, "Platform \xB7 ", p.name), /*#__PURE__*/React.createElement("h1", {
      style: {
        fontFamily: "var(--font-serif)",
        fontWeight: 300,
        fontSize: "3.75rem",
        lineHeight: 1.03,
        letterSpacing: "-0.025em",
        margin: "1.25rem 0 0",
        color: INK
      }
    }, p.name), /*#__PURE__*/React.createElement("p", {
      style: {
        fontFamily: "var(--font-sans)",
        fontSize: "1.1875rem",
        color: "var(--color-grey-800)",
        margin: "1.25rem auto 0",
        maxWidth: "48ch",
        lineHeight: 1.5
      }
    }, p.sub), /*#__PURE__*/React.createElement("div", {
      style: {
        display: "flex",
        gap: "0.625rem",
        justifyContent: "center",
        marginTop: "2.25rem",
        alignItems: "center"
      }
    }, /*#__PURE__*/React.createElement(PgButton, null, meta.verb), /*#__PURE__*/React.createElement(PgLink, {
      href: "developers.html"
    }, "Read the docs"))), /*#__PURE__*/React.createElement("div", {
      style: {
        ...wrap,
        marginTop: "3.5rem"
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        position: "relative",
        borderRadius: "26px 26px 0 0",
        overflow: "hidden",
        background: "#08080b",
        padding: "5.5rem 0 0",
        minHeight: "30rem"
      }
    }, /*#__PURE__*/React.createElement(DotPanel, {
      seed: p.slug.length * 7 + 3
    }), /*#__PURE__*/React.createElement("div", {
      style: {
        position: "relative",
        maxWidth: "44rem",
        margin: "0 auto",
        padding: "0 2rem"
      }
    }, /*#__PURE__*/React.createElement(Terminal, {
      title: "hypervisor — " + p.slug,
      lines: meta.lines,
      accent: true
    })))));
  }
  function SectionHead({
    eyebrow,
    title,
    sub,
    align = "left"
  }) {
    return /*#__PURE__*/React.createElement("div", {
      style: {
        maxWidth: "46rem",
        textAlign: align,
        margin: align === "center" ? "0 auto" : undefined
      }
    }, eyebrow && /*#__PURE__*/React.createElement(PgEyebrow, null, eyebrow), /*#__PURE__*/React.createElement("h2", {
      style: {
        fontFamily: "var(--font-serif)",
        fontWeight: 300,
        fontSize: "2.5rem",
        letterSpacing: "-0.02em",
        lineHeight: 1.08,
        margin: eyebrow ? "1rem 0 0" : 0,
        color: INK
      }
    }, title), sub && /*#__PURE__*/React.createElement("p", {
      style: {
        fontFamily: "var(--font-sans)",
        fontSize: "1.0625rem",
        color: "var(--color-grey-800)",
        marginTop: "1rem",
        lineHeight: 1.5
      }
    }, sub));
  }

  /* ---------- faceted motif (light, static, feature cards) ---------- */
  function DotField({
    seed = 0
  }) {
    return /*#__PURE__*/React.createElement(window.HvDots, {
      cover: true,
      cols: 9,
      rows: 6,
      gap: 26,
      seed: seed
    });
  }
  function Features({
    p
  }) {
    return /*#__PURE__*/React.createElement("section", {
      style: {
        ...wrap,
        paddingTop: "7rem"
      }
    }, /*#__PURE__*/React.createElement(SectionHead, {
      title: "Explore the main features"
    }), /*#__PURE__*/React.createElement("div", {
      style: {
        display: "grid",
        gridTemplateColumns: "repeat(3, 1fr)",
        gap: "1.25rem",
        marginTop: "2.5rem"
      }
    }, p.capabilities.map(([title, desc], i) => /*#__PURE__*/React.createElement("div", {
      key: title,
      style: {
        display: "flex",
        flexDirection: "column",
        background: "var(--color-white)",
        border: `0.5px solid ${HAIR}`,
        borderRadius: "var(--radius-card)",
        overflow: "hidden"
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        position: "relative",
        background: "var(--color-porcelain-grey)",
        aspectRatio: "1.6 / 1",
        borderBottom: `0.5px solid ${HAIR}`,
        overflow: "hidden"
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        position: "absolute",
        inset: "1.75rem",
        WebkitMaskImage: "radial-gradient(120% 120% at 50% 42%, #000 42%, transparent 80%)",
        maskImage: "radial-gradient(120% 120% at 50% 42%, #000 42%, transparent 80%)"
      }
    }, /*#__PURE__*/React.createElement(DotField, {
      seed: p.slug.length * 3 + i * 5
    }))), /*#__PURE__*/React.createElement("div", {
      style: {
        padding: "1.5rem 1.75rem 1.75rem"
      }
    }, /*#__PURE__*/React.createElement("h3", {
      style: {
        fontFamily: "var(--font-sans)",
        fontSize: "1.125rem",
        letterSpacing: "-0.015em",
        margin: 0,
        color: INK
      }
    }, title), /*#__PURE__*/React.createElement("p", {
      style: {
        fontFamily: "var(--font-sans)",
        fontSize: "0.9375rem",
        color: "var(--color-grey-800)",
        marginTop: "0.625rem",
        lineHeight: 1.5
      }
    }, desc))))));
  }

  /* ---------- signature governed-session mock (echoes the home hero panel) ---------- */
  function SessionMock({
    p
  }) {
    const rows = (p.capabilities || []).slice(0, 3).map(([t]) => t);
    const scopes = ["prim:fs.write", "scope:repo", "prim:proc.exec"];
    return /*#__PURE__*/React.createElement("div", {
      style: {
        position: "relative",
        background: "var(--color-porcelain-grey)",
        display: "grid",
        placeItems: "center",
        padding: "3rem 2.75rem",
        overflow: "hidden"
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        position: "absolute",
        inset: 0,
        opacity: 0.6,
        WebkitMaskImage: "radial-gradient(120% 115% at 72% 38%, #000 26%, transparent 76%)",
        maskImage: "radial-gradient(120% 115% at 72% 38%, #000 26%, transparent 76%)"
      },
      "aria-hidden": "true"
    }, /*#__PURE__*/React.createElement(window.HvDots, {
      cover: true,
      cols: 12,
      rows: 9,
      gap: 30,
      seed: p.slug.length * 9 + 4
    })), /*#__PURE__*/React.createElement("div", {
      style: {
        position: "relative",
        width: "100%",
        maxWidth: "23rem",
        background: "var(--color-white)",
        border: `0.5px solid ${HAIR}`,
        borderRadius: "var(--radius-card)",
        boxShadow: "var(--shadow-lg)",
        overflow: "hidden"
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        display: "flex",
        alignItems: "center",
        gap: 8,
        padding: "11px 14px",
        borderBottom: `0.5px solid ${HAIR}`
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        width: 20,
        height: 20,
        color: INK,
        display: "inline-flex"
      }
    }, /*#__PURE__*/React.createElement(PgLogo, {
      size: 20
    })), /*#__PURE__*/React.createElement("span", {
      style: {
        fontFamily: "var(--font-mono)",
        fontSize: 11.5,
        color: "var(--color-grey-800)"
      }
    }, "session \xB7 ", p.slug), /*#__PURE__*/React.createElement("span", {
      style: {
        marginLeft: "auto",
        fontFamily: "var(--font-mono)",
        fontSize: 10,
        letterSpacing: "0.04em",
        color: ACC,
        border: `0.5px solid color-mix(in srgb, ${ACC} 35%, transparent)`,
        background: "color-mix(in srgb, var(--color-pistachio-green) 40%, var(--color-white))",
        borderRadius: 999,
        padding: "3px 9px"
      }
    }, "Running")), /*#__PURE__*/React.createElement("div", {
      style: {
        padding: "14px",
        display: "flex",
        flexDirection: "column",
        gap: 8
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        fontFamily: "var(--font-mono)",
        fontSize: 10,
        letterSpacing: "0.09em",
        textTransform: "uppercase",
        color: "var(--color-grey-700)"
      }
    }, "Receipts"), rows.map((r, i) => /*#__PURE__*/React.createElement("div", {
      key: i,
      style: {
        display: "flex",
        alignItems: "center",
        gap: 9,
        border: `0.5px solid ${HAIR}`,
        borderRadius: "var(--radius-lg)",
        padding: "9px 11px"
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        width: 6,
        height: 6,
        borderRadius: "50%",
        background: "var(--color-green-600)",
        flexShrink: 0
      }
    }), /*#__PURE__*/React.createElement("span", {
      style: {
        fontFamily: "var(--font-sans)",
        fontSize: 12.5,
        color: INK,
        overflow: "hidden",
        textOverflow: "ellipsis",
        whiteSpace: "nowrap"
      }
    }, r), /*#__PURE__*/React.createElement("span", {
      style: {
        marginLeft: "auto",
        fontFamily: "var(--font-mono)",
        fontSize: 10.5,
        color: "var(--color-grey-700)",
        flexShrink: 0
      }
    }, scopes[i]))), /*#__PURE__*/React.createElement("div", {
      style: {
        display: "flex",
        alignItems: "center",
        gap: 9,
        border: `1px solid ${INK}`,
        borderRadius: "var(--radius-lg)",
        padding: "10px 11px",
        marginTop: 2
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        fontFamily: "var(--font-mono)",
        fontSize: 10,
        letterSpacing: "0.05em",
        color: ACC
      }
    }, "GATE"), /*#__PURE__*/React.createElement("span", {
      style: {
        fontFamily: "var(--font-sans)",
        fontSize: 12.5,
        color: INK
      }
    }, "Approve & continue"), /*#__PURE__*/React.createElement("span", {
      style: {
        marginLeft: "auto",
        display: "flex",
        gap: 6
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        fontFamily: "var(--font-sans)",
        fontSize: 11.5,
        background: INK,
        color: "#fff",
        borderRadius: 6,
        padding: "3px 9px"
      }
    }, "Allow"), /*#__PURE__*/React.createElement("span", {
      style: {
        fontFamily: "var(--font-sans)",
        fontSize: 11.5,
        border: `0.5px solid ${HAIR}`,
        color: "var(--color-grey-800)",
        borderRadius: 6,
        padding: "3px 9px"
      }
    }, "Deny"))))));
  }

  /* ---------- editorial deep-dive band (uses p.detail) ---------- */
  function Detail({
    p
  }) {
    const d = p.detail;
    if (!d) return null;
    const pts = d.points || [];
    return /*#__PURE__*/React.createElement("section", {
      style: {
        ...wrap,
        paddingTop: "7rem"
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        background: "var(--color-white)",
        border: `0.5px solid ${HAIR}`,
        borderRadius: "var(--radius-card)",
        overflow: "hidden"
      }
    }, /*#__PURE__*/React.createElement("div", {
      className: "hv-pd-detail",
      style: {
        display: "grid",
        gridTemplateColumns: "1.02fr 0.98fr"
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        padding: "3rem 3.25rem",
        borderRight: `0.5px solid ${HAIR}`,
        display: "flex",
        flexDirection: "column",
        justifyContent: "center"
      }
    }, /*#__PURE__*/React.createElement(PgEyebrow, null, d.eyebrow), /*#__PURE__*/React.createElement("h2", {
      style: {
        fontFamily: "var(--font-serif)",
        fontWeight: 300,
        fontSize: "2.25rem",
        letterSpacing: "-0.02em",
        lineHeight: 1.1,
        margin: "1rem 0 0",
        color: INK,
        maxWidth: "18ch"
      }
    }, d.heading), /*#__PURE__*/React.createElement("p", {
      style: {
        fontFamily: "var(--font-sans)",
        fontSize: "1.0625rem",
        color: "var(--color-grey-800)",
        marginTop: "1.1rem",
        lineHeight: 1.55,
        maxWidth: "44ch"
      }
    }, d.sub)), /*#__PURE__*/React.createElement(SessionMock, {
      p: p
    })), /*#__PURE__*/React.createElement("div", {
      className: "hv-pd-points",
      style: {
        borderTop: `0.5px solid ${HAIR}`,
        display: "grid",
        gridTemplateColumns: "1fr 1fr"
      }
    }, pts.map(([t, b], i) => /*#__PURE__*/React.createElement("div", {
      key: t,
      style: {
        padding: "2rem 2.25rem",
        borderRight: i % 2 === 0 ? `0.5px solid ${HAIR}` : "none",
        borderTop: i >= 2 ? `0.5px solid ${HAIR}` : "none"
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        fontFamily: "var(--font-mono)",
        fontSize: 11,
        letterSpacing: "0.04em",
        color: ACC
      }
    }, String(i + 1).padStart(2, "0")), /*#__PURE__*/React.createElement("h3", {
      style: {
        fontFamily: "var(--font-sans)",
        fontSize: "1.0625rem",
        letterSpacing: "-0.015em",
        margin: "0.75rem 0 0",
        color: INK
      }
    }, t), /*#__PURE__*/React.createElement("p", {
      style: {
        fontFamily: "var(--font-sans)",
        fontSize: "0.9375rem",
        color: "var(--color-grey-800)",
        marginTop: "0.5rem",
        lineHeight: 1.5
      }
    }, b))))));
  }

  /* ---------- specifications strip (uses p.specs) ---------- */
  function Specs({
    p
  }) {
    const specs = p.specs || [];
    if (!specs.length) return null;
    return /*#__PURE__*/React.createElement("section", {
      style: {
        ...wrap,
        paddingTop: "7rem"
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        display: "flex",
        alignItems: "baseline",
        gap: "0.875rem",
        paddingBottom: "1.5rem",
        borderBottom: `1px solid ${INK}`
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        fontFamily: "var(--font-mono)",
        fontSize: 11,
        letterSpacing: "0.09em",
        textTransform: "uppercase",
        color: ACC
      }
    }, "At a glance"), /*#__PURE__*/React.createElement("span", {
      style: {
        fontFamily: "var(--font-sans)",
        fontSize: "0.9375rem",
        color: "var(--color-grey-700)"
      }
    }, p.category)), /*#__PURE__*/React.createElement("div", {
      className: "hv-pd-specs",
      style: {
        display: "grid",
        gridTemplateColumns: `repeat(${specs.length}, 1fr)`
      }
    }, specs.map(([label, value], i) => /*#__PURE__*/React.createElement("div", {
      key: label,
      style: {
        padding: "1.75rem 1.5rem 0",
        paddingLeft: i ? "1.5rem" : 0,
        borderLeft: i ? `0.5px solid ${HAIR}` : "none"
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        fontFamily: "var(--font-mono)",
        fontSize: 10.5,
        letterSpacing: "0.06em",
        textTransform: "uppercase",
        color: "var(--color-grey-700)"
      }
    }, label), /*#__PURE__*/React.createElement("div", {
      style: {
        fontFamily: "var(--font-sans)",
        fontSize: "1.0625rem",
        color: INK,
        marginTop: "0.6rem",
        lineHeight: 1.35,
        letterSpacing: "-0.01em"
      }
    }, value)))));
  }

  /* ---------- related products (uses p.related) ---------- */
  function Related({
    p
  }) {
    const rel = (p.related || []).map(slug => {
      const prod = window.HV_PRODUCT_MAP[slug];
      if (prod) return {
        name: prod.name,
        file: prod.file,
        role: prod.category
      };
      const ext = window.HV_EXT && window.HV_EXT[slug];
      if (ext) return {
        name: ext.name,
        file: ext.file,
        role: "Solution"
      };
      return null;
    }).filter(Boolean);
    if (!rel.length) return null;
    return /*#__PURE__*/React.createElement("section", {
      style: {
        ...wrap,
        paddingTop: "7rem"
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        display: "flex",
        alignItems: "baseline",
        gap: "0.875rem",
        marginBottom: "1.75rem"
      }
    }, /*#__PURE__*/React.createElement(PgEyebrow, null, "Continue across the substrate"), /*#__PURE__*/React.createElement("span", {
      style: {
        fontFamily: "var(--font-sans)",
        fontSize: "0.9375rem",
        color: "var(--color-grey-700)"
      }
    }, "Binds to the same Hypervisor Core")), /*#__PURE__*/React.createElement("div", {
      className: "hv-pd-related",
      style: {
        display: "grid",
        gridTemplateColumns: `repeat(${rel.length}, 1fr)`,
        gap: "1.25rem"
      }
    }, rel.map(r => /*#__PURE__*/React.createElement("a", {
      key: r.file,
      href: r.file,
      className: "hv-relcard",
      style: {
        display: "flex",
        flexDirection: "column",
        gap: "0.75rem",
        background: "var(--color-white)",
        border: `0.5px solid ${HAIR}`,
        borderRadius: "var(--radius-card)",
        padding: "1.75rem",
        textDecoration: "none",
        color: "inherit",
        transition: "border-color 200ms cubic-bezier(0.22,1,0.36,1)"
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        fontFamily: "var(--font-mono)",
        fontSize: 10.5,
        letterSpacing: "0.05em",
        textTransform: "uppercase",
        color: "var(--color-grey-700)"
      }
    }, r.role), /*#__PURE__*/React.createElement("span", {
      style: {
        fontFamily: "var(--font-serif)",
        fontWeight: 300,
        fontSize: "1.5rem",
        letterSpacing: "-0.02em",
        lineHeight: 1.1,
        color: INK
      }
    }, r.name), /*#__PURE__*/React.createElement("span", {
      className: "hv-relarrow",
      style: {
        marginTop: "auto",
        display: "inline-flex",
        alignItems: "center",
        gap: 7,
        fontFamily: "var(--font-sans)",
        fontSize: "0.9375rem",
        color: ACC
      }
    }, "Explore ", /*#__PURE__*/React.createElement("span", {
      style: {
        transition: "transform 200ms cubic-bezier(0.22,1,0.36,1)",
        display: "inline-block"
      }
    }, "\u2192"))))));
  }
  function Quickstart({
    p,
    meta
  }) {
    const steps = [[meta.verb, p.slug === "web" ? "No install — open Hypervisor Web and sign in to your org." : "One command. The runtime is local-first and offline-capable from the start."], ["Authorize", "Scope credentials, tools, and spend. Nothing runs outside the grant you give it."], ["Run governed work", "Start a session. Every consequential action is approved, receipted, and replayable."]];
    return /*#__PURE__*/React.createElement("section", {
      style: {
        ...wrap,
        paddingTop: "7rem"
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        background: "var(--color-white)",
        border: `0.5px solid ${HAIR}`,
        borderRadius: "var(--radius-card)",
        overflow: "hidden"
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        padding: "2.75rem 3rem 2rem",
        maxWidth: "46rem"
      }
    }, /*#__PURE__*/React.createElement(SectionHead, {
      eyebrow: "Get started",
      title: "Up and running in minutes",
      sub: `${p.name} binds to the same Hypervisor Core as every other surface — it operates runtime truth, it never owns it.`
    })), /*#__PURE__*/React.createElement("div", {
      style: {
        borderTop: `1px solid ${HAIR}`,
        display: "grid",
        gridTemplateColumns: "repeat(3, 1fr)"
      }
    }, steps.map(([title, body], i) => /*#__PURE__*/React.createElement("div", {
      key: title,
      style: {
        padding: "2.25rem 2rem",
        borderRight: i < 2 ? `1px solid ${HAIR}` : "none"
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        fontFamily: "var(--font-mono)",
        fontSize: 11,
        color: ACC
      }
    }, String(i + 1).padStart(2, "0")), /*#__PURE__*/React.createElement("h3", {
      style: {
        fontFamily: "var(--font-sans)",
        fontSize: "1.0625rem",
        letterSpacing: "-0.015em",
        margin: "0.75rem 0 0",
        color: INK
      }
    }, title), /*#__PURE__*/React.createElement("p", {
      style: {
        fontFamily: "var(--font-sans)",
        fontSize: "0.9375rem",
        color: "var(--color-grey-800)",
        marginTop: "0.625rem",
        lineHeight: 1.5
      }
    }, body))))));
  }
  function InstallCTA({
    p,
    meta
  }) {
    return /*#__PURE__*/React.createElement("section", {
      style: {
        ...wrap,
        paddingTop: "7rem"
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        position: "relative",
        borderRadius: "var(--radius-card)",
        overflow: "hidden",
        background: "#08080b",
        minHeight: "26rem",
        display: "flex",
        alignItems: "center"
      }
    }, /*#__PURE__*/React.createElement(DotPanel, {
      seed: p.slug.length * 5 + 11
    }), /*#__PURE__*/React.createElement("div", {
      style: {
        position: "relative",
        padding: "0 4rem",
        maxWidth: "34rem"
      }
    }, /*#__PURE__*/React.createElement("h2", {
      style: {
        fontFamily: "var(--font-serif)",
        fontWeight: 300,
        fontSize: "3rem",
        lineHeight: 1.05,
        letterSpacing: "-0.02em",
        margin: 0,
        color: "#fff"
      }
    }, meta.verb === "Install" ? `Install ${p.name}` : `${meta.verb}`), /*#__PURE__*/React.createElement("p", {
      style: {
        fontFamily: "var(--font-sans)",
        fontSize: "1.0625rem",
        color: "rgba(255,255,255,0.6)",
        marginTop: "1rem",
        lineHeight: 1.5
      }
    }, p.sub), /*#__PURE__*/React.createElement("div", {
      style: {
        display: "flex",
        gap: "0.625rem",
        marginTop: "2rem"
      }
    }, /*#__PURE__*/React.createElement(PgButton, {
      theme: "white"
    }, meta.verb), /*#__PURE__*/React.createElement(PgButton, {
      variant: "outline",
      theme: "white"
    }, "Talk to sales")))), /*#__PURE__*/React.createElement("div", {
      style: {
        display: "flex",
        justifyContent: "center",
        marginTop: "2.5rem"
      }
    }, /*#__PURE__*/React.createElement(PgLink, {
      href: "platform.html"
    }, "Back to platform")));
  }
  function ProductPage() {
    const p = window.HV_PRODUCT_MAP[window.HV_CURRENT_SLUG];
    if (!p) return /*#__PURE__*/React.createElement("div", {
      style: {
        ...wrap,
        paddingTop: "6rem"
      }
    }, "Unknown product.");
    const meta = INSTALL[p.slug] || {
      verb: "Get started",
      lines: ["$ hv --help"]
    };
    return /*#__PURE__*/React.createElement("main", null, /*#__PURE__*/React.createElement(Hero, {
      p: p,
      meta: meta
    }), /*#__PURE__*/React.createElement(Features, {
      p: p
    }), /*#__PURE__*/React.createElement(Detail, {
      p: p
    }), /*#__PURE__*/React.createElement(Specs, {
      p: p
    }), /*#__PURE__*/React.createElement(Quickstart, {
      p: p,
      meta: meta
    }), /*#__PURE__*/React.createElement(Related, {
      p: p
    }), /*#__PURE__*/React.createElement(InstallCTA, {
      p: p,
      meta: meta
    }));
  }
  window.HvPage = ProductPage;
})();
})(); } catch (e) { __ds_ns.__errors.push({ path: "site/ProductPage.jsx", error: String((e && e.message) || e) }); }

// site/RevealDiagram.jsx
try { (() => {
// Scroll-into-view reveal for the hypervisor.com line-art diagrams.
// Generic: it reads the shared visual grammar of HvDiagrams —
//   · decorative SVG (dotted orbits, dashed VPC boundary, labels) → fade in
//   · solid SVG connectors (<line>/<path> with no dash) → stroke-draw
//   · HTML chips (nodes, cards, pills) → fade + lift, radiating out from center
// End-state is the base style; we animate *from* hidden, gated on inbound
// viewport entry (once) and disabled under prefers-reduced-motion.

const easeOutCubic = t => 1 - Math.pow(1 - t, 3);
const clamp01 = t => t < 0 ? 0 : t > 1 ? 1 : t;

// Inject the (once) keyframes for the post-reveal marching VPC boundary.
// Seamless: each cycle shifts the dash pattern by exactly one period (2+7=9u),
// so an infinite repeat reads as a calm continuous drift, not a march.
// Meaningful (a live, sealed perimeter), low-contrast, single. It begins the
// instant the boundary has faded in and keeps drifting through the rest of the
// reveal — off entirely under reduced-motion.
(function injectRevealStyle() {
  if (typeof document === "undefined") return;
  let s = document.getElementById("rv-style");
  if (!s) {
    s = document.createElement("style");
    s.id = "rv-style";
    document.head.appendChild(s);
  }
  s.textContent = "@keyframes rvVpcMarch { to { stroke-dashoffset: -6.5; } }" + "@keyframes rvOrbit { to { transform: rotate(360deg); } }" + "[data-orbit] { transform-box: fill-box; transform-origin: center; }" + "@media (prefers-reduced-motion: no-preference) {" + "  .rv-march [data-vpc-border] { animation: rvVpcMarch var(--vpc-period, 2.6s) linear infinite; }" + "  .rv-march [data-orbit] { animation: rvOrbit var(--orbit-period, 42s) linear infinite; }" + "}" + "body.vpc-march-off [data-vpc-border] { animation: none !important; }" + "body.orbit-spin-off [data-orbit] { animation: none !important; }";
  document.head.appendChild(s);
})();
function buildController(root, opts = {}) {
  const svg = root.querySelector("svg");
  const items = [];
  const order = opts.order || "radial";

  // ---- bespoke: code-editor diagram (DiagToolStack) ----
  // chrome settles → tool logos drop in from above → code types line-by-line →
  // cursor lands on the active (highlighted) line.
  if (order === "code") {
    const editor = root.querySelector('[data-rv="editor"]');
    const lines = Array.from(root.querySelectorAll('[data-rv="codeline"]'));
    const cursor = root.querySelector('[data-rv="cursor"]');
    const tools = Array.from(root.querySelectorAll('[data-rv="tools"] > *'));
    if (editor) {
      const base = editor.style.transform || "";
      editor.style.opacity = "0";
      editor.style.willChange = "transform, opacity";
      items.push({
        el: editor,
        kind: "rise",
        base,
        dy: 8,
        sc: 0.04,
        start: 0,
        dur: 0.32
      });
    }
    tools.forEach((el, i) => {
      const base = el.style.transform || "";
      el.style.opacity = "0";
      el.style.willChange = "transform, opacity";
      items.push({
        el,
        kind: "drop",
        base,
        dy: -10,
        start: 0.16 + i * 0.06,
        dur: 0.34
      });
    });
    const lineStart = 0.34,
      lineStep = 0.052;
    lines.forEach((el, i) => {
      el.style.opacity = "0";
      el.style.willChange = "opacity";
      items.push({
        el,
        kind: "type",
        start: lineStart + i * lineStep,
        dur: 0.22
      });
    });
    const typedEnd = lineStart + lines.length * lineStep; // ~0.76
    // active row (7 → index 6) gets the persistent highlight; row below (8 → index 7)
    // gets a transient highlight as the cursor sweeps up past it from below.
    const activeRow = lines[6],
      passRow = lines[7];
    if (activeRow) activeRow.style.background = "transparent"; // override static; the glow drives it
    const cStart = typedEnd + 0.02,
      cDur = 0.5;
    if (cursor) {
      const base = cursor.style.transform || "";
      cursor.style.opacity = "0";
      cursor.style.willChange = "transform, opacity";
      // enters from bottom-right, holds over row 8, then settles on row 7 (linear: honest travel)
      items.push({
        el: cursor,
        kind: "cursorPath",
        base,
        ease: "linear",
        start: cStart,
        dur: cDur
      });
    }
    if (passRow) {
      passRow.style.background = "transparent";
      // transient flash while the cursor holds over row 8 (mid-sweep)
      items.push({
        el: passRow,
        kind: "pulse",
        peak: 7.5,
        ease: "linear",
        start: cStart + 0.45 * cDur - 0.05,
        dur: 0.2
      });
    }
    if (activeRow) {
      // settles on row 7 as the cursor arrives
      items.push({
        el: activeRow,
        kind: "glow",
        peak: 9,
        ease: "linear",
        start: cStart + 0.84 * cDur,
        dur: 0.16
      });
    }
  } else
    // ---- bespoke: depth-stack diagram (DiagPrivacy) ----
    // deal the cascade of windows back-to-front (z-order), then draw the accent
    // connector as the private-model card seats, then fill the front card's lines.
    if (order === "stack") {
      const frame = svg ? svg.parentElement : root.querySelector("div");
      const cards = Array.from(frame.children).filter(c => c.tagName === "DIV"); // WinCards, DOM = back→front
      const dealStep = 0.11;
      cards.forEach((el, i) => {
        const base = el.style.transform || "";
        el.style.opacity = "0";
        el.style.willChange = "transform, opacity";
        // dealt in from up-and-right (the fan's origin), settling into the slot
        items.push({
          el,
          kind: "deal",
          base,
          dx: 34,
          dy: -26,
          start: i * dealStep,
          dur: 0.42
        });
      });
      // accent card is the one with an accent border (next-to-last in DOM)
      const accentIdx = Math.max(0, cards.length - 2);
      const accentSeated = accentIdx * dealStep + 0.42;
      if (svg) {
        svg.querySelectorAll("path").forEach(p => {
          let len = 0;
          try {
            len = p.getTotalLength();
          } catch (e) {}
          if (!len) return;
          p.style.strokeDasharray = len;
          p.style.strokeDashoffset = len;
          items.push({
            el: p,
            kind: "draw",
            len,
            start: accentSeated - 0.06,
            dur: 0.34
          });
        });
        svg.querySelectorAll("circle").forEach(c => {
          const target = parseFloat(getComputedStyle(c).opacity) || 1;
          c.style.opacity = "0";
          items.push({
            el: c,
            kind: "fade",
            target,
            start: accentSeated - 0.08,
            dur: 0.2
          });
        });
      }
      // front card's numbered code lines fill in last
      const winLines = Array.from(root.querySelectorAll('[data-rv="wincode"]'));
      const frontSeated = (cards.length - 1) * dealStep + 0.3;
      winLines.forEach((el, i) => {
        el.style.opacity = "0";
        el.style.willChange = "opacity";
        items.push({
          el,
          kind: "type",
          start: frontSeated + i * 0.06,
          dur: 0.22
        });
      });
    } else
      // ---- bespoke: agent capability tree (DiagAgentTree) ----
      // agent pill drops in → branch connector draws down → capability pills
      // ripple in row-by-row, center-out within each row.
      if (order === "tree") {
        const agent = root.querySelector('[data-rv="agent"]');
        const branchSvg = root.querySelector('[data-rv="branch"]');
        const rows = Array.from(root.querySelectorAll('[data-rv="caprow"]'));
        if (agent) {
          const base = agent.style.transform || "";
          agent.style.opacity = "0";
          agent.style.willChange = "transform, opacity";
          items.push({
            el: agent,
            kind: "drop",
            base,
            dy: -9,
            start: 0,
            dur: 0.34
          });
        }
        if (branchSvg) {
          branchSvg.querySelectorAll("path").forEach(p => {
            let len = 0;
            try {
              len = p.getTotalLength();
            } catch (e) {}
            if (!len) return;
            p.style.strokeDasharray = len;
            p.style.strokeDashoffset = len;
            items.push({
              el: p,
              kind: "draw",
              len,
              start: 0.22,
              dur: 0.3
            });
          });
        }
        const rowStart = 0.44,
          rowStep = 0.16;
        rows.forEach((rowEl, ri) => {
          const pills = Array.from(rowEl.querySelectorAll('[data-rv="cap"]'));
          // center-out ordering within the row
          const mid = (pills.length - 1) / 2;
          const ranked = pills.map((el, idx) => ({
            el,
            d: Math.abs(idx - mid)
          })).sort((a, b) => a.d - b.d);
          ranked.forEach(({
            el
          }, rank) => {
            const base = el.style.transform || "";
            el.style.display = el.style.display || "inline-block";
            el.style.opacity = "0";
            el.style.willChange = "transform, opacity";
            items.push({
              el,
              kind: "chip",
              base,
              start: rowStart + ri * rowStep + rank * 0.03,
              dur: 0.32
            });
          });
        });
      } else
        // ---- classify SVG layer ----
        if (svg) {
          const frame = svg.parentElement;

          // decorative: anything dashed, plus text + circles (orbits)
          const decor = Array.from(svg.querySelectorAll("[stroke-dasharray], text, circle"));
          decor.forEach((el, i) => {
            const target = parseFloat(getComputedStyle(el).opacity) || 1;
            el.style.opacity = "0";
            items.push({
              el,
              kind: "fade",
              target,
              start: Math.min(i * 0.035, 0.16),
              dur: 0.32
            });
          });

          // solid connectors: lines / paths with no dash pattern
          const conns = Array.from(svg.querySelectorAll("line, path")).filter(el => !el.getAttribute("stroke-dasharray") && !el.closest("[stroke-dasharray]"));
          conns.forEach((el, i) => {
            let len = 0;
            try {
              len = el.getTotalLength();
            } catch (e) {
              len = 0;
            }
            if (!len) return;
            el.style.strokeDasharray = len;
            el.style.strokeDashoffset = len;
            items.push({
              el,
              kind: "draw",
              len,
              start: 0.30 + i * 0.028,
              dur: 0.34
            });
          });

          // chips: frame children that aren't the svg.
          // order "radial"  → build from the geometric center outward (a hub diagram)
          // order "topdown" → build from the top down (a hierarchy whose source is up top)
          if (frame) {
            const rootRect = root.getBoundingClientRect();
            const cx = rootRect.left + rootRect.width / 2;
            const cy = rootRect.top + rootRect.height / 2;
            const chips = Array.from(frame.children).filter(c => c !== svg);
            const ranked = chips.map(el => {
              const r = el.getBoundingClientRect();
              const mx = r.left + r.width / 2;
              const my = r.top + r.height / 2;
              // radial: distance from center. topdown: vertical first, then
              // distance-from-center as the within-row tiebreak (center-out per row).
              const key = order === "topdown" ? (my - rootRect.top) * 1000 + Math.abs(mx - cx) : Math.hypot(mx - cx, my - cy);
              return {
                el,
                key
              };
            }).sort((a, b) => a.key - b.key);
            ranked.forEach(({
              el
            }, rank) => {
              // the joined AI-agent + Developer pill gets a gooey metaball merge
              const joined = el.querySelector && el.querySelector('[data-rv="joined"]');
              if (joined) {
                const L = joined.querySelector('[data-rv="goo-left"]');
                const R = joined.querySelector('[data-rv="goo-right"]');
                const B = joined.querySelector('[data-rv="goo-bridge"]');
                const TL = joined.querySelector('[data-rv="goo-tl"]');
                const TR = joined.querySelector('[data-rv="goo-tr"]');
                if (L) {
                  L.style.opacity = "0";
                  L.style.willChange = "transform, opacity";
                  items.push({
                    el: L,
                    kind: "gooSlide",
                    dx: -24,
                    start: 0.04,
                    dur: 0.42
                  });
                }
                if (R) {
                  R.style.opacity = "0";
                  R.style.willChange = "transform, opacity";
                  items.push({
                    el: R,
                    kind: "gooSlide",
                    dx: 24,
                    start: 0.04,
                    dur: 0.42
                  });
                }
                if (B) {
                  B.style.opacity = "0";
                  B.style.transformOrigin = "center";
                  B.style.willChange = "transform, opacity";
                  items.push({
                    el: B,
                    kind: "gooBridge",
                    start: 0.2,
                    dur: 0.24
                  });
                }
                if (TL) {
                  TL.style.opacity = "0";
                  items.push({
                    el: TL,
                    kind: "gooText",
                    start: 0.36,
                    dur: 0.24
                  });
                }
                if (TR) {
                  TR.style.opacity = "0";
                  items.push({
                    el: TR,
                    kind: "gooText",
                    start: 0.38,
                    dur: 0.24
                  });
                }
                return; // not a generic chip
              }
              const base = el.style.transform || "";
              el.style.opacity = "0";
              el.style.willChange = "transform, opacity";
              // source (first) leads; the rest follow once connectors are drawing
              const start = rank === 0 ? 0.14 : 0.42 + (rank - 1) * 0.058;
              items.push({
                el,
                kind: "chip",
                base,
                start,
                dur: 0.36
              });
            });
          }
        }
  const MAXEND = items.reduce((m, it) => Math.max(m, it.start + it.dur), 1);
  function apply(it, e) {
    if (it.kind === "fade") it.el.style.opacity = String(e * it.target);else if (it.kind === "draw") it.el.style.strokeDashoffset = String(it.len * (1 - e));else if (it.kind === "chip") {
      it.el.style.opacity = String(e);
      it.el.style.transform = `${it.base} translateY(${(1 - e) * 9}px) scale(${0.93 + 0.07 * e})`;
    } else if (it.kind === "gooSlide") {
      it.el.style.opacity = String(Math.min(1, e / 0.25));
      it.el.style.transform = `translateX(${(1 - e) * it.dx}px)`;
    } else if (it.kind === "gooBridge") {
      it.el.style.opacity = String(Math.min(1, e * 1.4));
      it.el.style.transform = `scaleX(${e})`;
    } else if (it.kind === "gooText") {
      it.el.style.opacity = String(e);
    } else if (it.kind === "rise") {
      it.el.style.opacity = String(e);
      it.el.style.transform = `${it.base} translateY(${(1 - e) * it.dy}px) scale(${1 - it.sc + it.sc * e})`;
    } else if (it.kind === "drop") {
      it.el.style.opacity = String(e);
      it.el.style.transform = `${it.base} translateY(${(1 - e) * it.dy}px)`;
    } else if (it.kind === "deal") {
      it.el.style.opacity = String(e);
      it.el.style.transform = `${it.base} translate(${(1 - e) * it.dx}px, ${(1 - e) * it.dy}px) scale(${0.96 + 0.04 * e})`;
    } else if (it.kind === "type") {
      it.el.style.opacity = String(e);
      it.el.style.transform = `translateX(${(1 - e) * -4}px)`;
    } else if (it.kind === "land") {
      it.el.style.opacity = String(e);
      it.el.style.transform = `${it.base} translate(${(1 - e) * -5}px, ${(1 - e) * -6}px) scale(${0.55 + 0.45 * e})`;
    } else if (it.kind === "cursorPath") {
      // bottom-right → hold over row 8 → settles on row 7 (offsets in px from rest)
      const lerp = (a, b, k) => a + (b - a) * k;
      const startPt = [22, 40],
        midPt = [6, 23]; // midPt ≈ one row below rest (over row 8)
      let dx, dy;
      if (e < 0.45) {
        const k = e / 0.45;
        dx = lerp(startPt[0], midPt[0], k);
        dy = lerp(startPt[1], midPt[1], k);
      } else if (e < 0.6) {
        dx = midPt[0];
        dy = midPt[1];
      } // hold over row 8
      else {
        const k = (e - 0.6) / 0.4;
        dx = lerp(midPt[0], 0, k);
        dy = lerp(midPt[1], 0, k);
      }
      it.el.style.opacity = String(Math.min(1, e / 0.12));
      it.el.style.transform = `${it.base} translate(${dx}px, ${dy}px) scale(${0.62 + 0.38 * Math.min(1, e / 0.25)})`;
    } else if (it.kind === "glow") {
      it.el.style.background = `color-mix(in srgb, var(--color-link-green) ${(it.peak * e).toFixed(2)}%, transparent)`;
    } else if (it.kind === "pulse") {
      const a = Math.sin(Math.PI * e); // 0 → 1 → 0
      it.el.style.background = `color-mix(in srgb, var(--color-link-green) ${(it.peak * a).toFixed(2)}%, transparent)`;
    }
  }
  function seek(tn) {
    const t = clamp01(tn) * MAXEND;
    for (const it of items) {
      const raw = clamp01((t - it.start) / it.dur);
      apply(it, it.ease === "linear" ? raw : easeOutCubic(raw));
    }
  }

  // Start the boundary's marching drift the moment it finishes fading in —
  // so it comes alive while the rest of the diagram is still revealing.
  const borderEl = root.querySelector("[data-vpc-border]");
  const borderItem = borderEl && items.find(it => it.el === borderEl);
  const marchAtTn = borderItem ? (borderItem.start + borderItem.dur) / MAXEND : 0.35;
  let raf = null,
    done = false,
    marched = false;
  function pause() {
    if (raf) {
      cancelAnimationFrame(raf);
      raf = null;
    }
  }
  function play(ms = 1550) {
    if (raf || done) return;
    const t0 = performance.now();
    const tick = now => {
      const tn = (now - t0) / ms;
      seek(tn);
      if (!marched && tn >= marchAtTn) {
        marched = true;
        root.classList.add("rv-march");
      }
      if (tn < 1) raf = requestAnimationFrame(tick);else {
        raf = null;
        done = true;
        seek(1);
        root.classList.add("rv-march");
      }
    };
    raf = requestAnimationFrame(tick);
  }
  function reset() {
    // restore the pre-reveal hidden state so the next entrance plays fresh
    pause();
    done = false;
    marched = false;
    root.classList.remove("rv-march");
    seek(0); // internal seek — does not latch `done`
  }
  seek(0);
  return {
    seek: t => {
      pause();
      done = true;
      seek(t);
    },
    play,
    pause,
    reset,
    _raw: seek,
    _items: items
  };
}
function Reveal({
  children,
  enter = 0.82,
  order = "radial"
}) {
  const ref = React.useRef(null);
  React.useEffect(() => {
    const root = ref.current;
    if (!root) return;
    const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
    let ctrl,
      ticking = false,
      cleaned = false,
      shown = false;
    const cleanup = () => {
      if (cleaned) return;
      cleaned = true;
      window.removeEventListener("scroll", onScroll, {
        passive: true
      });
      window.removeEventListener("resize", onScroll);
    };
    const inView = () => {
      const r = root.getBoundingClientRect();
      const vh = window.innerHeight || document.documentElement.clientHeight;
      return r.top < vh * enter && r.bottom > vh * (1 - enter);
    };
    // fully past the top or below the bottom — nothing of it is visible
    const fullyOut = () => {
      const r = root.getBoundingClientRect();
      const vh = window.innerHeight || document.documentElement.clientHeight;
      return r.bottom <= 0 || r.top >= vh;
    };
    const onScroll = () => {
      if (ticking || !ctrl) return;
      ticking = true;
      requestAnimationFrame(() => {
        ticking = false;
        if (!shown && inView()) {
          shown = true;
          ctrl.play();
        }
        // re-arm only once it has fully left the viewport, so it never
        // dismantles while any part is still on screen
        else if (shown && fullyOut()) {
          shown = false;
          ctrl.reset();
        }
      });
    };
    const id = requestAnimationFrame(() => {
      try {
        ctrl = buildController(root, {
          order
        });
      } catch (err) {
        // never leave the graphic stuck hidden — reveal it as-is
        root.querySelectorAll("[style]").forEach(el => {
          if (el.style.opacity === "0") el.style.opacity = "1";
          if (el.style.strokeDashoffset) el.style.strokeDashoffset = "0";
        });
        console.warn("RevealDiagram: build failed, shown statically", err);
        return;
      }
      (window.__reveals = window.__reveals || []).push(ctrl);
      if (reduce) {
        ctrl.seek(1);
        return;
      }
      window.addEventListener("scroll", onScroll, {
        passive: true
      });
      window.addEventListener("resize", onScroll);
      // fire immediately if already on-screen at mount
      if (inView()) {
        shown = true;
        ctrl.play();
      }
    });
    return () => {
      cancelAnimationFrame(id);
      cleanup();
    };
  }, []);
  return /*#__PURE__*/React.createElement("div", {
    ref: ref,
    style: {
      width: "100%",
      display: "flex",
      justifyContent: "center"
    }
  }, children);
}
window.RevealDiagram = {
  Reveal
};
})(); } catch (e) { __ds_ns.__errors.push({ path: "site/RevealDiagram.jsx", error: String((e && e.message) || e) }); }

// site/RuntimeSecurity.jsx
try { (() => {
// hypervisor.com — Runtime AI Security solution page.
const RSNS = window.IoiDesignSystem;
const {
  Button: RsButton,
  TextLink: RsLink,
  Eyebrow: RsEyebrow,
  Logo: RsLogo
} = RSNS;
const rswrap = {
  maxWidth: "75rem",
  margin: "0 auto",
  padding: "0 2.5rem"
};
const INK = "var(--color-onyx-black)";
const HAIR = "var(--color-grey-500)";
const ACC = "var(--color-link-green)";
const RED = "var(--color-red-500)";
function rsClock(period) {
  const [t, setT] = React.useState(0);
  React.useEffect(() => {
    const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduce) {
      setT(0.88);
      return;
    }
    let raf,
      start = null;
    const tick = ts => {
      if (start == null) start = ts;
      setT((ts - start) % period / period);
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, []);
  return t;
}
const rsIcon = (d, sw) => /*#__PURE__*/React.createElement("svg", {
  width: "17",
  height: "17",
  viewBox: "0 0 24 24",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: sw || 1.6,
  strokeLinecap: "round",
  strokeLinejoin: "round"
}, /*#__PURE__*/React.createElement("path", {
  d: d
}));
const SHIELD = "M12 3 L19 6 V11 C19 16 15.5 19.5 12 21 C8.5 19.5 5 16 5 11 V6 Z";

/* ============================================================ *
 * Hero product mockup — browser window, two panels:
 *  left  = agent conversation (suggestions + governed footer)
 *  right = live terminal with kernel policy enforcement
 * ============================================================ */
function AppMockup() {
  const t = rsClock(11000);
  const caretOn = Math.sin(t * Math.PI * 2 * 6) > 0;

  // right-panel terminal stream
  const term = [{
    at: 0.06,
    c: "dim",
    s: "hypervisor session start --scope=fs.read,shell.exec,net.none"
  }, {
    at: 0.13,
    c: "dim",
    s: "spawning worker · isolated sandbox (cTEE)"
  }, {
    at: 0.20,
    c: "ok",
    s: "session 9f2c1 ready · scoped credentials issued"
  }, {
    at: 0.29,
    c: "cmd",
    s: "worker run patch --cve CVE-2026-1042 --repo billing-api"
  }, {
    at: 0.37,
    c: "log",
    s: "read  src/deps/lockfile.json"
  }, {
    at: 0.44,
    c: "log",
    s: "edit  bumped libfoo 1.4.2 → 1.4.7"
  }, {
    at: 0.52,
    c: "block",
    s: "BLOCKED  net.outbound → registry.evil.sh  (policy net.none)"
  }, {
    at: 0.60,
    c: "log",
    s: "resolved via mirror · cache.internal"
  }, {
    at: 0.68,
    c: "cmd",
    s: "shell.exec npm test"
  }, {
    at: 0.76,
    c: "ok",
    s: "243 passed · 0 failing"
  }, {
    at: 0.85,
    c: "ok",
    s: "receipt sealed · 1 action blocked · IOI L1"
  }];
  const shown = term.filter(l => t >= l.at);
  const termColor = {
    dim: "rgba(255,255,255,0.42)",
    ok: ACC,
    cmd: "rgba(255,255,255,0.92)",
    log: "rgba(255,255,255,0.6)",
    block: "#ff6b6b"
  };
  const chips = ["Patch a CVE", "Triage Sentry errors", "Review open PRs"];
  const activeChip = Math.floor(t * 3) % 3;
  return /*#__PURE__*/React.createElement("div", {
    style: {
      width: "100%",
      maxWidth: 1060,
      margin: "0 auto",
      position: "relative"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      position: "absolute",
      inset: "-26px -26px -40px",
      borderRadius: 28,
      background: "radial-gradient(120% 120% at 70% 10%, color-mix(in srgb, var(--color-pistachio-green) 38%, var(--color-white)), var(--color-porcelain-grey))",
      zIndex: 0
    }
  }), /*#__PURE__*/React.createElement("div", {
    style: {
      position: "relative",
      zIndex: 1,
      background: "#0d0d10",
      borderRadius: 14,
      overflow: "hidden",
      boxShadow: "0 40px 90px rgba(0,0,0,0.4), 0 0 0 1px rgba(0,0,0,0.06)"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 8,
      padding: "11px 14px",
      background: "#17171c",
      borderBottom: "1px solid rgba(255,255,255,0.06)"
    }
  }, ["#ff5f57", "#ffbd2e", "#28c840"].map((c, i) => /*#__PURE__*/React.createElement("span", {
    key: i,
    style: {
      width: 11,
      height: 11,
      borderRadius: "50%",
      background: c
    }
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 7,
      marginLeft: 10,
      background: "#0d0d10",
      borderRadius: 7,
      padding: "5px 12px",
      border: "1px solid rgba(255,255,255,0.07)"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      color: ACC
    }
  }, rsIcon(SHIELD, 1.5)), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 11.5,
      color: "rgba(255,255,255,0.5)"
    }
  }, "app.hypervisor.io/session/9f2c1")), /*#__PURE__*/React.createElement("span", {
    style: {
      marginLeft: "auto",
      display: "flex",
      alignItems: "center",
      gap: 5,
      fontFamily: "var(--font-mono)",
      fontSize: 11,
      color: ACC,
      border: `1px solid color-mix(in srgb, ${ACC} 40%, transparent)`,
      borderRadius: 6,
      padding: "3px 9px"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 6,
      height: 6,
      borderRadius: "50%",
      background: ACC
    }
  }), "governed")), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "0.82fr 1.18fr",
      height: 480
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      background: "#fbfbfa",
      borderRight: "1px solid rgba(0,0,0,0.07)",
      display: "flex",
      flexDirection: "column"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 8,
      padding: "13px 18px",
      borderBottom: "1px solid rgba(0,0,0,0.06)"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      color: INK
    }
  }, rsIcon("M4 6 H20 M4 12 H20 M4 18 H14", 1.6)), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: 13.5,
      color: INK,
      fontWeight: 500
    }
  }, "Conversation")), /*#__PURE__*/React.createElement("div", {
    style: {
      flex: 1,
      display: "flex",
      flexDirection: "column",
      alignItems: "center",
      justifyContent: "center",
      padding: "0 26px",
      textAlign: "center"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 44,
      height: 44,
      borderRadius: 13,
      background: INK,
      display: "grid",
      placeItems: "center",
      color: "#fff",
      marginBottom: 18
    }
  }, /*#__PURE__*/React.createElement(RsLogo, {
    size: 22
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "1.5rem",
      letterSpacing: "-0.01em",
      color: INK
    }
  }, "What should the agent do?"), /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: 12.5,
      color: "var(--color-grey-600)",
      marginTop: 6
    }
  }, "Suggestions \u2014 every run stays inside policy"), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      flexWrap: "wrap",
      gap: 8,
      justifyContent: "center",
      marginTop: 22
    }
  }, chips.map((label, i) => /*#__PURE__*/React.createElement("span", {
    key: label,
    style: {
      display: "inline-flex",
      alignItems: "center",
      gap: 6,
      fontFamily: "var(--font-sans)",
      fontSize: 12.5,
      color: INK,
      background: i === activeChip ? "color-mix(in srgb, var(--color-pistachio-green) 40%, var(--color-white))" : "var(--color-white)",
      border: `0.5px solid ${i === activeChip ? "transparent" : HAIR}`,
      borderRadius: 999,
      padding: "8px 13px",
      transition: "background 0.4s"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 5,
      height: 5,
      borderRadius: "50%",
      background: ACC
    }
  }), label)))), /*#__PURE__*/React.createElement("div", {
    style: {
      margin: "0 16px 16px",
      border: `0.5px solid ${HAIR}`,
      borderRadius: 12,
      background: "var(--color-white)",
      padding: "11px 13px"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: 12.5,
      color: "var(--color-grey-500)"
    }
  }, "Describe a task\u2026"), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 8,
      marginTop: 16
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      display: "inline-flex",
      alignItems: "center",
      gap: 5,
      fontFamily: "var(--font-mono)",
      fontSize: 10.5,
      color: "var(--color-grey-700)",
      border: `0.5px solid ${HAIR}`,
      borderRadius: 6,
      padding: "3px 8px"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 5,
      height: 5,
      borderRadius: "50%",
      background: ACC
    }
  }), "Agent", /*#__PURE__*/React.createElement("svg", {
    width: "9",
    height: "9",
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: "2.4",
    strokeLinecap: "round"
  }, /*#__PURE__*/React.createElement("path", {
    d: "M6 9 L12 15 L18 9"
  }))), /*#__PURE__*/React.createElement("span", {
    style: {
      marginLeft: "auto",
      width: 28,
      height: 28,
      borderRadius: 8,
      background: INK,
      display: "grid",
      placeItems: "center"
    }
  }, /*#__PURE__*/React.createElement("svg", {
    width: "13",
    height: "13",
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "#fff",
    strokeWidth: "2",
    strokeLinecap: "round",
    strokeLinejoin: "round"
  }, /*#__PURE__*/React.createElement("path", {
    d: "M12 19 V5 M6 11 L12 5 L18 11"
  })))))), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      flexDirection: "column",
      background: "#0d0d10"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 18,
      padding: "0 18px",
      height: 38,
      borderBottom: "1px solid rgba(255,255,255,0.07)"
    }
  }, ["PROBLEMS", "OUTPUT", "TERMINAL"].map((tab, i) => /*#__PURE__*/React.createElement("span", {
    key: tab,
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 10.5,
      letterSpacing: "0.06em",
      color: i === 2 ? "rgba(255,255,255,0.9)" : "rgba(255,255,255,0.3)",
      borderBottom: i === 2 ? `1.5px solid ${ACC}` : "1.5px solid transparent",
      height: 38,
      display: "flex",
      alignItems: "center"
    }
  }, tab)), /*#__PURE__*/React.createElement("span", {
    style: {
      marginLeft: "auto",
      fontFamily: "var(--font-mono)",
      fontSize: 10.5,
      color: "rgba(255,255,255,0.3)"
    }
  }, "bash \xB7 sandbox")), /*#__PURE__*/React.createElement("div", {
    style: {
      flex: 1,
      padding: "16px 20px",
      fontFamily: "var(--font-mono)",
      fontSize: 12,
      lineHeight: 1.95,
      overflow: "hidden",
      WebkitMaskImage: "linear-gradient(180deg,#000 78%,transparent)",
      maskImage: "linear-gradient(180deg,#000 78%,transparent)"
    }
  }, shown.map((l, i) => /*#__PURE__*/React.createElement("div", {
    key: i,
    style: {
      display: "flex",
      gap: 9,
      color: termColor[l.c]
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      flex: "none",
      width: 10,
      color: l.c === "block" ? "#ff6b6b" : l.c === "ok" ? ACC : l.c === "cmd" ? "rgba(255,255,255,0.4)" : "rgba(255,255,255,0.18)"
    }
  }, l.c === "block" ? "✕" : l.c === "ok" ? "✓" : l.c === "cmd" ? "›" : "·"), /*#__PURE__*/React.createElement("span", {
    style: {
      whiteSpace: "pre-wrap"
    }
  }, l.s))), shown.length < term.length && /*#__PURE__*/React.createElement("span", {
    style: {
      display: "inline-block",
      width: 7,
      height: 14,
      background: "rgba(255,255,255,0.6)",
      opacity: caretOn ? 0.75 : 0,
      marginLeft: 19
    }
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      borderTop: "1px solid rgba(255,255,255,0.07)",
      padding: "9px 20px",
      display: "flex",
      alignItems: "center",
      gap: 16
    }
  }, [["scope", "fs.read · shell.exec · net.none", "rgba(255,255,255,0.6)"], ["blocked", "1", RED], ["receipt", t > 0.85 ? "signed" : "pending", t > 0.85 ? ACC : "rgba(255,255,255,0.4)"]].map(([k, v, col]) => /*#__PURE__*/React.createElement("span", {
    key: k,
    style: {
      display: "flex",
      alignItems: "center",
      gap: 5,
      fontFamily: "var(--font-mono)",
      fontSize: 10.5
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      color: "rgba(255,255,255,0.3)"
    }
  }, k), /*#__PURE__*/React.createElement("span", {
    style: {
      color: col
    }
  }, v))))))));
}

/* ===================== feature row ===================== */
function RsFeatureRow({
  eyebrow,
  heading,
  body,
  link,
  diagram,
  flip
}) {
  return /*#__PURE__*/React.createElement("div", {
    style: {
      background: "var(--color-white)",
      border: `0.5px solid ${HAIR}`,
      borderRadius: "var(--radius-card)",
      padding: "3rem 3.25rem",
      display: "grid",
      gridTemplateColumns: "1fr 1fr",
      gap: "3rem",
      alignItems: "center"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      order: flip ? 2 : 1
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      display: "inline-block",
      fontFamily: "var(--font-mono)",
      fontSize: 11,
      letterSpacing: "0.08em",
      textTransform: "uppercase",
      color: ACC,
      marginBottom: "0.875rem"
    }
  }, eyebrow), /*#__PURE__*/React.createElement("h3", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.625rem",
      letterSpacing: "-0.02em",
      lineHeight: 1.12,
      margin: 0,
      color: INK
    }
  }, heading), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.0625rem",
      color: "var(--color-grey-800)",
      marginTop: "1rem",
      lineHeight: 1.5,
      maxWidth: "42ch"
    }
  }, body), link && /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: "1.5rem"
    }
  }, /*#__PURE__*/React.createElement(RsLink, {
    href: link[1]
  }, link[0]))), /*#__PURE__*/React.createElement("div", {
    style: {
      order: flip ? 1 : 2,
      display: "flex",
      justifyContent: "center"
    }
  }, diagram));
}

/* ---- scope / tool authority panel ---- */
function ScopeDiagram() {
  const t = rsClock(6000);
  const pulse = (Math.sin(t * Math.PI * 2 * 2) + 1) / 2;
  const tools = [["fs.read", true, "Read files in /src"], ["shell.exec", true, "Run the test suite"], ["fs.write", false, "Write outside /src"], ["net.outbound", false, "External network"], ["secrets.vault", false, "Read raw secrets"]];
  return /*#__PURE__*/React.createElement("div", {
    style: {
      width: "100%",
      maxWidth: 380,
      background: "var(--color-white)",
      border: `0.5px solid ${HAIR}`,
      borderRadius: 14,
      overflow: "hidden",
      boxShadow: "var(--shadow-sm)"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 9,
      padding: "14px 18px",
      borderBottom: `0.5px solid ${HAIR}`
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      color: INK
    }
  }, rsIcon(SHIELD + " M9.5 12 L11 13.5 L14.5 10")), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: 14,
      color: INK
    }
  }, "Tool authority \xB7 9f2c1"), /*#__PURE__*/React.createElement("span", {
    style: {
      marginLeft: "auto",
      display: "flex",
      alignItems: "center",
      gap: 5
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 7,
      height: 7,
      borderRadius: "50%",
      background: ACC,
      boxShadow: `0 0 0 ${3 + pulse * 5}px color-mix(in srgb, ${ACC} 22%, transparent)`
    }
  }), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 10.5,
      color: ACC
    }
  }, "active"))), /*#__PURE__*/React.createElement("div", {
    style: {
      padding: "6px 0"
    }
  }, tools.map(([name, allowed, desc]) => /*#__PURE__*/React.createElement("div", {
    key: name,
    style: {
      display: "flex",
      alignItems: "center",
      gap: 12,
      padding: "10px 18px"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 18,
      height: 18,
      borderRadius: "50%",
      flex: "none",
      background: allowed ? ACC : RED,
      display: "grid",
      placeItems: "center"
    }
  }, allowed ? /*#__PURE__*/React.createElement("svg", {
    width: "10",
    height: "10",
    viewBox: "0 0 12 12",
    fill: "none"
  }, /*#__PURE__*/React.createElement("path", {
    d: "M2.5 6.3 L5 8.5 L9.5 3.7",
    stroke: "#fff",
    strokeWidth: "1.8",
    strokeLinecap: "round",
    strokeLinejoin: "round"
  })) : /*#__PURE__*/React.createElement("svg", {
    width: "9",
    height: "9",
    viewBox: "0 0 12 12",
    fill: "none"
  }, /*#__PURE__*/React.createElement("path", {
    d: "M3 3 L9 9 M9 3 L3 9",
    stroke: "#fff",
    strokeWidth: "1.8",
    strokeLinecap: "round"
  }))), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 12.5,
      color: INK,
      width: 108,
      flex: "none"
    }
  }, name), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: 12,
      color: "var(--color-grey-700)",
      whiteSpace: "nowrap",
      overflow: "hidden",
      textOverflow: "ellipsis"
    }
  }, desc)))));
}

/* ---- policy enforcement log ---- */
function ViolationsDiagram() {
  const t = rsClock(7000);
  const events = [{
    at: 0.08,
    blocked: true,
    text: "net.outbound → registry.evil.sh",
    scope: "net.none"
  }, {
    at: 0.22,
    blocked: false,
    text: "fs.read ← src/payment.ts",
    scope: "fs.read"
  }, {
    at: 0.36,
    blocked: true,
    text: "secrets.read ← .env",
    scope: "not granted"
  }, {
    at: 0.50,
    blocked: false,
    text: "shell.exec → npm test",
    scope: "shell.exec"
  }, {
    at: 0.64,
    blocked: false,
    text: "fs.read ← tests/payment.test.ts",
    scope: "fs.read"
  }, {
    at: 0.78,
    blocked: true,
    text: "net.outbound → api.github.com",
    scope: "net.none"
  }];
  const shown = events.filter(e => t >= e.at);
  return /*#__PURE__*/React.createElement("div", {
    style: {
      width: "100%",
      maxWidth: 380,
      background: "#0d0d10",
      border: "0.5px solid rgba(255,255,255,0.1)",
      borderRadius: 14,
      overflow: "hidden",
      boxShadow: "var(--shadow-md)"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 9,
      padding: "13px 18px",
      borderBottom: "1px solid rgba(255,255,255,0.07)"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 12.5,
      color: "rgba(255,255,255,0.7)"
    }
  }, "Policy enforcement log"), /*#__PURE__*/React.createElement("span", {
    style: {
      marginLeft: "auto",
      fontFamily: "var(--font-mono)",
      fontSize: 10.5,
      color: RED
    }
  }, shown.filter(e => e.blocked).length, " blocked")), /*#__PURE__*/React.createElement("div", {
    style: {
      padding: "6px 0",
      fontFamily: "var(--font-mono)",
      fontSize: 12,
      WebkitMaskImage: "linear-gradient(180deg,#000 65%,transparent)",
      maskImage: "linear-gradient(180deg,#000 65%,transparent)",
      minHeight: 180
    }
  }, shown.map((e, i) => /*#__PURE__*/React.createElement("div", {
    key: i,
    style: {
      display: "flex",
      alignItems: "center",
      gap: 10,
      padding: "8px 18px"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 14,
      height: 14,
      borderRadius: "50%",
      flex: "none",
      background: e.blocked ? RED : ACC,
      display: "grid",
      placeItems: "center"
    }
  }, e.blocked ? /*#__PURE__*/React.createElement("svg", {
    width: "8",
    height: "8",
    viewBox: "0 0 12 12",
    fill: "none"
  }, /*#__PURE__*/React.createElement("path", {
    d: "M3 3 L9 9 M9 3 L3 9",
    stroke: "#fff",
    strokeWidth: "1.8",
    strokeLinecap: "round"
  })) : /*#__PURE__*/React.createElement("svg", {
    width: "8",
    height: "8",
    viewBox: "0 0 12 12",
    fill: "none"
  }, /*#__PURE__*/React.createElement("path", {
    d: "M2.5 6.3 L5 8.5 L9.5 3.7",
    stroke: "#fff",
    strokeWidth: "1.8",
    strokeLinecap: "round",
    strokeLinejoin: "round"
  }))), /*#__PURE__*/React.createElement("span", {
    style: {
      color: e.blocked ? "rgba(255,107,107,0.9)" : "rgba(255,255,255,0.55)",
      flex: 1,
      whiteSpace: "nowrap",
      overflow: "hidden",
      textOverflow: "ellipsis"
    }
  }, e.text), /*#__PURE__*/React.createElement("span", {
    style: {
      color: e.blocked ? "#ff6b6b" : ACC,
      opacity: 0.75,
      flex: "none"
    }
  }, e.scope)))));
}

/* ---- session receipt ---- */
function ReceiptDiagram() {
  const entries = [["started", "session 9f2c1 · scope fs.read, shell.exec"], ["read", "src/payment.ts · src/resolvers/*.ts"], ["exec", "npm test · 243 passed"], ["blocked", "net.outbound × 2 (policy enforced)"], ["signed", "receipt sealed · IOI L1"]];
  return /*#__PURE__*/React.createElement("div", {
    style: {
      width: "100%",
      maxWidth: 380,
      background: "var(--color-white)",
      border: `0.5px solid ${HAIR}`,
      borderRadius: 14,
      boxShadow: "var(--shadow-sm)",
      padding: "20px 22px"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 8,
      marginBottom: 16
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      color: ACC
    }
  }, rsIcon(SHIELD + " M9.5 12 L11 13.5 L14.5 10")), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: 15,
      fontWeight: 600,
      color: INK
    }
  }, "Session receipt"), /*#__PURE__*/React.createElement("span", {
    style: {
      marginLeft: "auto",
      fontFamily: "var(--font-mono)",
      fontSize: 10.5,
      color: ACC,
      border: `0.5px solid ${ACC}`,
      borderRadius: 5,
      padding: "2px 7px"
    }
  }, "verifiable")), /*#__PURE__*/React.createElement("div", {
    style: {
      position: "relative",
      paddingLeft: 18
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      position: "absolute",
      left: 4,
      top: 6,
      bottom: 6,
      width: 1,
      background: HAIR
    }
  }), entries.map(([verb, detail], i) => /*#__PURE__*/React.createElement("div", {
    key: i,
    style: {
      display: "flex",
      gap: 10,
      padding: "7px 0",
      position: "relative"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      position: "absolute",
      left: -18,
      top: 10,
      width: 9,
      height: 9,
      borderRadius: "50%",
      background: i === entries.length - 1 ? ACC : verb === "blocked" ? RED : "var(--color-white)",
      border: `1.5px solid ${i === entries.length - 1 ? ACC : verb === "blocked" ? RED : "var(--color-grey-600)"}`
    }
  }), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 11.5,
      color: verb === "blocked" ? RED : verb === "signed" ? ACC : INK,
      width: 52,
      flex: "none"
    }
  }, verb), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: 12.5,
      color: "var(--color-grey-800)",
      lineHeight: 1.4
    }
  }, detail)))));
}

/* ===================== page ===================== */
function RsHero() {
  return /*#__PURE__*/React.createElement("section", {
    style: {
      ...rswrap,
      paddingTop: "5rem"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      textAlign: "center",
      maxWidth: "42rem",
      margin: "0 auto 3.75rem"
    }
  }, /*#__PURE__*/React.createElement(RsEyebrow, {
    color: ACC
  }, "Solutions \xB7 Runtime AI security"), /*#__PURE__*/React.createElement("h1", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "3.75rem",
      lineHeight: 1.03,
      letterSpacing: "-0.02em",
      margin: "1.25rem 0 0",
      color: INK
    }
  }, "Give agents autonomy,", /*#__PURE__*/React.createElement("br", null), "the kernel keeps control"), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.1875rem",
      color: "var(--color-grey-800)",
      marginTop: "1.25rem",
      lineHeight: 1.5
    }
  }, "Hypervisor enforces security policy at the runtime level \u2014 inside your VPC. Control what agents can execute, access, connect to, and read from memory. Every action receipted."), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      gap: "0.5rem",
      justifyContent: "center",
      marginTop: "2rem"
    }
  }, /*#__PURE__*/React.createElement(RsButton, {
    iconRight: /*#__PURE__*/React.createElement("span", null, "\u2192")
  }, "Get started"), /*#__PURE__*/React.createElement(RsButton, {
    variant: "outline"
  }, "Request early access"))), /*#__PURE__*/React.createElement(AppMockup, null));
}
function RsKernelSection() {
  return /*#__PURE__*/React.createElement("section", {
    style: {
      ...rswrap,
      paddingTop: "8rem"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "0.9fr 1.1fr",
      gap: "4rem",
      alignItems: "center"
    }
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("h2", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "2.5rem",
      letterSpacing: "-0.02em",
      lineHeight: 1.08,
      margin: 0,
      color: INK
    }
  }, "Enforces policy at the kernel level"), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.0625rem",
      color: "var(--color-grey-800)",
      marginTop: "1.25rem",
      lineHeight: 1.55,
      maxWidth: "44ch"
    }
  }, "Hypervisor enforces policy within the kernel, with infrastructure running inside your VPC. You control what agents can execute, access, connect to, and read from memory."), /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: "1.75rem"
    }
  }, /*#__PURE__*/React.createElement(RsLink, {
    href: "platform.html"
  }, "Read the technical deep-dive"))), /*#__PURE__*/React.createElement(ScopeDiagram, null)));
}
function RsFeatures() {
  return /*#__PURE__*/React.createElement("section", {
    style: {
      ...rswrap,
      paddingTop: "6rem",
      display: "flex",
      flexDirection: "column",
      gap: "1.5rem"
    }
  }, /*#__PURE__*/React.createElement(RsFeatureRow, {
    eyebrow: "Policy enforcement",
    heading: "Every call is a request, not a grant",
    body: "Tool calls don't inherit permissions. Each action is evaluated against the session's declared scope \u2014 blocked, allowed, and logged at the kernel level before it executes.",
    flip: false,
    diagram: /*#__PURE__*/React.createElement(ViolationsDiagram, null)
  }), /*#__PURE__*/React.createElement(RsFeatureRow, {
    eyebrow: "Audit",
    heading: "A receipt for every action",
    body: "Every session produces a verifiable receipt \u2014 what was read, executed, blocked, and approved \u2014 logged, traceable, and sealed on IOI L1. Compliance without configuration.",
    link: ["See the receipt format", "platform.html"],
    flip: true,
    diagram: /*#__PURE__*/React.createElement(ReceiptDiagram, null)
  }));
}
function RsStats() {
  const stats = [["0", "Data left on shared infrastructure"], ["100%", "Actions logged before execution"], ["<1ms", "Policy evaluation overhead"]];
  return /*#__PURE__*/React.createElement("section", {
    style: {
      ...rswrap,
      paddingTop: "6rem"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "repeat(3, 1fr)",
      gap: "1.25rem"
    }
  }, stats.map(([value, label]) => /*#__PURE__*/React.createElement("div", {
    key: label,
    style: {
      background: "var(--color-porcelain-grey)",
      border: `0.5px solid ${HAIR}`,
      borderRadius: "var(--radius-card)",
      padding: "2.25rem 2rem"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "3rem",
      lineHeight: 1,
      letterSpacing: "-0.02em",
      color: INK
    }
  }, value), /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "0.9375rem",
      color: "var(--color-grey-700)",
      marginTop: "0.625rem"
    }
  }, label)))));
}
function RsCTA() {
  return /*#__PURE__*/React.createElement("section", {
    style: {
      ...rswrap,
      paddingTop: "8rem",
      textAlign: "center"
    }
  }, /*#__PURE__*/React.createElement("h2", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "3rem",
      letterSpacing: "-0.02em",
      margin: 0,
      color: INK
    }
  }, "Deploy under your policy"), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.0625rem",
      color: "var(--color-grey-800)",
      maxWidth: "44ch",
      margin: "1rem auto 0"
    }
  }, "Hypervisor deploys inside your VPC. Bring your models, your secrets store, and your policies."), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      gap: "0.5rem",
      justifyContent: "center",
      marginTop: "1.75rem"
    }
  }, /*#__PURE__*/React.createElement(RsButton, {
    iconRight: /*#__PURE__*/React.createElement("span", null, "\u2192")
  }, "Get started"), /*#__PURE__*/React.createElement(RsLink, {
    href: "solutions.html"
  }, "Back to solutions")));
}
function HvPage() {
  return /*#__PURE__*/React.createElement("main", null, /*#__PURE__*/React.createElement(RsHero, null), /*#__PURE__*/React.createElement(RsKernelSection, null), /*#__PURE__*/React.createElement(RsFeatures, null), /*#__PURE__*/React.createElement(RsStats, null), /*#__PURE__*/React.createElement(RsCTA, null));
}
window.HvPage = HvPage;
window.HvPageActive = "Solutions";
})(); } catch (e) { __ds_ns.__errors.push({ path: "site/RuntimeSecurity.jsx", error: String((e && e.message) || e) }); }

// site/Solutions.jsx
try { (() => {
// hypervisor.com — Solutions page.
const SNS = window.IoiDesignSystem;
const {
  Button: SgButton,
  Badge: SgBadge,
  Card: SgCard,
  TextLink: SgLink,
  Eyebrow: SgEyebrow
} = SNS;
const swrap = {
  maxWidth: "75rem",
  margin: "0 auto",
  padding: "0 2.5rem"
};
const USECASES = [["Background work", "Task in, pull request out. Delegate work to cloud workers that run end-to-end and return reviewed PRs — keep momentum from any device.", "prim:vcs.pr", "background-work.html"], ["Automations & fleets", "Repeatable workflows triggered on PRs, schedules, or webhooks. Run agent fleets across your codebase with one governed configuration.", "scope:repo.write", "automations-fleets.html"], ["Code modernization", "Migrate deprecated APIs and modernize legacy code with worker fleets — hundreds of repos, every change receipted.", "prim:fs.write", "code-modernization.html"], ["Runtime AI security", "Auto-resolve CVEs, patch vulnerable dependencies, triage Sentry errors, and verify merged changes under scoped authority.", "scope:secrets.read", "runtime-security.html"], ["AI code review", "Review pull requests with workers that carry context, cite evidence, and never act outside their granted scope.", "prim:read", "code-review.html"], ["Worker training", "Turn workflows, traces, and corrections into a deployable specialist worker with Foundry — train for a defined outcome.", "scope:foundry", "worker-training.html"]];
const PATTERNS = ["Automatically resolve CVEs", "Modernize code with agent fleets", "Review pull requests with AI", "Fix bugs from Linear", "Verify merged changes", "Summarize CI failures", "Triage Sentry errors", "Patch vulnerable deps", "Draft release notes", "Pick up backlog work", "Migrate deprecated APIs", "Onboard a new service"];
function HvPage() {
  return /*#__PURE__*/React.createElement("main", null, /*#__PURE__*/React.createElement("section", {
    style: {
      ...swrap,
      paddingTop: "4rem",
      textAlign: "center",
      display: "flex",
      flexDirection: "column",
      alignItems: "center"
    }
  }, /*#__PURE__*/React.createElement(SgEyebrow, {
    color: "var(--color-link-green)"
  }, "Solutions"), /*#__PURE__*/React.createElement("h1", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "3.5rem",
      lineHeight: 1.05,
      letterSpacing: "-0.02em",
      margin: "1.25rem 0 0",
      maxWidth: "18ch",
      color: "var(--color-onyx-black)"
    }
  }, "Put workers to work across your SDLC"), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.1875rem",
      color: "var(--color-grey-800)",
      marginTop: "1.25rem",
      maxWidth: "50ch",
      lineHeight: 1.5
    }
  }, "One-off handoffs and durable automations are different products over the same execution substrate. Every consequential action stays scoped, gated, and receipted."), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      gap: "0.5rem",
      marginTop: "2rem"
    }
  }, /*#__PURE__*/React.createElement(SgButton, {
    iconRight: /*#__PURE__*/React.createElement("span", null, "\u2192")
  }, "Get started"), /*#__PURE__*/React.createElement(SgButton, {
    variant: "outline"
  }, "Request a demo"))), /*#__PURE__*/React.createElement("section", {
    style: {
      ...swrap,
      paddingTop: "5rem"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "repeat(3, 1fr)",
      gap: "1.25rem"
    }
  }, USECASES.map(([t, d, scope, href]) => /*#__PURE__*/React.createElement(SgCard, {
    key: t,
    style: {
      display: "flex",
      flexDirection: "column",
      gap: "0.875rem",
      padding: "1.75rem"
    }
  }, /*#__PURE__*/React.createElement("h3", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.1875rem",
      letterSpacing: "-0.015em",
      margin: 0
    }
  }, t), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "0.9375rem",
      color: "var(--color-grey-800)",
      margin: 0,
      lineHeight: 1.45,
      flex: 1
    }
  }, d), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: "0.875rem"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 11,
      color: "var(--color-link-green)",
      border: "0.5px solid var(--color-grey-500)",
      borderRadius: 6,
      padding: "5px 8px",
      width: "fit-content"
    }
  }, scope), href && /*#__PURE__*/React.createElement("span", {
    style: {
      marginLeft: "auto"
    }
  }, /*#__PURE__*/React.createElement(SgLink, {
    href: href
  }, "Explore"))))))), /*#__PURE__*/React.createElement("section", {
    style: {
      ...swrap,
      paddingTop: "6rem"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      background: "var(--color-porcelain-grey)",
      border: "0.5px solid var(--color-grey-500)",
      borderRadius: "var(--radius-card)",
      padding: "3rem"
    }
  }, /*#__PURE__*/React.createElement("h2", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "2rem",
      letterSpacing: "-0.02em",
      margin: 0,
      maxWidth: "24ch"
    }
  }, "Ready-made patterns your workers run on day one"), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      flexWrap: "wrap",
      gap: "0.625rem",
      marginTop: "1.75rem"
    }
  }, PATTERNS.map(p => /*#__PURE__*/React.createElement("span", {
    key: p,
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "0.9375rem",
      color: "var(--color-grey-900)",
      background: "var(--color-white)",
      border: "0.5px solid var(--color-grey-500)",
      borderRadius: "var(--radius-full)",
      padding: "8px 14px"
    }
  }, p))))), /*#__PURE__*/React.createElement("section", {
    style: {
      ...swrap,
      paddingTop: "6rem",
      display: "grid",
      gridTemplateColumns: "repeat(3, 1fr)",
      gap: "3rem"
    }
  }, [["4x", "productivity increase on modernization work"], ["83%", "of PRs co-authored by Hypervisor workers"], ["400+", "repos modernized in six months"]].map(([v, l]) => /*#__PURE__*/React.createElement("div", {
    key: v
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "3.5rem",
      lineHeight: 1,
      letterSpacing: "-0.02em",
      color: "var(--color-onyx-black)"
    }
  }, v), /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1rem",
      color: "var(--color-grey-800)",
      marginTop: "0.5rem",
      maxWidth: "22ch"
    }
  }, l)))), /*#__PURE__*/React.createElement("section", {
    style: {
      ...swrap,
      paddingTop: "8rem",
      textAlign: "center"
    }
  }, /*#__PURE__*/React.createElement("h2", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "3rem",
      letterSpacing: "-0.02em",
      margin: 0
    }
  }, "Find the workflow that fits"), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      gap: "0.5rem",
      justifyContent: "center",
      marginTop: "1.75rem"
    }
  }, /*#__PURE__*/React.createElement(SgButton, {
    iconRight: /*#__PURE__*/React.createElement("span", null, "\u2192")
  }, "Get started"), /*#__PURE__*/React.createElement(SgLink, {
    href: "platform.html"
  }, "Explore the platform"))));
}
window.HvPage = HvPage;
})(); } catch (e) { __ds_ns.__errors.push({ path: "site/Solutions.jsx", error: String((e && e.message) || e) }); }

// site/WorkerTraining.jsx
try { (() => {
// hypervisor.com — Worker Training (Foundry) solution page.
const WTNS = window.IoiDesignSystem;
const {
  Button: WtButton,
  TextLink: WtLink,
  Eyebrow: WtEyebrow,
  Logo: WtLogo
} = WTNS;
const wtwrap = {
  maxWidth: "75rem",
  margin: "0 auto",
  padding: "0 2.5rem"
};
const INK = "var(--color-onyx-black)";
const HAIR = "var(--color-grey-500)";
const ACC = "var(--color-link-green)";
function wtClock(period) {
  const [t, setT] = React.useState(0);
  React.useEffect(() => {
    const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduce) {
      setT(0.9);
      return;
    }
    let raf,
      start = null;
    const tick = ts => {
      if (start == null) start = ts;
      setT((ts - start) % period / period);
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, []);
  return t;
}
const ease = x => 1 - Math.pow(1 - Math.max(0, Math.min(1, x)), 2.4);

/* ============================================================ *
 * Hero showcase — Foundry training run: eval accuracy climbing
 * ============================================================ */
function FoundryTraining() {
  const t = wtClock(11000);
  const p = ease(Math.min(1, t * 1.12));
  const acc = 0.62 + p * 0.32; // 62% → 94%
  const epoch = Math.min(12, Math.floor(p * 12) + (p > 0 ? 1 : 0));
  const traces = Math.round(120 + p * 1120);
  const done = p > 0.985;

  // chart geometry
  const W = 320,
    H = 132,
    pad = 8;
  const N = 26;
  const pts = [];
  for (let i = 0; i < N; i++) {
    const x = pad + i / (N - 1) * (W - pad * 2);
    const localP = Math.min(1, i / (N - 1) / Math.max(0.001, p)); // only draw up to current progress
    const drawn = i / (N - 1) <= p;
    const yv = 0.62 + ease(i / (N - 1)) * 0.32;
    const y = H - pad - (yv - 0.55) / 0.45 * (H - pad * 2);
    if (drawn) pts.push(`${x},${y}`);
  }
  const baselineY = H - pad - (0.62 - 0.55) / 0.45 * (H - pad * 2);
  const targetY = H - pad - (0.90 - 0.55) / 0.45 * (H - pad * 2);
  const evals = [["Field extraction", 0.96, 0.0], ["Edge-case handling", 0.91, 0.1], ["Format compliance", 0.99, 0.2], ["Refusal accuracy", 0.94, 0.32]];
  return /*#__PURE__*/React.createElement("div", {
    style: {
      width: "100%",
      maxWidth: 1060,
      margin: "0 auto",
      position: "relative"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      position: "absolute",
      inset: -2,
      borderRadius: 18,
      background: "linear-gradient(135deg, color-mix(in srgb, var(--color-pistachio-green) 75%, var(--color-white)), color-mix(in srgb, var(--color-link-green) 32%, var(--color-white)) 55%, var(--color-porcelain-grey))",
      zIndex: 0
    }
  }), /*#__PURE__*/React.createElement("div", {
    style: {
      position: "relative",
      zIndex: 1,
      margin: 6,
      background: "#0d0d10",
      borderRadius: 14,
      overflow: "hidden",
      boxShadow: "0 40px 90px rgba(0,0,0,0.4)"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 11,
      padding: "16px 22px",
      borderBottom: "1px solid rgba(255,255,255,0.07)"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 30,
      height: 30,
      borderRadius: 8,
      background: "rgba(255,255,255,0.08)",
      display: "grid",
      placeItems: "center",
      color: "#fff"
    }
  }, /*#__PURE__*/React.createElement(WtLogo, {
    size: 15
  })), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: 14,
      color: "#fff"
    }
  }, "Foundry \xB7 training run"), /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 11,
      color: "rgba(255,255,255,0.4)",
      marginTop: 1
    }
  }, "worker \xB7 invoice-specialist")), /*#__PURE__*/React.createElement("span", {
    style: {
      marginLeft: "auto",
      display: "flex",
      alignItems: "center",
      gap: 6,
      fontFamily: "var(--font-mono)",
      fontSize: 11,
      color: done ? ACC : "rgba(255,255,255,0.7)",
      border: `1px solid ${done ? "color-mix(in srgb, " + ACC + " 40%, transparent)" : "rgba(255,255,255,0.15)"}`,
      borderRadius: 6,
      padding: "4px 10px"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 6,
      height: 6,
      borderRadius: "50%",
      background: done ? ACC : "rgba(255,255,255,0.5)"
    }
  }), done ? "ready to deploy" : `training · epoch ${epoch}/12`)), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "1.1fr 0.9fr",
      minHeight: 360
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      borderRight: "1px solid rgba(255,255,255,0.07)",
      padding: "22px 24px"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "baseline",
      gap: 10
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 11,
      letterSpacing: "0.06em",
      textTransform: "uppercase",
      color: "rgba(255,255,255,0.4)"
    }
  }, "Eval accuracy"), /*#__PURE__*/React.createElement("span", {
    style: {
      marginLeft: "auto",
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: 38,
      color: "#fff",
      lineHeight: 1
    }
  }, Math.round(acc * 100), /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: 20,
      color: "rgba(255,255,255,0.5)"
    }
  }, "%"))), /*#__PURE__*/React.createElement("svg", {
    width: "100%",
    viewBox: `0 0 ${W} ${H}`,
    style: {
      marginTop: 14,
      display: "block"
    }
  }, /*#__PURE__*/React.createElement("line", {
    x1: pad,
    y1: targetY,
    x2: W - pad,
    y2: targetY,
    stroke: "rgba(255,255,255,0.18)",
    strokeWidth: "1",
    strokeDasharray: "3 4"
  }), /*#__PURE__*/React.createElement("text", {
    x: W - pad,
    y: targetY - 5,
    textAnchor: "end",
    fontFamily: "var(--font-mono)",
    fontSize: "8.5",
    fill: "rgba(255,255,255,0.35)"
  }, "target 90%"), /*#__PURE__*/React.createElement("line", {
    x1: pad,
    y1: baselineY,
    x2: W - pad,
    y2: baselineY,
    stroke: "rgba(255,255,255,0.12)",
    strokeWidth: "1"
  }), /*#__PURE__*/React.createElement("text", {
    x: pad,
    y: baselineY - 5,
    fontFamily: "var(--font-mono)",
    fontSize: "8.5",
    fill: "rgba(255,255,255,0.3)"
  }, "baseline"), pts.length > 1 && /*#__PURE__*/React.createElement("polyline", {
    points: pts.join(" "),
    fill: "none",
    stroke: ACC,
    strokeWidth: "2.2",
    strokeLinecap: "round",
    strokeLinejoin: "round"
  }), pts.length > 0 && (() => {
    const [cx, cy] = pts[pts.length - 1].split(",");
    return /*#__PURE__*/React.createElement("circle", {
      cx: cx,
      cy: cy,
      r: "3.5",
      fill: ACC
    });
  })()), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      gap: 10,
      marginTop: 16
    }
  }, [["Traces ingested", traces.toLocaleString()], ["Corrections", Math.round(p * 86)], ["Epoch", `${epoch}/12`]].map(([k, v]) => /*#__PURE__*/React.createElement("div", {
    key: k,
    style: {
      flex: 1,
      padding: "10px 12px",
      background: "rgba(255,255,255,0.04)",
      borderRadius: 9,
      border: "1px solid rgba(255,255,255,0.06)"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 9.5,
      letterSpacing: "0.05em",
      textTransform: "uppercase",
      color: "rgba(255,255,255,0.35)"
    }
  }, k), /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 15,
      color: "#fff",
      marginTop: 4
    }
  }, v))))), /*#__PURE__*/React.createElement("div", {
    style: {
      padding: "22px 24px"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 11,
      letterSpacing: "0.06em",
      textTransform: "uppercase",
      color: "rgba(255,255,255,0.4)",
      marginBottom: 16
    }
  }, "Evaluation suite"), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      flexDirection: "column",
      gap: 16
    }
  }, evals.map(([label, target, delay]) => {
    const lp = ease(Math.max(0, Math.min(1, (p - delay) / (1 - delay))));
    const val = 0.5 + lp * (target - 0.5);
    const pass = val >= 0.9;
    return /*#__PURE__*/React.createElement("div", {
      key: label
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        display: "flex",
        alignItems: "center",
        gap: 8,
        marginBottom: 7
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        fontFamily: "var(--font-sans)",
        fontSize: 12.5,
        color: "rgba(255,255,255,0.78)"
      }
    }, label), /*#__PURE__*/React.createElement("span", {
      style: {
        marginLeft: "auto",
        fontFamily: "var(--font-mono)",
        fontSize: 11.5,
        color: pass ? ACC : "rgba(255,255,255,0.55)"
      }
    }, Math.round(val * 100), "%")), /*#__PURE__*/React.createElement("div", {
      style: {
        height: 5,
        borderRadius: 3,
        background: "rgba(255,255,255,0.08)",
        overflow: "hidden"
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        height: "100%",
        width: `${val * 100}%`,
        background: pass ? ACC : "rgba(255,255,255,0.4)",
        borderRadius: 3,
        transition: "width 0.2s linear"
      }
    })));
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: 22,
      display: "flex",
      alignItems: "center",
      gap: 9,
      padding: "11px 14px",
      borderRadius: 10,
      background: done ? "color-mix(in srgb, var(--color-link-green) 14%, #0d0d10)" : "rgba(255,255,255,0.04)",
      border: `1px solid ${done ? "color-mix(in srgb, " + ACC + " 45%, transparent)" : "rgba(255,255,255,0.08)"}`,
      transition: "all 0.4s"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 18,
      height: 18,
      borderRadius: "50%",
      flex: "none",
      background: done ? ACC : "rgba(255,255,255,0.15)",
      display: "grid",
      placeItems: "center"
    }
  }, done && /*#__PURE__*/React.createElement("svg", {
    width: "10",
    height: "10",
    viewBox: "0 0 12 12",
    fill: "none"
  }, /*#__PURE__*/React.createElement("path", {
    d: "M2.5 6.3 L5 8.5 L9.5 3.7",
    stroke: "#fff",
    strokeWidth: "1.8",
    strokeLinecap: "round",
    strokeLinejoin: "round"
  }))), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: 12.5,
      color: done ? "#fff" : "rgba(255,255,255,0.55)"
    }
  }, done ? "Meets promotion threshold — deployable" : "Awaiting promotion threshold (90%)"))))));
}

/* ===================== feature row ===================== */
function WtFeatureRow({
  eyebrow,
  heading,
  body,
  link,
  diagram,
  flip
}) {
  return /*#__PURE__*/React.createElement("div", {
    style: {
      background: "var(--color-white)",
      border: `0.5px solid ${HAIR}`,
      borderRadius: "var(--radius-card)",
      padding: "3rem 3.25rem",
      display: "grid",
      gridTemplateColumns: "1fr 1fr",
      gap: "3rem",
      alignItems: "center"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      order: flip ? 2 : 1
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      display: "inline-block",
      fontFamily: "var(--font-mono)",
      fontSize: 11,
      letterSpacing: "0.08em",
      textTransform: "uppercase",
      color: ACC,
      marginBottom: "0.875rem"
    }
  }, eyebrow), /*#__PURE__*/React.createElement("h3", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.625rem",
      letterSpacing: "-0.02em",
      lineHeight: 1.12,
      margin: 0,
      color: INK
    }
  }, heading), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.0625rem",
      color: "var(--color-grey-800)",
      marginTop: "1rem",
      lineHeight: 1.5,
      maxWidth: "42ch"
    }
  }, body), link && /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: "1.5rem"
    }
  }, /*#__PURE__*/React.createElement(WtLink, {
    href: link[1]
  }, link[0]))), /*#__PURE__*/React.createElement("div", {
    style: {
      order: flip ? 1 : 2,
      display: "flex",
      justifyContent: "center"
    }
  }, diagram));
}
const wtIcon = d => /*#__PURE__*/React.createElement("svg", {
  width: "18",
  height: "18",
  viewBox: "0 0 24 24",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: "1.6",
  strokeLinecap: "round",
  strokeLinejoin: "round"
}, /*#__PURE__*/React.createElement("path", {
  d: d
}));

/* ---- training inputs diagram ---- */
function InputsDiagram() {
  const t = wtClock(6500);
  const inputs = [["Session traces", "1,240 governed runs", "M4 6 h16 M4 12 h16 M4 18 h10", 0.0], ["Human corrections", "86 reviewer edits", "M14 6 L18 10 L8 20 L4 20 L4 16 Z", 0.16], ["Workflows", "12 reusable automations", "M3 8 h12 a4 4 0 0 1 0 8 H9 M6 5 L3 8 L6 11", 0.32]];
  const active = Math.floor(t * 4);
  return /*#__PURE__*/React.createElement("div", {
    style: {
      width: "100%",
      maxWidth: 380,
      display: "flex",
      flexDirection: "column",
      gap: 12
    }
  }, inputs.map(([label, meta, d, delay], i) => {
    const on = t >= delay;
    return /*#__PURE__*/React.createElement("div", {
      key: label,
      style: {
        display: "flex",
        alignItems: "center",
        gap: 13,
        background: "var(--color-white)",
        border: `0.5px solid ${HAIR}`,
        borderRadius: 12,
        boxShadow: "var(--shadow-xs)",
        padding: "13px 16px",
        opacity: on ? 1 : 0.45,
        transform: on ? "translateX(0)" : "translateX(-8px)",
        transition: "all 0.4s"
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        width: 34,
        height: 34,
        borderRadius: 9,
        flex: "none",
        background: "var(--color-porcelain-grey)",
        display: "grid",
        placeItems: "center",
        color: INK
      }
    }, wtIcon(d)), /*#__PURE__*/React.createElement("div", {
      style: {
        flex: 1
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        fontFamily: "var(--font-sans)",
        fontSize: 14,
        color: INK
      }
    }, label), /*#__PURE__*/React.createElement("div", {
      style: {
        fontFamily: "var(--font-mono)",
        fontSize: 11,
        color: "var(--color-grey-600)",
        marginTop: 2
      }
    }, meta)), /*#__PURE__*/React.createElement("span", {
      style: {
        width: 16,
        height: 16,
        borderRadius: "50%",
        flex: "none",
        background: ACC,
        display: "grid",
        placeItems: "center"
      }
    }, /*#__PURE__*/React.createElement("svg", {
      width: "9",
      height: "9",
      viewBox: "0 0 12 12",
      fill: "none"
    }, /*#__PURE__*/React.createElement("path", {
      d: "M2.5 6.3 L5 8.5 L9.5 3.7",
      stroke: "#fff",
      strokeWidth: "1.8",
      strokeLinecap: "round",
      strokeLinejoin: "round"
    }))));
  }), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      justifyContent: "center",
      margin: "2px 0"
    }
  }, /*#__PURE__*/React.createElement("svg", {
    width: "20",
    height: "22",
    viewBox: "0 0 20 22",
    fill: "none",
    stroke: "var(--color-grey-500)",
    strokeWidth: "1.5"
  }, /*#__PURE__*/React.createElement("path", {
    d: "M10 1 V17 M5 12 L10 17 L15 12",
    strokeLinecap: "round",
    strokeLinejoin: "round"
  }))), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 13,
      background: INK,
      borderRadius: 12,
      padding: "15px 18px",
      boxShadow: "var(--shadow-md)"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 36,
      height: 36,
      borderRadius: 9,
      flex: "none",
      background: "rgba(255,255,255,0.12)",
      display: "grid",
      placeItems: "center",
      color: "#fff"
    }
  }, /*#__PURE__*/React.createElement(WtLogo, {
    size: 17
  })), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: 14.5,
      color: "#fff"
    }
  }, "invoice-specialist"), /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 11,
      color: "rgba(255,255,255,0.5)",
      marginTop: 2
    }
  }, "specialist worker \xB7 trained in Foundry"))));
}

/* ---- deploy / package diagram ---- */
function DeployDiagram() {
  const t = wtClock(7000);
  const deployed = t > 0.55;
  return /*#__PURE__*/React.createElement("div", {
    style: {
      width: "100%",
      maxWidth: 380,
      background: "var(--color-white)",
      border: `0.5px solid ${HAIR}`,
      borderRadius: 14,
      boxShadow: "var(--shadow-sm)",
      overflow: "hidden"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 11,
      padding: "16px 18px",
      borderBottom: `0.5px solid ${HAIR}`
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 36,
      height: 36,
      borderRadius: 9,
      flex: "none",
      background: INK,
      display: "grid",
      placeItems: "center",
      color: "#fff"
    }
  }, /*#__PURE__*/React.createElement(WtLogo, {
    size: 17
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      flex: 1
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: 15,
      color: INK
    }
  }, "invoice-specialist"), /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 11,
      color: "var(--color-grey-600)",
      marginTop: 2
    }
  }, "v1.0 \xB7 94% eval \xB7 signed")), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 10.5,
      color: ACC,
      border: `0.5px solid ${ACC}`,
      borderRadius: 5,
      padding: "3px 8px"
    }
  }, "verified")), /*#__PURE__*/React.createElement("div", {
    style: {
      padding: "14px 18px",
      display: "flex",
      flexDirection: "column",
      gap: 11
    }
  }, [["Scope", "fs.read · invoice.parse"], ["Runtime", "any · cloud / VPC / cTEE"], ["Benchmark", "94% · promoted"]].map(([k, v]) => /*#__PURE__*/React.createElement("div", {
    key: k,
    style: {
      display: "flex",
      alignItems: "center",
      justifyContent: "space-between"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: 12.5,
      color: "var(--color-grey-700)"
    }
  }, k), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: 12,
      color: INK
    }
  }, v)))), /*#__PURE__*/React.createElement("div", {
    style: {
      padding: "0 18px 18px"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      gap: 9,
      padding: "12px",
      borderRadius: 10,
      background: deployed ? "color-mix(in srgb, var(--color-pistachio-green) 40%, var(--color-white))" : "var(--color-porcelain-grey)",
      border: `0.5px solid ${deployed ? "transparent" : HAIR}`,
      transition: "background 0.4s"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      width: 16,
      height: 16,
      borderRadius: "50%",
      background: deployed ? ACC : "var(--color-grey-500)",
      display: "grid",
      placeItems: "center"
    }
  }, deployed && /*#__PURE__*/React.createElement("svg", {
    width: "9",
    height: "9",
    viewBox: "0 0 12 12",
    fill: "none"
  }, /*#__PURE__*/React.createElement("path", {
    d: "M2.5 6.3 L5 8.5 L9.5 3.7",
    stroke: "#fff",
    strokeWidth: "1.8",
    strokeLinecap: "round",
    strokeLinejoin: "round"
  }))), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: 13.5,
      color: INK
    }
  }, deployed ? "Deployed to production" : "Deploying…"))));
}

/* ===================== page ===================== */
function WtHero() {
  return /*#__PURE__*/React.createElement("section", {
    style: {
      ...wtwrap,
      paddingTop: "5rem"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      textAlign: "center",
      maxWidth: "44rem",
      margin: "0 auto 3.75rem"
    }
  }, /*#__PURE__*/React.createElement(WtEyebrow, {
    color: ACC
  }, "Solutions \xB7 Worker training"), /*#__PURE__*/React.createElement("h1", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "3.75rem",
      lineHeight: 1.03,
      letterSpacing: "-0.02em",
      margin: "1.25rem 0 0",
      color: INK
    }
  }, "Train a specialist", /*#__PURE__*/React.createElement("br", null), "for the work you do"), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.1875rem",
      color: "var(--color-grey-800)",
      marginTop: "1.25rem",
      lineHeight: 1.5
    }
  }, "Turn workflows, traces, and corrections into a deployable specialist worker with Foundry \u2014 trained for a defined outcome and evaluated before it ships."), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      gap: "0.5rem",
      justifyContent: "center",
      marginTop: "2rem"
    }
  }, /*#__PURE__*/React.createElement(WtButton, {
    iconRight: /*#__PURE__*/React.createElement("span", null, "\u2192")
  }, "Get started"), /*#__PURE__*/React.createElement(WtButton, {
    variant: "outline"
  }, "Request a demo"))), /*#__PURE__*/React.createElement(FoundryTraining, null));
}
function WtInputsSection() {
  return /*#__PURE__*/React.createElement("section", {
    style: {
      ...wtwrap,
      paddingTop: "8rem"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "0.9fr 1.1fr",
      gap: "4rem",
      alignItems: "center"
    }
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("h2", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "2.5rem",
      letterSpacing: "-0.02em",
      lineHeight: 1.08,
      margin: 0,
      color: INK
    }
  }, "Learns from how your team actually works"), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.0625rem",
      color: "var(--color-grey-800)",
      marginTop: "1.25rem",
      lineHeight: 1.55,
      maxWidth: "44ch"
    }
  }, "Foundry trains on the receipts you already produce \u2014 governed session traces, reviewer corrections, and the workflows your team runs. No labeling project, no data leaving your boundary."), /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: "1.75rem"
    }
  }, /*#__PURE__*/React.createElement(WtLink, {
    href: "platform.html"
  }, "How Foundry works"))), /*#__PURE__*/React.createElement(InputsDiagram, null)));
}
function WtFeatures() {
  return /*#__PURE__*/React.createElement("section", {
    style: {
      ...wtwrap,
      paddingTop: "6rem",
      display: "flex",
      flexDirection: "column",
      gap: "1.5rem"
    }
  }, /*#__PURE__*/React.createElement(WtFeatureRow, {
    eyebrow: "Deploy",
    heading: "Ship it as a governed, versioned worker",
    body: "A trained worker is a package \u2014 versioned, benchmarked, and signed. Deploy it under scoped authority on any runtime, and settle its work the same way as any other worker.",
    link: ["Read the worker spec", "platform.html"],
    flip: false,
    diagram: /*#__PURE__*/React.createElement(DeployDiagram, null)
  }));
}
function WtStats() {
  const stats = [["94%", "Eval accuracy before it ships"], ["0", "Labeling projects required"], ["Any runtime", "Cloud · VPC · cTEE"]];
  return /*#__PURE__*/React.createElement("section", {
    style: {
      ...wtwrap,
      paddingTop: "6rem"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "repeat(3, 1fr)",
      gap: "1.25rem"
    }
  }, stats.map(([value, label]) => /*#__PURE__*/React.createElement("div", {
    key: label,
    style: {
      background: "var(--color-porcelain-grey)",
      border: `0.5px solid ${HAIR}`,
      borderRadius: "var(--radius-card)",
      padding: "2.25rem 2rem"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "2.75rem",
      lineHeight: 1.05,
      letterSpacing: "-0.02em",
      color: INK
    }
  }, value), /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "0.9375rem",
      color: "var(--color-grey-700)",
      marginTop: "0.625rem"
    }
  }, label)))));
}
function WtCTA() {
  return /*#__PURE__*/React.createElement("section", {
    style: {
      ...wtwrap,
      paddingTop: "8rem",
      textAlign: "center"
    }
  }, /*#__PURE__*/React.createElement("h2", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "3rem",
      letterSpacing: "-0.02em",
      margin: 0,
      color: INK
    }
  }, "Train your first specialist"), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      gap: "0.5rem",
      justifyContent: "center",
      marginTop: "1.75rem"
    }
  }, /*#__PURE__*/React.createElement(WtButton, {
    iconRight: /*#__PURE__*/React.createElement("span", null, "\u2192")
  }, "Get started"), /*#__PURE__*/React.createElement(WtLink, {
    href: "solutions.html"
  }, "Back to solutions")));
}
function HvPage() {
  return /*#__PURE__*/React.createElement("main", null, /*#__PURE__*/React.createElement(WtHero, null), /*#__PURE__*/React.createElement(WtInputsSection, null), /*#__PURE__*/React.createElement(WtFeatures, null), /*#__PURE__*/React.createElement(WtStats, null), /*#__PURE__*/React.createElement(WtCTA, null));
}
window.HvPage = HvPage;
window.HvPageActive = "Solutions";
})(); } catch (e) { __ds_ns.__errors.push({ path: "site/WorkerTraining.jsx", error: String((e && e.message) || e) }); }

// site/WorkersMotion.jsx
try { (() => {
// Workers-section motion — count-up stats + a native octahedron-facet field.
// The facet field is the on-brand echo of the IOI mark (a triangulated
// octahedron), used in place of a borrowed round-dot grid.
const {
  useState,
  useEffect,
  useRef,
  useReducer,
  useMemo
} = React;

/* tiny shared store so the Tweaks panel can drive both pieces */
const _store = window.__hvMotion = window.__hvMotion || {
  statCount: true,
  triField: true,
  subs: new Set()
};
function setMotion(patch) {
  Object.assign(_store, patch);
  _store.subs.forEach(f => f());
}
function useMotion() {
  const [, force] = useReducer(x => x + 1, 0);
  useEffect(() => {
    _store.subs.add(force);
    return () => {
      _store.subs.delete(force);
    };
  }, []);
  return _store;
}
const REDUCED = typeof window !== "undefined" && window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
function useInView(threshold) {
  const ref = useRef(null);
  const [seen, setSeen] = useState(false);
  useEffect(() => {
    const el = ref.current;
    if (!el || seen) return;
    let done = false;
    const check = () => {
      if (done) return;
      const r = el.getBoundingClientRect();
      const vh = window.innerHeight || document.documentElement.clientHeight;
      if (r.top < vh * 0.9 && r.bottom > vh * 0.06) {
        done = true;
        setSeen(true);
        cleanup();
      }
    };
    const cleanup = () => {
      window.removeEventListener("scroll", check, true);
      window.removeEventListener("resize", check);
    };
    window.addEventListener("scroll", check, true);
    window.addEventListener("resize", check);
    check();
    const t1 = setTimeout(check, 300);
    const t2 = setTimeout(check, 1200);
    return () => {
      cleanup();
      clearTimeout(t1);
      clearTimeout(t2);
    };
  }, [seen]);
  return [ref, seen];
}

/* ---- odometer-style count up ---- */
function CountStat({
  to,
  decimals = 0,
  prefix = "",
  suffix = "",
  style
}) {
  const motion = useMotion();
  const [ref, seen] = useInView(0.45);
  const [val, setVal] = useState(motion.statCount && !REDUCED ? 0 : to);
  useEffect(() => {
    if (!motion.statCount || REDUCED) {
      setVal(to);
      return;
    }
    if (!seen) {
      setVal(0);
      return;
    }
    let raf;
    const t0 = performance.now();
    const dur = 1500;
    const tick = now => {
      const p = Math.min(1, (now - t0) / dur);
      const e = 1 - Math.pow(1 - p, 3);
      setVal(to * e);
      if (p < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [seen, motion.statCount, to]);
  const num = val.toLocaleString("en-US", {
    minimumFractionDigits: decimals,
    maximumFractionDigits: decimals
  });
  return /*#__PURE__*/React.createElement("div", {
    ref: ref,
    style: style
  }, prefix, num, suffix);
}

/* ---- triangulated facet field ---- */
function buildFacets(W, H, g, t) {
  const out = [];
  for (let r = 0; r * g <= H; r++) {
    const cy = r * g;
    for (let c = 0; c * g <= W; c++) {
      const cx = c * g + (r % 2 ? g / 2 : 0);
      if (cx > W) continue;
      const up = (r + c) % 2 === 0;
      const pts = up ? `${cx},${(cy - t).toFixed(1)} ${(cx + t * 0.87).toFixed(1)},${(cy + t * 0.5).toFixed(1)} ${(cx - t * 0.87).toFixed(1)},${(cy + t * 0.5).toFixed(1)}` : `${cx},${(cy + t).toFixed(1)} ${(cx + t * 0.87).toFixed(1)},${(cy - t * 0.5).toFixed(1)} ${(cx - t * 0.87).toFixed(1)},${(cy - t * 0.5).toFixed(1)}`;
      // vertical falloff (fade top/bottom) + organic jitter
      const vf = Math.sin(Math.PI * (cy / H));
      const op = Math.max(0, 0.6 * vf * (0.55 + 0.45 * ((Math.sin(cx * 12.9 + cy * 78.2) + 1) / 2)));
      out.push({
        pts,
        cx,
        op
      });
    }
  }
  return out;
}
function TriField({
  side
}) {
  const motion = useMotion();
  const [ref, seen] = useInView(0.25);
  const W = 168,
    H = 256,
    g = 18,
    t = 4.4;
  const facets = useMemo(() => buildFacets(W, H, g, t), []);
  if (!motion.triField) return null;
  const outer = side === "left" ? "left" : "right";
  const fade = side === "left" ? "linear-gradient(to right, transparent 4%, #000 78%)" : "linear-gradient(to left, transparent 4%, #000 78%)";
  const pos = side === "left" ? {
    right: "100%",
    marginRight: "1.75rem"
  } : {
    left: "100%",
    marginLeft: "1.75rem"
  };
  return /*#__PURE__*/React.createElement("div", {
    ref: ref,
    className: "hv-trifield",
    "data-in": seen ? 1 : 0,
    "aria-hidden": "true",
    style: {
      position: "absolute",
      top: "50%",
      transform: "translateY(-50%)",
      width: W,
      height: H,
      zIndex: 0,
      pointerEvents: "none",
      WebkitMaskImage: fade,
      maskImage: fade,
      ...pos
    }
  }, /*#__PURE__*/React.createElement("svg", {
    width: W,
    height: H,
    viewBox: `0 0 ${W} ${H}`,
    fill: "none"
  }, facets.map((f, i) => {
    const dnorm = side === "left" ? (W - f.cx) / W : f.cx / W; // inner edge first
    const delay = (dnorm * 0.4 + i % 6 * 0.015).toFixed(3);
    return /*#__PURE__*/React.createElement("polygon", {
      key: i,
      className: "tri",
      points: f.pts,
      fill: "var(--color-link-green)",
      style: {
        fillOpacity: f.op,
        animationDelay: `${delay}s`
      }
    });
  })));
}
window.WorkersMotion = {
  CountStat,
  TriField,
  setMotion,
  useMotion
};
})(); } catch (e) { __ds_ns.__errors.push({ path: "site/WorkersMotion.jsx", error: String((e && e.message) || e) }); }

// site/tweaks-panel.jsx
try { (() => {
// @ds-adherence-ignore -- omelette starter scaffold (raw elements/hex/px by design)

/* BEGIN USAGE */
// tweaks-panel.jsx
// Reusable Tweaks shell + form-control helpers.
// Exports (to window): useTweaks, TweaksPanel, TweakSection, TweakRow, TweakSlider,
//   TweakToggle, TweakRadio, TweakSelect, TweakText, TweakNumber, TweakColor, TweakButton.
//
// Owns the host protocol (listens for __activate_edit_mode / __deactivate_edit_mode,
// posts __edit_mode_available / __edit_mode_set_keys / __edit_mode_dismissed) so
// individual prototypes don't re-roll it. Ships a consistent set of controls so you
// don't hand-draw <input type="range">, segmented radios, steppers, etc.
//
// Usage (in an HTML file that loads React + Babel):
//
//   const TWEAK_DEFAULTS = /*EDITMODE-BEGIN*/{
//     "primaryColor": "#D97757",
//     "palette": ["#D97757", "#29261b", "#f6f4ef"],
//     "fontSize": 16,
//     "density": "regular",
//     "dark": false
//   }/*EDITMODE-END*/;
//
//   function App() {
//     const [t, setTweak] = useTweaks(TWEAK_DEFAULTS);
//     return (
//       <div style={{ fontSize: t.fontSize, color: t.primaryColor }}>
//         Hello
//         <TweaksPanel>
//           <TweakSection label="Typography" />
//           <TweakSlider label="Font size" value={t.fontSize} min={10} max={32} unit="px"
//                        onChange={(v) => setTweak('fontSize', v)} />
//           <TweakRadio  label="Density" value={t.density}
//                        options={['compact', 'regular', 'comfy']}
//                        onChange={(v) => setTweak('density', v)} />
//           <TweakSection label="Theme" />
//           <TweakColor  label="Primary" value={t.primaryColor}
//                        options={['#D97757', '#2A6FDB', '#1F8A5B', '#7A5AE0']}
//                        onChange={(v) => setTweak('primaryColor', v)} />
//           <TweakColor  label="Palette" value={t.palette}
//                        options={[['#D97757', '#29261b', '#f6f4ef'],
//                                  ['#475569', '#0f172a', '#f1f5f9']]}
//                        onChange={(v) => setTweak('palette', v)} />
//           <TweakToggle label="Dark mode" value={t.dark}
//                        onChange={(v) => setTweak('dark', v)} />
//         </TweaksPanel>
//       </div>
//     );
//   }
//
// TweakRadio is the segmented control for 2–3 short options (auto-falls-back to
// TweakSelect past ~16/~10 chars per label); reach for TweakSelect directly when
// options are many or long. For color tweaks always curate 3-4 options rather than
// a free picker; an option can also be a whole 2–5 color palette (the stored value
// is the array). The Tweak* controls are a floor, not a ceiling — build custom
// controls inside the panel if a tweak calls for UI they don't cover.
/* END USAGE */
// ─────────────────────────────────────────────────────────────────────────────

const __TWEAKS_STYLE = `
  .twk-panel{position:fixed;right:16px;bottom:16px;z-index:2147483646;width:280px;
    max-height:calc(100vh - 32px);display:flex;flex-direction:column;
    transform:scale(var(--dc-inv-zoom,1));transform-origin:bottom right;
    background:rgba(250,249,247,.78);color:#29261b;
    -webkit-backdrop-filter:blur(24px) saturate(160%);backdrop-filter:blur(24px) saturate(160%);
    border:.5px solid rgba(255,255,255,.6);border-radius:14px;
    box-shadow:0 1px 0 rgba(255,255,255,.5) inset,0 12px 40px rgba(0,0,0,.18);
    font:11.5px/1.4 ui-sans-serif,system-ui,-apple-system,sans-serif;overflow:hidden}
  .twk-hd{display:flex;align-items:center;justify-content:space-between;
    padding:10px 8px 10px 14px;cursor:move;user-select:none}
  .twk-hd b{font-size:12px;font-weight:600;letter-spacing:.01em}
  .twk-x{appearance:none;border:0;background:transparent;color:rgba(41,38,27,.55);
    width:22px;height:22px;border-radius:6px;cursor:default;font-size:13px;line-height:1}
  .twk-x:hover{background:rgba(0,0,0,.06);color:#29261b}
  .twk-body{padding:2px 14px 14px;display:flex;flex-direction:column;gap:10px;
    overflow-y:auto;overflow-x:hidden;min-height:0;
    scrollbar-width:thin;scrollbar-color:rgba(0,0,0,.15) transparent}
  .twk-body::-webkit-scrollbar{width:8px}
  .twk-body::-webkit-scrollbar-track{background:transparent;margin:2px}
  .twk-body::-webkit-scrollbar-thumb{background:rgba(0,0,0,.15);border-radius:4px;
    border:2px solid transparent;background-clip:content-box}
  .twk-body::-webkit-scrollbar-thumb:hover{background:rgba(0,0,0,.25);
    border:2px solid transparent;background-clip:content-box}
  .twk-row{display:flex;flex-direction:column;gap:5px}
  .twk-row-h{flex-direction:row;align-items:center;justify-content:space-between;gap:10px}
  .twk-lbl{display:flex;justify-content:space-between;align-items:baseline;
    color:rgba(41,38,27,.72)}
  .twk-lbl>span:first-child{font-weight:500}
  .twk-val{color:rgba(41,38,27,.5);font-variant-numeric:tabular-nums}

  .twk-sect{font-size:10px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;
    color:rgba(41,38,27,.45);padding:10px 0 0}
  .twk-sect:first-child{padding-top:0}

  .twk-field{appearance:none;box-sizing:border-box;width:100%;min-width:0;height:26px;padding:0 8px;
    border:.5px solid rgba(0,0,0,.1);border-radius:7px;
    background:rgba(255,255,255,.6);color:inherit;font:inherit;outline:none}
  .twk-field:focus{border-color:rgba(0,0,0,.25);background:rgba(255,255,255,.85)}
  select.twk-field{padding-right:22px;
    background-image:url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='10' height='6' viewBox='0 0 10 6'><path fill='rgba(0,0,0,.5)' d='M0 0h10L5 6z'/></svg>");
    background-repeat:no-repeat;background-position:right 8px center}

  .twk-slider{appearance:none;-webkit-appearance:none;width:100%;height:4px;margin:6px 0;
    border-radius:999px;background:rgba(0,0,0,.12);outline:none}
  .twk-slider::-webkit-slider-thumb{-webkit-appearance:none;appearance:none;
    width:14px;height:14px;border-radius:50%;background:#fff;
    border:.5px solid rgba(0,0,0,.12);box-shadow:0 1px 3px rgba(0,0,0,.2);cursor:default}
  .twk-slider::-moz-range-thumb{width:14px;height:14px;border-radius:50%;
    background:#fff;border:.5px solid rgba(0,0,0,.12);box-shadow:0 1px 3px rgba(0,0,0,.2);cursor:default}

  .twk-seg{position:relative;display:flex;padding:2px;border-radius:8px;
    background:rgba(0,0,0,.06);user-select:none}
  .twk-seg-thumb{position:absolute;top:2px;bottom:2px;border-radius:6px;
    background:rgba(255,255,255,.9);box-shadow:0 1px 2px rgba(0,0,0,.12);
    transition:left .15s cubic-bezier(.3,.7,.4,1),width .15s}
  .twk-seg.dragging .twk-seg-thumb{transition:none}
  .twk-seg button{appearance:none;position:relative;z-index:1;flex:1;border:0;
    background:transparent;color:inherit;font:inherit;font-weight:500;min-height:22px;
    border-radius:6px;cursor:default;padding:4px 6px;line-height:1.2;
    overflow-wrap:anywhere}

  .twk-toggle{position:relative;width:32px;height:18px;border:0;border-radius:999px;
    background:rgba(0,0,0,.15);transition:background .15s;cursor:default;padding:0}
  .twk-toggle[data-on="1"]{background:#34c759}
  .twk-toggle i{position:absolute;top:2px;left:2px;width:14px;height:14px;border-radius:50%;
    background:#fff;box-shadow:0 1px 2px rgba(0,0,0,.25);transition:transform .15s}
  .twk-toggle[data-on="1"] i{transform:translateX(14px)}

  .twk-num{display:flex;align-items:center;box-sizing:border-box;min-width:0;height:26px;padding:0 0 0 8px;
    border:.5px solid rgba(0,0,0,.1);border-radius:7px;background:rgba(255,255,255,.6)}
  .twk-num-lbl{font-weight:500;color:rgba(41,38,27,.6);cursor:ew-resize;
    user-select:none;padding-right:8px}
  .twk-num input{flex:1;min-width:0;height:100%;border:0;background:transparent;
    font:inherit;font-variant-numeric:tabular-nums;text-align:right;padding:0 8px 0 0;
    outline:none;color:inherit;-moz-appearance:textfield}
  .twk-num input::-webkit-inner-spin-button,.twk-num input::-webkit-outer-spin-button{
    -webkit-appearance:none;margin:0}
  .twk-num-unit{padding-right:8px;color:rgba(41,38,27,.45)}

  .twk-btn{appearance:none;height:26px;padding:0 12px;border:0;border-radius:7px;
    background:rgba(0,0,0,.78);color:#fff;font:inherit;font-weight:500;cursor:default}
  .twk-btn:hover{background:rgba(0,0,0,.88)}
  .twk-btn.secondary{background:rgba(0,0,0,.06);color:inherit}
  .twk-btn.secondary:hover{background:rgba(0,0,0,.1)}

  .twk-swatch{appearance:none;-webkit-appearance:none;width:56px;height:22px;
    border:.5px solid rgba(0,0,0,.1);border-radius:6px;padding:0;cursor:default;
    background:transparent;flex-shrink:0}
  .twk-swatch::-webkit-color-swatch-wrapper{padding:0}
  .twk-swatch::-webkit-color-swatch{border:0;border-radius:5.5px}
  .twk-swatch::-moz-color-swatch{border:0;border-radius:5.5px}

  .twk-chips{display:flex;gap:6px}
  .twk-chip{position:relative;appearance:none;flex:1;min-width:0;height:46px;
    padding:0;border:0;border-radius:6px;overflow:hidden;cursor:default;
    box-shadow:0 0 0 .5px rgba(0,0,0,.12),0 1px 2px rgba(0,0,0,.06);
    transition:transform .12s cubic-bezier(.3,.7,.4,1),box-shadow .12s}
  .twk-chip:hover{transform:translateY(-1px);
    box-shadow:0 0 0 .5px rgba(0,0,0,.18),0 4px 10px rgba(0,0,0,.12)}
  .twk-chip[data-on="1"]{box-shadow:0 0 0 1.5px rgba(0,0,0,.85),
    0 2px 6px rgba(0,0,0,.15)}
  .twk-chip>span{position:absolute;top:0;bottom:0;right:0;width:34%;
    display:flex;flex-direction:column;box-shadow:-1px 0 0 rgba(0,0,0,.1)}
  .twk-chip>span>i{flex:1;box-shadow:0 -1px 0 rgba(0,0,0,.1)}
  .twk-chip>span>i:first-child{box-shadow:none}
  .twk-chip svg{position:absolute;top:6px;left:6px;width:13px;height:13px;
    filter:drop-shadow(0 1px 1px rgba(0,0,0,.3))}
`;

// ── useTweaks ───────────────────────────────────────────────────────────────
// Single source of truth for tweak values. setTweak persists via the host
// (__edit_mode_set_keys → host rewrites the EDITMODE block on disk).
function useTweaks(defaults) {
  const [values, setValues] = React.useState(defaults);
  // Accepts either setTweak('key', value) or setTweak({ key: value, ... }) so a
  // useState-style call doesn't write a "[object Object]" key into the persisted
  // JSON block.
  const setTweak = React.useCallback((keyOrEdits, val) => {
    const edits = typeof keyOrEdits === 'object' && keyOrEdits !== null ? keyOrEdits : {
      [keyOrEdits]: val
    };
    setValues(prev => ({
      ...prev,
      ...edits
    }));
    window.parent.postMessage({
      type: '__edit_mode_set_keys',
      edits
    }, '*');
    // Same-window signal so in-page listeners (deck-stage rail thumbnails)
    // can react — the parent message only reaches the host, not peers.
    window.dispatchEvent(new CustomEvent('tweakchange', {
      detail: edits
    }));
  }, []);
  return [values, setTweak];
}

// ── TweaksPanel ─────────────────────────────────────────────────────────────
// Floating shell. Registers the protocol listener BEFORE announcing
// availability — if the announce ran first, the host's activate could land
// before our handler exists and the toolbar toggle would silently no-op.
// The close button posts __edit_mode_dismissed so the host's toolbar toggle
// flips off in lockstep; the host echoes __deactivate_edit_mode back which
// is what actually hides the panel.
function TweaksPanel({
  title = 'Tweaks',
  children
}) {
  const [open, setOpen] = React.useState(false);
  const dragRef = React.useRef(null);
  const offsetRef = React.useRef({
    x: 16,
    y: 16
  });
  const PAD = 16;
  const clampToViewport = React.useCallback(() => {
    const panel = dragRef.current;
    if (!panel) return;
    const w = panel.offsetWidth,
      h = panel.offsetHeight;
    const maxRight = Math.max(PAD, window.innerWidth - w - PAD);
    const maxBottom = Math.max(PAD, window.innerHeight - h - PAD);
    offsetRef.current = {
      x: Math.min(maxRight, Math.max(PAD, offsetRef.current.x)),
      y: Math.min(maxBottom, Math.max(PAD, offsetRef.current.y))
    };
    panel.style.right = offsetRef.current.x + 'px';
    panel.style.bottom = offsetRef.current.y + 'px';
  }, []);
  React.useEffect(() => {
    if (!open) return;
    clampToViewport();
    if (typeof ResizeObserver === 'undefined') {
      window.addEventListener('resize', clampToViewport);
      return () => window.removeEventListener('resize', clampToViewport);
    }
    const ro = new ResizeObserver(clampToViewport);
    ro.observe(document.documentElement);
    return () => ro.disconnect();
  }, [open, clampToViewport]);
  React.useEffect(() => {
    const onMsg = e => {
      const t = e?.data?.type;
      if (t === '__activate_edit_mode') setOpen(true);else if (t === '__deactivate_edit_mode') setOpen(false);
    };
    window.addEventListener('message', onMsg);
    window.parent.postMessage({
      type: '__edit_mode_available'
    }, '*');
    return () => window.removeEventListener('message', onMsg);
  }, []);
  const dismiss = () => {
    setOpen(false);
    window.parent.postMessage({
      type: '__edit_mode_dismissed'
    }, '*');
  };
  const onDragStart = e => {
    const panel = dragRef.current;
    if (!panel) return;
    const r = panel.getBoundingClientRect();
    const sx = e.clientX,
      sy = e.clientY;
    const startRight = window.innerWidth - r.right;
    const startBottom = window.innerHeight - r.bottom;
    const move = ev => {
      offsetRef.current = {
        x: startRight - (ev.clientX - sx),
        y: startBottom - (ev.clientY - sy)
      };
      clampToViewport();
    };
    const up = () => {
      window.removeEventListener('mousemove', move);
      window.removeEventListener('mouseup', up);
    };
    window.addEventListener('mousemove', move);
    window.addEventListener('mouseup', up);
  };
  if (!open) return null;
  return /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("style", null, __TWEAKS_STYLE), /*#__PURE__*/React.createElement("div", {
    ref: dragRef,
    className: "twk-panel",
    "data-omelette-chrome": "",
    style: {
      right: offsetRef.current.x,
      bottom: offsetRef.current.y
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "twk-hd",
    onMouseDown: onDragStart
  }, /*#__PURE__*/React.createElement("b", null, title), /*#__PURE__*/React.createElement("button", {
    className: "twk-x",
    "aria-label": "Close tweaks",
    onMouseDown: e => e.stopPropagation(),
    onClick: dismiss
  }, "\u2715")), /*#__PURE__*/React.createElement("div", {
    className: "twk-body"
  }, children)));
}

// ── Layout helpers ──────────────────────────────────────────────────────────

function TweakSection({
  label,
  children
}) {
  return /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("div", {
    className: "twk-sect"
  }, label), children);
}
function TweakRow({
  label,
  value,
  children,
  inline = false
}) {
  return /*#__PURE__*/React.createElement("div", {
    className: inline ? 'twk-row twk-row-h' : 'twk-row'
  }, /*#__PURE__*/React.createElement("div", {
    className: "twk-lbl"
  }, /*#__PURE__*/React.createElement("span", null, label), value != null && /*#__PURE__*/React.createElement("span", {
    className: "twk-val"
  }, value)), children);
}

// ── Controls ────────────────────────────────────────────────────────────────

function TweakSlider({
  label,
  value,
  min = 0,
  max = 100,
  step = 1,
  unit = '',
  onChange
}) {
  return /*#__PURE__*/React.createElement(TweakRow, {
    label: label,
    value: `${value}${unit}`
  }, /*#__PURE__*/React.createElement("input", {
    type: "range",
    className: "twk-slider",
    min: min,
    max: max,
    step: step,
    value: value,
    onChange: e => onChange(Number(e.target.value))
  }));
}
function TweakToggle({
  label,
  value,
  onChange
}) {
  return /*#__PURE__*/React.createElement("div", {
    className: "twk-row twk-row-h"
  }, /*#__PURE__*/React.createElement("div", {
    className: "twk-lbl"
  }, /*#__PURE__*/React.createElement("span", null, label)), /*#__PURE__*/React.createElement("button", {
    type: "button",
    className: "twk-toggle",
    "data-on": value ? '1' : '0',
    role: "switch",
    "aria-checked": !!value,
    onClick: () => onChange(!value)
  }, /*#__PURE__*/React.createElement("i", null)));
}
function TweakRadio({
  label,
  value,
  options,
  onChange
}) {
  const trackRef = React.useRef(null);
  const [dragging, setDragging] = React.useState(false);
  // The active value is read by pointer-move handlers attached for the lifetime
  // of a drag — ref it so a stale closure doesn't fire onChange for every move.
  const valueRef = React.useRef(value);
  valueRef.current = value;

  // Segments wrap mid-word once per-segment width runs out. The track is
  // ~248px (280 panel − 28 body pad − 4 seg pad), each button loses 12px
  // to its own padding, and 11.5px system-ui averages ~6.3px/char — so 2
  // options fit ~16 chars each, 3 fit ~10. Past that (or >3 options), fall
  // back to a dropdown rather than wrap.
  const labelLen = o => String(typeof o === 'object' ? o.label : o).length;
  const maxLen = options.reduce((m, o) => Math.max(m, labelLen(o)), 0);
  const fitsAsSegments = maxLen <= ({
    2: 16,
    3: 10
  }[options.length] ?? 0);
  if (!fitsAsSegments) {
    // <select> emits strings — map back to the original option value so the
    // fallback stays type-preserving (numbers, booleans) like the segment path.
    const resolve = s => {
      const m = options.find(o => String(typeof o === 'object' ? o.value : o) === s);
      return m === undefined ? s : typeof m === 'object' ? m.value : m;
    };
    return /*#__PURE__*/React.createElement(TweakSelect, {
      label: label,
      value: value,
      options: options,
      onChange: s => onChange(resolve(s))
    });
  }
  const opts = options.map(o => typeof o === 'object' ? o : {
    value: o,
    label: o
  });
  const idx = Math.max(0, opts.findIndex(o => o.value === value));
  const n = opts.length;
  const segAt = clientX => {
    const r = trackRef.current.getBoundingClientRect();
    const inner = r.width - 4;
    const i = Math.floor((clientX - r.left - 2) / inner * n);
    return opts[Math.max(0, Math.min(n - 1, i))].value;
  };
  const onPointerDown = e => {
    setDragging(true);
    const v0 = segAt(e.clientX);
    if (v0 !== valueRef.current) onChange(v0);
    const move = ev => {
      if (!trackRef.current) return;
      const v = segAt(ev.clientX);
      if (v !== valueRef.current) onChange(v);
    };
    const up = () => {
      setDragging(false);
      window.removeEventListener('pointermove', move);
      window.removeEventListener('pointerup', up);
    };
    window.addEventListener('pointermove', move);
    window.addEventListener('pointerup', up);
  };
  return /*#__PURE__*/React.createElement(TweakRow, {
    label: label
  }, /*#__PURE__*/React.createElement("div", {
    ref: trackRef,
    role: "radiogroup",
    onPointerDown: onPointerDown,
    className: dragging ? 'twk-seg dragging' : 'twk-seg'
  }, /*#__PURE__*/React.createElement("div", {
    className: "twk-seg-thumb",
    style: {
      left: `calc(2px + ${idx} * (100% - 4px) / ${n})`,
      width: `calc((100% - 4px) / ${n})`
    }
  }), opts.map(o => /*#__PURE__*/React.createElement("button", {
    key: o.value,
    type: "button",
    role: "radio",
    "aria-checked": o.value === value
  }, o.label))));
}
function TweakSelect({
  label,
  value,
  options,
  onChange
}) {
  return /*#__PURE__*/React.createElement(TweakRow, {
    label: label
  }, /*#__PURE__*/React.createElement("select", {
    className: "twk-field",
    value: value,
    onChange: e => onChange(e.target.value)
  }, options.map(o => {
    const v = typeof o === 'object' ? o.value : o;
    const l = typeof o === 'object' ? o.label : o;
    return /*#__PURE__*/React.createElement("option", {
      key: v,
      value: v
    }, l);
  })));
}
function TweakText({
  label,
  value,
  placeholder,
  onChange
}) {
  return /*#__PURE__*/React.createElement(TweakRow, {
    label: label
  }, /*#__PURE__*/React.createElement("input", {
    className: "twk-field",
    type: "text",
    value: value,
    placeholder: placeholder,
    onChange: e => onChange(e.target.value)
  }));
}
function TweakNumber({
  label,
  value,
  min,
  max,
  step = 1,
  unit = '',
  onChange
}) {
  const clamp = n => {
    if (min != null && n < min) return min;
    if (max != null && n > max) return max;
    return n;
  };
  const startRef = React.useRef({
    x: 0,
    val: 0
  });
  const onScrubStart = e => {
    e.preventDefault();
    startRef.current = {
      x: e.clientX,
      val: value
    };
    const decimals = (String(step).split('.')[1] || '').length;
    const move = ev => {
      const dx = ev.clientX - startRef.current.x;
      const raw = startRef.current.val + dx * step;
      const snapped = Math.round(raw / step) * step;
      onChange(clamp(Number(snapped.toFixed(decimals))));
    };
    const up = () => {
      window.removeEventListener('pointermove', move);
      window.removeEventListener('pointerup', up);
    };
    window.addEventListener('pointermove', move);
    window.addEventListener('pointerup', up);
  };
  return /*#__PURE__*/React.createElement("div", {
    className: "twk-num"
  }, /*#__PURE__*/React.createElement("span", {
    className: "twk-num-lbl",
    onPointerDown: onScrubStart
  }, label), /*#__PURE__*/React.createElement("input", {
    type: "number",
    value: value,
    min: min,
    max: max,
    step: step,
    onChange: e => onChange(clamp(Number(e.target.value)))
  }), unit && /*#__PURE__*/React.createElement("span", {
    className: "twk-num-unit"
  }, unit));
}

// Relative-luminance contrast pick — checkmarks drawn over a swatch need to
// read on both #111 and #fafafa without per-option configuration. Hex input
// only (#rgb / #rrggbb); named or rgb()/hsl() colors fall through to "light".
function __twkIsLight(hex) {
  const h = String(hex).replace('#', '');
  const x = h.length === 3 ? h.replace(/./g, c => c + c) : h.padEnd(6, '0');
  const n = parseInt(x.slice(0, 6), 16);
  if (Number.isNaN(n)) return true;
  const r = n >> 16 & 255,
    g = n >> 8 & 255,
    b = n & 255;
  return r * 299 + g * 587 + b * 114 > 148000;
}
const __TwkCheck = ({
  light
}) => /*#__PURE__*/React.createElement("svg", {
  viewBox: "0 0 14 14",
  "aria-hidden": "true"
}, /*#__PURE__*/React.createElement("path", {
  d: "M3 7.2 5.8 10 11 4.2",
  fill: "none",
  strokeWidth: "2.2",
  strokeLinecap: "round",
  strokeLinejoin: "round",
  stroke: light ? 'rgba(0,0,0,.78)' : '#fff'
}));

// TweakColor — curated color/palette picker. Each option is either a single
// hex string or an array of 1-5 hex strings; the card adapts — a lone color
// renders solid, a palette renders colors[0] as the hero (left ~2/3) with the
// rest stacked in a sharp column on the right. onChange emits the
// option in the shape it was passed (string stays string, array stays array).
// Without options it falls back to the native color input for back-compat.
function TweakColor({
  label,
  value,
  options,
  onChange
}) {
  if (!options || !options.length) {
    return /*#__PURE__*/React.createElement("div", {
      className: "twk-row twk-row-h"
    }, /*#__PURE__*/React.createElement("div", {
      className: "twk-lbl"
    }, /*#__PURE__*/React.createElement("span", null, label)), /*#__PURE__*/React.createElement("input", {
      type: "color",
      className: "twk-swatch",
      value: value,
      onChange: e => onChange(e.target.value)
    }));
  }
  // Native <input type=color> emits lowercase hex per the HTML spec, so
  // compare case-insensitively. String() guards JSON.stringify(undefined),
  // which returns the primitive undefined (no .toLowerCase).
  const key = o => String(JSON.stringify(o)).toLowerCase();
  const cur = key(value);
  return /*#__PURE__*/React.createElement(TweakRow, {
    label: label
  }, /*#__PURE__*/React.createElement("div", {
    className: "twk-chips",
    role: "radiogroup"
  }, options.map((o, i) => {
    const colors = Array.isArray(o) ? o : [o];
    const [hero, ...rest] = colors;
    const sup = rest.slice(0, 4);
    const on = key(o) === cur;
    return /*#__PURE__*/React.createElement("button", {
      key: i,
      type: "button",
      className: "twk-chip",
      role: "radio",
      "aria-checked": on,
      "data-on": on ? '1' : '0',
      "aria-label": colors.join(', '),
      title: colors.join(' · '),
      style: {
        background: hero
      },
      onClick: () => onChange(o)
    }, sup.length > 0 && /*#__PURE__*/React.createElement("span", null, sup.map((c, j) => /*#__PURE__*/React.createElement("i", {
      key: j,
      style: {
        background: c
      }
    }))), on && /*#__PURE__*/React.createElement(__TwkCheck, {
      light: __twkIsLight(hero)
    }));
  })));
}
function TweakButton({
  label,
  onClick,
  secondary = false
}) {
  return /*#__PURE__*/React.createElement("button", {
    type: "button",
    className: secondary ? 'twk-btn secondary' : 'twk-btn',
    onClick: onClick
  }, label);
}
Object.assign(window, {
  useTweaks,
  TweaksPanel,
  TweakSection,
  TweakRow,
  TweakSlider,
  TweakToggle,
  TweakRadio,
  TweakSelect,
  TweakText,
  TweakNumber,
  TweakColor,
  TweakButton
});
})(); } catch (e) { __ds_ns.__errors.push({ path: "site/tweaks-panel.jsx", error: String((e && e.message) || e) }); }

// ui_kits/website/BlogScreen.jsx
try { (() => {
// Blog index + single post (ioi-branded, IOI design system).
const {
  Badge: BBadge,
  TextLink: BLink
} = window.IoiDesignSystem;
const ALL_POSTS = [["ioi is joining the action layer", "Our life's work just got bigger. Today we're announcing the next chapter for ioi and the future of software engineering agents.", "AI", "June 11, 2026", "Johannes Landgraf"], ["The last year of localhost", "The companies winning with background agents didn't start with better models. They standardized their development environments years ago — and now those environments run agents at scale.", "Platform", "Feb 13, 2026", "Pauline Narvas"], ["How agents escape their own denylist and sandbox", "The adversary can reason now, and our security tools weren't built for that. A look at what runtime AI security really requires.", "Security", "Mar 3, 2026", "Leonardo Di Donato"], ["Auto-resolving CVEs with agent fleets", "How a fleet of background agents triaged, patched, and shipped fixes for 200+ vulnerabilities across a Fortune 100 codebase.", "Engineering", "Jan 28, 2026", "Sofia Reyes"], ["Bank-grade guardrails for autonomous agents", "Fine-grained policies, scoped credentials, and kernel-level enforcement — the controls that let regulated teams say yes to agents.", "Security", "Dec 9, 2025", "Leonardo Di Donato"], ["What we learned running 1M agent sessions", "Patterns, failure modes, and the infrastructure decisions that kept a million cloud agent sessions fast and safe.", "Platform", "Nov 18, 2025", "Pauline Narvas"]];
function BlogScreen({
  onNav
}) {
  const [feature, ...rest] = ALL_POSTS;
  return /*#__PURE__*/React.createElement("main", {
    style: {
      maxWidth: "75rem",
      margin: "0 auto",
      padding: "3rem 2.5rem 0"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: "0.75rem",
      textTransform: "uppercase",
      letterSpacing: "0.08em",
      color: "var(--color-grey-700)"
    }
  }, "Blog"), /*#__PURE__*/React.createElement("h1", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "3.5rem",
      letterSpacing: "-0.02em",
      margin: "0.75rem 0 0"
    }
  }, "Stories from the team"), /*#__PURE__*/React.createElement("div", {
    onClick: () => onNav("post"),
    style: {
      cursor: "pointer",
      display: "grid",
      gridTemplateColumns: "1.1fr 1fr",
      gap: "2.5rem",
      alignItems: "center",
      marginTop: "3rem",
      padding: "2rem",
      border: "0.5px solid var(--color-grey-500)",
      borderRadius: "var(--radius-card)"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      aspectRatio: "16/10",
      borderRadius: "var(--radius-lg)",
      background: "var(--color-porcelain-grey)",
      border: "0.5px solid var(--color-grey-500)",
      overflow: "hidden",
      padding: 24
    }
  }, /*#__PURE__*/React.createElement(DotMatrix, {
    seed: 3,
    cols: 10,
    rows: 7
  })), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      gap: 8,
      alignItems: "center"
    }
  }, /*#__PURE__*/React.createElement(BBadge, {
    tone: "outline"
  }, feature[2]), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: "0.75rem",
      color: "var(--color-grey-700)"
    }
  }, feature[3])), /*#__PURE__*/React.createElement("h2", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "2.25rem",
      lineHeight: 1.08,
      letterSpacing: "-0.02em",
      margin: "1rem 0 0"
    }
  }, feature[0]), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.0625rem",
      color: "var(--color-grey-800)",
      marginTop: "1rem",
      lineHeight: 1.45
    }
  }, feature[1]), /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: "1.5rem"
    }
  }, /*#__PURE__*/React.createElement(BLink, null, "Read the story")))), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "repeat(3, 1fr)",
      gap: "1.5rem",
      marginTop: "1.5rem"
    }
  }, rest.map(p => /*#__PURE__*/React.createElement("article", {
    key: p[0],
    onClick: () => onNav("post"),
    style: {
      cursor: "pointer",
      display: "flex",
      flexDirection: "column",
      gap: "1rem",
      padding: "1.5rem",
      border: "0.5px solid var(--color-grey-500)",
      borderRadius: "var(--radius-card)"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      aspectRatio: "16/10",
      borderRadius: "var(--radius-lg)",
      background: "var(--color-porcelain-grey)",
      border: "0.5px solid var(--color-grey-500)",
      overflow: "hidden",
      padding: 16
    }
  }, /*#__PURE__*/React.createElement(DotMatrix, {
    seed: p[0].length,
    cols: 8,
    rows: 6
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      gap: 8,
      alignItems: "center"
    }
  }, /*#__PURE__*/React.createElement(BBadge, {
    tone: "outline"
  }, p[2]), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: "0.75rem",
      color: "var(--color-grey-700)"
    }
  }, p[3])), /*#__PURE__*/React.createElement("h3", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.1875rem",
      letterSpacing: "-0.02em",
      margin: 0,
      lineHeight: 1.2
    }
  }, p[0]), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "0.9375rem",
      color: "var(--color-grey-800)",
      margin: 0,
      lineHeight: 1.4
    }
  }, p[1].slice(0, 110), "\u2026")))));
}
function PostScreen({
  onNav
}) {
  return /*#__PURE__*/React.createElement("main", {
    style: {
      maxWidth: "44rem",
      margin: "0 auto",
      padding: "3rem 2.5rem 0"
    }
  }, /*#__PURE__*/React.createElement(BLink, {
    onClick: () => onNav("blog"),
    arrow: false
  }, "\u2190 All stories"), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      gap: 8,
      alignItems: "center",
      marginTop: "2rem"
    }
  }, /*#__PURE__*/React.createElement(BBadge, {
    tone: "outline"
  }, "Platform"), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: "0.75rem",
      color: "var(--color-grey-700)"
    }
  }, "Feb 13, 2026 \xB7 6 min read")), /*#__PURE__*/React.createElement("h1", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "3rem",
      lineHeight: 1.06,
      letterSpacing: "-0.02em",
      margin: "1.25rem 0 0"
    }
  }, "The last year of localhost"), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 12,
      marginTop: "1.5rem"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      width: 36,
      height: 36,
      borderRadius: "50%",
      background: "var(--color-pistachio-green)",
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      fontFamily: "var(--font-mono)",
      fontSize: 13,
      color: "var(--color-moss-green)"
    }
  }, "PN"), /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "0.9375rem",
      color: "var(--color-grey-800)"
    }
  }, "Pauline Narvas")), /*#__PURE__*/React.createElement("div", {
    style: {
      aspectRatio: "16/8",
      borderRadius: "var(--radius-card)",
      background: "var(--color-porcelain-grey)",
      border: "0.5px solid var(--color-grey-500)",
      overflow: "hidden",
      padding: 28,
      margin: "2.5rem 0"
    }
  }, /*#__PURE__*/React.createElement(DotMatrix, {
    seed: 5,
    cols: 14,
    rows: 6
  })), ["The companies winning with background agents didn't start with better models. They standardized their development environments years ago — and now those environments run agents at scale.", "For a decade, \"works on my machine\" was a punchline. The real cost was invisible: every laptop a slightly different snowflake, every onboarding a multi-day yak-shave, every CI failure a debugging session into someone else's $PATH.", "When you hand a task to an agent, that variance becomes a liability. An agent can't reason its way around a missing system dependency or a credential that only lives in one engineer's keychain. It needs a clean, reproducible, governed place to work — every time.", "That place is a connected environment: a full cloud machine with your tools, your network access, and your permissions, spun up on demand and torn down when the work is done. Move the agents off laptops and into the cloud, and the whole model changes."].map((para, i) => /*#__PURE__*/React.createElement("p", {
    key: i,
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.1875rem",
      lineHeight: 1.6,
      color: "var(--color-grey-900)",
      margin: "0 0 1.5rem"
    }
  }, para)), /*#__PURE__*/React.createElement("h2", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.5rem",
      letterSpacing: "-0.02em",
      margin: "2.5rem 0 1rem"
    }
  }, "Standardize first, automate second"), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.1875rem",
      lineHeight: 1.6,
      color: "var(--color-grey-900)",
      margin: "0 0 1.5rem"
    }
  }, "The teams getting leverage from agents treated the environment as the product. Once execution is standardized, automation is a configuration change, not a re-platforming."));
}
window.BlogScreen = BlogScreen;
window.PostScreen = PostScreen;
})(); } catch (e) { __ds_ns.__errors.push({ path: "ui_kits/website/BlogScreen.jsx", error: String((e && e.message) || e) }); }

// ui_kits/website/DotMatrix.jsx
try { (() => {
// Decorative dot-matrix — greyscale dots whose shade follows a soft diagonal
// gradient, echoing the illustrations in the homepage feature cards.
function DotMatrix({
  cols = 11,
  rows = 11,
  gap = 22,
  dot = 7,
  seed = 0
}) {
  const shades = ["#E6E6E6", "#A9A9A9", "#1F1F1F"];
  const dots = [];
  for (let r = 0; r < rows; r++) {
    for (let c = 0; c < cols; c++) {
      const t = Math.sin((c + seed) * 0.6) + Math.cos((r + seed) * 0.55) + (c - r) * 0.12;
      const idx = t > 0.9 ? 2 : t > -0.2 ? 1 : 0;
      const cx = c * gap + gap / 2;
      const cy = r * gap + gap / 2;
      dots.push(/*#__PURE__*/React.createElement("g", {
        key: `${r}-${c}`
      }, /*#__PURE__*/React.createElement("circle", {
        cx: cx,
        cy: cy,
        r: dot,
        fill: shades[idx]
      }), /*#__PURE__*/React.createElement("circle", {
        cx: cx,
        cy: cy,
        r: dot - 0.4,
        fill: "none",
        stroke: "rgba(0,0,0,0.1)",
        strokeWidth: "0.7"
      })));
    }
  }
  const w = cols * gap,
    h = rows * gap;
  return /*#__PURE__*/React.createElement("svg", {
    viewBox: `0 0 ${w} ${h}`,
    width: "100%",
    height: "100%",
    "aria-hidden": "true",
    style: {
      display: "block"
    }
  }, dots);
}
window.DotMatrix = DotMatrix;
})(); } catch (e) { __ds_ns.__errors.push({ path: "ui_kits/website/DotMatrix.jsx", error: String((e && e.message) || e) }); }

// ui_kits/website/HomeScreen.jsx
try { (() => {
// Homepage recreation (ioi-branded, IOI design system).
const {
  Button: HButton,
  Badge: HBadge,
  Stat: HStat,
  TextLink: HLink,
  Card: HCard
} = window.IoiDesignSystem;
const FEATURES = [["Background agents", "Task in, pull request out. ioi executes end-to-end in the background. Keep momentum from any device.", "See how agents work", 0], ["Automations", "Agent fleets at scale. Triggered across your codebase with repeatable workflows that run on PRs, schedules, or webhooks.", "Explore automations", 3], ["Connected environments", "More than a sandbox. Each agent gets a full cloud environment with your tools, network access, and permissions.", "Tour environments", 6], ["Runtime AI security", "Runs in your VPC with complete network control. Audit trails, scoped credentials, and kernel-level policy enforcement.", "See the security model", 9]];
const POSTS = [["ioi is joining the action layer", "Our life's work just got bigger.", "AI", "June 11, 2026"], ["The last year of localhost", "The companies winning with background agents standardized their dev environments years ago — and now those environments run agents at scale.", "Platform", "Feb 13, 2026"], ["How agents escape their sandbox", "The adversary can reason now, and our security tools weren't built for that.", "Security", "Mar 3, 2026"]];
function HomeScreen({
  onNav
}) {
  return /*#__PURE__*/React.createElement("main", null, /*#__PURE__*/React.createElement("section", {
    style: {
      maxWidth: "75rem",
      margin: "0 auto",
      padding: "2rem 2.5rem 0",
      textAlign: "center",
      display: "flex",
      flexDirection: "column",
      alignItems: "center"
    }
  }, /*#__PURE__*/React.createElement("h1", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "4rem",
      lineHeight: 1.05,
      letterSpacing: "-0.02em",
      margin: 0,
      maxWidth: "14ch",
      color: "var(--color-onyx-black)"
    }
  }, "The platform for background agents"), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.125rem",
      color: "var(--color-grey-800)",
      marginTop: "1.25rem",
      maxWidth: "44ch"
    }
  }, "Run a team of AI software engineers in the cloud. Orchestrated, governed, secured at the kernel."), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      gap: "0.5rem",
      marginTop: "2rem"
    }
  }, /*#__PURE__*/React.createElement(HButton, {
    onClick: () => onNav("pricing")
  }, "Get started"), /*#__PURE__*/React.createElement(HButton, {
    variant: "outline"
  }, "Request a demo"))), /*#__PURE__*/React.createElement("section", {
    style: {
      maxWidth: "75rem",
      margin: "0 auto",
      padding: "3rem 2.5rem 0"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      position: "relative",
      borderRadius: "var(--radius-card)",
      overflow: "hidden",
      border: "0.5px solid var(--color-grey-500)",
      aspectRatio: "455/256",
      background: "url(/assets/textures/pistachio-noise.png) center/cover"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      position: "absolute",
      inset: 0,
      display: "flex",
      alignItems: "center",
      justifyContent: "center"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      width: 64,
      height: 64,
      borderRadius: "50%",
      background: "rgba(255,255,255,0.9)",
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      boxShadow: "var(--shadow-md)"
    }
  }, /*#__PURE__*/React.createElement("svg", {
    width: "20",
    height: "24",
    viewBox: "0 0 42 49",
    fill: "none"
  }, /*#__PURE__*/React.createElement("path", {
    fill: "var(--color-onyx-black)",
    d: "M0 48.333V0l41.083 24.167L0 48.333Z"
  })))), /*#__PURE__*/React.createElement("span", {
    style: {
      position: "absolute",
      left: 20,
      bottom: 16,
      fontFamily: "var(--font-mono)",
      fontSize: "0.75rem",
      color: "var(--color-moss-green)",
      background: "rgba(255,255,255,0.75)",
      padding: "5px 10px",
      borderRadius: 6
    }
  }, "ioi \xB7 product tour"))), /*#__PURE__*/React.createElement("section", {
    style: {
      maxWidth: "75rem",
      margin: "0 auto",
      padding: "8rem 2.5rem 0"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      background: "var(--color-white)",
      border: "0.5px solid var(--color-grey-500)",
      borderRadius: "var(--radius-card)",
      overflow: "hidden"
    }
  }, /*#__PURE__*/React.createElement("h2", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.9375rem",
      lineHeight: 1.1,
      letterSpacing: "-0.02em",
      padding: "3rem 3rem 2.25rem",
      margin: 0
    }
  }, "The AI engineering workforce.", /*#__PURE__*/React.createElement("br", null), /*#__PURE__*/React.createElement("span", {
    style: {
      color: "var(--color-grey-700)"
    }
  }, "Set the direction. ioi runs the execution. Continuously and autonomously.")), /*#__PURE__*/React.createElement("div", {
    style: {
      borderTop: "1px solid var(--color-grey-500)",
      display: "grid",
      gridTemplateColumns: "1fr 1fr"
    }
  }, FEATURES.map(([title, body, link, seed], i) => /*#__PURE__*/React.createElement("div", {
    key: title,
    style: {
      display: "flex",
      alignItems: "flex-start",
      gap: "2rem",
      padding: "3.5rem 3rem",
      borderBottom: i < 2 ? "1px solid var(--color-grey-500)" : "none",
      borderRight: i % 2 === 0 ? "1px solid var(--color-grey-500)" : "none"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      flex: 1,
      minWidth: 0,
      paddingTop: "1.5rem"
    }
  }, /*#__PURE__*/React.createElement("h3", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.25rem",
      lineHeight: 1.1,
      letterSpacing: "-0.02em",
      margin: 0
    }
  }, title), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1rem",
      color: "var(--color-grey-800)",
      marginTop: "1rem",
      lineHeight: 1.35
    }
  }, body), /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: "1.5rem"
    }
  }, /*#__PURE__*/React.createElement(HLink, null, link))), /*#__PURE__*/React.createElement("div", {
    style: {
      width: "40%",
      maxWidth: 200,
      aspectRatio: "1",
      flexShrink: 0
    }
  }, /*#__PURE__*/React.createElement(DotMatrix, {
    seed: seed
  }))))))), /*#__PURE__*/React.createElement("section", {
    style: {
      maxWidth: "75rem",
      margin: "0 auto",
      padding: "8rem 2.5rem 0"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "repeat(3, 1fr)",
      gap: "3rem"
    }
  }, /*#__PURE__*/React.createElement(HStat, {
    value: "4x",
    label: "productivity increase"
  }), /*#__PURE__*/React.createElement(HStat, {
    value: "83%",
    label: "of PRs co-authored by ioi"
  }), /*#__PURE__*/React.createElement(HStat, {
    value: "400+",
    label: "Python repos modernized in 6 months"
  }))), /*#__PURE__*/React.createElement("section", {
    style: {
      maxWidth: "75rem",
      margin: "0 auto",
      padding: "8rem 2.5rem 0"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "baseline",
      justifyContent: "space-between",
      marginBottom: "2rem"
    }
  }, /*#__PURE__*/React.createElement("h2", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "2.75rem",
      letterSpacing: "-0.02em",
      margin: 0
    }
  }, "From the blog"), /*#__PURE__*/React.createElement(HLink, {
    onClick: () => onNav("blog")
  }, "Read all stories")), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "repeat(3, 1fr)",
      gap: "1.5rem"
    }
  }, POSTS.map(([title, body, tag, date]) => /*#__PURE__*/React.createElement("div", {
    key: title,
    onClick: () => onNav("post"),
    style: {
      cursor: "pointer"
    }
  }, /*#__PURE__*/React.createElement(HCard, {
    style: {
      height: "100%",
      display: "flex",
      flexDirection: "column",
      gap: "1rem"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      aspectRatio: "16/10",
      borderRadius: "var(--radius-lg)",
      background: "var(--color-porcelain-grey)",
      border: "0.5px solid var(--color-grey-500)",
      overflow: "hidden",
      padding: 18
    }
  }, /*#__PURE__*/React.createElement(DotMatrix, {
    seed: title.length,
    cols: 8,
    rows: 6
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      gap: 8
    }
  }, /*#__PURE__*/React.createElement(HBadge, {
    tone: "outline"
  }, tag), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: "0.75rem",
      color: "var(--color-grey-700)",
      alignSelf: "center"
    }
  }, date)), /*#__PURE__*/React.createElement("h3", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.25rem",
      letterSpacing: "-0.02em",
      margin: 0
    }
  }, title), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "0.9375rem",
      color: "var(--color-grey-800)",
      margin: 0,
      lineHeight: 1.4
    }
  }, body)))))));
}
window.HomeScreen = HomeScreen;
})(); } catch (e) { __ds_ns.__errors.push({ path: "ui_kits/website/HomeScreen.jsx", error: String((e && e.message) || e) }); }

// ui_kits/website/PricingScreen.jsx
try { (() => {
// Pricing recreation (ioi-branded, IOI design system).
const {
  Button: PButton,
  Badge: PBadge,
  TextLink: PLink
} = window.IoiDesignSystem;
const CHECK = /*#__PURE__*/React.createElement("svg", {
  width: "16",
  height: "16",
  viewBox: "0 0 16 16",
  fill: "none",
  style: {
    flexShrink: 0,
    marginTop: 3
  }
}, /*#__PURE__*/React.createElement("path", {
  d: "M3 8.5l3.2 3.2L13 5",
  stroke: "var(--color-link-green)",
  strokeWidth: "1.5",
  strokeLinecap: "round",
  strokeLinejoin: "round"
}));
const TIERS = [{
  name: "Core",
  price: "$20",
  unit: "/ month",
  blurb: "For individuals and small teams getting started with background agents.",
  cta: "Get started",
  theme: "outline",
  feat: ["Full VS Code in the browser", "Background & ambient agents", "Connect GitHub & GitLab", "Bring your own AI model", "Community support"]
}, {
  name: "Enterprise",
  price: "Custom",
  unit: "",
  blurb: "For organizations running agent fleets with governance and security.",
  featured: true,
  cta: "Request a demo",
  theme: "fill",
  feat: ["Everything in Core", "Deploy in your own VPC", "Kernel-level policy enforcement", "Audit trails & scoped credentials", "SOC 2 · GDPR · SSO / SCIM", "Dedicated support & SLA"]
}];
function PricingScreen() {
  return /*#__PURE__*/React.createElement("main", {
    style: {
      maxWidth: "75rem",
      margin: "0 auto",
      padding: "3rem 2.5rem 0"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      textAlign: "center",
      display: "flex",
      flexDirection: "column",
      alignItems: "center"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: "0.75rem",
      textTransform: "uppercase",
      letterSpacing: "0.08em",
      color: "var(--color-grey-700)"
    }
  }, "Pricing"), /*#__PURE__*/React.createElement("h1", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "3.5rem",
      lineHeight: 1.05,
      letterSpacing: "-0.02em",
      margin: "1rem 0 0",
      maxWidth: "18ch"
    }
  }, "Usage-based. Priced to scale with your team."), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.125rem",
      color: "var(--color-grey-800)",
      marginTop: "1.25rem",
      maxWidth: "46ch"
    }
  }, "Start in minutes. Move to your own VPC when you're ready to run agents at scale.")), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "1fr 1fr",
      gap: "1.5rem",
      marginTop: "3.5rem",
      alignItems: "start"
    }
  }, TIERS.map(t => /*#__PURE__*/React.createElement("div", {
    key: t.name,
    style: {
      borderRadius: "var(--radius-card)",
      padding: "2.5rem",
      border: t.featured ? "1px solid var(--color-onyx-black)" : "0.5px solid var(--color-grey-500)",
      background: t.featured ? "var(--color-onyx-black)" : "var(--color-white)",
      color: t.featured ? "var(--color-white)" : "var(--color-onyx-black)"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 10
    }
  }, /*#__PURE__*/React.createElement("h2", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.25rem",
      margin: 0
    }
  }, t.name), t.featured && /*#__PURE__*/React.createElement(PBadge, {
    tone: "green"
  }, "Most popular")), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "baseline",
      gap: 8,
      marginTop: "1.5rem"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "3.5rem",
      lineHeight: 1,
      letterSpacing: "-0.02em"
    }
  }, t.price), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1rem",
      color: t.featured ? "var(--color-grey-600)" : "var(--color-grey-700)"
    }
  }, t.unit)), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "0.9375rem",
      color: t.featured ? "var(--color-grey-600)" : "var(--color-grey-800)",
      marginTop: "1rem",
      lineHeight: 1.4
    }
  }, t.blurb), /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: "1.75rem"
    }
  }, /*#__PURE__*/React.createElement(PButton, {
    variant: t.theme,
    theme: t.featured ? "white" : "onyx",
    style: {
      width: "100%"
    }
  }, t.cta)), /*#__PURE__*/React.createElement("ul", {
    style: {
      listStyle: "none",
      margin: "2rem 0 0",
      padding: "2rem 0 0",
      borderTop: t.featured ? "1px solid rgba(255,255,255,0.12)" : "0.5px solid var(--color-grey-500)",
      display: "flex",
      flexDirection: "column",
      gap: "0.875rem"
    }
  }, t.feat.map(f => /*#__PURE__*/React.createElement("li", {
    key: f,
    style: {
      display: "flex",
      gap: 10,
      fontFamily: "var(--font-sans)",
      fontSize: "0.9375rem"
    }
  }, CHECK, /*#__PURE__*/React.createElement("span", {
    style: {
      color: t.featured ? "rgba(255,255,255,0.9)" : "var(--color-onyx-black)"
    }
  }, f))))))), /*#__PURE__*/React.createElement("div", {
    style: {
      textAlign: "center",
      marginTop: "3rem"
    }
  }, /*#__PURE__*/React.createElement(PLink, null, "Compare all plans")));
}
window.PricingScreen = PricingScreen;
})(); } catch (e) { __ds_ns.__errors.push({ path: "ui_kits/website/PricingScreen.jsx", error: String((e && e.message) || e) }); }

// ui_kits/website/SiteChrome.jsx
try { (() => {
// Site chrome — sticky header + footer. Composes DS Button + the Hypervisor lockup.
const {
  Button: IoiButton,
  Logo: IoiLogo,
  Wordmark: HvWordmark
} = window.IoiDesignSystem;
function SiteHeader({
  onNav
}) {
  const items = [["Platform", "home", true], ["Use cases", "home", true], ["Resources", "blog", true], ["Blog", "blog", false], ["Docs", "home", false], ["Pricing", "pricing", false]];
  return /*#__PURE__*/React.createElement("header", {
    style: {
      position: "sticky",
      top: 0,
      zIndex: 10,
      background: "var(--color-white)"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      maxWidth: "75rem",
      margin: "0 auto",
      display: "flex",
      alignItems: "center",
      gap: "1.25rem",
      padding: "1.25rem 2.5rem"
    }
  }, /*#__PURE__*/React.createElement("a", {
    href: "#",
    onClick: e => {
      e.preventDefault();
      onNav("home");
    },
    "aria-label": "Hypervisor",
    style: {
      display: "flex",
      flexShrink: 0,
      textDecoration: "none",
      color: "var(--color-onyx-black)"
    }
  }, /*#__PURE__*/React.createElement(HvWordmark, {
    height: 26
  })), /*#__PURE__*/React.createElement("ul", {
    style: {
      display: "flex",
      listStyle: "none",
      margin: 0,
      padding: 0,
      gap: "0.25rem"
    }
  }, items.map(([label, to, chev]) => /*#__PURE__*/React.createElement("li", {
    key: label,
    style: {
      display: "flex"
    }
  }, /*#__PURE__*/React.createElement("button", {
    onClick: () => onNav(to),
    style: {
      display: "inline-flex",
      alignItems: "center",
      gap: 4,
      background: "none",
      border: "none",
      cursor: "pointer",
      padding: "0.6875rem 0.4375rem",
      fontFamily: "var(--font-sans)",
      fontSize: "1rem",
      color: "var(--color-onyx-black)"
    }
  }, label, chev && /*#__PURE__*/React.createElement("svg", {
    width: "14",
    height: "14",
    viewBox: "0 0 16 17",
    fill: "none",
    style: {
      opacity: 0.6
    }
  }, /*#__PURE__*/React.createElement("path", {
    d: "m5.332 7.167 2.667 2.666 2.666-2.666",
    stroke: "currentColor",
    strokeLinecap: "square"
  })))))), /*#__PURE__*/React.createElement("div", {
    style: {
      marginLeft: "auto",
      display: "flex",
      gap: "0.5rem"
    }
  }, /*#__PURE__*/React.createElement(IoiButton, {
    theme: "grey",
    size: "md"
  }, "Sign in"), /*#__PURE__*/React.createElement(IoiButton, {
    theme: "grey",
    size: "md"
  }, "Request a demo"))));
}
function FooterCol({
  title,
  links
}) {
  return /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      flexDirection: "column",
      gap: "0.875rem"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "0.9375rem",
      color: "var(--color-onyx-black)"
    }
  }, title), /*#__PURE__*/React.createElement("ul", {
    style: {
      listStyle: "none",
      margin: 0,
      padding: 0,
      display: "flex",
      flexDirection: "column",
      gap: "0.625rem"
    }
  }, links.map(l => /*#__PURE__*/React.createElement("li", {
    key: l
  }, /*#__PURE__*/React.createElement("a", {
    href: "#",
    onClick: e => e.preventDefault(),
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "0.9375rem",
      color: "var(--color-grey-800)",
      textDecoration: "none"
    }
  }, l)))));
}
function SiteFooter() {
  return /*#__PURE__*/React.createElement("footer", {
    style: {
      borderTop: "0.5px solid var(--color-grey-500)",
      marginTop: "8rem"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      maxWidth: "75rem",
      margin: "0 auto",
      padding: "6rem 2.5rem 4rem",
      textAlign: "center"
    }
  }, /*#__PURE__*/React.createElement("h2", {
    style: {
      fontFamily: "var(--font-serif)",
      fontWeight: 300,
      fontSize: "2.75rem",
      lineHeight: 1.05,
      letterSpacing: "-0.02em",
      margin: 0,
      color: "var(--color-onyx-black)"
    }
  }, "Move agents off laptops,", /*#__PURE__*/React.createElement("br", null), "into the cloud"), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "1.125rem",
      color: "var(--color-grey-800)",
      marginTop: "1.25rem"
    }
  }, "Delegate work to cloud agents today, with environments and guardrails handled"), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      gap: "0.5rem",
      justifyContent: "center",
      marginTop: "2rem"
    }
  }, /*#__PURE__*/React.createElement(IoiButton, null, "Get started"), /*#__PURE__*/React.createElement(IoiButton, {
    variant: "outline"
  }, "Request a demo"))), /*#__PURE__*/React.createElement("div", {
    style: {
      maxWidth: "75rem",
      margin: "0 auto",
      padding: "3rem 2.5rem",
      borderTop: "0.5px solid var(--color-grey-500)",
      display: "grid",
      gridTemplateColumns: "1.4fr repeat(5, 1fr)",
      gap: "2rem"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      color: "var(--color-onyx-black)"
    }
  }, /*#__PURE__*/React.createElement(HvWordmark, {
    height: 26
  }), /*#__PURE__*/React.createElement("p", {
    style: {
      fontFamily: "var(--font-mono)",
      fontSize: "0.75rem",
      color: "var(--color-grey-700)",
      marginTop: "1.25rem",
      lineHeight: 1.5
    }
  }, "The platform for", /*#__PURE__*/React.createElement("br", null), "background agents")), /*#__PURE__*/React.createElement(FooterCol, {
    title: "Platform",
    links: ["Agents", "Environments", "Guardrails", "Integrations"]
  }), /*#__PURE__*/React.createElement(FooterCol, {
    title: "Use cases",
    links: ["Modernization", "Security", "Code review", "Automations"]
  }), /*#__PURE__*/React.createElement(FooterCol, {
    title: "Compare",
    links: ["vs. Devin", "vs. Copilot", "vs. Cursor"]
  }), /*#__PURE__*/React.createElement(FooterCol, {
    title: "Resources",
    links: ["Docs", "Blog", "Changelog", "Guides"]
  }), /*#__PURE__*/React.createElement(FooterCol, {
    title: "Company",
    links: ["About", "Careers", "Contact", "Status"]
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      maxWidth: "75rem",
      margin: "0 auto",
      padding: "1.5rem 2.5rem 3rem",
      borderTop: "0.5px solid var(--color-grey-500)",
      display: "flex",
      gap: "1.5rem",
      flexWrap: "wrap"
    }
  }, ["Security", "Terms of service", "Privacy policy", "Cookie policy", "Imprint"].map(l => /*#__PURE__*/React.createElement("a", {
    key: l,
    href: "#",
    onClick: e => e.preventDefault(),
    style: {
      fontFamily: "var(--font-sans)",
      fontSize: "0.8125rem",
      color: "var(--color-grey-700)",
      textDecoration: "none"
    }
  }, l)), /*#__PURE__*/React.createElement("span", {
    style: {
      marginLeft: "auto",
      fontFamily: "var(--font-mono)",
      fontSize: "0.75rem",
      color: "var(--color-grey-700)"
    }
  }, "\xA9 2026 ioi")));
}
window.SiteHeader = SiteHeader;
window.SiteFooter = SiteFooter;
})(); } catch (e) { __ds_ns.__errors.push({ path: "ui_kits/website/SiteChrome.jsx", error: String((e && e.message) || e) }); }

__ds_ns.Button = __ds_scope.Button;

__ds_ns.TextLink = __ds_scope.TextLink;

__ds_ns.Logo = __ds_scope.Logo;

__ds_ns.Wordmark = __ds_scope.Wordmark;

__ds_ns.ByIOI = __ds_scope.ByIOI;

__ds_ns.Badge = __ds_scope.Badge;

__ds_ns.Card = __ds_scope.Card;

__ds_ns.Eyebrow = __ds_scope.Eyebrow;

__ds_ns.Stat = __ds_scope.Stat;

__ds_ns.Input = __ds_scope.Input;

})();
