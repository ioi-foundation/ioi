#!/usr/bin/env node
// Every contrast figure the brand sheets print comes from this file.
//
// The second review of this identity found that both printed justifications for
// adding tokens to the shared design system were numerically false — asserted from
// memory, never measured. On an identity whose thesis is that a price must carry its
// evidence, that is the one error that cannot stand. So the numbers are computed
// here, and the sheets quote this output rather than a recollection of it.
//
// WCAG 2.1 relative luminance and contrast ratio, verbatim from the spec.
// Usage: node apps/decentralized-cloud/brand/measure-contrast.mjs

const channel = (v) => {
  const c = v / 255;
  return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
};

const luminance = (hex) => {
  const h = hex.replace("#", "");
  const [r, g, b] = [0, 2, 4].map((i) => parseInt(h.slice(i, i + 2), 16));
  return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b);
};

const ratio = (a, b) => {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
};

// Thresholds: 4.5:1 normal text, 3:1 large text (>=18.66px bold or >=24px) and
// meaningful non-text (WCAG 1.4.11 — borders and dots that carry state).
const PAIRS = [
  ["link-green on white", "#397554", "#ffffff", 4.5, "chip text, live label"],
  ["link-green on onyx", "#397554", "#0a0e19", 4.5, "why green-on-dark exists"],
  ["green-on-dark on onyx", "#7bbd97", "#0a0e19", 4.5, "the dot and wordmark dot on dark"],
  ["red-600 on white", "#e40014", "#ffffff", 4.5, "expired chip text"],
  ["grey-800 on white", "#636363", "#ffffff", 4.5, "labels, eyebrows, body-muted"],
  ["grey-700 on white", "#818181", "#ffffff", 4.5, "was carrying label text — replaced"],
  ["grey-700 on porcelain", "#818181", "#f9f9f9", 3.0, "state dots on the surface tint"],
  ["grey-600 on white", "#cecece", "#ffffff", 3.0, "absence dot — non-text state"],
  ["grey-500 on white", "#e1e1e1", "#ffffff", 3.0, "hairline — decorative, exempt"],
  ["onyx on white", "#0a0e19", "#ffffff", 4.5, "ink"],
  ["white on onyx", "#ffffff", "#0a0e19", 4.5, "wordmark on the dark variant"],
];

let worst = null;
for (const [name, fg, bg, floor, note] of PAIRS) {
  const r = ratio(fg, bg);
  const verdict = r >= floor ? "pass" : "FAIL";
  if (verdict === "FAIL" && (!worst || r < worst.r)) worst = { name, r };
  console.log(
    `  ${verdict.padEnd(4)}  ${name.padEnd(26)} ${fg} on ${bg}  ${r.toFixed(2)}:1  (floor ${floor}:1)  ${note}`
  );
}

console.log(`\n${PAIRS.length} pairs measured.`);
console.log(
  "Sheets may print only figures from this list. A colour that fails its floor is " +
  "either not used for that role or the failure is stated where it is used."
);
