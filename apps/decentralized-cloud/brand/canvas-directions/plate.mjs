#!/usr/bin/env node
// THE HEAD-TO-HEAD PLATE for the two owner mark references.
//
// Rendered at deviceScaleFactor 1 so 16px is SIXTEEN DEVICE PIXELS. That is the whole
// discipline of this plate: an earlier round in this programme manufactured a finding
// because wide plates were downsampled in delivery, undoing the magnification they
// depended on, and a second round had two readers name the scale before the letter
// because per-plate magnification varied. Here nothing is magnified at all — the small
// sizes are shown at their true size, and the large reference is beside them, labelled.
//
// Both marks are drawn from marks.mjs, so what is scored is what would ship.

import { writeFileSync, mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { MARKS } from "./marks.mjs";
import { WORDMARK } from "./brand.mjs";
import { readFileSync } from "node:fs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.join(HERE, "plates");
mkdirSync(OUT, { recursive: true });

const IOI_B64 = readFileSync(path.join(HERE, "ioi-ttf.b64"), "utf8").trim();
const INK = "#0a0e19", PAPER = "#ffffff", LABEL = "#636363", HAIR = "#e1e1e1";

// Which mark is A and which is B on the plate is DECIDED BY A COIN, not by my order of
// preference, and the mapping is written to a file the readers never see. Presenting
// them always in authored order is how an order effect becomes a score.
const shuffled = Math.random() < 0.5 ? ["A", "B"] : ["B", "A"];
const legend = shuffled.map((k, i) => `${"LEFT RIGHT".split(" ")[i]} = ${MARKS[k].name} (${k})`).join("\n");
writeFileSync(path.join(OUT, "KEY-do-not-show-readers.txt"),
  `${legend}\nrendered ${new Date().toISOString()}\n`);

const cell = (label, body) => `
  <div style="display:flex;flex-direction:column;gap:8px;align-items:flex-start">
    <div style="font:400 10px/1 ui-monospace,Menlo,monospace;letter-spacing:.1em;text-transform:uppercase;color:${LABEL}">${label}</div>
    <div style="display:flex;align-items:center;gap:14px;min-height:34px">${body}</div>
  </div>`;

const column = (which, m) => `
<section style="flex:1;display:flex;flex-direction:column;gap:26px;padding:30px;border:1px solid ${HAIR};border-radius:10px;background:${PAPER}">
  <div style="font:600 15px/1.2 ui-sans-serif,system-ui,sans-serif">${which}</div>

  ${cell("true size · 16px, 24px, 32px — no magnification", `
    ${m.draw({ size: 16 })}${m.draw({ size: 24 })}${m.draw({ size: 32 })}`)}

  ${cell("favicon tile · 16px and 32px, on the tile", `
    ${m.draw({ size: 16, tile: INK })}${m.draw({ size: 32, tile: INK })}`)}

  ${cell("one ink", `${m.draw({ size: 32, mono: INK })}${m.draw({ size: 24, mono: INK })}${m.draw({ size: 16, mono: INK })}`)}

  ${cell("on a dark ground", `<div style="display:flex;gap:14px;align-items:center;background:${INK};padding:12px 16px;border-radius:8px">
    ${m.draw({ size: 32, mono: PAPER })}${m.draw({ size: 24, mono: PAPER })}${m.draw({ size: 16, mono: PAPER })}</div>`)}

  ${cell("in the lockup · 19px wordmark", `
    <div style="display:flex;align-items:center;gap:9px">${m.draw({ size: 27 })}${WORDMARK(19, INK)}</div>`)}

  ${cell("in the lockup · 14px wordmark", `
    <div style="display:flex;align-items:center;gap:7px">${m.draw({ size: 20 })}${WORDMARK(14, INK)}</div>`)}

  ${cell("large reference · 96px", m.draw({ size: 96 }))}
</section>`;

const html = `<!doctype html><meta charset="utf-8">
<style>
  @font-face{font-family:"IOI Display";src:url(data:font/ttf;base64,${IOI_B64}) format("truetype");font-weight:400 700;font-display:block}
  body{margin:0;background:#f9f9f9;padding:34px;font-family:ui-sans-serif,system-ui,-apple-system,sans-serif;color:${INK}}
</style>
<h1 style="margin:0 0 6px;font-size:17px;font-weight:600">Two marks, same product</h1>
<p style="margin:0 0 26px;font-size:13px;color:${LABEL};max-width:96ch">
  Every small size below is rendered at its TRUE size — 16px is sixteen pixels. Nothing on this
  plate is magnified. The wordmark is set entirely in the product's own face.
</p>
<div style="display:flex;gap:26px;align-items:stretch">
  ${column("LEFT", MARKS[shuffled[0]])}
  ${column("RIGHT", MARKS[shuffled[1]])}
</div>
`;

const file = path.join(OUT, "marks-head-to-head.html");
writeFileSync(file, html);
console.log("plate:", file);
console.log("key:", path.join(OUT, "KEY-do-not-show-readers.txt"));
