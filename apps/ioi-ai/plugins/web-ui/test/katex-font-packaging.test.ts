import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { KATEX_FONT_ALIAS, KATEX_FONT_PATTERN } from "../vite.config.ts";

test("every KaTeX font referenced by the product CSS resolves to a packaged dependency asset", () => {
  const cssPath = fileURLToPath(new URL("../node_modules/@earendil-works/pi-web-ui/dist/app.css", import.meta.url));
  const css = readFileSync(cssPath, "utf8");
  const references = new Set(
    [...css.matchAll(/url\((?:["'])?(fonts\/KaTeX_[^)"']+)(?:["'])?\)/g)].map((match) => match[1]),
  );

  assert.equal(references.size, 60);
  for (const reference of references) {
    assert.match(reference, KATEX_FONT_PATTERN);
    const resolved = reference.replace(KATEX_FONT_PATTERN, KATEX_FONT_ALIAS);
    assert.equal(existsSync(resolved), true, `${reference} must resolve to ${resolved}`);
  }
});
