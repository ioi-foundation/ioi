#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { failWith, implementationRoot, listTreeFiles } from "./lib.mjs";

const errors = [];
const files = listTreeFiles(implementationRoot).filter((file) => file.endsWith(".md"));

function tableCells(line) {
  let value = line.trim();
  if (!value.startsWith("|") || !value.endsWith("|")) return null;
  value = value.slice(1, -1);
  const cells = [];
  let cell = "";
  let escaped = false;
  let codeRun = 0;
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index];
    if (escaped) {
      cell += character;
      escaped = false;
      continue;
    }
    if (character === "\\") {
      cell += character;
      escaped = true;
      continue;
    }
    if (character === "`") {
      let end = index;
      while (end < value.length && value[end] === "`") end += 1;
      const length = end - index;
      cell += value.slice(index, end);
      if (codeRun === 0) codeRun = length;
      else if (length === codeRun) codeRun = 0;
      index = end - 1;
      continue;
    }
    if (character === "|" && codeRun === 0) {
      cells.push(cell.trim());
      cell = "";
      continue;
    }
    cell += character;
  }
  cells.push(cell.trim());
  return cells;
}

function analyzeMarkdown(source, relative) {
  const found = [];
  const lines = source.split(/\r?\n/u);
  let fence = null;
  const outsideFence = new Array(lines.length).fill(true);
  for (const [index, line] of lines.entries()) {
    const match = /^\s*(`{3,}|~{3,})(.*)$/u.exec(line);
    if (fence === null && match) {
      fence = { character: match[1][0], length: match[1].length, marker: match[1] };
      outsideFence[index] = false;
      continue;
    }
    if (fence !== null) {
      outsideFence[index] = false;
      if (
        match
        && match[1][0] === fence.character
        && match[1].length >= fence.length
        && match[2].trim() === ""
      ) {
        fence = null;
      }
    }
  }
  if (fence !== null) found.push(`${relative}: unclosed ${fence.marker} fence`);

  for (let index = 0; index < lines.length;) {
    if (!outsideFence[index] || tableCells(lines[index]) === null) {
      index += 1;
      continue;
    }
    const start = index;
    const rows = [];
    while (index < lines.length && outsideFence[index]) {
      const cells = tableCells(lines[index]);
      if (cells === null) break;
      rows.push({ line: index + 1, cells });
      index += 1;
    }
    const separators = rows
      .map((row, rowIndex) => row.cells.every((cell) => /^:?-{3,}:?$/u.test(cell)) ? rowIndex : -1)
      .filter((rowIndex) => rowIndex >= 0);
    if (separators.length !== 1 || separators[0] !== 1) {
      found.push(`${relative}:${start + 1}: pipe-table block must have exactly one GFM separator as its second row`);
      continue;
    }
    const width = rows[0].cells.length;
    if (width === 0) found.push(`${relative}:${start + 1}: pipe-table header has no columns`);
    for (const row of rows) {
      if (row.cells.length !== width) {
        found.push(`${relative}:${row.line}: pipe-table row has ${row.cells.length} columns; expected ${width}`);
      }
    }
  }
  return found;
}

function runSelfTest() {
  const cases = [
    {
      name: "long fence rejects shorter close",
      source: "````text\nvalue\n```\n",
      expected: "unclosed ```` fence",
    },
    {
      name: "matching long fence passes",
      source: "````text\n``` nested\n````\n",
      expected: null,
    },
    {
      name: "table arity mismatch fails",
      source: "| A | B |\n| --- | --- |\n| one |\n",
      expected: "row has 1 columns; expected 2",
    },
    {
      name: "escaped and code-span pipes do not split cells",
      source: "| A | B |\n| --- | --- |\n| one\\|two | `x|y` |\n",
      expected: null,
    },
  ];
  const failures = [];
  for (const testCase of cases) {
    const result = analyzeMarkdown(testCase.source, testCase.name);
    if (testCase.expected === null && result.length > 0) failures.push(`${testCase.name}: ${result.join("; ")}`);
    if (testCase.expected !== null && !result.some((entry) => entry.includes(testCase.expected))) failures.push(`${testCase.name}: expected ${testCase.expected}; found ${result.join("; ") || "no error"}`);
  }
  failWith("Markdown-structure self-test", failures);
  process.stdout.write(`Markdown-structure self-test passed: ${cases.length} exact fence and table cases\n`);
}

if (process.argv[2] === "--self-test") {
  if (process.argv.length !== 3) failWith("Markdown-structure self-test", ["usage: check-markdown-structure.mjs [--self-test]"]);
  runSelfTest();
  process.exit(0);
}
if (process.argv.length !== 2) failWith("Markdown-structure check", ["usage: check-markdown-structure.mjs [--self-test]"]);

for (const file of files) {
  const relative = path.relative(implementationRoot, file).split(path.sep).join("/");
  errors.push(...analyzeMarkdown(fs.readFileSync(file, "utf8"), relative));
}

failWith("Markdown-structure check", [...new Set(errors)]);
process.stdout.write(`Markdown-structure check passed: ${files.length} current and preserved private Markdown files have balanced fences and table separators\n`);
