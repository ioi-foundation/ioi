import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const HTTP_METHODS = new Set(["get", "post", "put", "patch", "delete"]);
const OPEN_TO_CLOSE = new Map([
  ["(", ")"],
  ["[", "]"],
  ["{", "}"],
]);
const CLOSE_TO_OPEN = new Map(
  [...OPEN_TO_CLOSE.entries()].map(([open, close]) => [close, open]),
);

function isOpenToken(token) {
  return token?.type === "punctuation" && OPEN_TO_CLOSE.has(token.value);
}

function isCloseToken(token) {
  return token?.type === "punctuation" && CLOSE_TO_OPEN.has(token.value);
}

export function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

export function normalizeRepoPath(repoRoot, candidate) {
  const resolvedRoot = fs.realpathSync(repoRoot);
  const resolved = fs.realpathSync(candidate);
  const relative = path.relative(resolvedRoot, resolved);
  if (relative === "" || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw new Error(`path escapes repository root: ${candidate}`);
  }
  return relative.split(path.sep).join("/");
}

export function readRepoFile(repoRoot, relativePath) {
  const candidate = path.join(repoRoot, relativePath);
  const normalized = normalizeRepoPath(repoRoot, candidate);
  return {
    relativePath: normalized,
    source: fs.readFileSync(candidate, "utf8"),
  };
}

function decodeQuoted(raw) {
  const quote = raw[0];
  const inner = raw.slice(1, -1);
  let value = "";
  for (let index = 0; index < inner.length; index += 1) {
    const character = inner[index];
    if (character !== "\\") {
      value += character;
      continue;
    }
    index += 1;
    if (index >= inner.length) {
      value += "\\";
      break;
    }
    const escaped = inner[index];
    const replacements = {
      n: "\n",
      r: "\r",
      t: "\t",
      "\\": "\\",
      '"': '"',
      "'": "'",
      "`": "`",
    };
    value += replacements[escaped] ?? escaped;
  }
  return { quote, value };
}

function consumeQuoted(source, start, quote) {
  let index = start + 1;
  let dynamic = false;
  while (index < source.length) {
    if (source[index] === "\\") {
      index += 2;
      continue;
    }
    if (quote === "`" && source[index] === "$" && source[index + 1] === "{") {
      dynamic = true;
    }
    if (source[index] === quote) {
      return { end: index + 1, dynamic };
    }
    if (quote !== "`" && source[index] === "\n") {
      return null;
    }
    index += 1;
  }
  return null;
}

function consumeRustRawString(source, start) {
  let cursor = start;
  if (source[cursor] === "b") {
    cursor += 1;
  }
  if (source[cursor] !== "r") {
    return null;
  }
  cursor += 1;
  let hashes = 0;
  while (source[cursor] === "#") {
    hashes += 1;
    cursor += 1;
  }
  if (source[cursor] !== '"') {
    return null;
  }
  const terminator = `"${"#".repeat(hashes)}`;
  const contentStart = cursor + 1;
  const terminatorStart = source.indexOf(terminator, contentStart);
  if (terminatorStart === -1) {
    throw new Error(`unterminated Rust raw string at byte ${start}`);
  }
  return {
    end: terminatorStart + terminator.length,
    value: source.slice(contentStart, terminatorStart),
  };
}

function consumeJavaScriptRegex(source, start) {
  let index = start + 1;
  let inCharacterClass = false;
  while (index < source.length) {
    if (source[index] === "\\") {
      index += 2;
      continue;
    }
    if (source[index] === "\n" || source[index] === "\r") {
      return null;
    }
    if (source[index] === "[") {
      inCharacterClass = true;
      index += 1;
      continue;
    }
    if (source[index] === "]") {
      inCharacterClass = false;
      index += 1;
      continue;
    }
    if (source[index] === "/" && !inCharacterClass) {
      index += 1;
      while (/[A-Za-z]/u.test(source[index] ?? "")) {
        index += 1;
      }
      return { end: index };
    }
    index += 1;
  }
  return null;
}

export function lexSource(source, { language = "generic" } = {}) {
  const tokens = [];
  let index = 0;
  let line = 1;

  const push = (type, value, start, end, tokenLine = line) => {
    tokens.push({ type, value, start, end, line: tokenLine });
  };

  while (index < source.length) {
    const character = source[index];
    if (/\s/u.test(character)) {
      if (character === "\n") {
        line += 1;
      }
      index += 1;
      continue;
    }

    if (character === "/" && source[index + 1] === "/") {
      index += 2;
      while (index < source.length && source[index] !== "\n") {
        index += 1;
      }
      continue;
    }

    if (character === "/" && source[index + 1] === "*") {
      const start = index;
      let depth = 1;
      index += 2;
      while (index < source.length && depth > 0) {
        if (source[index] === "\n") {
          line += 1;
          index += 1;
        } else if (source[index] === "/" && source[index + 1] === "*") {
          depth += 1;
          index += 2;
        } else if (source[index] === "*" && source[index + 1] === "/") {
          depth -= 1;
          index += 2;
        } else {
          index += 1;
        }
      }
      if (depth !== 0) {
        throw new Error(`unterminated block comment at byte ${start}`);
      }
      continue;
    }

    const previousToken = tokens.at(-1);
    const regexMayStart = previousToken === undefined
      || (
        previousToken.type === "punctuation"
        && ["(", "[", "{", "=", "=>", ",", ":", ";", "!", "?", "&&", "||"]
          .includes(previousToken.value)
      )
      || (
        previousToken.type === "identifier"
        && ["return", "case", "throw", "yield", "await"].includes(previousToken.value)
      );
    if (language === "javascript" && character === "/" && regexMayStart) {
      const regex = consumeJavaScriptRegex(source, index);
      if (regex !== null) {
        push("regex", source.slice(index, regex.end), index, regex.end, line);
        index = regex.end;
        continue;
      }
    }

    const rawString = consumeRustRawString(source, index);
    if (rawString !== null) {
      const tokenLine = line;
      const raw = source.slice(index, rawString.end);
      line += (raw.match(/\n/g) ?? []).length;
      push("string", rawString.value, index, rawString.end, tokenLine);
      index = rawString.end;
      continue;
    }

    if (
      language === "rust"
      && character === "'"
      && /[A-Za-z_]/u.test(source[index + 1] ?? "")
    ) {
      let lifetimeEnd = index + 2;
      while (/[A-Za-z0-9_]/u.test(source[lifetimeEnd] ?? "")) {
        lifetimeEnd += 1;
      }
      if (source[lifetimeEnd] !== "'") {
        push("punctuation", character, index, index + 1, line);
        index += 1;
        continue;
      }
    }

    if (character === '"' || character === "'" || character === "`") {
      const tokenLine = line;
      const consumed = consumeQuoted(source, index, character);
      if (consumed === null && character === "'") {
        push("punctuation", character, index, index + 1, tokenLine);
        index += 1;
        continue;
      }
      if (consumed === null) {
        throw new Error(`unterminated ${character} string at byte ${index}`);
      }
      const raw = source.slice(index, consumed.end);
      line += (raw.match(/\n/g) ?? []).length;
      if (character === "`" && consumed.dynamic) {
        push("dynamic_string", raw, index, consumed.end, tokenLine);
      } else {
        push("string", decodeQuoted(raw).value, index, consumed.end, tokenLine);
      }
      index = consumed.end;
      continue;
    }

    if (/[A-Za-z_$]/u.test(character)) {
      const start = index;
      index += 1;
      while (index < source.length && /[A-Za-z0-9_$]/u.test(source[index])) {
        index += 1;
      }
      push("identifier", source.slice(start, index), start, index);
      continue;
    }

    if (/[0-9]/u.test(character)) {
      const start = index;
      index += 1;
      while (index < source.length && /[A-Za-z0-9_.]/u.test(source[index])) {
        index += 1;
      }
      push("number", source.slice(start, index), start, index);
      continue;
    }

    const paired = ["::", "=>", "->", "?.", "??", "==", "!=", "<=", ">=", "&&", "||"]
      .find((candidate) => source.startsWith(candidate, index));
    if (paired !== undefined) {
      push("punctuation", paired, index, index + paired.length);
      index += paired.length;
      continue;
    }

    push("punctuation", character, index, index + 1);
    index += 1;
  }

  return tokens;
}

export function findMatchingToken(tokens, openIndex) {
  const openToken = tokens[openIndex];
  const open = openToken?.value;
  if (!isOpenToken(openToken)) {
    throw new Error(`token ${openIndex} is not an opening delimiter`);
  }
  const stack = [open];
  for (let index = openIndex + 1; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (isOpenToken(token)) {
      stack.push(token.value);
    } else if (isCloseToken(token)) {
      const expected = CLOSE_TO_OPEN.get(token.value);
      const actual = stack.pop();
      if (actual !== expected) {
        throw new Error(`delimiter mismatch at line ${tokens[index].line}`);
      }
      if (stack.length === 0) {
        return index;
      }
    }
  }
  throw new Error(`unclosed delimiter at line ${tokens[openIndex].line}`);
}

function topLevelComma(tokens, start, end) {
  const stack = [];
  for (let index = start; index < end; index += 1) {
    const token = tokens[index];
    if (isOpenToken(token)) {
      stack.push(token.value);
    } else if (isCloseToken(token)) {
      stack.pop();
    } else if (token.value === "," && stack.length === 0) {
      return index;
    }
  }
  return -1;
}

function topLevelRanges(tokens, start, end) {
  const ranges = [];
  const stack = [];
  let rangeStart = start;
  for (let index = start; index < end; index += 1) {
    const token = tokens[index];
    if (isOpenToken(token)) {
      stack.push(token.value);
    } else if (isCloseToken(token)) {
      stack.pop();
    } else if (token.value === "," && stack.length === 0) {
      ranges.push([rangeStart, index]);
      rangeStart = index + 1;
    }
  }
  if (rangeStart < end) {
    ranges.push([rangeStart, end]);
  }
  return ranges;
}

function normalizeSymbolTokens(tokens, start, end) {
  if (start >= end) {
    return "";
  }
  const values = tokens.slice(start, end).map((token) => token.value);
  return values
    .join(" ")
    .replaceAll(/\s*::\s*/gu, "::")
    .replaceAll(/\s*\.\s*/gu, ".")
    .replaceAll(/\s*,\s*/gu, ", ")
    .replaceAll(/\s+/gu, " ")
    .trim();
}

function callSequenceInRange(tokens, start, end) {
  const calls = [];
  for (let cursor = start; cursor < end - 1; cursor += 1) {
    if (
      tokens[cursor].type !== "identifier"
      || tokens[cursor + 1]?.value !== "("
    ) {
      continue;
    }
    let symbolStart = cursor;
    while (
      symbolStart >= start + 2
      && ["::", "."].includes(tokens[symbolStart - 1].value)
      && tokens[symbolStart - 2].type === "identifier"
    ) {
      symbolStart -= 2;
    }
    calls.push(normalizeSymbolTokens(tokens, symbolStart, cursor + 1));
  }
  return calls;
}

function anchor(source, startToken, endToken) {
  const text = source.slice(startToken.start, endToken.end);
  return {
    line: startToken.line,
    sha256: sha256(text),
    text,
  };
}

export function discoverAxumRoutes({ repoRoot, relativePath, surface }) {
  const { source } = readRepoFile(repoRoot, relativePath);
  const tokens = lexSource(source, { language: "rust" });
  const discovered = [];

  for (let index = 0; index < tokens.length - 3; index += 1) {
    if (
      tokens[index].value !== "."
      || tokens[index + 1].value !== "route"
      || tokens[index + 2].value !== "("
    ) {
      continue;
    }

    const closeIndex = findMatchingToken(tokens, index + 2);
    const commaIndex = topLevelComma(tokens, index + 3, closeIndex);
    if (commaIndex === -1) {
      throw new Error(`${relativePath}:${tokens[index].line}: route has no router argument`);
    }
    const pathToken = tokens.slice(index + 3, commaIndex).find((token) => token.type === "string");
    const dynamicPath = tokens.slice(index + 3, commaIndex).some(
      (token) => token.type === "dynamic_string" || token.type === "identifier",
    );
    if (pathToken === undefined || dynamicPath) {
      throw new Error(`${relativePath}:${tokens[index].line}: route path is not one literal`);
    }

    const routerStart = commaIndex + 1;
    const stack = [];
    const methods = [];
    for (let cursor = routerStart; cursor < closeIndex; cursor += 1) {
      const token = tokens[cursor];
      const value = token.value;
      if (isOpenToken(token)) {
        stack.push(value);
        continue;
      }
      if (isCloseToken(token)) {
        stack.pop();
        continue;
      }
      if (
        stack.length === 0
        && tokens[cursor].type === "identifier"
        && HTTP_METHODS.has(value)
        && tokens[cursor + 1]?.value === "("
      ) {
        const handlerClose = findMatchingToken(tokens, cursor + 1);
        const handlerComma = topLevelComma(tokens, cursor + 2, handlerClose);
        const handlerEnd = handlerComma === -1 ? handlerClose : handlerComma;
        methods.push({
          method: value.toUpperCase(),
          handler: normalizeSymbolTokens(tokens, cursor + 2, handlerEnd),
        });
        cursor = handlerClose;
      }
    }

    if (methods.length === 0) {
      throw new Error(`${relativePath}:${tokens[index].line}: no literal HTTP method router found`);
    }

    const routeAnchor = anchor(source, tokens[index], tokens[closeIndex]);
    for (const method of methods) {
      discovered.push({
        identity: `http:${surface}:${method.method} ${pathToken.value}`,
        kind: "http",
        surface,
        operation: `${method.method} ${pathToken.value}`,
        method: method.method,
        path: pathToken.value,
        source_file: relativePath,
        source_symbol: method.handler,
        handler: method.handler,
        source_anchor: {
          line: routeAnchor.line,
          sha256: routeAnchor.sha256,
        },
      });
    }
    index = closeIndex;
  }

  return discovered;
}

export function discoverRustFunctions({ repoRoot, relativePath }) {
  const { source } = readRepoFile(repoRoot, relativePath);
  const tokens = lexSource(source, { language: "rust" });
  const functions = [];
  for (let index = 0; index < tokens.length - 2; index += 1) {
    if (tokens[index].value !== "fn" || tokens[index + 1].type !== "identifier") {
      continue;
    }
    const nameToken = tokens[index + 1];
    let parametersOpen = index + 2;
    while (parametersOpen < tokens.length && tokens[parametersOpen].value !== "(") {
      if (tokens[parametersOpen].value === ";" || tokens[parametersOpen].value === "{") {
        break;
      }
      parametersOpen += 1;
    }
    if (tokens[parametersOpen]?.value !== "(") {
      continue;
    }
    const parametersClose = findMatchingToken(tokens, parametersOpen);
    let bodyOpen = parametersClose + 1;
    const stack = [];
    while (bodyOpen < tokens.length) {
      const token = tokens[bodyOpen];
      const value = token.value;
      if (value === ";" && stack.length === 0) {
        break;
      }
      if (value === "{" && stack.length === 0) {
        break;
      }
      if (isOpenToken(token)) {
        stack.push(value);
      } else if (isCloseToken(token)) {
        stack.pop();
      }
      bodyOpen += 1;
    }
    if (tokens[bodyOpen]?.value !== "{") {
      continue;
    }
    const bodyClose = findMatchingToken(tokens, bodyOpen);
    const functionAnchor = anchor(source, tokens[index], tokens[bodyClose]);
    const callSequence = callSequenceInRange(tokens, bodyOpen + 1, bodyClose);
    functions.push({
      name: nameToken.value,
      relativePath,
      line: nameToken.line,
      sha256: functionAnchor.sha256,
      start: tokens[index].start,
      end: tokens[bodyClose].end,
      source: functionAnchor.text,
      callSequence,
    });
    index = bodyClose;
  }
  return functions;
}

export function buildRustFunctionIndex({ repoRoot, relativePaths }) {
  const index = new Map();
  for (const relativePath of relativePaths) {
    const functions = discoverRustFunctions({ repoRoot, relativePath });
    const byName = new Map();
    for (const fn of functions) {
      const existing = byName.get(fn.name) ?? [];
      existing.push(fn);
      byName.set(fn.name, existing);
    }
    index.set(relativePath, byName);
  }
  return index;
}

function simpleRustSymbol(handler) {
  return /^[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*$/u.test(handler);
}

function functionCandidates(functionIndex, relativePath, name) {
  return functionIndex.get(relativePath)?.get(name) ?? [];
}

export function attachRustHandlerDefinitions({
  repoRoot,
  entries,
  functionIndex,
  defaultSourceFile,
  moduleSourceFiles = new Map(),
}) {
  return entries.map((entry) => {
    if (!simpleRustSymbol(entry.handler ?? "")) {
      return {
        ...entry,
        handler_source_file: entry.source_file,
        handler_source_symbol: entry.handler,
        handler_anchor: entry.source_anchor,
        handler_resolution: "inline_registration",
      };
    }

    const parts = entry.handler.split("::");
    const name = parts.at(-1);
    const moduleName = parts
      .slice(0, -1)
      .reverse()
      .find((part) => moduleSourceFiles.has(part)) ?? null;
    const preferredFile = moduleName === null
      ? defaultSourceFile
      : moduleSourceFiles.get(moduleName);
    let candidates = preferredFile === undefined
      ? []
      : functionCandidates(functionIndex, preferredFile, name);

    if (candidates.length === 0) {
      candidates = [...functionIndex.values()]
        .flatMap((byName) => byName.get(name) ?? []);
    }

    if (candidates.length !== 1) {
      if (
        candidates.length === 0
        && preferredFile !== undefined
        && repoRoot !== undefined
      ) {
        const { source } = readRepoFile(repoRoot, preferredFile);
        return {
          ...entry,
          handler_source_file: preferredFile,
          handler_source_symbol: entry.handler,
          handler_anchor: {
            line: 1,
            sha256: sha256(source),
          },
          handler_resolution: "file_locked_generated_handler",
        };
      }
      return {
        ...entry,
        handler_source_file: preferredFile ?? null,
        handler_source_symbol: entry.handler,
        handler_anchor: null,
        handler_resolution: candidates.length === 0 ? "unresolved" : "ambiguous",
      };
    }

    const definition = candidates[0];
    return {
      ...entry,
      handler_source_file: definition.relativePath,
      handler_source_symbol: name,
      handler_anchor: {
        line: definition.line,
        sha256: definition.sha256,
      },
      handler_resolution: "function_body",
      handler_calls: [...new Set(definition.callSequence)].sort(),
      handler_call_sequence: definition.callSequence,
    };
  });
}

export function rustModuleSourceMap(relativePaths) {
  return new Map(
    relativePaths.map((relativePath) => [
      path.basename(relativePath, path.extname(relativePath)),
      relativePath,
    ]),
  );
}

function findTokenSequence(tokens, values, start = 0) {
  outer:
  for (let index = start; index <= tokens.length - values.length; index += 1) {
    for (let offset = 0; offset < values.length; offset += 1) {
      if (tokens[index + offset].value !== values[offset]) {
        continue outer;
      }
    }
    return index;
  }
  return -1;
}

export function discoverWalletServiceMethods({
  repoRoot,
  relativePath = "crates/services/src/wallet_network/mod.rs",
}) {
  const { source } = readRepoFile(repoRoot, relativePath);
  const tokens = lexSource(source, { language: "rust" });
  const matchIndex = findTokenSequence(tokens, ["match", "method"]);
  if (matchIndex === -1) {
    throw new Error(`${relativePath}: match method registry not found`);
  }
  const openIndex = tokens.findIndex(
    (token, index) => index > matchIndex && token.value === "{",
  );
  if (openIndex === -1) {
    throw new Error(`${relativePath}: match method body not found`);
  }
  const closeIndex = findMatchingToken(tokens, openIndex);
  const discovered = [];
  let cursor = openIndex + 1;

  while (cursor < closeIndex) {
    if (tokens[cursor].type !== "string" || tokens[cursor + 1]?.value !== "=>") {
      cursor += 1;
      continue;
    }
    const methodToken = tokens[cursor];
    let armEnd = cursor + 2;
    const stack = [];
    while (armEnd < closeIndex) {
      const token = tokens[armEnd];
      const value = token.value;
      if (
        armEnd > cursor + 2
        && stack.length === 0
        && tokens[armEnd].type === "string"
        && tokens[armEnd + 1]?.value === "=>"
      ) {
        break;
      }
      if (isOpenToken(token)) {
        stack.push(value);
      } else if (isCloseToken(token)) {
        stack.pop();
      } else if (value === "," && stack.length === 0) {
        break;
      }
      armEnd += 1;
    }

    let handlerStart = -1;
    let handlerOpen = -1;
    for (let index = cursor + 2; index < armEnd; index += 1) {
      if (tokens[index].value !== "handlers" || tokens[index + 1]?.value !== "::") {
        continue;
      }
      let scan = index;
      while (
        scan < armEnd
        && (
          tokens[scan].type === "identifier"
          || tokens[scan].value === "::"
        )
      ) {
        scan += 1;
      }
      if (tokens[scan]?.value === "(") {
        handlerStart = index;
        handlerOpen = scan;
      }
    }
    if (handlerStart === -1) {
      throw new Error(
        `${relativePath}:${methodToken.line}: wallet method ${methodToken.value} has no handler call`,
      );
    }

    const handler = normalizeSymbolTokens(tokens, handlerStart, handlerOpen);
    const armAnchor = anchor(source, methodToken, tokens[Math.max(cursor + 2, armEnd - 1)]);
    discovered.push({
      identity: `service:wallet.network:${methodToken.value}`,
      kind: "service_method",
      surface: "wallet.network",
      operation: methodToken.value,
      service_method: methodToken.value,
      source_file: relativePath,
      source_symbol: "WalletNetworkService::handle_service_call",
      handler,
      source_anchor: {
        line: armAnchor.line,
        sha256: armAnchor.sha256,
      },
    });
    cursor = tokens[armEnd]?.value === "," ? armEnd + 1 : armEnd;
  }

  return discovered;
}

function methodArmEnd(tokens, start, closeIndex) {
  let cursor = start;
  const stack = [];
  while (cursor < closeIndex) {
    const token = tokens[cursor];
    if (
      cursor > start
      && stack.length === 0
      && (token.type === "string" || token.value === "_")
      && tokens[cursor + 1]?.value === "=>"
    ) {
      break;
    }
    if (isOpenToken(token)) {
      stack.push(token.value);
    } else if (isCloseToken(token)) {
      stack.pop();
    } else if (token.value === "," && stack.length === 0) {
      break;
    }
    cursor += 1;
  }
  return cursor;
}

function singleLiteralServiceId(functions, relativePath, expectedServiceId) {
  const candidates = functions.filter((fn) => fn.name === "id");
  if (candidates.length !== 1) {
    throw new Error(
      `${relativePath}: expected one literal service id function, found ${candidates.length}`,
    );
  }
  const literals = lexSource(candidates[0].source, { language: "rust" })
    .filter((token) => token.type === "string")
    .map((token) => token.value);
  if (literals.length !== 1 || literals[0] !== expectedServiceId) {
    throw new Error(
      `${relativePath}: expected service id ${expectedServiceId}, found `
      + `${literals.length === 1 ? literals[0] : "non-literal or ambiguous"}`,
    );
  }
}

export function discoverRustMatchServiceMethods({
  repoRoot,
  relativePath,
  serviceId,
  serviceType,
  surface = `blockchain-service:${serviceId}`,
  activeState,
}) {
  const functions = discoverRustFunctions({ repoRoot, relativePath });
  singleLiteralServiceId(functions, relativePath, serviceId);
  const handlers = functions.filter((fn) => fn.name === "handle_service_call");
  if (handlers.length !== 1) {
    throw new Error(
      `${relativePath}: expected one handle_service_call function, found ${handlers.length}`,
    );
  }

  const handlerDefinition = handlers[0];
  const source = handlerDefinition.source;
  const tokens = lexSource(source, { language: "rust" });
  const matchIndex = findTokenSequence(tokens, ["match", "method"]);
  if (matchIndex === -1) {
    throw new Error(`${relativePath}: match method registry not found`);
  }
  const openIndex = tokens.findIndex(
    (token, index) => index > matchIndex && token.value === "{",
  );
  if (openIndex === -1) {
    throw new Error(`${relativePath}: match method body not found`);
  }
  const closeIndex = findMatchingToken(tokens, openIndex);
  const discovered = [];

  let cursor = openIndex + 1;
  while (cursor < closeIndex) {
    if (tokens[cursor].type !== "string" || tokens[cursor + 1]?.value !== "=>") {
      cursor += 1;
      continue;
    }
    const methodToken = tokens[cursor];
    const armEnd = methodArmEnd(tokens, cursor + 2, closeIndex);
    const finalToken = tokens[Math.max(cursor + 1, armEnd - 1)];
    const armAnchor = anchor(source, methodToken, finalToken);
    const callSequence = callSequenceInRange(tokens, cursor + 2, armEnd);
    const delegatedCalls = callSequence.filter((call) => ![
      "codec::from_bytes_canonical",
      "ioi_types::codec::from_bytes_canonical",
      "format",
      "Ok",
      "Err",
      "Some",
      "None",
    ].includes(call));
    const handler = delegatedCalls.at(-1)
      ?? `${serviceType}::handle_service_call`;
    discovered.push({
      identity: `service:${serviceId}:${methodToken.value}`,
      kind: "service_method",
      surface,
      operation: methodToken.value,
      service_method: methodToken.value,
      service_id: serviceId,
      source_file: relativePath,
      source_symbol: `${serviceType}::handle_service_call[${methodToken.value}]`,
      handler,
      active_state: activeState,
      source_anchor: {
        line: handlerDefinition.line - 1 + armAnchor.line,
        sha256: armAnchor.sha256,
      },
      handler_source_file: relativePath,
      handler_source_symbol: `${serviceType}::handle_service_call[${methodToken.value}]`,
      handler_anchor: {
        line: handlerDefinition.line - 1 + armAnchor.line,
        sha256: armAnchor.sha256,
      },
      handler_resolution: "literal_service_dispatch_arm",
      handler_calls: [...new Set(callSequence)].sort(),
      handler_call_sequence: callSequence,
    });
    cursor = tokens[armEnd]?.value === "," ? armEnd + 1 : armEnd;
  }

  if (discovered.length === 0) {
    throw new Error(`${relativePath}: no literal service methods discovered`);
  }
  return discovered;
}

function serviceInterfaceAttribute(tokens, index) {
  return (
    tokens[index]?.value === "#"
    && tokens[index + 1]?.value === "["
    && tokens[index + 2]?.value === "service_interface"
    && tokens[index + 3]?.value === "("
  );
}

export function discoverRustServiceInterfaceMethods({
  repoRoot,
  relativePath,
  expectedServiceId,
  surface = `blockchain-service:${expectedServiceId}`,
  activeState,
}) {
  const { source } = readRepoFile(repoRoot, relativePath);
  const tokens = lexSource(source, { language: "rust" });
  const attributeIndexes = tokens
    .map((_token, index) => index)
    .filter((index) => serviceInterfaceAttribute(tokens, index));
  if (attributeIndexes.length !== 1) {
    throw new Error(
      `${relativePath}: expected one service_interface registry, found ${attributeIndexes.length}`,
    );
  }

  const attributeIndex = attributeIndexes[0];
  const argsClose = findMatchingToken(tokens, attributeIndex + 3);
  const serviceIdTokens = tokens.slice(attributeIndex + 4, argsClose);
  const idKey = serviceIdTokens.findIndex((token) => token.value === "id");
  const idToken = idKey === -1
    ? null
    : serviceIdTokens.slice(idKey + 1).find((token) => token.type === "string");
  if (idToken?.value !== expectedServiceId) {
    throw new Error(
      `${relativePath}: expected macro service id ${expectedServiceId}, found `
      + `${idToken?.value ?? "non-literal"}`,
    );
  }

  const attributeClose = findMatchingToken(tokens, attributeIndex + 1);
  let implIndex = attributeClose + 1;
  while (implIndex < tokens.length && tokens[implIndex].value !== "impl") {
    implIndex += 1;
  }
  if (implIndex === tokens.length) {
    throw new Error(`${relativePath}: service_interface impl not found`);
  }
  const implOpen = tokens.findIndex(
    (token, index) => index > implIndex && token.value === "{",
  );
  const implClose = findMatchingToken(tokens, implOpen);
  const serviceType = normalizeSymbolTokens(tokens, implIndex + 1, implOpen);
  const discovered = [];

  for (let index = implOpen + 1; index < implClose - 4; index += 1) {
    if (
      tokens[index].value !== "#"
      || tokens[index + 1]?.value !== "["
      || tokens[index + 2]?.value !== "method"
      || tokens[index + 3]?.value !== "]"
    ) {
      continue;
    }
    let fnIndex = index + 4;
    while (fnIndex < implClose && tokens[fnIndex].value !== "fn") {
      fnIndex += 1;
    }
    if (tokens[fnIndex + 1]?.type !== "identifier") {
      throw new Error(`${relativePath}:${tokens[index].line}: method function not found`);
    }
    const methodToken = tokens[fnIndex + 1];
    let paramsOpen = fnIndex + 2;
    while (paramsOpen < implClose && tokens[paramsOpen].value !== "(") {
      paramsOpen += 1;
    }
    const paramsClose = findMatchingToken(tokens, paramsOpen);
    let bodyOpen = paramsClose + 1;
    while (bodyOpen < implClose && tokens[bodyOpen].value !== "{") {
      bodyOpen += 1;
    }
    const bodyClose = findMatchingToken(tokens, bodyOpen);
    const methodAnchor = anchor(source, tokens[index], tokens[bodyClose]);
    const callSequence = callSequenceInRange(tokens, bodyOpen + 1, bodyClose);
    const serviceMethod = `${methodToken.value}@v1`;
    discovered.push({
      identity: `service:${expectedServiceId}:${serviceMethod}`,
      kind: "service_method",
      surface,
      operation: serviceMethod,
      service_method: serviceMethod,
      service_id: expectedServiceId,
      source_file: relativePath,
      source_symbol: `${serviceType}::${methodToken.value}`,
      handler: `${serviceType}::${methodToken.value}`,
      active_state: activeState,
      source_anchor: {
        line: methodAnchor.line,
        sha256: methodAnchor.sha256,
      },
      handler_source_file: relativePath,
      handler_source_symbol: `${serviceType}::${methodToken.value}`,
      handler_anchor: {
        line: methodAnchor.line,
        sha256: methodAnchor.sha256,
      },
      handler_resolution: "service_interface_method_body",
      handler_calls: [...new Set(callSequence)].sort(),
      handler_call_sequence: callSequence,
    });
    index = bodyClose;
  }

  if (discovered.length === 0) {
    throw new Error(`${relativePath}: no #[method] service methods discovered`);
  }
  return discovered;
}

export function discoverProtoService({
  repoRoot,
  relativePath,
  serviceName,
  surface,
  activeState,
}) {
  const { source } = readRepoFile(repoRoot, relativePath);
  const tokens = lexSource(source, { language: "proto" });
  const serviceIndex = findTokenSequence(tokens, ["service", serviceName]);
  if (serviceIndex === -1) {
    throw new Error(`${relativePath}: service ${serviceName} not found`);
  }
  const openIndex = tokens.findIndex(
    (token, index) => index > serviceIndex && token.value === "{",
  );
  const closeIndex = findMatchingToken(tokens, openIndex);
  const discovered = [];
  for (let index = openIndex + 1; index < closeIndex; index += 1) {
    if (tokens[index].value !== "rpc" || tokens[index + 1]?.type !== "identifier") {
      continue;
    }
    const rpcToken = tokens[index + 1];
    let endIndex = index + 2;
    while (endIndex < closeIndex && tokens[endIndex].value !== ";") {
      endIndex += 1;
    }
    const rpcAnchor = anchor(source, tokens[index], tokens[Math.min(endIndex, closeIndex - 1)]);
    discovered.push({
      identity: `rpc:${surface}:${rpcToken.value}`,
      kind: "rpc",
      surface,
      operation: rpcToken.value,
      rpc_method: rpcToken.value,
      source_file: relativePath,
      source_symbol: `${serviceName}.${rpcToken.value}`,
      handler: null,
      active_state: activeState,
      source_anchor: {
        line: rpcAnchor.line,
        sha256: rpcAnchor.sha256,
      },
    });
    index = endIndex;
  }
  return discovered;
}

function findCallOpen(tokens, identifierIndex) {
  let cursor = identifierIndex + 1;
  if (tokens[cursor]?.value === "<") {
    let angleDepth = 0;
    while (cursor < tokens.length) {
      if (tokens[cursor].value === "<") {
        angleDepth += 1;
      } else if (tokens[cursor].value === ">") {
        angleDepth -= 1;
        if (angleDepth === 0) {
          cursor += 1;
          break;
        }
      }
      cursor += 1;
    }
  }
  return tokens[cursor]?.value === "(" ? cursor : -1;
}

export function discoverLiteralCalls({
  repoRoot,
  relativePaths,
  callee,
  identityPrefix,
  surface,
  kind = "js_action",
}) {
  const calls = [];
  for (const relativePath of relativePaths) {
    const { source } = readRepoFile(repoRoot, relativePath);
    const tokens = lexSource(source, { language: "javascript" });
    for (let index = 0; index < tokens.length; index += 1) {
      if (tokens[index].value !== callee) {
        continue;
      }
      const openIndex = findCallOpen(tokens, index);
      if (openIndex === -1) {
        continue;
      }
      const closeIndex = findMatchingToken(tokens, openIndex);
      const argument = tokens[openIndex + 1];
      if (argument?.type !== "string") {
        throw new Error(
          `${relativePath}:${tokens[index].line}: ${callee} call does not use a literal first argument`,
        );
      }
      const callAnchor = anchor(source, tokens[index], tokens[closeIndex]);
      calls.push({
        identity: `${identityPrefix}:${argument.value}`,
        kind,
        surface,
        operation: argument.value,
        command: argument.value,
        source_file: relativePath,
        source_symbol: `${callee}(${JSON.stringify(argument.value)})`,
        handler: callee,
        source_anchor: {
          line: callAnchor.line,
          sha256: callAnchor.sha256,
        },
      });
      index = closeIndex;
    }
  }
  return calls;
}

export function aggregateLiteralCalls(calls) {
  const byIdentity = new Map();
  for (const call of calls) {
    const existing = byIdentity.get(call.identity);
    const callSite = {
      source_file: call.source_file,
      source_symbol: call.source_symbol,
      source_anchor: call.source_anchor,
    };
    if (existing === undefined) {
      byIdentity.set(call.identity, {
        ...call,
        call_sites: [callSite],
      });
    } else {
      existing.call_sites.push(callSite);
    }
  }
  return [...byIdentity.values()]
    .map((entry) => ({
      ...entry,
      call_sites: [...entry.call_sites].sort((left, right) => (
        left.source_file.localeCompare(right.source_file)
        || left.source_anchor.line - right.source_anchor.line
      )),
      source_anchor: {
        line: entry.call_sites[0].source_anchor.line,
        sha256: sha256(
          entry.call_sites
            .map((site) => `${site.source_file}:${site.source_anchor.sha256}`)
            .sort()
            .join("\n"),
        ),
      },
    }))
    .sort((left, right) => left.identity.localeCompare(right.identity));
}

function objectPropertyExpression(tokens, start, end, property) {
  for (let index = start; index < end - 2; index += 1) {
    if (
      tokens[index].value !== property
      || tokens[index + 1]?.value !== ":"
    ) {
      continue;
    }
    let expressionEnd = index + 2;
    const stack = [];
    while (expressionEnd < end) {
      const token = tokens[expressionEnd];
      if (isOpenToken(token)) {
        stack.push(token.value);
      } else if (isCloseToken(token)) {
        if (stack.length === 0) {
          break;
        }
        stack.pop();
      } else if (token.value === "," && stack.length === 0) {
        break;
      }
      expressionEnd += 1;
    }
    return normalizeSymbolTokens(tokens, index + 2, expressionEnd);
  }
  return null;
}

function normalizedCallMethod(expression, fallback = "DYNAMIC") {
  if (expression === null || expression === "") {
    return fallback;
  }
  const unquoted = expression.replace(/^["'`](.*)["'`]$/u, "$1");
  return /^(GET|HEAD|POST|PUT|PATCH|DELETE)$/iu.test(unquoted)
    ? unquoted.toUpperCase()
    : `DYNAMIC(${expression})`;
}

export function discoverJsOutboundCalls({
  repoRoot,
  relativePaths,
  surface,
  activeState,
}) {
  const discovered = [];
  const duplicateOrdinals = new Map();
  for (const relativePath of relativePaths) {
    const { source } = readRepoFile(repoRoot, relativePath);
    const tokens = lexSource(source, { language: "javascript" });
    for (let index = 0; index < tokens.length - 1; index += 1) {
      const callee = tokens[index].value;
      if (![
        "EventSource",
        "WebSocket",
        "daemon",
        "fetch",
        "request",
        "sendBeacon",
      ].includes(callee)) {
        continue;
      }
      const openIndex = findCallOpen(tokens, index);
      if (openIndex === -1) {
        continue;
      }
      if (
        ["request", "sendBeacon"].includes(callee)
        && tokens[index - 1]?.value !== "."
      ) {
        continue;
      }
      const closeIndex = findMatchingToken(tokens, openIndex);
      const ranges = topLevelRanges(tokens, openIndex + 1, closeIndex);
      if (ranges.length === 0) {
        throw new Error(`${relativePath}:${tokens[index].line}: empty ${callee} call`);
      }

      let method;
      let target;
      if (callee === "daemon") {
        method = normalizedCallMethod(
          normalizeSymbolTokens(tokens, ranges[0][0], ranges[0][1]),
        );
        target = ranges[1] === undefined
          ? "<missing-path>"
          : normalizeSymbolTokens(tokens, ranges[1][0], ranges[1][1]);
      } else if (callee === "fetch") {
        target = normalizeSymbolTokens(tokens, ranges[0][0], ranges[0][1]);
        const methodExpression = ranges[1] === undefined
          ? null
          : objectPropertyExpression(tokens, ranges[1][0], ranges[1][1], "method");
        method = normalizedCallMethod(methodExpression, "GET");
      } else if (callee === "request") {
        const options = ranges[0];
        const methodExpression = objectPropertyExpression(
          tokens,
          options[0],
          options[1],
          "method",
        );
        const pathExpression = objectPropertyExpression(
          tokens,
          options[0],
          options[1],
          "path",
        );
        method = normalizedCallMethod(methodExpression);
        target = pathExpression ?? normalizeSymbolTokens(tokens, options[0], options[1]);
      } else {
        target = normalizeSymbolTokens(tokens, ranges[0][0], ranges[0][1]);
        method = callee === "WebSocket"
          ? "WEBSOCKET"
          : callee === "sendBeacon"
              ? "POST"
              : "GET";
      }

      const baseIdentity = `js-outbound:${surface}:${method} ${target}`;
      const ordinal = (duplicateOrdinals.get(baseIdentity) ?? 0) + 1;
      duplicateOrdinals.set(baseIdentity, ordinal);
      const callAnchor = anchor(source, tokens[index], tokens[closeIndex]);
      discovered.push({
        identity: `${baseIdentity}#${ordinal}`,
        kind: "js_outbound",
        surface,
        operation: `${method} ${target}`,
        method,
        path: target,
        source_file: relativePath,
        source_symbol: `${callee} call at line ${tokens[index].line}`,
        handler: callee,
        active_state: activeState,
        source_anchor: {
          line: callAnchor.line,
          sha256: callAnchor.sha256,
        },
        handler_source_file: relativePath,
        handler_source_symbol: `${callee} call at line ${tokens[index].line}`,
        handler_anchor: {
          line: callAnchor.line,
          sha256: callAnchor.sha256,
        },
        handler_resolution: "javascript_outbound_call",
        handler_calls: [callee],
        handler_call_sequence: [callee],
      });
      index = closeIndex;
    }
  }
  return discovered;
}

function enclosingNamedFunction(functions, byteOffset) {
  const containing = functions
    .filter((fn) => fn.start <= byteOffset && byteOffset < fn.end)
    .sort((left, right) => (left.end - left.start) - (right.end - right.start));
  return containing[0] ?? null;
}

export function discoverJsStorageMutations({
  repoRoot,
  relativePaths,
  surface = "hypervisor-app-local-storage",
  activeState = "active_application_local_state",
}) {
  const discovered = [];
  for (const relativePath of relativePaths) {
    const { source } = readRepoFile(repoRoot, relativePath);
    const tokens = lexSource(source, { language: "javascript" });
    const functions = [];
    for (let index = 0; index < tokens.length - 3; index += 1) {
      if (
        tokens[index].value !== "function"
        || tokens[index + 1].type !== "identifier"
        || tokens[index + 2].value !== "("
      ) {
        continue;
      }
      const bodyOpen = findMatchingToken(tokens, index + 2) + 1;
      let resolvedBodyOpen = bodyOpen;
      while (
        resolvedBodyOpen < tokens.length
        && tokens[resolvedBodyOpen].value !== "{"
        && tokens[resolvedBodyOpen].value !== ";"
      ) {
        resolvedBodyOpen += 1;
      }
      if (tokens[resolvedBodyOpen]?.value !== "{") {
        continue;
      }
      const bodyClose = findMatchingToken(tokens, resolvedBodyOpen);
      functions.push({
        name: tokens[index + 1].value,
        start: tokens[index].start,
        end: tokens[bodyClose].end,
      });
    }

    for (let index = 0; index < tokens.length - 4; index += 1) {
      if (
        !["localStorage", "sessionStorage"].includes(tokens[index].value)
        || tokens[index + 1].value !== "."
        || !["setItem", "removeItem", "clear"].includes(tokens[index + 2].value)
        || tokens[index + 3].value !== "("
      ) {
        continue;
      }
      const closeIndex = findMatchingToken(tokens, index + 3);
      const fn = enclosingNamedFunction(functions, tokens[index].start);
      const symbol = fn?.name ?? `module_scope_line_${tokens[index].line}`;
      const storage = tokens[index].value;
      const method = tokens[index + 2].value;
      const argumentRanges = topLevelRanges(tokens, index + 4, closeIndex);
      const keyExpression = method === "clear"
        ? "<all-keys>"
        : argumentRanges[0] === undefined
            ? "<missing-key>"
            : normalizeSymbolTokens(
                tokens,
                argumentRanges[0][0],
                argumentRanges[0][1],
              );
      const mutationAnchor = anchor(source, tokens[index], tokens[closeIndex]);
      discovered.push({
        identity: `js-storage-action:${relativePath}#${symbol}:${storage}.${method}:`
          + `${tokens[index].line}`,
        kind: "js_local_storage",
        surface,
        operation: `${storage}.${method} at ${symbol}`,
        storage_method: `${storage}.${method}`,
        storage_key_expression: keyExpression,
        source_file: relativePath,
        source_symbol: symbol,
        handler: `window.${storage}.${method}`,
        active_state: activeState,
        source_anchor: {
          line: mutationAnchor.line,
          sha256: mutationAnchor.sha256,
        },
      });
      index = closeIndex;
    }
  }
  return discovered;
}

const JS_FILESYSTEM_EFFECT_CALLEES = new Set([
  "appendFile",
  "appendFileSync",
  "copyFile",
  "copyFileSync",
  "createWriteStream",
  "mkdir",
  "mkdirSync",
  "rename",
  "renameSync",
  "rm",
  "rmSync",
  "rmdir",
  "rmdirSync",
  "unlink",
  "unlinkSync",
  "writeFile",
  "writeFileSync",
]);

const JS_PROCESS_EFFECT_CALLEES = new Set([
  "exec",
  "execFile",
  "execFileSync",
  "execSync",
  "fork",
  "spawn",
  "spawnSync",
]);

export function discoverJsSystemEffects({ repoRoot, relativePaths }) {
  const discovered = [];
  for (const relativePath of relativePaths) {
    const { source } = readRepoFile(repoRoot, relativePath);
    const tokens = lexSource(source, { language: "javascript" });
    const functions = [];
    for (let index = 0; index < tokens.length - 3; index += 1) {
      if (
        tokens[index].value !== "function"
        || tokens[index + 1].type !== "identifier"
        || tokens[index + 2].value !== "("
      ) {
        continue;
      }
      let paramsClose;
      try {
        paramsClose = findMatchingToken(tokens, index + 2);
      } catch {
        continue;
      }
      let bodyOpen = paramsClose + 1;
      while (
        bodyOpen < tokens.length
        && tokens[bodyOpen].value !== "{"
        && tokens[bodyOpen].value !== ";"
      ) {
        bodyOpen += 1;
      }
      if (tokens[bodyOpen]?.value !== "{") {
        continue;
      }
      let bodyClose;
      try {
        bodyClose = findMatchingToken(tokens, bodyOpen);
      } catch {
        continue;
      }
      functions.push({
        name: tokens[index + 1].value,
        start: tokens[index].start,
        end: tokens[bodyClose].end,
      });
    }

    const groups = new Map();
    for (let index = 0; index < tokens.length - 1; index += 1) {
      const token = tokens[index];
      const directFilesystem = JS_FILESYSTEM_EFFECT_CALLEES.has(token.value);
      const directProcess = JS_PROCESS_EFFECT_CALLEES.has(token.value);
      const processKill = (
        token.value === "kill"
        && tokens[index - 1]?.value === "."
      );
      if (!directFilesystem && !directProcess && !processKill) {
        continue;
      }
      const openIndex = findCallOpen(tokens, index);
      if (openIndex === -1) {
        continue;
      }
      const closeIndex = findMatchingToken(tokens, openIndex);
      const fn = enclosingNamedFunction(functions, token.start);
      const sourceSymbol = fn?.name ?? `module_scope_line_${token.line}`;
      const groupKey = `${relativePath}#${sourceSymbol}`;
      const callee = processKill
        ? `${tokens[index - 2]?.value ?? "<dynamic>"}.kill`
        : token.value;
      const category = directFilesystem ? "filesystem" : "process";
      const callAnchor = anchor(source, token, tokens[closeIndex]);
      const group = groups.get(groupKey) ?? {
        identity: `js-system-effect:${groupKey}`,
        kind: "js_system_effect",
        operation: `${category} effect at ${sourceSymbol}`,
        source_file: relativePath,
        source_symbol: sourceSymbol,
        handler: callee,
        source_anchor: {
          line: callAnchor.line,
          sha256: callAnchor.sha256,
        },
        handler_source_file: relativePath,
        handler_source_symbol: sourceSymbol,
        handler_anchor: {
          line: callAnchor.line,
          sha256: callAnchor.sha256,
        },
        handler_resolution: "javascript_system_effect_calls",
        handler_calls: [],
        handler_call_sequence: [],
        system_effect_categories: [],
        call_anchors: [],
      };
      group.handler_calls.push(callee);
      group.handler_call_sequence.push(callee);
      group.system_effect_categories.push(category);
      group.call_anchors.push(callAnchor);
      groups.set(groupKey, group);
      index = closeIndex;
    }

    for (const group of groups.values()) {
      const anchorMaterial = group.call_anchors
        .map((callAnchor) => `${callAnchor.line}:${callAnchor.sha256}`)
        .join("\n");
      const firstAnchor = group.call_anchors[0];
      discovered.push({
        ...group,
        handler_calls: [...new Set(group.handler_calls)].sort(),
        system_effect_categories: [...new Set(group.system_effect_categories)].sort(),
        source_anchor: {
          line: firstAnchor.line,
          sha256: sha256(anchorMaterial),
        },
        handler_anchor: {
          line: firstAnchor.line,
          sha256: sha256(anchorMaterial),
        },
        call_anchors: undefined,
      });
    }
  }
  return discovered.sort((left, right) => left.identity.localeCompare(right.identity));
}

export function discoverSwitchCases({
  repoRoot,
  relativePath,
  identityPrefix,
  surface,
}) {
  const { source } = readRepoFile(repoRoot, relativePath);
  const tokens = lexSource(source, { language: "javascript" });
  const discovered = [];
  for (let index = 0; index < tokens.length - 2; index += 1) {
    if (
      tokens[index].value !== "case"
      || tokens[index + 1].type !== "string"
      || tokens[index + 2].value !== ":"
    ) {
      continue;
    }
    let endIndex = index + 3;
    const stack = [];
    while (endIndex < tokens.length) {
      const token = tokens[endIndex];
      const value = token.value;
      if (isOpenToken(token)) {
        stack.push(value);
      } else if (isCloseToken(token)) {
        stack.pop();
      }
      if (
        stack.length === 0
        && (tokens[endIndex].value === "case" || tokens[endIndex].value === "default")
      ) {
        break;
      }
      endIndex += 1;
    }
    const caseAnchor = anchor(
      source,
      tokens[index],
      tokens[Math.max(index + 2, endIndex - 1)],
    );
    discovered.push({
      identity: `${identityPrefix}:${tokens[index + 1].value}`,
      kind: "compatibility_dispatch",
      surface,
      operation: tokens[index + 1].value,
      command: tokens[index + 1].value,
      source_file: relativePath,
      source_symbol: `case ${JSON.stringify(tokens[index + 1].value)}`,
      handler: "handleInvoke",
      source_anchor: {
        line: caseAnchor.line,
        sha256: caseAnchor.sha256,
      },
    });
    index = endIndex - 1;
  }
  return discovered;
}

export function assertUniqueIdentities(entries, label = "discovery") {
  const seen = new Map();
  for (const entry of entries) {
    const previous = seen.get(entry.identity);
    if (previous !== undefined) {
      throw new Error(
        `${label}: duplicate identity ${entry.identity} at ${previous} and `
        + `${entry.source_file}:${entry.source_anchor.line}`,
      );
    }
    seen.set(entry.identity, `${entry.source_file}:${entry.source_anchor.line}`);
  }
}

export function sortByIdentity(entries) {
  return [...entries].sort((left, right) => left.identity.localeCompare(right.identity));
}
