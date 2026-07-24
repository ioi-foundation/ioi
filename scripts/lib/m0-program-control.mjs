import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import ts from "typescript";

const HTTP_METHODS = new Set([
  "connect",
  "delete",
  "get",
  "head",
  "options",
  "patch",
  "post",
  "put",
  "trace",
]);
const AXUM_UNSUPPORTED_REGISTRATION_METHODS = new Set([
  "fallback",
  "fallback_service",
  "merge",
  "method_not_allowed_fallback",
  "nest",
  "nest_service",
  "route_service",
]);
const AXUM_SERVICE_ROUTER_METHODS = new Set([
  "any_service",
  "connect_service",
  "delete_service",
  "get_service",
  "head_service",
  "on_service",
  "options_service",
  "patch_service",
  "post_service",
  "put_service",
  "trace_service",
]);
const AXUM_METHOD_ROUTER_DECORATORS = new Set([
  "layer",
]);
const RUST_EFFECT_CALL = /(?:^|::|\.)(?:persist(?:_|$)|persist_record$|persist_env$|persist_availability_locked$|persist_runnability_locked$|write(?:_|$)|write_all$|remove_record$|remove_file$|remove_dir_all$|create_dir(?:_all)?$|rename$|save(?:_|$)|store(?:_|$)|store_typed$|append(?:_|$)|append_audit_event(?:_with_records)?$|state\.insert$|state\.delete$|state\.batch_apply$|admit_and_persist|apply_workspace_patch$|Command::new$|spawn$|send$|try_send$|submit_ibc_messages$|set_secret$|provision_with_domain$|perform_sign$|sync_all$|register_service$)/u;
const RUST_EXTERNAL_EFFECT_CALLS = new Set([
  "MuxEngine::open",
  "admit_artifact_availability_incident",
  "admit_code_editor_adapter_launch_plan",
  "admit_harness_profile_mutation",
  "admit_harness_session_binding",
  "admit_harness_session_terminal_attach",
  "admit_hypervisor_approved_operation",
  "admit_hypervisor_session_launch_recipe",
  "admit_managed_worker_instance_lifecycle_transition",
  "admit_model_route_mutation",
  "admit_model_weight_custody",
  "admit_physical_action_intent",
  "admit_private_workspace_mount",
  "admit_runtime_thread_event",
  "admit_service_composition_receipt_bundle",
  "admit_worker_package_install",
  "commit_runtime_memory_state",
  "commit_runtime_run_state_to_dir",
  "spawn_mux_writer_cfg",
  "sync_all",
  "write_all",
]);
const RUST_EXTERNAL_PURE_CALLS = new Set([
  "write_validator_sets",
]);
const RUST_OPEN_OPTIONS_MUTATING_METHODS = new Set([
  "append",
  "create",
  "create_new",
  "truncate",
  "write",
]);
const RUST_OPEN_OPTIONS_READ_ONLY_FLAGS = new Set([
  "O_CLOEXEC",
  "O_DIRECT",
  "O_DIRECTORY",
  "O_DSYNC",
  "O_NOATIME",
  "O_NOCTTY",
  "O_NOFOLLOW",
  "O_NONBLOCK",
  "O_PATH",
  "O_RDONLY",
  "O_SYNC",
]);
const RUST_OPEN_OPTIONS_WRITE_FLAGS = new Set([
  "O_APPEND",
  "O_CREAT",
  "O_EXCL",
  "O_RDWR",
  "O_TMPFILE",
  "O_TRUNC",
  "O_WRONLY",
]);
const RUST_OPEN_OPTIONS_WRITE_EFFECT = "std::fs::OpenOptions::open[write]";
const RUST_OPEN_OPTIONS_READ_ONLY = "std::fs::OpenOptions::open[read_only]";
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

function fsyncDirectory(directory) {
  let descriptor;
  try {
    descriptor = fs.openSync(directory, fs.constants.O_RDONLY);
    fs.fsyncSync(descriptor);
  } catch (error) {
    if (!["EINVAL", "ENOTSUP", "EPERM"].includes(error?.code)) {
      throw error;
    }
  } finally {
    if (descriptor !== undefined) {
      fs.closeSync(descriptor);
    }
  }
}

export function atomicWriteFileSync(
  absolutePath,
  source,
  { exclusive = false } = {},
) {
  const directory = path.dirname(absolutePath);
  const basename = path.basename(absolutePath);
  const temporaryPath = path.join(
    directory,
    `.${basename}.${process.pid}.${crypto.randomBytes(8).toString("hex")}.tmp`,
  );
  const existingMode = (() => {
    try {
      return fs.statSync(absolutePath).mode & 0o777;
    } catch (error) {
      if (error?.code === "ENOENT") {
        return 0o666;
      }
      throw error;
    }
  })();
  let descriptor;
  try {
    descriptor = fs.openSync(
      temporaryPath,
      fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY,
      existingMode,
    );
    const bytes = Buffer.isBuffer(source) ? source : Buffer.from(source, "utf8");
    let offset = 0;
    while (offset < bytes.length) {
      offset += fs.writeSync(
        descriptor,
        bytes,
        offset,
        bytes.length - offset,
      );
    }
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor);
    descriptor = undefined;
    if (exclusive) {
      fs.linkSync(temporaryPath, absolutePath);
      fs.unlinkSync(temporaryPath);
    } else {
      fs.renameSync(temporaryPath, absolutePath);
    }
    fsyncDirectory(directory);
  } catch (error) {
    if (descriptor !== undefined) {
      try {
        fs.closeSync(descriptor);
      } catch {
        // Preserve the original write failure.
      }
    }
    try {
      fs.unlinkSync(temporaryPath);
    } catch (cleanupError) {
      if (cleanupError?.code !== "ENOENT") {
        error.message += `; temporary-file cleanup failed: ${cleanupError.message}`;
      }
    }
    throw error;
  }
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

function resolveRustAliasMap(aliases, symbol) {
  let resolved = symbol;
  const seen = new Set();
  while (simpleRustSymbol(resolved)) {
    const parts = resolved.split("::");
    const first = parts[0];
    const alias = aliases?.get(first);
    if (alias === undefined || seen.has(first)) {
      break;
    }
    seen.add(first);
    resolved = [alias, ...parts.slice(1)].join("::");
  }
  return resolved;
}

function rustOpenOptionsMarkersInRange(
  tokens,
  start,
  end,
  { aliases = new Map(), relativePath = "<Rust source>" } = {},
) {
  const markers = new Map();
  for (let cursor = start; cursor < end - 1; cursor += 1) {
    if (
      tokens[cursor].value !== "new"
      || tokens[cursor + 1]?.value !== "("
    ) {
      continue;
    }
    let symbolStart = cursor;
    while (
      symbolStart >= start + 2
      && tokens[symbolStart - 1].value === "::"
      && tokens[symbolStart - 2].type === "identifier"
    ) {
      symbolStart -= 2;
    }
    const symbol = normalizeSymbolTokens(tokens, symbolStart, cursor + 1);
    const resolved = resolveRustAliasMap(aliases, symbol);
    if (!/^(?:std|tokio)::fs::OpenOptions::new$/u.test(resolved)) {
      continue;
    }
    const constructorClose = findMatchingToken(tokens, cursor + 1);
    if (constructorClose >= end) {
      throw new Error(
        `${relativePath}:${tokens[cursor].line}: OpenOptions constructor `
        + "escapes the discovered function body",
      );
    }
    let chainCursor = constructorClose + 1;
    let writeCapable = false;
    let opened = false;
    while (
      chainCursor + 2 < end
      && tokens[chainCursor].value === "."
      && tokens[chainCursor + 1].type === "identifier"
      && tokens[chainCursor + 2].value === "("
    ) {
      const methodToken = tokens[chainCursor + 1];
      const method = methodToken.value;
      const argumentsOpen = chainCursor + 2;
      const argumentsClose = findMatchingToken(tokens, argumentsOpen);
      if (argumentsClose >= end) {
        throw new Error(
          `${relativePath}:${methodToken.line}: OpenOptions ${method} call `
          + "escapes the discovered function body",
        );
      }
      if (method === "open") {
        markers.set(
          chainCursor + 1,
          writeCapable
            ? RUST_OPEN_OPTIONS_WRITE_EFFECT
            : RUST_OPEN_OPTIONS_READ_ONLY,
        );
        opened = true;
        break;
      }
      if (RUST_OPEN_OPTIONS_MUTATING_METHODS.has(method)) {
        const argument = tokens.slice(argumentsOpen + 1, argumentsClose);
        if (
          argument.length !== 1
          || !["true", "false"].includes(argument[0].value)
        ) {
          throw new Error(
            `${relativePath}:${methodToken.line}: unsupported dynamic `
            + `OpenOptions ${method} mode`,
          );
        }
        writeCapable ||= argument[0].value === "true";
      } else if (method === "custom_flags") {
        const argument = tokens.slice(argumentsOpen + 1, argumentsClose);
        const identifiers = argument
          .filter((token) => token.type === "identifier")
          .map((token) => token.value)
          .filter((value) => value !== "libc");
        const unknown = identifiers.filter((value) => (
          !RUST_OPEN_OPTIONS_READ_ONLY_FLAGS.has(value)
          && !RUST_OPEN_OPTIONS_WRITE_FLAGS.has(value)
        ));
        const unsupportedToken = argument.find((token) => (
          token.type === "number"
          || (
            token.type !== "identifier"
            && !["::", "|"].includes(token.value)
          )
        ));
        if (
          identifiers.length === 0
          || unknown.length > 0
          || unsupportedToken !== undefined
        ) {
          throw new Error(
            `${relativePath}:${methodToken.line}: unsupported OpenOptions `
            + "custom_flags form",
          );
        }
        writeCapable ||= identifiers.some((value) => (
          RUST_OPEN_OPTIONS_WRITE_FLAGS.has(value)
        ));
      } else if (!["mode", "read"].includes(method)) {
        throw new Error(
          `${relativePath}:${methodToken.line}: unsupported OpenOptions `
          + `builder method ${method}`,
        );
      }
      chainCursor = argumentsClose + 1;
    }
    if (!opened) {
      throw new Error(
        `${relativePath}:${tokens[cursor].line}: unsupported indirect `
        + "OpenOptions builder form",
      );
    }
  }
  return markers;
}

function callSequenceInRange(tokens, start, end, rustContext = {}) {
  const openOptionsMarkers = rustOpenOptionsMarkersInRange(
    tokens,
    start,
    end,
    rustContext,
  );
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
    const symbol = normalizeSymbolTokens(tokens, symbolStart, cursor + 1);
    calls.push(
      symbolStart === cursor && tokens[cursor - 1]?.value === "."
        ? `.${symbol}`
        : symbol,
    );
    const openOptionsMarker = openOptionsMarkers.get(cursor);
    if (openOptionsMarker !== undefined) {
      calls.push(openOptionsMarker);
    }
  }
  return calls;
}

function uniqueInOrder(values) {
  return values.filter((value, index) => values.indexOf(value) === index);
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

  for (let index = 0; index < tokens.length - 2; index += 1) {
    const memberCall = (
      tokens[index].value === "."
      && tokens[index + 1]?.type === "identifier"
      && tokens[index + 2]?.value === "("
    )
      ? tokens[index + 1]
      : null;
    if (
      memberCall !== null
      && AXUM_UNSUPPORTED_REGISTRATION_METHODS.has(memberCall.value)
    ) {
      throw new Error(
        `${relativePath}:${memberCall.line}: unsupported Axum registration `
        + `${memberCall.value}(...)`,
      );
    }
    if (
      tokens[index].value === "::"
      && tokens[index + 1]?.value === "route"
      && tokens[index + 2]?.value === "("
    ) {
      throw new Error(
        `${relativePath}:${tokens[index + 1].line}: unsupported associated Axum `
        + "route registration",
      );
    }
  }

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
    const pathTokens = tokens.slice(index + 3, commaIndex);
    if (pathTokens.length !== 1 || pathTokens[0].type !== "string") {
      throw new Error(`${relativePath}:${tokens[index].line}: route path is not one literal`);
    }
    const pathToken = pathTokens[0];

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
        && tokens[cursor + 1]?.value === "("
      ) {
        const handlerClose = findMatchingToken(tokens, cursor + 1);
        const argumentRanges = topLevelRanges(tokens, cursor + 2, handlerClose);
        if (HTTP_METHODS.has(value) || value === "any") {
          if (argumentRanges.length !== 1) {
            throw new Error(
              `${relativePath}:${tokens[cursor].line}: ${value}(...) must have one handler`,
            );
          }
          methods.push({
            method: value === "any" ? "ANY" : value.toUpperCase(),
            handler: normalizeSymbolTokens(
              tokens,
              argumentRanges[0][0],
              argumentRanges[0][1],
            ),
            callSequence: callSequenceInRange(
              tokens,
              argumentRanges[0][0],
              argumentRanges[0][1],
            ),
          });
        } else if (value === "on") {
          if (argumentRanges.length !== 2) {
            throw new Error(
              `${relativePath}:${tokens[cursor].line}: on(...) must have one `
              + "literal method filter and one handler",
            );
          }
          const filter = normalizeSymbolTokens(
            tokens,
            argumentRanges[0][0],
            argumentRanges[0][1],
          );
          const filters = [...filter.matchAll(
            /(?:^|::)(CONNECT|DELETE|GET|HEAD|OPTIONS|PATCH|POST|PUT|TRACE)\b/gu,
          )].map((match) => match[1]);
          const residue = filter
            .replaceAll(
              /(?:[A-Za-z_][A-Za-z0-9_]*::)*(?:CONNECT|DELETE|GET|HEAD|OPTIONS|PATCH|POST|PUT|TRACE)/gu,
              "",
            )
            .replaceAll(/[|()\s]/gu, "");
          if (filters.length === 0 || residue !== "") {
            throw new Error(
              `${relativePath}:${tokens[cursor].line}: unsupported dynamic Axum `
              + `method filter ${filter}`,
            );
          }
          for (const method of [...new Set(filters)]) {
            methods.push({
              method,
              handler: normalizeSymbolTokens(
                tokens,
                argumentRanges[1][0],
                argumentRanges[1][1],
              ),
              callSequence: callSequenceInRange(
                tokens,
                argumentRanges[1][0],
                argumentRanges[1][1],
              ),
            });
          }
        } else if (AXUM_METHOD_ROUTER_DECORATORS.has(value)) {
          if (argumentRanges.length !== 1) {
            throw new Error(
              `${relativePath}:${tokens[cursor].line}: ${value}(...) must have one layer`,
            );
          }
        } else if (AXUM_SERVICE_ROUTER_METHODS.has(value)) {
          throw new Error(
            `${relativePath}:${tokens[cursor].line}: unsupported Axum service `
            + `router ${value}(...)`,
          );
        } else {
          throw new Error(
            `${relativePath}:${tokens[cursor].line}: unsupported Axum method `
            + `router ${value}(...)`,
          );
        }
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
        registration_handler_call_sequence: method.callSequence,
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

function macroGeneratedRustFunctions(source, tokens, relativePath, templates) {
  const generated = [];
  for (let index = 0; index < tokens.length - 4; index += 1) {
    if (
      tokens[index].value !== "macro_rules"
      || tokens[index + 1]?.value !== "!"
      || tokens[index + 2]?.type !== "identifier"
      || tokens[index + 3]?.value !== "{"
    ) {
      continue;
    }
    const macroName = tokens[index + 2].value;
    const macroClose = findMatchingToken(tokens, index + 3);
    const patternOpen = tokens.findIndex(
      (token, cursor) => cursor > index + 3
        && cursor < macroClose
        && token.value === "(",
    );
    if (patternOpen === -1) {
      continue;
    }
    const patternClose = findMatchingToken(tokens, patternOpen);
    const parameters = topLevelRanges(tokens, patternOpen + 1, patternClose)
      .map(([start, end]) => tokens.slice(start, end).find(
        (token) => token.type === "identifier" && token.value.startsWith("$"),
      )?.value)
      .filter((value) => value !== undefined);
    const macroTemplates = templates.filter((definition) => (
      definition.start >= tokens[index].start
      && definition.end <= tokens[macroClose].end
      && definition.name.startsWith("$")
    ));
    if (macroTemplates.length === 0) {
      index = macroClose;
      continue;
    }

    for (let cursor = macroClose + 1; cursor < tokens.length - 2; cursor += 1) {
      if (
        tokens[cursor].value !== macroName
        || tokens[cursor + 1]?.value !== "!"
        || !["(", "[", "{"].includes(tokens[cursor + 2]?.value)
      ) {
        continue;
      }
      const invocationClose = findMatchingToken(tokens, cursor + 2);
      const argumentsByParameter = new Map();
      const argumentRanges = topLevelRanges(tokens, cursor + 3, invocationClose);
      if (argumentRanges.length !== parameters.length) {
        throw new Error(
          `${relativePath}:${tokens[cursor].line}: macro ${macroName} argument `
          + "count does not match its discoverable function template",
        );
      }
      for (let offset = 0; offset < parameters.length; offset += 1) {
        argumentsByParameter.set(
          parameters[offset],
          normalizeSymbolTokens(
            tokens,
            argumentRanges[offset][0],
            argumentRanges[offset][1],
          ),
        );
      }
      const invocationText = source.slice(
        tokens[cursor].start,
        tokens[invocationClose].end,
      );
      for (const template of macroTemplates) {
        const name = argumentsByParameter.get(template.name);
        if (!/^[A-Za-z_][A-Za-z0-9_]*$/u.test(name ?? "")) {
          throw new Error(
            `${relativePath}:${tokens[cursor].line}: macro-generated function `
            + `${template.name} does not resolve to one identifier`,
          );
        }
        const substitute = (value) => {
          let resolved = value;
          for (const [parameter, argument] of argumentsByParameter) {
            resolved = resolved.replaceAll(parameter, argument);
          }
          return resolved;
        };
        const generatedSource = `${substitute(template.source)}\n${invocationText}`;
        generated.push({
          ...template,
          name,
          line: tokens[cursor].line,
          sha256: sha256(generatedSource),
          start: tokens[cursor].start,
          end: tokens[invocationClose].end,
          source: generatedSource,
          callSequence: template.callSequence.map(substitute),
          resolution: "macro_generated_function",
        });
      }
      cursor = invocationClose;
    }
    index = macroClose;
  }
  return generated;
}

function rustAliases(tokens) {
  const aliases = new Map();
  for (let index = 0; index < tokens.length; index += 1) {
    if (tokens[index].value === "use") {
      let end = index + 1;
      const stack = [];
      while (end < tokens.length) {
        if (tokens[end].value === ";" && stack.length === 0) {
          break;
        }
        if (isOpenToken(tokens[end])) {
          stack.push(tokens[end].value);
        } else if (isCloseToken(tokens[end])) {
          stack.pop();
        }
        end += 1;
      }
      const body = tokens.slice(index + 1, end);
      const braceOpen = body.findIndex((token) => token.value === "{");
      const imports = [];
      if (braceOpen === -1) {
        imports.push(body);
      } else {
        const absoluteBraceOpen = index + 1 + braceOpen;
        const braceClose = findMatchingToken(tokens, absoluteBraceOpen);
        const prefix = tokens.slice(index + 1, absoluteBraceOpen);
        for (const [start, finish] of topLevelRanges(
          tokens,
          absoluteBraceOpen + 1,
          braceClose,
        )) {
          imports.push([...prefix, ...tokens.slice(start, finish)]);
        }
      }
      for (const imported of imports) {
        const asIndex = imported.findIndex((token) => token.value === "as");
        const targetTokens = asIndex === -1 ? imported : imported.slice(0, asIndex);
        const target = normalizeSymbolTokens(targetTokens, 0, targetTokens.length);
        const local = asIndex === -1
          ? targetTokens.filter((token) => token.type === "identifier").at(-1)?.value
          : imported[asIndex + 1]?.value;
        if (
          /^[A-Za-z_][A-Za-z0-9_]*$/u.test(local ?? "")
          && simpleRustSymbol(target)
          && local !== "self"
        ) {
          aliases.set(local, target);
        }
      }
      index = end;
      continue;
    }
    if (
      tokens[index].value === "let"
      && tokens[index + 1]?.type === "identifier"
      && tokens[index + 2]?.value === "="
    ) {
      let end = index + 3;
      while (end < tokens.length && tokens[end].value !== ";") {
        end += 1;
      }
      const target = normalizeSymbolTokens(tokens, index + 3, end);
      if (simpleRustSymbol(target)) {
        aliases.set(tokens[index + 1].value, target);
      }
    }
  }
  return aliases;
}

export function discoverRustFunctions({ repoRoot, relativePath }) {
  const { source } = readRepoFile(repoRoot, relativePath);
  const tokens = lexSource(source, { language: "rust" });
  const aliases = rustAliases(tokens);
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
    const callSequence = callSequenceInRange(
      tokens,
      bodyOpen + 1,
      bodyClose,
      { aliases, relativePath },
    );
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
  return [
    ...functions.filter((definition) => !definition.name.startsWith("$")),
    ...macroGeneratedRustFunctions(source, tokens, relativePath, functions),
  ];
}

export function buildRustFunctionIndex({ repoRoot, relativePaths }) {
  const index = new Map();
  const aliasesByFile = new Map();
  for (const relativePath of relativePaths) {
    const { source } = readRepoFile(repoRoot, relativePath);
    aliasesByFile.set(
      relativePath,
      rustAliases(lexSource(source, { language: "rust" })),
    );
    const functions = discoverRustFunctions({ repoRoot, relativePath });
    const byName = new Map();
    for (const fn of functions) {
      const existing = byName.get(fn.name) ?? [];
      existing.push(fn);
      byName.set(fn.name, existing);
    }
    index.set(relativePath, byName);
  }
  index.aliasesByFile = aliasesByFile;
  return index;
}

function simpleRustSymbol(handler) {
  return /^[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*$/u.test(handler);
}

function functionCandidates(functionIndex, relativePath, name) {
  return functionIndex.get(relativePath)?.get(name) ?? [];
}

const RUST_NON_HELPER_CALLS = new Set([
  "Box",
  "Err",
  "Json",
  "None",
  "Ok",
  "Path",
  "Query",
  "Some",
  "State",
  "String",
  "Vec",
  "format",
]);

function resolveRustAlias(functionIndex, relativePath, symbol) {
  return resolveRustAliasMap(
    functionIndex.aliasesByFile?.get(relativePath),
    symbol,
  );
}

function rustDefinitionResolution({
  functionIndex,
  moduleSourceFiles,
  defaultSourceFile,
  currentFile,
  symbol,
  seenResolutions = new Set(),
}) {
  if (!simpleRustSymbol(symbol) || symbol.includes(".")) {
    return { status: "external", candidates: [] };
  }
  const resolutionKey = `${currentFile}:${symbol}`;
  if (seenResolutions.has(resolutionKey)) {
    return { status: "ambiguous", candidates: [], resolved: symbol };
  }
  const nextSeenResolutions = new Set(seenResolutions);
  nextSeenResolutions.add(resolutionKey);
  const resolved = resolveRustAlias(functionIndex, currentFile, symbol);
  const parts = resolved.split("::");
  const name = parts.at(-1);
  if (parts.slice(0, -1).some((part) => /^[A-Z]/u.test(part))) {
    return { status: "external", candidates: [], resolved };
  }
  const moduleName = parts
    .slice(0, -1)
    .reverse()
    .find((part) => moduleSourceFiles.has(part)) ?? null;
  const explicitlyQualified = parts.length > 1;
  let preferredFile;
  if (moduleName !== null) {
    preferredFile = moduleSourceFiles.get(moduleName);
  } else {
    preferredFile = currentFile;
  }
  let candidates = functionCandidates(functionIndex, preferredFile, name);
  const reexport = candidates.length === 0
    ? functionIndex.aliasesByFile?.get(preferredFile)?.get(name)
    : undefined;
  if (reexport !== undefined && reexport !== resolved) {
    return rustDefinitionResolution({
      functionIndex,
      moduleSourceFiles,
      defaultSourceFile,
      currentFile: preferredFile,
      symbol: reexport,
      seenResolutions: nextSeenResolutions,
    });
  }
  if (
    candidates.length === 0
    && parts[0] === "super"
    && currentFile !== defaultSourceFile
    && moduleName === null
  ) {
    preferredFile = defaultSourceFile;
    candidates = functionCandidates(functionIndex, preferredFile, name);
  }
  if (candidates.length === 0 && explicitlyQualified) {
    candidates = [...functionIndex.values()]
      .flatMap((byName) => byName.get(name) ?? []);
    if (candidates.length === 1) {
      preferredFile = candidates[0].relativePath;
    }
  }
  return {
    status: candidates.length === 1
      ? "resolved"
      : candidates.length === 0
          ? "unresolved"
          : "ambiguous",
    candidates,
    resolved,
    preferredFile,
    explicitlyQualified,
  };
}

function effectRelevantRustCall(call) {
  const name = call.split("::").at(-1);
  return RUST_EFFECT_CALL.test(call)
    || /^(?:admit|append|apply|commit|create|delete|ensure|execute|persist|provision|register|remove|rename|save|send|set|spawn|store|submit|sync|write)(?:_|$)/u
      .test(name);
}

function knownExternalRustEffect(call, resolved = call) {
  const symbols = [call, resolved];
  return symbols.some((symbol) => (
    RUST_EXTERNAL_EFFECT_CALLS.has(symbol)
    || RUST_EXTERNAL_EFFECT_CALLS.has(symbol.split("::").at(-1))
    || symbol === RUST_OPEN_OPTIONS_WRITE_EFFECT
    || /^(?:std|tokio)::fs::File::(?:create|create_new)$/u.test(symbol)
    || /^(?:std|tokio)::fs::(?:copy|create_dir(?:_all)?|hard_link|remove_dir(?:_all)?|remove_file|rename|set_permissions|write)$/u
      .test(symbol)
    || /^std::os::(?:unix|windows)::fs::(?:symlink|symlink_dir|symlink_file)$/u
      .test(symbol)
    || /^(?:std::thread|tokio|tokio::task)::spawn$/u.test(symbol)
    || symbol === "tokio::task::spawn_blocking"
    || symbol === "libc::flock"
    || symbol === "libc::write"
  ));
}

function knownExternalRustPure(call, resolved = call) {
  return [call, resolved].some((symbol) => (
    RUST_EXTERNAL_PURE_CALLS.has(symbol.split("::").at(-1))
  ));
}

export function attachRustHandlerDefinitions({
  repoRoot,
  entries,
  functionIndex,
  defaultSourceFile,
  moduleSourceFiles = new Map(),
}) {
  return entries.map((entry) => {
    const rootResolution = simpleRustSymbol(entry.handler ?? "")
      ? rustDefinitionResolution({
          functionIndex,
          moduleSourceFiles,
          defaultSourceFile,
          currentFile: entry.source_file,
          symbol: entry.handler,
        })
      : { status: "inline", candidates: [] };

    if (!["resolved", "inline"].includes(rootResolution.status)) {
      return {
        ...entry,
        handler_source_file: rootResolution.preferredFile ?? entry.source_file,
        handler_source_symbol: entry.handler,
        handler_anchor: null,
        handler_resolution: rootResolution.status,
      };
    }

    const definitions = [];
    const sequence = [];
    const effects = [];
    const errors = [];
    const visited = new Set();
    const visitCalls = (relativePath, calls) => {
      for (const call of calls) {
        sequence.push(call);
        if (RUST_NON_HELPER_CALLS.has(call) || call.includes(".")) {
          if (RUST_EFFECT_CALL.test(call) || knownExternalRustEffect(call)) {
            effects.push(call);
          }
          continue;
        }
        const aliasedCall = resolveRustAlias(
          functionIndex,
          relativePath,
          call,
        );
        if (knownExternalRustEffect(call, aliasedCall)) {
          effects.push(call);
          continue;
        }
        if (knownExternalRustPure(call, aliasedCall)) {
          continue;
        }
        const resolution = rustDefinitionResolution({
          functionIndex,
          moduleSourceFiles,
          defaultSourceFile,
          currentFile: relativePath,
          symbol: call,
        });
        if (resolution.status === "resolved") {
          if (RUST_EFFECT_CALL.test(call)) {
            effects.push(call);
          }
          visitDefinition(resolution.candidates[0]);
        } else if (
          resolution.status === "ambiguous"
          && effectRelevantRustCall(call)
        ) {
          errors.push(
            `${relativePath}: ambiguous effect-relevant Rust helper ${call}`,
          );
        } else if (
          resolution.status === "unresolved"
          && effectRelevantRustCall(call)
        ) {
          errors.push(
            `${relativePath}: unresolved effect-relevant Rust helper ${call}`,
          );
        } else if (resolution.status === "external" && RUST_EFFECT_CALL.test(call)) {
          effects.push(call);
        }
      }
    };
    const visitDefinition = (definition) => {
      const key = `${definition.relativePath}:${definition.line}:${definition.name}`;
      if (visited.has(key)) {
        return;
      }
      visited.add(key);
      definitions.push(definition);
      visitCalls(definition.relativePath, definition.callSequence);
    };

    let definition = null;
    if (rootResolution.status === "resolved") {
      definition = rootResolution.candidates[0];
      visitDefinition(definition);
    } else {
      visitCalls(
        entry.source_file,
        entry.registration_handler_call_sequence ?? [],
      );
    }
    if (errors.length > 0) {
      return {
        ...entry,
        handler_source_file: definition?.relativePath ?? entry.source_file,
        handler_source_symbol: definition?.name ?? entry.handler,
        handler_anchor: null,
        handler_resolution: `effect_reachability_error:${errors.join("; ")}`,
      };
    }
    const closureMaterial = [
      `registration:${entry.source_file}:${entry.source_anchor.sha256}`,
      ...definitions
        .map((reachable) => (
          `${reachable.relativePath}:${reachable.line}:${reachable.name}:${reachable.sha256}`
        ))
        .sort(),
    ].join("\n");
    return {
      ...entry,
      handler_source_file: definition?.relativePath ?? entry.source_file,
      handler_source_symbol: definition?.name ?? entry.handler,
      handler_anchor: {
        line: definition?.line ?? entry.source_anchor.line,
        sha256: sha256(closureMaterial),
      },
      handler_resolution: definition === null
        ? "inline_registration_transitive_closure"
        : definition.resolution === "macro_generated_function"
            ? "macro_generated_transitive_closure"
            : "transitive_function_closure",
      handler_calls: [...new Set(sequence)].sort(),
      handler_call_sequence: sequence,
      handler_effect_calls: uniqueInOrder(effects),
      reachable_handler_functions: definitions.map((reachable) => (
        `${reachable.relativePath}#${reachable.name}:${reachable.line}`
      )),
    };
  });
}

export function rustModuleSourceMap(relativePaths) {
  const modules = new Map();
  for (const relativePath of relativePaths) {
    const basename = path.basename(relativePath, path.extname(relativePath));
    const moduleName = basename === "mod"
      ? path.basename(path.dirname(relativePath))
      : basename;
    if (modules.has(moduleName)) {
      throw new Error(
        `ambiguous Rust module ${moduleName}: `
        + `${modules.get(moduleName)} and ${relativePath}`,
      );
    }
    modules.set(moduleName, relativePath);
  }
  return modules;
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

function rustTraitImplRange({
  source,
  tokens,
  relativePath,
  traitName,
  serviceType,
}) {
  const matches = [];
  for (let index = 0; index < tokens.length; index += 1) {
    if (tokens[index].value !== "impl") {
      continue;
    }
    let openIndex = index + 1;
    while (
      openIndex < tokens.length
      && !["{", ";"].includes(tokens[openIndex].value)
    ) {
      openIndex += 1;
    }
    if (tokens[openIndex]?.value !== "{") {
      continue;
    }
    const forIndex = tokens.findIndex(
      (token, cursor) => (
        cursor > index
        && cursor < openIndex
        && token.value === "for"
      ),
    );
    if (forIndex === -1) {
      continue;
    }
    const trait = normalizeSymbolTokens(tokens, index + 1, forIndex);
    const implementation = normalizeSymbolTokens(tokens, forIndex + 1, openIndex)
      .split(/\s+where\s+/u)[0];
    if (
      (trait === traitName || trait.endsWith(`::${traitName}`))
      && implementation === serviceType
    ) {
      matches.push({
        openIndex,
        closeIndex: findMatchingToken(tokens, openIndex),
      });
    }
  }
  if (matches.length !== 1) {
    throw new Error(
      `${relativePath}: expected one ${traitName} implementation for `
      + `${serviceType}, found ${matches.length}`,
    );
  }
  const range = matches[0];
  return {
    ...range,
    source: source.slice(
      tokens[range.openIndex].start,
      tokens[range.closeIndex].end,
    ),
  };
}

function matchMethodRegistry({
  source,
  tokens,
  relativePath,
  handlerDefinition,
}) {
  const bodyOpen = tokens.findIndex((token) => token.value === "{");
  if (bodyOpen === -1) {
    throw new Error(`${relativePath}: handle_service_call body not found`);
  }
  const aliases = new Set(["method"]);
  for (let index = bodyOpen + 1; index < tokens.length - 3; index += 1) {
    if (
      tokens[index].value === "let"
      && tokens[index + 1]?.type === "identifier"
      && tokens[index + 2]?.value === "="
      && aliases.has(tokens[index + 3]?.value)
    ) {
      aliases.add(tokens[index + 1].value);
    }
  }

  const matches = [];
  const stack = [];
  for (let index = bodyOpen; index < tokens.length - 2; index += 1) {
    const token = tokens[index];
    if (
      token.value === "match"
      && stack.length === 1
      && aliases.has(tokens[index + 1]?.value)
    ) {
      let openIndex = index + 2;
      while (openIndex < tokens.length && tokens[openIndex].value !== "{") {
        openIndex += 1;
      }
      if (tokens[openIndex]?.value !== "{") {
        throw new Error(
          `${relativePath}:${token.line}: dispatch match body not found`,
        );
      }
      matches.push({
        matchIndex: index,
        openIndex,
        closeIndex: findMatchingToken(tokens, openIndex),
      });
    }
    if (isOpenToken(token)) {
      stack.push(token.value);
    } else if (isCloseToken(token)) {
      stack.pop();
    }
  }
  if (matches.length !== 1) {
    throw new Error(
      `${relativePath}:${handlerDefinition.line}: expected one top-level literal `
      + `method dispatch in handle_service_call, found ${matches.length}`,
    );
  }
  return matches[0];
}

function looksLikeMethodArm(tokens, start, closeIndex) {
  let cursor = start;
  let sawPattern = false;
  while (cursor < closeIndex) {
    if (tokens[cursor].type === "string" || tokens[cursor].value === "_") {
      sawPattern = true;
      cursor += 1;
      continue;
    }
    if (tokens[cursor].value === "|") {
      cursor += 1;
      continue;
    }
    return sawPattern && tokens[cursor].value === "=>";
  }
  return false;
}

function methodArmEnd(tokens, start, closeIndex) {
  let cursor = start;
  const stack = [];
  while (cursor < closeIndex) {
    const token = tokens[cursor];
    if (
      cursor > start
      && stack.length === 0
      && looksLikeMethodArm(tokens, cursor, closeIndex)
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

function parseLiteralMethodArms({
  source,
  tokens,
  openIndex,
  closeIndex,
  relativePath,
  lineOffset = 0,
}) {
  const arms = [];
  let cursor = openIndex + 1;
  while (cursor < closeIndex) {
    while (tokens[cursor]?.value === ",") {
      cursor += 1;
    }
    if (cursor >= closeIndex) {
      break;
    }
    let arrowIndex = cursor;
    while (arrowIndex < closeIndex && tokens[arrowIndex].value !== "=>") {
      if (isOpenToken(tokens[arrowIndex])) {
        throw new Error(
          `${relativePath}:${lineOffset + tokens[cursor].line}: unsupported `
          + "structured service dispatch pattern",
        );
      }
      arrowIndex += 1;
    }
    if (arrowIndex === closeIndex) {
      throw new Error(
        `${relativePath}:${lineOffset + tokens[cursor].line}: service dispatch `
        + "arm has no arrow",
      );
    }
    const patternTokens = tokens.slice(cursor, arrowIndex);
    const patternResidue = patternTokens.filter((token) => (
      token.type !== "string"
      && token.value !== "|"
      && token.value !== "_"
    ));
    if (patternResidue.length > 0) {
      throw new Error(
        `${relativePath}:${lineOffset + tokens[cursor].line}: unsupported dynamic `
        + `service dispatch pattern ${normalizeSymbolTokens(
          patternTokens,
          0,
          patternTokens.length,
        )}`,
      );
    }
    const methods = patternTokens
      .filter((token) => token.type === "string")
      .map((token) => token.value);
    const wildcard = patternTokens.some((token) => token.value === "_");
    if ((methods.length === 0) === !wildcard || (wildcard && methods.length > 0)) {
      throw new Error(
        `${relativePath}:${lineOffset + tokens[cursor].line}: invalid service `
        + "dispatch pattern",
      );
    }
    const armEnd = methodArmEnd(tokens, arrowIndex + 1, closeIndex);
    if (!wildcard) {
      const finalToken = tokens[Math.max(arrowIndex, armEnd - 1)];
      const armAnchor = anchor(source, tokens[cursor], finalToken);
      arms.push({
        methods,
        line: lineOffset + armAnchor.line,
        sha256: armAnchor.sha256,
        calls: callSequenceInRange(tokens, arrowIndex + 1, armEnd),
      });
    }
    cursor = tokens[armEnd]?.value === "," ? armEnd + 1 : armEnd;
  }
  if (arms.length === 0) {
    throw new Error(`${relativePath}: no literal service methods discovered`);
  }
  return arms;
}

function selectedTraitFunctions({
  repoRoot,
  relativePath,
  traitName,
  serviceType,
}) {
  const { source } = readRepoFile(repoRoot, relativePath);
  const tokens = lexSource(source, { language: "rust" });
  const range = rustTraitImplRange({
    source,
    tokens,
    relativePath,
    traitName,
    serviceType,
  });
  const functions = discoverRustFunctions({ repoRoot, relativePath }).filter((definition) => (
    definition.start > tokens[range.openIndex].start
    && definition.end < tokens[range.closeIndex].end
  ));
  return { source, tokens, range, functions };
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

export function discoverWalletServiceMethods({
  repoRoot,
  relativePath = "crates/services/src/wallet_network/mod.rs",
}) {
  const selected = selectedTraitFunctions({
    repoRoot,
    relativePath,
    traitName: "BlockchainService",
    serviceType: "WalletNetworkService",
  });
  singleLiteralServiceId(selected.functions, relativePath, "wallet_network");
  const handlers = selected.functions.filter((fn) => fn.name === "handle_service_call");
  if (handlers.length !== 1) {
    throw new Error(
      `${relativePath}: expected one WalletNetworkService::handle_service_call, `
      + `found ${handlers.length}`,
    );
  }
  const handlerDefinition = handlers[0];
  const source = handlerDefinition.source;
  const tokens = lexSource(source, { language: "rust" });
  const registry = matchMethodRegistry({
    source,
    tokens,
    relativePath,
    handlerDefinition,
  });
  const arms = parseLiteralMethodArms({
    source,
    tokens,
    openIndex: registry.openIndex,
    closeIndex: registry.closeIndex,
    relativePath,
    lineOffset: handlerDefinition.line - 1,
  });
  return arms.flatMap((arm) => {
    const delegatedCalls = arm.calls.filter((call) => (
      call.startsWith("handlers::")
    ));
    if (delegatedCalls.length !== 1) {
      throw new Error(
        `${relativePath}:${arm.line}: wallet dispatch arm must resolve exactly `
        + `one handler call, found ${delegatedCalls.length}`,
      );
    }
    return arm.methods.map((method) => ({
      identity: `service:wallet.network:${method}`,
      kind: "service_method",
      surface: "wallet.network",
      operation: method,
      service_method: method,
      source_file: relativePath,
      source_symbol: `WalletNetworkService::handle_service_call[${method}]`,
      handler: delegatedCalls[0],
      registration_handler_call_sequence: arm.calls,
      source_anchor: {
        line: arm.line,
        sha256: arm.sha256,
      },
    }));
  });
}

export function discoverRustMatchServiceMethods({
  repoRoot,
  relativePath,
  serviceId,
  serviceType,
  surface = `blockchain-service:${serviceId}`,
  activeState,
}) {
  const selected = selectedTraitFunctions({
    repoRoot,
    relativePath,
    traitName: "BlockchainService",
    serviceType,
  });
  singleLiteralServiceId(selected.functions, relativePath, serviceId);
  const handlers = selected.functions.filter((fn) => fn.name === "handle_service_call");
  if (handlers.length !== 1) {
    throw new Error(
      `${relativePath}: expected one handle_service_call function, found ${handlers.length}`,
    );
  }

  const handlerDefinition = handlers[0];
  const source = handlerDefinition.source;
  const tokens = lexSource(source, { language: "rust" });
  const registry = matchMethodRegistry({
    source,
    tokens,
    relativePath,
    handlerDefinition,
  });
  const arms = parseLiteralMethodArms({
    source,
    tokens,
    openIndex: registry.openIndex,
    closeIndex: registry.closeIndex,
    relativePath,
    lineOffset: handlerDefinition.line - 1,
  });
  const discovered = arms.flatMap((arm) => arm.methods.map((method) => {
    const delegatedCalls = arm.calls.filter((call) => ![
      "codec::from_bytes_canonical",
      "ioi_types::codec::from_bytes_canonical",
      "format",
      "Ok",
      "Err",
      "Some",
      "None",
    ].includes(call));
    return {
      identity: `service:${serviceId}:${method}`,
      kind: "service_method",
      surface,
      operation: method,
      service_method: method,
      service_id: serviceId,
      source_file: relativePath,
      source_symbol: `${serviceType}::handle_service_call[${method}]`,
      handler: delegatedCalls.at(-1) ?? `${serviceType}::handle_service_call`,
      active_state: activeState,
      source_anchor: {
        line: arm.line,
        sha256: arm.sha256,
      },
      registration_handler_call_sequence: arm.calls,
    };
  }));
  const functionIndex = buildRustFunctionIndex({
    repoRoot,
    relativePaths: [relativePath],
  });
  return attachRustHandlerDefinitions({
    repoRoot,
    entries: discovered.map((entry) => ({
      ...entry,
      dispatch_handler: entry.handler,
      handler: "<literal-service-dispatch-arm>",
    })),
    functionIndex,
    defaultSourceFile: relativePath,
  }).map((entry) => ({
    ...entry,
    handler: entry.dispatch_handler,
    dispatch_handler: undefined,
    handler_source_symbol: entry.source_symbol,
    handler_resolution: "literal_service_dispatch_transitive_closure",
  }));
}

function serviceInterfaceAttribute(tokens, index) {
  if (tokens[index]?.value !== "#" || tokens[index + 1]?.value !== "[") {
    return null;
  }
  const attributeClose = findMatchingToken(tokens, index + 1);
  const macroIndex = tokens.findIndex((token, cursor) => (
    cursor > index + 1
    && cursor < attributeClose
    && token.value === "service_interface"
  ));
  if (macroIndex === -1 || tokens[macroIndex + 1]?.value !== "(") {
    return null;
  }
  const pathTokens = tokens.slice(index + 2, macroIndex);
  if (pathTokens.some((token) => (
    token.type !== "identifier" && token.value !== "::"
  ))) {
    throw new Error(
      `${tokens[index].line}: unsupported service_interface attribute path`,
    );
  }
  return {
    attributeClose,
    argsOpen: macroIndex + 1,
    argsClose: findMatchingToken(tokens, macroIndex + 1),
  };
}

function markerAttribute(tokens, index, marker) {
  if (tokens[index]?.value !== "#" || tokens[index + 1]?.value !== "[") {
    return null;
  }
  const attributeClose = findMatchingToken(tokens, index + 1);
  const body = tokens.slice(index + 2, attributeClose);
  const markerIndex = body.findIndex((token) => token.value === marker);
  if (markerIndex === -1) {
    return null;
  }
  if (
    markerIndex !== body.length - 1
    || body.some((token) => (
      token.type !== "identifier" && token.value !== "::"
    ))
  ) {
    throw new Error(
      `${tokens[index].line}: unsupported ${marker} attribute form`,
    );
  }
  return { attributeClose };
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
  const attributes = tokens
    .map((_token, index) => ({
      index,
      descriptor: serviceInterfaceAttribute(tokens, index),
    }))
    .filter((entry) => entry.descriptor !== null);
  if (attributes.length !== 1) {
    throw new Error(
      `${relativePath}: expected one service_interface registry, found ${attributes.length}`,
    );
  }

  const { index: attributeIndex, descriptor } = attributes[0];
  const serviceIdTokens = tokens.slice(descriptor.argsOpen + 1, descriptor.argsClose);
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

  let implIndex = descriptor.attributeClose + 1;
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
    const methodAttribute = markerAttribute(tokens, index, "method");
    if (methodAttribute === null) {
      continue;
    }
    let fnIndex = methodAttribute.attributeClose + 1;
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
  const functionIndex = buildRustFunctionIndex({
    repoRoot,
    relativePaths: [relativePath],
  });
  return attachRustHandlerDefinitions({
    repoRoot,
    entries: discovered.map((entry) => ({
      ...entry,
      declared_handler: entry.handler,
      handler: entry.handler.split("::").at(-1),
    })),
    functionIndex,
    defaultSourceFile: relativePath,
  }).map((entry) => ({
    ...entry,
    handler: entry.declared_handler,
    declared_handler: undefined,
    handler_source_symbol: entry.source_symbol,
    handler_resolution: entry.handler_anchor === null
      ? entry.handler_resolution
      : "service_interface_method_transitive_closure",
  }));
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

export function discoverProtoServiceNames({ repoRoot, relativePath }) {
  const { source } = readRepoFile(repoRoot, relativePath);
  const tokens = lexSource(source, { language: "proto" });
  const names = [];
  for (let index = 0; index < tokens.length - 2; index += 1) {
    if (
      tokens[index].value === "service"
      && tokens[index + 1]?.type === "identifier"
      && tokens[index + 2]?.value === "{"
    ) {
      names.push(tokens[index + 1].value);
      index = findMatchingToken(tokens, index + 2);
    }
  }
  if (names.length === 0) {
    throw new Error(`${relativePath}: no literal proto services discovered`);
  }
  return names.sort();
}

export function discoverTonicServiceRegistrations({ repoRoot, relativePath }) {
  const { source } = readRepoFile(repoRoot, relativePath);
  const tokens = lexSource(source, { language: "rust" });
  const registrations = [];
  for (let index = 0; index < tokens.length - 3; index += 1) {
    if (
      tokens[index].value === "."
      && /^add_.*service$/u.test(tokens[index + 1]?.value ?? "")
      && tokens[index + 2]?.value === "("
      && tokens[index + 1].value !== "add_service"
    ) {
      throw new Error(
        `${relativePath}:${tokens[index + 1].line}: unsupported tonic service `
        + `registration ${tokens[index + 1].value}(...)`,
      );
    }
    if (
      tokens[index].value === "::"
      && tokens[index + 1]?.value === "add_service"
      && tokens[index + 2]?.value === "("
    ) {
      throw new Error(
        `${relativePath}:${tokens[index + 1].line}: unsupported associated tonic `
        + "service registration",
      );
    }
    if (
      tokens[index].value !== "."
      || tokens[index + 1]?.value !== "add_service"
      || tokens[index + 2]?.value !== "("
    ) {
      continue;
    }
    const closeIndex = findMatchingToken(tokens, index + 2);
    const candidates = [];
    for (let cursor = index + 3; cursor < closeIndex - 2; cursor += 1) {
      if (
        tokens[cursor].type === "identifier"
        && tokens[cursor].value.endsWith("Server")
        && tokens[cursor + 1]?.value === "::"
        && ["new", "with_interceptor"].includes(tokens[cursor + 2]?.value)
        && tokens[cursor + 3]?.value === "("
      ) {
        candidates.push(tokens[cursor].value.slice(0, -"Server".length));
      }
    }
    const services = [...new Set(candidates)];
    if (services.length !== 1) {
      throw new Error(
        `${relativePath}:${tokens[index + 1].line}: tonic add_service must `
        + `contain exactly one literal generated service constructor, found `
        + services.length,
      );
    }
    registrations.push(services[0]);
    index = closeIndex;
  }
  return registrations.sort();
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

const JS_FILESYSTEM_EFFECT_CALLEES = new Set([
  "append",
  "appendFile",
  "appendFileSync",
  "chmod",
  "chmodSync",
  "chown",
  "chownSync",
  "copyFile",
  "copyFileSync",
  "cp",
  "cpSync",
  "createWriteStream",
  "fchmod",
  "fchmodSync",
  "fchown",
  "fchownSync",
  "fdatasync",
  "fdatasyncSync",
  "fsync",
  "fsyncSync",
  "link",
  "linkSync",
  "mkdir",
  "mkdirSync",
  "mkdtemp",
  "mkdtempSync",
  "open",
  "openSync",
  "rename",
  "renameSync",
  "rm",
  "rmSync",
  "rmdir",
  "rmdirSync",
  "symlink",
  "symlinkSync",
  "truncate",
  "truncateSync",
  "unlink",
  "unlinkSync",
  "utimes",
  "utimesSync",
  "write",
  "writeSync",
  "writev",
  "writevSync",
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

const JS_STORAGE_EFFECT_CALLEES = new Set(["clear", "removeItem", "setItem"]);
const JS_PROCESS_TERMINATION_CALLEES = new Set(["abort", "exit", "kill"]);

function javascriptScriptKind(relativePath) {
  if (relativePath.endsWith(".tsx")) {
    return ts.ScriptKind.TSX;
  }
  if (relativePath.endsWith(".jsx")) {
    return ts.ScriptKind.JSX;
  }
  if (relativePath.endsWith(".ts")) {
    return ts.ScriptKind.TS;
  }
  return ts.ScriptKind.JS;
}

function parseJavaScriptSource(source, fileName, scriptKind) {
  const sourceFile = ts.createSourceFile(
    fileName,
    source,
    ts.ScriptTarget.Latest,
    true,
    scriptKind,
  );
  const diagnostics = sourceFile.parseDiagnostics ?? [];
  if (diagnostics.length > 0) {
    const diagnostic = diagnostics[0];
    const line = diagnostic.start === undefined
      ? 1
      : sourceFile.getLineAndCharacterOfPosition(diagnostic.start).line + 1;
    throw new Error(
      `${fileName}:${line}: unsupported JavaScript syntax: `
      + ts.flattenDiagnosticMessageText(diagnostic.messageText, "\n"),
    );
  }
  return sourceFile;
}

function isJavaScriptScope(node) {
  return ts.isSourceFile(node)
    || ts.isBlock(node)
    || ts.isCaseBlock(node)
    || ts.isCatchClause(node)
    || ts.isFunctionDeclaration(node)
    || ts.isFunctionExpression(node)
    || ts.isArrowFunction(node)
    || ts.isMethodDeclaration(node)
    || ts.isConstructorDeclaration(node)
    || ts.isGetAccessorDeclaration(node)
    || ts.isSetAccessorDeclaration(node);
}

function nearestJavaScriptScope(node) {
  let cursor = node;
  while (cursor !== undefined && !isJavaScriptScope(cursor)) {
    cursor = cursor.parent;
  }
  return cursor;
}

function javascriptScopeChain(node) {
  const scopes = [];
  let cursor = node;
  while (cursor !== undefined) {
    if (isJavaScriptScope(cursor)) {
      scopes.push(cursor);
    }
    cursor = cursor.parent;
  }
  return scopes;
}

function staticPropertyName(name) {
  if (ts.isIdentifier(name) || ts.isPrivateIdentifier(name)) {
    return name.text;
  }
  if (
    ts.isStringLiteral(name)
    || ts.isNumericLiteral(name)
    || ts.isNoSubstitutionTemplateLiteral(name)
  ) {
    return name.text;
  }
  if (
    ts.isComputedPropertyName(name)
    && (
      ts.isStringLiteral(name.expression)
      || ts.isNoSubstitutionTemplateLiteral(name.expression)
    )
  ) {
    return name.expression.text;
  }
  return null;
}

function moduleEffectDescriptor(moduleName, importedName) {
  if (/^(?:node:)?fs(?:\/promises)?$/u.test(moduleName)) {
    return JS_FILESYSTEM_EFFECT_CALLEES.has(importedName)
      ? { domain: "filesystem", callee: importedName }
      : { domain: "filesystem_namespace" };
  }
  if (/^(?:node:)?child_process$/u.test(moduleName)) {
    return JS_PROCESS_EFFECT_CALLEES.has(importedName)
      ? { domain: "process", callee: importedName }
      : { domain: "process_namespace" };
  }
  if (/^(?:node:)?process$/u.test(moduleName)) {
    return JS_PROCESS_TERMINATION_CALLEES.has(importedName)
      ? { domain: "process", callee: `process.${importedName}` }
      : { domain: "process_namespace" };
  }
  if (importedName === "fetch") {
    return { domain: "network", callee: "fetch" };
  }
  if (importedName === "request" && /^(?:node:)?https?$/u.test(moduleName)) {
    return { domain: "network", callee: "request" };
  }
  if (importedName === "WebSocket" || importedName === "EventSource") {
    return { domain: "network", callee: importedName };
  }
  return null;
}

function unwrapJavaScriptExpression(node) {
  let current = node;
  while (
    current !== undefined
    && (
      ts.isParenthesizedExpression(current)
      || ts.isAsExpression(current)
      || ts.isTypeAssertionExpression(current)
      || ts.isNonNullExpression(current)
      || ts.isSatisfiesExpression(current)
    )
  ) {
    current = current.expression;
  }
  return current;
}

function requireModuleName(node) {
  const expression = unwrapJavaScriptExpression(node);
  if (
    !ts.isCallExpression(expression)
    || !ts.isIdentifier(expression.expression)
    || expression.expression.text !== "require"
    || expression.arguments.length !== 1
    || !ts.isStringLiteral(expression.arguments[0])
  ) {
    return null;
  }
  return expression.arguments[0].text;
}

function buildJavaScriptBindings(sourceFile) {
  const bindings = new Map();
  const mutatedObjects = new Set();
  const add = (name, record) => {
    const records = bindings.get(name) ?? [];
    records.push(record);
    bindings.set(name, records);
  };
  const addBindingName = (name, initializer, declaration, descriptor = null) => {
    if (ts.isIdentifier(name)) {
      add(name.text, {
        descriptor,
        initializer,
        position: declaration.getStart(sourceFile),
        scope: nearestJavaScriptScope(declaration.parent),
      });
      return;
    }
    if (ts.isObjectBindingPattern(name)) {
      for (const element of name.elements) {
        if (!ts.isIdentifier(element.name)) {
          throw new Error(
            `${sourceFile.fileName}: unsupported nested JavaScript effect alias binding`,
          );
        }
        const property = element.propertyName === undefined
          ? element.name.text
          : staticPropertyName(element.propertyName);
        if (property === null) {
          throw new Error(
            `${sourceFile.fileName}: unsupported computed JavaScript effect alias binding`,
          );
        }
        add(element.name.text, {
          descriptor: {
            domain: "member_alias",
            base: initializer,
            property,
          },
          initializer: null,
          position: declaration.getStart(sourceFile),
          scope: nearestJavaScriptScope(declaration.parent),
        });
      }
    }
  };

  const visit = (node) => {
    if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier)) {
      const moduleName = node.moduleSpecifier.text;
      const clause = node.importClause;
      if (clause?.name !== undefined) {
        add(clause.name.text, {
          descriptor: moduleEffectDescriptor(moduleName, "default"),
          initializer: null,
          position: -1,
          scope: sourceFile,
        });
      }
      if (clause?.namedBindings !== undefined) {
        if (ts.isNamespaceImport(clause.namedBindings)) {
          const namespace = moduleEffectDescriptor(moduleName, "<namespace>");
          add(clause.namedBindings.name.text, {
            descriptor: namespace,
            initializer: null,
            position: -1,
            scope: sourceFile,
          });
        } else {
          for (const element of clause.namedBindings.elements) {
            const importedName = element.propertyName?.text ?? element.name.text;
            add(element.name.text, {
              descriptor: moduleEffectDescriptor(moduleName, importedName),
              initializer: null,
              position: -1,
              scope: sourceFile,
            });
          }
        }
      }
    } else if (ts.isParameter(node) && ts.isIdentifier(node.name)) {
      add(node.name.text, {
        descriptor: { domain: "dynamic_parameter" },
        initializer: null,
        position: node.getStart(sourceFile),
        scope: nearestJavaScriptScope(node.parent),
      });
    } else if (ts.isVariableDeclaration(node)) {
      const moduleName = node.initializer === undefined
        ? null
        : requireModuleName(node.initializer);
      const descriptor = moduleName === null
        ? null
        : moduleEffectDescriptor(moduleName, "<namespace>");
      addBindingName(node.name, node.initializer ?? null, node, descriptor);
    } else if (
      ts.isBinaryExpression(node)
      && node.operatorToken.kind === ts.SyntaxKind.EqualsToken
    ) {
      const left = unwrapJavaScriptExpression(node.left);
      if (ts.isIdentifier(left)) {
        add(left.text, {
          descriptor: null,
          initializer: node.right,
          position: node.getStart(sourceFile),
          scope: nearestJavaScriptScope(node),
        });
      } else if (
        ts.isPropertyAccessExpression(left)
        && ts.isIdentifier(unwrapJavaScriptExpression(left.expression))
      ) {
        mutatedObjects.add(unwrapJavaScriptExpression(left.expression).text);
      } else if (
        ts.isElementAccessExpression(left)
        && ts.isIdentifier(unwrapJavaScriptExpression(left.expression))
      ) {
        mutatedObjects.add(unwrapJavaScriptExpression(left.expression).text);
      }
    }
    if (ts.isCallExpression(node)) {
      const callee = unwrapJavaScriptExpression(node.expression);
      if (
        ts.isPropertyAccessExpression(callee)
        && (
          (
            ts.isIdentifier(unwrapJavaScriptExpression(callee.expression))
            && unwrapJavaScriptExpression(callee.expression).text === "Object"
            && callee.name.text === "assign"
          )
          || (
            ts.isIdentifier(unwrapJavaScriptExpression(callee.expression))
            && unwrapJavaScriptExpression(callee.expression).text === "Reflect"
            && callee.name.text === "set"
          )
        )
      ) {
        const target = node.arguments[0] === undefined
          ? null
          : unwrapJavaScriptExpression(node.arguments[0]);
        if (target !== null && ts.isIdentifier(target)) {
          mutatedObjects.add(target.text);
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  let expanded = true;
  while (expanded) {
    expanded = false;
    for (const name of [...mutatedObjects]) {
      for (const record of bindings.get(name) ?? []) {
        const initializer = record.initializer === null
          ? null
          : unwrapJavaScriptExpression(record.initializer);
        if (
          initializer !== null
          && ts.isIdentifier(initializer)
          && !mutatedObjects.has(initializer.text)
        ) {
          mutatedObjects.add(initializer.text);
          expanded = true;
        }
      }
    }
  }
  return { bindings, mutatedObjects };
}

function bindingForIdentifier(identifier, analysis) {
  const records = analysis.bindings.get(identifier.text) ?? [];
  const scopes = javascriptScopeChain(identifier);
  const position = identifier.getStart(analysis.sourceFile);
  const candidates = records
    .filter((record) => record.position <= position && scopes.includes(record.scope))
    .sort((left, right) => (
      scopes.indexOf(left.scope) - scopes.indexOf(right.scope)
      || right.position - left.position
    ));
  return candidates[0] ?? null;
}

function objectLiteralProperty(object, propertyName) {
  let dynamicSpread = false;
  for (let index = object.properties.length - 1; index >= 0; index -= 1) {
    const property = object.properties[index];
    if (ts.isSpreadAssignment(property)) {
      dynamicSpread = true;
      continue;
    }
    const name = staticPropertyName(property.name);
    if (name !== propertyName) {
      continue;
    }
    if (ts.isPropertyAssignment(property)) {
      return { expression: property.initializer, dynamicSpread };
    }
    if (ts.isShorthandPropertyAssignment(property)) {
      return { expression: property.name, dynamicSpread };
    }
    return { expression: null, dynamicSpread: true };
  }
  return { expression: null, dynamicSpread };
}

function boundJavaScriptExpression(node, analysis, seen = new Set()) {
  const expression = unwrapJavaScriptExpression(node);
  if (!ts.isIdentifier(expression) || seen.has(expression.text)) {
    return expression;
  }
  const binding = bindingForIdentifier(expression, analysis);
  if (
    binding === null
    || binding.initializer === null
    || binding.descriptor?.domain === "dynamic_parameter"
  ) {
    return expression;
  }
  seen.add(expression.text);
  return boundJavaScriptExpression(binding.initializer, analysis, seen);
}

function staticJavaScriptString(node, analysis, seen = new Set()) {
  const expression = unwrapJavaScriptExpression(node);
  if (
    ts.isStringLiteral(expression)
    || ts.isNoSubstitutionTemplateLiteral(expression)
  ) {
    return expression.text;
  }
  if (ts.isIdentifier(expression)) {
    if (seen.has(expression.text)) {
      return null;
    }
    const binding = bindingForIdentifier(expression, analysis);
    if (
      binding === null
      || binding.initializer === null
      || binding.descriptor?.domain === "dynamic_parameter"
    ) {
      return null;
    }
    seen.add(expression.text);
    return staticJavaScriptString(binding.initializer, analysis, seen);
  }
  if (ts.isConditionalExpression(expression)) {
    const whenTrue = staticJavaScriptString(expression.whenTrue, analysis, new Set(seen));
    const whenFalse = staticJavaScriptString(expression.whenFalse, analysis, new Set(seen));
    return whenTrue !== null && whenTrue === whenFalse ? whenTrue : null;
  }
  return null;
}

function javascriptExpressionText(node, analysis) {
  if (node === undefined) {
    return "<missing>";
  }
  const expression = unwrapJavaScriptExpression(node);
  if (
    ts.isStringLiteral(expression)
    || ts.isNoSubstitutionTemplateLiteral(expression)
  ) {
    return expression.text;
  }
  const text = expression.getText(analysis.sourceFile);
  try {
    const tokens = lexSource(text, { language: "javascript" });
    return normalizeSymbolTokens(tokens, 0, tokens.length);
  } catch {
    return text.replaceAll(/\s+/gu, " ").trim();
  }
}

function memberEffectDescriptor(baseNode, property, analysis, seen) {
  const base = resolveJavaScriptEffect(baseNode, analysis, seen);
  if (base?.domain === "filesystem_namespace") {
    return JS_FILESYSTEM_EFFECT_CALLEES.has(property)
      ? { domain: "filesystem", callee: property }
      : base;
  }
  if (base?.domain === "process_namespace") {
    if (JS_PROCESS_EFFECT_CALLEES.has(property)) {
      return { domain: "process", callee: property };
    }
    if (JS_PROCESS_TERMINATION_CALLEES.has(property)) {
      return { domain: "process", callee: `process.${property}` };
    }
    return base;
  }
  if (base?.domain === "storage_namespace") {
    return JS_STORAGE_EFFECT_CALLEES.has(property)
      ? {
          domain: "storage",
          callee: property,
          storage: base.storage,
        }
      : base;
  }
  if (base?.domain === "global_namespace") {
    if (["fetch", "EventSource", "WebSocket"].includes(property)) {
      return { domain: "network", callee: property };
    }
    if (["localStorage", "sessionStorage"].includes(property)) {
      return { domain: "storage_namespace", storage: property };
    }
    if (property === "process") {
      return { domain: "process_namespace" };
    }
  }
  if (base?.domain === "navigator_namespace" && property === "sendBeacon") {
    return { domain: "network", callee: "sendBeacon" };
  }

  const boundBase = boundJavaScriptExpression(baseNode, analysis);
  if (ts.isObjectLiteralExpression(boundBase)) {
    const resolved = objectLiteralProperty(boundBase, property);
    if (resolved.expression !== null) {
      return resolveJavaScriptEffect(resolved.expression, analysis, seen);
    }
  }
  if (property === "request") {
    return { domain: "network", callee: "request" };
  }
  if (property === "sendBeacon") {
    return { domain: "network", callee: "sendBeacon" };
  }
  if (property === "kill") {
    return {
      domain: "process",
      callee: `${javascriptExpressionText(baseNode, analysis)}.kill`,
    };
  }
  return null;
}

function resolveJavaScriptEffect(node, analysis, seen = new Set()) {
  const expression = unwrapJavaScriptExpression(node);
  if (expression === undefined) {
    return null;
  }
  const requiredModule = requireModuleName(expression);
  if (requiredModule !== null) {
    return moduleEffectDescriptor(requiredModule, "<namespace>");
  }
  if (ts.isIdentifier(expression)) {
    const builtins = {
      EventSource: { domain: "network", callee: "EventSource" },
      WebSocket: { domain: "network", callee: "WebSocket" },
      daemon: { domain: "network", callee: "daemon" },
      fetch: { domain: "network", callee: "fetch" },
      globalThis: { domain: "global_namespace" },
      localStorage: { domain: "storage_namespace", storage: "localStorage" },
      navigator: { domain: "navigator_namespace" },
      process: { domain: "process_namespace" },
      sessionStorage: { domain: "storage_namespace", storage: "sessionStorage" },
      window: { domain: "global_namespace" },
    };
    const binding = bindingForIdentifier(expression, analysis);
    if (binding !== null && !seen.has(expression.text)) {
      seen.add(expression.text);
      if (binding.descriptor?.domain === "member_alias") {
        return memberEffectDescriptor(
          binding.descriptor.base,
          binding.descriptor.property,
          analysis,
          seen,
        );
      }
      if (binding.descriptor?.domain === "dynamic_parameter") {
        return null;
      }
      if (binding.descriptor !== null) {
        return binding.descriptor;
      }
      if (binding.initializer !== null) {
        return resolveJavaScriptEffect(binding.initializer, analysis, seen);
      }
    }
    if (JS_FILESYSTEM_EFFECT_CALLEES.has(expression.text)) {
      return { domain: "filesystem", callee: expression.text };
    }
    if (JS_PROCESS_EFFECT_CALLEES.has(expression.text)) {
      return { domain: "process", callee: expression.text };
    }
    return builtins[expression.text] ?? null;
  }
  if (ts.isPropertyAccessExpression(expression)) {
    return memberEffectDescriptor(
      expression.expression,
      expression.name.text,
      analysis,
      seen,
    );
  }
  if (ts.isElementAccessExpression(expression)) {
    const property = expression.argumentExpression === undefined
      ? null
      : staticJavaScriptString(expression.argumentExpression, analysis);
    if (property !== null) {
      return memberEffectDescriptor(expression.expression, property, analysis, seen);
    }
    const base = resolveJavaScriptEffect(expression.expression, analysis, seen);
    if (
      base !== null
      && [
        "filesystem",
        "filesystem_namespace",
        "global_namespace",
        "navigator_namespace",
        "network",
        "process",
        "process_namespace",
        "storage",
        "storage_namespace",
      ].includes(base.domain)
    ) {
      const line = analysis.lineFor(expression);
      throw new Error(
        `${analysis.relativePath}:${line}: unsupported dynamic computed `
        + `JavaScript effect member ${javascriptExpressionText(expression, analysis)}`,
      );
    }
  }
  return null;
}

function resolvedObjectProperty(node, propertyName, analysis, seen = new Set()) {
  const expression = unwrapJavaScriptExpression(node);
  if (ts.isIdentifier(expression)) {
    if (analysis.mutatedObjects.has(expression.text) || seen.has(expression.text)) {
      return { expression: null, dynamic: true };
    }
    const binding = bindingForIdentifier(expression, analysis);
    if (binding === null || binding.initializer === null) {
      return { expression: null, dynamic: true };
    }
    seen.add(expression.text);
    return resolvedObjectProperty(binding.initializer, propertyName, analysis, seen);
  }
  if (
    expression.kind === ts.SyntaxKind.UndefinedKeyword
    || expression.kind === ts.SyntaxKind.NullKeyword
  ) {
    return { expression: null, dynamic: false };
  }
  if (!ts.isObjectLiteralExpression(expression)) {
    return { expression: null, dynamic: true };
  }
  const direct = objectLiteralProperty(expression, propertyName);
  if (direct.expression !== null) {
    return direct.dynamicSpread
      ? { expression: null, dynamic: true }
      : { expression: direct.expression, dynamic: false };
  }
  for (let index = expression.properties.length - 1; index >= 0; index -= 1) {
    const property = expression.properties[index];
    if (!ts.isSpreadAssignment(property)) {
      continue;
    }
    const spread = resolvedObjectProperty(
      property.expression,
      propertyName,
      analysis,
      new Set(seen),
    );
    if (spread.expression !== null || spread.dynamic) {
      return spread;
    }
  }
  return { expression: null, dynamic: false };
}

function javascriptMethod(node, analysis, { missing = "DYNAMIC" } = {}) {
  if (node === null || node === undefined) {
    return missing;
  }
  const literal = staticJavaScriptString(node, analysis);
  if (
    literal !== null
    && /^(?:CONNECT|DELETE|GET|HEAD|OPTIONS|PATCH|POST|PUT|TRACE)$/iu.test(literal)
  ) {
    return literal.toUpperCase();
  }
  return `DYNAMIC(${javascriptExpressionText(node, analysis)})`;
}

function fetchMethod(options, analysis) {
  if (options === undefined) {
    return "GET";
  }
  const method = resolvedObjectProperty(options, "method", analysis);
  if (method.expression !== null) {
    return javascriptMethod(method.expression, analysis);
  }
  return method.dynamic
    ? `DYNAMIC(${javascriptExpressionText(options, analysis)}.method)`
    : "GET";
}

function templateText(node) {
  if (ts.isNoSubstitutionTemplateLiteral(node)) {
    return node.text;
  }
  let text = node.head.text;
  for (const [index, span] of node.templateSpans.entries()) {
    text += `__IOI_TEMPLATE_EXPRESSION_${index}__`;
    text += span.literal.text;
  }
  return text;
}

function javascriptContexts(relativePath, source) {
  const rootHash = sha256(source);
  let executableSource = source;
  let rootBaseLine = 0;
  let root;
  try {
    root = parseJavaScriptSource(
      executableSource,
      relativePath,
      javascriptScriptKind(relativePath),
    );
  } catch (error) {
    if (/\(function\s*\(\)\s*\{/u.test(source)) {
      executableSource = `${source}\n})();`;
    } else if (/\}\)\(\);\s*$/u.test(source)) {
      executableSource = `(function () {\n${source}`;
      rootBaseLine = -1;
    } else {
      throw error;
    }
    root = parseJavaScriptSource(
      executableSource,
      relativePath,
      javascriptScriptKind(relativePath),
    );
  }
  const contexts = [{
    source: executableSource,
    sourceFile: root,
    baseLine: rootBaseLine,
    rootHash,
  }];
  let templateOrdinal = 0;
  const visit = (node) => {
    if (
      ts.isNoSubstitutionTemplateLiteral(node)
      || ts.isTemplateExpression(node)
    ) {
      const materialized = templateText(node);
      const scripts = [];
      for (const match of materialized.matchAll(
        /<script\b[^>]*>([\s\S]*?)<\/script\s*>/giu,
      )) {
        scripts.push({
          source: match[1],
          offset: match.index + match[0].indexOf(match[1]),
        });
      }
      if (
        scripts.length === 0
        && (
          ts.isVariableDeclaration(node.parent)
          && ts.isIdentifier(node.parent.name)
          && /(?:bootstrap|client|javascript|script|worker)/iu.test(node.parent.name.text)
          || ts.isPropertyAssignment(node.parent)
          && /(?:bootstrap|client|javascript|script|worker)/iu.test(
            staticPropertyName(node.parent.name) ?? "",
          )
        )
        && /(?:\bfetch\s*(?:\?\.)?\(|\bprocess\s*(?:\.|\[)|\b(?:localStorage|sessionStorage)\s*(?:\.|\[)|\b(?:exec|execFile|execFileSync|execSync|fork|spawn|spawnSync|writeFile|writeFileSync)\s*(?:\?\.)?\()/u
          .test(materialized)
      ) {
        scripts.push({ source: materialized, offset: 0 });
      }
      const templateLine = rootBaseLine
        + root.getLineAndCharacterOfPosition(node.getStart(root)).line
        + 1;
      for (const script of scripts) {
        templateOrdinal += 1;
        const offsetLines = (materialized.slice(0, script.offset).match(/\n/gu) ?? []).length;
        const fileName = `${relativePath}#generated-script-${templateOrdinal}.js`;
        contexts.push({
          source: script.source,
          sourceFile: parseJavaScriptSource(script.source, fileName, ts.ScriptKind.JS),
          baseLine: templateLine - 1 + offsetLines,
          rootHash,
        });
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(root);
  return contexts;
}

function enclosingJavaScriptFunction(node, sourceFile) {
  let cursor = node.parent;
  while (cursor !== undefined) {
    if (
      (ts.isFunctionDeclaration(cursor) || ts.isFunctionExpression(cursor))
      && cursor.name !== undefined
    ) {
      return cursor.name.getText(sourceFile);
    }
    if (
      (
        ts.isArrowFunction(cursor)
        || ts.isFunctionExpression(cursor)
      )
      && ts.isVariableDeclaration(cursor.parent)
      && ts.isIdentifier(cursor.parent.name)
    ) {
      return cursor.parent.name.text;
    }
    if (
      ts.isMethodDeclaration(cursor)
      && cursor.name !== undefined
    ) {
      return staticPropertyName(cursor.name);
    }
    cursor = cursor.parent;
  }
  return null;
}

function collectJavaScriptEffects({ repoRoot, relativePath }) {
  const { source } = readRepoFile(repoRoot, relativePath);
  const effects = [];
  for (const context of javascriptContexts(relativePath, source)) {
    const bindings = buildJavaScriptBindings(context.sourceFile);
    const analysis = {
      ...bindings,
      relativePath,
      sourceFile: context.sourceFile,
      lineFor(node) {
        return context.baseLine
          + context.sourceFile.getLineAndCharacterOfPosition(
            node.getStart(context.sourceFile),
          ).line
          + 1;
      },
    };
    const visit = (node) => {
      if (ts.isCallExpression(node) || ts.isNewExpression(node)) {
        const descriptor = resolveJavaScriptEffect(node.expression, analysis);
        if (
          descriptor !== null
          && ["filesystem", "network", "process", "storage"].includes(descriptor.domain)
        ) {
          const args = [...(node.arguments ?? [])];
          const line = analysis.lineFor(node);
          const callText = node.getText(context.sourceFile);
          effects.push({
            descriptor,
            args,
            node,
            analysis,
            line,
            sourceSymbol: enclosingJavaScriptFunction(node, context.sourceFile)
              ?? `module_scope_line_${line}`,
            anchor: {
              line,
              sha256: sha256(`${context.rootHash}:${callText}`),
            },
          });
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(context.sourceFile);
  }
  return effects;
}

export function javascriptSourceHasEffects({ repoRoot, relativePath }) {
  return collectJavaScriptEffects({ repoRoot, relativePath }).length > 0;
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
    const effects = collectJavaScriptEffects({ repoRoot, relativePath })
      .filter((effect) => effect.descriptor.domain === "network");
    for (const effect of effects) {
      const { callee } = effect.descriptor;
      let method;
      let target;
      if (callee === "daemon") {
        method = javascriptMethod(effect.args[0], effect.analysis);
        target = javascriptExpressionText(effect.args[1], effect.analysis);
      } else if (callee === "fetch") {
        target = javascriptExpressionText(effect.args[0], effect.analysis);
        method = fetchMethod(effect.args[1], effect.analysis);
      } else if (callee === "request") {
        const options = effect.args[0];
        const methodProperty = options === undefined
          ? { expression: null, dynamic: true }
          : resolvedObjectProperty(options, "method", effect.analysis);
        const pathProperty = options === undefined
          ? { expression: null, dynamic: true }
          : resolvedObjectProperty(options, "path", effect.analysis);
        method = methodProperty.expression === null
          ? methodProperty.dynamic
              ? `DYNAMIC(${javascriptExpressionText(options, effect.analysis)}.method)`
              : "DYNAMIC"
          : javascriptMethod(methodProperty.expression, effect.analysis);
        target = pathProperty.expression === null
          ? javascriptExpressionText(options, effect.analysis)
          : javascriptExpressionText(pathProperty.expression, effect.analysis);
      } else {
        target = javascriptExpressionText(effect.args[0], effect.analysis);
        method = callee === "WebSocket"
          ? "WEBSOCKET"
          : callee === "sendBeacon"
              ? "POST"
              : "GET";
      }
      const baseIdentity = `js-outbound:${surface}:${method} ${target}`;
      const ordinal = (duplicateOrdinals.get(baseIdentity) ?? 0) + 1;
      duplicateOrdinals.set(baseIdentity, ordinal);
      const sourceSymbol = `${callee} call at line ${effect.line}`;
      discovered.push({
        identity: `${baseIdentity}#${ordinal}`,
        kind: "js_outbound",
        surface,
        operation: `${method} ${target}`,
        method,
        path: target,
        source_file: relativePath,
        source_symbol: sourceSymbol,
        handler: callee,
        active_state: activeState,
        source_anchor: effect.anchor,
        handler_source_file: relativePath,
        handler_source_symbol: sourceSymbol,
        handler_anchor: effect.anchor,
        handler_resolution: "typescript_ast_outbound_call",
        handler_calls: [callee],
        handler_call_sequence: [callee],
      });
    }
  }
  return discovered;
}

export function discoverJsStorageMutations({
  repoRoot,
  relativePaths,
  surface = "hypervisor-app-local-storage",
  activeState = "active_application_local_state",
}) {
  const discovered = [];
  const duplicateOrdinals = new Map();
  for (const relativePath of relativePaths) {
    const effects = collectJavaScriptEffects({ repoRoot, relativePath })
      .filter((effect) => effect.descriptor.domain === "storage");
    for (const effect of effects) {
      const { callee: method, storage } = effect.descriptor;
      const keyExpression = method === "clear"
        ? "<all-keys>"
        : javascriptExpressionText(effect.args[0], effect.analysis);
      const baseIdentity = `js-storage-action:${relativePath}#${effect.sourceSymbol}:`
        + `${storage}.${method}:${effect.line}`;
      const ordinal = (duplicateOrdinals.get(baseIdentity) ?? 0) + 1;
      duplicateOrdinals.set(baseIdentity, ordinal);
      discovered.push({
        identity: ordinal === 1 ? baseIdentity : `${baseIdentity}#${ordinal}`,
        kind: "js_local_storage",
        surface,
        operation: `${storage}.${method} at ${effect.sourceSymbol}`,
        storage_method: `${storage}.${method}`,
        storage_key_expression: keyExpression,
        source_file: relativePath,
        source_symbol: effect.sourceSymbol,
        handler: `window.${storage}.${method}`,
        active_state: activeState,
        source_anchor: effect.anchor,
      });
    }
  }
  return discovered;
}

export function discoverJsSystemEffects({ repoRoot, relativePaths }) {
  const discovered = [];
  for (const relativePath of relativePaths) {
    const groups = new Map();
    const effects = collectJavaScriptEffects({ repoRoot, relativePath })
      .filter((effect) => ["filesystem", "process"].includes(effect.descriptor.domain));
    for (const effect of effects) {
      const category = effect.descriptor.domain;
      const callee = effect.descriptor.callee;
      const groupKey = `${relativePath}#${effect.sourceSymbol}`;
      const group = groups.get(groupKey) ?? {
        identity: `js-system-effect:${groupKey}`,
        kind: "js_system_effect",
        operation: `${category} effect at ${effect.sourceSymbol}`,
        source_file: relativePath,
        source_symbol: effect.sourceSymbol,
        handler: callee,
        source_anchor: effect.anchor,
        handler_source_file: relativePath,
        handler_source_symbol: effect.sourceSymbol,
        handler_anchor: effect.anchor,
        handler_resolution: "typescript_ast_system_effect_calls",
        handler_calls: [],
        handler_call_sequence: [],
        system_effect_categories: [],
        call_anchors: [],
      };
      group.handler_calls.push(callee);
      group.handler_call_sequence.push(callee);
      group.system_effect_categories.push(category);
      group.call_anchors.push(effect.anchor);
      groups.set(groupKey, group);
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
