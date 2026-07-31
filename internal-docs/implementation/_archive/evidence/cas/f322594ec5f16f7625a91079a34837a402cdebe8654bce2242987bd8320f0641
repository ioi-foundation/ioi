// Shared estate primitives. Every tool loads its scan boundary from
// program/estate-boundary.v1.json rather than carrying an inline ignore list.
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

export const ESTATE_ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
);
export const REPO_ROOT = path.resolve(ESTATE_ROOT, "..", "..");
export const ESTATE_REL = path.relative(REPO_ROOT, ESTATE_ROOT);

let boundaryCache = null;

export function boundary() {
  if (boundaryCache) return boundaryCache;
  boundaryCache = readJson(
    path.join(ESTATE_ROOT, "program", "estate-boundary.v1.json"),
  );
  return boundaryCache;
}

export function readJson(absolute) {
  return JSON.parse(fs.readFileSync(absolute, "utf8"));
}

export function writeJsonDeterministic(absolute, value) {
  fs.mkdirSync(path.dirname(absolute), { recursive: true });
  fs.writeFileSync(absolute, `${JSON.stringify(value, null, 2)}\n`);
}

// Capture and restore an exact, bounded set of files around a multi-tool
// mutation. Generated projections and filing moves are writes just as surely
// as the primary JSON update is; a transaction that snapshots only the files
// it writes directly is not atomic once a child process starts regenerating
// them. Callers must enumerate every possible target before the first write.
export function snapshotFileSet(absolutePaths) {
  return [...new Set(absolutePaths.map((entry) => path.resolve(entry)))]
    .sort()
    .map((absolute) => {
      if (!fs.existsSync(absolute)) {
        return { absolute, existed: false, bytes: null, mode: null };
      }
      const stat = fs.lstatSync(absolute);
      if (!stat.isFile()) {
        throw new Error(
          `file transaction target is not a regular file: ${absolute}`,
        );
      }
      return {
        absolute,
        existed: true,
        bytes: fs.readFileSync(absolute),
        mode: stat.mode & 0o7777,
      };
    });
}

export function restoreFileSet(snapshot) {
  // Remove newly-created targets first. This matters for filing moves: the
  // destination must disappear before the original source bytes are restored.
  for (const entry of snapshot.filter((item) => !item.existed)) {
    fs.rmSync(entry.absolute, { force: true });
  }
  for (const entry of snapshot.filter((item) => item.existed)) {
    // A failed rename/recreate may leave a new regular file or symlink at the
    // original path. Remove that replacement before restoring the snapshotted
    // regular file so writes cannot follow a substituted inode.
    fs.rmSync(entry.absolute, { force: true });
    fs.mkdirSync(path.dirname(entry.absolute), { recursive: true });
    fs.writeFileSync(entry.absolute, entry.bytes);
    fs.chmodSync(entry.absolute, entry.mode);
  }
}

export function withFileRollback(absolutePaths, mutation) {
  const snapshot = snapshotFileSet(absolutePaths);
  try {
    return mutation();
  } catch (error) {
    restoreFileSet(snapshot);
    throw error;
  }
}

// Strict singleton option parser shared by mutating selectors. A missing
// value, a flag presented as the value, or a duplicate selector must refuse
// before any caller scans and writes its estate.
export function singletonOption(argv, name) {
  const indexes = argv
    .map((value, index) => value === name ? index : -1)
    .filter((index) => index >= 0);
  if (indexes.length === 0) return { present: false, value: null, error: null };
  if (indexes.length > 1) {
    return {
      present: true,
      value: null,
      error: `${name} may be supplied at most once`,
    };
  }
  const value = argv[indexes[0] + 1];
  if (!value || value.startsWith("-")) {
    return {
      present: true,
      value: null,
      error: `${name} requires one non-flag value`,
    };
  }
  return { present: true, value, error: null };
}

export function sha256(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

export function sha256File(absolute) {
  return sha256(fs.readFileSync(absolute));
}

export function sha256Text(text) {
  return sha256(Buffer.from(text, "utf8"));
}

function excluded(relative) {
  return boundary().not_estate.some((entry) => {
    const pattern = entry.pattern;
    if (pattern.endsWith("/")) {
      return relative === pattern.slice(0, -1) ||
        relative.startsWith(pattern);
    }
    return relative === pattern || relative.startsWith(`${pattern}/`);
  });
}

// Walk the estate honouring the declared boundary. Never descends into a
// non-estate directory, so a nested checkout costs one readdir entry, not a
// recursive traversal.
export function listEstateFiles(subdirectory = "") {
  const out = [];
  const start = subdirectory
    ? path.join(ESTATE_ROOT, subdirectory)
    : ESTATE_ROOT;
  if (!fs.existsSync(start)) return out;
  const stack = [start];
  while (stack.length > 0) {
    const current = stack.pop();
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const absolute = path.join(current, entry.name);
      const relative = path.relative(ESTATE_ROOT, absolute);
      if (excluded(relative)) continue;
      if (entry.isDirectory()) {
        stack.push(absolute);
      } else if (entry.isFile()) {
        out.push(relative);
      }
    }
  }
  return out.sort();
}

export function inScope(relative, scopeList) {
  return scopeList.some((scope) =>
    scope.endsWith("/") ? relative.startsWith(scope) : relative === scope
  );
}

export function repoFileExists(relative) {
  return fs.existsSync(path.join(REPO_ROOT, relative));
}

// A finding is the only shape a tool reports. Structured so every lane can
// aggregate, filter, and count without parsing prose.
export function finding(level, check, message, extra = {}) {
  return { level, check, message, ...extra };
}

// Write a whole string to a file descriptor SYNCHRONOUSLY, retrying the
// non-blocking-pipe case.
//
// This is not a style preference. `process.stdout.write()` is asynchronous when
// stdout is a PIPE, and every tool here ends with `process.exit(report(...))`,
// which tears the process down before the pipe drains. Redirected to a file the
// output was complete; piped to a consumer it was TRUNCATED mid-value — so the
// same verdict parsed when a human redirected it and failed when a machine read
// it, which is the worst possible failure mode for a machine channel. Found by
// tools/test-json-stdout-purity.mjs on a 156 KB report that arrived as 146 KB.
function writeAllSync(fd, text) {
  const buffer = Buffer.from(text, "utf8");
  let offset = 0;
  while (offset < buffer.length) {
    try {
      offset += fs.writeSync(fd, buffer, offset, buffer.length - offset);
    } catch (error) {
      // A non-blocking pipe that is momentarily full. Spin rather than drop:
      // dropping is exactly the truncation this function exists to prevent.
      if (error.code === "EAGAIN") continue;
      throw error;
    }
  }
}

// Human narration. NEVER stdout.
//
// stdout is the MACHINE channel: in `--json` mode it must carry exactly one
// parseable JSON value and nothing else. A progress line printed to stdout
// before the JSON does not corrupt the JSON visually — it corrupts it
// mechanically, because `JSON.parse(stdout)` then throws on the prefix. That is
// the defect this helper exists to make structurally impossible: narration has
// one destination, it is stderr, and it is the same destination in every mode
// so that no branch can reintroduce the prefix when a flag is absent.
export function progress(line) {
  writeAllSync(2, line.endsWith("\n") ? line : `${line}\n`);
}

export function report(name, findings, { json = false } = {}) {
  const errors = findings.filter((f) => f.level === "error");
  const skips = findings.filter((f) => f.level === "skip");
  const warns = findings.filter((f) => f.level === "warn");
  if (json) {
    // EXACTLY ONE JSON VALUE ON STDOUT. Nothing may precede it and nothing may
    // follow it: narration goes through progress() to stderr, and this write is
    // synchronous so a piped consumer receives the whole value.
    writeAllSync(
      1,
      `${
        JSON.stringify(
          {
            check: name,
            result: errors.length === 0 ? "PASS" : "FAIL",
            error_count: errors.length,
            warn_count: warns.length,
            skip_count: skips.length,
            findings,
          },
          null,
          2,
        )
      }\n`,
    );
  } else {
    let text = "";
    for (const f of findings) {
      text += `[${f.level.toUpperCase()}] ${f.check}: ${f.message}\n`;
    }
    const verdict = errors.length === 0 ? "PASS" : "FAIL";
    text +=
      `${name}: ${verdict} (${errors.length} error, ${warns.length} warn, ${skips.length} skip)\n`;
    writeAllSync(1, text);
  }
  return errors.length === 0 ? 0 : 1;
}

export function parseFrontMatter(text) {
  if (!text.startsWith("---\n")) return null;
  const end = text.indexOf("\n---\n", 4);
  if (end === -1) return null;
  const block = text.slice(4, end);
  const out = {};
  let currentKey = null;
  for (const line of block.split("\n")) {
    if (/^\s*-\s+/.test(line) && currentKey) {
      out[currentKey] = Array.isArray(out[currentKey]) ? out[currentKey] : [];
      out[currentKey].push(line.replace(/^\s*-\s+/, "").trim());
      continue;
    }
    const m = /^([a-z_]+):\s*(.*)$/.exec(line);
    if (!m) continue;
    currentKey = m[1];
    const raw = m[2].trim();
    if (raw === "") {
      out[currentKey] = [];
    } else if (raw.startsWith("[") && raw.endsWith("]")) {
      out[currentKey] = raw
        .slice(1, -1)
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
    } else {
      out[currentKey] = raw;
    }
  }
  return { data: out, body: text.slice(end + 5) };
}
