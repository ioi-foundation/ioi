import fs from "node:fs";
import path from "node:path";
import { git, repoRoot, sha256, sha256File } from "./lib.mjs";

function oneLineValue(source, key) {
  const escaped = key.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
  const values = [...source.matchAll(new RegExp(`^${escaped}=(.*)$`, "gmu"))]
    .map((match) => match[1]);
  return values.length === 1 ? values[0] : null;
}

const committedArtifactCache = new Map();

export function refsContainingArtifactHash(relativePath, expectedSha256) {
  const cacheKey = `${relativePath}\0${expectedSha256}`;
  if (committedArtifactCache.has(cacheKey)) return committedArtifactCache.get(cacheKey);
  if (!/^[0-9a-f]{64}$/u.test(expectedSha256 ?? "")) return [];
  const listed = git([
    "for-each-ref",
    "--format=%(refname:short)",
    "refs/heads",
    "refs/remotes/origin",
  ]);
  if (listed.status !== 0) return [];
  const refs = listed.stdout.split(/\r?\n/u).filter(Boolean).sort();
  const matches = refs.filter((ref) => {
    const shown = git(["show", `${ref}:${relativePath}`]);
    return shown.status === 0 && sha256(shown.stdout) === expectedSha256;
  });
  committedArtifactCache.set(cacheKey, matches);
  return matches;
}

export function inspectContentBoundLiteralEvidence(ref, literal) {
  const absolute = path.join(repoRoot, ref);
  if (!fs.existsSync(absolute) || !fs.statSync(absolute).isFile()) {
    return {
      ref,
      has_literal: false,
      content_bound: false,
      reason: "evidence ref is unavailable or not a file",
    };
  }
  const source = fs.readFileSync(absolute, "utf8");
  const literalCount = source.split(/\r?\n/u).filter((line) => line === literal).length;
  if (literalCount === 0) {
    return { ref, has_literal: false, content_bound: false, reason: "literal is absent" };
  }
  if (literalCount !== 1) {
    return {
      ref,
      has_literal: true,
      content_bound: false,
      reason: `literal occurs ${literalCount} times; expected exactly one`,
    };
  }

  const format = oneLineValue(source, "IOI_LITERAL_EXIT_LOG_FORMAT");
  const bar = oneLineValue(source, "BAR");
  const artifactRef = oneLineValue(source, "ARTIFACT");
  const declaredSha256 = oneLineValue(source, "ARTIFACT_SHA256");
  const expectedBar = literal.replace(/_EXIT=0$/u, "");
  if (format !== "ioi.program.literal_exit.v1") {
    return {
      ref,
      has_literal: true,
      content_bound: false,
      reason: "missing or invalid IOI_LITERAL_EXIT_LOG_FORMAT",
    };
  }
  if (bar !== expectedBar) {
    return {
      ref,
      has_literal: true,
      content_bound: false,
      reason: `BAR must equal ${expectedBar}`,
    };
  }
  if (typeof artifactRef !== "string" || artifactRef.length === 0 || path.isAbsolute(artifactRef)) {
    return {
      ref,
      has_literal: true,
      content_bound: false,
      reason: "missing or invalid repository-relative ARTIFACT",
    };
  }
  const artifactAbsolute = path.resolve(repoRoot, artifactRef);
  const artifactRelative = path.relative(repoRoot, artifactAbsolute);
  if (artifactRelative.startsWith("..") || path.isAbsolute(artifactRelative)) {
    return {
      ref,
      has_literal: true,
      content_bound: false,
      reason: "ARTIFACT escapes the repository",
    };
  }
  if (!/^[0-9a-f]{64}$/u.test(declaredSha256 ?? "")) {
    return {
      ref,
      has_literal: true,
      content_bound: false,
      reason: "missing or malformed ARTIFACT_SHA256",
    };
  }

  const checkoutBound = fs.existsSync(artifactAbsolute)
    && fs.statSync(artifactAbsolute).isFile()
    && sha256File(artifactAbsolute) === declaredSha256;
  const committedRefs = refsContainingArtifactHash(artifactRef, declaredSha256);
  if (!checkoutBound && committedRefs.length === 0) {
    return {
      ref,
      has_literal: true,
      content_bound: false,
      reason: "ARTIFACT_SHA256 matches neither checkout bytes nor a committed artifact identity",
    };
  }
  return {
    ref,
    has_literal: true,
    content_bound: true,
    artifact_ref: artifactRef,
    artifact_sha256: declaredSha256,
    checkout_bound: checkoutBound,
    committed_binding_refs: committedRefs,
  };
}

export function contentBoundLiteralEvidence(ref, literal) {
  return inspectContentBoundLiteralEvidence(ref, literal).content_bound;
}
