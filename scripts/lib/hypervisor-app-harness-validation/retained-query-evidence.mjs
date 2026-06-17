import { existsSync } from "node:fs";
import { join } from "node:path";

import { AUTOPILOT_RETAINED_QUERIES } from "../hypervisor-app-harness-contract.mjs";
import { typeQuery } from "./desktop.mjs";

function sleep(ms) {
  return new Promise((resolveSleep) => setTimeout(resolveSleep, ms));
}

export function autopilotProfileRoot() {
  const profile = process.env.AUTOPILOT_DATA_PROFILE || "desktop-localgpu";
  return join(
    process.env.HOME || "",
    ".local/share/ai.ioi.autopilot/profiles",
    profile,
  );
}

function normalizeText(value) {
  return String(value ?? "")
    .replace(/\s+/g, " ")
    .trim();
}

function extractUserRequest(storeContent) {
  const marker = "[User request]";
  const content = String(storeContent ?? "");
  const markerIndex = content.indexOf(marker);
  if (markerIndex < 0) return content.trim();
  return content.slice(markerIndex + marker.length).trim();
}

export async function openReadonlySqliteDatabase(filePath) {
  try {
    const { default: Database } = await import("better-sqlite3");
    return new Database(filePath, { readonly: true, fileMustExist: true });
  } catch (error) {
    const { DatabaseSync } = await import("node:sqlite");
    const db = new DatabaseSync(filePath, { readOnly: true });
    db.__fallbackReason = String(error?.message || error);
    return db;
  }
}

export async function retainedQueryRuntimeEvidence(query, startedAtMs) {
  const profileRoot = autopilotProfileRoot();
  const chatDbPath = join(profileRoot, "chat-memory.db");
  if (!existsSync(chatDbPath)) {
    return {
      matchedUserRequest: false,
      hasAssistantResponse: false,
      concatenatedPrompt: false,
      reason: `chat memory database not found: ${chatDbPath}`,
    };
  }

  let db;
  try {
    db = await openReadonlySqliteDatabase(chatDbPath);
    const rows = db
      .prepare(
        "select id, hex(thread_id) as thread_hex, role, timestamp_ms, store_content from checkpoint_transcript_messages where timestamp_ms >= ? order by id asc",
      )
      .all(startedAtMs);
    const normalizedQuery = normalizeText(query);
    const retainedQueries = new Set(
      AUTOPILOT_RETAINED_QUERIES.map((item) => normalizeText(item.query)),
    );
    for (let index = 0; index < rows.length; index += 1) {
      const row = rows[index];
      if (row.role !== "user") continue;
      const extracted = normalizeText(extractUserRequest(row.store_content));
      if (extracted !== normalizedQuery) continue;
      const concatenatedPrompt = [...retainedQueries].some(
        (candidate) =>
          candidate !== normalizedQuery && extracted.includes(candidate),
      );
      const assistant = rows
        .slice(index + 1)
        .find(
          (candidate) =>
            candidate.thread_hex === row.thread_hex &&
            ["agent", "assistant"].includes(
              String(candidate.role).toLowerCase(),
            ) &&
            normalizeText(candidate.store_content).length > 0,
        );
      return {
        matchedUserRequest: true,
        hasAssistantResponse: Boolean(assistant),
        concatenatedPrompt,
        containsInlineSourcesUsed: assistant
          ? /sources used:/i.test(String(assistant.store_content || ""))
          : false,
        threadId: row.thread_hex,
        userTimestampMs: row.timestamp_ms,
        assistantTimestampMs: assistant?.timestamp_ms ?? null,
        assistantSnippet: assistant
          ? normalizeText(assistant.store_content).slice(0, 240)
          : "",
      };
    }
    return {
      matchedUserRequest: false,
      hasAssistantResponse: false,
      concatenatedPrompt: false,
      reason: "exact retained query not found in transcript projection",
    };
  } catch (error) {
    return {
      matchedUserRequest: false,
      hasAssistantResponse: false,
      concatenatedPrompt: false,
      reason: String(error?.message || error),
    };
  } finally {
    try {
      db?.close();
    } catch {
      // best-effort close
    }
  }
}

export async function waitForRetainedQueryRuntimeEvidence(
  query,
  startedAtMs,
  timeoutMs,
) {
  const deadline = Date.now() + timeoutMs;
  let latest = {
    matchedUserRequest: false,
    hasAssistantResponse: false,
    concatenatedPrompt: false,
    reason: "not checked",
  };
  while (Date.now() < deadline) {
    latest = await retainedQueryRuntimeEvidence(query, startedAtMs);
    if (
      latest.matchedUserRequest === true &&
      latest.hasAssistantResponse === true &&
      latest.concatenatedPrompt !== true
    ) {
      return latest;
    }
    await sleep(2_000);
  }
  return {
    ...latest,
    timedOut: true,
  };
}

export async function waitForRetainedQueryUserRequest(query, startedAtMs, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  let latest = {
    matchedUserRequest: false,
    hasAssistantResponse: false,
    concatenatedPrompt: false,
    reason: "not checked",
  };
  while (Date.now() < deadline) {
    latest = await retainedQueryRuntimeEvidence(query, startedAtMs);
    if (
      latest.matchedUserRequest === true &&
      latest.concatenatedPrompt !== true
    ) {
      return latest;
    }
    await sleep(1_000);
  }
  return {
    ...latest,
    timedOutWaitingForSubmit: true,
  };
}

export async function submitRetainedQuery(windowId, query, startedAtMs) {
  let latest = {
    matchedUserRequest: false,
    hasAssistantResponse: false,
    concatenatedPrompt: false,
    reason: "not submitted",
  };
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    typeQuery(windowId, query);
    latest = await waitForRetainedQueryUserRequest(query, startedAtMs, 6_000);
    if (
      latest.matchedUserRequest === true &&
      latest.concatenatedPrompt !== true
    ) {
      return {
        ...latest,
        submitAttempt: attempt,
      };
    }
    await sleep(1_000);
  }
  return {
    ...latest,
    submitAttempt: 3,
  };
}
