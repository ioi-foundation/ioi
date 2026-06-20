import assert from "node:assert/strict";
import test from "node:test";

import {
  terminalEventsFromTranscript,
  assembleSessionOperationsLiveProjection,
  sessionOperationsEvents,
} from "./runtime-hypervisor-session-watcher.mjs";
import { createPortListenerRegistry } from "./runtime-port-listener-registry.mjs";

const SAMPLE_LANE = {
  transcript_lines: [
    "Hypervisor Generic CLI Local Harness ready: model=qwen",
    "[generic-cli:qwen] planning: create a website that explains post-quantum computers",
    "[generic-cli:qwen] wrote index.html (220 bytes)",
  ],
  files_written: ["index.html"],
  receipt_refs: ["receipt://harness-spawn-lane/abc"],
};

const SAMPLE_DIFF = {
  changed_file_groups: [
    {
      group_ref: "changed-group:root",
      folder: "./",
      files: [
        {
          file_ref: "changed-file:index-html",
          name: "index.html",
          delta: "+5",
          status: "added",
          receipt_ref: "receipt://changes/index-html",
        },
      ],
    },
  ],
};

const SAMPLE_STATUS = { phase: "running", components: {} };

test("derives terminal events from the harness transcript", () => {
  const events = terminalEventsFromTranscript(SAMPLE_LANE.transcript_lines, "s1");
  assert.equal(events.length, 3);
  assert.match(events[2].command_summary, /wrote index.html/);
  assert.equal(events[0].status, "executed");
});

test("marks a no-model transcript line as blocked", () => {
  const events = terminalEventsFromTranscript(
    ["[generic-cli:qwen] no model route: ECONNREFUSED"],
    "s1",
  );
  assert.equal(events[0].status, "blocked");
});

test("assembles a live projection from real lane + diff + ports", () => {
  const registry = createPortListenerRegistry();
  const port = registry.register("s1", { port: 4173, url: "http://127.0.0.1:4173" });
  assert.equal(port.exposure_state, "lease_required"); // gated until a lease

  const projection = assembleSessionOperationsLiveProjection({
    sessionRef: "s1",
    environmentStatus: SAMPLE_STATUS,
    laneResult: SAMPLE_LANE,
    diffProjection: SAMPLE_DIFF,
    ports: registry.list("s1"),
  });
  assert.equal(projection.terminal_events.length, 3);
  assert.equal(projection.changed_file_groups[0].files[0].name, "index.html");
  assert.deepEqual(projection.files_written, ["index.html"]);
  assert.equal(projection.environment_ports[0].exposure_state, "lease_required");
});

test("port exposure opens only with a wallet capability lease", () => {
  const registry = createPortListenerRegistry();
  registry.register("s1", { port: 4173 });
  const opened = registry.grantLease(
    "s1",
    4173,
    "wallet-capability:port-expose/4173",
    "https://preview.session/s1",
  );
  assert.equal(opened.exposure_state, "open");
  assert.equal(opened.capability_lease_ref, "wallet-capability:port-expose/4173");
});

test("projects the canonical session-events SSE envelope", () => {
  const projection = assembleSessionOperationsLiveProjection({
    sessionRef: "s1",
    environmentStatus: SAMPLE_STATUS,
    laneResult: SAMPLE_LANE,
    diffProjection: SAMPLE_DIFF,
    ports: [],
  });
  const events = sessionOperationsEvents(projection);
  const eventNames = events.map((event) => event.event);
  assert.ok(eventNames.includes("environment_status"));
  assert.ok(eventNames.includes("workspace_change"));
  assert.ok(eventNames.includes("terminal_chunk"));
  assert.ok(eventNames.includes("receipt_projection"));
  assert.equal(eventNames[eventNames.length - 1], "readiness");
  const readiness = events[events.length - 1];
  assert.equal(readiness.data.ready, true);
});
