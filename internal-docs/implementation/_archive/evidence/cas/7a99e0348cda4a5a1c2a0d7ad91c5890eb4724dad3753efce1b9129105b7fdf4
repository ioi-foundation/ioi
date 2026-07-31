#!/usr/bin/env node
import assert from "node:assert/strict";
import { buildProjection, stageState } from "./generate-now.mjs";

const stage = { id: "MX", exit_gate: { aggregate_work_item_id: "mx-exit" } };
const records = [
  { stage_id: "MX", work_item_id: "mx-child", record_role: "cut", status: "verified", file: "fixture" },
  { stage_id: "MX", work_item_id: "mx-wrong-aggregate", record_role: "aggregate_exit", status: "verified", file: "fixture" },
  { stage_id: "MX", work_item_id: "mx-exit", record_role: "aggregate_exit", status: "proposed", file: "fixture" },
];
assert.equal(stageState(stage, records).state, "pending", "must use the exact sequence exit id, not the first aggregate or child statuses");
records[2].status = "verified";
assert.equal(stageState(stage, records).state, "verified");
assert.equal(stageState(stage, records, new Map([["mx-exit", ["hold://successor"]]])).state, "evidence_ready", "an open successor hold must prevent unqualified verified orientation");
assert.match(stageState(stage, records, new Map([["mx-exit", ["hold://successor"]]])).reason, /verified_historical_with_open_successor/);
const projection = buildProjection();
const directLane = projection.differentialLanes.find(
  (lane) => lane.lane_id === "m3-direct-non-system",
);
assert.ok(directLane, "the sequence-owned M3 direct differential must project");
assert.equal(directLane.permitted, false, "a completed lane must not remain open merely because its exact work-item dependencies are satisfied");
assert.equal(directLane.stage_state, "verified", "the lane must project the exact verified aggregate exit state without inventing a second stage state");
assert.deepEqual(directLane.bypassed_stage_dependencies, ["M1", "M2"]);
assert.deepEqual(
  directLane.records.map((record) => record.work_item_id),
  ["m3-pursuit-definition-resolution"],
);
assert.equal(directLane.records[0].status, "verified");
console.log("generated orientation regression: PASS");
