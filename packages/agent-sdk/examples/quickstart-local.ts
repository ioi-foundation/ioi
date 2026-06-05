import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { Agent, createRuntimeSubstrateClient } from "../src/index.js";

const checkpointDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-agent-sdk-quickstart-"));
const substrateClient = createRuntimeSubstrateClient({
  cwd: process.cwd(),
  checkpointDir,
});

const agent = await Agent.create({
  model: { id: "local:auto" },
  local: { cwd: process.cwd() },
  substrateClient,
});

const run = await agent.send("Summarize what this repository does");

for await (const event of run.stream()) {
  console.log(`${event.cursor} ${event.type}: ${event.summary}`);
}

const result = await run.wait();
console.log(result.stopCondition.reason);
