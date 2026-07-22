#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  MANIFEST_PATH,
  PROTOCOL_PATH,
  validateManifest,
  validateProtocol,
} from "./lib/p0-collaboration-protocol.mjs";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const protocolBytes = fs.readFileSync(path.join(repoRoot, PROTOCOL_PATH));
const protocol = JSON.parse(protocolBytes);
const manifest = JSON.parse(fs.readFileSync(path.join(repoRoot, MANIFEST_PATH), "utf8"));

validateProtocol(protocol);
validateManifest(manifest, protocolBytes);
process.stdout.write(
  `P0 comparison protocol check passed: ${protocol.protocol_id}; status ${protocol.status}; cohort not executed.\n`,
);
