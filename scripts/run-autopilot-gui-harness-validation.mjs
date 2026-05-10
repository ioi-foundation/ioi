#!/usr/bin/env node
import { main } from "./lib/autopilot-gui-harness-validation/core.mjs";

main()
  .then((code) => {
    process.exitCode = code;
  })
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
