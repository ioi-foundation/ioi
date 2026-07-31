#!/usr/bin/env node

// Dedicated read-only contract check for the generated Hypervisor breadth
// projection. Generation remains an explicit, separate --write transaction.

import { checkHypervisorSurfaceCoverage } from "./generate-hypervisor-surface-coverage.mjs";

checkHypervisorSurfaceCoverage();
