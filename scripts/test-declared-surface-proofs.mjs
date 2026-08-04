import { admissibleUnderSurface, selfInclusionFindings, DECLARED_SURFACES }
  from "/home/heathledger/Documents/ioi/repos/ioi/internal-docs/implementation/tools/check-claims-coverage.mjs";
const decl = DECLARED_SURFACES["docs/evidence/m5-event-substrate/m4-aggregate.log"];
const r = (label, got, want) =>
  console.log(`${got === want ? "PASS" : "FAIL"} ${label} -> ${got ? "admitted" : "refused"} (want ${want ? "admitted" : "refused"})`);

// (i) delta touching a DECLARED surface -> stale log refused
r("(i)  delta touches crates/ (declared)", admissibleUnderSurface(["crates/node/src/x.rs"], decl), false);
// (ii) delta touching the gate's OWN verifier -> refused via self-inclusion
r("(ii) delta touches the gate's own verifier", admissibleUnderSurface(
  ["apps/hypervisor/scripts/verify-m4-outcome-room-system-spine.mjs"], decl), false);
// (iii) tool delta OUTSIDE every declared surface -> admitted
r("(iii) delta outside every surface", admissibleUnderSurface(
  ["scripts/test-pre-next-leg-gates.mjs", "docs/evidence/m5-event-substrate/x.log"], decl), true);
// (iv) UNDECLARED gate + non-evidence delta -> refused under the strict default
r("(iv) undeclared gate, non-evidence delta", admissibleUnderSurface(["scripts/x.mjs"], undefined), false);
// self-inclusion is enforced, not trusted
const broken = { "l": { producers: ["apps/hypervisor/scripts/v.mjs"], surface: ["crates/"] } };
console.log(`${selfInclusionFindings(broken).length === 1 ? "PASS" : "FAIL"} (v)  a surface omitting its own producer is a GATE FAILURE`);
console.log(`${selfInclusionFindings().length === 0 ? "PASS" : "FAIL"} (vi) every shipped surface covers its own producers`);

// (vii) CODEX'S REFUTATION, as a required proof: a Cargo.lock-class delta must
// invalidate Rust-gate evidence even though it contains zero .rs files.
for (const path of ["Cargo.lock", ".cargo/config.toml", "rust-toolchain.toml",
                    "apps/hypervisor/fixtures/x.json"]) {
  const got = admissibleUnderSurface([path], decl);
  console.log(`${got === false ? "PASS" : "FAIL"} (vii) zero-.rs delta "${path}" -> ${got ? "admitted" : "refused"} (want refused)`);
}
