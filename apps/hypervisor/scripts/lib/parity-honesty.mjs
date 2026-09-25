// THE HONEST-PARITY INVARIANT (R-240). Ten parity verifiers asserted that `reference_capture` stayed
// the estate's majority (at least twenty rows, or more than the daemon-wired set). That was true while
// few seeds were ported and false once they were — 13 daemon_wired and 20 reference_ported against 6
// reference_capture — so all ten went red for the estate doing its job, and a red that never clears
// hides the one that matters. What "no false parity" meant is that no row claims a class its evidence
// does not carry. That is what is checked now, row by row, against the fields each class always holds:
//   daemon_wired     — a pixel-certified shell (flag AND artifact) over a daemon-bound surface;
//   reference_ported — its port surface, its adjudication and the surface it binds;
//   and nothing is ever `covered`, which is not a parity class.
export function parityOverclaims(matrix) {
  const out = [];
  for (const s of (matrix && matrix.seeds) || []) {
    if (s.parity_class === "covered") out.push(`${s.slug}: 'covered' is not a parity class`);
    if (s.parity_class === "daemon_wired" && !(s.shell_pixel_certified === true && s.shell_pixel_certification_artifact && s.candidate_surface)) {
      out.push(`${s.slug}: daemon_wired without a pixel certification over a daemon-bound surface`);
    }
    if (s.parity_class === "reference_ported" && !(s.port_surface && s.adjudication_ref && s.candidate_surface)) {
      out.push(`${s.slug}: reference_ported without its port surface, adjudication and bound surface`);
    }
  }
  return out;
}
