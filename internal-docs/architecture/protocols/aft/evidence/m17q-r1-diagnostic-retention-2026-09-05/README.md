# Restart diagnostic retention — 2026-09-05

Status: restart retention regression passed; captured process run active.

The prior logging-filter run passed but did not retain general child stderr.
Initial launch drained stderr to an in-memory broadcast unless the trace
directory was configured; orchestration restarts did not preserve that trace
path. Empty filtered restart snapshots did not diagnose the intermittent
saturation failure. The incomplete capture remains recorded in the earlier
process-transport-diagnostics bundle.

ProcessBackend now remembers the orchestration trace path and appends restarted
stderr to that file. It opens the destination before spawning, refusing setup
if it cannot open it. Write failures emit an explicit harness-failure marker;
the initial trace drain now reports write failures too. The local child-process
regression passed: two restarts preserve initial log content and append their
diagnostics, while a directory used as the file destination prevents spawn.

The M16Q runner now creates per-phase component directories, passes the trace
path explicitly, refuses reported capture failures or absent nonempty
orchestration logs, and hashes nested component logs. It includes the restart
retention regression. Formatting, shell syntax, and documentation checks pass.
The full runner has not been qualified by these local checks.

process-capture/ records a fresh diagnostic campaign with both logging filter
and persistent trace directory. Its command, environment, source hashes, main
log, and component logs are retained. No process pass is claimed while active.
Logging and capture change timing; this is diagnostic evidence, not performance
admission. The unexplained saturation coverage failure and R1 finding 004
remain open, together with all remaining R2/refinement/review obligations.

## Captured result and operation correlation

process-capture/ passed and retained eight component logs, all hash-verified.
It contained transient enrollment/connection issues but lacked per-operation
lifecycle records, so it did not explain the retained saturation failure.

The runtime now emits diagnostic nonce-bound operation start/finish, durable
member queue/completion, and reply-routing events under the quv debug target.
Coverage errors also name the nonce. The feature-enabled validator check passed.
These logs are diagnostic observations, not admission or authorization evidence;
protocol decisions and exact coverage assertions are unchanged. operation-capture/
is the new active run, with persistent component logs and observed case-output
timestamps for correlation. Its instrumentation is not performance qualification.
