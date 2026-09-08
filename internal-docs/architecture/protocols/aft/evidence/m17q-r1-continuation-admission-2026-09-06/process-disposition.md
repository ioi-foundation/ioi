Initial process campaign FAILED (exit 101), unchanged recorded source. Placement
0 passed exact invalid-signature/no-storage negative, sole-correct execution
(reply 290 ms, call 5559 ms) and unchanged terminal replay. Placement 1 reported
Unavailable: Node is initializing; this was correctly not accepted as the
required signature refusal. No component sink was enabled.

Repair in process-recovery/: require the exact non-authorizing signature refusal
before isolating each restarted executor, retrying only typed startup errors
within the existing 120-second recovery allowance. Require all four exact
terminal results before all-correct saturation. The live 5-second decision,
5-second continuation, 4-second reply envelope and 30-second RPC limits remain
unchanged. The retry enables retained component logs. No R2 admission.
