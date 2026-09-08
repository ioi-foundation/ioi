# Prepared concurrent RPC workload — local validation passed

The prior dispatch loop signed each candidate and immediately spawned its RPC
before signing the next candidate. Earlier RPCs could therefore enter QUV while
later candidates were still being prepared. The retained trace showed a
5689.907 ms spread and at most three overlapping verifier intervals.

All candidate signatures and request data are now prepared before any RPC is
released. A controller-side Tokio barrier releases the four prepared requests
together. This adds no runtime hook, changes no protocol deadline or authority
rule, and retains exact member coverage. Preparation time is reported separately
from the post-release workload duration; RPC dispatch spread is also recorded.
The prior workload duration included interleaved candidate preparation and is
not directly comparable to the new post-release duration.

The production campaign passed, including every sole-correct placement, exact
four-member participation for each workload receipt, two typed conflict refusals
with zero durable resource records, and successful unrelated execution. Request
preparation took 7097 ms; dispatch spread rounded down to 0 ms. The four logged
verifier starts spanned 739.821 ms and all four intervals overlapped, compared
with at most three in the prior trace. The latest valid workload reply arrived
at 2270 ms within the 4000 ms qualified envelope.

`check.json` binds the command, source snapshot and raw logs. The diagnostic
analyzer retained eleven nonce lifecycles with zero malformed JSON lines;
`saturation-overlap.json` records the four workload nonces and selection method.
These wall-clock log observations establish overlap for this run, not a protocol
monotonic deadline proof or sustained queue/storage saturation. Preparation time
is excluded from the new workload duration. Debug logging/capture costs remain
unqualified. The earlier intermittent missing-member failure remains unresolved;
this local pass does not close R1 or establish R2 admission.
