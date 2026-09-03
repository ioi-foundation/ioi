# Hash-only fallback composition model

`OptimisticFallbackComposition.tla` is the bounded temporal kernel for one AFT
height. It checks the part not established by the exact-quorum arithmetic
tests: a durable fallback transition captures already committed optimistic
state, disables later optimistic authority at that height, and constrains the
asynchronous decision to the captured root. Protocol randomness never appears
in the authority transition.

The model intentionally does not pretend to prove the CCS 2024 asynchronous
construction or signature unforgeability. Those remain named assumptions and
implementation-specific proof obligations. The executable Rust tests cover
exact `3f+1/2f+1` intersection, signed high-QC/lock contributions, rooted QC
verification, restart durability, and rejection of late optimistic votes and
certificates.
