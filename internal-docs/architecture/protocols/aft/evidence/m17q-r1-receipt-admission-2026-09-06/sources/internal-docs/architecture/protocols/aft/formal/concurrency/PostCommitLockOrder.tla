------------------------ MODULE PostCommitLockOrder ------------------------
EXTENDS Naturals
CONSTANT ReleaseBeforeContinuation
VARIABLE f, s, nodeOwner, contextOwner
vars == <<f, s, nodeOwner, contextOwner>>
\* Two finite callers only. F acquires node state then needs context; S owns
\* context before inspecting node state. This does not model the full runtime.
Init == /\ f = 0 /\ s = 0 /\ nodeOwner = "none" /\ contextOwner = "none"
Finalizer ==
    \/ /\ f = 0 /\ nodeOwner = "none"
       /\ nodeOwner' = "F" /\ f' = 1
       /\ UNCHANGED <<s, contextOwner>>
    \/ /\ f = 1
       /\ nodeOwner' = IF ReleaseBeforeContinuation THEN "none" ELSE "F"
       /\ f' = 2 /\ UNCHANGED <<s, contextOwner>>
    \/ /\ f = 2 /\ contextOwner = "none"
       /\ contextOwner' = "F" /\ f' = 3
       /\ UNCHANGED <<s, nodeOwner>>
    \/ /\ f = 3
       /\ contextOwner' = "none"
       /\ nodeOwner' = IF nodeOwner = "F" THEN "none" ELSE nodeOwner
       /\ f' = 4 /\ UNCHANGED s
Sync ==
    \/ /\ s = 0 /\ contextOwner = "none"
       /\ contextOwner' = "S" /\ s' = 1
       /\ UNCHANGED <<f, nodeOwner>>
    \/ /\ s = 1 /\ nodeOwner = "none"
       /\ nodeOwner' = "S" /\ s' = 2
       /\ UNCHANGED <<f, contextOwner>>
    \/ /\ s = 2
       /\ nodeOwner' = "none" /\ contextOwner' = "none" /\ s' = 3
       /\ UNCHANGED f
Done == f = 4 /\ s = 3
Next == Finalizer \/ Sync \/ (Done /\ UNCHANGED vars)
Spec == Init /\ [][Next]_vars /\ WF_vars(Finalizer) /\ WF_vars(Sync)
TypeOK == /\ f \in 0..4 /\ s \in 0..3
          /\ nodeOwner \in {"none", "F", "S"}
          /\ contextOwner \in {"none", "F", "S"}
NoCircularWait == ~(f = 2 /\ s = 1 /\ nodeOwner = "F" /\ contextOwner = "S")
BothComplete == <>Done
=============================================================================
