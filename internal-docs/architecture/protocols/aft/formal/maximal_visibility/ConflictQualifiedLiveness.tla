------------------------- MODULE ConflictQualifiedLiveness -------------------------
EXTENDS FiniteSets, Naturals

CONSTANTS Values, X, Y

ASSUME /\ Values = {X, Y}
       /\ X # Y

OnlyX == {X}
OnlyY == {Y}
Both == {X, Y}
SubmissionCases == {OnlyX, OnlyY, Both}

VARIABLE authorized

vars == <<authorized>>

(* Singleton submission is live.  A rooted conflict rule may select at most
   one value when both conflicting values are submitted; it need not authorize
   both. *)
TaskSemantics ==
    /\ authorized \in [SubmissionCases -> SUBSET Values]
    /\ X \in authorized[OnlyX]
    /\ Y \in authorized[OnlyY]
    /\ Cardinality(authorized[Both]) <= 1
    /\ \A submitted \in SubmissionCases :
         authorized[submitted] \subseteq submitted

Init == TaskSemantics

Next == UNCHANGED vars

ConflictQualified ==
    /\ X \in authorized[OnlyX]
    /\ Y \in authorized[OnlyY]
    /\ Cardinality(authorized[Both]) <= 1

Spec == Init /\ [][Next]_vars

=============================================================================
