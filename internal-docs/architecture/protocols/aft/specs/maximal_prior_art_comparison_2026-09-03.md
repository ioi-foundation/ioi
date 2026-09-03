# Maximal-consensus prior-art and task comparison — 2026-09-03

Status: M12 local research evidence; **not independently reviewed and not a
novelty or protocol-admission claim**.

This comparison tests whether a known construction defeats the exact M11 task
or exposes an omitted assumption in L-MAX. It compares task definitions and
authority sources rather than fault-tolerance percentages. The normative task
remains `maximal_consensus_task.md`; the lower-bound candidate remains
`maximal_visibility_viability.md`.

## 1. Comparison dimensions

The decisive question is not whether a construction reaches some form of
agreement at `f=n-1`. It is whether the same construction simultaneously gives
all of the following for one nontrivial rooted instance:

1. a non-`Abort` result for a valid input held by the sole correct member while
   all other configured members remain permanently silent;
2. persistent proof bytes that an offline verifier can accept without being
   told which member is correct;
3. rejection of every conflicting proof under every role-switched fault
   assignment; and
4. no selecting relay, publisher, linearizable object, TEE, trusted clock,
   honest quorum, or bounded-resource assumption outside the stated model.

Internal agreement among a singleton correct set, local timeout completion,
dissemination, data reconstructibility, and consequence-level idempotency are
tracked separately.

## 2. Systematic matrix

| Construction or result | Fault/timing/setup surface | What it establishes | Why it does not currently discharge M11/L-MAX |
|---|---|---|---|
| Dolev–Strong authenticated Byzantine agreement | Known synchronous rounds; authenticated identities; the paper gives `t+1` as both a lower bound and achieved round count | Internal Byzantine agreement with consistency/unanimity despite arbitrary authenticated faults | A correct process can decide from a completed round transcript, but M11 additionally requires a live persistent non-`Abort` authorization accepted by offline verifiers. Accepting a singleton signer for that purpose enables the role switch; requiring all possible honest identities restores withholding. |
| FLP | Fully asynchronous deterministic message passing; even one crash | An admissible nondeciding execution exists for any partially correct deterministic consensus protocol | FLP explains why deterministic asynchronous decision termination is unavailable, but L-MAX is different and stronger in another direction: its contradiction survives known synchrony and randomized termination because Byzantine endpoints may choose silence and later emit their own valid bytes. |
| Dwork–Lynch–Stockmeyer partial synchrony | Unknown bound or unknown GST; explicit processor/message timing models | Separates safety from eventual termination and gives matching resilience bounds; authenticated Byzantine partial-synchrony consensus requires `N >= 3t+1` in the paper's model | It rejects rather than supplies `t=N-1` partial-synchrony progress. Its fully synchronous authenticated comparison permits arbitrary fault counts for internal consensus, but does not add M11's offline transferable authorization semantics. |
| Unreliable failure detectors | Asynchronous crash-fault model augmented with explicit completeness/accuracy information | Makes consensus solvable under stated detector classes and relates consensus to atomic broadcast | A detector contributes information not present in asynchronous messages. Suspicion alone is not proof that a Byzantine identity cannot later issue conflicting authority; a detector accurate enough to select canonical authority must be named as the added oracle/assumption. |
| Bracha asynchronous reliable broadcast | Asynchronous channels; standard resilience `n >= 3t+1` | Sender validity plus consistency/totality among correct recipients; a faulty sender may cause no delivery | RBC propagates a value that enters its echo/ready thresholds. It neither forces a permanently silent Byzantine sender to publish nor chooses between independent singleton authorizations at `t=n-1`. |
| HoneyBadgerBFT / ACS | Fully asynchronous randomized protocol, `N >= 3f+1`; threshold-encryption setup in the described construction | Atomic broadcast agreement/total order and probabilistic progress; censorship resilience when a transaction reaches `N-f` correct nodes | The resilience and inclusion premise both require many correct nodes. ACS intentionally outputs a quorum-supported subset, not an authorization available from whichever identity happens to be the sole correct one. |
| DAG-Rider | Fully asynchronous randomized atomic broadcast, optimal `n >= 3f+1`; reliable broadcast plus a global perfect coin | Post-quantum-safe total ordering; eventual decision of messages proposed by correct processes | This is a strong PQ asynchronous baseline but retains the classical resilience geometry and an explicit coin. It does not offer silent-`n-1` transferable effect authorization. |
| Narwhal/Tusk | `n=3f+1`; `2f+1` availability certificates; asynchronous coin for Tusk | Decouples data dissemination/availability from ordering; certificates imply at least `f+1` honest stores under the assumed geometry | The availability certificate itself requires `2f+1` acts. Narwhal also uses consensus to choose garbage-collection/order frontiers, so it cannot serve as a non-circular `f=n-1` canonical-close primitive. |
| Fraud proofs and data-availability sampling / LazyLedger | Probabilistic sampling, erasure coding, and a minimum honest rebroadcast/underlying-chain assumption | Efficient evidence that committed block data is likely reconstructible; separates data availability from transaction execution | Sampling answers whether selected data is available. It does not select the canonical commitment or establish that no conflicting singleton authorization exists; the underlying chain still supplies ordering. |
| Linearizable consensus/sticky object | Wait-free shared-memory object whose first decision sticks; Herlihy classifies sticky byte and comparable universal objects at infinite consensus number | A canonical first-writer/decision bit and universal wait-free object construction | This would distinguish the paired executions, which is exactly why it cannot be treated as ordinary storage. Its linearizability, availability, implementation, and failure assumptions are a new consensus-powerful authority that M11 explicitly requires the proposal to name and construct. |
| Geeq Proof of Honesty / user validation | Users independently assess candidate histories/forks under Geeq's validation and economic model | A user-facing fork-choice/security claim rather than classical single-history consensus under the M11 verifier task | Allowing different users to select different histories changes transferable non-conflict into user-relative acceptance. It may be a useful policy model, but it does not satisfy one rooted verifier accepting no conflicting pair. |
| Atomic idempotency register at the consequence boundary | External linearizable resource keyed by effect identity | At-most-once physical mutation even if duplicate authorizations arrive | This protects a modeled resource, not the consensus-proof property. It can be an explicit end-to-end assumption, but using it to choose between `pi_X` and `pi_Y` concedes that the resource is the final selector and leaves transferable non-conflict unsatisfied. |

## 3. Primary sources and reproducible observations

- D. Dolev and H. R. Strong, [Authenticated Algorithms for Byzantine
  Agreement](https://doi.org/10.1137/0212045), SIAM Journal on Computing 12(4),
  1983. The abstract states the `t+1` lower bound and matching authenticated
  algorithm.
- M. J. Fischer, N. A. Lynch, and M. S. Paterson,
  [Impossibility of Distributed Consensus with One Faulty
  Process](https://www.cs.cornell.edu/courses/cs614/2003sp/papers/FLP85.pdf),
  JACM 32(2), 1985. Sections 2–3 define admissible/deciding runs and prove the
  nontermination result.
- C. Dwork, N. Lynch, and L. Stockmeyer,
  [Consensus in the Presence of Partial
  Synchrony](https://groups.csail.mit.edu/tds/papers/Lynch/jacm88.pdf), JACM
  35(2), 1988. Table I and Sections 1–2 state the timing models and resilience
  boundaries used above.
- T. D. Chandra and S. Toueg, [Unreliable Failure Detectors for Reliable
  Distributed Systems](https://doi.org/10.1145/226643.226647), JACM 43(2),
  1996. The paper makes the detector's completeness/accuracy information and
  crash-fault scope explicit and proves reductions between consensus and
  atomic broadcast in that model.
- G. Bracha, [Asynchronous Byzantine Agreement
  Protocols](https://doi.org/10.1016/0890-5401%2887%2990054-X), Information and
  Computation 75(2), 1987. The broadcast layer filters Byzantine behavior for
  randomized agreement under the classical bound.
- A. Miller et al., [The Honey Badger of BFT
  Protocols](https://eprint.iacr.org/2016/199.pdf), CCS 2016. Sections 3–4 state
  the asynchronous model, `3f+1 <= N`, setup, atomic-broadcast properties, and
  ACS construction.
- I. Keidar et al., [All You Need Is
  DAG](https://arxiv.org/abs/2102.08325), PODC 2021. The abstract and model
  identify reliable broadcast, a global coin, optimal resilience, PQ safety,
  and correct-proposal inclusion.
- G. Danezis et al., [Narwhal and Tusk: A DAG-based Mempool and Efficient BFT
  Consensus](https://arxiv.org/abs/2105.11827), EuroSys 2022. Sections 3–5
  define `2f+1` availability certificates, the `3f+1` model, ordering, and the
  random-coin dependency.
- M. Al-Bassam, A. Sonnino, and V. Buterin,
  [Fraud and Data Availability
  Proofs](https://arxiv.org/abs/1809.09044), 2018, and M. Al-Bassam,
  [LazyLedger](https://arxiv.org/abs/1905.09274), 2019. These make the
  availability/ordering separation explicit.
- M. Herlihy, [Wait-Free
  Synchronization](https://cs.brown.edu/people/mph/Herlihy91/p124-herlihy.pdf),
  TOPLAS 13(1), 1991. Sections 2–4 define wait freedom, consensus number, the
  first-decision sticky specification, and universal objects. This is used as
  a diagnostic reduction, not as a Byzantine message-passing proof of L-MAX.
- Geeq, [Proof of Honesty white
  paper](https://geeq.io/white-paper). This is the project-authored source for
  its user-validation and claimed fault-tolerance model; those claims are not
  adopted here as independently established results.

## 4. Surviving conclusion and falsifier

No construction in this comparison currently falsifies L-MAX. That is a local
inference, not an exhaustive literature claim. The strongest apparent escape
is a canonical first-publication/close object, but the comparison identifies
it as the very consensus-powerful selecting authority whose non-circular
implementation is in dispute.

The conclusion is falsified by one concrete construction that satisfies every
M11 property and gives a sole correct member a finite accepted non-`Abort`
proof while all other members are silent, yet prevents the role-switched
Byzantine identity from causing any offline verifier to accept its reproduced
proof—without relying on an excluded authority or changing the rooted
instance. The independent M12 reviewer is required to attempt exactly that
construction.
