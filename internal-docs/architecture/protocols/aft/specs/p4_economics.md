# AFT-CB P4.2 — Economics Memo

**Owner-facing. This is NOT a proof (rule 2).** Every number below carries
its stated assumption inline; strip the assumption and the number means
nothing. The T8 selection-supply model appears here only as a
PROBABILITY and is never composed into a deterministic tolerance figure —
that composition is explicitly forbidden (the theorem corpus enforces it
with a gate; this memo respects the same line).

## 1. What money defends, and what it does not

The AFT-CB safety story is deterministic-under-A2 (at least one honest
boundary member) and does NOT rest on economics: a UBC is unique under
the Minimal Honesty Axiom regardless of bond size (T1). Economics
defends two DIFFERENT things:

- **Liveness griefing** — the cost of making seals stall (withholding),
  which A2 does not bound because one withholder freezes the cadence
  (L2, the unanimity lower bound).
- **The MHA purchase price** — the cost of buying ALL n seats so that A2
  itself fails. This is the only way to break safety, and it is an
  economic + selection question, not a protocol one.

Money never authorizes; it only prices attacks. Below, `n` is the ring
size, `b` the per-seat bond, `D_act` the activation depth, `W` the
withdrawal/unbond delay, and `T_halt` the succession tick threshold
(RES-R12, not yet parameterized on a live clock).

## 2. Seal-cadence griefing

**Cost to the griefer** (assumption: a withholder is slashable only if
its withholding is attributable; under the two-tier design a stall
delays only irreversible-effect release, T4a):

- One withholder freezes the seal cadence at zero marginal cost to
  itself IF withholding is not attributable. **The design choice that
  prices this**: the seal path must make non-response attributable
  (a member that owes a share and does not publish it within the
  bulletin window is slashable), so the griefing cost becomes `b` per
  griefing-round per member, recovered by the honest majority through
  the resolution log (R3) + ejection (R5, live-tier only — the strong
  ring exits only via handover).
- **Bound**: griefing sustained across `k` seal rounds costs the
  adversary `k · b` in slashable bond IF each round's withholding is
  attributable; if it is NOT attributable (a design gap, tracked), the
  cost is zero and the only remedy is membership rotation via handover.
  This asymmetry is why attributable non-response is load-bearing and
  is called out as a build obligation for the seal path, not an
  economic tuning knob.

## 3. The MHA purchase price (all-seat capture)

To break safety the adversary must own all n seats simultaneously.
Under the R5 admission plane:

- **Bond floor**: acquiring n seats costs at least `n · b` locked for
  `W` (assumption: the bond floor is enforced at registration and not
  refundable before `W` elapses — R5 gates registration bonds but bond
  ESCROW accounting is a named residual to the wallet plane, so this
  number is a floor the wallet plane must actually hold).
- **Queue depth**: seats activate only after `D_act` events in the
  public queue (assumption: `D_act > 0`, enforced by R5's queue), so
  capture cannot be instantaneous — the honest set has `D_act` events
  of warning and can itself register to dilute.
- **Diversity floors**: constituency floors (C5) force the adversary to
  acquire seats across ≥ (number of floored constituencies) distinct
  constituencies (assumption: constituencies are Sybil-resistant, which
  is an IDENTITY assumption outside this protocol — named, not
  defended here).
- **Sortition unpredictability**: seat ASSIGNMENT is beacon-derived
  (C5), so an adversary cannot pre-commit capital to specific seats
  before the beacon resolves (assumption: the beacon is unpredictable —
  today the reference beacon, load-bearing only once R11's VDF lands;
  until then this term is a REFERENCE bound, not a security bound).

**Floor**: all-seat capture costs at least `n · b` locked for `W`,
spread across the constituency floors, with `D_act` events of public
warning — under the four assumptions above, each of which is named and
at least one of which (sortition unpredictability) is a reference bound
pending R11.

## 4. The T8 selection-supply model (PROBABILITY ONLY)

T8 asks: under open selection, what is the probability that a formed
ring contains ≥ 1 honest member (i.e. A2 holds for the formed ring)?

- **Base form**: with an adversary controlling a fraction ρ of the
  eligible pool and IID seat draws, P(A2 fails) = ρ^n. This is the
  naïve bound and it OVERSTATES safety because seat failures correlate.
- **Correlated-failure form (the one this memo adopts)**: with
  constituency floors partitioning seats and a published
  intra-constituency correlation coefficient γ, P(A2 fails) is bounded
  by the product over floored constituencies of the per-constituency
  capture probability, each inflated by γ. The correlations must be
  PUBLISHED (a deployment obligation) — an unpublished correlation
  makes this number meaningless.
- **Adaptive-corruption term**: because assignment is sortition-derived
  and unpredictable (C5), an adaptive adversary cannot target seats
  before assignment; the adaptive advantage is bounded by the beacon's
  unpredictability margin (again: reference bound until R11).
- **Standby-capture term (C2)**: standby diversity/queueing raises the
  cost of pre-positioning to capture a succession (RES-R12); until R12
  lands this term is a DESIGN quantity, not a measured one.

**This is a probability.** It is NEVER to be read as "the protocol is
1 − ρ^n safe" or converted into any deterministic tolerance figure. The
deterministic guarantee is A2-conditional and lives in T1; T8 prices how
likely open selection is to SUPPLY A2, which is a different and weaker
statement.

## 5. Parameter recommendation (owner-facing, assumption-tagged)

Starting points for a first deployment, each to be revisited against
measured costs (P4.3) and the deployment's own threat model:

| Parameter | Suggested start | The assumption it rides on |
|---|---|---|
| `n` (ring size) | 4 → 8 as the pool grows | larger n raises capture cost linearly but seal latency too (P4.3) |
| `b` (per-seat bond) | ≥ the value of one epoch's sealed irreversible effects | bonds must exceed what a single stall can extract |
| `D_act` | ≥ 2 events, scaled to block cadence for a real time-warning | the honest set needs time to react to a capture attempt |
| `W` (unbond delay) | ≥ the long-range bootstrap horizon | so a departed member's key cannot forge post-unbond history before W (A8/T5b) |
| seal cadence | as slow as effect-release latency tolerates | slower cadence = fewer griefing surfaces |
| `T_halt` | RES-R12 — unparameterized pending R11's clock | needs the objective tick; not a wall-clock value |
| σ margin | RES-R11 — pending the VDF construction | not settable until the construction is vetted |

## 6. What is NOT priced here (honest gaps)

- Bond escrow accounting (the wallet plane must actually LOCK the bond
  the floors assume) — named residual.
- The sortition beacon's security (reference bound until R11).
- `T_halt` and σ (RES-R11/R12).
- Sybil-resistance of constituencies (an identity-plane assumption,
  outside AFT).

None of these gaps affects the A2-conditional deterministic safety
(T1); they affect how expensive it is to make A2 fail, which is exactly
what an economics memo — not a proof — is for.
