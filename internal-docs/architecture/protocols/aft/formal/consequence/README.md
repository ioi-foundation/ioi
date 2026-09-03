# M5 at-most-once externalization formal kernel

`AtMostOnceExternalization.tla` models one accepted authorization, the durable
`Authorized -> Claimed -> InFlight` path, an atomic idempotency register, an
invocation whose response may be lost, crash recovery into `Unknown`, and
lookup-only reconciliation. The invariant is consequence-level: at most one
modeled resource mutation occurs, including when the resource mutates while
the local durable state remains `InFlight`.

The model consumes the declared atomic-register contract. It does not prove an
arbitrary HTTP endpoint, physical device, or adapter implementation has that
contract. Runtime profile binding, crash injection, duplicate delivery, and
signed-versus-unsigned contradiction tests enforce that boundary in Rust.

Reproduce from this directory:

```text
java -cp "$(git rev-parse --show-toplevel)/.internal/formal-cache/tools/tla/tla2tools.jar" tlc2.TLC \
  -cleanup -deadlock -config AtMostOnceExternalization.cfg AtMostOnceExternalization.tla
```
