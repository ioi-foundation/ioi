# T6/L-M no-laundering formal kernel

`GuaranteeMeet.tla` models two assurance coordinates and two verified
constituents over a bounded three-level lattice. A wrapper can claim any
output. The verifier accepts the exact coordinate-wise meet; a result above or
below that exact certificate-only answer is refused. If independently verified
new evidence is present, only the transform's named coordinate may differ.

This is the bounded state-machine counterpart of the certificate
indistinguishability lower bound. It proves neither a particular cryptographic
proof system nor a future transform verifier. Those implementations must
establish their own new-evidence predicate before their rule can leave the
runtime registry's default-deny state.

Reproduce with:

```text
java -cp "$(git rev-parse --show-toplevel)/.internal/formal-cache/tools/tla/tla2tools.jar" tlc2.TLC \
  -cleanup -deadlock -config GuaranteeMeet.cfg GuaranteeMeet.tla
```
