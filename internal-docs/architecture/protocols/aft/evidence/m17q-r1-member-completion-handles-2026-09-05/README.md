# Captured member-completion handles

The instrumented predecessor campaign observed up to 1657.767ms between async
durable-work return and reply-command preparation, a span containing the
preparation-notification context lock and encoding. A subsequent commander-clone
lock took up to 287.859ms. These observations identify removable context accesses;
they do not isolate the earlier uninstrumented late reply's cause.

Member processing now captures the preparation notifier and QUV command sender
in its initial rooted-context read. After durable work returns, a synchronous
completion object notifies through that captured handle and returns a response
only on successful durable work. The response carries its exact recipient and
signed reply with the captured sender. Remote forwarding serializes and queues
it without acquiring the main context. Local self-delivery still observes its
own reply through the existing verifier path. No transcript gains authority.

The completion API contains neither a main-context reference nor a context-lock
guard. The initial rooted validation and durable write-before-reply remain in
place. Sender/notifier clones refer to the same lifecycle resources; current
channel authentication and capability checks remain at transport admission.
Notification wakes selection but does not authorize preparation or an effect.
The command channel can still impose backpressure, and admission there is not
durable outbox admission or delivery.

The runtime regressions cover notification before a blocked command send,
exact recipient and reply forwarding, refusal without a reply, and closed-lane
errors. They do not reproduce all main-context contention or qualify wall-clock
service. Verifier observation still acquires the main context and was observed
to wait up to 1350.235ms in the preceding campaign; that separate delay remains.
Initial compilation exposed a borrowed test notifier moved before its waiter
was dropped; the fixture now clones its handle, and the failed log is retained.

A new process campaign, process-level contention controls, aggregate readiness,
full refinement and whole R1 closure remain outstanding. The prior diagnostic
process pass is historical evidence for its exact recorded sources.

Final checks: 11 runtime tests passed; both removed-rule controls failed at the
intended assertions; restored completion tests passed; CLI compilation, Rust
formatting, runner syntax and diff checks passed. Source hashes are retained.
