# Tool Authoring Checklist

Status: implementation scaffold active

Every new tool, graph node adapter, connector operation, workflow step, plugin
entrypoint, browser/computer-use action, and artifact promotion path must declare
its runtime classification before implementation.

## Classification

- Is the operation consequential?
- Is it simulation-only?
- Which `ActionTarget` does it map to?
- Which read scopes and write scopes does it need?
- Which capability lease authorizes it?
- Which policy rules should match?
- Does it require external approval?

## Invocation Envelope

Consequential tools must be callable through a runtime invocation envelope with:

- session id
- actor id
- request hash
- target and scope
- policy decision hash
- capability lease hash
- approval grant hash when required
- deadline
- idempotency key
- required receipt manifest

## Evidence

Declare the evidence required for the target:

- browser: before/after DOM or screenshot hashes, origin, action, postcondition
- filesystem: path, operation, before/after hash or diff hash
- shell: command digest, cwd, env policy hash, exit code, stdout/stderr digests
- MCP: server identity, tool schema hash, request/response hash, timeout policy
- computer-use/clipboard: window binding, visual hashes, semantic target or coordinates
- connector/network: connector id, operation, resource scope, request/response digest, auth scope
- artifact: candidate refs, validation hash, render/eval hash when applicable

## Plan And Scope

Graph, workflow, and swarm execution must validate an executable plan before
dispatch. Independent steps with overlapping write scopes must be serialized or
rejected with a conflict receipt. Remote workflow triggers must include an
idempotency key, and every non-simulation step must declare a timeout policy and
required capability.

## Required Tests

Add at least one focused test for:

- missing policy decision fails closed
- missing or out-of-scope capability/approval fails closed
- timeout produces a bounded failure
- required receipt evidence is present before settlement/promotion
- projection-only state is not treated as settlement authority
