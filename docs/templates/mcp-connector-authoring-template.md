# MCP Connector Authoring Template

Status: authoring template for MCP servers and connectors (this front matter describes the template file itself).
Canonical owner: this file for the authoring checklist shape; connector doctrine is owned by [`docs/architecture/components/connectors-tools/doctrine.md`](../architecture/components/connectors-tools/doctrine.md)
Document class: `canonical-reference`
Doctrine status: reference
Implementation status: mixed (authoring template; no runtime behavior)
Last implementation audit: 2026-07-26

Use this template when adding an MCP server or connector. MCP support must use the same runtime substrate contracts as CLI, GUI, workflow compositor, harness, and benchmarks.

## Server Identity

- Server name:
- Command:
- Arguments:
- Version or integrity ref:
- Source:
- Tier:

## Containment

- Containment mode:
- Network egress:
- Child processes:
- Workspace root:
- Environment variables:
- Secret handling:
- Kill-on-drop behavior:

## Tool Exposure

- Declared allowed tools:
- Runtime discovery receipt:
- Namespacing:
- Capability retirement behavior:
- Explicit operator override behavior:

## Authority And Receipts

- Policy target:
- Approval boundaries:
- Receipt kind:
- Required receipt fields:
- Redacted fields:
- Trace export projection:
- Replay reconstruction:

## Validation

- Static containment command:
- Mock substrate test:
- Live substrate test:
- Policy/firewall test:
- Failure recovery test:
- Dashboard evidence:

