# sas.xyz

**Buy outcomes, not seats.**

`sas.xyz` is the demand-side service layer for the IOI network. It is where enterprises buy, deploy, govern, and measure finished AI-native services with SLAs, policy controls, liability boundaries, evidence, and reporting.

The clean split is:

*   `aiagent.xyz` packages autonomous supply.
*   `sas.xyz` sells outcome-based services built from that supply.

## 🌐 Positioning

Use this rule everywhere:

*   If the buyer is choosing **how it works**, it belongs closer to `aiagent.xyz`.
*   If the buyer is choosing **what result they want**, it belongs closer to `sas.xyz`.

That keeps the hierarchy based on abstraction level rather than size.

## 🚀 Product Surface

The frontend includes both a marketing site and an authenticated operating surface:

*   **Marketing Landing (`/`)**: Outcome-led positioning for enterprise buyers.
*   **Solutions (`/solutions`)**: Business-function and industry service lanes.
*   **Catalog (`/templates`)**: Finished services grouped by business outcome.
*   **Docs (`/docs`)**: Brand architecture, promotion path, governance model, and pricing split.
*   **Pricing (`/economics`)**: Per-outcome, managed SLA, gainshare, and hybrid commercial models.
*   **Trust (`/security`)**: Governance, audit trails, approvals, attestation, and signed receipts.
*   **Dashboard (`/app`)**: Buyer-facing service operations, evidence, billing, and customer controls.

## 🧱 Relationship to aiagent.xyz

`sas.xyz` is not a separate universe from `aiagent.xyz`.

The intended maturity ladder is:

1.  Agent
2.  Workflow
3.  Operator Pack
4.  Service Module
5.  Managed Service
6.  Enterprise SaS Offering

`aiagent.xyz` is the substrate marketplace. `sas.xyz` is the productized service layer on top of it.

## 💸 Commercial Model

Supply-side pricing belongs in `aiagent.xyz`:

*   metered execution
*   license
*   rev share
*   lease
*   settlement-based compensation

Demand-side pricing belongs in `sas.xyz`:

*   per outcome
*   managed SLA
*   gainshare
*   hybrid base fee + outcome kicker

## 🛠 Tech Stack

*   **Framework**: React 18 + Vite
*   **Styling**: Tailwind CSS
*   **Icons**: Lucide React
*   **Animations**: Framer Motion (`motion/react`)
*   **Routing**: React Router DOM

## 🔐 Trust Language

Both properties inherit the same IOI substrate, but the framing changes:

`aiagent.xyz`

*   verifiable execution
*   bounded autonomy
*   programmable policy
*   signed receipts
*   sovereign deployment

`sas.xyz`

*   governed outcomes
*   approval controls
*   audit trails
*   measurable service delivery
*   policy-backed automation

## 🗺️ Next Steps

The next product work should keep reinforcing the split:

*   classify `aiagent.xyz` by execution shape
*   classify `sas.xyz` by business outcome
*   make promotion from verified components to managed services explicit
*   keep the buyer experience focused on results, not agent topology
