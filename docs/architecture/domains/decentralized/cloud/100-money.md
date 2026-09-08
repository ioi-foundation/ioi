# 100 — Money: metering, pricing, billing, settlement

Status: adopted product specification (owner, 2026-09-08); design baseline September 7, 2026.
Canonical owner: this file for metering, pricing, billing and settlement.
Doctrine status: canonical
Implementation status: planned (the selected architecture, adopted 2026-09-08; nothing here is a claim that the product exists — what the Hypervisor daemon implements today is in `../cloud.md`)

**Spec section:** 18. **Depends on:** 010, 040, 080. **Defines:** meters, units, quote
validity, rating, cost attribution (100); customer balances, commitments, journals,
invoices, refunds, hard limits (110); treasury, native transactions, escrow, finality,
reconciliation (120). Sections 18.5–18.9 split into 110 and 120 when those documents
are opened. **Required diagrams:** meter flow, rating, customer/supplier attribution;
double-entry flows, holds, invoice finalization; funding, transaction uncertainty,
settlement closure.

> **Estate note (ADR 0001, open decision A):** the default until decided is that a
> prepaid USD balance is a budget the wallet issues grants against; the customer never
> sees a token.

## 18. Metering, pricing, billing, settlement

### 18.1 Commercial model

The platform is the customer-facing seller of the managed cloud service.

The customer receives:

```text
USD rate card
USD quote
USD usage statement
USD invoice
platform service terms
```

The platform purchases native infrastructure separately.

**Supplier settlement is not customer billing.**

### 18.2 Pricing products

| Product             | Customer contract                                                             |
| ------------------- | ----------------------------------------------------------------------------- |
| On-demand           | Accepted USD rate valid for the stated interval or renewal terms              |
| Interruptible       | Lower rate with explicit interruption and recovery conditions                 |
| Reserved            | Capacity commitment with interval, cancellation, and replacement terms        |
| Market pass-through | Advanced product with explicit variable-price exposure                        |
| Managed endpoint    | Compute/service rate plus disclosed data/network charges                      |
| Archive             | Stored capacity, retention, retrieval, and protocol-related charges as quoted |

Dynamic supplier prices do not retroactively change an accepted fixed USD rate.

### 18.3 Who bears volatility risk?

For fixed-price products, **the cloud operator bears supplier-price, exchange-rate, startup, and settlement timing risk within the accepted contract**.

Manage that risk through:

```text
short quote validity
bounded pricing terms
prefunded supplier balances
limited token inventory
matched commitments
risk reserves
provider diversification
circuit breakers
hedging only where suitable and operationally justified
```

A hedge is not assumed to exist for every protocol asset. Stable-denominated mechanisms also retain counterparty, liquidity, and protocol risks.

Current Akash node documentation includes ACT funding and ACT/AKT burn-mint-equilibrium components. The adapter must follow the deployed protocol version rather than hard-code an older payment model. ([Akash Network][16])

### 18.4 Payment collection

Use a hosted payment flow for cards and supported bank payments. The cloud should not handle raw card data.

Stripe's documentation describes hosted payment fields and integrations that keep sensitive card entry within its payment infrastructure; this reduces the cloud's direct handling of card data but does not remove the cloud's own compliance responsibilities. ([Stripe][17])

Launch prepaid service credit and approved invoiced accounts. Treat auto-recharge authorization separately from resource deployment authorization.

Crypto is optional through supported payment rails. Ordinary customers never need protocol tokens.

### 18.5 Financial ledger

Maintain an append-only double-entry ledger with accounts for:

```text
customer receivables
customer prepaid service liabilities
cash/payment-processor balances
reserved spending commitments
earned revenue
supplier expenses
supplier payables
native-token inventory
protocol escrow assets
fees
FX gains/losses
credits and refunds
```

A spend hold is not revenue. A protocol escrow deposit is not automatically consumed supplier expense.

Corrections create reversing or adjusting entries. Posted journal entries are not edited.

### 18.6 Metering

A usage record contains:

```text
record_id
organization/project/resource/allocation
meter
quantity and integer base unit
interval_start / interval_end
source_id / source_epoch / sequence
evidence references
rate-card version
correction reference, if any
```

Use integer quantities and decimal/rational rates. Round monetary amounts at documented invoice boundaries, not independently every second.

Examples:

```text
GPU milliseconds
vCPU milliseconds
memory byte-seconds
stored byte-seconds
billable egress bytes
request count
model-token count where the runtime meter is qualified
```

Meters declare exactly what they count. Logical object size is not physical replica size. Customer-visible network charges must not count the same payload independently at every internal relay.

### 18.7 Billing start and stop

| Resource        | Customer billing start                                                 |
| --------------- | ---------------------------------------------------------------------- |
| Managed Service | Accepted readiness/billable event under the product contract           |
| Job             | Accepted execution start                                               |
| Direct instance | Instance made available to the customer                                |
| Storage         | Data or reserved capacity accepted under the selected storage contract |
| Reservation     | Reservation interval begins                                            |

Supplier costs may begin earlier, such as lease acquisition. The operator accounts for that difference.

For platform-caused repair, do not double-charge the customer for temporary replacement overlap. Elective migration surge is disclosed in the plan.

### 18.8 Budgets and hard limits

Distinguish:

```text
Budget: alerting and forecasting
Admission limit: blocks new commitments
Hard customer spend ceiling: contractual maximum liability
Continuity reserve: approved funds for existing service/data preservation
```

A strict ceiling cannot rely only on delayed usage reports. Issue bounded spending grants before acquisition, reserve committed costs, limit uncontrolled egress, and account for meter lag.

Where upstream resources cannot stop instantly, the operator absorbs costs beyond the agreed customer ceiling. It does not silently transfer those costs to the customer.

Data retention after compute suspension has its own funded policy. Do not delete production data immediately because a card payment fails.

### 18.9 Reconciliation and invoices

Reconcile three independent streams:

```text
Customer-authorized service usage
Provider/native resource usage and obligations
Payment-processor and protocol settlement records
```

Monthly invoices finalize customer charges according to the commercial contract. Delayed native settlement remains an operator liability or receivable; it need not keep a fixed-price customer invoice indefinitely open.

Advanced resource views expose native acquisition price, currency, FX basis, allocation methodology, platform price, and settlement state.

[16]: https://akash.network/docs/node-operators/architecture/overview/
[17]: https://stripe.com/guides/pci-compliance
