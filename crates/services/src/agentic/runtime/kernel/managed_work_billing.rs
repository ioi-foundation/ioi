//! Owner-derived managed-work billing kernel.
//!
//! This module is deliberately an internal ledger seam, not a public usage
//! mint. It keeps money, Work Credits, supplier evidence, and coarse telemetry
//! separate while enforcing one fixed-point quote -> hold -> usage -> debit ->
//! downward-adjustment chain.

use std::collections::BTreeSet;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use ioi_types::app::generated::architecture_contracts::validate_architecture_contract;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const MANAGED_WORK_BILLING_BUNDLE_CONTRACT_ID: &str =
    "schema://ioi/foundations/managed-work-billing-ledger-bundle/v1";
pub const MANAGED_WORK_BILLING_SCHEMA_VERSION: &str =
    "ioi.foundations.managed-work-billing-ledger-bundle.v1";
pub const MAX_SAFE_FIXED_POINT_UNITS: u64 = 9_007_199_254_740_991;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedWorkBillingError {
    pub code: &'static str,
    pub message: String,
}

impl ManagedWorkBillingError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for ManagedWorkBillingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for ManagedWorkBillingError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerResolvedBillingContext {
    pub billing_account_ref: String,
    pub work_ref: String,
    pub authority_ref: String,
    pub owner_evidence_refs: Vec<String>,
    pub idempotency_key: String,
    pub observed_at_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChargeComponent {
    ManagedModel,
    ManagedRuntime,
    Broker,
    Participant,
    Verifier,
    IoiManagedService,
    NonBillableTelemetry,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResetPolicy {
    NonResetting,
    MonthlyExpiring,
    ContractTermExpiring,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverrunPolicy {
    Block,
    ExactAdditionalHold,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum CommercialPosture {
    Managed,
    CustomerByok,
    CustomerByoa,
    CustomerCloud,
    SelfHosted,
    Local,
}

impl CommercialPosture {
    fn is_customer_borne(self) -> bool {
        !matches!(self, Self::Managed)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupplierReconciliationState {
    NotApplicable,
    Estimated,
    SupplierStatementReconciled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldKind {
    Initial,
    ExactAdditional,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldStatus {
    Active,
    Consumed,
    Released,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverrunAction {
    Block,
    ExactAdditionalHold,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdjustmentKind {
    Refund,
    Writeoff,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BillingAssuranceStatus {
    InternalEventLog,
    SupplierPartiallyReconciled,
    SupplierReconciled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkCreditAmount {
    pub unit: String,
    pub units: u64,
}

impl WorkCreditAmount {
    pub fn micro(units: u64) -> Self {
        Self {
            unit: "micro_work_credit".to_string(),
            units,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedWorkCostBreakdown {
    pub currency_code: String,
    pub provider_cost_minor: u64,
    pub broker_fee_minor: u64,
    pub participant_cost_minor: u64,
    pub verifier_cost_minor: u64,
    pub ioi_fee_minor: u64,
    pub excluded_customer_borne_provider_cost_minor: u64,
    pub supplier_reconciliation_state: SupplierReconciliationState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeterRate {
    pub meter_class: String,
    pub work_credit_micro_units_per_meter_unit: u64,
    pub charge_component: ChargeComponent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateCardInput {
    pub rate_card_ref: String,
    pub version: u64,
    pub currency_code: String,
    pub meter_rates: Vec<MeterRate>,
    pub ioi_fee_policy_ref: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateCard {
    pub rate_card_ref: String,
    pub version: u64,
    pub body_hash: String,
    pub currency_code: String,
    pub meter_rates: Vec<MeterRate>,
    pub ioi_fee_policy_ref: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanInput {
    pub plan_ref: String,
    pub version: u64,
    pub rate_card_ref: String,
    pub rate_card_body_hash: String,
    pub included_work_credit_units: u64,
    pub reset_policy: ResetPolicy,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedWorkPlan {
    pub plan_ref: String,
    pub version: u64,
    pub body_hash: String,
    pub rate_card_ref: String,
    pub rate_card_body_hash: String,
    pub included_work_credits: WorkCreditAmount,
    pub reset_policy: ResetPolicy,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkQuoteInput {
    pub quote_ref: String,
    pub rate_card_ref: String,
    pub rate_card_body_hash: String,
    pub plan_ref: String,
    pub plan_body_hash: String,
    pub estimated_work_credit_units: u64,
    pub required_hold_work_credit_units: u64,
    pub overrun_policy: OverrunPolicy,
    pub max_attempt_count: u64,
    pub allowed_commercial_postures: Vec<CommercialPosture>,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkQuote {
    pub quote_ref: String,
    pub body_hash: String,
    pub rate_card_ref: String,
    pub rate_card_body_hash: String,
    pub plan_ref: String,
    pub plan_body_hash: String,
    pub estimated_work_credits: WorkCreditAmount,
    pub required_hold: WorkCreditAmount,
    pub overrun_policy: OverrunPolicy,
    pub max_attempt_count: u64,
    pub allowed_commercial_postures: Vec<CommercialPosture>,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreditHoldInput {
    pub hold_ref: String,
    pub quote_ref: String,
    pub hold_kind: HoldKind,
    pub overrun_decision_ref: Option<String>,
    pub amount_work_credit_units: u64,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreditHold {
    pub hold_ref: String,
    pub body_hash: String,
    pub quote_ref: String,
    pub idempotency_key: String,
    pub hold_kind: HoldKind,
    pub overrun_decision_ref: Option<String>,
    pub amount: WorkCreditAmount,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
    pub status: HoldStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageRecordInput {
    pub usage_ref: String,
    pub quote_ref: String,
    pub previous_usage_hash: Option<String>,
    pub runtime_receipt_refs: Vec<String>,
    pub supplier_statement_refs: Vec<String>,
    pub meter_class: String,
    pub quantity_units: u64,
    pub commercial_posture: CommercialPosture,
    pub cost_breakdown: ManagedWorkCostBreakdown,
    pub coarse_ocu_projection: bool,
    pub occurred_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageRecord {
    pub usage_ref: String,
    pub body_hash: String,
    pub quote_ref: String,
    pub sequence: u64,
    pub previous_usage_hash: Option<String>,
    pub runtime_receipt_refs: Vec<String>,
    pub supplier_statement_refs: Vec<String>,
    pub meter_class: String,
    pub quantity_units: u64,
    pub rate_work_credit_micro_units_per_meter_unit: u64,
    pub charged_work_credits: WorkCreditAmount,
    pub commercial_posture: CommercialPosture,
    pub cost_breakdown: ManagedWorkCostBreakdown,
    pub coarse_ocu_projection: bool,
    pub occurred_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverrunDecisionInput {
    pub overrun_decision_ref: String,
    pub quote_ref: String,
    pub usage_head_hash: Option<String>,
    pub projected_work_credit_units: u64,
    pub action: OverrunAction,
    pub requested_additional_hold_work_credit_units: u64,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverrunDecision {
    pub overrun_decision_ref: String,
    pub body_hash: String,
    pub quote_ref: String,
    pub usage_head_hash: Option<String>,
    pub held_work_credits: WorkCreditAmount,
    pub projected_work_credits: WorkCreditAmount,
    pub exact_overage_work_credits: WorkCreditAmount,
    pub decision: OverrunAction,
    pub additional_hold_amount: WorkCreditAmount,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalDebitInput {
    pub final_debit_ref: String,
    pub quote_ref: String,
    pub usage_head_hash: Option<String>,
    pub requested_debit_work_credit_units: u64,
    pub finalized_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalDebit {
    pub final_debit_ref: String,
    pub body_hash: String,
    pub quote_ref: String,
    pub usage_head_hash: Option<String>,
    pub usage_record_refs: Vec<String>,
    pub hold_refs: Vec<String>,
    pub debited_work_credits: WorkCreditAmount,
    pub finalized_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BillingAdjustmentInput {
    pub adjustment_ref: String,
    pub final_debit_ref: String,
    pub previous_adjustment_hash: Option<String>,
    pub adjustment_kind: AdjustmentKind,
    pub amount_work_credit_units: u64,
    pub reason_code: String,
    pub evidence_refs: Vec<String>,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BillingAdjustment {
    pub adjustment_ref: String,
    pub body_hash: String,
    pub final_debit_ref: String,
    pub previous_adjustment_hash: Option<String>,
    pub adjustment_kind: AdjustmentKind,
    pub amount: WorkCreditAmount,
    pub reason_code: String,
    pub evidence_refs: Vec<String>,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command_type", content = "command", rename_all = "snake_case")]
pub enum ManagedWorkBillingCommand {
    PublishRateCard {
        context: OwnerResolvedBillingContext,
        input: RateCardInput,
    },
    PublishPlan {
        context: OwnerResolvedBillingContext,
        input: PlanInput,
    },
    IssueQuote {
        context: OwnerResolvedBillingContext,
        input: WorkQuoteInput,
    },
    PlaceHold {
        context: OwnerResolvedBillingContext,
        input: CreditHoldInput,
    },
    RecordUsage {
        context: OwnerResolvedBillingContext,
        input: UsageRecordInput,
    },
    DecideOverrun {
        context: OwnerResolvedBillingContext,
        input: OverrunDecisionInput,
    },
    FinalizeDebit {
        context: OwnerResolvedBillingContext,
        input: FinalDebitInput,
    },
    ApplyAdjustment {
        context: OwnerResolvedBillingContext,
        input: BillingAdjustmentInput,
    },
}

impl ManagedWorkBillingCommand {
    fn context(&self) -> &OwnerResolvedBillingContext {
        match self {
            Self::PublishRateCard { context, .. }
            | Self::PublishPlan { context, .. }
            | Self::IssueQuote { context, .. }
            | Self::PlaceHold { context, .. }
            | Self::RecordUsage { context, .. }
            | Self::DecideOverrun { context, .. }
            | Self::FinalizeDebit { context, .. }
            | Self::ApplyAdjustment { context, .. } => context,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "record_type", content = "record", rename_all = "snake_case")]
pub enum ManagedWorkBillingRecord {
    RateCard(RateCard),
    Plan(ManagedWorkPlan),
    WorkQuote(WorkQuote),
    CreditHold(CreditHold),
    UsageRecord(UsageRecord),
    OverrunDecision(OverrunDecision),
    FinalDebit(FinalDebit),
    Adjustment(BillingAdjustment),
}

impl ManagedWorkBillingRecord {
    fn body_hash(&self) -> &str {
        match self {
            Self::RateCard(record) => &record.body_hash,
            Self::Plan(record) => &record.body_hash,
            Self::WorkQuote(record) => &record.body_hash,
            Self::CreditHold(record) => &record.body_hash,
            Self::UsageRecord(record) => &record.body_hash,
            Self::OverrunDecision(record) => &record.body_hash,
            Self::FinalDebit(record) => &record.body_hash,
            Self::Adjustment(record) => &record.body_hash,
        }
    }

    fn record_ref(&self) -> &str {
        match self {
            Self::RateCard(record) => &record.rate_card_ref,
            Self::Plan(record) => &record.plan_ref,
            Self::WorkQuote(record) => &record.quote_ref,
            Self::CreditHold(record) => &record.hold_ref,
            Self::UsageRecord(record) => &record.usage_ref,
            Self::OverrunDecision(record) => &record.overrun_decision_ref,
            Self::FinalDebit(record) => &record.final_debit_ref,
            Self::Adjustment(record) => &record.adjustment_ref,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedWorkBillingLedgerEntry {
    pub sequence: u64,
    pub entry_ref: String,
    pub billing_account_ref: String,
    pub work_ref: String,
    pub idempotency_key: String,
    pub command_hash: String,
    pub previous_entry_hash: Option<String>,
    pub record_body_hash: String,
    pub record: ManagedWorkBillingRecord,
    pub entry_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedWorkBillingApplyOutcome {
    pub entry: ManagedWorkBillingLedgerEntry,
    pub replayed: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ManagedWorkBillingLedger {
    billing_account_ref: Option<String>,
    work_ref: Option<String>,
    rate_card: Option<RateCard>,
    plan: Option<ManagedWorkPlan>,
    quote: Option<WorkQuote>,
    holds: Vec<CreditHold>,
    usage_records: Vec<UsageRecord>,
    overrun_decisions: Vec<OverrunDecision>,
    final_debit: Option<FinalDebit>,
    adjustments: Vec<BillingAdjustment>,
    entries: Vec<ManagedWorkBillingLedgerEntry>,
}

impl ManagedWorkBillingLedger {
    pub fn entries(&self) -> &[ManagedWorkBillingLedgerEntry] {
        &self.entries
    }

    pub fn current_usage_head_hash(&self) -> Option<&str> {
        self.usage_records
            .last()
            .map(|record| record.body_hash.as_str())
    }

    pub fn current_ledger_head_hash(&self) -> Option<&str> {
        self.entries.last().map(|entry| entry.entry_hash.as_str())
    }

    pub fn total_usage_work_credit_units(&self) -> Result<u64, ManagedWorkBillingError> {
        checked_sum(
            self.usage_records
                .iter()
                .map(|record| record.charged_work_credits.units),
            "billing_usage_total_overflow",
        )
    }

    pub fn total_held_work_credit_units(&self) -> Result<u64, ManagedWorkBillingError> {
        checked_sum(
            self.holds.iter().map(|record| record.amount.units),
            "billing_hold_total_overflow",
        )
    }

    pub fn apply(
        &mut self,
        command: ManagedWorkBillingCommand,
    ) -> Result<ManagedWorkBillingApplyOutcome, ManagedWorkBillingError> {
        let command_hash = canonical_hash(&command)?;
        let context = command.context().clone();
        validate_context(&context)?;

        if let Some(existing) = self
            .entries
            .iter()
            .find(|entry| entry.idempotency_key == context.idempotency_key)
        {
            if existing.command_hash == command_hash {
                return Ok(ManagedWorkBillingApplyOutcome {
                    entry: existing.clone(),
                    replayed: true,
                });
            }
            return Err(ManagedWorkBillingError::new(
                "billing_idempotency_conflict",
                "the idempotency key already binds different canonical command bytes",
            ));
        }
        self.bind_ledger_identity(&context)?;

        let record = match command {
            ManagedWorkBillingCommand::PublishRateCard { context, input } => {
                self.publish_rate_card(&context, input)?
            }
            ManagedWorkBillingCommand::PublishPlan { context, input } => {
                self.publish_plan(&context, input)?
            }
            ManagedWorkBillingCommand::IssueQuote { context, input } => {
                self.issue_quote(&context, input)?
            }
            ManagedWorkBillingCommand::PlaceHold { context, input } => {
                self.place_hold(&context, input)?
            }
            ManagedWorkBillingCommand::RecordUsage { context, input } => {
                self.record_usage(&context, input)?
            }
            ManagedWorkBillingCommand::DecideOverrun { context, input } => {
                self.decide_overrun(&context, input)?
            }
            ManagedWorkBillingCommand::FinalizeDebit { context, input } => {
                self.finalize_debit(&context, input)?
            }
            ManagedWorkBillingCommand::ApplyAdjustment { context, input } => {
                self.apply_adjustment(&context, input)?
            }
        };
        let entry = self.append_record(&context, command_hash, record)?;
        Ok(ManagedWorkBillingApplyOutcome {
            entry,
            replayed: false,
        })
    }

    pub fn replay(
        entries: Vec<ManagedWorkBillingLedgerEntry>,
    ) -> Result<Self, ManagedWorkBillingError> {
        let mut ledger = Self::default();
        for entry in entries {
            ledger.verify_and_absorb_entry(entry)?;
        }
        Ok(ledger)
    }

    pub fn export_bundle(
        &self,
        bundle_ref: &str,
        exported_at_ms: u64,
    ) -> Result<Value, ManagedWorkBillingError> {
        require_ref("bundle_ref", bundle_ref)?;
        require_safe("exported_at_ms", exported_at_ms)?;
        let rate_card = self.rate_card.as_ref().ok_or_else(|| {
            ManagedWorkBillingError::new("billing_rate_card_missing", "RateCard is missing")
        })?;
        let plan = self.plan.as_ref().ok_or_else(|| {
            ManagedWorkBillingError::new("billing_plan_missing", "Plan is missing")
        })?;
        let quote = self.quote.as_ref().ok_or_else(|| {
            ManagedWorkBillingError::new("billing_quote_missing", "WorkQuote is missing")
        })?;
        if self.holds.is_empty() {
            return Err(ManagedWorkBillingError::new(
                "billing_hold_missing",
                "at least one CreditHold is required",
            ));
        }
        let billing_account_ref = self.billing_account_ref.as_deref().ok_or_else(|| {
            ManagedWorkBillingError::new(
                "billing_ledger_identity_missing",
                "billing account is missing",
            )
        })?;
        let work_ref = self.work_ref.as_deref().ok_or_else(|| {
            ManagedWorkBillingError::new("billing_ledger_identity_missing", "work ref is missing")
        })?;
        let ledger_head_hash = self.current_ledger_head_hash().ok_or_else(|| {
            ManagedWorkBillingError::new("billing_ledger_empty", "billing ledger is empty")
        })?;
        let hold_status = if self.final_debit.is_some() {
            HoldStatus::Consumed
        } else {
            HoldStatus::Active
        };
        let holds = self
            .holds
            .iter()
            .cloned()
            .map(|mut hold| {
                hold.status = hold_status;
                hold
            })
            .collect::<Vec<_>>();
        let assurance_status = self.assurance_status();
        let bundle = json!({
            "schema_version": MANAGED_WORK_BILLING_SCHEMA_VERSION,
            "bundle_ref": bundle_ref,
            "billing_account_ref": billing_account_ref,
            "work_ref": work_ref,
            "rate_card": rate_card,
            "plan": plan,
            "quote": quote,
            "holds": holds,
            "usage_records": self.usage_records,
            "overrun_decisions": self.overrun_decisions,
            "final_debit": self.final_debit,
            "adjustments": self.adjustments,
            "ledger_head_hash": ledger_head_hash,
            "exported_at_ms": exported_at_ms,
            "assurance_status": assurance_status,
        });
        validate_architecture_contract(MANAGED_WORK_BILLING_BUNDLE_CONTRACT_ID, &bundle).map_err(
            |error| {
                ManagedWorkBillingError::new(
                    "billing_bundle_contract_invalid",
                    format!("exported billing bundle violates the registered contract: {error}"),
                )
            },
        )?;
        Ok(bundle)
    }

    fn assurance_status(&self) -> BillingAssuranceStatus {
        let managed = self
            .usage_records
            .iter()
            .filter(|record| record.commercial_posture == CommercialPosture::Managed)
            .collect::<Vec<_>>();
        if managed.is_empty() {
            return BillingAssuranceStatus::InternalEventLog;
        }
        let reconciled = managed
            .iter()
            .filter(|record| {
                record.cost_breakdown.supplier_reconciliation_state
                    == SupplierReconciliationState::SupplierStatementReconciled
                    && !record.supplier_statement_refs.is_empty()
            })
            .count();
        if reconciled == managed.len() {
            BillingAssuranceStatus::SupplierReconciled
        } else if reconciled > 0 {
            BillingAssuranceStatus::SupplierPartiallyReconciled
        } else {
            BillingAssuranceStatus::InternalEventLog
        }
    }

    fn bind_ledger_identity(
        &mut self,
        context: &OwnerResolvedBillingContext,
    ) -> Result<(), ManagedWorkBillingError> {
        match (&self.billing_account_ref, &self.work_ref) {
            (None, None) => {
                self.billing_account_ref = Some(context.billing_account_ref.clone());
                self.work_ref = Some(context.work_ref.clone());
                Ok(())
            }
            (Some(account), Some(work))
                if account == &context.billing_account_ref && work == &context.work_ref =>
            {
                Ok(())
            }
            _ => Err(ManagedWorkBillingError::new(
                "billing_ledger_identity_conflict",
                "command billing-account/work identity differs from the ledger",
            )),
        }
    }

    fn publish_rate_card(
        &self,
        context: &OwnerResolvedBillingContext,
        input: RateCardInput,
    ) -> Result<ManagedWorkBillingRecord, ManagedWorkBillingError> {
        if self.rate_card.is_some() {
            return Err(ManagedWorkBillingError::new(
                "billing_rate_card_already_published",
                "this work ledger already freezes one RateCard revision",
            ));
        }
        require_ref("rate_card_ref", &input.rate_card_ref)?;
        require_ref("ioi_fee_policy_ref", &input.ioi_fee_policy_ref)?;
        require_positive_safe("rate_card.version", input.version)?;
        validate_currency(&input.currency_code)?;
        validate_window(
            "rate_card",
            input.issued_at_ms,
            input.expires_at_ms,
            context.observed_at_ms,
        )?;
        if input.meter_rates.is_empty() {
            return Err(ManagedWorkBillingError::new(
                "billing_rate_card_empty",
                "RateCard requires at least one meter rate",
            ));
        }
        let mut meter_classes = BTreeSet::new();
        for rate in &input.meter_rates {
            require_nonempty("meter_class", &rate.meter_class)?;
            require_safe(
                "work_credit_micro_units_per_meter_unit",
                rate.work_credit_micro_units_per_meter_unit,
            )?;
            if !meter_classes.insert(rate.meter_class.as_str()) {
                return Err(ManagedWorkBillingError::new(
                    "billing_rate_card_duplicate_meter",
                    format!("meter class '{}' appears more than once", rate.meter_class),
                ));
            }
            if rate.charge_component == ChargeComponent::NonBillableTelemetry
                && rate.work_credit_micro_units_per_meter_unit != 0
            {
                return Err(ManagedWorkBillingError::new(
                    "billing_non_billable_meter_has_rate",
                    "non-billable telemetry must have a zero Work Credit rate",
                ));
            }
        }
        let mut record = RateCard {
            rate_card_ref: input.rate_card_ref,
            version: input.version,
            body_hash: String::new(),
            currency_code: input.currency_code,
            meter_rates: input.meter_rates,
            ioi_fee_policy_ref: input.ioi_fee_policy_ref,
            issued_at_ms: input.issued_at_ms,
            expires_at_ms: input.expires_at_ms,
        };
        record.body_hash = canonical_record_body_hash(&record)?;
        Ok(ManagedWorkBillingRecord::RateCard(record))
    }

    fn publish_plan(
        &self,
        context: &OwnerResolvedBillingContext,
        input: PlanInput,
    ) -> Result<ManagedWorkBillingRecord, ManagedWorkBillingError> {
        if self.plan.is_some() {
            return Err(ManagedWorkBillingError::new(
                "billing_plan_already_published",
                "this work ledger already freezes one Plan revision",
            ));
        }
        let rate_card = self.rate_card.as_ref().ok_or_else(|| {
            ManagedWorkBillingError::new(
                "billing_rate_card_missing",
                "Plan requires a published RateCard",
            )
        })?;
        require_ref("plan_ref", &input.plan_ref)?;
        require_positive_safe("plan.version", input.version)?;
        require_safe(
            "included_work_credit_units",
            input.included_work_credit_units,
        )?;
        require_exact_binding(
            "rate_card",
            &input.rate_card_ref,
            &input.rate_card_body_hash,
            &rate_card.rate_card_ref,
            &rate_card.body_hash,
        )?;
        validate_window(
            "plan",
            input.issued_at_ms,
            input.expires_at_ms,
            context.observed_at_ms,
        )?;
        if input.expires_at_ms > rate_card.expires_at_ms {
            return Err(ManagedWorkBillingError::new(
                "billing_plan_outlives_rate_card",
                "Plan expiry cannot exceed its RateCard expiry",
            ));
        }
        let mut record = ManagedWorkPlan {
            plan_ref: input.plan_ref,
            version: input.version,
            body_hash: String::new(),
            rate_card_ref: input.rate_card_ref,
            rate_card_body_hash: input.rate_card_body_hash,
            included_work_credits: WorkCreditAmount::micro(input.included_work_credit_units),
            reset_policy: input.reset_policy,
            issued_at_ms: input.issued_at_ms,
            expires_at_ms: input.expires_at_ms,
        };
        record.body_hash = canonical_record_body_hash(&record)?;
        Ok(ManagedWorkBillingRecord::Plan(record))
    }

    fn issue_quote(
        &self,
        context: &OwnerResolvedBillingContext,
        input: WorkQuoteInput,
    ) -> Result<ManagedWorkBillingRecord, ManagedWorkBillingError> {
        if self.quote.is_some() {
            return Err(ManagedWorkBillingError::new(
                "billing_quote_already_issued",
                "a WorkQuote is immutable and unique within this work ledger",
            ));
        }
        let rate_card = self.rate_card.as_ref().ok_or_else(|| {
            ManagedWorkBillingError::new(
                "billing_rate_card_missing",
                "WorkQuote requires a RateCard",
            )
        })?;
        let plan = self.plan.as_ref().ok_or_else(|| {
            ManagedWorkBillingError::new("billing_plan_missing", "WorkQuote requires a Plan")
        })?;
        require_ref("quote_ref", &input.quote_ref)?;
        require_exact_binding(
            "rate_card",
            &input.rate_card_ref,
            &input.rate_card_body_hash,
            &rate_card.rate_card_ref,
            &rate_card.body_hash,
        )?;
        require_exact_binding(
            "plan",
            &input.plan_ref,
            &input.plan_body_hash,
            &plan.plan_ref,
            &plan.body_hash,
        )?;
        require_positive_safe(
            "estimated_work_credit_units",
            input.estimated_work_credit_units,
        )?;
        require_positive_safe(
            "required_hold_work_credit_units",
            input.required_hold_work_credit_units,
        )?;
        if input.required_hold_work_credit_units != input.estimated_work_credit_units {
            return Err(ManagedWorkBillingError::new(
                "billing_quote_hold_not_exact",
                "v1 requires the initial hold to equal the quoted Work Credit estimate",
            ));
        }
        require_positive_safe("max_attempt_count", input.max_attempt_count)?;
        if input.allowed_commercial_postures.is_empty() {
            return Err(ManagedWorkBillingError::new(
                "billing_quote_posture_empty",
                "WorkQuote requires at least one commercial posture",
            ));
        }
        let unique = input
            .allowed_commercial_postures
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        if unique.len() != input.allowed_commercial_postures.len() {
            return Err(ManagedWorkBillingError::new(
                "billing_quote_posture_duplicate",
                "WorkQuote commercial postures must be unique",
            ));
        }
        validate_window(
            "quote",
            input.issued_at_ms,
            input.expires_at_ms,
            context.observed_at_ms,
        )?;
        if input.expires_at_ms > rate_card.expires_at_ms || input.expires_at_ms > plan.expires_at_ms
        {
            return Err(ManagedWorkBillingError::new(
                "billing_quote_outlives_inputs",
                "WorkQuote expiry cannot exceed its RateCard or Plan expiry",
            ));
        }
        let mut record = WorkQuote {
            quote_ref: input.quote_ref,
            body_hash: String::new(),
            rate_card_ref: input.rate_card_ref,
            rate_card_body_hash: input.rate_card_body_hash,
            plan_ref: input.plan_ref,
            plan_body_hash: input.plan_body_hash,
            estimated_work_credits: WorkCreditAmount::micro(input.estimated_work_credit_units),
            required_hold: WorkCreditAmount::micro(input.required_hold_work_credit_units),
            overrun_policy: input.overrun_policy,
            max_attempt_count: input.max_attempt_count,
            allowed_commercial_postures: input.allowed_commercial_postures,
            issued_at_ms: input.issued_at_ms,
            expires_at_ms: input.expires_at_ms,
        };
        record.body_hash = canonical_record_body_hash(&record)?;
        Ok(ManagedWorkBillingRecord::WorkQuote(record))
    }

    fn place_hold(
        &self,
        context: &OwnerResolvedBillingContext,
        input: CreditHoldInput,
    ) -> Result<ManagedWorkBillingRecord, ManagedWorkBillingError> {
        if self.final_debit.is_some() {
            return Err(ManagedWorkBillingError::new(
                "billing_already_finalized",
                "no hold may be appended after FinalDebit",
            ));
        }
        let quote = self.quote.as_ref().ok_or_else(|| {
            ManagedWorkBillingError::new("billing_quote_missing", "CreditHold requires a WorkQuote")
        })?;
        require_ref("hold_ref", &input.hold_ref)?;
        require_exact_ref("quote_ref", &input.quote_ref, &quote.quote_ref)?;
        require_positive_safe("hold.amount", input.amount_work_credit_units)?;
        validate_window(
            "hold",
            input.created_at_ms,
            input.expires_at_ms,
            context.observed_at_ms,
        )?;
        if input.expires_at_ms > quote.expires_at_ms {
            return Err(ManagedWorkBillingError::new(
                "billing_hold_outlives_quote",
                "CreditHold expiry cannot exceed WorkQuote expiry",
            ));
        }
        if self
            .holds
            .iter()
            .any(|hold| hold.hold_ref == input.hold_ref)
        {
            return Err(ManagedWorkBillingError::new(
                "billing_hold_ref_conflict",
                "CreditHold ref already exists",
            ));
        }
        match input.hold_kind {
            HoldKind::Initial => {
                if !self.holds.is_empty() {
                    return Err(ManagedWorkBillingError::new(
                        "billing_initial_hold_already_exists",
                        "only one initial CreditHold is valid",
                    ));
                }
                if input.overrun_decision_ref.is_some()
                    || input.amount_work_credit_units != quote.required_hold.units
                {
                    return Err(ManagedWorkBillingError::new(
                        "billing_initial_hold_not_exact",
                        "initial CreditHold must equal the quoted required hold and have no overrun decision",
                    ));
                }
            }
            HoldKind::ExactAdditional => {
                let decision_ref = input.overrun_decision_ref.as_deref().ok_or_else(|| {
                    ManagedWorkBillingError::new(
                        "billing_additional_hold_decision_missing",
                        "additional CreditHold requires an OverrunDecision",
                    )
                })?;
                let decision = self
                    .overrun_decisions
                    .iter()
                    .find(|record| record.overrun_decision_ref == decision_ref)
                    .ok_or_else(|| {
                        ManagedWorkBillingError::new(
                            "billing_additional_hold_decision_unknown",
                            "referenced OverrunDecision does not exist",
                        )
                    })?;
                if decision.decision != OverrunAction::ExactAdditionalHold
                    || decision.additional_hold_amount.units != input.amount_work_credit_units
                    || decision.usage_head_hash.as_deref() != self.current_usage_head_hash()
                {
                    return Err(ManagedWorkBillingError::new(
                        "billing_additional_hold_not_exact",
                        "additional CreditHold must exactly consume the current-head OverrunDecision",
                    ));
                }
                if self
                    .holds
                    .iter()
                    .any(|hold| hold.overrun_decision_ref.as_deref() == Some(decision_ref))
                {
                    return Err(ManagedWorkBillingError::new(
                        "billing_overrun_decision_already_consumed",
                        "OverrunDecision already has an additional CreditHold",
                    ));
                }
            }
        }
        let mut record = CreditHold {
            hold_ref: input.hold_ref,
            body_hash: String::new(),
            quote_ref: input.quote_ref,
            idempotency_key: context.idempotency_key.clone(),
            hold_kind: input.hold_kind,
            overrun_decision_ref: input.overrun_decision_ref,
            amount: WorkCreditAmount::micro(input.amount_work_credit_units),
            created_at_ms: input.created_at_ms,
            expires_at_ms: input.expires_at_ms,
            status: HoldStatus::Active,
        };
        record.body_hash = canonical_record_body_hash(&record)?;
        Ok(ManagedWorkBillingRecord::CreditHold(record))
    }

    fn record_usage(
        &self,
        context: &OwnerResolvedBillingContext,
        input: UsageRecordInput,
    ) -> Result<ManagedWorkBillingRecord, ManagedWorkBillingError> {
        if self.final_debit.is_some() {
            return Err(ManagedWorkBillingError::new(
                "billing_usage_after_final_debit",
                "UsageRecord cannot be appended after FinalDebit",
            ));
        }
        let quote = self.quote.as_ref().ok_or_else(|| {
            ManagedWorkBillingError::new("billing_quote_missing", "UsageRecord requires WorkQuote")
        })?;
        let rate_card = self.rate_card.as_ref().ok_or_else(|| {
            ManagedWorkBillingError::new(
                "billing_rate_card_missing",
                "UsageRecord requires RateCard",
            )
        })?;
        require_ref("usage_ref", &input.usage_ref)?;
        require_exact_ref("quote_ref", &input.quote_ref, &quote.quote_ref)?;
        if input.occurred_at_ms > context.observed_at_ms
            || input.occurred_at_ms >= quote.expires_at_ms
        {
            return Err(ManagedWorkBillingError::new(
                "billing_usage_time_invalid",
                "usage must be owner-observed no later than command time and before quote expiry",
            ));
        }
        let next_attempt = u64::try_from(self.usage_records.len())
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| {
                ManagedWorkBillingError::new(
                    "billing_usage_sequence_overflow",
                    "UsageRecord sequence overflow",
                )
            })?;
        if next_attempt > quote.max_attempt_count {
            return Err(ManagedWorkBillingError::new(
                "billing_attempt_limit_exceeded",
                "UsageRecord would exceed the attempt cap frozen into WorkQuote",
            ));
        }
        let expected_head = self.current_usage_head_hash();
        if input.previous_usage_hash.as_deref() != expected_head {
            return Err(ManagedWorkBillingError::new(
                "billing_usage_head_conflict",
                "UsageRecord does not bind the current usage head",
            ));
        }
        require_nonempty_refs("runtime_receipt_refs", &input.runtime_receipt_refs)?;
        validate_unique_refs("runtime_receipt_refs", &input.runtime_receipt_refs)?;
        validate_unique_refs("supplier_statement_refs", &input.supplier_statement_refs)?;
        if !quote
            .allowed_commercial_postures
            .contains(&input.commercial_posture)
        {
            return Err(ManagedWorkBillingError::new(
                "billing_commercial_posture_denied",
                "usage commercial posture is outside the WorkQuote",
            ));
        }
        require_safe("quantity_units", input.quantity_units)?;
        validate_cost_breakdown(
            &input.cost_breakdown,
            &rate_card.currency_code,
            input.commercial_posture,
            &input.supplier_statement_refs,
        )?;
        let rate = rate_card
            .meter_rates
            .iter()
            .find(|rate| rate.meter_class == input.meter_class)
            .ok_or_else(|| {
                ManagedWorkBillingError::new(
                    "billing_meter_not_quoted",
                    "UsageRecord meter class is absent from the frozen RateCard",
                )
            })?;
        if input.coarse_ocu_projection {
            if rate.charge_component != ChargeComponent::NonBillableTelemetry
                || rate.work_credit_micro_units_per_meter_unit != 0
                || input.cost_breakdown != zero_nonbillable_cost(&rate_card.currency_code)
                || !input.supplier_statement_refs.is_empty()
            {
                return Err(ManagedWorkBillingError::new(
                    "billing_coarse_ocu_not_billable",
                    "coarse OCU may only use a zero-rate non-billable telemetry meter with no supplier-cost claim",
                ));
            }
        } else if rate.charge_component == ChargeComponent::NonBillableTelemetry {
            return Err(ManagedWorkBillingError::new(
                "billing_non_billable_meter_misclassified",
                "a non-billable telemetry meter must be explicitly marked coarse telemetry",
            ));
        }
        let charged_units = checked_mul(
            input.quantity_units,
            rate.work_credit_micro_units_per_meter_unit,
            "billing_rate_multiplication_overflow",
        )?;
        let current_usage = self.total_usage_work_credit_units()?;
        let projected_usage =
            checked_add(current_usage, charged_units, "billing_usage_total_overflow")?;
        let held = self.active_held_units_at(input.occurred_at_ms)?;
        if projected_usage > held {
            return Err(ManagedWorkBillingError::new(
                "billing_overrun_decision_required",
                format!(
                    "projected usage {projected_usage} exceeds active held Work Credits {held}"
                ),
            ));
        }
        let sequence = next_attempt;
        require_safe("usage.sequence", sequence)?;
        let mut record = UsageRecord {
            usage_ref: input.usage_ref,
            body_hash: String::new(),
            quote_ref: input.quote_ref,
            sequence,
            previous_usage_hash: input.previous_usage_hash,
            runtime_receipt_refs: input.runtime_receipt_refs,
            supplier_statement_refs: input.supplier_statement_refs,
            meter_class: input.meter_class,
            quantity_units: input.quantity_units,
            rate_work_credit_micro_units_per_meter_unit: rate
                .work_credit_micro_units_per_meter_unit,
            charged_work_credits: WorkCreditAmount::micro(charged_units),
            commercial_posture: input.commercial_posture,
            cost_breakdown: input.cost_breakdown,
            coarse_ocu_projection: input.coarse_ocu_projection,
            occurred_at_ms: input.occurred_at_ms,
        };
        record.body_hash = canonical_record_body_hash(&record)?;
        Ok(ManagedWorkBillingRecord::UsageRecord(record))
    }

    fn decide_overrun(
        &self,
        context: &OwnerResolvedBillingContext,
        input: OverrunDecisionInput,
    ) -> Result<ManagedWorkBillingRecord, ManagedWorkBillingError> {
        if self.final_debit.is_some() {
            return Err(ManagedWorkBillingError::new(
                "billing_already_finalized",
                "OverrunDecision cannot follow FinalDebit",
            ));
        }
        let quote = self.quote.as_ref().ok_or_else(|| {
            ManagedWorkBillingError::new(
                "billing_quote_missing",
                "OverrunDecision requires WorkQuote",
            )
        })?;
        require_ref("overrun_decision_ref", &input.overrun_decision_ref)?;
        require_exact_ref("quote_ref", &input.quote_ref, &quote.quote_ref)?;
        require_safe("overrun_decision.created_at_ms", input.created_at_ms)?;
        if input.created_at_ms > context.observed_at_ms
            || input.created_at_ms >= quote.expires_at_ms
        {
            return Err(ManagedWorkBillingError::new(
                "billing_overrun_decision_time_invalid",
                "OverrunDecision must be owner-observed and precede quote expiry",
            ));
        }
        if input.usage_head_hash.as_deref() != self.current_usage_head_hash() {
            return Err(ManagedWorkBillingError::new(
                "billing_overrun_usage_head_conflict",
                "OverrunDecision does not bind the current usage head",
            ));
        }
        require_safe(
            "projected_work_credit_units",
            input.projected_work_credit_units,
        )?;
        let held = self.active_held_units_at(input.created_at_ms)?;
        if input.projected_work_credit_units <= held {
            return Err(ManagedWorkBillingError::new(
                "billing_overrun_not_present",
                "projected usage does not exceed held Work Credits",
            ));
        }
        let exact_overage = input
            .projected_work_credit_units
            .checked_sub(held)
            .ok_or_else(|| {
                ManagedWorkBillingError::new(
                    "billing_overrun_arithmetic_invalid",
                    "projected usage underflowed held Work Credits",
                )
            })?;
        let additional_hold_units = match input.action {
            OverrunAction::Block => {
                if input.requested_additional_hold_work_credit_units != 0 {
                    return Err(ManagedWorkBillingError::new(
                        "billing_block_decision_has_hold",
                        "block decision requires zero additional hold",
                    ));
                }
                0
            }
            OverrunAction::ExactAdditionalHold => {
                if quote.overrun_policy != OverrunPolicy::ExactAdditionalHold {
                    return Err(ManagedWorkBillingError::new(
                        "billing_quote_blocks_overrun",
                        "WorkQuote does not permit an additional hold",
                    ));
                }
                if input.requested_additional_hold_work_credit_units != exact_overage {
                    return Err(ManagedWorkBillingError::new(
                        "billing_overrun_hold_not_exact",
                        "additional hold request must equal projected usage minus held Work Credits",
                    ));
                }
                exact_overage
            }
        };
        if self
            .overrun_decisions
            .iter()
            .any(|record| record.overrun_decision_ref == input.overrun_decision_ref)
        {
            return Err(ManagedWorkBillingError::new(
                "billing_overrun_decision_ref_conflict",
                "OverrunDecision ref already exists",
            ));
        }
        let mut record = OverrunDecision {
            overrun_decision_ref: input.overrun_decision_ref,
            body_hash: String::new(),
            quote_ref: input.quote_ref,
            usage_head_hash: input.usage_head_hash,
            held_work_credits: WorkCreditAmount::micro(held),
            projected_work_credits: WorkCreditAmount::micro(input.projected_work_credit_units),
            exact_overage_work_credits: WorkCreditAmount::micro(exact_overage),
            decision: input.action,
            additional_hold_amount: WorkCreditAmount::micro(additional_hold_units),
            created_at_ms: input.created_at_ms,
        };
        record.body_hash = canonical_record_body_hash(&record)?;
        Ok(ManagedWorkBillingRecord::OverrunDecision(record))
    }

    fn finalize_debit(
        &self,
        context: &OwnerResolvedBillingContext,
        input: FinalDebitInput,
    ) -> Result<ManagedWorkBillingRecord, ManagedWorkBillingError> {
        if self.final_debit.is_some() {
            return Err(ManagedWorkBillingError::new(
                "billing_final_debit_already_exists",
                "exactly one FinalDebit is permitted",
            ));
        }
        let quote = self.quote.as_ref().ok_or_else(|| {
            ManagedWorkBillingError::new("billing_quote_missing", "FinalDebit requires WorkQuote")
        })?;
        require_ref("final_debit_ref", &input.final_debit_ref)?;
        require_exact_ref("quote_ref", &input.quote_ref, &quote.quote_ref)?;
        require_safe("final_debit.finalized_at_ms", input.finalized_at_ms)?;
        if input.finalized_at_ms > context.observed_at_ms
            || input.finalized_at_ms >= quote.expires_at_ms
            || self
                .usage_records
                .last()
                .is_some_and(|record| input.finalized_at_ms < record.occurred_at_ms)
        {
            return Err(ManagedWorkBillingError::new(
                "billing_final_debit_time_invalid",
                "FinalDebit must follow usage, be owner-observed, and precede quote expiry",
            ));
        }
        if input.usage_head_hash.as_deref() != self.current_usage_head_hash() {
            return Err(ManagedWorkBillingError::new(
                "billing_final_debit_usage_head_conflict",
                "FinalDebit does not bind the current usage head",
            ));
        }
        if self.holds.is_empty() {
            return Err(ManagedWorkBillingError::new(
                "billing_hold_missing",
                "FinalDebit requires at least one CreditHold",
            ));
        }
        let usage_total = self.total_usage_work_credit_units()?;
        if input.requested_debit_work_credit_units != usage_total {
            return Err(ManagedWorkBillingError::new(
                "billing_final_debit_not_exact",
                "FinalDebit must equal the complete checked UsageRecord total",
            ));
        }
        let held_total = self.active_held_units_at(input.finalized_at_ms)?;
        if usage_total > held_total {
            return Err(ManagedWorkBillingError::new(
                "billing_final_debit_exceeds_hold",
                "FinalDebit cannot exceed held Work Credits",
            ));
        }
        let mut record = FinalDebit {
            final_debit_ref: input.final_debit_ref,
            body_hash: String::new(),
            quote_ref: input.quote_ref,
            usage_head_hash: input.usage_head_hash,
            usage_record_refs: self
                .usage_records
                .iter()
                .map(|record| record.usage_ref.clone())
                .collect(),
            hold_refs: self
                .holds
                .iter()
                .filter(|record| {
                    record.status == HoldStatus::Active
                        && record.created_at_ms <= input.finalized_at_ms
                        && input.finalized_at_ms < record.expires_at_ms
                })
                .map(|record| record.hold_ref.clone())
                .collect(),
            debited_work_credits: WorkCreditAmount::micro(usage_total),
            finalized_at_ms: input.finalized_at_ms,
        };
        record.body_hash = canonical_record_body_hash(&record)?;
        Ok(ManagedWorkBillingRecord::FinalDebit(record))
    }

    fn apply_adjustment(
        &self,
        context: &OwnerResolvedBillingContext,
        input: BillingAdjustmentInput,
    ) -> Result<ManagedWorkBillingRecord, ManagedWorkBillingError> {
        let final_debit = self.final_debit.as_ref().ok_or_else(|| {
            ManagedWorkBillingError::new(
                "billing_final_debit_missing",
                "BillingAdjustment requires FinalDebit",
            )
        })?;
        require_ref("adjustment_ref", &input.adjustment_ref)?;
        require_exact_ref(
            "final_debit_ref",
            &input.final_debit_ref,
            &final_debit.final_debit_ref,
        )?;
        require_safe("adjustment.created_at_ms", input.created_at_ms)?;
        if input.created_at_ms < final_debit.finalized_at_ms
            || input.created_at_ms > context.observed_at_ms
        {
            return Err(ManagedWorkBillingError::new(
                "billing_adjustment_time_invalid",
                "BillingAdjustment must follow FinalDebit and be owner-observed",
            ));
        }
        require_positive_safe("adjustment.amount", input.amount_work_credit_units)?;
        require_nonempty("reason_code", &input.reason_code)?;
        require_nonempty_refs("adjustment.evidence_refs", &input.evidence_refs)?;
        validate_unique_refs("adjustment.evidence_refs", &input.evidence_refs)?;
        let expected_head = self
            .adjustments
            .last()
            .map(|record| record.body_hash.as_str());
        if input.previous_adjustment_hash.as_deref() != expected_head {
            return Err(ManagedWorkBillingError::new(
                "billing_adjustment_head_conflict",
                "BillingAdjustment does not bind the current adjustment head",
            ));
        }
        if self
            .adjustments
            .iter()
            .any(|record| record.adjustment_ref == input.adjustment_ref)
        {
            return Err(ManagedWorkBillingError::new(
                "billing_adjustment_ref_conflict",
                "BillingAdjustment ref already exists",
            ));
        }
        let prior = checked_sum(
            self.adjustments.iter().map(|record| record.amount.units),
            "billing_adjustment_total_overflow",
        )?;
        let adjusted = checked_add(
            prior,
            input.amount_work_credit_units,
            "billing_adjustment_total_overflow",
        )?;
        if adjusted > final_debit.debited_work_credits.units {
            return Err(ManagedWorkBillingError::new(
                "billing_adjustment_exceeds_debit",
                "cumulative refund/writeoff cannot exceed FinalDebit",
            ));
        }
        let mut record = BillingAdjustment {
            adjustment_ref: input.adjustment_ref,
            body_hash: String::new(),
            final_debit_ref: input.final_debit_ref,
            previous_adjustment_hash: input.previous_adjustment_hash,
            adjustment_kind: input.adjustment_kind,
            amount: WorkCreditAmount::micro(input.amount_work_credit_units),
            reason_code: input.reason_code,
            evidence_refs: input.evidence_refs,
            created_at_ms: input.created_at_ms,
        };
        record.body_hash = canonical_record_body_hash(&record)?;
        Ok(ManagedWorkBillingRecord::Adjustment(record))
    }

    fn active_held_units_at(&self, occurred_at_ms: u64) -> Result<u64, ManagedWorkBillingError> {
        checked_sum(
            self.holds
                .iter()
                .filter(|hold| {
                    hold.status == HoldStatus::Active
                        && hold.created_at_ms <= occurred_at_ms
                        && occurred_at_ms < hold.expires_at_ms
                })
                .map(|hold| hold.amount.units),
            "billing_hold_total_overflow",
        )
    }

    fn append_record(
        &mut self,
        context: &OwnerResolvedBillingContext,
        command_hash: String,
        record: ManagedWorkBillingRecord,
    ) -> Result<ManagedWorkBillingLedgerEntry, ManagedWorkBillingError> {
        let sequence = u64::try_from(self.entries.len())
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| {
                ManagedWorkBillingError::new(
                    "billing_ledger_sequence_overflow",
                    "ledger sequence overflow",
                )
            })?;
        require_safe("ledger.sequence", sequence)?;
        let previous_entry_hash = self.entries.last().map(|entry| entry.entry_hash.clone());
        let body_hash = record.body_hash().to_string();
        let entry_ref = format!(
            "ledger-entry://managed-work/{sequence}/{}",
            body_hash.trim_start_matches("sha256:")
        );
        let mut entry = ManagedWorkBillingLedgerEntry {
            sequence,
            entry_ref,
            billing_account_ref: context.billing_account_ref.clone(),
            work_ref: context.work_ref.clone(),
            idempotency_key: context.idempotency_key.clone(),
            command_hash,
            previous_entry_hash,
            record_body_hash: body_hash,
            record,
            entry_hash: String::new(),
        };
        entry.entry_hash = canonical_record_body_hash(&entry)?;
        self.absorb_record(entry.record.clone())?;
        self.entries.push(entry.clone());
        Ok(entry)
    }

    fn verify_and_absorb_entry(
        &mut self,
        entry: ManagedWorkBillingLedgerEntry,
    ) -> Result<(), ManagedWorkBillingError> {
        let expected_sequence = u64::try_from(self.entries.len())
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| {
                ManagedWorkBillingError::new(
                    "billing_ledger_sequence_overflow",
                    "ledger sequence overflow",
                )
            })?;
        if entry.sequence != expected_sequence
            || entry.previous_entry_hash.as_deref() != self.current_ledger_head_hash()
        {
            return Err(ManagedWorkBillingError::new(
                "billing_ledger_chain_conflict",
                "ledger sequence or previous-entry hash is discontinuous",
            ));
        }
        require_hash("command_hash", &entry.command_hash)?;
        let expected_record_hash = canonical_managed_record_body_hash(&entry.record)?;
        if entry.record_body_hash != expected_record_hash
            || entry.record.body_hash() != expected_record_hash
        {
            return Err(ManagedWorkBillingError::new(
                "billing_record_body_hash_mismatch",
                "record body hash does not match canonical record bytes",
            ));
        }
        let expected_entry_hash = canonical_record_body_hash(&entry)?;
        if entry.entry_hash != expected_entry_hash {
            return Err(ManagedWorkBillingError::new(
                "billing_ledger_entry_hash_mismatch",
                "ledger entry hash does not match canonical entry bytes",
            ));
        }
        if let Some(existing) = self
            .entries
            .iter()
            .find(|candidate| candidate.idempotency_key == entry.idempotency_key)
        {
            if existing.command_hash != entry.command_hash {
                return Err(ManagedWorkBillingError::new(
                    "billing_idempotency_conflict",
                    "durable ledger reuses an idempotency key for different command bytes",
                ));
            }
            return Err(ManagedWorkBillingError::new(
                "billing_duplicate_ledger_entry",
                "durable ledger duplicates an already admitted idempotency key",
            ));
        }
        let context = OwnerResolvedBillingContext {
            billing_account_ref: entry.billing_account_ref.clone(),
            work_ref: entry.work_ref.clone(),
            authority_ref: "authority://durable-replay".to_string(),
            owner_evidence_refs: vec!["ledger://durable-replay".to_string()],
            idempotency_key: entry.idempotency_key.clone(),
            observed_at_ms: 0,
        };
        self.bind_ledger_identity(&context)?;
        self.absorb_record(entry.record.clone())?;
        self.entries.push(entry);
        Ok(())
    }

    fn absorb_record(
        &mut self,
        record: ManagedWorkBillingRecord,
    ) -> Result<(), ManagedWorkBillingError> {
        if self
            .entries
            .iter()
            .any(|entry| entry.record.record_ref() == record.record_ref())
        {
            return Err(ManagedWorkBillingError::new(
                "billing_record_ref_conflict",
                "billing record ref already exists",
            ));
        }
        match record {
            ManagedWorkBillingRecord::RateCard(record) => {
                if self.rate_card.is_some() || !self.entries.is_empty() {
                    return Err(ManagedWorkBillingError::new(
                        "billing_replay_transition_invalid",
                        "RateCard must be the first and only RateCard",
                    ));
                }
                self.rate_card = Some(record);
            }
            ManagedWorkBillingRecord::Plan(record) => {
                let rate = self.rate_card.as_ref().ok_or_else(|| {
                    ManagedWorkBillingError::new(
                        "billing_replay_transition_invalid",
                        "Plan precedes RateCard",
                    )
                })?;
                require_exact_binding(
                    "rate_card",
                    &record.rate_card_ref,
                    &record.rate_card_body_hash,
                    &rate.rate_card_ref,
                    &rate.body_hash,
                )?;
                if self.plan.is_some() {
                    return Err(ManagedWorkBillingError::new(
                        "billing_replay_transition_invalid",
                        "duplicate Plan",
                    ));
                }
                self.plan = Some(record);
            }
            ManagedWorkBillingRecord::WorkQuote(record) => {
                let rate = self.rate_card.as_ref().ok_or_else(|| {
                    ManagedWorkBillingError::new(
                        "billing_replay_transition_invalid",
                        "WorkQuote precedes RateCard",
                    )
                })?;
                let plan = self.plan.as_ref().ok_or_else(|| {
                    ManagedWorkBillingError::new(
                        "billing_replay_transition_invalid",
                        "WorkQuote precedes Plan",
                    )
                })?;
                require_exact_binding(
                    "rate_card",
                    &record.rate_card_ref,
                    &record.rate_card_body_hash,
                    &rate.rate_card_ref,
                    &rate.body_hash,
                )?;
                require_exact_binding(
                    "plan",
                    &record.plan_ref,
                    &record.plan_body_hash,
                    &plan.plan_ref,
                    &plan.body_hash,
                )?;
                if self.quote.is_some() {
                    return Err(ManagedWorkBillingError::new(
                        "billing_replay_transition_invalid",
                        "duplicate WorkQuote",
                    ));
                }
                self.quote = Some(record);
            }
            ManagedWorkBillingRecord::CreditHold(record) => {
                let quote = self.quote.as_ref().ok_or_else(|| {
                    ManagedWorkBillingError::new(
                        "billing_replay_transition_invalid",
                        "CreditHold precedes WorkQuote",
                    )
                })?;
                require_exact_ref("quote_ref", &record.quote_ref, &quote.quote_ref)?;
                if record.hold_kind == HoldKind::Initial && !self.holds.is_empty() {
                    return Err(ManagedWorkBillingError::new(
                        "billing_replay_transition_invalid",
                        "duplicate or late initial CreditHold",
                    ));
                }
                if record.hold_kind == HoldKind::ExactAdditional {
                    let decision_ref = record.overrun_decision_ref.as_deref().ok_or_else(|| {
                        ManagedWorkBillingError::new(
                            "billing_replay_transition_invalid",
                            "additional CreditHold lacks OverrunDecision",
                        )
                    })?;
                    let decision = self
                        .overrun_decisions
                        .iter()
                        .find(|decision| decision.overrun_decision_ref == decision_ref)
                        .ok_or_else(|| {
                            ManagedWorkBillingError::new(
                                "billing_replay_transition_invalid",
                                "additional CreditHold precedes OverrunDecision",
                            )
                        })?;
                    if decision.additional_hold_amount != record.amount {
                        return Err(ManagedWorkBillingError::new(
                            "billing_replay_transition_invalid",
                            "additional CreditHold amount differs from OverrunDecision",
                        ));
                    }
                }
                self.holds.push(record);
            }
            ManagedWorkBillingRecord::UsageRecord(record) => {
                if self.final_debit.is_some()
                    || record.sequence != self.usage_records.len() as u64 + 1
                    || record.previous_usage_hash.as_deref() != self.current_usage_head_hash()
                {
                    return Err(ManagedWorkBillingError::new(
                        "billing_replay_transition_invalid",
                        "UsageRecord order/head is invalid or follows FinalDebit",
                    ));
                }
                self.usage_records.push(record);
            }
            ManagedWorkBillingRecord::OverrunDecision(record) => {
                if self.final_debit.is_some()
                    || record.usage_head_hash.as_deref() != self.current_usage_head_hash()
                {
                    return Err(ManagedWorkBillingError::new(
                        "billing_replay_transition_invalid",
                        "OverrunDecision usage head is invalid or follows FinalDebit",
                    ));
                }
                self.overrun_decisions.push(record);
            }
            ManagedWorkBillingRecord::FinalDebit(record) => {
                if self.final_debit.is_some()
                    || record.usage_head_hash.as_deref() != self.current_usage_head_hash()
                {
                    return Err(ManagedWorkBillingError::new(
                        "billing_replay_transition_invalid",
                        "FinalDebit is duplicated or binds a stale usage head",
                    ));
                }
                self.final_debit = Some(record);
            }
            ManagedWorkBillingRecord::Adjustment(record) => {
                let debit = self.final_debit.as_ref().ok_or_else(|| {
                    ManagedWorkBillingError::new(
                        "billing_replay_transition_invalid",
                        "BillingAdjustment precedes FinalDebit",
                    )
                })?;
                if record.final_debit_ref != debit.final_debit_ref
                    || record.previous_adjustment_hash.as_deref()
                        != self
                            .adjustments
                            .last()
                            .map(|value| value.body_hash.as_str())
                {
                    return Err(ManagedWorkBillingError::new(
                        "billing_replay_transition_invalid",
                        "BillingAdjustment debit/head binding is invalid",
                    ));
                }
                let prior = checked_sum(
                    self.adjustments.iter().map(|value| value.amount.units),
                    "billing_adjustment_total_overflow",
                )?;
                let total = checked_add(
                    prior,
                    record.amount.units,
                    "billing_adjustment_total_overflow",
                )?;
                if total > debit.debited_work_credits.units {
                    return Err(ManagedWorkBillingError::new(
                        "billing_adjustment_exceeds_debit",
                        "durable adjustments exceed FinalDebit",
                    ));
                }
                self.adjustments.push(record);
            }
        }
        Ok(())
    }
}

/// Process-local serialized, fsync-backed JSONL store. It is intentionally not
/// wired to a public daemon route: callers must first resolve authority and
/// runtime/supplier evidence in their owning plane.
pub struct ManagedWorkBillingStore {
    root: PathBuf,
    lock: Mutex<()>,
}

impl ManagedWorkBillingStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            lock: Mutex::new(()),
        }
    }

    pub fn apply_owner_resolved(
        &self,
        command: ManagedWorkBillingCommand,
    ) -> Result<ManagedWorkBillingApplyOutcome, ManagedWorkBillingError> {
        let _guard = self.lock.lock().map_err(|_| {
            ManagedWorkBillingError::new(
                "billing_store_lock_poisoned",
                "managed-work billing store lock is poisoned",
            )
        })?;
        let context = command.context().clone();
        let path = self.ledger_path(&context.billing_account_ref, &context.work_ref)?;
        let mut ledger = self.load_path(&path)?;
        let outcome = ledger.apply(command)?;
        if outcome.replayed {
            return Ok(outcome);
        }
        fs::create_dir_all(&self.root).map_err(|error| {
            ManagedWorkBillingError::new(
                "billing_store_create_failed",
                format!("could not create billing store: {error}"),
            )
        })?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|error| {
                ManagedWorkBillingError::new(
                    "billing_store_open_failed",
                    format!("could not open billing ledger: {error}"),
                )
            })?;
        let encoded = serde_json::to_vec(&outcome.entry).map_err(|error| {
            ManagedWorkBillingError::new(
                "billing_store_encode_failed",
                format!("could not encode billing entry: {error}"),
            )
        })?;
        file.write_all(&encoded)
            .and_then(|_| file.write_all(b"\n"))
            .and_then(|_| file.sync_data())
            .map_err(|error| {
                ManagedWorkBillingError::new(
                    "billing_store_append_failed",
                    format!("could not durably append billing entry: {error}"),
                )
            })?;
        Ok(outcome)
    }

    pub fn load(
        &self,
        billing_account_ref: &str,
        work_ref: &str,
    ) -> Result<ManagedWorkBillingLedger, ManagedWorkBillingError> {
        let _guard = self.lock.lock().map_err(|_| {
            ManagedWorkBillingError::new(
                "billing_store_lock_poisoned",
                "managed-work billing store lock is poisoned",
            )
        })?;
        let path = self.ledger_path(billing_account_ref, work_ref)?;
        self.load_path(&path)
    }

    fn ledger_path(
        &self,
        billing_account_ref: &str,
        work_ref: &str,
    ) -> Result<PathBuf, ManagedWorkBillingError> {
        require_ref("billing_account_ref", billing_account_ref)?;
        require_ref("work_ref", work_ref)?;
        let name = canonical_hash(&json!({
            "billing_account_ref": billing_account_ref,
            "work_ref": work_ref,
        }))?;
        Ok(self.root.join(format!(
            "managed-work-{}.jsonl",
            name.trim_start_matches("sha256:")
        )))
    }

    fn load_path(&self, path: &Path) -> Result<ManagedWorkBillingLedger, ManagedWorkBillingError> {
        if !path.exists() {
            return Ok(ManagedWorkBillingLedger::default());
        }
        let file = fs::File::open(path).map_err(|error| {
            ManagedWorkBillingError::new(
                "billing_store_open_failed",
                format!("could not read billing ledger: {error}"),
            )
        })?;
        let mut entries = Vec::new();
        for (index, line) in BufReader::new(file).lines().enumerate() {
            let line = line.map_err(|error| {
                ManagedWorkBillingError::new(
                    "billing_store_read_failed",
                    format!("could not read billing ledger line {}: {error}", index + 1),
                )
            })?;
            if line.trim().is_empty() {
                continue;
            }
            let entry =
                serde_json::from_str::<ManagedWorkBillingLedgerEntry>(&line).map_err(|error| {
                    ManagedWorkBillingError::new(
                        "billing_store_decode_failed",
                        format!("invalid billing ledger line {}: {error}", index + 1),
                    )
                })?;
            entries.push(entry);
        }
        ManagedWorkBillingLedger::replay(entries)
    }
}

fn canonical_hash<T: Serialize>(value: &T) -> Result<String, ManagedWorkBillingError> {
    let bytes = serde_jcs::to_vec(value).map_err(|error| {
        ManagedWorkBillingError::new(
            "billing_canonicalization_failed",
            format!("billing value cannot be canonically encoded: {error}"),
        )
    })?;
    let mut hash = Sha256::new();
    hash.update(bytes);
    Ok(format!("sha256:{:x}", hash.finalize()))
}

fn canonical_record_body_hash<T: Serialize>(record: &T) -> Result<String, ManagedWorkBillingError> {
    let mut value = serde_json::to_value(record).map_err(|error| {
        ManagedWorkBillingError::new(
            "billing_canonicalization_failed",
            format!("billing record cannot be represented: {error}"),
        )
    })?;
    let object = value.as_object_mut().ok_or_else(|| {
        ManagedWorkBillingError::new(
            "billing_canonicalization_failed",
            "billing record must be an object",
        )
    })?;
    object.remove("body_hash");
    object.remove("entry_hash");
    canonical_hash(&value)
}

fn canonical_managed_record_body_hash(
    record: &ManagedWorkBillingRecord,
) -> Result<String, ManagedWorkBillingError> {
    match record {
        ManagedWorkBillingRecord::RateCard(value) => canonical_record_body_hash(value),
        ManagedWorkBillingRecord::Plan(value) => canonical_record_body_hash(value),
        ManagedWorkBillingRecord::WorkQuote(value) => canonical_record_body_hash(value),
        ManagedWorkBillingRecord::CreditHold(value) => canonical_record_body_hash(value),
        ManagedWorkBillingRecord::UsageRecord(value) => canonical_record_body_hash(value),
        ManagedWorkBillingRecord::OverrunDecision(value) => canonical_record_body_hash(value),
        ManagedWorkBillingRecord::FinalDebit(value) => canonical_record_body_hash(value),
        ManagedWorkBillingRecord::Adjustment(value) => canonical_record_body_hash(value),
    }
}

fn validate_context(context: &OwnerResolvedBillingContext) -> Result<(), ManagedWorkBillingError> {
    require_ref("billing_account_ref", &context.billing_account_ref)?;
    require_ref("work_ref", &context.work_ref)?;
    require_ref("authority_ref", &context.authority_ref)?;
    require_nonempty("idempotency_key", &context.idempotency_key)?;
    require_nonempty_refs("owner_evidence_refs", &context.owner_evidence_refs)?;
    validate_unique_refs("owner_evidence_refs", &context.owner_evidence_refs)?;
    require_safe("observed_at_ms", context.observed_at_ms)
}

fn validate_window(
    name: &str,
    issued_at_ms: u64,
    expires_at_ms: u64,
    observed_at_ms: u64,
) -> Result<(), ManagedWorkBillingError> {
    require_safe(&format!("{name}.issued_at_ms"), issued_at_ms)?;
    require_positive_safe(&format!("{name}.expires_at_ms"), expires_at_ms)?;
    if issued_at_ms >= expires_at_ms {
        return Err(ManagedWorkBillingError::new(
            "billing_validity_window_invalid",
            format!("{name} validity interval is empty or reversed"),
        ));
    }
    if observed_at_ms < issued_at_ms || observed_at_ms >= expires_at_ms {
        return Err(ManagedWorkBillingError::new(
            "billing_object_expired_or_not_yet_valid",
            format!("{name} is not active at the owner-observed time"),
        ));
    }
    Ok(())
}

fn validate_currency(currency: &str) -> Result<(), ManagedWorkBillingError> {
    if currency.len() != 3 || !currency.bytes().all(|byte| byte.is_ascii_uppercase()) {
        return Err(ManagedWorkBillingError::new(
            "billing_currency_invalid",
            "currency code must be three uppercase ASCII letters",
        ));
    }
    Ok(())
}

fn validate_cost_breakdown(
    cost: &ManagedWorkCostBreakdown,
    currency: &str,
    posture: CommercialPosture,
    supplier_statement_refs: &[String],
) -> Result<(), ManagedWorkBillingError> {
    validate_currency(&cost.currency_code)?;
    if cost.currency_code != currency {
        return Err(ManagedWorkBillingError::new(
            "billing_cost_currency_conflict",
            "usage cost currency differs from the frozen RateCard",
        ));
    }
    let values = [
        cost.provider_cost_minor,
        cost.broker_fee_minor,
        cost.participant_cost_minor,
        cost.verifier_cost_minor,
        cost.ioi_fee_minor,
        cost.excluded_customer_borne_provider_cost_minor,
    ];
    for value in values {
        require_safe("cost_breakdown amount", value)?;
    }
    checked_sum(values, "billing_cost_breakdown_overflow")?;
    if posture.is_customer_borne() && cost.provider_cost_minor != 0 {
        return Err(ManagedWorkBillingError::new(
            "billing_customer_borne_provider_cost_charged",
            "BYOK/BYOA/customer-cloud/self-hosted/local usage must have zero managed provider cost",
        ));
    }
    match cost.supplier_reconciliation_state {
        SupplierReconciliationState::SupplierStatementReconciled
            if supplier_statement_refs.is_empty() =>
        {
            Err(ManagedWorkBillingError::new(
                "billing_supplier_statement_missing",
                "supplier-reconciled cost requires supplier-statement evidence",
            ))
        }
        SupplierReconciliationState::NotApplicable
            if cost.provider_cost_minor != 0 || !supplier_statement_refs.is_empty() =>
        {
            Err(ManagedWorkBillingError::new(
                "billing_supplier_reconciliation_misclassified",
                "not-applicable supplier reconciliation cannot carry managed provider cost or statements",
            ))
        }
        _ => Ok(()),
    }
}

fn zero_nonbillable_cost(currency: &str) -> ManagedWorkCostBreakdown {
    ManagedWorkCostBreakdown {
        currency_code: currency.to_string(),
        provider_cost_minor: 0,
        broker_fee_minor: 0,
        participant_cost_minor: 0,
        verifier_cost_minor: 0,
        ioi_fee_minor: 0,
        excluded_customer_borne_provider_cost_minor: 0,
        supplier_reconciliation_state: SupplierReconciliationState::NotApplicable,
    }
}

fn require_exact_binding(
    name: &str,
    actual_ref: &str,
    actual_hash: &str,
    expected_ref: &str,
    expected_hash: &str,
) -> Result<(), ManagedWorkBillingError> {
    require_hash(&format!("{name}_body_hash"), actual_hash)?;
    if actual_ref != expected_ref || actual_hash != expected_hash {
        return Err(ManagedWorkBillingError::new(
            "billing_exact_binding_conflict",
            format!("{name} ref/body hash differs from the frozen owner object"),
        ));
    }
    Ok(())
}

fn require_exact_ref(
    name: &str,
    actual: &str,
    expected: &str,
) -> Result<(), ManagedWorkBillingError> {
    require_ref(name, actual)?;
    if actual != expected {
        return Err(ManagedWorkBillingError::new(
            "billing_exact_ref_conflict",
            format!("{name} differs from the frozen billing chain"),
        ));
    }
    Ok(())
}

fn require_nonempty(name: &str, value: &str) -> Result<(), ManagedWorkBillingError> {
    if value.trim().is_empty() {
        Err(ManagedWorkBillingError::new(
            "billing_required_field_missing",
            format!("{name} is required"),
        ))
    } else {
        Ok(())
    }
}

fn require_ref(name: &str, value: &str) -> Result<(), ManagedWorkBillingError> {
    require_nonempty(name, value)?;
    let Some((scheme, tail)) = value.split_once("://") else {
        return Err(ManagedWorkBillingError::new(
            "billing_ref_invalid",
            format!("{name} must be a typed ref"),
        ));
    };
    if !scheme
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_lowercase)
        || tail.trim().is_empty()
        || !scheme.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"+.-".contains(&byte)
        })
    {
        return Err(ManagedWorkBillingError::new(
            "billing_ref_invalid",
            format!("{name} must be a typed lowercase-scheme ref"),
        ));
    }
    Ok(())
}

fn require_hash(name: &str, value: &str) -> Result<(), ManagedWorkBillingError> {
    let hash = value.strip_prefix("sha256:").ok_or_else(|| {
        ManagedWorkBillingError::new(
            "billing_hash_invalid",
            format!("{name} must be a sha256 hash"),
        )
    })?;
    if hash.len() != 64
        || !hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ManagedWorkBillingError::new(
            "billing_hash_invalid",
            format!("{name} must contain 64 hex characters"),
        ));
    }
    Ok(())
}

fn require_nonempty_refs(name: &str, values: &[String]) -> Result<(), ManagedWorkBillingError> {
    if values.is_empty() {
        return Err(ManagedWorkBillingError::new(
            "billing_evidence_missing",
            format!("{name} requires at least one owner-derived ref"),
        ));
    }
    for value in values {
        require_ref(name, value)?;
    }
    Ok(())
}

fn validate_unique_refs(name: &str, values: &[String]) -> Result<(), ManagedWorkBillingError> {
    for value in values {
        require_ref(name, value)?;
    }
    if values.iter().collect::<BTreeSet<_>>().len() != values.len() {
        return Err(ManagedWorkBillingError::new(
            "billing_duplicate_ref",
            format!("{name} contains duplicate refs"),
        ));
    }
    Ok(())
}

fn require_safe(name: &str, value: u64) -> Result<(), ManagedWorkBillingError> {
    if value > MAX_SAFE_FIXED_POINT_UNITS {
        Err(ManagedWorkBillingError::new(
            "billing_fixed_point_overflow",
            format!("{name} exceeds the portable fixed-point safe-integer ceiling"),
        ))
    } else {
        Ok(())
    }
}

fn require_positive_safe(name: &str, value: u64) -> Result<(), ManagedWorkBillingError> {
    require_safe(name, value)?;
    if value == 0 {
        Err(ManagedWorkBillingError::new(
            "billing_positive_amount_required",
            format!("{name} must be positive"),
        ))
    } else {
        Ok(())
    }
}

fn checked_add(left: u64, right: u64, code: &'static str) -> Result<u64, ManagedWorkBillingError> {
    let value = left
        .checked_add(right)
        .ok_or_else(|| ManagedWorkBillingError::new(code, "fixed-point addition overflowed u64"))?;
    require_safe("fixed-point sum", value).map_err(|_| {
        ManagedWorkBillingError::new(
            code,
            "fixed-point sum exceeds portable safe-integer ceiling",
        )
    })?;
    Ok(value)
}

fn checked_mul(left: u64, right: u64, code: &'static str) -> Result<u64, ManagedWorkBillingError> {
    let value = left.checked_mul(right).ok_or_else(|| {
        ManagedWorkBillingError::new(code, "fixed-point multiplication overflowed u64")
    })?;
    require_safe("fixed-point product", value).map_err(|_| {
        ManagedWorkBillingError::new(
            code,
            "fixed-point product exceeds portable safe-integer ceiling",
        )
    })?;
    Ok(value)
}

fn checked_sum(
    values: impl IntoIterator<Item = u64>,
    code: &'static str,
) -> Result<u64, ManagedWorkBillingError> {
    values
        .into_iter()
        .try_fold(0_u64, |sum, value| checked_add(sum, value, code))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(key: &str, observed_at_ms: u64) -> OwnerResolvedBillingContext {
        OwnerResolvedBillingContext {
            billing_account_ref: "billing-account://test".to_string(),
            work_ref: "work-run://test".to_string(),
            authority_ref: "authority://billing/test".to_string(),
            owner_evidence_refs: vec!["receipt://owner/test".to_string()],
            idempotency_key: key.to_string(),
            observed_at_ms,
        }
    }

    fn rate_card_input() -> RateCardInput {
        RateCardInput {
            rate_card_ref: "rate-card://managed-work/test/1".to_string(),
            version: 1,
            currency_code: "USD".to_string(),
            meter_rates: vec![
                MeterRate {
                    meter_class: "managed_model_block".to_string(),
                    work_credit_micro_units_per_meter_unit: 10,
                    charge_component: ChargeComponent::ManagedModel,
                },
                MeterRate {
                    meter_class: "coarse_ocu".to_string(),
                    work_credit_micro_units_per_meter_unit: 0,
                    charge_component: ChargeComponent::NonBillableTelemetry,
                },
            ],
            ioi_fee_policy_ref: "fee-basis://managed-work/test/1".to_string(),
            issued_at_ms: 1_000,
            expires_at_ms: 100_000,
        }
    }

    fn managed_cost(provider_cost_minor: u64) -> ManagedWorkCostBreakdown {
        ManagedWorkCostBreakdown {
            currency_code: "USD".to_string(),
            provider_cost_minor,
            broker_fee_minor: 1,
            participant_cost_minor: 2,
            verifier_cost_minor: 3,
            ioi_fee_minor: 4,
            excluded_customer_borne_provider_cost_minor: 0,
            supplier_reconciliation_state: SupplierReconciliationState::SupplierStatementReconciled,
        }
    }

    fn publish_rate_card(ledger: &mut ManagedWorkBillingLedger) -> RateCard {
        let outcome = ledger
            .apply(ManagedWorkBillingCommand::PublishRateCard {
                context: context("rate-card", 2_000),
                input: rate_card_input(),
            })
            .expect("rate card");
        match outcome.entry.record {
            ManagedWorkBillingRecord::RateCard(record) => record,
            other => panic!("expected rate card, got {other:?}"),
        }
    }

    fn publish_plan(ledger: &mut ManagedWorkBillingLedger, rate: &RateCard) -> ManagedWorkPlan {
        let outcome = ledger
            .apply(ManagedWorkBillingCommand::PublishPlan {
                context: context("plan", 3_000),
                input: PlanInput {
                    plan_ref: "plan://managed-work/test/1".to_string(),
                    version: 1,
                    rate_card_ref: rate.rate_card_ref.clone(),
                    rate_card_body_hash: rate.body_hash.clone(),
                    included_work_credit_units: 10_000,
                    reset_policy: ResetPolicy::MonthlyExpiring,
                    issued_at_ms: 1_000,
                    expires_at_ms: 90_000,
                },
            })
            .expect("plan");
        match outcome.entry.record {
            ManagedWorkBillingRecord::Plan(record) => record,
            other => panic!("expected plan, got {other:?}"),
        }
    }

    fn issue_quote(
        ledger: &mut ManagedWorkBillingLedger,
        rate: &RateCard,
        plan: &ManagedWorkPlan,
        policy: OverrunPolicy,
    ) -> WorkQuote {
        let outcome = ledger
            .apply(ManagedWorkBillingCommand::IssueQuote {
                context: context("quote", 4_000),
                input: WorkQuoteInput {
                    quote_ref: "quote://managed-work/test/1".to_string(),
                    rate_card_ref: rate.rate_card_ref.clone(),
                    rate_card_body_hash: rate.body_hash.clone(),
                    plan_ref: plan.plan_ref.clone(),
                    plan_body_hash: plan.body_hash.clone(),
                    estimated_work_credit_units: 100,
                    required_hold_work_credit_units: 100,
                    overrun_policy: policy,
                    max_attempt_count: 3,
                    allowed_commercial_postures: vec![
                        CommercialPosture::Managed,
                        CommercialPosture::CustomerByok,
                    ],
                    issued_at_ms: 2_000,
                    expires_at_ms: 80_000,
                },
            })
            .expect("quote");
        match outcome.entry.record {
            ManagedWorkBillingRecord::WorkQuote(record) => record,
            other => panic!("expected quote, got {other:?}"),
        }
    }

    fn place_initial_hold(ledger: &mut ManagedWorkBillingLedger, quote: &WorkQuote) -> CreditHold {
        let outcome = ledger
            .apply(ManagedWorkBillingCommand::PlaceHold {
                context: context("hold-initial", 5_000),
                input: CreditHoldInput {
                    hold_ref: "credit-hold://managed-work/test/initial".to_string(),
                    quote_ref: quote.quote_ref.clone(),
                    hold_kind: HoldKind::Initial,
                    overrun_decision_ref: None,
                    amount_work_credit_units: 100,
                    created_at_ms: 5_000,
                    expires_at_ms: 80_000,
                },
            })
            .expect("hold");
        match outcome.entry.record {
            ManagedWorkBillingRecord::CreditHold(record) => record,
            other => panic!("expected hold, got {other:?}"),
        }
    }

    fn setup(policy: OverrunPolicy) -> (ManagedWorkBillingLedger, WorkQuote) {
        let mut ledger = ManagedWorkBillingLedger::default();
        let rate = publish_rate_card(&mut ledger);
        let plan = publish_plan(&mut ledger, &rate);
        let quote = issue_quote(&mut ledger, &rate, &plan, policy);
        place_initial_hold(&mut ledger, &quote);
        (ledger, quote)
    }

    fn record_managed_usage(
        ledger: &mut ManagedWorkBillingLedger,
        quote: &WorkQuote,
        key: &str,
        usage_ref: &str,
        quantity: u64,
        occurred_at_ms: u64,
    ) -> Result<ManagedWorkBillingApplyOutcome, ManagedWorkBillingError> {
        ledger.apply(ManagedWorkBillingCommand::RecordUsage {
            context: context(key, occurred_at_ms + 1),
            input: UsageRecordInput {
                usage_ref: usage_ref.to_string(),
                quote_ref: quote.quote_ref.clone(),
                previous_usage_hash: ledger.current_usage_head_hash().map(str::to_string),
                runtime_receipt_refs: vec![format!("receipt://runtime/{key}")],
                supplier_statement_refs: vec![format!("supplier-statement://provider/{key}")],
                meter_class: "managed_model_block".to_string(),
                quantity_units: quantity,
                commercial_posture: CommercialPosture::Managed,
                cost_breakdown: managed_cost(5),
                coarse_ocu_projection: false,
                occurred_at_ms,
            },
        })
    }

    #[test]
    fn fixed_point_happy_path_exports_registered_bundle() {
        let (mut ledger, quote) = setup(OverrunPolicy::Block);
        record_managed_usage(
            &mut ledger,
            &quote,
            "usage-1",
            "usage://managed-work/test/1",
            8,
            6_000,
        )
        .expect("usage");
        let usage_head = ledger.current_usage_head_hash().map(str::to_string);
        ledger
            .apply(ManagedWorkBillingCommand::FinalizeDebit {
                context: context("final-debit", 7_000),
                input: FinalDebitInput {
                    final_debit_ref: "final-debit://managed-work/test/1".to_string(),
                    quote_ref: quote.quote_ref.clone(),
                    usage_head_hash: usage_head,
                    requested_debit_work_credit_units: 80,
                    finalized_at_ms: 7_000,
                },
            })
            .expect("debit");
        ledger
            .apply(ManagedWorkBillingCommand::ApplyAdjustment {
                context: context("refund-1", 8_000),
                input: BillingAdjustmentInput {
                    adjustment_ref: "billing-adjustment://managed-work/test/refund-1".to_string(),
                    final_debit_ref: "final-debit://managed-work/test/1".to_string(),
                    previous_adjustment_hash: None,
                    adjustment_kind: AdjustmentKind::Refund,
                    amount_work_credit_units: 10,
                    reason_code: "supplier_credit".to_string(),
                    evidence_refs: vec!["supplier-statement://provider/credit-1".to_string()],
                    created_at_ms: 8_000,
                },
            })
            .expect("refund");

        let bundle = ledger
            .export_bundle("billing-bundle://managed-work/test/1", 9_000)
            .expect("contract-valid bundle");
        assert_eq!(bundle["final_debit"]["debited_work_credits"]["units"], 80);
        assert_eq!(bundle["adjustments"][0]["amount"]["units"], 10);
        assert_eq!(bundle["assurance_status"], "supplier_reconciled");
    }

    #[test]
    fn same_key_same_body_replays_and_changed_body_conflicts() {
        let mut ledger = ManagedWorkBillingLedger::default();
        let command = ManagedWorkBillingCommand::PublishRateCard {
            context: context("same-key", 2_000),
            input: rate_card_input(),
        };
        let first = ledger.apply(command.clone()).expect("first");
        let replay = ledger.apply(command).expect("replay");
        assert!(replay.replayed);
        assert_eq!(first.entry, replay.entry);
        assert_eq!(ledger.entries().len(), 1);

        let mut changed_input = rate_card_input();
        changed_input.version = 2;
        let error = ledger
            .apply(ManagedWorkBillingCommand::PublishRateCard {
                context: context("same-key", 2_000),
                input: changed_input,
            })
            .expect_err("changed body must conflict");
        assert_eq!(error.code, "billing_idempotency_conflict");
    }

    #[test]
    fn expired_rate_card_plan_and_quote_fail_closed() {
        let mut ledger = ManagedWorkBillingLedger::default();
        let error = ledger
            .apply(ManagedWorkBillingCommand::PublishRateCard {
                context: context("expired-rate", 100_000),
                input: rate_card_input(),
            })
            .expect_err("expired rate");
        assert_eq!(error.code, "billing_object_expired_or_not_yet_valid");

        let rate = publish_rate_card(&mut ledger);
        let mut plan_input = PlanInput {
            plan_ref: "plan://managed-work/expired".to_string(),
            version: 1,
            rate_card_ref: rate.rate_card_ref.clone(),
            rate_card_body_hash: rate.body_hash.clone(),
            included_work_credit_units: 100,
            reset_policy: ResetPolicy::MonthlyExpiring,
            issued_at_ms: 1_000,
            expires_at_ms: 2_000,
        };
        let error = ledger
            .apply(ManagedWorkBillingCommand::PublishPlan {
                context: context("expired-plan", 3_000),
                input: plan_input.clone(),
            })
            .expect_err("expired plan");
        assert_eq!(error.code, "billing_object_expired_or_not_yet_valid");
        plan_input.expires_at_ms = 90_000;
    }

    #[test]
    fn stale_usage_head_and_fixed_point_overflow_are_rejected() {
        let (mut ledger, quote) = setup(OverrunPolicy::Block);
        record_managed_usage(
            &mut ledger,
            &quote,
            "usage-1",
            "usage://managed-work/test/1",
            1,
            6_000,
        )
        .expect("usage");
        let error =
            ledger
                .apply(ManagedWorkBillingCommand::RecordUsage {
                    context: context("usage-stale", 6_101),
                    input: UsageRecordInput {
                        usage_ref: "usage://managed-work/test/stale".to_string(),
                        quote_ref: quote.quote_ref.clone(),
                        previous_usage_hash: None,
                        runtime_receipt_refs: vec!["receipt://runtime/stale".to_string()],
                        supplier_statement_refs: vec![
                            "supplier-statement://provider/stale".to_string()
                        ],
                        meter_class: "managed_model_block".to_string(),
                        quantity_units: 1,
                        commercial_posture: CommercialPosture::Managed,
                        cost_breakdown: managed_cost(1),
                        coarse_ocu_projection: false,
                        occurred_at_ms: 6_100,
                    },
                })
                .expect_err("stale head");
        assert_eq!(error.code, "billing_usage_head_conflict");

        let rate = ledger.rate_card.as_mut().expect("rate");
        rate.meter_rates[0].work_credit_micro_units_per_meter_unit = MAX_SAFE_FIXED_POINT_UNITS;
        let error = record_managed_usage(
            &mut ledger,
            &quote,
            "usage-overflow",
            "usage://managed-work/test/overflow",
            2,
            6_200,
        )
        .expect_err("overflow");
        assert_eq!(error.code, "billing_rate_multiplication_overflow");
    }

    #[test]
    fn exact_overrun_requires_decision_and_matching_additional_hold() {
        let (mut ledger, quote) = setup(OverrunPolicy::ExactAdditionalHold);
        record_managed_usage(
            &mut ledger,
            &quote,
            "usage-1",
            "usage://managed-work/test/1",
            8,
            6_000,
        )
        .expect("usage");
        let error = record_managed_usage(
            &mut ledger,
            &quote,
            "usage-over",
            "usage://managed-work/test/2",
            4,
            6_100,
        )
        .expect_err("overrun needs hold");
        assert_eq!(error.code, "billing_overrun_decision_required");

        let head = ledger.current_usage_head_hash().map(str::to_string);
        let error = ledger
            .apply(ManagedWorkBillingCommand::DecideOverrun {
                context: context("overrun-wrong", 6_200),
                input: OverrunDecisionInput {
                    overrun_decision_ref: "overrun-decision://managed-work/test/wrong".to_string(),
                    quote_ref: quote.quote_ref.clone(),
                    usage_head_hash: head.clone(),
                    projected_work_credit_units: 120,
                    action: OverrunAction::ExactAdditionalHold,
                    requested_additional_hold_work_credit_units: 21,
                    created_at_ms: 6_200,
                },
            })
            .expect_err("hold must be exact");
        assert_eq!(error.code, "billing_overrun_hold_not_exact");

        ledger
            .apply(ManagedWorkBillingCommand::DecideOverrun {
                context: context("overrun", 6_200),
                input: OverrunDecisionInput {
                    overrun_decision_ref: "overrun-decision://managed-work/test/1".to_string(),
                    quote_ref: quote.quote_ref.clone(),
                    usage_head_hash: head,
                    projected_work_credit_units: 120,
                    action: OverrunAction::ExactAdditionalHold,
                    requested_additional_hold_work_credit_units: 20,
                    created_at_ms: 6_200,
                },
            })
            .expect("decision");
        let error = ledger
            .apply(ManagedWorkBillingCommand::PlaceHold {
                context: context("additional-wrong", 6_300),
                input: CreditHoldInput {
                    hold_ref: "credit-hold://managed-work/test/additional-wrong".to_string(),
                    quote_ref: quote.quote_ref.clone(),
                    hold_kind: HoldKind::ExactAdditional,
                    overrun_decision_ref: Some(
                        "overrun-decision://managed-work/test/1".to_string(),
                    ),
                    amount_work_credit_units: 19,
                    created_at_ms: 6_300,
                    expires_at_ms: 80_000,
                },
            })
            .expect_err("additional hold exact");
        assert_eq!(error.code, "billing_additional_hold_not_exact");
        ledger
            .apply(ManagedWorkBillingCommand::PlaceHold {
                context: context("additional", 6_300),
                input: CreditHoldInput {
                    hold_ref: "credit-hold://managed-work/test/additional-1".to_string(),
                    quote_ref: quote.quote_ref.clone(),
                    hold_kind: HoldKind::ExactAdditional,
                    overrun_decision_ref: Some(
                        "overrun-decision://managed-work/test/1".to_string(),
                    ),
                    amount_work_credit_units: 20,
                    created_at_ms: 6_300,
                    expires_at_ms: 80_000,
                },
            })
            .expect("additional hold");
        record_managed_usage(
            &mut ledger,
            &quote,
            "usage-2",
            "usage://managed-work/test/2",
            4,
            6_400,
        )
        .expect("usage after hold");
        assert_eq!(ledger.total_usage_work_credit_units().unwrap(), 120);
    }

    #[test]
    fn quote_block_policy_records_block_and_never_mints_hold() {
        let (mut ledger, quote) = setup(OverrunPolicy::Block);
        record_managed_usage(
            &mut ledger,
            &quote,
            "usage-1",
            "usage://managed-work/test/1",
            10,
            6_000,
        )
        .expect("usage");
        let head = ledger.current_usage_head_hash().map(str::to_string);
        ledger
            .apply(ManagedWorkBillingCommand::DecideOverrun {
                context: context("block", 6_100),
                input: OverrunDecisionInput {
                    overrun_decision_ref: "overrun-decision://managed-work/test/block".to_string(),
                    quote_ref: quote.quote_ref.clone(),
                    usage_head_hash: head,
                    projected_work_credit_units: 110,
                    action: OverrunAction::Block,
                    requested_additional_hold_work_credit_units: 0,
                    created_at_ms: 6_100,
                },
            })
            .expect("block");
        let error = record_managed_usage(
            &mut ledger,
            &quote,
            "usage-blocked",
            "usage://managed-work/test/blocked",
            1,
            6_200,
        )
        .expect_err("held cap remains");
        assert_eq!(error.code, "billing_overrun_decision_required");
        assert_eq!(ledger.holds.len(), 1);
    }

    #[test]
    fn byok_provider_cost_and_coarse_ocu_billing_are_rejected() {
        let (mut ledger, quote) = setup(OverrunPolicy::Block);
        let error = ledger
            .apply(ManagedWorkBillingCommand::RecordUsage {
                context: context("byok", 6_001),
                input: UsageRecordInput {
                    usage_ref: "usage://managed-work/test/byok".to_string(),
                    quote_ref: quote.quote_ref.clone(),
                    previous_usage_hash: None,
                    runtime_receipt_refs: vec!["receipt://runtime/byok".to_string()],
                    supplier_statement_refs: vec![],
                    meter_class: "managed_model_block".to_string(),
                    quantity_units: 1,
                    commercial_posture: CommercialPosture::CustomerByok,
                    cost_breakdown: ManagedWorkCostBreakdown {
                        currency_code: "USD".to_string(),
                        provider_cost_minor: 1,
                        broker_fee_minor: 0,
                        participant_cost_minor: 0,
                        verifier_cost_minor: 0,
                        ioi_fee_minor: 0,
                        excluded_customer_borne_provider_cost_minor: 1,
                        supplier_reconciliation_state: SupplierReconciliationState::NotApplicable,
                    },
                    coarse_ocu_projection: false,
                    occurred_at_ms: 6_000,
                },
            })
            .expect_err("BYOK provider double charge");
        assert_eq!(error.code, "billing_customer_borne_provider_cost_charged");

        let error = ledger
            .apply(ManagedWorkBillingCommand::RecordUsage {
                context: context("coarse", 6_101),
                input: UsageRecordInput {
                    usage_ref: "usage://managed-work/test/coarse".to_string(),
                    quote_ref: quote.quote_ref,
                    previous_usage_hash: None,
                    runtime_receipt_refs: vec!["receipt://runtime/coarse".to_string()],
                    supplier_statement_refs: vec!["supplier-statement://fake".to_string()],
                    meter_class: "coarse_ocu".to_string(),
                    quantity_units: 1,
                    commercial_posture: CommercialPosture::Managed,
                    cost_breakdown: managed_cost(1),
                    coarse_ocu_projection: true,
                    occurred_at_ms: 6_100,
                },
            })
            .expect_err("coarse OCU supplier mint");
        assert_eq!(error.code, "billing_coarse_ocu_not_billable");
    }

    #[test]
    fn no_double_debit_or_over_refund_writeoff() {
        let (mut ledger, quote) = setup(OverrunPolicy::Block);
        record_managed_usage(
            &mut ledger,
            &quote,
            "usage-1",
            "usage://managed-work/test/1",
            5,
            6_000,
        )
        .expect("usage");
        let head = ledger.current_usage_head_hash().map(str::to_string);
        let debit = ManagedWorkBillingCommand::FinalizeDebit {
            context: context("debit", 7_000),
            input: FinalDebitInput {
                final_debit_ref: "final-debit://managed-work/test/1".to_string(),
                quote_ref: quote.quote_ref,
                usage_head_hash: head,
                requested_debit_work_credit_units: 50,
                finalized_at_ms: 7_000,
            },
        };
        ledger.apply(debit).expect("debit");
        let error = ledger
            .apply(ManagedWorkBillingCommand::FinalizeDebit {
                context: context("debit-2", 7_100),
                input: FinalDebitInput {
                    final_debit_ref: "final-debit://managed-work/test/2".to_string(),
                    quote_ref: "quote://managed-work/test/1".to_string(),
                    usage_head_hash: ledger.current_usage_head_hash().map(str::to_string),
                    requested_debit_work_credit_units: 50,
                    finalized_at_ms: 7_100,
                },
            })
            .expect_err("double debit");
        assert_eq!(error.code, "billing_final_debit_already_exists");

        ledger
            .apply(ManagedWorkBillingCommand::ApplyAdjustment {
                context: context("refund", 8_000),
                input: BillingAdjustmentInput {
                    adjustment_ref: "billing-adjustment://managed-work/test/refund".to_string(),
                    final_debit_ref: "final-debit://managed-work/test/1".to_string(),
                    previous_adjustment_hash: None,
                    adjustment_kind: AdjustmentKind::Refund,
                    amount_work_credit_units: 30,
                    reason_code: "supplier_credit".to_string(),
                    evidence_refs: vec!["supplier-statement://credit/refund".to_string()],
                    created_at_ms: 8_000,
                },
            })
            .expect("refund");
        let adjustment_head = ledger
            .adjustments
            .last()
            .map(|value| value.body_hash.clone());
        let error = ledger
            .apply(ManagedWorkBillingCommand::ApplyAdjustment {
                context: context("writeoff", 8_100),
                input: BillingAdjustmentInput {
                    adjustment_ref: "billing-adjustment://managed-work/test/writeoff".to_string(),
                    final_debit_ref: "final-debit://managed-work/test/1".to_string(),
                    previous_adjustment_hash: adjustment_head,
                    adjustment_kind: AdjustmentKind::Writeoff,
                    amount_work_credit_units: 21,
                    reason_code: "uncollectible".to_string(),
                    evidence_refs: vec!["decision://billing/writeoff".to_string()],
                    created_at_ms: 8_100,
                },
            })
            .expect_err("cumulative adjustment exceeds debit");
        assert_eq!(error.code, "billing_adjustment_exceeds_debit");
    }

    #[test]
    fn durable_store_replays_without_double_append_and_detects_body_conflict() {
        let directory = tempfile::tempdir().expect("tempdir");
        let store = ManagedWorkBillingStore::new(directory.path());
        let command = ManagedWorkBillingCommand::PublishRateCard {
            context: context("durable-rate", 2_000),
            input: rate_card_input(),
        };
        store
            .apply_owner_resolved(command.clone())
            .expect("durable append");
        let replay = store.apply_owner_resolved(command).expect("durable replay");
        assert!(replay.replayed);
        let loaded = store
            .load("billing-account://test", "work-run://test")
            .expect("load");
        assert_eq!(loaded.entries().len(), 1);

        let mut changed = rate_card_input();
        changed.currency_code = "EUR".to_string();
        let error = store
            .apply_owner_resolved(ManagedWorkBillingCommand::PublishRateCard {
                context: context("durable-rate", 2_000),
                input: changed,
            })
            .expect_err("durable changed-body conflict");
        assert_eq!(error.code, "billing_idempotency_conflict");
    }
}
