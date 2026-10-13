//! Honest compact and advanced M1 System read projections.
//!
//! Both views are rebuilt from the same verified admission and live-chain
//! owners. No projection record is persisted and presentation grants no
//! authority.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};

use super::system_activation_routes::{classify, required_string, verr, with_source_locks};
use super::DaemonState;

type VErr = (String, String);

// M08.9 — the compact row is canon's `HypervisorSystemsProjection`, registered and validated
// before it is served: the verified admission and live chain as before, the membership plane's
// projection (desired topology) and the writer plane's projection (observed) composed in as
// typed presence or typed absence, the seven contextual modes as routes, and the policy basis
// that admitted the row for THIS caller. Nothing here is persisted and nothing grants authority.
const SYSTEMS_PROJECTION_SCHEMA: &str = "ioi.hypervisor.systems-projection.v1";
const SYSTEMS_PROJECTION_CONTRACT_ID: &str =
    "schema://ioi/components/hypervisor/systems-projection/v1";
const SYSTEM_MODES: &[(&str, &str)] = &[
    ("overview", ""),
    ("design", "/design"),
    ("operate", "/operate"),
    ("govern", "/govern"),
    ("evidence", "/evidence"),
    ("improve", "/improve"),
    ("interfaces", "/interfaces"),
];

fn required(value: &Value, pointer: &str) -> Result<String, VErr> {
    required_string(value, pointer).map(str::to_owned)
}

/// A plane's projection as typed presence or typed absence — the refusal CODE a plane answers
/// with is the reason, never an invented topology and never a silent null.
fn plane_presence(result: Result<Value, VErr>) -> Value {
    match result {
        Ok(projection) => {
            json!({ "state": "present", "projection": projection, "reason": Value::Null })
        }
        Err((code, _)) => json!({ "state": "absent", "projection": Value::Null, "reason": code }),
    }
}

/// The seven contextual modes canon names, as routes under the System's canonical route. The
/// `serving` lane is null until the App binds a renderer to the mode — said, not assumed.
fn system_modes(system_id: &str) -> Vec<Value> {
    let tail = system_id.strip_prefix("system://").unwrap_or(system_id);
    SYSTEM_MODES
        .iter()
        .map(|(mode, segment)| {
            json!({ "mode": mode, "route": format!("/systems/{tail}{segment}"), "serving": Value::Null })
        })
        .collect()
}

/// Policy is decided per row from the request identity and the verified genesis record alone, two
/// ways. A System is visible to the principal that proposed its genesis, or to a caller holding the
/// tenant its admission names as owner (the admitting caller's one org:// tenant, stamped at
/// admission). Anything else is not in this caller's inventory — not hidden, not present — and a
/// principal who sees no System gets `honest_empty`, never a fabricated row.
///
/// HOLDING A RECORD UNDER A SYSTEM GRANTS NO SIGHT OF IT (R-240, System seam authority). A third
/// clause (R-186, S4c-1) made a System visible to any principal holding System-record seam scopes
/// under it; it was added when no genesis record named an owner, so the second clause matched no
/// one. Admission has stamped `owner_ref` since R-240 (2026-09-25), and the seam now admits a record
/// only from a principal who may WRITE under the System — who already holds the owner tenant, so
/// the clause admitted no legitimate reader the second one misses. What it did admit: a principal
/// that planted a record under someone else's System (the seam checked only that the System was
/// active), and a writer who has since left the owner tenant, whom the second clause deliberately
/// stops showing the System to. Records such a principal holds stay readable through the seam's own
/// scope reads; the System they sit under does not.
fn row_visible_to(
    record: &Value,
    identity: &super::substrate_store::RequestIdentity,
) -> Option<&'static str> {
    if record.get("proposed_by_ref").and_then(Value::as_str)
        == Some(identity.principal_ref.as_str())
    {
        return Some("proposed_by_ref == principal_ref");
    }
    if record
        .get("owner_ref")
        .and_then(Value::as_str)
        .is_some_and(|owner| identity.authorizes_tenant(owner))
    {
        return Some("owner_ref in tenant_refs");
    }
    None
}

/// WHO MAY WRITE UNDER A SYSTEM (R-240, System seam authority): the principal its admission names as
/// admitter, or an active administrator (`odk_routes::principal_is_active_admin`, the invite plane's
/// org-admin test) — in both cases only while the caller's session holds the owner tenant the
/// admission names. Seeing is not writing: a member of the owner tenant reads the System and writes
/// nothing under it, and a proposer ref grants sight, never authority. A System whose admission names
/// no owner (admitted before admission stamped one) has no writer at all — fail closed.
fn row_writable_by(
    record: &Value,
    identity: &super::substrate_store::RequestIdentity,
    caller_is_admin: impl FnOnce() -> bool,
) -> Option<&'static str> {
    let owner = record.get("owner_ref").and_then(Value::as_str)?;
    if !identity.authorizes_tenant(owner) {
        return None;
    }
    if record
        .get("admitted_by_principal_ref")
        .and_then(Value::as_str)
        == Some(identity.principal_ref.as_str())
    {
        return Some("admitted_by_principal_ref == principal_ref, owner_ref in tenant_refs");
    }
    if caller_is_admin() {
        return Some("active administrator, owner_ref in tenant_refs");
    }
    None
}

/// One caller's standing over one System. `Absent` is BOTH a System no admission answers to and one
/// outside the caller's inventory: a caller never learns which. `Sees` reads it; `Writes` may also
/// admit records under it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SystemStanding {
    Absent,
    Sees,
    Writes,
}

/// The standing an admission record (`None`: no admission answers) gives this caller: the row
/// policy for sight, then the write rule.
pub(crate) fn standing_over(
    data_dir: &str,
    record: Option<&Value>,
    identity: &super::substrate_store::RequestIdentity,
) -> SystemStanding {
    let Some(record) = record else {
        return SystemStanding::Absent;
    };
    if row_visible_to(record, identity).is_none() {
        return SystemStanding::Absent;
    }
    let admin = || super::odk_routes::principal_is_active_admin(data_dir, &identity.principal_ref);
    if row_writable_by(record, identity, admin).is_some() {
        SystemStanding::Writes
    } else {
        SystemStanding::Sees
    }
}

/// The verified genesis admission record answering to `system_id`, or `None` when none does. A
/// substrate that cannot answer is the typed error, never a guess.
pub(crate) fn admission_record(data_dir: &str, system_id: &str) -> Result<Option<Value>, VErr> {
    let key = super::system_genesis_routes::record_tail(system_id);
    let Some(admission) =
        super::system_genesis_routes::load_verified_admission_by_key(data_dir, &key)?
    else {
        return Ok(None);
    };
    if admission.record.get("system_id").and_then(Value::as_str) != Some(system_id) {
        return Ok(None);
    }
    Ok(Some(admission.record))
}

/// Whether ONE System is in this caller's inventory: `row_visible_to` over its verified genesis
/// admission — the policy every projection row passes (R-240 journey WP-B: a record that ties itself to
/// a System may name only a System its author can see). `Ok(false)` when no admission answers to the
/// id; a substrate that cannot answer is the typed error, never a guess.
pub(crate) fn system_in_inventory(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
    system_id: &str,
) -> Result<bool, VErr> {
    Ok(admission_record(data_dir, system_id)?
        .is_some_and(|record| row_visible_to(&record, identity).is_some()))
}

fn project_one(data_dir: &str, record: &Value, view: &str, policy: &Value) -> Result<Value, VErr> {
    let system_id = required(record, "/system_id")?;
    let key = super::system_genesis_routes::record_tail(&system_id);
    let admission = super::system_genesis_routes::load_verified_admission_by_key(data_dir, &key)?
        .ok_or_else(|| {
        verr(
            "system_projection_source_missing",
            "verified admission vanished",
        )
    })?;
    let (_, live) = super::system_amendment_routes::load_amendment_source(data_dir, &key)?;
    let canonical_roots = json!({
        "proposal_root":admission.record["proposal_root"],
        "admitted_manifest_root":admission.record["admitted_manifest_root"],
        "initial_profile_bundle_root":admission.record["initial_profile_bundle_root"],
        "active_profile_set_root":live.chain_head["active_profile_set_root"],
        "latest_state_root":live.chain_head["latest_state_root"],
        "operation_log_root":live.chain_head["operation_log_root"],
        "chain_root":live.chain_head["chain_root"],
    });
    let compact = json!({
        "system_id":system_id,
        "source_record_tail":key,
        "package_id":admission.record["package_id"],
        "manifest_ref":admission.record["manifest_ref"],
        "genesis_ref":admission.record["genesis_ref"],
        "constitution_ref":live.chain_head["constitution_ref"],
        "status":live.chain_head["status"],
        "latest_sequence":live.chain_head["latest_sequence"],
        "network_enrollment_ref":live.chain_head["network_enrollment_ref"],
        "canonical_roots":canonical_roots,
        "evidence_refs":{
            "genesis_admission_receipt_ref":admission.record["admission_receipt_ref"],
            "latest_receipt_ref":live.chain_head["latest_receipt_ref"],
            "operation_log_ref":live.chain_head["operation_log_ref"],
            "chain_ref":live.chain_head["chain_ref"]
        }
    });
    // THE ROW IS CANON'S SHAPE, VALIDATED BEFORE IT IS SERVED. The two plane projections are read
    // through their owners' own loaders and builders — never by this module opening their records —
    // and a plane that has nothing admitted for this System is a typed absence carrying that
    // plane's own refusal code, never a topology this module made up.
    let mut row = compact;
    row["schema_version"] = json!(SYSTEMS_PROJECTION_SCHEMA);
    row["projection_row_id"] = json!(format!("hypervisor_systems_projection:{system_id}"));
    row["topology"] = json!({
        "desired": plane_presence(
            super::system_membership_routes::load_membership_source(data_dir, &key).and_then(|source| {
                super::system_membership_routes::build_membership_projection(
                    &source.binding.system_id,
                    source.desired_topology.as_ref().zip(source.desired_topology_root.as_deref()),
                    &source.records,
                    &source.head,
                )
            }),
        ),
        "observed": plane_presence(
            super::system_writer_routes::load_writer_source(data_dir, &key).and_then(|source| {
                super::system_writer_routes::build_writer_projection(
                    &system_id,
                    &source.fence_head,
                    &source.lost_suffix_revisions,
                )
            }),
        ),
    });
    row["modes"] = Value::Array(system_modes(&system_id));
    row["policy_basis"] = policy.clone();
    row["source_projection_refs"] = json!([
        "verified_owner_reconstruction",
        "system_membership_projection",
        "system_writer_projection"
    ]);
    row["read_model_only"] = json!(true);
    ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
        SYSTEMS_PROJECTION_CONTRACT_ID,
        &row,
    )
    .map_err(|error| {
        verr(
            "system_projection_row_contract_invalid",
            format!(
                "the assembled row violates its registered contract and is NOT served: {error}"
            ),
        )
    })?;
    if view == "compact" {
        return Ok(row);
    }
    Ok(json!({
        "compact":row,
        "genesis_admission":admission.record,
        "genesis_admission_receipt":admission.receipt,
        "activation_effect":live.activation_effect,
        "latest_step":live.previous_step,
        "active_profile_set":live.predecessor_profile_set,
        "operation_log":live.operation_log,
        "chain_head":live.chain_head
    }))
}

/// GET /v1/hypervisor/autonomous-systems/projection?view=compact|advanced
pub(crate) async fn handle_get(
    State(state): State<Arc<DaemonState>>,
    headers: axum::http::HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> axum::response::Response {
    super::system_activation_routes::system_read_reply(
        handle_get_reply(State(state), headers, Query(query)).await,
    )
}

async fn handle_get_reply(
    State(state): State<Arc<DaemonState>>,
    headers: axum::http::HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    let view = query.get("view").map(String::as_str).unwrap_or("compact");
    if !matches!(view, "compact" | "advanced") {
        return classify(verr(
            "system_projection_view_invalid",
            "view must be exactly 'compact' or 'advanced'",
        ));
    }
    // POLICY BEFORE ROWS. The inventory is filtered by the request identity before any row is
    // built, counted or reported as `honest_empty`; an unresolvable caller is a typed refusal.
    let identity = match super::substrate_store::resolve_request_identity(&state.data_dir, &headers)
    {
        Ok(identity) => identity,
        Err(error) => return super::mutation_event_foundation::scope_refusal_reply(error),
    };
    // ONE STRICT PASS FOR THE WHOLE READ (R-240): every exact Agentgres read the rows make — the
    // verified admission, the live chain, the membership and writer planes, for every visible System —
    // is answered from one validated snapshot instead of one full-log pass each.
    // BUILD-DELTA #48: the read is synchronous and long (one strict pass over the whole Agentgres log
    // under the System source locks), so it runs on the blocking pool, never on an async worker.
    let data_dir = state.data_dir.clone();
    let view = view.to_string();
    let read = super::system_activation_routes::off_the_async_workers(state.system_reads.clone(), move || {
        super::substrate_store::with_exact_read_snapshot(&data_dir, || {
            with_source_locks(|| {
                let mut records = super::system_genesis_routes::scan_records(&data_dir)
                    .map_err(|message| verr("system_projection_source_unreadable", message))?;
                let mut substrate_records = super::substrate_store::read_required_all(
                    &data_dir,
                    super::system_genesis_routes::RECORD_DIR,
                )
                .map_err(|error| {
                    verr(
                        "system_projection_source_unreadable",
                        format!("Agentgres admission census failed ({error})"),
                    )
                })?;
                records.sort_by_key(|record| {
                    record
                        .get("system_id")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_owned()
                });
                substrate_records.sort_by_key(|record| {
                    record
                        .get("system_id")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_owned()
                });
                if substrate_records != records {
                    return Err(verr(
                        "system_projection_source_incomplete",
                        "local and Agentgres genesis admission censuses differ",
                    ));
                }
                if let Some(filter) = query.get("system_id") {
                    records.retain(|record| {
                        record.get("system_id").and_then(Value::as_str) == Some(filter.as_str())
                    });
                }
                let visible: Vec<(&Value, &'static str)> = records
                    .iter()
                    .filter_map(|record| {
                        row_visible_to(record, &identity).map(|filter| (record, filter))
                    })
                    .collect();
                let systems = visible
                    .iter()
                    .map(|(record, filter)| {
                        let policy =
                            json!({ "principal_ref": identity.principal_ref, "filter": filter });
                        project_one(&data_dir, record, &view, &policy)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok::<_, VErr>(json!({
                    "schema_version":"ioi.hypervisor.autonomous-system-read-projection.v1",
                    "row_schema_version": SYSTEMS_PROJECTION_SCHEMA,
                    "row_contract_id": SYSTEMS_PROJECTION_CONTRACT_ID,
                    "view":view,
                    "state":if systems.is_empty(){"honest_empty"}else{"ready"},
                    "systems":systems,
                    "policy":{"principal_ref": identity.principal_ref, "applied_before": ["rows", "state"], "admitted_rows": systems.len(), "inventory_rows": records.len()},
                    "projection_source":"verified_owner_reconstruction",
                    "nonclaims":{"authority":false,"mutation":false,"membership":false,"writer":false,"network_assurance":false,"runtime_effect":false,"persistence":false}
                }))
            })
        })
    })
    .await;
    match read.and_then(|answer| answer) {
        Ok(value) => (StatusCode::OK, Json(value)),
        Err(error) => classify(error),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    use super::super::substrate_store::{request_identity_for_test, RequestIdentity};
    use super::{row_visible_to, row_writable_by, standing_over, SystemStanding};

    /// A record shaped as genesis admission actually writes it: the proposal names a project://
    /// proposer and an org:// governing authority (neither is a person), and the admission names
    /// the signed-in caller that admitted it and that caller's one org:// tenant as owner.
    fn admitted() -> Value {
        json!({
            "system_id": "system://acme/outcome",
            "proposed_by_ref": "project://acme/outcome-operator",
            "governing_authority_ref": "org://acme/research",
            "admitted_by_principal_ref": "user://operator",
            "owner_ref": "org://local"
        })
    }

    #[test]
    fn an_admitted_system_is_visible_to_its_owner_tenant_and_to_nobody_else() {
        let admitted = admitted();
        let member = request_identity_for_test("user://colleague", ["org://local".to_string()]);
        assert_eq!(
            row_visible_to(&admitted, &member),
            Some("owner_ref in tenant_refs")
        );
        let outsider = request_identity_for_test("user://outsider", ["org://other".to_string()]);
        assert_eq!(row_visible_to(&admitted, &outsider), None);
        // Governing a System is not owning it: the constitution's authority is a portable ref,
        // not a tenant this daemon hosts, and holding a same-named tenant reads nothing.
        let governor =
            request_identity_for_test("user://governor", ["org://acme/research".to_string()]);
        assert_eq!(row_visible_to(&admitted, &governor), None);
        // The admitter who has since left the owner tenant no longer sees it.
        let departed = request_identity_for_test("user://operator", []);
        assert_eq!(row_visible_to(&admitted, &departed), None);
    }

    #[test]
    fn the_genesis_clauses_still_decide_first() {
        let identity = RequestIdentity::local_development_operator("user://alice");
        let proposed = json!({ "system_id": "system://x", "proposed_by_ref": "user://alice" });
        assert_eq!(
            row_visible_to(&proposed, &identity),
            Some("proposed_by_ref == principal_ref")
        );
    }

    /// The retired third clause, by name: a System that names no owner and a proposer that is not
    /// the caller is in nobody's inventory, however many seam records the caller holds under it. The
    /// row policy reads the genesis record and the identity and NOTHING ELSE — it has no parameter a
    /// record holding could reach it through (the seam test `a_record_planted_before_the_fix_grants_
    /// no_sight_of_the_system` drives the same through a real plant).
    #[test]
    fn holding_records_under_a_system_is_not_a_clause_of_the_row_policy() {
        let holder = request_identity_for_test("user://alice", ["org://other".to_string()]);
        let unowned = json!({ "system_id": "system://ioi/orchestration/demo", "proposed_by_ref": "project://ioi/orchestration" });
        assert_eq!(row_visible_to(&unowned, &holder), None);
        assert_eq!(row_visible_to(&admitted(), &holder), None);
    }

    #[test]
    fn only_the_admitter_or_an_administrator_holding_the_owner_tenant_writes_under_a_system() {
        let admitted = admitted();
        let never =
            || -> bool { panic!("the admin test is read only when the admitter test fails") };
        let admitter = request_identity_for_test("user://operator", ["org://local".to_string()]);
        assert_eq!(
            row_writable_by(&admitted, &admitter, never),
            Some("admitted_by_principal_ref == principal_ref, owner_ref in tenant_refs")
        );
        let member = request_identity_for_test("user://colleague", ["org://local".to_string()]);
        assert_eq!(
            row_writable_by(&admitted, &member, || false),
            None,
            "seeing is not writing"
        );
        assert_eq!(
            row_writable_by(&admitted, &member, || true),
            Some("active administrator, owner_ref in tenant_refs")
        );
        // Neither the admitter nor an administrator writes without the owner tenant in session.
        let departed = request_identity_for_test("user://operator", []);
        assert_eq!(row_writable_by(&admitted, &departed, || true), None);
        let foreign_admin = request_identity_for_test("user://root", ["org://other".to_string()]);
        assert_eq!(row_writable_by(&admitted, &foreign_admin, || true), None);
        // A System whose admission names no owner has no writer.
        let unowned = json!({ "system_id": "system://x", "proposed_by_ref": "user://alice" });
        let proposer = request_identity_for_test("user://alice", ["org://local".to_string()]);
        assert_eq!(row_writable_by(&unowned, &proposer, || true), None);
    }

    fn principal(data_dir: &str, principal_id: &str, role: &str, status: &str) {
        super::super::persist_record(
            data_dir,
            "principals",
            principal_id,
            &json!({ "principal_id": principal_id, "role": role, "status": status }),
        )
        .unwrap();
    }

    #[test]
    fn standing_reads_sight_first_then_the_write_rule_over_the_principal_registry() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().to_str().unwrap();
        principal(d, "operator", "member", "active");
        principal(d, "colleague", "member", "active");
        principal(d, "root", "admin", "active");
        principal(d, "former", "admin", "suspended");
        principal(d, "stranger", "admin", "active");
        let admitted = admitted();
        let local = |id: &str| {
            request_identity_for_test(&format!("user://{id}"), ["org://local".to_string()])
        };
        assert_eq!(
            standing_over(d, Some(&admitted), &local("operator")),
            SystemStanding::Writes
        );
        assert_eq!(
            standing_over(d, Some(&admitted), &local("root")),
            SystemStanding::Writes
        );
        assert_eq!(
            standing_over(d, Some(&admitted), &local("colleague")),
            SystemStanding::Sees
        );
        assert_eq!(
            standing_over(d, Some(&admitted), &local("former")),
            SystemStanding::Sees,
            "a suspended administrator administers nothing"
        );
        let stranger =
            request_identity_for_test("user://stranger", ["project://elsewhere".to_string()]);
        assert_eq!(
            standing_over(d, Some(&admitted), &stranger),
            SystemStanding::Absent,
            "an admin role is not a key to another org's Systems"
        );
        assert_eq!(
            standing_over(d, None, &local("root")),
            SystemStanding::Absent
        );
    }
}

/// BUILD-DELTA #48: a Systems projection read is long and synchronous (one strict pass over the
/// whole Agentgres log, under the System source locks); it must never hold an async worker that
/// every other request, identity resolution included, needs.
#[cfg(test)]
mod worker_starvation_tests {
    use std::collections::HashMap;
    use std::time::{Duration, Instant};

    use axum::extract::{Query, State};
    use axum::http::HeaderMap;
    use serde_json::json;

    /// A signed-in principal of the `org://local` tenant: its principal, membership and session
    /// records, and the bearer headers that present the session.
    fn signed_in(data_dir: &str) -> HeaderMap {
        super::super::persist_record(
            data_dir,
            "principals",
            "operator",
            &json!({ "schema_version": "ioi.hypervisor.principal.v1", "principal_id": "operator",
                     "email": "operator@example.test", "name": "operator", "role": "owner",
                     "status": "active", "source": "test",
                     "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z" }),
        )
        .unwrap();
        super::super::lifecycle_routes::apply_membership_transition(
            data_dir,
            "user://operator",
            "user://operator",
            "org://local",
            "organization",
            "active",
            0,
            "test-operator-org-local",
            "test membership",
            "deployment_bootstrap",
        )
        .unwrap();
        let token = "token-operator";
        super::super::persist_record(
            data_dir,
            "sessions",
            "session-operator",
            &json!({ "session_id": "session-operator", "token_hash": super::super::sha256_hex_str(token),
                     "principal_id": "operator", "source": "test",
                     "created_at": "2026-01-01T00:00:00Z", "expires_at": "9999-12-31T23:59:59Z" }),
        )
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        headers
    }

    /// With ONE async worker and a projection read made honestly slow (the Agentgres log grown
    /// through the store's own write path until one read takes at least a second, every calibration
    /// read succeeding), four parallel projection reads do not delay identity resolution
    /// (`/auth/whoami`): once the daemon acknowledges that a read has begun on the blocking pool (its
    /// admission count moves, not a sleep), five identity resolutions in a row each answer the
    /// signed-in principal (`authenticated: true`, principal `operator`) in under half a read, while
    /// a read is still in flight.
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn parallel_systems_projections_never_delay_identity_resolution() {
        use axum::response::IntoResponse;
        use std::sync::atomic::Ordering;
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().to_str().unwrap().to_string();
        let state = crate::test_daemon_state(&data_dir);
        let headers = signed_in(&data_dir);
        let (written, one_read) =
            calibrate(&state, &data_dir, &headers, Duration::from_secs(1)).await;
        eprintln!("load: {written} records, one projection read {one_read:?}");
        let begun = state.system_reads.started.load(Ordering::SeqCst);
        let reads: Vec<_> = (0..4)
            .map(|_| {
                let (state, headers) = (state.clone(), headers.clone());
                tokio::spawn(async move {
                    super::handle_get(State(state), headers, Query(HashMap::new()))
                        .await
                        .into_response()
                })
            })
            .collect();
        // THE ACKNOWLEDGED OVERLAP: a read has begun on the blocking pool.
        let deadline = Instant::now() + Duration::from_secs(30);
        while state.system_reads.started.load(Ordering::SeqCst) == begun {
            assert!(
                Instant::now() < deadline,
                "a projection read begins on the blocking pool"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let mut waits = Vec::new();
        for _ in 0..5 {
            let started = Instant::now();
            let whoami = tokio::spawn(super::super::lifecycle_routes::handle_auth_whoami(
                State(state.clone()),
                headers.clone(),
            ));
            let (status, body) = whoami.await.unwrap();
            waits.push(started.elapsed());
            assert!(
                status == axum::http::StatusCode::OK
                    && body.0["authenticated"] == json!(true)
                    && body.0["principal"]["principal_id"] == json!("operator"),
                "identity resolution answers the signed-in principal: {status} {}",
                body.0
            );
        }
        assert!(
            !reads.iter().all(|read| read.is_finished()),
            "a projection read is still in flight after the identity samples"
        );
        let worst = waits.iter().max().copied().unwrap_or_default();
        eprintln!(
            "identity resolution answered after at most {worst:?} over {} samples (one projection read {one_read:?})",
            waits.len()
        );
        assert!(
            worst < one_read / 2,
            "identity resolution waited {worst:?} behind projection reads that take {one_read:?} each"
        );
        for read in reads {
            assert_eq!(read.await.unwrap().status(), axum::http::StatusCode::OK);
        }
    }

    /// Grow the Agentgres log through the store's own write path until one projection read takes at
    /// least `at_least`; every calibration read must succeed. Returns (records, one read).
    async fn calibrate(
        state: &std::sync::Arc<super::DaemonState>,
        data_dir: &str,
        headers: &HeaderMap,
        at_least: Duration,
    ) -> (usize, Duration) {
        use axum::response::IntoResponse;
        let mut written = 0usize;
        let mut one_read = Duration::ZERO;
        while one_read < at_least {
            let target = (written * 2).max(1000);
            assert!(
                target <= 128_000,
                "the load did not reach {at_least:?} per read: {written} records, {one_read:?} per read"
            );
            for index in written..target {
                super::super::persist_record(
                    data_dir,
                    "provider-receipts",
                    &format!("load-{index:06}"),
                    &json!({ "receipt_id": format!("load-{index:06}"), "kind": "load", "index": index }),
                )
                .unwrap();
            }
            written = target;
            let started = Instant::now();
            let answer =
                super::handle_get(State(state.clone()), headers.clone(), Query(HashMap::new()))
                    .await
                    .into_response();
            one_read = started.elapsed();
            assert_eq!(
                answer.status(),
                axum::http::StatusCode::OK,
                "a calibration read succeeds"
            );
        }
        (written, one_read)
    }

    /// A burst of Systems projection reads larger than the blocking pool never starves another user
    /// of that pool: with 8 blocking threads and 16 parallel reads (each one strict pass over a log
    /// grown until a read takes half a second), an UNRELATED spawn_blocking, sampled repeatedly while
    /// the reads are in flight, always completes within one read's time; and every read answers,
    /// 200 or a typed 503 (`system_source_read_busy`, with Retry-After), instead of hanging.
    #[test]
    fn a_burst_of_systems_reads_never_starves_the_blocking_pool() {
        use axum::response::IntoResponse;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .max_blocking_threads(8)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let data_dir = dir.path().to_str().unwrap().to_string();
            let state = crate::test_daemon_state(&data_dir);
            let headers = signed_in(&data_dir);
            let (written, one_read) =
                calibrate(&state, &data_dir, &headers, Duration::from_millis(500)).await;
            eprintln!("load: {written} records, one projection read {one_read:?}");
            let reads: Vec<_> = (0..16)
                .map(|_| {
                    let (state, headers) = (state.clone(), headers.clone());
                    tokio::spawn(async move {
                        super::handle_get(State(state), headers, Query(HashMap::new()))
                            .await
                            .into_response()
                    })
                })
                .collect();
            // Repeated samples of an unrelated blocking operation while the reads are in flight.
            let mut samples = Vec::new();
            while !reads.iter().all(|read| read.is_finished()) && samples.len() < 400 {
                let submitted = Instant::now();
                tokio::task::spawn_blocking(|| ()).await.unwrap();
                samples.push(submitted.elapsed());
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            let worst = samples.iter().max().copied().unwrap_or_default();
            eprintln!(
                "unrelated blocking operation: {} samples, worst {worst:?} (one projection read {one_read:?})",
                samples.len()
            );
            assert!(
                worst < one_read,
                "an unrelated blocking operation waited {worst:?} behind projection reads that take {one_read:?} each"
            );
            let mut busy = 0;
            for read in reads {
                let answer = tokio::time::timeout(Duration::from_secs(120), read)
                    .await
                    .expect("every read answers within two minutes")
                    .unwrap();
                match answer.status() {
                    axum::http::StatusCode::OK => {}
                    axum::http::StatusCode::SERVICE_UNAVAILABLE => {
                        busy += 1;
                        assert!(
                            answer.headers().contains_key(axum::http::header::RETRY_AFTER),
                            "a busy read answers with Retry-After"
                        );
                        let body = axum::body::to_bytes(answer.into_body(), usize::MAX)
                            .await
                            .unwrap();
                        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
                        assert_eq!(
                            body["error"]["code"],
                            json!("system_source_read_busy"),
                            "a busy read is typed: {body}"
                        );
                    }
                    other => panic!("a read answers 200 or 503, not {other}"),
                }
            }
            eprintln!("reads answered busy: {busy} of 16");
            assert!(busy > 0, "a burst past the admission bound is answered busy, not queued");
        });
    }
}
