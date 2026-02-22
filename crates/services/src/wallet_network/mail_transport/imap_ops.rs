use super::constants::{
    IMAP_FETCH_ATTRS_FULL_BODY, IMAP_FETCH_ATTRS_META_ONLY, IMAP_FETCH_ATTRS_TEXT,
    IMAP_LIST_FETCH_BATCH_SIZE, MAILBOX_COUNT_FRESHNESS_FALLBACK_NO_STATUS,
    MAILBOX_COUNT_FRESHNESS_FALLBACK_STATUS_ZERO, MAILBOX_COUNT_FRESHNESS_STATUS_FRESH,
    MAILBOX_COUNT_FRESHNESS_STATUS_RECONCILED, MAIL_DELETE_SPAM_EVALUATION_MULTIPLIER,
    MAIL_DELETE_SPAM_MAX_EVALUATED, PRIMARY_UNWANTED_ADAPTIVE_PROMOTION_MIN_RATIO_BPS,
    PRIMARY_UNWANTED_ADAPTIVE_PROMOTION_SCORE_DELTA_BPS,
    PRIMARY_UNWANTED_BULK_PROMOTION_MIN_RATIO_BPS,
};
use super::mailbox::{
    cleanup_scope_label, is_primary_unwanted_promotion_candidate,
    preservation_bucket_from_signal_tags, resolve_remote_primary_mailbox,
    resolve_remote_spam_mailbox, select_remote_mailbox, CleanupMailboxScope, PreservationBucket,
};
use super::message::mail_provider_message_from_fetch;
use super::model::{
    MailProviderCredentials, MailProviderDeleteSpamOutcome, MailProviderListOutcome,
    MailProviderMailboxTotalCountOutcome, MailProviderMessage,
};
use crate::wallet_network::mail_ontology::{
    classify_mail_spam, estimate_parse_confidence_bps, is_high_confidence_spam, parse_volume_band,
    MAIL_ONTOLOGY_SIGNAL_VERSION, SPAM_HIGH_CONFIDENCE_THRESHOLD_BPS,
};
use ioi_types::app::wallet_network::{
    MailConnectorAuthMode, MailConnectorEndpoint, MailboxTotalCountProvenance,
};
use ioi_types::error::TransactionError;
use native_tls::TlsConnector;
use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

pub(super) fn open_plain_imap_client(
    endpoint: &MailConnectorEndpoint,
) -> Result<imap::Client<TcpStream>, TransactionError> {
    let stream = TcpStream::connect((endpoint.host.as_str(), endpoint.port)).map_err(|e| {
        TransactionError::Invalid(format!(
            "imap plaintext connect failed for '{}:{}': {}",
            endpoint.host, endpoint.port, e
        ))
    })?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(20)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(20)));
    let mut client = imap::Client::new(stream);
    client.read_greeting().map_err(|e| {
        TransactionError::Invalid(format!(
            "imap greeting read failed for '{}:{}': {}",
            endpoint.host, endpoint.port, e
        ))
    })?;
    Ok(client)
}

pub(super) fn build_tls_connector() -> Result<TlsConnector, TransactionError> {
    TlsConnector::builder()
        .build()
        .map_err(|e| TransactionError::Invalid(format!("imap tls builder failed: {}", e)))
}

fn imap_auth_secret(credentials: &MailProviderCredentials) -> &str {
    match credentials.auth_mode {
        MailConnectorAuthMode::Password | MailConnectorAuthMode::Oauth2 => {
            credentials.imap_secret.as_str()
        }
    }
}

pub(super) fn smtp_auth_secret(credentials: &MailProviderCredentials) -> &str {
    match credentials.auth_mode {
        MailConnectorAuthMode::Password | MailConnectorAuthMode::Oauth2 => {
            credentials.smtp_secret.as_str()
        }
    }
}

struct ImapXoauth2Authenticator<'a> {
    username: &'a str,
    access_token: &'a str,
}

impl imap::Authenticator for ImapXoauth2Authenticator<'_> {
    type Response = String;

    fn process(&self, _challenge: &[u8]) -> Self::Response {
        format!(
            "user={}\x01auth=Bearer {}\x01\x01",
            self.username, self.access_token
        )
    }
}

struct ImapPlainAuthenticator<'a> {
    username: &'a str,
    password: &'a str,
}

impl imap::Authenticator for ImapPlainAuthenticator<'_> {
    type Response = String;

    fn process(&self, _challenge: &[u8]) -> Self::Response {
        format!("\x00{}\x00{}", self.username, self.password)
    }
}

pub(super) fn authenticate_imap_session<T: Read + Write>(
    client: imap::Client<T>,
    credentials: &MailProviderCredentials,
) -> Result<imap::Session<T>, TransactionError> {
    match credentials.auth_mode {
        MailConnectorAuthMode::Password => {
            match client.login(&credentials.imap_username, imap_auth_secret(credentials)) {
                Ok(session) => Ok(session),
                Err((login_err, client)) => {
                    let authenticator = ImapPlainAuthenticator {
                        username: &credentials.imap_username,
                        password: imap_auth_secret(credentials),
                    };
                    client
                        .authenticate("PLAIN", &authenticator)
                        .map_err(|(plain_err, _)| {
                            TransactionError::Invalid(format!(
                                "imap password auth failed for '{}': login={} plain={}",
                                credentials.imap_username, login_err, plain_err
                            ))
                        })
                }
            }
        }
        MailConnectorAuthMode::Oauth2 => {
            let authenticator = ImapXoauth2Authenticator {
                username: &credentials.imap_username,
                access_token: imap_auth_secret(credentials),
            };
            client
                .authenticate("XOAUTH2", &authenticator)
                .map_err(|(e, _)| {
                    TransactionError::Invalid(format!(
                        "imap xoauth2 authenticate failed for '{}': {}",
                        credentials.imap_username, e
                    ))
                })
        }
    }
}

pub(super) fn read_latest_from_imap_session<T: Read + Write>(
    session: &mut imap::Session<T>,
    mailbox: &str,
    now_ms: u64,
) -> Result<MailProviderMessage, TransactionError> {
    let _ = select_remote_mailbox(session, mailbox)?;

    let mut sequence_ids: Vec<u32> = session
        .search("ALL")
        .map_err(|e| TransactionError::Invalid(format!("imap search failed: {}", e)))?
        .into_iter()
        .collect();
    if sequence_ids.is_empty() {
        return Err(TransactionError::Invalid(format!(
            "mailbox '{}' has no messages",
            mailbox
        )));
    }
    sequence_ids.sort_unstable();
    let latest_seq = sequence_ids[sequence_ids.len() - 1];
    let sequence = latest_seq.to_string();

    let fetches = session
        .fetch(sequence.clone(), IMAP_FETCH_ATTRS_TEXT)
        .or_else(|_| session.fetch(sequence.clone(), IMAP_FETCH_ATTRS_FULL_BODY))
        .or_else(|_| session.fetch(sequence, IMAP_FETCH_ATTRS_META_ONLY))
        .map_err(|e| TransactionError::Invalid(format!("imap fetch failed: {}", e)))?;
    let fetch = fetches
        .iter()
        .next()
        .ok_or_else(|| TransactionError::Invalid("imap returned empty fetch result".to_string()))?;
    mail_provider_message_from_fetch(fetch, now_ms)
}

pub(super) fn list_recent_from_imap_session<T: Read + Write>(
    session: &mut imap::Session<T>,
    mailbox: &str,
    limit: usize,
    now_ms: u64,
) -> Result<MailProviderListOutcome, TransactionError> {
    let _ = select_remote_mailbox(session, mailbox)?;

    let mut sequence_ids: Vec<u32> = session
        .search("ALL")
        .map_err(|e| TransactionError::Invalid(format!("imap search failed: {}", e)))?
        .into_iter()
        .collect();
    let mailbox_total_count = mailbox_total_count_from_mailbox(session, mailbox)
        .map(|outcome| outcome.mailbox_total_count)
        .unwrap_or_else(|_| u32::try_from(sequence_ids.len()).unwrap_or(u32::MAX));
    sequence_ids.sort_unstable_by(|a, b| b.cmp(a));
    sequence_ids.truncate(limit);
    if sequence_ids.is_empty() {
        return Ok(MailProviderListOutcome {
            messages: Vec::new(),
            requested_limit: limit,
            evaluated_count: 0,
            parse_error_count: 0,
            parse_confidence_bps: 10_000,
            parse_volume_band: parse_volume_band(0).to_string(),
            mailbox_total_count,
        });
    }

    let evaluated_count = sequence_ids.len();
    let mut parse_error_count = 0usize;
    let mut out = Vec::new();
    for chunk in sequence_ids.chunks(IMAP_LIST_FETCH_BATCH_SIZE) {
        let sequence_set = chunk
            .iter()
            .map(|id| id.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let fetches = session
            .fetch(sequence_set.clone(), IMAP_FETCH_ATTRS_TEXT)
            .or_else(|_| session.fetch(sequence_set.clone(), IMAP_FETCH_ATTRS_FULL_BODY))
            .or_else(|_| session.fetch(sequence_set, IMAP_FETCH_ATTRS_META_ONLY));
        match fetches {
            Ok(fetches) => {
                for fetch in fetches.iter() {
                    match mail_provider_message_from_fetch(fetch, now_ms) {
                        Ok(message) => out.push(message),
                        Err(_) => parse_error_count = parse_error_count.saturating_add(1),
                    }
                }
            }
            Err(_) => {
                parse_error_count = parse_error_count.saturating_add(chunk.len());
            }
        }
    }
    out.sort_by(|a, b| {
        b.received_at_ms
            .cmp(&a.received_at_ms)
            .then_with(|| a.message_id.cmp(&b.message_id))
    });
    if out.len() > limit {
        out.truncate(limit);
    }
    let parsed_count = out.len();
    let parse_confidence_bps =
        estimate_parse_confidence_bps(limit, evaluated_count, parsed_count, parse_error_count);
    let parse_volume_band_value = parse_volume_band(parsed_count).to_string();
    Ok(MailProviderListOutcome {
        messages: out,
        requested_limit: limit,
        evaluated_count,
        parse_error_count,
        parse_confidence_bps,
        parse_volume_band: parse_volume_band_value,
        mailbox_total_count,
    })
}

pub(super) fn mailbox_total_count_from_mailbox<T: Read + Write>(
    session: &mut imap::Session<T>,
    mailbox: &str,
) -> Result<MailProviderMailboxTotalCountOutcome, TransactionError> {
    let status_exists = session
        .status(mailbox, "(MESSAGES)")
        .ok()
        .map(|status| status.exists);
    if let Some(exists) = status_exists {
        if exists > 0 {
            return Ok(MailProviderMailboxTotalCountOutcome {
                mailbox_total_count: exists,
                provenance: MailboxTotalCountProvenance {
                    status_exists: Some(exists),
                    select_exists: None,
                    uid_search_count: None,
                    search_count: None,
                    freshness_marker: MAILBOX_COUNT_FRESHNESS_STATUS_FRESH.to_string(),
                },
            });
        }
    }

    let selected_exists = select_remote_mailbox(session, mailbox)?;
    let uid_count_result = session.uid_search("ALL");
    let seq_count_result = session.search("ALL");
    if let (Err(uid_err), Err(seq_err)) = (&uid_count_result, &seq_count_result) {
        return Err(TransactionError::Invalid(format!(
            "imap uid search failed: {}; imap search failed: {}",
            uid_err, seq_err
        )));
    }
    let uid_search_count = uid_count_result
        .ok()
        .and_then(|uids| u32::try_from(uids.len()).ok())
        .unwrap_or(0);
    let search_count = seq_count_result
        .ok()
        .and_then(|seqs| u32::try_from(seqs.len()).ok())
        .unwrap_or(0);
    let fallback_count = selected_exists.max(uid_search_count).max(search_count);
    let mailbox_total_count = status_exists
        .map(|exists| exists.max(fallback_count))
        .unwrap_or(fallback_count);
    let freshness_marker = match status_exists {
        Some(exists) if exists >= fallback_count => MAILBOX_COUNT_FRESHNESS_STATUS_FRESH,
        Some(exists) if exists == 0 => MAILBOX_COUNT_FRESHNESS_FALLBACK_STATUS_ZERO,
        Some(_) => MAILBOX_COUNT_FRESHNESS_STATUS_RECONCILED,
        None => MAILBOX_COUNT_FRESHNESS_FALLBACK_NO_STATUS,
    };
    Ok(MailProviderMailboxTotalCountOutcome {
        mailbox_total_count,
        provenance: MailboxTotalCountProvenance {
            status_exists,
            select_exists: Some(selected_exists),
            uid_search_count: Some(uid_search_count),
            search_count: Some(search_count),
            freshness_marker: freshness_marker.to_string(),
        },
    })
}

fn reconcile_mailbox_total_count_after_delete(
    mailbox_total_count_before: u32,
    deleted_count: u32,
    measured_after: Option<u32>,
) -> u32 {
    let expected_after = mailbox_total_count_before.saturating_sub(deleted_count);
    let Some(measured_after) = measured_after else {
        return expected_after;
    };
    if deleted_count > 0 && measured_after >= mailbox_total_count_before {
        return expected_after;
    }
    measured_after
        .min(mailbox_total_count_before)
        .max(expected_after)
}

pub(super) fn delete_spam_from_imap_session<T: Read + Write>(
    session: &mut imap::Session<T>,
    mailbox: &str,
    max_delete: u32,
    cleanup_scope: CleanupMailboxScope,
    classification_mailbox: &str,
) -> Result<MailProviderDeleteSpamOutcome, TransactionError> {
    let cleanup_scope_label = cleanup_scope_label(cleanup_scope).to_string();
    if max_delete == 0 {
        return Ok(MailProviderDeleteSpamOutcome {
            evaluated_count: 0,
            deleted_count: 0,
            skipped_low_confidence_count: 0,
            high_confidence_deleted_count: 0,
            mailbox_total_count_before: 0,
            mailbox_total_count_after: 0,
            mailbox_total_count_delta: 0,
            spam_confidence_threshold_bps: SPAM_HIGH_CONFIDENCE_THRESHOLD_BPS,
            ontology_version: MAIL_ONTOLOGY_SIGNAL_VERSION.to_string(),
            cleanup_scope: cleanup_scope_label,
            preserved_transactional_or_personal_count: 0,
            preserved_trusted_system_count: 0,
            preserved_low_confidence_other_count: 0,
            preserved_due_to_delete_cap_count: 0,
        });
    }
    let (selected_mailbox, selected_mailbox_total_count) = match cleanup_scope {
        CleanupMailboxScope::SpamMailbox => resolve_remote_spam_mailbox(session, mailbox)?,
        CleanupMailboxScope::PrimaryInbox => resolve_remote_primary_mailbox(session, mailbox)?,
    };
    let mailbox_total_count_before = mailbox_total_count_from_mailbox(session, &selected_mailbox)
        .map(|outcome| outcome.mailbox_total_count)
        .unwrap_or(selected_mailbox_total_count);

    let mut uids: Vec<u32> = session
        .uid_search("ALL")
        .map_err(|e| TransactionError::Invalid(format!("imap uid search failed: {}", e)))?
        .into_iter()
        .collect();
    uids.sort_unstable_by(|a, b| b.cmp(a));
    let evaluation_limit = (max_delete as usize)
        .saturating_mul(MAIL_DELETE_SPAM_EVALUATION_MULTIPLIER)
        .clamp(max_delete as usize, MAIL_DELETE_SPAM_MAX_EVALUATED);
    uids.truncate(evaluation_limit);
    if uids.is_empty() {
        return Ok(MailProviderDeleteSpamOutcome {
            evaluated_count: 0,
            deleted_count: 0,
            skipped_low_confidence_count: 0,
            high_confidence_deleted_count: 0,
            mailbox_total_count_before,
            mailbox_total_count_after: mailbox_total_count_before,
            mailbox_total_count_delta: 0,
            spam_confidence_threshold_bps: SPAM_HIGH_CONFIDENCE_THRESHOLD_BPS,
            ontology_version: MAIL_ONTOLOGY_SIGNAL_VERSION.to_string(),
            cleanup_scope: cleanup_scope_label,
            preserved_transactional_or_personal_count: 0,
            preserved_trusted_system_count: 0,
            preserved_low_confidence_other_count: 0,
            preserved_due_to_delete_cap_count: 0,
        });
    }

    let evaluated_count = uids.len();
    let uid_set = uids
        .iter()
        .map(|uid| uid.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let fetches = session
        .uid_fetch(uid_set.clone(), IMAP_FETCH_ATTRS_TEXT)
        .or_else(|_| session.uid_fetch(uid_set.clone(), IMAP_FETCH_ATTRS_FULL_BODY))
        .or_else(|_| session.uid_fetch(uid_set, IMAP_FETCH_ATTRS_META_ONLY))
        .map_err(|e| {
            TransactionError::Invalid(format!(
                "imap uid fetch for spam classification failed: {}",
                e
            ))
        })?;

    let mut high_confidence_uids: Vec<(u32, u16)> = Vec::new();
    let mut promoted_primary_unwanted_uids: Vec<(u32, u16)> = Vec::new();
    let mut preserved_transactional_or_personal_count = 0u32;
    let mut preserved_trusted_system_count = 0u32;
    let mut low_confidence_other_uids: Vec<(u32, u16)> = Vec::new();
    for fetch in fetches.iter() {
        let Some(uid) = fetch.uid else {
            continue;
        };
        let Ok(message) = mail_provider_message_from_fetch(fetch, 1) else {
            continue;
        };
        let classification = classify_mail_spam(
            classification_mailbox,
            &message.from,
            &message.subject,
            &message.preview,
        );
        if is_high_confidence_spam(classification.confidence_bps) {
            high_confidence_uids.push((uid, classification.confidence_bps));
            continue;
        }
        let preservation_bucket = preservation_bucket_from_signal_tags(&classification.signal_tags);
        if cleanup_scope == CleanupMailboxScope::PrimaryInbox
            && matches!(preservation_bucket, PreservationBucket::LowConfidenceOther)
            && is_primary_unwanted_promotion_candidate(&classification)
        {
            promoted_primary_unwanted_uids.push((uid, classification.confidence_bps));
        }
        match preservation_bucket {
            PreservationBucket::TransactionalOrPersonal => {
                preserved_transactional_or_personal_count =
                    preserved_transactional_or_personal_count.saturating_add(1);
            }
            PreservationBucket::TrustedSystemSender => {
                preserved_trusted_system_count = preserved_trusted_system_count.saturating_add(1);
            }
            PreservationBucket::LowConfidenceOther => {
                low_confidence_other_uids.push((uid, classification.confidence_bps));
            }
        }
    }
    let low_confidence_other_total_count = low_confidence_other_uids.len() as u32;
    let mut low_confidence_other_candidate_uids = BTreeSet::new();
    for (uid, score) in promoted_primary_unwanted_uids {
        if low_confidence_other_candidate_uids.insert(uid) {
            high_confidence_uids.push((uid, score));
        }
    }
    if cleanup_scope == CleanupMailboxScope::PrimaryInbox {
        let low_other_ratio_bps = if evaluated_count == 0 {
            0
        } else {
            ((low_confidence_other_total_count.saturating_mul(10_000)) / (evaluated_count as u32))
                .min(10_000)
        };
        if low_other_ratio_bps >= PRIMARY_UNWANTED_BULK_PROMOTION_MIN_RATIO_BPS {
            for (uid, score) in &low_confidence_other_uids {
                if low_confidence_other_candidate_uids.insert(*uid) {
                    high_confidence_uids.push((*uid, *score));
                }
            }
        } else if high_confidence_uids.is_empty()
            && low_other_ratio_bps >= PRIMARY_UNWANTED_ADAPTIVE_PROMOTION_MIN_RATIO_BPS
            && !low_confidence_other_uids.is_empty()
        {
            // Adaptive primary-inbox cleanup: when most recent messages are low-confidence
            // "other" and strict spam signals found none, promote the top score band.
            let mut ranked = low_confidence_other_uids.clone();
            ranked.sort_unstable_by(|(uid_a, score_a), (uid_b, score_b)| {
                score_b.cmp(score_a).then_with(|| uid_b.cmp(uid_a))
            });
            let top_score = ranked[0].1;
            let adaptive_floor =
                top_score.saturating_sub(PRIMARY_UNWANTED_ADAPTIVE_PROMOTION_SCORE_DELTA_BPS);
            for (uid, score) in ranked.iter().copied() {
                if low_confidence_other_candidate_uids.len() >= max_delete as usize {
                    break;
                }
                if score < adaptive_floor {
                    continue;
                }
                if low_confidence_other_candidate_uids.insert(uid) {
                    high_confidence_uids.push((uid, score));
                }
            }

            if high_confidence_uids.is_empty() {
                if let Some((uid, score)) = ranked.first().copied() {
                    if low_confidence_other_candidate_uids.insert(uid) {
                        high_confidence_uids.push((uid, score));
                    }
                }
            }
        }
    }
    let preserved_low_confidence_other_count = low_confidence_other_total_count.saturating_sub(
        low_confidence_other_candidate_uids
            .len()
            .min(u32::MAX as usize) as u32,
    );
    let high_confidence_candidate_count = high_confidence_uids.len() as u32;
    let skipped_low_confidence_count = preserved_transactional_or_personal_count
        .saturating_add(preserved_trusted_system_count)
        .saturating_add(preserved_low_confidence_other_count);
    high_confidence_uids.sort_unstable_by(|(uid_a, score_a), (uid_b, score_b)| {
        score_b.cmp(score_a).then_with(|| uid_b.cmp(uid_a))
    });
    high_confidence_uids.truncate(max_delete as usize);

    let mut selected_uids = high_confidence_uids
        .iter()
        .map(|(uid, _)| *uid)
        .collect::<Vec<_>>();
    selected_uids.sort_unstable_by(|a, b| b.cmp(a));
    let target_count = selected_uids.len() as u32;
    let preserved_due_to_delete_cap_count =
        high_confidence_candidate_count.saturating_sub(target_count);
    if selected_uids.is_empty() {
        return Ok(MailProviderDeleteSpamOutcome {
            evaluated_count: evaluated_count as u32,
            deleted_count: 0,
            skipped_low_confidence_count,
            high_confidence_deleted_count: 0,
            mailbox_total_count_before,
            mailbox_total_count_after: mailbox_total_count_before,
            mailbox_total_count_delta: 0,
            spam_confidence_threshold_bps: SPAM_HIGH_CONFIDENCE_THRESHOLD_BPS,
            ontology_version: MAIL_ONTOLOGY_SIGNAL_VERSION.to_string(),
            cleanup_scope: cleanup_scope_label,
            preserved_transactional_or_personal_count,
            preserved_trusted_system_count,
            preserved_low_confidence_other_count,
            preserved_due_to_delete_cap_count,
        });
    }
    let selected_set = selected_uids
        .iter()
        .map(|uid| uid.to_string())
        .collect::<Vec<_>>()
        .join(",");
    if session.uid_mv(&selected_set, "Trash").is_ok() {
        let measured_after = mailbox_total_count_from_mailbox(session, &selected_mailbox)
            .ok()
            .map(|outcome| outcome.mailbox_total_count);
        let mailbox_total_count_after = reconcile_mailbox_total_count_after_delete(
            mailbox_total_count_before,
            target_count,
            measured_after,
        );
        return Ok(MailProviderDeleteSpamOutcome {
            evaluated_count: evaluated_count as u32,
            deleted_count: target_count,
            skipped_low_confidence_count,
            high_confidence_deleted_count: target_count,
            mailbox_total_count_before,
            mailbox_total_count_after,
            mailbox_total_count_delta: mailbox_total_count_before
                .saturating_sub(mailbox_total_count_after),
            spam_confidence_threshold_bps: SPAM_HIGH_CONFIDENCE_THRESHOLD_BPS,
            ontology_version: MAIL_ONTOLOGY_SIGNAL_VERSION.to_string(),
            cleanup_scope: cleanup_scope_label,
            preserved_transactional_or_personal_count,
            preserved_trusted_system_count,
            preserved_low_confidence_other_count,
            preserved_due_to_delete_cap_count,
        });
    }

    session
        .uid_store(&selected_set, "+FLAGS.SILENT (\\Deleted)")
        .map_err(|e| TransactionError::Invalid(format!("imap uid store +deleted failed: {}", e)))?;
    let deleted_count = match session.uid_expunge(&selected_set) {
        Ok(expunged) => expunged.len() as u32,
        Err(_) => {
            session
                .expunge()
                .map_err(|e| TransactionError::Invalid(format!("imap expunge failed: {}", e)))?;
            target_count
        }
    };
    let measured_after = mailbox_total_count_from_mailbox(session, &selected_mailbox)
        .ok()
        .map(|outcome| outcome.mailbox_total_count);
    let mailbox_total_count_after = reconcile_mailbox_total_count_after_delete(
        mailbox_total_count_before,
        deleted_count,
        measured_after,
    );
    Ok(MailProviderDeleteSpamOutcome {
        evaluated_count: evaluated_count as u32,
        deleted_count,
        skipped_low_confidence_count,
        high_confidence_deleted_count: deleted_count,
        mailbox_total_count_before,
        mailbox_total_count_after,
        mailbox_total_count_delta: mailbox_total_count_before
            .saturating_sub(mailbox_total_count_after),
        spam_confidence_threshold_bps: SPAM_HIGH_CONFIDENCE_THRESHOLD_BPS,
        ontology_version: MAIL_ONTOLOGY_SIGNAL_VERSION.to_string(),
        cleanup_scope: cleanup_scope_label,
        preserved_transactional_or_personal_count,
        preserved_trusted_system_count,
        preserved_low_confidence_other_count,
        preserved_due_to_delete_cap_count,
    })
}
