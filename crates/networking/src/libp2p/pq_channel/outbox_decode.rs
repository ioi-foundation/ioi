//! Streaming v2 decoding with a per-entry allocation boundary. This does not
//! reserve aggregate retained-state memory or establish a recovery time bound.
use super::*;
use parity_scale_codec::{Compact, Input};
use std::io::{BufReader, Read};

struct BoundedInput<R> {
    reader: R,
    remaining: u64,
    entry_budget: u64,
}

impl<R: Read> Input for BoundedInput<R> {
    fn remaining_len(&mut self) -> Result<Option<usize>, parity_scale_codec::Error> {
        Ok(Some(
            self.remaining.min(self.entry_budget).min(usize::MAX as u64) as usize,
        ))
    }
    fn read(&mut self, into: &mut [u8]) -> Result<(), parity_scale_codec::Error> {
        let length = into.len() as u64;
        if length > self.remaining || length > self.entry_budget {
            return Err("outbox decode exceeds available bytes or entry budget".into());
        }
        self.reader
            .read_exact(into)
            .map_err(|_| parity_scale_codec::Error::from("outbox read failed"))?;
        self.remaining -= length;
        self.entry_budget -= length;
        Ok(())
    }
}

pub(super) fn read_outbox(
    path: &Path,
    expected: &PqOutboxStateV2,
    rooted_accounts: &std::collections::BTreeSet<AccountId>,
) -> Result<PqOutboxStateV2> {
    let file = File::open(path)?;
    let length = file.metadata()?.len();
    let mut input = BoundedInput {
        reader: BufReader::with_capacity(64 * 1024, file),
        remaining: length,
        entry_budget: length,
    };
    let (
        protocol_version,
        schema_version,
        network_id,
        configuration_hash,
        epoch,
        local_account_id,
        count,
    ) = <(u16, u16, [u8; 32], [u8; 32], u64, AccountId, Compact<u32>)>::decode(&mut input)
        .map_err(anyhow::Error::msg)?;
    if protocol_version != expected.protocol_version
        || schema_version != expected.schema_version
        || network_id != expected.network_id
        || configuration_hash != expected.configuration_hash
        || epoch != expected.epoch
        || local_account_id != expected.local_account_id
    {
        return Err(anyhow!(
            "PQ outbox scope/version does not match the active configuration"
        ));
    }
    // Every v2 entry has two fixed 32-byte identities and a payload. Do not
    // preallocate a vector from an untrusted count, even in a sparse file.
    if u64::from(count.0) > input.remaining / 64 {
        return Err(anyhow!("PQ outbox entry count exceeds available bytes"));
    }
    let capacity = rooted_accounts
        .len()
        .checked_mul(PQ_OUTBOX_PER_RECIPIENT_MAX)
        .ok_or_else(|| anyhow!("PQ outbox account capacity overflow"))?;
    if u64::from(count.0) > capacity as u64 {
        return Err(anyhow!("PQ outbox count exceeds rooted account capacity"));
    }
    let mut entries = Vec::new();
    let mut byte_usage = OutboxByteUsage::default();
    let mut per_recipient = std::collections::BTreeMap::<AccountId, usize>::new();
    for _ in 0..count.0 {
        input.entry_budget = 64 + PQ_CHANNEL_MAX_RECORD_PLAINTEXT_V1 as u64;
        let recipient_account_id = AccountId::decode(&mut input).map_err(anyhow::Error::msg)?;
        if !rooted_accounts.contains(&recipient_account_id) {
            return Err(anyhow!(
                "PQ outbox recipient is outside rooted account scope"
            ));
        }
        let used = per_recipient.entry(recipient_account_id).or_default();
        *used += 1;
        if *used > PQ_OUTBOX_PER_RECIPIENT_MAX {
            return Err(anyhow!("PQ outbox exceeds the per-recipient durable limit"));
        }
        let message_id = <[u8; 32]>::decode(&mut input).map_err(anyhow::Error::msg)?;
        let payload = PqConsensusPayloadV1::decode(&mut input).map_err(|error| {
            anyhow!("PQ outbox entry violates record plaintext limit or encoding: {error}")
        })?;
        byte_usage.observe(recipient_account_id, &payload)?;
        entries.push(Arc::new(PqOutboxEntryV2 {
            recipient_account_id,
            message_id,
            payload,
        }));
    }
    if input.remaining != 0 || input.reader.read(&mut [0; 1])? != 0 {
        return Err(anyhow!("PQ outbox has trailing bytes or changed length"));
    }
    Ok(PqOutboxStateV2 {
        protocol_version,
        schema_version,
        network_id,
        configuration_hash,
        epoch,
        local_account_id,
        entries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn entry_budget_rejects_declared_vector_before_reading_body() {
        let mut bytes = Compact(100_u32).encode();
        let prefix = bytes.len();
        bytes.extend_from_slice(&[7; 100]);
        let mut input = BoundedInput {
            remaining: bytes.len() as u64,
            entry_budget: 10,
            reader: Cursor::new(bytes),
        };
        struct AllocationProbe<'a> {
            input: &'a mut BoundedInput<Cursor<Vec<u8>>>,
            allocated: usize,
            ignore_budget: bool,
        }
        impl Input for AllocationProbe<'_> {
            fn remaining_len(&mut self) -> Result<Option<usize>, parity_scale_codec::Error> {
                if self.ignore_budget {
                    Ok(Some(self.input.remaining as usize))
                } else {
                    self.input.remaining_len()
                }
            }
            fn read(&mut self, into: &mut [u8]) -> Result<(), parity_scale_codec::Error> {
                Input::read(self.input, into)
            }
            fn on_before_alloc_mem(
                &mut self,
                size: usize,
            ) -> Result<(), parity_scale_codec::Error> {
                self.allocated += size;
                Ok(())
            }
        }
        let mut probe = AllocationProbe {
            input: &mut input,
            allocated: 0,
            ignore_budget: false,
        };
        assert!(Vec::<u8>::decode(&mut probe).is_err());
        assert_eq!(
            probe.allocated, 0,
            "invalid declared payload must fail before allocation"
        );
        assert_eq!(input.reader.position(), prefix as u64);
        // Removed-rule control: late read refusal alone permits the allocation.
        input.reader.set_position(0);
        input.remaining = input.reader.get_ref().len() as u64;
        input.entry_budget = 10;
        let mut removed_rule = AllocationProbe {
            input: &mut input,
            allocated: 0,
            ignore_budget: true,
        };
        assert!(Vec::<u8>::decode(&mut removed_rule).is_err());
        assert_eq!(removed_rule.allocated, 100);

        let mut exact = BoundedInput {
            remaining: 5,
            entry_budget: 5,
            reader: Cursor::new(vec![16, 1, 2, 3, 4]),
        };
        assert_eq!(Vec::<u8>::decode(&mut exact).unwrap(), vec![1, 2, 3, 4]);
        assert_eq!(exact.remaining, 0);
    }
}
