//! One statement's bounded encrypted batch preparation, before any Store or authorization.
use super::*;
use crate::query_rpc::{ProofJob, Requests};
use peer_runtime::ProofReply;
use sql_plan::RowValues;
use zeroize::Zeroizing;

pub(super) struct StagedShardInsert {
    pub slot: usize,
    pub table: Table,
    pub job: MutationJob,
    pub proof: ProofReply,
}

fn insert_targets(
    shards: &[(u64, usize)],
    incoming: usize,
    max_updates: u32,
) -> Result<Vec<(usize, std::ops::Range<usize>)>> {
    if incoming == 0 || incoming > 256 {
        return Err(Error::InvalidInput(
            "INSERT requires 1..=256 incoming rows".into(),
        ));
    }
    let capacity: usize = shards
        .iter()
        .map(|(_, count)| 256usize.saturating_sub(*count))
        .sum();
    if incoming > capacity {
        return Err(Error::InvalidInput(
            "INSERT exceeds the complete shard capacity; no shard was published".into(),
        ));
    }
    // Fill the largest capacities first to minimize proof jobs and changed heads.
    // Preserve input order within each contiguous chunk; jobs themselves use shard order.
    let mut candidates: Vec<_> = (0..shards.len()).collect();
    candidates.sort_by_key(|slot| (shards[*slot].1, shards[*slot].0));
    let mut targets = Vec::new();
    let mut assigned = 0;
    for slot in candidates {
        let count = 256usize
            .saturating_sub(shards[slot].1)
            .min(incoming - assigned);
        if count != 0 {
            targets.push((slot, assigned..assigned + count));
            assigned += count;
        }
        if assigned == incoming {
            break;
        }
    }
    targets.sort_by_key(|(slot, _)| shards[*slot].0);
    if targets.len() > max_updates as usize {
        return Err(Error::InvalidInput(
            "INSERT requires more shard updates than the protocol profile allows; no shard was published".into(),
        ));
    }
    Ok(targets)
}

impl Session {
    pub(super) fn prepare_insert_shards(
        &self,
        incoming: &[RowValues],
        requests: &Requests,
    ) -> Result<Vec<StagedShardInsert>> {
        // Counts come from the freshly authenticated agreed heads. Preflight the
        // whole statement before fetching/proving/storing even its first shard.
        let counts: Vec<_> = self
            .data
            .shards
            .iter()
            .map(|shard| (shard.info.id, shard.info.rows))
            .collect();
        let targets = insert_targets(&counts, incoming.len(), self.journal.profile().max_updates)?;
        crate::jobs::run(targets.len(), |target| {
            let (slot, ordinals) = &targets[target];
            let rows = Zeroizing::new(
                ordinals
                    .clone()
                    .map(|ordinal| {
                        let row = incoming[ordinal];
                        PlainRow {
                            age: row.age,
                            amount: row.amount,
                        }
                    })
                    .collect::<Vec<_>>(),
            );
            self.prepare_insert_shard(*slot, &rows, requests)
        })
    }

    fn prepare_insert_shard(
        &self,
        slot: usize,
        incoming: &[PlainRow],
        requests: &Requests,
    ) -> Result<StagedShardInsert> {
        let shard = &self.data.shards[slot];
        let (remote, table) = self.fetch_online(shard)?;
        let prepared = self.data.owner.prepare_insert_for_experiment(
            &table,
            incoming,
            256,
            Limits::default(),
        )?;
        let request = prepared.request().to_vec();
        let (reply, checked) = requests.request(
            &remote,
            &shard.peers,
            ProofJob {
                object: shard.info.object,
                setup: self.data.setup_id,
                operation: Operation::Insert,
                ciphertext: &request,
            },
            |reply| {
                self.verifier
                    .check_job(Operation::Insert, &request, reply)
                    .map_err(protocol)
            },
        )?;
        let table = self.data.owner.stage_checked_insert(
            &table,
            prepared,
            &reply.output,
            checked,
            Limits::default(),
        )?;
        Ok(StagedShardInsert {
            slot,
            table,
            job: MutationJob {
                shard: shard.info.id,
                request,
            },
            proof: reply,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_plan_preserves_every_input_at_bounded_targets_in_shard_order() {
        assert_eq!(
            insert_targets(&[(9, 254), (7, 254), (3, 256)], 4, 2).unwrap(),
            vec![(1, 0..2), (0, 2..4)],
        );
    }

    #[test]
    fn batch_requiring_two_updates_rejects_a_one_update_protocol_profile() {
        let error = insert_targets(&[(9, 255), (7, 255)], 2, 1).unwrap_err();

        assert!(matches!(error, Error::InvalidInput(_)));
        assert!(error.to_string().contains("protocol profile"));
        assert_eq!(
            insert_targets(&[(9, 0), (7, 0)], 2, 1).unwrap(),
            vec![(1, 0..2)]
        );
        assert_eq!(
            insert_targets(&[(9, 254), (7, 250)], 4, 1).unwrap(),
            vec![(1, 0..4)]
        );
    }

    #[test]
    fn insufficient_total_capacity_rejects_the_batch_instead_of_admitting_a_prefix() {
        let error = insert_targets(&[(7, 255), (9, 255)], 3, 2).unwrap_err();

        assert!(matches!(error, Error::InvalidInput(_)));
        assert!(error.to_string().contains("complete shard capacity"));
    }
}
