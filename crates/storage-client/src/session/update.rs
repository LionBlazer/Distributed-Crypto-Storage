//! Complete proved per-shard UPDATE preparation, without network publication.
use super::*;
use crate::query_rpc::{ProofJob, Requests};
use peer_runtime::{PageAddress, PageImage, ProofReply};
use sql_plan::Predicate;

pub(super) struct StagedShardUpdate {
    pub slot: usize,
    pub table: Option<Table>,
    pub affected_rows: usize,
    pub replacements: Vec<PageAddress>,
    pub job: MutationJob,
    pub proof: ProofReply,
}

impl Session {
    pub(super) fn prepare_update_shards(
        &self,
        predicate: Predicate,
        delta: u16,
        requests: &Requests,
    ) -> Result<Vec<StagedShardUpdate>> {
        crate::jobs::run(0..self.data.shards.len(), |slot| {
            self.prepare_update_shard(slot, predicate, delta, requests)
        })
    }

    fn prepare_update_shard(
        &self,
        slot: usize,
        predicate: Predicate,
        delta: u16,
        requests: &Requests,
    ) -> Result<StagedShardUpdate> {
        let shard = &self.data.shards[slot];
        let (remote, table) = self.fetch_online(shard)?;
        let prepared = self.data.owner.prepare_provable_update(
            &table,
            predicate.age_range().map(|r| AgeRange {
                lower: r.lower,
                upper: r.upper,
            }),
            delta,
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
                operation: Operation::Update,
                ciphertext: &request,
            },
            |reply| {
                self.verifier
                    .check_job(Operation::Update, &request, reply)
                    .map_err(protocol)
            },
        )?;
        let stage = self.data.owner.stage_checked_update(
            &table,
            prepared,
            &reply.output,
            checked,
            Limits::default(),
        )?;
        if stage.overflowed() {
            return Err(Error::InvalidInput(
                "UPDATE overflowed; no shard was published".into(),
            ));
        }
        let affected_rows = stage.matched_rows();
        let replacements = stage
            .replaced_data_pages()
            .iter()
            .map(|&index| PageAddress {
                image: PageImage::Data,
                index,
            })
            .chain(
                stage
                    .replaced_index_pages()
                    .iter()
                    .map(|&index| PageAddress {
                        image: PageImage::Index,
                        index,
                    }),
            )
            .collect();
        let next = stage
            .into_table()
            .ok_or_else(|| protocol("Missing proved update"))?;
        Ok(StagedShardUpdate {
            slot,
            table: (next.commitment() != table.commitment()).then_some(next),
            affected_rows,
            replacements,
            job: MutationJob {
                shard: shard.info.id,
                request,
            },
            proof: reply,
        })
    }
}
