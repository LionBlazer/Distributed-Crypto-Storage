//! Complete proved per-shard UPDATE preparation, without network publication.
use super::writeback::{StagedImages, UpdateSourceKind, Writeback};
use super::*;
use crate::query_rpc::{ProofJob, Requests};
use compact_query::{ReadView, UpdateView};
use peer_runtime::{PageAddress, PageImage, ProofReply, ReadImage};
use sql_plan::Predicate;

pub(super) struct StagedShardUpdate {
    pub slot: usize,
    pub images: Option<StagedImages>,
    pub affected_rows: usize,
    pub job: MutationJob,
    pub proof: ProofReply,
}

enum UpdateSource {
    Full(Table),
    Static(ReadImage),
}

impl Session {
    pub(super) fn prepare_update_shards(
        &self,
        predicate: Predicate,
        delta: u16,
        requests: &Requests,
        writeback: &Writeback,
    ) -> Result<Vec<StagedShardUpdate>> {
        crate::jobs::run(0..self.data.shards.len(), |slot| {
            self.prepare_update_shard(
                slot,
                predicate,
                delta,
                requests,
                writeback.source_kind(slot)?,
            )
        })
    }

    fn prepare_update_shard(
        &self,
        slot: usize,
        predicate: Predicate,
        delta: u16,
        requests: &Requests,
        source_kind: UpdateSourceKind,
    ) -> Result<StagedShardUpdate> {
        let shard = &self.data.shards[slot];
        let heads = self.read_heads(slot)?;
        // This class is frozen before any proof job, independently of responses.
        // A failed static source never triggers a full-source fallback.
        let (remote, source) = match source_kind {
            UpdateSourceKind::Full => {
                let (remote, table) = self.fetch_online(shard)?;
                (remote, UpdateSource::Full(table))
            }
            UpdateSourceKind::Static => {
                let (remote, image) = self.fetch_read_image(slot, &heads, requests)?;
                (remote, UpdateSource::Static(image))
            }
        };
        let predicate = predicate.age_range().map(|range| AgeRange {
            lower: range.lower,
            upper: range.upper,
        });
        let prepared = match &source {
            UpdateSource::Full(table) => self.data.owner.prepare_provable_update(
                table,
                predicate,
                delta,
                256,
                Limits::default(),
            )?,
            UpdateSource::Static(image) => {
                let index = super::source::IndexPrefix(image);
                let source = ReadView::new(heads.clone(), image.data(), &index)?;
                self.data.owner.prepare_provable_update_from_source(
                    &source,
                    predicate,
                    delta,
                    256,
                    Limits::default(),
                )?
            }
        };
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
        let (affected_rows, images) = match source {
            UpdateSource::Full(table) => {
                let stage = self.data.owner.stage_checked_update(
                    &table,
                    prepared,
                    &reply.output,
                    checked,
                    Limits::default(),
                )?;
                if stage.overflowed() {
                    return Err(update_overflow());
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
                let images =
                    (next.commitment() != table.commitment()).then_some(StagedImages::Full {
                        table: next,
                        replacements: Some(replacements),
                    });
                (affected_rows, images)
            }
            UpdateSource::Static(image) => {
                let index = super::source::IndexPrefix(&image);
                let header = image.index_page_for_reissue(0).map_err(protocol)?;
                let source = UpdateView::new(heads, image.data(), &index, header)?;
                let stage = self.data.owner.stage_checked_update_from_source(
                    source,
                    prepared,
                    &reply.output,
                    checked,
                    Limits::default(),
                )?;
                if stage.overflowed() {
                    return Err(update_overflow());
                }
                let affected_rows = stage.matched_rows();
                (affected_rows, stage.into_patch().map(StagedImages::Update))
            }
        };
        Ok(StagedShardUpdate {
            slot,
            images,
            affected_rows,
            job: MutationJob {
                shard: shard.info.id,
                request,
            },
            proof: reply,
        })
    }
}
fn update_overflow() -> Error {
    Error::InvalidInput("UPDATE overflowed; no shard was published".into())
}
