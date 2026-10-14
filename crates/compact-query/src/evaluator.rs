use crate::wire::{CountCipher, EncryptedPredicate, Request, SumCipher, UpdatedRow};
use crate::{Error, Evaluator, MAX_ROWS, Result, Stages, UnverifiedOutput, check_schema, ms};
use compact_store::{Commitment, EncryptedSnapshot, Limits, LookupResponse};
use tfhe::prelude::*;
use tfhe::{FheBool, FheUint8, FheUint10, FheUint16, FheUint24, with_server_key_as_context};
const MAX_ROW_WORKERS: usize = 8;
const _: () = assert!(MAX_ROWS < (1 << 10));
const _: () = assert!((MAX_ROWS as u64) * (u16::MAX as u64) < (1 << 24));

impl Evaluator {
    /// Opt-in experiment: at most eight additional scoped initiating OS threads.
    /// TFHE's internal Rayon pool is shared. The default evaluator stays serial.
    pub fn with_row_workers_for_experiment(&self, requested: usize) -> Result<Self> {
        if !(1..=MAX_ROW_WORKERS).contains(&requested) {
            return Err(Error::WorkerBudget {
                requested,
                maximum: MAX_ROW_WORKERS,
            });
        }
        Ok(Self {
            server_key: self.server_key.clone(),
            domain: self.domain,
            row_workers: requested,
        })
    }
    fn map_rows<T: Sync, R: Send>(&self, rows: &[T], operation: impl Fn(&T) -> R + Sync) -> Vec<R> {
        if self.row_workers == 1 || rows.len() < 2 {
            return rows.iter().map(operation).collect();
        }
        let chunk_size = rows.len().div_ceil(self.row_workers.min(rows.len()));
        // Initiate outside Rayon: TFHE may steal nested tasks without replacing
        // the already borrowed server-key TLS of a Rayon initiating worker.
        std::thread::scope(|scope| {
            let handles: Vec<_> = rows
                .chunks(chunk_size)
                .map(|chunk| {
                    let operation = &operation;
                    scope.spawn(move || {
                        with_server_key_as_context(self.server_key.clone(), || {
                            chunk.iter().map(operation).collect::<Vec<_>>()
                        })
                    })
                })
                .collect();
            handles
                .into_iter()
                .flat_map(|handle| handle.join().expect("FHE row worker panicked"))
                .collect()
        })
    }
    /// No owner secret/plaintext is accepted. Exact pages are independently verified
    /// against the request head before public compact bytes are XORed with FHE pads.
    pub fn evaluate(
        &self,
        snapshot: &EncryptedSnapshot,
        request_wire: &[u8],
        limits: Limits,
    ) -> Result<UnverifiedOutput> {
        let start = std::time::Instant::now();
        let request: Request = crate::wire::decode(request_wire)?;
        let mut stages = Stages {
            peer_request_decode_ms: ms(start),
            row_worker_budget: self.row_workers,
            ..Stages::default()
        };
        if request.domain != self.domain {
            return Err(Error::WrongDomain);
        }
        let head = Commitment::decode(&request.head, limits)?;
        if &head != snapshot.commitment() {
            return Err(Error::WrongVersion);
        }
        check_schema(&head)?;
        if request.rows.len() > MAX_ROWS {
            return Err(Error::SelectionBudget {
                selected: request.rows.len(),
                budget: MAX_ROWS,
            });
        }
        if request
            .rows
            .windows(2)
            .any(|pair| pair[0].ordinal >= pair[1].ordinal)
        {
            return Err(Error::DuplicateAddress);
        }
        let start = std::time::Instant::now();
        let mut compact = Vec::with_capacity(request.rows.len());
        let mut previous = u64::MAX;
        let mut page = None;
        for row in &request.rows {
            let address = head.layout().address_of(row.ordinal)?;
            if address.page_index != previous {
                let encoded = snapshot.lookup(address.page_index, limits)?.encode();
                stages.page_response_bytes += encoded.len();
                page = Some(LookupResponse::decode(&encoded, limits)?.verify(
                    &head,
                    address.page_index,
                    limits,
                )?);
                previous = address.page_index;
            }
            let bytes =
                &page.as_ref().unwrap().ciphertext()[address.byte_offset..address.byte_offset + 3];
            compact.push((bytes[0], u16::from_le_bytes([bytes[1], bytes[2]])));
        }
        stages.peer_lookup_proof_verify_ms = ms(start);
        Ok(with_server_key_as_context(self.server_key.clone(), || {
            let start = std::time::Instant::now();
            let inputs: Vec<_> = request.rows.iter().zip(compact).collect();
            let rows: Vec<(FheUint8, FheUint16)> = self
                .map_rows(&inputs, |(mask, (age, amount))| {
                    (&mask.age ^ *age, &mask.amount ^ *amount)
                });
            stages.peer_compact_to_fhe_ms = ms(start);
            let start = std::time::Instant::now();
            let matches: Vec<_> = self.map_rows(&rows, |(age, _)| match &request.predicate {
                EncryptedPredicate::Equal(value) => age.eq(value),
                EncryptedPredicate::AtLeast(value) => age.ge(value),
                EncryptedPredicate::AtMost(value) => age.le(value),
                EncryptedPredicate::Range { lower, upper } => age.ge(lower) & age.le(upper),
            });
            let selected: Vec<_> = rows.iter().zip(&matches).collect();
            // The one-row path keeps the genuine encrypted predicate and selection;
            // only known-zero high blocks are omitted from the output encoding.
            let (count, sum) = if rows.len() == 1 {
                (
                    CountCipher::Single(matches[0].clone()),
                    SumCipher::Single(matches[0].if_then_zero(&rows[0].1)),
                )
            } else {
                let count: FheUint10 = matches
                    .iter()
                    .map(|bit| FheUint10::cast_from(bit.clone()))
                    .sum();
                let sum: FheUint24 = self
                    .map_rows(&selected, |((_, amount), bit)| {
                        FheUint24::cast_from(bit.if_then_zero(amount))
                    })
                    .into_iter()
                    .sum();
                (CountCipher::Multiple(count), SumCipher::Multiple(sum))
            };
            let (rejected, updated) = if let Some(delta) = &request.delta {
                let mut rejected = FheBool::encrypt_trivial(false);
                let candidates: Vec<_> = if self.row_workers == 1 {
                    rows.iter()
                        .zip(&matches)
                        .map(|((_, amount), matched)| {
                            let (candidate, overflow) = amount.overflowing_add(delta);
                            rejected |= matched & overflow;
                            candidate
                        })
                        .collect()
                } else {
                    let candidates = self.map_rows(&selected, |((_, amount), matched)| {
                        let (candidate, overflow) = amount.overflowing_add(delta);
                        (candidate, *matched & overflow)
                    });
                    candidates
                        .into_iter()
                        .map(|(candidate, overflow)| {
                            rejected |= overflow;
                            candidate
                        })
                        .collect()
                };
                let permitted = !&rejected;
                let inputs: Vec<_> = rows
                    .iter()
                    .zip(&request.rows)
                    .zip(matches)
                    .zip(candidates)
                    .collect();
                let updated =
                    self.map_rows(&inputs, |((((_, amount), input), matched), candidate)| {
                        UpdatedRow {
                            ordinal: input.ordinal,
                            amount: (matched & &permitted).if_then_else(candidate, amount),
                        }
                    });
                (Some(rejected), updated)
            } else {
                (None, Vec::new())
            };
            stages.peer_fhe_evaluate_ms = ms(start);
            UnverifiedOutput {
                domain: self.domain,
                id: request.id,
                head: request.head,
                count,
                sum,
                rejected,
                rows: updated,
                stages,
            }
        }))
    }
    pub fn evaluation_key_serialized_bytes(&self) -> Result<u64> {
        bincode::serialized_size(&self.server_key).map_err(|e| Error::Codec(e.to_string()))
    }
    /// Public evaluation key only; bounded trusted experiment round trip.
    pub fn encode_evaluation_key_for_experiment(&self) -> Result<Vec<u8>> {
        bincode::serialize(&(self.domain, &self.server_key))
            .map_err(|e| Error::Codec(e.to_string()))
    }
    pub fn restore_evaluation_key_for_experiment(bytes: &[u8]) -> Result<Self> {
        use bincode::Options;
        let (domain, server_key) = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(512 * 1024 * 1024)
            .reject_trailing_bytes()
            .deserialize(bytes)
            .map_err(|e| Error::Codec(e.to_string()))?;
        Ok(Self {
            domain,
            server_key,
            row_workers: 1,
        })
    }
}
