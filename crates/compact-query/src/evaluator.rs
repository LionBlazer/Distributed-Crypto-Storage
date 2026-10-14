use crate::wire::{Request, UpdatedRow};
use crate::{Error, Evaluator, MAX_ROWS, Result, Stages, UnverifiedOutput, check_schema, ms};
use compact_store::{Commitment, EncryptedSnapshot, Limits, LookupResponse};
use tfhe::prelude::*;
use tfhe::{FheBool, FheUint8, FheUint10, FheUint16, FheUint32, with_server_key_as_context};

impl Evaluator {
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
            let rows: Vec<(FheUint8, FheUint16)> = request
                .rows
                .iter()
                .zip(compact)
                .map(|(mask, (age, amount))| (&mask.age ^ age, &mask.amount ^ amount))
                .collect();
            stages.peer_compact_to_fhe_ms = ms(start);
            let start = std::time::Instant::now();
            let matches: Vec<_> = rows
                .iter()
                .map(|(age, _)| {
                    if request.equality {
                        age.eq(&request.lower)
                    } else {
                        age.ge(&request.lower) & age.le(&request.upper)
                    }
                })
                .collect();
            let count: FheUint10 = matches
                .iter()
                .map(|bit| FheUint10::cast_from(bit.clone()))
                .sum();
            let zero = FheUint16::encrypt_trivial(0u16);
            let sum: FheUint32 = rows
                .iter()
                .zip(&matches)
                .map(|((_, amount), bit)| FheUint32::cast_from(bit.if_then_else(amount, &zero)))
                .sum();
            let (rejected, updated) = if let Some(delta) = &request.delta {
                let mut rejected = FheBool::encrypt_trivial(false);
                let candidates: Vec<_> = rows
                    .iter()
                    .zip(&matches)
                    .map(|((_, amount), matched)| {
                        let (candidate, overflow) = amount.overflowing_add(delta);
                        rejected |= matched & overflow;
                        candidate
                    })
                    .collect();
                let permitted = !&rejected;
                let updated = rows
                    .iter()
                    .zip(&request.rows)
                    .zip(matches)
                    .zip(candidates)
                    .map(|((((_, amount), input), matched), candidate)| UpdatedRow {
                        ordinal: input.ordinal,
                        amount: (matched & &permitted).if_then_else(&candidate, amount),
                    })
                    .collect();
                (Some(rejected), updated)
            } else {
                (None, Vec::new())
            };
            stages.peer_fhe_evaluate_ms = ms(start);
            UnverifiedOutput {
                domain: self.domain,
                id: request.id,
                head: request.head,
                count: FheUint32::cast_from(count),
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
        Ok(Self { domain, server_key })
    }
}
