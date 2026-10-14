//! Public-fixture, owner-online BFV experiment. No query proof or production parser.
mod metrics;

use bincode::Options;
use compact_store::{
    Commitment, EncryptedSnapshot, Layout, Limits, LookupResponse, Owner as PageOwner,
};
use fhe::bfv::{
    BfvParameters, Ciphertext, Encoding, EvaluationKey, EvaluationKeyBuilder, Plaintext,
    RelinearizationKey, SecretKey,
};
use fhe_traits::{
    DeserializeParametrized, FheDecoder, FheDecrypter, FheEncoder, FheEncrypter,
    Serialize as FheSerialize,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeSet;
use std::error::Error;
use std::sync::Arc;
use std::time::Instant;
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const SUM_BOUND: u64 = 256 * 65_535;
const LIMB_SUM_BOUND: u64 = 256 * 255;
const WIRE_LIMIT: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
enum Predicate {
    Equal,
    AtLeast,
    Range,
}

#[derive(Serialize, Deserialize)]
struct Request {
    query_id: [u8; 16],
    head: Vec<u8>,
    rows: usize,
    stride: usize,
    predicate: Predicate,
    age: Vec<u8>,
    lower: Vec<u8>,
    upper: Option<Vec<u8>>,
    values: Vec<u8>,
}
#[derive(Serialize, Deserialize)]
struct Output {
    query_id: [u8; 16],
    head: Vec<u8>,
    rows: usize,
    count_sum: Vec<u8>,
}

// A peer has public parameters, public evaluation keys and encrypted pages only.
struct Peer {
    parameters: Arc<BfvParameters>,
    relin: RelinearizationKey,
    rotations: EvaluationKey,
    data: EncryptedSnapshot,
    fused_ge: bool,
    additive_range: bool,
    output_level: usize,
}
struct Counters {
    multiplications: usize,
    rotations: usize,
}
impl Peer {
    fn multiply(&self, a: &Ciphertext, b: &Ciphertext, n: &mut Counters) -> Result<Ciphertext> {
        let mut product = a * b;
        self.relin.relinearizes(&mut product)?;
        n.multiplications += 1;
        Ok(product)
    }
    fn rotate(&self, a: &Ciphertext, shift: usize, n: &mut Counters) -> Result<Ciphertext> {
        n.rotations += 1;
        Ok(self.rotations.rotates_columns_by(a, shift)?)
    }
    fn bit_equal(
        &self,
        a: &Ciphertext,
        b: &Ciphertext,
        n: &mut Counters,
    ) -> Result<(Ciphertext, Ciphertext)> {
        let ab = self.multiply(a, b, n)?;
        let mut equal = &ab + &ab;
        let ones = Plaintext::try_encode(
            &vec![1u64; self.parameters.degree()],
            Encoding::simd(),
            &self.parameters,
        )?;
        equal += &ones;
        equal -= a;
        equal -= b;
        let greater = a - &ab;
        Ok((equal, greater))
    }
    fn equal(
        &self,
        a: &Ciphertext,
        b: &Ciphertext,
        stride: usize,
        n: &mut Counters,
    ) -> Result<Ciphertext> {
        let (mut equal, _) = self.bit_equal(a, b, n)?;
        // Only block zero is consumed. Source block i contains bit 7-i.
        for shift in [stride, 2 * stride, 4 * stride] {
            let low = self.rotate(&equal, shift, n)?;
            equal = self.multiply(&equal, &low, n)?;
        }
        Ok(equal)
    }
    fn greater_equal(
        &self,
        a: &Ciphertext,
        b: &Ciphertext,
        stride: usize,
        n: &mut Counters,
    ) -> Result<Ciphertext> {
        let (mut equal, mut greater) = self.bit_equal(a, b, n)?;
        let shifts: &[usize] = if self.fused_ge {
            &[stride, 2 * stride]
        } else {
            &[stride, 2 * stride, 4 * stride]
        };
        for &shift in shifts {
            // Both products use OLD E/G. Adjacent pairs are MSB to LSB.
            let low_greater = self.rotate(&greater, shift, n)?;
            let propagated = self.multiply(&equal, &low_greater, n)?;
            let low_equal = self.rotate(&equal, shift, n)?;
            let new_equal = self.multiply(&equal, &low_equal, n)?;
            greater += &propagated;
            equal = new_equal;
        }
        if self.fused_ge {
            let low_ge = &greater + &equal;
            let low_ge = self.rotate(&low_ge, 4 * stride, n)?;
            let propagated = self.multiply(&equal, &low_ge, n)?;
            Ok(&greater + &propagated)
        } else {
            Ok(&greater + &equal)
        }
    }
    fn evaluate(&self, wire: &[u8]) -> Result<(Vec<u8>, serde_json::Value)> {
        let started = Instant::now();
        let request: Request = decode(wire)?;
        if request.head.as_slice() != self.data.commitment().encode()
            || request.rows == 0
            || request.rows > 256
            || request.rows != self.data.commitment().layout().row_count as usize
            || request.stride != request.rows.next_power_of_two()
            || 16 * request.stride > self.parameters.degree() / 2
            || matches!(request.predicate, Predicate::Range) != request.upper.is_some()
        {
            return Err("Invalid public request shape or stale head".into());
        }
        let a = Ciphertext::from_bytes(&request.age, &self.parameters)?;
        let lower = Ciphertext::from_bytes(&request.lower, &self.parameters)?;
        let upper = request
            .upper
            .as_ref()
            .map(|v| Ciphertext::from_bytes(v, &self.parameters))
            .transpose()?;
        let values = Ciphertext::from_bytes(&request.values, &self.parameters)?;
        let decode_ms = elapsed(started);
        let started = Instant::now();
        let mut counters = Counters {
            multiplications: 0,
            rotations: 0,
        };
        let selected = match request.predicate {
            Predicate::Equal => self.equal(&a, &lower, request.stride, &mut counters)?,
            Predicate::AtLeast => self.greater_equal(&a, &lower, request.stride, &mut counters)?,
            Predicate::Range => {
                let lo = self.greater_equal(&a, &lower, request.stride, &mut counters)?;
                let hi =
                    self.greater_equal(upper.as_ref().unwrap(), &a, request.stride, &mut counters)?;
                if self.additive_range {
                    // OWNER rejected reversed bounds before encryption. For lo<=hi,
                    // GE(age,lo)+GE(hi,age)-1 equals the closed-range bit.
                    let ones = Plaintext::try_encode(
                        &vec![1u64; self.parameters.degree()],
                        Encoding::simd(),
                        &self.parameters,
                    )?;
                    let mut selected = &lo + &hi;
                    selected -= &ones;
                    selected
                } else {
                    self.multiply(&lo, &hi, &mut counters)?
                }
            }
        };
        // Only group base blocks carry values; COUNT occupies row0/group1.
        let mut sums = self.multiply(&selected, &values, &mut counters)?;
        let mut shift = 1;
        while shift < request.stride {
            let rotated = self.rotate(&sums, shift, &mut counters)?;
            sums += &rotated;
            shift *= 2;
        }
        sums.switch_to_level(self.output_level)?;
        let evaluate_ms = elapsed(started);
        let started = Instant::now();
        let output = encode(&Output {
            query_id: request.query_id,
            head: request.head,
            rows: request.rows,
            count_sum: sums.to_bytes(),
        })?;
        Ok((
            output,
            json!({
                "peer_request_decode_ms": decode_ms,
                "peer_evaluate_ms": evaluate_ms,
                "peer_output_encode_ms": elapsed(started),
                "ct_ct_multiplications": counters.multiplications,
                "rotations": counters.rotations,
                "multiplicative_depth": if matches!(request.predicate, Predicate::Range) && !self.additive_range { 6 } else { 5 }
            }),
        ))
    }
}

#[derive(Clone, Copy)]
struct Row {
    age: u8,
    amount: u16,
}
fn elapsed(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.0
}
fn encode<T: Serialize>(v: &T) -> Result<Vec<u8>> {
    Ok(bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(WIRE_LIMIT)
        .serialize(v)?)
}
fn decode<T: serde::de::DeserializeOwned>(v: &[u8]) -> Result<T> {
    if v.len() > WIRE_LIMIT as usize {
        return Err("Wire exceeds experiment bound".into());
    }
    Ok(bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(WIRE_LIMIT)
        .reject_trailing_bytes()
        .deserialize(v)?)
}
fn planes(rows: &[Row], threshold: Option<u8>, n: usize, stride: usize) -> Zeroizing<Vec<u64>> {
    let mut out = Zeroizing::new(vec![0; n]);
    for (index, row) in rows.iter().enumerate() {
        let value = threshold.unwrap_or(row.age);
        for bit in 0..8 {
            let value = u64::from((value >> (7 - bit)) & 1);
            for group in [0, 8 * stride, n / 2, n / 2 + 8 * stride] {
                out[group + bit * stride + index] = value;
            }
        }
    }
    out
}
fn encrypted(values: &[u64], key: &SecretKey, par: &Arc<BfvParameters>) -> Result<Vec<u8>> {
    let pt = Plaintext::try_encode(values, Encoding::simd(), par)?;
    let ct: Ciphertext = key.try_encrypt(&pt, &mut rand::rng())?;
    Ok(ct.to_bytes())
}
fn fetch_owner_rows(
    owner: &PageOwner,
    peer: &Peer,
    head: &Commitment,
) -> Result<(Vec<Row>, usize)> {
    let limits = Limits::default();
    let mut rows = Vec::new();
    let mut wire_bytes = 0;
    for page in 0..head.layout().page_count()? {
        let wire = peer.data.lookup(page as u64, limits)?.encode();
        wire_bytes += wire.len();
        let verified = LookupResponse::decode(&wire, limits)?.verify(head, page as u64, limits)?;
        let plain = owner.decrypt(&verified)?;
        for value in plain.as_bytes().as_chunks::<3>().0 {
            rows.push(Row {
                age: value[0],
                amount: u16::from_le_bytes([value[1], value[2]]),
            });
        }
    }
    Ok((rows, wire_bytes))
}
fn fixture(count: usize, kind: &str) -> Vec<Row> {
    (0..count)
        .map(|i| Row {
            age: [0, 255, 17, 18, 42, 127, 128, 254][i % 8],
            amount: match kind {
                "allmax" => u16::MAX,
                "allzero" => 0,
                "all255" => 255,
                "all256" => 256,
                "all65280" => 65_280,
                "byteedges" => [0, 1, 255, 256, 257, 65_280, 65_534, 65_535][i % 8],
                _ => ((i * 257 + 19) % 65_536) as u16,
            },
        })
        .collect()
}
fn expected(rows: &[Row], predicate: Predicate, lower: u8, upper: u8) -> (u64, u64) {
    rows.iter()
        .filter(|r| match predicate {
            Predicate::Equal => r.age == lower,
            Predicate::AtLeast => r.age >= lower,
            Predicate::Range => lower <= r.age && r.age <= upper,
        })
        .fold((0, 0), |(count, sum), r| {
            (count + 1, sum + u64::from(r.amount))
        })
}
fn parse<T: std::str::FromStr>(args: &[String], flag: &str, default: T) -> Result<T> {
    match args.iter().position(|v| v == flag) {
        None => Ok(default),
        Some(i) => args
            .get(i + 1)
            .ok_or("Missing argument")?
            .parse()
            .map_err(|_| "Invalid argument".into()),
    }
}
fn enforce_memory_budget() -> Result<()> {
    let memory = metrics::native_memory();
    for field in ["peak_working_set_bytes", "peak_commit_bytes"] {
        if memory
            .get(field)
            .and_then(|v| v.as_u64())
            .is_some_and(|v| v >= 2_000_000_000)
        {
            eprintln!(
                "{}",
                json!({"event": "resource_failure", "native_memory": memory})
            );
            return Err("Native process peak exceeds the 2 GB experiment cap".into());
        }
    }
    Ok(())
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    let noise_diagnostics = args.iter().any(|arg| arg == "--noise-diagnostic");
    let degree = parse(&args, "--degree", 8192usize)?;
    let fused_ge = args.iter().any(|arg| arg == "--fused-ge");
    let additive_range = args.iter().any(|arg| arg == "--additive-range");
    let output_level = parse(&args, "--output-level", 0usize)?;
    let count = parse(&args, "--rows", 16usize)?;
    let samples = parse(&args, "--samples", 1usize)?;
    let lower = parse(&args, "--lower", 18u8)?;
    let upper = parse(&args, "--upper", 255u8)?;
    let kind = parse(&args, "--fixture", String::from("mixed"))?;
    let predicate = match parse(&args, "--predicate", String::from("ge"))?.as_str() {
        "eq" => Predicate::Equal,
        "ge" => Predicate::AtLeast,
        "range" => Predicate::Range,
        _ => return Err("Use --predicate eq|ge|range".into()),
    };
    if degree != 8192
        || output_level > 4
        || !matches!(count, 16 | 256)
        || !(1..=20).contains(&samples)
        || lower > upper
        || !matches!(
            kind.as_str(),
            "mixed" | "allmax" | "byteedges" | "allzero" | "all255" | "all256" | "all65280"
        )
    {
        return Err(
            "Use official degree8192, output-level0..4, rows16/256, samples1..20, valid bounds/fixture".into(),
        );
    }
    let started = Instant::now();
    // Keep the release's prescribed secret/error distributions and complete Q profile.
    // Upstream labels these ABOUT 128 bits; this is not independent validation.
    let parameters = BfvParameters::default_parameters_128(17)?
        .find(|p| p.degree() == degree)
        .ok_or("Missing official profile")?;
    if parameters.plaintext() <= LIMB_SUM_BOUND || parameters.plaintext() % (2 * degree as u64) != 1
    {
        return Err("Profile does not support the required exact sum and SIMD".into());
    }
    let stride = count.next_power_of_two();
    let key = SecretKey::random(&parameters, &mut rand::rng());
    let mut shifts = BTreeSet::from([stride, 2 * stride, 4 * stride]);
    let mut shift = 1;
    while shift < stride {
        shifts.insert(shift);
        shift *= 2;
    }
    let (relin_wire, rotation_wire) = {
        let relin = RelinearizationKey::new(&key, &mut rand::rng())?;
        let mut builder = EvaluationKeyBuilder::new(&key)?;
        for shift in &shifts {
            builder.enable_column_rotation(*shift)?;
        }
        let rotations = builder.build(&mut rand::rng())?;
        drop(builder); // It temporarily held a secret-key clone during OWNER setup.
        (relin.to_bytes(), rotations.to_bytes())
    };
    let relin = RelinearizationKey::from_bytes(&relin_wire, &parameters)?;
    let rotations = EvaluationKey::from_bytes(&rotation_wire, &parameters)?;
    let owner_key_bytes = Zeroizing::new(key.to_bytes()).len();
    let owner = PageOwner::generate(*b"PUBLIC-BFV-PROBE")?;
    let rows = fixture(count, &kind);
    let mut canonical = Zeroizing::new(Vec::with_capacity(3 * count));
    for row in &rows {
        canonical.push(row.age);
        canonical.extend_from_slice(&row.amount.to_le_bytes());
    }
    let data = owner.seal(
        Layout {
            schema: *b"BFVAGEAMOUNT0001",
            row_width: 3,
            rows_per_page: 256,
            row_count: count as u64,
        },
        &canonical,
        Limits::default(),
    )?;
    let head = data.commitment().clone();
    let canonical_bytes = data.encoded_len();
    let hash_bytes = data.index_hash_bytes();
    let peer = Peer {
        parameters: parameters.clone(),
        relin,
        rotations,
        data,
        fused_ge,
        additive_range,
        output_level,
    };
    println!(
        "{}",
        json!({
            "event": "setup", "library": "fhe=0.1.1", "degree": degree,
        "optimized_ntt": cfg!(feature = "optimized-ntt"), "fused_ge": fused_ge,
        "additive_range": additive_range,
        "output_level": output_level, "native_peak_cap_bytes": 2_000_000_000u64,
            "plaintext_modulus": parameters.plaintext(), "coefficient_moduli": parameters.moduli(),
            "coefficient_moduli_bits": parameters.moduli_sizes(), "level": 0,
            "profile": "upstream default_parameters_128(17), unchanged CBD variance10",
            "packing": "byte low/high/count in three of four repeated predicate groups",
            "security_gate": "upstream_about128_not_independently_validated",
            "noise_gate": "exact public fixture checks only; no worst-case noise proof",
            "setup_ms": elapsed(started), "public_parameter_bytes": parameters.to_bytes().len(),
            "relinearization_key_bytes": relin_wire.len(), "rotation_key_bytes": rotation_wire.len(),
            "rotation_steps": shifts, "owner_bfv_secret_key_serialized_bytes": owner_key_bytes,
            "owner_compact_key_database_domain_bytes": 64, "trusted_head_bytes": compact_store::MANIFEST_BYTES,
            "canonical_data_bytes": canonical_bytes, "rebuildable_hash_payload_bytes": hash_bytes,
            "peak_whole_process_resident_bytes": metrics::peak_resident_bytes(),
            "native_memory": metrics::native_memory(),
            "proof": "unavailable"
        })
    );
    enforce_memory_budget()?;
    drop(relin_wire);
    drop(rotation_wire);
    drop(canonical);
    // Oracle is used only AFTER the timed encrypted operation, on explicitly public fixtures.
    for sample in 0..samples {
        let whole = Instant::now();
        let started = Instant::now();
        let (fetched, page_bytes) = fetch_owner_rows(&owner, &peer, &head)?;
        let fetch_ms = elapsed(started);
        let started = Instant::now();
        let age = planes(&fetched, None, degree, stride);
        let lower_bits = planes(&fetched, Some(lower), degree, stride);
        let mut values = Zeroizing::new(vec![0; degree]);
        for (i, row) in fetched.iter().enumerate() {
            values[i] = u64::from(row.amount & 255);
            values[degree / 2 + i] = u64::from(row.amount >> 8);
            values[8 * stride + i] = 1;
        }
        let query_id = rand::random();
        let request = Request {
            query_id,
            head: head.encode().to_vec(),
            rows: count,
            stride,
            predicate,
            age: encrypted(&age, &key, &parameters)?,
            lower: encrypted(&lower_bits, &key, &parameters)?,
            upper: if matches!(predicate, Predicate::Range) {
                Some(encrypted(
                    &planes(&fetched, Some(upper), degree, stride),
                    &key,
                    &parameters,
                )?)
            } else {
                None
            },
            values: encrypted(&values, &key, &parameters)?,
        };
        let owner_prepare_ms = elapsed(started);
        let started = Instant::now();
        let request_wire = encode(&request)?;
        let request_encode_ms = elapsed(started);
        drop(request);
        let (output_wire, peer_stages) = peer.evaluate(&request_wire)?;
        let started = Instant::now();
        let output: Output = decode(&output_wire)?;
        if output.query_id != query_id || output.head != head.encode() || output.rows != count {
            return Err("Wrong output binding".into());
        }
        let ciphertext = Ciphertext::from_bytes(&output.count_sum, &parameters)?;
        let plaintext = key.try_decrypt(&ciphertext)?;
        let decoded = Vec::<u64>::try_decode(&plaintext, Encoding::simd())?;
        let low_sum = decoded[0];
        let high_sum = decoded[degree / 2];
        let count_sum = decoded[8 * stride];
        let actual = (count_sum, low_sum + 256 * high_sum);
        let in_bounds = actual.0 <= count as u64
            && actual.1 <= SUM_BOUND
            && low_sum <= LIMB_SUM_BOUND
            && high_sum <= LIMB_SUM_BOUND
            && low_sum <= 255 * count_sum
            && high_sum <= 255 * count_sum;
        let count_u32 = u32::try_from(actual.0)?;
        let sum_u32 = u32::try_from(actual.1)?;
        let owner_output_ms = elapsed(started);
        let whole_ms = elapsed(whole);
        let correct = in_bounds && actual == expected(&fetched, predicate, lower, upper);
        let noise = if noise_diagnostics {
            let started = Instant::now();
            // SAFETY: owner-local diagnostic on this probe's fresh keys and public
            // fixtures only. Variable-time noise measurement is excluded from timing
            // and never exposed as a production verifier/decryption oracle.
            let noise_bits = unsafe { key.measure_noise(&ciphertext)? };
            let nominal_limit = parameters.moduli()[..parameters.moduli().len() - output_level]
                .iter()
                .map(|q| (*q as f64).log2())
                .sum::<f64>()
                - (parameters.plaintext() as f64).log2()
                - 1.0;
            json!({"library_noise_bits": noise_bits,
                "nominal_log2_q_over_2t": nominal_limit,
                "nominal_margin_bits": nominal_limit - noise_bits as f64,
                "owner_diagnostic_ms_outside_query": elapsed(started),
                "worst_case_noise_bound": false})
        } else {
            serde_json::Value::Null
        };
        println!(
            "{}",
            json!({
                "event": "query", "sample": sample, "cold": sample == 0, "rows": count,
                "predicate": format!("{predicate:?}"), "lower": lower, "upper": upper, "fixture": kind,
                "count": count_u32, "sum": sum_u32, "exact_fixture_check": correct,
            "low_limb_sum": low_sum, "high_limb_sum": high_sum,
            "unsigned_contract_bounds": in_bounds, "noise_diagnostic": noise,
                "owner_page_fetch_auth_decrypt_ms": fetch_ms, "page_response_bytes": page_bytes,
                "owner_pack_encrypt_ms": owner_prepare_ms, "request_encode_ms": request_encode_ms,
                "request_bytes": request_wire.len(), "output_bytes": output_wire.len(),
                "owner_output_decode_decrypt_ms": owner_output_ms, "peer": peer_stages,
                "whole_local_owner_to_owner_ms": whole_ms, "network_latency_measured": false,
                "total_query_wire_bytes": page_bytes + request_wire.len() + output_wire.len(),
                "peak_whole_process_resident_bytes": metrics::peak_resident_bytes(),
            "native_memory": metrics::native_memory(),
                "proof": "unavailable"
            })
        );
        enforce_memory_budget()?;
        if !correct {
            return Err("Exact output/noise gate failed; do not report successful latency".into());
        }
    }
    Ok(())
}
