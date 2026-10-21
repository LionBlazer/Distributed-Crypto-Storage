//! Public-fixture arithmetic falsifier only; never a proof, SQL result or peer service.
#![forbid(unsafe_code)]
use fhe::bfv::{BfvParameters, BfvParametersBuilder, Ciphertext, Encoding, Plaintext, SecretKey};
use fhe_traits::{
    DeserializeParametrized, FheDecoder, FheDecrypter, FheEncoder, FheEncrypter, Serialize,
};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::{error::Error, hint::black_box, io, sync::Arc, time::Instant};
use zeroize::{Zeroize, Zeroizing};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const STRIDE: usize = 512;
const ROWS: usize = 4;
const LANES: usize = 2 * ROWS;
const MAX_CIPHERTEXT: usize = 1024 * 1024;
const REQUEST_HEADER: usize = 88;
const RESPONSE_HEADER: usize = 80;
const REQUEST_MAGIC: &[u8; 8] = b"UNSELR01";
const RESPONSE_MAGIC: &[u8; 8] = b"UNSELO01";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Row {
    age: u8,
    amount: u16,
}
// Explicitly PUBLIC NONSECRET inputs. No file, database, credential or participant input is accepted.
const PUBLIC_ROWS: [Row; ROWS] = [
    Row {
        age: 0,
        amount: 65535,
    },
    Row { age: 1, amount: 0 },
    Row {
        age: 128,
        amount: 255,
    },
    Row {
        age: 255,
        amount: 65534,
    },
];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Profile {
    Baseline,
    Candidate,
}
impl Profile {
    fn name(self) -> &'static str {
        match self {
            Self::Baseline => "n8192_q218_parameter_basis_new2lane_noRK",
            Self::Candidate => "n4096_q60_new2lane_noRK_candidate",
        }
    }
    fn parameters(self) -> Result<Arc<BfvParameters>> {
        let mut builder = BfvParametersBuilder::new();
        match self {
            Self::Baseline => {
                builder
                    .set_degree(8192)
                    .set_plaintext_modulus(114689)
                    .set_moduli(&bfv_fixed_geometry::MODULI);
            }
            Self::Candidate => {
                builder
                    .set_degree(4096)
                    .set_plaintext_modulus(65537)
                    .set_moduli_sizes(&[30, 30]);
            }
        }
        Ok(builder.set_variance(10).build_arc()?)
    }
}
#[derive(Clone, Copy, Debug)]
enum Case {
    All,
    None,
    Ge128,
}
impl Case {
    fn parse(text: &str) -> Result<Self> {
        match text {
            "all" => Ok(Self::All),
            "none" => Ok(Self::None),
            "ge128" => Ok(Self::Ge128),
            _ => Err(invalid("case must be all, none or ge128").into()),
        }
    }
    // Compiles only the public age domain. It receives neither Source rows nor answers.
    fn private_mask(self) -> Zeroizing<[u8; 32]> {
        let mut mask = Zeroizing::new([0; 32]);
        for age in 0..256 {
            let matches = match self {
                Self::All => true,
                Self::None => false,
                Self::Ge128 => age >= 128,
            };
            if matches {
                mask[age / 8] |= 1 << (age % 8);
            }
        }
        mask
    }
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn ms(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.
}
fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn id(parameters: &BfvParameters) -> [u8; 32] {
    digest(&parameters.to_bytes())
}
fn source_polynomial(degree: usize, rows: &[Row; ROWS]) -> Zeroizing<Vec<u64>> {
    let mut values = Zeroizing::new(vec![0; degree]);
    for (ordinal, row) in rows.iter().enumerate() {
        values[(2 * ordinal) * STRIDE + usize::from(row.age)] = 256 + u64::from(row.age);
        values[(2 * ordinal + 1) * STRIDE + usize::from(row.age)] = u64::from(row.amount);
    }
    values
}
fn mask_polynomial(degree: usize, mask: &[u8; 32]) -> Zeroizing<Vec<u64>> {
    let mut values = Zeroizing::new(vec![0; degree]);
    for age in 0..256 {
        values[255 - age] = u64::from((mask[age / 8] >> (age % 8)) & 1);
    }
    values
}
#[derive(Default)]
struct InputTimes {
    encode_ms: f64,
    encrypt_ms: f64,
    wire_ms: f64,
}
fn encrypt(
    parameters: &Arc<BfvParameters>,
    key: &SecretKey,
    values: &[u64],
) -> Result<(Vec<u8>, InputTimes)> {
    let mut times = InputTimes::default();
    let start = Instant::now();
    let plaintext = Zeroizing::new(Plaintext::try_encode(values, Encoding::poly(), parameters)?);
    times.encode_ms = ms(start);
    let start = Instant::now();
    let ciphertext: Ciphertext = key.try_encrypt(&*plaintext, &mut rand::rng())?;
    times.encrypt_ms = ms(start);
    let start = Instant::now();
    let bytes = ciphertext.to_bytes();
    if bytes.len() > MAX_CIPHERTEXT {
        return Err(invalid("ciphertext cap").into());
    }
    times.wire_ms = ms(start);
    Ok((bytes, times))
}
fn canonical_ciphertext(
    parameters: &Arc<BfvParameters>,
    bytes: &[u8],
    parts: usize,
) -> Result<Ciphertext> {
    if bytes.is_empty() || bytes.len() > MAX_CIPHERTEXT {
        return Err(invalid("ciphertext extent").into());
    }
    let ciphertext = Ciphertext::from_bytes(bytes, parameters)?;
    if ciphertext.len() != parts || ciphertext.to_bytes() != bytes {
        return Err(invalid("noncanonical ciphertext or component count").into());
    }
    for polynomial in ciphertext.iter() {
        if polynomial.ctx().moduli() != parameters.moduli() {
            return Err(invalid("ordered modulus or level mismatch").into());
        }
        let coefficients = polynomial.coefficients();
        if coefficients.nrows() != parameters.moduli().len()
            || coefficients.ncols() != parameters.degree()
        {
            return Err(invalid("polynomial geometry").into());
        }
        for (row, q) in coefficients.outer_iter().zip(parameters.moduli()) {
            if row.iter().any(|c| c >= q) {
                return Err(invalid("noncanonical modulus coefficient").into());
            }
        }
    }
    Ok(ciphertext)
}
struct Pending {
    parameters: [u8; 32],
    request: [u8; 32],
}
struct Prepared {
    request: Vec<u8>,
    pending: Pending,
    source_ms: f64,
    mask_ms: f64,
    binding_ms: f64,
    source_prepare_ms: f64,
    mask_prepare_ms: f64,
    source_input: InputTimes,
    mask_input: InputTimes,
}
fn prepare(
    parameters: &Arc<BfvParameters>,
    key: &SecretKey,
    rows: &[Row; ROWS],
    case: Case,
) -> Result<Prepared> {
    let start = Instant::now();
    let prepare_start = Instant::now();
    let values = source_polynomial(parameters.degree(), rows);
    let source_prepare_ms = ms(prepare_start);
    let (original, source_input) = encrypt(parameters, key, &values)?;
    drop(values);
    let source_ms = ms(start);
    let start = Instant::now();
    let prepare_start = Instant::now();
    let mask = case.private_mask();
    let values = mask_polynomial(parameters.degree(), &mask);
    let mask_prepare_ms = ms(prepare_start);
    let (predicate, mask_input) = encrypt(parameters, key, &values)?;
    drop(values);
    let mask_ms = ms(start);
    let start = Instant::now();
    let parameter_id = id(parameters);
    let mut request = Vec::with_capacity(REQUEST_HEADER + original.len() + predicate.len());
    request.extend_from_slice(REQUEST_MAGIC);
    request.extend_from_slice(&parameter_id);
    let mut nonce = [0; 32];
    rand::rng().fill_bytes(&mut nonce);
    request.extend_from_slice(&nonce);
    request.extend_from_slice(&u32::try_from(original.len())?.to_le_bytes());
    request.extend_from_slice(&u32::try_from(predicate.len())?.to_le_bytes());
    request.extend_from_slice(&[0; 8]);
    request.extend_from_slice(&original);
    request.extend_from_slice(&predicate);
    let pending = Pending {
        parameters: parameter_id,
        request: digest(&request),
    };
    Ok(Prepared {
        request,
        pending,
        source_ms,
        mask_ms,
        binding_ms: ms(start),
        source_prepare_ms,
        mask_prepare_ms,
        source_input,
        mask_input,
    })
}
fn read_u32(bytes: &[u8], at: usize) -> usize {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) as usize
}
fn request_inputs<'a>(wire: &'a [u8], expected: &[u8; 32]) -> Result<(&'a [u8], &'a [u8])> {
    if wire.len() < REQUEST_HEADER
        || wire.len() > REQUEST_HEADER + 2 * MAX_CIPHERTEXT
        || &wire[..8] != REQUEST_MAGIC
        || wire[8..40] != *expected
        || wire[80..88] != [0; 8]
    {
        return Err(invalid("request header, parameter, cap or padding").into());
    }
    let a = read_u32(wire, 72);
    let b = read_u32(wire, 76);
    if a == 0
        || b == 0
        || a > MAX_CIPHERTEXT
        || b > MAX_CIPHERTEXT
        || REQUEST_HEADER.checked_add(a).and_then(|n| n.checked_add(b)) != Some(wire.len())
    {
        return Err(invalid("request lengths or EOF").into());
    }
    Ok((
        &wire[REQUEST_HEADER..REQUEST_HEADER + a],
        &wire[REQUEST_HEADER + a..],
    ))
}
#[derive(Default)]
struct PeerTimes {
    decode_ms: f64,
    product_ms: f64,
    serialize_ms: f64,
}
// This peer-facing role has only parameters. No SecretKey, plaintext, row, mask or callback.
struct Evaluator {
    parameters: Arc<BfvParameters>,
}
impl Evaluator {
    fn evaluate(&self, wire: &[u8]) -> Result<(Vec<u8>, PeerTimes)> {
        let mut times = PeerTimes::default();
        let start = Instant::now();
        let parameter_id = id(&self.parameters);
        let (a, b) = request_inputs(wire, &parameter_id)?;
        let a = canonical_ciphertext(&self.parameters, a, 2)?;
        let b = canonical_ciphertext(&self.parameters, b, 2)?;
        times.decode_ms = ms(start);
        eprintln!(
            "unrelinearized_probe phase=product_start degree={}",
            self.parameters.degree()
        );
        let start = Instant::now();
        let product = &a * &b; // Real SDK multiplication, deliberately WITHOUT relinearization.
        times.product_ms = ms(start);
        eprintln!(
            "unrelinearized_probe phase=product_end degree={}",
            self.parameters.degree()
        );
        let start = Instant::now();
        let ciphertext = product.to_bytes();
        if product.len() != 3 || ciphertext.len() > MAX_CIPHERTEXT {
            return Err(invalid("three-component result extent").into());
        }
        let mut response = Vec::with_capacity(RESPONSE_HEADER + ciphertext.len());
        response.extend_from_slice(RESPONSE_MAGIC);
        response.extend_from_slice(&parameter_id);
        response.extend_from_slice(&digest(wire));
        response.extend_from_slice(&u32::try_from(ciphertext.len())?.to_le_bytes());
        response.extend_from_slice(&[0; 4]);
        response.extend_from_slice(&ciphertext);
        times.serialize_ms = ms(start);
        Ok((response, times))
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DecodedRow {
    ordinal: u8,
    present: bool,
    age: u8,
    amount: u16,
}
impl Zeroize for DecodedRow {
    fn zeroize(&mut self) {
        self.ordinal.zeroize();
        self.present.zeroize();
        self.age.zeroize();
        self.amount.zeroize();
    }
}
fn decode_rows(values: &[u64], degree: usize) -> Result<[DecodedRow; ROWS]> {
    if !matches!(degree, 4096 | 8192) || values.len() != degree {
        return Err(invalid("decoded degree").into());
    }
    // Full coefficient shape only. Never read originals or reevaluate a predicate.
    for (at, value) in values.iter().enumerate() {
        let lane = at / STRIDE;
        let bound = if lane < LANES && at % STRIDE <= 510 {
            if lane.is_multiple_of(2) { 511 } else { 65535 }
        } else {
            0
        };
        if *value > bound {
            return Err(invalid("full polynomial bound or reserved coefficient").into());
        }
    }
    let mut rows = [DecodedRow {
        ordinal: 0,
        present: false,
        age: 0,
        amount: 0,
    }; ROWS];
    for (ordinal, row) in rows.iter_mut().enumerate() {
        let at = 2 * ordinal * STRIDE + 255;
        let packed = values[at];
        let amount = values[at + STRIDE];
        if (packed == 0 && amount != 0) || (packed != 0 && !(256..=511).contains(&packed)) {
            return Err(invalid("packed presence and age").into());
        }
        *row = DecodedRow {
            ordinal: ordinal as u8,
            present: packed != 0,
            age: if packed == 0 { 0 } else { (packed - 256) as u8 },
            amount: amount as u16,
        };
    }
    Ok(rows)
}
#[derive(Default)]
struct ClientTimes {
    response_decode_ms: f64,
    decrypt_ms: f64,
    plaintext_decode_ms: f64,
    full_check_ms: f64,
}
struct UnverifiedCompletion {
    rows: [DecodedRow; ROWS],
    values: Zeroizing<Vec<u64>>,
    times: ClientTimes,
}
impl Drop for UnverifiedCompletion {
    fn drop(&mut self) {
        self.rows.zeroize();
    }
}
fn complete(
    parameters: &Arc<BfvParameters>,
    key: &SecretKey,
    pending: Pending,
    response: &[u8],
) -> Result<UnverifiedCompletion> {
    let mut times = ClientTimes::default();
    let start = Instant::now();
    if pending.parameters != id(parameters)
        || response.len() < RESPONSE_HEADER
        || response.len() > RESPONSE_HEADER + MAX_CIPHERTEXT
        || &response[..8] != RESPONSE_MAGIC
        || response[8..40] != pending.parameters
        || response[40..72] != pending.request
        || response[76..80] != [0; 4]
        || RESPONSE_HEADER.checked_add(read_u32(response, 72)) != Some(response.len())
    {
        return Err(invalid("response binding, length or EOF").into());
    }
    let ciphertext = canonical_ciphertext(parameters, &response[RESPONSE_HEADER..], 3)?;
    times.response_decode_ms = ms(start);
    let start = Instant::now();
    let plaintext = Zeroizing::new(key.try_decrypt(&ciphertext)?);
    times.decrypt_ms = ms(start);
    let start = Instant::now();
    let values = Zeroizing::new(Vec::<u64>::try_decode(&plaintext, Encoding::poly())?);
    times.plaintext_decode_ms = ms(start);
    let start = Instant::now();
    let rows = decode_rows(&values, parameters.degree())?;
    times.full_check_ms = ms(start);
    Ok(UnverifiedCompletion {
        rows,
        values,
        times,
    })
}
struct Observation {
    source_ms: f64,
    mask_ms: f64,
    binding_ms: f64,
    source_prepare_ms: f64,
    mask_prepare_ms: f64,
    source_input: InputTimes,
    mask_input: InputTimes,
    peer: PeerTimes,
    client_ms: f64,
    math_ms: f64,
    request_bytes: usize,
    response_bytes: usize,
    response_digest: [u8; 32],
}
fn observe(
    parameters: &Arc<BfvParameters>,
    key: &SecretKey,
    case: Case,
) -> Result<(Observation, UnverifiedCompletion)> {
    let whole = Instant::now();
    let prepared = prepare(parameters, key, &PUBLIC_ROWS, case)?;
    let evaluator = Evaluator {
        parameters: parameters.clone(),
    };
    let (response, peer) = evaluator.evaluate(&prepared.request)?;
    let client = Instant::now();
    let rows = complete(parameters, key, prepared.pending, &response)?;
    let client_ms = ms(client);
    let math_ms = ms(whole);
    Ok((
        Observation {
            source_ms: prepared.source_ms,
            mask_ms: prepared.mask_ms,
            binding_ms: prepared.binding_ms,
            source_prepare_ms: prepared.source_prepare_ms,
            mask_prepare_ms: prepared.mask_prepare_ms,
            source_input: prepared.source_input,
            mask_input: prepared.mask_input,
            peer,
            client_ms,
            math_ms,
            request_bytes: prepared.request.len(),
            response_bytes: response.len(),
            response_digest: digest(&response),
        },
        rows,
    ))
}
fn arguments() -> Result<(Vec<Profile>, Case)> {
    let mut mode = "pair".to_owned();
    let mut case = Case::All;
    let mut seen_mode = false;
    let mut seen_case = false;
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| invalid("each flag requires a value"))?;
        match flag.as_str() {
            "--mode" if !seen_mode => {
                mode = value;
                seen_mode = true;
            }
            "--case" if !seen_case => {
                case = Case::parse(&value)?;
                seen_case = true;
            }
            _ => return Err(invalid("only --mode and --case are supported once each").into()),
        }
    }
    let profiles = match mode.as_str() {
        "pair" => vec![Profile::Baseline, Profile::Candidate],
        "baseline" => vec![Profile::Baseline],
        "candidate" => vec![Profile::Candidate],
        _ => return Err(invalid("mode must be pair, baseline or candidate").into()),
    };
    Ok((profiles, case))
}
fn main() -> Result<()> {
    let (profiles, case) = arguments()?;
    for profile in profiles {
        let start = Instant::now();
        let parameters = profile.parameters()?;
        let parameters_ms = ms(start);
        let start = Instant::now();
        let key = SecretKey::random(&parameters, &mut rand::rng());
        let key_ms = ms(start);
        let (o, completion) = observe(&parameters, &key, case)?;
        black_box(&completion.rows);
        black_box(&completion.values);
        let source = serde_json::json!({
            "prepare_ms": o.source_prepare_ms, "plaintext_encode_ms": o.source_input.encode_ms,
            "encrypt_ms": o.source_input.encrypt_ms, "wire_ms": o.source_input.wire_ms,
            "total_ms": o.source_ms
        });
        let mask = serde_json::json!({
            "compile_prepare_ms": o.mask_prepare_ms, "plaintext_encode_ms": o.mask_input.encode_ms,
            "encrypt_ms": o.mask_input.encrypt_ms, "wire_ms": o.mask_input.wire_ms,
            "total_ms": o.mask_ms
        });
        let peer = serde_json::json!({
            "request_decode_ms": o.peer.decode_ms, "product_wall_ms": o.peer.product_ms,
            "response_wire_ms": o.peer.serialize_ms
        });
        let client = serde_json::json!({
            "response_binding_decode_ms": completion.times.response_decode_ms,
            "decrypt_ms": completion.times.decrypt_ms,
            "plaintext_decode_ms": completion.times.plaintext_decode_ms,
            "full_coefficient_check_ms": completion.times.full_check_ms,
            "total_ms": o.client_ms
        });
        let timing = serde_json::json!({
            "parameters_ms": parameters_ms, "secret_key_ms": key_ms,
            "source": source, "mask": mask, "request_binding_ms": o.binding_ms,
            "peer": peer, "client": client, "math_full_wall_ms": o.math_ms,
            "setup_plus_math_wall_ms": parameters_ms + key_ms + o.math_ms
        });
        let parameter = serde_json::json!({
            "degree": parameters.degree(), "moduli": parameters.moduli(),
            "moduli_bits": parameters.moduli_sizes(), "plaintext_modulus": parameters.plaintext(),
            "sha256": hex(&id(&parameters))
        });
        let wire = serde_json::json!({
            "request_bytes": o.request_bytes, "response_bytes": o.response_bytes,
            "response_sha256": hex(&o.response_digest)
        });
        let operations = serde_json::json!({
            "products": 1, "output_components": 3, "relinearizations": 0, "rotations": 0
        });
        println!(
            "{}",
            serde_json::json!({
                "kind": "unrelinearized_math_observation", "profile": profile.name(),
                "operation": "experimental_packed2lane_depth1_noRK",
                "current_production_operation_measured": false,
                "parameter": parameter, "timing": timing, "wire": wire, "operations": operations,
                "sample_math_exceeds_full_500ms_target": o.math_ms > 500.,
                "proof_verified": false, "sql_accepted": false, "security_assessed": false,
                "noise_certified": false, "cpu_and_peak_memory_require_external_sampler": true
            })
        );
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    // Independent plaintext ring multiplication is TEST-ONLY and uses explicitly public operands.
    fn public_convolution_oracle(parameters: &BfvParameters, case: Case) -> Vec<u64> {
        let n = parameters.degree();
        let t = parameters.plaintext();
        let a = source_polynomial(n, &PUBLIC_ROWS);
        let b = mask_polynomial(n, &case.private_mask());
        let mut out = vec![0u64; n];
        for (i, x) in a.iter().enumerate().filter(|(_, x)| **x != 0) {
            for (j, y) in b.iter().enumerate().filter(|(_, y)| **y != 0) {
                let term = ((*x as u128 * *y as u128) % t as u128) as u64;
                let at = (i + j) % n;
                out[at] = if i + j < n {
                    (out[at] + term) % t
                } else {
                    (out[at] + t - term) % t
                };
            }
        }
        out
    }
    #[test]
    fn encrypted_all_none_and_hidden_boundary_return_exact_original_ordinals() -> Result<()> {
        for profile in [Profile::Baseline, Profile::Candidate] {
            let parameters = profile.parameters()?;
            let key = SecretKey::random(&parameters, &mut rand::rng());
            for (case, selected) in [
                (Case::All, [true, true, true, true]),
                (Case::None, [false; ROWS]),
                (Case::Ge128, [false, false, true, true]),
            ] {
                // Act: every answer comes from real encrypted multiplication and client decryption.
                let (_, actual) = observe(&parameters, &key, case)?;
                // Public, test-only oracle; never used by Evaluator or client completion.
                let expected: [DecodedRow; ROWS] = std::array::from_fn(|i| DecodedRow {
                    ordinal: i as u8,
                    present: selected[i],
                    age: if selected[i] { PUBLIC_ROWS[i].age } else { 0 },
                    amount: if selected[i] {
                        PUBLIC_ROWS[i].amount
                    } else {
                        0
                    },
                });
                assert_eq!(actual.rows, expected);
                let expected_polynomial = public_convolution_oracle(&parameters, case);
                assert!(
                    actual.values.as_slice() == expected_polynomial.as_slice(),
                    "genuine SDK product differs at a full polynomial coefficient"
                );
            }
        }
        Ok(())
    }
    #[test]
    fn decoded_reserved_tail_and_impossible_presence_are_rejected() {
        let mut values = vec![0; 4096];
        values[4095] = 1;
        assert!(decode_rows(&values, 4096).is_err());
        values[4095] = 0;
        values[255] = 255;
        assert!(decode_rows(&values, 4096).is_err());
        values[255] = 0;
        values[767] = 1;
        assert!(decode_rows(&values, 4096).is_err());
    }
    #[test]
    fn bounded_request_syntax_rejects_extra_fields_extent_and_foreign_parameters() {
        // Untrusted envelope bytes only; this does not construct a verified ciphertext.
        let mut request = vec![0; REQUEST_HEADER + 2];
        request[..8].copy_from_slice(REQUEST_MAGIC);
        request[72..76].copy_from_slice(&1u32.to_le_bytes());
        request[76..80].copy_from_slice(&1u32.to_le_bytes());
        assert!(request_inputs(&request, &[1; 32]).is_err());
        request[80] = 1;
        assert!(request_inputs(&request, &[0; 32]).is_err());
        request[80] = 0;
        request.push(0);
        assert!(request_inputs(&request, &[0; 32]).is_err());
        request.truncate(REQUEST_HEADER);
        assert!(request_inputs(&request, &[0; 32]).is_err());
    }
    #[test]
    fn hidden_mask_compilation_covers_domain_edges_without_source_access() {
        let all = Case::All.private_mask();
        let none = Case::None.private_mask();
        let ge = Case::Ge128.private_mask();
        assert_eq!(*all, [255; 32]);
        assert_eq!(*none, [0; 32]);
        assert_eq!(&ge[..16], &[0; 16]);
        assert_eq!(&ge[16..], &[255; 16]);
    }
}
