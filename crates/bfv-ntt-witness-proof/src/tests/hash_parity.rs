//! One public genuine proof, exported only for an explicit local parity run.
use crate::{
    Error, MAX_PROOF_BYTES,
    backend::{self, Backend},
    fixture, proof, prove, verify,
};
use bfv_ntt_circuit::{Basis, DEGREE, Direction, Output, Request};
use p3_air::BaseAir;
use p3_challenger::CanFinalizeDigest;
use p3_commit::MultilinearPcs;
use p3_field::PrimeCharacteristicRing;
use p3_multi_stark::{
    VerifierInstance, VerifierInstances, config::MultiStarkConfig, verify_with_security,
};
use p3_sumcheck::layout::Table;
use std::{
    env,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Instant,
};

const EXPORT: &str = "DCS_NTT_HASH_PARITY_EXPORT";
const BASELINE: &str = "DCS_NTT_HASH_PARITY_BASELINE";
const FILES: [&str; 7] = [
    "request.bin",
    "output.bin",
    "profile.bin",
    "proof.bin",
    "preprocessing-roots.bin",
    "verifier-transcript.bin",
    "security-report.postcard",
];

// Artifacts contain only the deterministic PUBLIC NONSECRET fixture below. A
// caller must opt in to a new directory inside this checkout's ignored .local.
fn artifact_path(variable: &str, existing: bool) -> Option<PathBuf> {
    let path = PathBuf::from(env::var_os(variable)?);
    assert!(path.is_absolute(), "{variable} must be an absolute path");
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let local = fs::canonicalize(workspace.join(".local"))
        .expect("create this checkout's ignored .local before exporting artifacts");
    if existing {
        let resolved = fs::canonicalize(&path).expect("baseline directory must already exist");
        assert!(
            resolved.starts_with(&local),
            "baseline must be inside .local"
        );
        for name in FILES {
            assert!(
                resolved.join(name).is_file(),
                "missing baseline file {name}"
            );
        }
        Some(resolved)
    } else {
        let parent = fs::canonicalize(path.parent().unwrap())
            .expect("export parent directory must already exist");
        assert!(parent.starts_with(&local), "export must be inside .local");
        assert!(!path.exists(), "export directory must be new");
        Some(parent.join(path.file_name().expect("export needs a directory name")))
    }
}

// Rebuild the same public tables and PCS commitment as SDK setup. The opaque VK
// remains private. Drop its PK before the extra commitment, and drop the extra
// codeword before replaying the actual verifier transcript.
fn preprocessing_and_transcript(
    input: &Request,
    output: &Output,
    frame: &[u8],
) -> (Vec<u8>, [u8; 64]) {
    let Backend {
        machine,
        config,
        prover,
        verifier,
        ..
    } = Backend::new(input, output).unwrap();
    drop(prover);
    let tables = machine
        .airs()
        .iter()
        .filter(|air| air.preprocessed_width() != 0)
        .map(|air| Table::new(air.preprocessed_trace().unwrap().transpose()))
        .collect();
    let profile = backend::profile_digest(input.direction(), input.basis());
    let witness = config.build_witness(tables);
    let (commitment, data) = config
        .preprocessed_pcs()
        .commit(
            witness,
            &mut config.challenger(profile, &input.encode(), &output.encode()),
        )
        .unwrap();
    let mut roots = Vec::new();
    assert_eq!(commitment.num_roots(), 1, "the fixed profile uses one root");
    for root in commitment.roots() {
        for word in root {
            roots.extend(word.to_le_bytes());
        }
    }
    assert_eq!(roots.len(), 64);
    drop(data);

    let decoded = proof::decode_frame(input, output, frame).unwrap();
    let instances = VerifierInstances::new(
        machine
            .airs()
            .iter()
            .map(|air| VerifierInstance::new(air, &verifier, air.height().ilog2() as usize, &[]))
            .collect(),
    );
    let mut challenger = config.challenger(profile, &input.encode(), &output.encode());
    verify_with_security(
        &config,
        instances,
        &decoded,
        0,
        backend::POLICY_BITS,
        &mut challenger,
    )
    .unwrap();
    (roots, challenger.clone().finalize())
}

fn compare_complete(baseline: &Path, name: &str, expected: &[u8]) {
    // Bound even a damaged local artifact before allocation. Read and compare
    // every byte, including the last one; a digest alone is not this check.
    let mut bytes = Vec::with_capacity(expected.len() + 1);
    File::open(baseline.join(name))
        .unwrap()
        .take((expected.len() + 1) as u64)
        .read_to_end(&mut bytes)
        .unwrap();
    assert_eq!(bytes.len(), expected.len(), "{name} length changed");
    let mismatch = bytes.iter().zip(expected).position(|(a, b)| a != b);
    assert_eq!(mismatch, None, "{name} differs at this byte offset");
}

#[test]
#[ignore = "explicit sequential baseline/candidate genuine N8192 hash parity gate"]
fn one_public_ntt_preserves_complete_proof_preprocessing_and_transcript() {
    let export = artifact_path(EXPORT, false);
    let baseline = artifact_path(BASELINE, true);
    let input = fixture::request(Direction::Forward, Basis::new(0).unwrap(), [0x71; 32]).unwrap();
    assert_eq!(input.input().len(), DEGREE);
    let generated = prove(&input).unwrap();
    assert!(generated.proof.len() <= MAX_PROOF_BYTES);
    let checked = verify(&input, &generated.output, &generated.proof).unwrap();
    assert!(checked.matches(&input, &generated.output));
    assert_eq!(checked.security_report().required_security_bits, 144);
    assert!(checked.security_report().whole_security_bits >= 144.0);
    assert!(checked.security_report().unassessed_components.is_empty());

    // Independent native SDK arithmetic over every coefficient, with the same
    // nonzero edge-heavy input as the existing full genuine owning tests.
    let modulus = fhe_math::zq::Modulus::new(input.basis().modulus()).unwrap();
    let native = fhe_math::ntt::NttOperator::new(&modulus, DEGREE).unwrap();
    let mut expected = input.input().to_vec();
    native.forward(&mut expected);
    assert_eq!(generated.output.coefficients(), expected);

    let capture_start = Instant::now();
    let (roots, transcript) =
        preprocessing_and_transcript(&input, &generated.output, &generated.proof);
    let capture_ms = capture_start.elapsed().as_secs_f64() * 1000.0;

    // Preserve all frame/layout rules: decode and canonically reencode a real
    // semantic polynomial mutation, then require rejection by actual verification.
    let mut corrupt = proof::decode_frame(&input, &generated.output, &generated.proof).unwrap();
    corrupt.sumcheck.round_polys[0][0] += backend::Challenge::ONE;
    let corrupt = proof::encode_frame(&input, &generated.output, &corrupt).unwrap();
    assert!(proof::decode_frame(&input, &generated.output, &corrupt).is_ok());
    assert_eq!(
        verify(&input, &generated.output, &corrupt).unwrap_err(),
        Error::Verification
    );

    let report = postcard::to_allocvec(checked.security_report()).unwrap();
    assert!(report.len() <= 64 * 1024);
    let artifacts = [
        input.encode(),
        generated.output.encode(),
        backend::profile_digest(input.direction(), input.basis()).to_vec(),
        generated.proof,
        roots,
        transcript.to_vec(),
        report,
    ];
    if let Some(baseline) = baseline {
        for (name, bytes) in FILES.into_iter().zip(&artifacts) {
            compare_complete(&baseline, name, bytes);
        }
    }
    if let Some(export) = export {
        fs::create_dir(&export).expect("export directory must be new");
        for (name, bytes) in FILES.into_iter().zip(&artifacts) {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(export.join(name))
                .unwrap();
            file.write_all(bytes).unwrap();
            file.sync_all().unwrap();
        }
        eprintln!("PUBLIC NONSECRET parity artifacts: {}", export.display());
    }
    eprintln!(
        "proof={}B; production prove={:?}; production verify={:?}; extra PP/transcript capture={capture_ms:.3}ms",
        artifacts[3].len(),
        generated.timings,
        checked.timings,
    );
}
