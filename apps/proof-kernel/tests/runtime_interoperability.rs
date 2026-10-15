//! Real full-profile proofs across the portable engine and installed SIMD kernels.
//! Public fixture values are non-secret; fresh owner keys never leave this process.
use bfv_query_core::{
    Geometry, HEAD_BYTES, Owner, PublicUpdateEvaluator, QueryContext, RowProjection, SelectedField,
    UnverifiedUpdateOutcome,
};
use bfv_query_proof::{Operation, prove, verify};
use proof_acceleration::{Kernel, Kind};
use std::path::PathBuf;

#[test]
#[ignore = "requires kernels built by dcs-launch; set DCS_TEST_KERNEL_DIR"]
fn genuine_proofs_interoperate_and_reject_tampering_across_cpu_variants() {
    assert_eq!(
        bfv_query_proof::compiled_kind(),
        Kind::Baseline,
        "build this interoperability test with portable RUSTFLAGS"
    );
    let directory =
        PathBuf::from(std::env::var_os("DCS_TEST_KERNEL_DIR").expect("set DCS_TEST_KERNEL_DIR"));
    let kernels: Vec<_> = [Kind::Avx2, Kind::Avx512]
        .into_iter()
        .filter(|kind| kind.is_supported())
        .map(|kind| {
            let kernel = Kernel::load(&directory, kind)
                .expect("every CPU-supported installed kernel must load");
            assert_eq!(kernel.kind(), kind);
            kernel
        })
        .collect();
    assert!(
        !kernels.is_empty(),
        "this test requires an AVX2-capable host"
    );

    let (owner, setup) = Owner::generate(Geometry::Rows256).unwrap();
    let peer = PublicUpdateEvaluator::from_parameters(&setup.update_parameters().unwrap()).unwrap();
    let context = QueryContext::new([7; 16], [2; HEAD_BYTES], [3; HEAD_BYTES]);
    let fields = [
        SelectedField {
            age: 18,
            amount: 20,
            active: true,
        },
        SelectedField {
            age: 42,
            amount: 30,
            active: true,
        },
    ];
    for operation in [Operation::Addition, Operation::PublicPolynomialProduct] {
        let addition = (operation == Operation::Addition).then(|| {
            owner
                .prepare_indexed_update_for_experiment(context.clone(), &fields, 5)
                .unwrap()
        });
        let selection = (operation == Operation::PublicPolynomialProduct).then(|| {
            owner
                .prepare_exact_select_for_experiment(
                    context.clone(),
                    &fields,
                    RowProjection::AgeAmount,
                )
                .unwrap()
        });
        let input = match (&addition, &selection) {
            (Some(prepared), _) => peer.circuit_request(&prepared.request).unwrap(),
            (_, Some(prepared)) => peer.select_circuit_request(&prepared.request).unwrap(),
            _ => unreachable!(),
        };
        let baseline = prove(&input).unwrap();
        let mut generated = vec![(
            "baseline",
            baseline.output().to_vec(),
            baseline.proof().to_vec(),
        )];
        for kernel in &kernels {
            let proved = kernel.prove(&input).unwrap();
            assert_eq!(
                proved.output(),
                baseline.output(),
                "{} output",
                kernel.kind()
            );
            generated.push((
                kernel.kind().name(),
                proved.output().to_vec(),
                proved.proof().to_vec(),
            ));
        }
        for (producer, output, proof) in &generated {
            verify(&input, output, proof).unwrap();
            for verifier in &kernels {
                verifier
                    .verify(&input, output, proof)
                    .unwrap_or_else(|error| panic!("{producer} -> {}: {error:?}", verifier.kind()));
            }
            let mut wrong_output = output.clone();
            let offset = wrong_output.len() - 8;
            let residue = u64::from_le_bytes(wrong_output[offset..].try_into().unwrap());
            wrong_output[offset..]
                .copy_from_slice(&((residue + 1) % bfv_linear_circuit::MODULI[4]).to_le_bytes());
            let mut rebound_input = input.clone();
            let mut rebound_output = output.clone();
            rebound_input[8] ^= 1;
            rebound_output[8] ^= 1;
            for (request, result, evidence) in [
                (&input[..], &wrong_output[..], &proof[..]),
                (&rebound_input[..], &rebound_output[..], &proof[..]),
                (&input[..], &output[..], &[][..]),
            ] {
                assert!(verify(request, result, evidence).is_err());
                for verifier in &kernels {
                    assert!(verifier.verify(request, result, evidence).is_err());
                }
            }
            eprintln!(
                "{operation:?}: {producer} proof verified by portable and all supported SIMD kernels ({} bytes)",
                proof.len()
            );
        }
        // Only decrypt after the independent arithmetic proof checks above.
        if let Some(prepared) = addition {
            let response = peer
                .restore_circuit_output(&prepared.request, baseline.output())
                .unwrap();
            let UnverifiedUpdateOutcome::Values(actual) = owner
                .decrypt_indexed_update_unverified_for_experiment(prepared.pending, &response)
                .unwrap()
            else {
                panic!("public fixture must not overflow")
            };
            assert_eq!(
                actual.rows.iter().map(|row| row.amount).collect::<Vec<_>>(),
                [25, 35]
            );
        }
        if let Some(prepared) = selection {
            let response = peer
                .restore_select_circuit_output(&prepared.request, baseline.output())
                .unwrap();
            let actual = owner
                .decrypt_indexed_select_unverified_for_experiment(prepared.pending, &response)
                .unwrap();
            assert_eq!(
                actual
                    .rows
                    .iter()
                    .map(|row| (row.age, row.amount))
                    .collect::<Vec<_>>(),
                [(Some(18), Some(20)), (Some(42), Some(30))]
            );
        }
    }
}
