use bfv_addition_proof::{Error, MAX_PROOF_BYTES, verify};

#[test]
fn half_megabyte_of_empty_quotient_chunks_is_rejected_by_the_decoder_limit() {
    // Deliberately malformed SDK proof, never a cryptographic fixture. Both caps
    // contain one canonical zero digest, then the four absent/empty opening rows
    // lead to quotient_chunks. A generic Vec decoder would reserve >= 12 MiB
    // for this field before discovering the missing later proof fields.
    let mut frame = b"BFVP3A01".to_vec();
    for _ in 0..2 {
        frame.push(1);
        frame.extend_from_slice(&[0; 32]);
    }
    frame.push(0); // commitments.random
    frame.extend_from_slice(&[0; 4]); // trace_local and three optional rows
    frame.extend(postcard::to_allocvec(&524_288_usize).unwrap());
    frame.resize(frame.len() + 524_288, 0); // empty quotient chunks
    frame.push(0); // opened_values.random
    assert!(frame.len() < MAX_PROOF_BYTES);

    let result = verify(&[], &[], &frame);

    // This specifically proves that decoding reached the sequence limit, rather
    // than failing on the caps, fields, magic, or the absent statement bytes.
    assert_eq!(result.unwrap_err(), Error::ProofResourceLimit);
}
