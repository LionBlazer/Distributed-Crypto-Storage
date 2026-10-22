//! Owning public-arithmetic tests. The SDK exists only in this dev boundary.
pub(crate) mod fixture;

#[test]
fn historical_unassessed_profile_and_frame_are_byte_contracts() {
    let profile: String = crate::profile_digest()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(
        profile,
        "9d97f6eede741c9a179fc359d8b33f299720ab54576fbfe955f6192af65a5724fecbfad31bf8b4f7ba1d88c2d9aebcdcd2a2c925b0f9b838b71be1806b343bed"
    );
    assert_eq!(crate::certificate::LOGICAL_FRAME_BYTES, 1_737_899);
    assert_eq!(crate::CERTIFICATE_BYTES, 1_081_595);
    let wire: String = crate::wire_profile_digest()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(
        wire,
        "640191d5fd1e4324df163e6ec2602c812ebfeb03f1dd5feec9ccf61036f3898a"
    );
    assert_eq!(crate::POINTS, 18);
}
