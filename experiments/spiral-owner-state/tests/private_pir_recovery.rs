use std::process::Command;
#[test]
fn restored_keys_recover_first_middle_last_records_and_wrong_seed_fails_oracle() {
    let output = Command::new(env!("CARGO_BIN_EXE_spiral-owner-state"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "Public fixture probe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["restored_reads"], 3);
    assert_eq!(result["original_reads"], 1);
    assert_eq!(result["wrong_seed_oracle_mismatch"], true);
    assert_eq!(result["identical_original_public_wire_restored"], true);
    assert_eq!(result["canonical_owner_image_bytes"], 336);
    assert_eq!(result["original_public_setup_bytes"], 6_029_344);
    assert_eq!(result["owner_plus_public_bytes"], 6_029_680);
    assert_eq!(result["secret_image_written"], false);
}
