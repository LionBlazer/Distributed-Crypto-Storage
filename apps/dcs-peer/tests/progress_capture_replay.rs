//! Isolated PUBLIC fixture network replay. No FHE producer or SQL output.
#[path = "support/progress_capture.rs"]
mod capture;
#[path = "support/progress_capture_network.rs"]
mod network;
#[path = "support/joint_process.rs"]
#[expect(
    dead_code,
    reason = "Shared test supervisor also owns other explicit process grammars"
)]
mod process;

use std::{io, path::PathBuf};

fn required_path(name: &str) -> io::Result<PathBuf> {
    let path = std::env::var_os(name)
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::other(format!("Required opt-in public fixture path: {name}")))?;
    capture::require(path.is_absolute(), "Replay fixture paths must be absolute")?;
    Ok(path)
}

#[test]
#[ignore = "Requires independent Root invocation pins, COMPLETE public capture and four actual OS validators"]
fn actual_four_validators_cold_replay_original_product1_without_fhe() -> io::Result<()> {
    let archive = required_path("DCS_PROGRESS_REPLAY_CAPTURE_DIR")?;
    let pins = required_path("DCS_PROGRESS_REPLAY_PIN_FILE")?;
    // Supplied separately by the operator, never read from manifest/COMPLETE.
    let digest = std::env::var("DCS_PROGRESS_REPLAY_PIN_SHA256")
        .map_err(|_| io::Error::other("Independent invocation PinSpec digest is required"))?;
    let digest = capture::decode_hex(&digest)?;
    capture::require(
        digest == capture::decode_hex(capture::INVOCATION_SHA256)?,
        "This isolated gate is pinned to the original PUBLIC product1 invocation",
    )?;
    let scratch = network::Directory::new()?;
    let result = (|| {
        let archive = capture::load(&archive, &pins, digest, scratch.path())?;
        network::run(&archive, scratch.path())
    })();
    // Cleanup is after every borrowed archive/RPC/process owner has returned.
    let cleanup = scratch.finish();
    result.and(cleanup)
}
