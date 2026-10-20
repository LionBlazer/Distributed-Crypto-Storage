//! Explicit Progress-only process entry. EOF joins actual native and signer work.
use peer_runtime::{
    ProgressParticipantBootstrap, participant::ParticipantInstall,
    progress_participant::ProgressParticipantHost,
};
use std::{
    io::{self, Read, Write},
    path::Path,
};

pub fn run(
    directory: &Path,
    install: ParticipantInstall,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut input = io::stdin().lock();
    let config = ProgressParticipantBootstrap::read(&mut input)?;
    let host = ProgressParticipantHost::bind(directory, install, config, &mut input)?;
    let (ready, mut running) = host.spawn()?;
    println!("{}", serde_json::to_string(&ready)?);
    io::stdout().flush()?;
    let mut byte = [0];
    let reason = loop {
        match input.read(&mut byte) {
            Ok(0) => break Ok(()),
            Ok(_) => break Err(io::Error::other("Unexpected Progress supervisor input")),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => (),
            Err(e) => break Err(e),
        }
    };
    running.stop()?;
    reason?;
    Ok(())
}
