//! Explicit Word-only process entry. EOF joins actual native and signer work.
use peer_runtime::{
    WordParticipantBootstrap, participant::ParticipantInstall,
    word_participant::WordParticipantHost,
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
    let config = WordParticipantBootstrap::read(&mut input)?;
    let host = WordParticipantHost::bind(directory, install, config)?;
    let (ready, mut running) = host.spawn()?;
    println!("{}", serde_json::to_string(&ready)?);
    io::stdout().flush()?;
    let mut byte = [0];
    let reason = loop {
        match input.read(&mut byte) {
            Ok(0) => break Ok(()),
            Ok(_) => break Err(io::Error::other("Unexpected Word supervisor input")),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => (),
            Err(e) => break Err(e),
        }
    };
    running.stop()?;
    reason?;
    Ok(())
}
