//! Explicit supervised participant mode. Local EOF requests a joined shutdown.
use peer_runtime::{
    ParticipantBootstrap,
    participant::{ParticipantHost, ParticipantInstall},
};
use std::{
    io::{self, Read, Write},
    path::Path,
};
pub fn run(
    directory: &Path,
    install: ParticipantInstall,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = ParticipantBootstrap::read(&mut io::stdin().lock())?;
    let host = ParticipantHost::bind(directory, install, config)?;
    let (ready, mut running) = host.spawn()?;
    println!("{}", serde_json::to_string(&ready)?);
    io::stdout().flush()?;
    let mut byte = [0];
    let reason = loop {
        match io::stdin().read(&mut byte) {
            Ok(0) => break Ok(()),
            Ok(_) => break Err(io::Error::other("Unexpected participant supervisor input")),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => (),
            Err(e) => break Err(e),
        }
    };
    // Do not use legacy watch_parent/process::exit: the actual actor and any
    // nonpreemptible proof must finish before the owned signer/lock is dropped.
    running.stop()?;
    reason?;
    Ok(())
}
