//! Standalone peer daemon. Its stdin bootstrap contains TLS credentials, never FHE secrets.
use peer_runtime::{Bootstrap, PeerServer};
use std::{
    io::{self, Write},
    path::PathBuf,
};
mod joint_participant;
mod participant;
mod progress_participant;
mod supervision;
mod word_participant;
fn main() {
    if let Err(error) = run() {
        eprintln!("dcs-peer: {error}");
        std::process::exit(1);
    }
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let first = args.next();
    if first.as_deref() == Some("--participant-word-finality") {
        let install = match args.next().as_deref() {
            Some("new") => peer_runtime::participant::ParticipantInstall::New,
            Some("existing") => peer_runtime::participant::ParticipantInstall::Existing,
            _ => return Err("Expected participant-word-finality new|existing".into()),
        };
        let directory = PathBuf::from(args.next().ok_or("Missing Word participant directory")?);
        if args.next().is_some() {
            return Err("Unexpected Word participant argument".into());
        }
        return word_participant::run(&directory, install);
    }
    if first.as_deref() == Some("--participant-progress-finality") {
        let install = match args.next().as_deref() {
            Some("new") => peer_runtime::participant::ParticipantInstall::New,
            Some("existing") => peer_runtime::participant::ParticipantInstall::Existing,
            _ => return Err("Expected participant-progress-finality new|existing".into()),
        };
        let directory = PathBuf::from(
            args.next()
                .ok_or("Missing Progress participant directory")?,
        );
        if args.next().is_some() {
            return Err("Unexpected Progress participant argument".into());
        }
        return progress_participant::run(&directory, install);
    }
    if first.as_deref() == Some("--participant-joint-finality") {
        let install = match args.next().as_deref() {
            Some("new") => peer_runtime::participant::ParticipantInstall::New,
            Some("existing") => peer_runtime::participant::ParticipantInstall::Existing,
            _ => return Err("Expected participant-joint-finality new|existing".into()),
        };
        let directory = PathBuf::from(args.next().ok_or("Missing Joint participant directory")?);
        if args.next().is_some() {
            return Err("Unexpected Joint participant argument".into());
        }
        return joint_participant::run(&directory, install);
    }
    if first.as_deref() == Some("--participant-finality") {
        let install = match args.next().as_deref() {
            Some("new") => peer_runtime::participant::ParticipantInstall::New,
            Some("existing") => peer_runtime::participant::ParticipantInstall::Existing,
            _ => return Err("Expected participant-finality new|existing".into()),
        };
        let directory = PathBuf::from(args.next().ok_or("Missing participant directory")?);
        if args.next().is_some() {
            return Err("Unexpected participant argument".into());
        }
        return participant::run(&directory, install);
    }
    if first.as_deref() != Some("--state-dir") {
        return Err(
            "Usage: dcs-peer --state-dir PATH [--exit-on-stdin-close]; pass a bounded JSON Bootstrap frame on stdin".into(),
        );
    }
    let directory = PathBuf::from(args.next().ok_or("Missing state directory")?);
    let supervised = match args.next().as_deref() {
        None => false,
        Some("--exit-on-stdin-close") => true,
        _ => return Err("Unexpected argument".into()),
    };
    if args.next().is_some() {
        return Err("Unexpected argument".into());
    }
    let bytes = zeroize::Zeroizing::new(peer_transport::read_frame(
        &mut io::stdin().lock(),
        64 * 1024,
    )?);
    let bootstrap: Bootstrap = serde_json::from_slice(&bytes)?;
    drop(bytes);
    if supervised {
        supervision::watch_parent()?;
    }
    let executable = std::env::current_exe()?;
    let kernel_directory = executable
        .parent()
        .ok_or("the peer executable has no parent directory")?
        .join("proof-kernels");
    let backend = bfv_query_proof::initialize_backend(&kernel_directory)?;
    eprintln!("Proof backend: {backend}");
    let server = PeerServer::bind(bootstrap, &directory)?;
    println!("{}", serde_json::to_string(server.endpoint())?);
    io::stdout().flush()?;
    server.run()?;
    Ok(())
}
