//! Standalone peer daemon. Its stdin bootstrap contains TLS credentials, never FHE secrets.
use peer_runtime::{Bootstrap, PeerServer};
use std::{
    io::{self, Write},
    path::PathBuf,
};
fn main() {
    if let Err(error) = run() {
        eprintln!("dcs-peer: {error}");
        std::process::exit(1);
    }
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    if args.next().as_deref() != Some("--state-dir") {
        return Err(
            "Usage: dcs-peer --state-dir PATH; pass a bounded JSON Bootstrap frame on stdin".into(),
        );
    }
    let directory = PathBuf::from(args.next().ok_or("Missing state directory")?);
    if args.next().is_some() {
        return Err("Unexpected argument".into());
    }
    let executable = std::env::current_exe()?;
    let kernel_directory = executable
        .parent()
        .ok_or("the peer executable has no parent directory")?
        .join("proof-kernels");
    let backend = bfv_query_proof::initialize_backend(&kernel_directory)?;
    eprintln!("Proof backend: {backend}");
    let bytes = zeroize::Zeroizing::new(peer_transport::read_frame(
        &mut io::stdin().lock(),
        64 * 1024,
    )?);
    let bootstrap: Bootstrap = serde_json::from_slice(&bytes)?;
    let server = PeerServer::bind(bootstrap, &directory)?;
    println!("{}", serde_json::to_string(server.endpoint())?);
    io::stdout().flush()?;
    server.run()?;
    Ok(())
}
