//! Opt-in local process ownership. Network reachability never controls lifetime.
use std::io::{self, Read};

pub fn watch_parent() -> io::Result<()> {
    std::thread::Builder::new()
        .name("dcs-parent-lifetime".into())
        .spawn(|| {
            let mut input = io::stdin().lock();
            let mut byte = [0];
            loop {
                match input.read(&mut byte) {
                    // The parent has no remaining write handle, including after
                    // forced termination. Stop even during an in-flight FHE job.
                    Ok(0) => std::process::exit(0),
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    _ => {
                        eprintln!("Peer supervisor pipe failed or received unexpected data");
                        std::process::exit(1);
                    }
                }
            }
        })?;
    Ok(())
}
