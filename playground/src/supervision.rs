//! Optional application lifecycle IPC; independent peers have no GUI dependency.
use std::io::{self, Read};

pub fn watch_launcher() -> io::Result<()> {
    let mut arguments = std::env::args_os().skip(1);
    match arguments.next() {
        None => return Ok(()),
        Some(argument) if argument == "--exit-on-stdin-close" && arguments.next().is_none() => {}
        _ => {
            return Err(io::Error::other(
                "Usage: fhe-playground [--exit-on-stdin-close]",
            ));
        }
    }
    std::thread::Builder::new()
        .name("dcs-launcher-lifetime".into())
        .spawn(|| {
            let mut input = io::stdin().lock();
            let mut byte = [0];
            loop {
                match input.read(&mut byte) {
                    // Exit the entire process even if the UI or a worker is busy.
                    // Closing its owned peer pipes then terminates local children.
                    Ok(0) => std::process::exit(0),
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    _ => {
                        eprintln!("Playground supervisor pipe failed or received unexpected data");
                        std::process::exit(1);
                    }
                }
            }
        })?;
    Ok(())
}
