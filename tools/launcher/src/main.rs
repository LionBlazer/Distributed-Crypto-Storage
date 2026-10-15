//! Build the portable applications and packaged ISA kernels before starting the GUI.
#![forbid(unsafe_code)]

mod package;

use package::{BuildPlan, Options};
use std::{env, error::Error, io, path::Path, process::Command};

fn main() {
    if let Err(error) = run() {
        eprintln!("dcs-launch: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let Some(options) = Options::parse(env::args_os().skip(1))? else {
        println!("Usage: dcs-launch playground [--build-only]");
        return Ok(());
    };
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or("the launcher package must reside in tools/launcher")?
        .canonicalize()?;
    let rustc = env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let compiler = Command::new(rustc).arg("-vV").output()?;
    if !compiler.status.success() {
        return Err(io::Error::other(format!(
            "rustc -vV failed: {}",
            String::from_utf8_lossy(&compiler.stderr)
        ))
        .into());
    }
    let compiler_version = String::from_utf8(compiler.stdout)?;
    let host = package::host_triple(&compiler_version)?;
    let plan = BuildPlan::new(&root, host)?;
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    for build in &plan.builds {
        eprintln!("Building {} ({})", build.label, plan.host);
        let mut command = Command::new(&cargo);
        command.current_dir(&root);
        build.configure(&mut command, &plan.host);
        if !command.status()?.success() {
            return Err(io::Error::other(format!("{} build failed", build.label)).into());
        }
    }
    plan.install_kernels()?;
    plan.check_applications()?;
    println!("playground={}", plan.playground.display());
    println!("peer={}", plan.peer.display());
    println!("proof_kernels={}", plan.kernel_directory.display());
    if options.build_only {
        return Ok(());
    }
    let status = Command::new(&plan.playground).current_dir(&root).status()?;
    if !status.success() {
        return Err(io::Error::other(format!("the playground exited with {status}")).into());
    }
    Ok(())
}
