use proof_acceleration::{Kind as KernelKind, abi::kernel_file_name};
use std::{
    env,
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{self, Read},
    path::{Path, PathBuf},
    process::Command,
};

const AVX2: &str = "+avx2";
const AVX512: &str = "+avx2,+avx512f,+avx512dq,+avx512bw,+avx512vl";

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Options {
    pub build_only: bool,
}

impl Options {
    pub fn parse(args: impl IntoIterator<Item = OsString>) -> io::Result<Option<Self>> {
        let mut args = args.into_iter();
        match args.next().as_deref() {
            Some(arg) if arg == "--help" || arg == "-h" => {
                if args.next().is_some() {
                    return Err(usage());
                }
                Ok(None)
            }
            Some(arg) if arg == "playground" => {
                let build_only = match args.next().as_deref() {
                    None => false,
                    Some(arg) if arg == "--build-only" => true,
                    _ => return Err(usage()),
                };
                if args.next().is_some() {
                    return Err(usage());
                }
                Ok(Some(Self { build_only }))
            }
            _ => Err(usage()),
        }
    }
}

fn usage() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "Usage: dcs-launch playground [--build-only]",
    )
}

pub(super) fn host_triple(version: &str) -> io::Result<&str> {
    let host = version
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .ok_or_else(|| io::Error::other("rustc did not report its host target"))?;
    if host.is_empty()
        || !host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(io::Error::other("rustc reported an invalid host target"));
    }
    Ok(host)
}

#[derive(Debug)]
pub(super) struct Build {
    pub label: &'static str,
    packages: &'static [&'static str],
    target_directory: PathBuf,
    rustflags: String,
    kernel_kind: Option<KernelKind>,
}

impl Build {
    pub fn configure(&self, command: &mut Command, host: &str) {
        // RUSTFLAGS has priority over build.rustflags, target.*.rustflags and
        // cfg-based Cargo settings. Replace it, rather than concatenate arrays.
        for (name, _) in env::vars_os() {
            if clears_build_environment(&name.to_string_lossy()) {
                command.env_remove(name);
            }
        }
        command
            .env_remove("CARGO_ENCODED_RUSTFLAGS")
            .env_remove("CARGO_BUILD_TARGET")
            .env("RUSTFLAGS", &self.rustflags)
            .env("CARGO_TARGET_DIR", &self.target_directory)
            .args(["build", "--release", "--locked", "--target", host])
            .arg("--target-dir")
            .arg(&self.target_directory);
        for package in self.packages {
            command.args(["-p", package]);
        }
    }
}

fn clears_build_environment(name: &str) -> bool {
    let name = name.to_ascii_uppercase();
    name == "RUSTFLAGS"
        || name == "CARGO_ENCODED_RUSTFLAGS"
        || name == "CARGO_BUILD_TARGET"
        || (name.starts_with("CARGO_") && name.ends_with("_RUSTFLAGS"))
}

#[derive(Debug)]
pub(super) struct BuildPlan {
    pub host: String,
    pub builds: Vec<Build>,
    pub playground: PathBuf,
    pub peer: PathBuf,
    pub kernel_directory: PathBuf,
}

impl BuildPlan {
    pub fn new(root: &Path, host: &str) -> io::Result<Self> {
        // Keep the compiler-reported target a single path component.
        if host_triple(&format!("host: {host}"))? != host {
            return Err(io::Error::other("host target must be a single line"));
        }
        let x86_64 = host.starts_with("x86_64-");
        let baseline = if x86_64 {
            "-C target-cpu=x86-64"
        } else {
            // A non-empty RUSTFLAGS overrides inherited Cargo ISA settings while
            // preserving the compiler's portable target-default instruction set.
            "-C opt-level=3"
        };
        let target = root.join(".local/target-playground");
        let release = target.join(host).join("release");
        let executable_suffix = if host.contains("-windows-") {
            ".exe"
        } else {
            ""
        };
        let mut builds = vec![Build {
            label: "portable playground and peer",
            packages: &["dcs-peer", "fhe-playground"],
            target_directory: target,
            rustflags: baseline.into(),
            kernel_kind: None,
        }];
        if x86_64 {
            for (label, directory, features, kind) in [
                (
                    "AVX2 proof kernel",
                    "target-proof-avx2",
                    AVX2,
                    KernelKind::Avx2,
                ),
                (
                    "AVX-512 proof kernel",
                    "target-proof-avx512",
                    AVX512,
                    KernelKind::Avx512,
                ),
            ] {
                builds.push(Build {
                    label,
                    packages: &["dcs-proof-kernel"],
                    target_directory: root.join(".local").join(directory),
                    rustflags: format!("-C target-cpu=x86-64 -C target-feature={features}"),
                    kernel_kind: Some(kind),
                });
            }
        }
        Ok(Self {
            host: host.into(),
            builds,
            playground: release.join(format!("fhe-playground{executable_suffix}")),
            peer: release.join(format!("dcs-peer{executable_suffix}")),
            kernel_directory: release.join("proof-kernels"),
        })
    }

    fn kernel_artifacts(&self) -> impl Iterator<Item = (PathBuf, PathBuf)> + '_ {
        self.builds.iter().filter_map(|build| {
            let kind = build.kernel_kind?;
            let source_name = if self.host.contains("-windows-") {
                "dcs_proof_kernel.dll"
            } else if self.host.contains("-apple-") {
                "libdcs_proof_kernel.dylib"
            } else {
                "libdcs_proof_kernel.so"
            };
            Some((
                build
                    .target_directory
                    .join(&self.host)
                    .join("release")
                    .join(source_name),
                self.kernel_directory.join(kernel_file_name(kind)),
            ))
        })
    }

    pub fn install_kernels(&self) -> io::Result<()> {
        fs::create_dir_all(&self.kernel_directory)?;
        for (source, destination) in self.kernel_artifacts() {
            install_file(&source, &destination)?;
        }
        Ok(())
    }

    pub fn check_applications(&self) -> io::Result<()> {
        for executable in [&self.playground, &self.peer] {
            if !executable.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("the build did not produce {}", executable.display()),
                ));
            }
        }
        Ok(())
    }
}

fn install_file(source: &Path, destination: &Path) -> io::Result<()> {
    if identical_files(source, destination)? {
        return Ok(());
    }
    let file_name = destination
        .file_name()
        .ok_or_else(|| io::Error::other("kernel destination needs a file name"))?;
    let mut temporary_name = file_name.to_os_string();
    temporary_name.push(format!(".{}.pending", std::process::id()));
    let temporary = destination.with_file_name(temporary_name);
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    let result = (|| {
        io::copy(&mut File::open(source)?, &mut output)?;
        output.sync_all()?;
        drop(output);
        // Replace a complete file atomically. An active Windows DLL may reject
        // replacement; return that error and leave the running process alone.
        fs::rename(&temporary, destination)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "cannot package {} as {}: {error}",
                source.display(),
                destination.display()
            ),
        )
    })
}

fn identical_files(source: &Path, destination: &Path) -> io::Result<bool> {
    let mut source = File::open(source)?;
    let mut destination = match File::open(destination) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    if source.metadata()?.len() != destination.metadata()?.len() {
        return Ok(false);
    }
    let mut a = [0; 16 * 1024];
    let mut b = [0; 16 * 1024];
    loop {
        let count = source.read(&mut a)?;
        destination.read_exact(&mut b[..count])?;
        if a[..count] != b[..count] {
            return Ok(false);
        }
        if count == 0 {
            return Ok(true);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            use std::sync::atomic::{AtomicUsize, Ordering};
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.local/launcher-tests");
            fs::create_dir_all(&root).unwrap();
            let directory = root.join(format!(
                "{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&directory).unwrap();
            Self(directory.canonicalize().unwrap())
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            // This exact directory was created exclusively by the test above.
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn build_only_is_explicit_and_unknown_commands_are_rejected() {
        assert_eq!(
            Options::parse(["playground".into(), "--build-only".into()]).unwrap(),
            Some(Options { build_only: true })
        );
        assert_eq!(
            Options::parse(["playground".into()]).unwrap(),
            Some(Options { build_only: false })
        );
        for args in [
            vec![],
            vec!["--build-only"],
            vec!["playground", "native"],
            vec!["playground", "--build-only", "extra"],
        ] {
            assert!(Options::parse(args.into_iter().map(OsString::from)).is_err());
        }
    }

    #[test]
    fn x86_package_contains_a_portable_host_and_both_exact_isa_variants() {
        let plan = BuildPlan::new(Path::new("checkout"), "x86_64-pc-windows-msvc").unwrap();
        assert_eq!(plan.builds.len(), 3);
        assert_eq!(plan.builds[0].rustflags, "-C target-cpu=x86-64");
        assert_eq!(
            plan.builds[1].rustflags,
            "-C target-cpu=x86-64 -C target-feature=+avx2"
        );
        assert_eq!(
            plan.builds[2].rustflags,
            "-C target-cpu=x86-64 -C target-feature=+avx2,+avx512f,+avx512dq,+avx512bw,+avx512vl"
        );
        assert_eq!(
            plan.playground,
            Path::new(
                "checkout/.local/target-playground/x86_64-pc-windows-msvc/release/fhe-playground.exe"
            )
        );
        assert_eq!(
            plan.peer.parent(),
            plan.kernel_directory.parent(),
            "both processes resolve kernels beside their executable"
        );
        let artifacts: Vec<_> = plan.kernel_artifacts().collect();
        assert_eq!(artifacts.len(), 2);
        assert!(
            artifacts[0]
                .0
                .ends_with("target-proof-avx2/x86_64-pc-windows-msvc/release/dcs_proof_kernel.dll")
        );
        assert!(artifacts[0].1.ends_with(kernel_file_name(KernelKind::Avx2)));
        assert!(
            artifacts[1]
                .1
                .ends_with(kernel_file_name(KernelKind::Avx512))
        );
    }

    #[test]
    fn aarch64_uses_portable_sdk_without_building_x86_libraries() {
        let plan = BuildPlan::new(Path::new("checkout"), "aarch64-apple-darwin").unwrap();
        assert_eq!(plan.builds.len(), 1);
        assert_eq!(plan.builds[0].rustflags, "-C opt-level=3");
        assert_eq!(plan.kernel_artifacts().count(), 0);
        assert!(plan.playground.ends_with("release/fhe-playground"));
    }

    #[test]
    fn host_target_cannot_escape_artifact_directories() {
        assert_eq!(
            host_triple("rustc 1.99.0\nhost: x86_64-unknown-linux-gnu\nrelease: 1.99.0").unwrap(),
            "x86_64-unknown-linux-gnu"
        );
        for invalid in ["", "../outside", "x86_64/../../outside", "-h\nextra"] {
            assert!(BuildPlan::new(Path::new("checkout"), invalid).is_err());
        }
    }

    #[test]
    fn cargo_commands_override_inherited_isa_flags_and_build_the_host_explicitly() {
        let plan = BuildPlan::new(Path::new("checkout"), "x86_64-unknown-linux-gnu").unwrap();
        let mut command = Command::new("cargo");
        plan.builds[1].configure(&mut command, &plan.host);
        let args: Vec<_> = command.get_args().collect();
        assert_eq!(
            args[..5],
            [
                "build",
                "--release",
                "--locked",
                "--target",
                "x86_64-unknown-linux-gnu",
            ]
        );
        assert_eq!(args[5], "--target-dir");
        assert_eq!(
            Path::new(args[6]),
            Path::new("checkout/.local/target-proof-avx2")
        );
        assert_eq!(args[7..], ["-p", "dcs-proof-kernel"]);
        let variables: Vec<_> = command.get_envs().collect();
        assert!(variables.contains(&(
            std::ffi::OsStr::new("RUSTFLAGS"),
            Some(std::ffi::OsStr::new(
                "-C target-cpu=x86-64 -C target-feature=+avx2"
            ))
        )));
        assert!(variables.contains(&(std::ffi::OsStr::new("CARGO_ENCODED_RUSTFLAGS"), None)));
        assert!(clears_build_environment(
            "CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS"
        ));
        assert!(clears_build_environment("CARGO_BUILD_RUSTFLAGS"));
        assert!(!clears_build_environment("CARGO_HOME"));
    }

    #[test]
    fn kernel_packaging_replaces_complete_files_and_missing_input_preserves_installed_bytes() {
        let directory = TestDirectory::new();
        let source = directory.0.join("built-kernel");
        let destination = directory.0.join("packaged-kernel");
        fs::write(&source, b"public packaging test bytes, version one").unwrap();

        install_file(&source, &destination).unwrap();
        assert_eq!(fs::read(&destination).unwrap(), fs::read(&source).unwrap());
        install_file(&source, &destination).unwrap();
        fs::write(&source, b"public packaging test bytes, version two").unwrap();
        install_file(&source, &destination).unwrap();

        let installed = fs::read(&destination).unwrap();
        assert_eq!(installed, b"public packaging test bytes, version two");
        assert!(install_file(&directory.0.join("missing-kernel"), &destination).is_err());
        assert_eq!(fs::read(&destination).unwrap(), installed);
        assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 2);
    }
}
