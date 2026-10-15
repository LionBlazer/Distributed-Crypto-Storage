//! The application is a consumer of the core, never its dependency.
use serde_json::Value;
use std::{collections::BTreeSet, path::Path, process::Command};

#[test]
fn core_build_targets_and_dependencies_exclude_applications_and_experiments() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let core = root.join("crates").canonicalize().unwrap();
    let output = Command::new(env!("CARGO"))
        .args([
            "metadata",
            "--offline",
            "--locked",
            "--no-deps",
            "--format-version",
            "1",
        ])
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let metadata: Value = serde_json::from_slice(&output.stdout).unwrap();
    let mut core_members = BTreeSet::new();
    for package in metadata["packages"].as_array().unwrap() {
        let directory = Path::new(package["manifest_path"].as_str().unwrap())
            .parent()
            .unwrap()
            .canonicalize()
            .unwrap();
        if !directory.starts_with(&core) {
            continue;
        }
        core_members.insert(package["id"].as_str().unwrap().to_string());
        for dependency in package["dependencies"].as_array().unwrap() {
            let name = dependency["name"].as_str().unwrap();
            assert!(
                !matches!(name, "egui" | "eframe" | "fhe-playground" | "fhe-prototype"),
                "Core dependency on {name}"
            );
            if let Some(path) = dependency["path"].as_str() {
                assert!(
                    Path::new(path).canonicalize().unwrap().starts_with(&core),
                    "Core dependency escapes its layer: {path}"
                );
            }
        }
        for target in package["targets"].as_array().unwrap() {
            assert!(
                !target["kind"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|kind| kind == "example" || kind == "bin"),
                "Core must expose libraries, not application/measurement targets: {target}"
            );
        }
    }
    let defaults: BTreeSet<_> = metadata["workspace_default_members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|id| id.as_str().unwrap().to_string())
        .collect();
    assert!(!core_members.is_empty());
    assert_eq!(
        defaults, core_members,
        "A default workspace build must select only core libraries"
    );
}
