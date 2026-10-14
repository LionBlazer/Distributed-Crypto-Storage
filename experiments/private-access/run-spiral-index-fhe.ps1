[CmdletBinding()]
param(
    [ValidateRange(1000000,1000000)][int]$Rows = 1000000,
    [ValidateRange(4,12)][int]$Rounds = 8,
    [ValidateRange(1,8)][int]$Threads = 8,
    [string]$Cargo = 'cargo',
    [string]$CargoHome,
    [string]$TargetDirectory,
    [switch]$PrepareOnly,
    [switch]$Offline
)
$ErrorActionPreference = 'Stop'
$repository = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$localRoot = Join-Path $repository '.local/private-access'
$sourceRoot = Join-Path $localRoot 'sdk'
$probeRoot = Join-Path $localRoot 'spiral-index-fhe-probe'
$revision = 'fdb7206517c249603b0c91b65f1f29f95272107c'
New-Item -ItemType Directory -Force -Path $localRoot, (Join-Path $probeRoot 'src') | Out-Null
if (-not (Test-Path -LiteralPath (Join-Path $sourceRoot '.git'))) {
    if ($Offline) { throw 'Pinned SDK source is absent; an initial online run is required' }
    & git clone --no-checkout 'https://github.com/blyssprivacy/sdk.git' $sourceRoot
    if ($LASTEXITCODE -ne 0) { throw 'PIR source clone failed' }
    & git -C $sourceRoot checkout --detach $revision
    if ($LASTEXITCODE -ne 0) { throw 'Pinned PIR source checkout failed' }
}
$actualRevision = (& git -C $sourceRoot rev-parse HEAD).Trim()
if ($actualRevision -ne $revision) { throw "Expected SDK revision $revision; found $actualRevision" }
$sourceChanges = & git -C $sourceRoot status --porcelain --untracked-files=no
if ($sourceChanges) { throw 'Pinned SDK source has tracked modifications' }
@'
[package]
name = "private-access-spiral-index-fhe"
version = "0.1.0"
edition = "2024"
[workspace]
[dependencies]
spiral-rs = { path = "../sdk/lib/spiral-rs", features = ["server"] }
compact-store = { path = "../../../crates/compact-store" }
tfhe = { version = "=1.8.1", default-features = false, features = ["integer"] }
rayon = "1.11"
serde_json = "1"
serde = { version = "1", features = ["derive"] }
bincode = "1.3"
getrandom = "0.2"
zeroize = "1"
'@ | Set-Content -LiteralPath (Join-Path $probeRoot 'Cargo.toml') -Encoding utf8
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'spiral_index_fhe_probe.rs') -Destination (Join-Path $probeRoot 'src/main.rs')
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'padded_index_codec.rs') -Destination (Join-Path $probeRoot 'src/padded_index_codec.rs')
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'padded_index_codec_tests.rs') -Destination (Join-Path $probeRoot 'src/padded_index_codec_tests.rs')
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'SpiralIndexFhe.Cargo.lock') -Destination (Join-Path $probeRoot 'Cargo.lock')
if ($PrepareOnly) { Write-Output "Prepared standalone source: $probeRoot"; return }
$oldCargoHome = $env:CARGO_HOME
$oldTargetDirectory = $env:CARGO_TARGET_DIR
try {
    if (-not $CargoHome) { $CargoHome = Join-Path $repository '.local/cargo-home' }
    $env:CARGO_HOME = [IO.Path]::GetFullPath($CargoHome)
    if (-not $TargetDirectory) { $TargetDirectory = Join-Path $repository 'target' }
    $env:CARGO_TARGET_DIR = [IO.Path]::GetFullPath($TargetDirectory)
    $buildArguments = @('build', '--release', '--locked', '--manifest-path', (Join-Path $probeRoot 'Cargo.toml'))
    if ($Offline) { $buildArguments += '--offline' }
    & $Cargo @buildArguments
    if ($LASTEXITCODE -ne 0) { throw 'Spiral index FHE probe build failed' }
    $executable = Join-Path $env:CARGO_TARGET_DIR 'release/private-access-spiral-index-fhe.exe'
    if ($env:OS -ne 'Windows_NT') { $executable = Join-Path $env:CARGO_TARGET_DIR 'release/private-access-spiral-index-fhe' }
    $report = Join-Path $localRoot ('spiral-index-fhe-' + $Rows + '-' + $Rounds + '-t' + $Threads + '-' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss-fff') + '.jsonl')
    & $executable $Rows $Rounds $Threads | Tee-Object -FilePath $report
    if ($LASTEXITCODE -ne 0) { throw "Spiral index FHE probe failed; partial report: $report" }
    Write-Output "Report: $report"
}
finally {
    $env:CARGO_HOME = $oldCargoHome
    $env:CARGO_TARGET_DIR = $oldTargetDirectory
}
