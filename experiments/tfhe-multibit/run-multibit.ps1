[CmdletBinding()]
param(
    [ValidateSet('classic','group4')][string]$Preset = 'group4',
    [ValidateSet(2,4,8)][int]$Threads = 2,
    [ValidateRange(1,8)][int]$RowWorkers = 1,
    [ValidateRange(1,5)][int]$Rounds = 2,
    [ValidateRange(1,20)][int]$PointUpdates = 4,
    [string]$Cargo = 'cargo',
    [string]$CargoHome,
    [string]$TargetDirectory,
    [switch]$PrepareOnly,
    [switch]$Offline
)
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'The process-memory/thread adapter currently supports Windows' }
$repository = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$localRoot = Join-Path $repository '.local/tfhe-multibit'
$probeRoot = Join-Path $localRoot ('probe-' + $Preset)
$revision = '9c4ad836c8a581455bfb4a7a9d395a9e87507675'
New-Item -ItemType Directory -Force -Path $localRoot, $probeRoot | Out-Null
$resolved = (& git -C $repository rev-parse ($revision + '^{commit}')).Trim()
if ($LASTEXITCODE -ne 0 -or $resolved -ne $revision) { throw 'Pinned current-main source revision unavailable' }
$archive = Join-Path $localRoot 'source-9c4ad836.zip'
& git -C $repository archive --format=zip --output=$archive $revision crates/compact-query crates/compact-store
if ($LASTEXITCODE -ne 0) { throw 'Pinned project source export failed' }
Expand-Archive -LiteralPath $archive -DestinationPath $probeRoot -Force

$ownerFile = Join-Path $probeRoot 'crates/compact-query/src/owner.rs'
$evalFile = Join-Path $probeRoot 'crates/compact-query/src/evaluator.rs'
$ownerOriginalHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $ownerFile).Hash
$evalOriginalHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $evalFile).Hash
$ownerText = [IO.File]::ReadAllText($ownerFile)
$originalImport = 'use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;'
if ([regex]::Matches($ownerText, [regex]::Escape($originalImport)).Count -ne 1) {
    throw 'Pinned owner parameter import changed unexpectedly'
}
if ($Preset -eq 'group4') {
    $multiImport = 'use tfhe::shortint::parameters::current_params::V1_8_PARAM_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128 as PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;'
    $ownerText = $ownerText.Replace($originalImport, $multiImport)
    [IO.File]::WriteAllText($ownerFile, $ownerText, (New-Object Text.UTF8Encoding($false)))
}
$evalText = [IO.File]::ReadAllText($evalFile)
$originalCap = '.with_limit(512 * 1024 * 1024)'
if ([regex]::Matches($evalText, [regex]::Escape($originalCap)).Count -ne 1) {
    throw 'Pinned evaluator key limit changed unexpectedly'
}
# Same noncryptographic framing allowance in BOTH copied profiles. No main edit.
$evalText = $evalText.Replace($originalCap, '.with_limit(1024 * 1024 * 1024)')
[IO.File]::WriteAllText($evalFile, $evalText, (New-Object Text.UTF8Encoding($false)))
$helperRoot = Join-Path $probeRoot 'crates/compact-query/examples/multibit_support'
New-Item -ItemType Directory -Force -Path $helperRoot | Out-Null
$example = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'probe.rs'))
$example = $example.Replace('"__PRESET__"', ('"' + $Preset + '"'))
$example = $example.Replace('#[path = "support.rs"]', '#[path = "multibit_support/mod.rs"]')
[IO.File]::WriteAllText((Join-Path $probeRoot 'crates/compact-query/examples/multibit_query.rs'), $example, (New-Object Text.UTF8Encoding($false)))
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'support.rs') -Destination (Join-Path $helperRoot 'mod.rs')
@'
[workspace]
members = ["crates/compact-query", "crates/compact-store"]
resolver = "3"
[workspace.package]
edition = "2024"
rust-version = "1.91.1"
[workspace.dependencies]
tfhe = { version = "=1.8.1", default-features = false, features = ["integer"] }
rayon = "1.11"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
[profile.release]
debug = 0
[profile.test]
opt-level = 3
debug = 0
'@ | Set-Content -LiteralPath (Join-Path $probeRoot 'Cargo.toml') -Encoding utf8
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Cargo.lock') -Destination (Join-Path $probeRoot 'Cargo.lock')
[ordered]@{
    baseline_revision = $revision
    preset = $Preset
    owner_original_sha256 = $ownerOriginalHash
    owner_prepared_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $ownerFile).Hash
    evaluator_original_sha256 = $evalOriginalHash
    evaluator_prepared_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $evalFile).Hash
    copied_project_source = 'crates/compact-query and crates/compact-store'
    shared_workbench_change = 'evaluation-key decoder cap 512 MiB -> 1 GiB'
    candidate_only_core_change = 'official grouping4 CPU TUniform 2M128 parameter import'
    dedicated_oprf_configuration = 'unchanged; enabled by default'
} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $probeRoot 'source-provenance.json') -Encoding utf8
if ($PrepareOnly) { Write-Output "Prepared source only: $probeRoot"; return }

$oldCargoHome = $env:CARGO_HOME
$oldTargetDirectory = $env:CARGO_TARGET_DIR
try {
    if (-not $CargoHome) { $CargoHome = Join-Path $repository '.local/cargo-home' }
    $env:CARGO_HOME = [IO.Path]::GetFullPath($CargoHome)
    if (-not $TargetDirectory) { $TargetDirectory = Join-Path $repository 'target' }
    $env:CARGO_TARGET_DIR = [IO.Path]::GetFullPath($TargetDirectory)
    $buildArgs = @('build','--release','--locked','--manifest-path',
        (Join-Path $probeRoot 'Cargo.toml'),'-p','compact-query','--example','multibit_query')
    if ($Offline) { $buildArgs += '--offline' }
    & $Cargo @buildArgs
    if ($LASTEXITCODE -ne 0) { throw 'Multi-bit comparison build failed' }
    $exe = Join-Path $env:CARGO_TARGET_DIR 'release/examples/multibit_query.exe'
    $report = Join-Path $localRoot ('multibit-' + $Preset + '-r' + $Threads + '-w' +
        $RowWorkers + '-' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss-fff') + '.jsonl')
    & $exe 1000000 $Rounds $PointUpdates $Threads $RowWorkers | Tee-Object -FilePath $report
    if ($LASTEXITCODE -ne 0) { throw "Probe failed or memory guard stopped it; partial report: $report" }
    Write-Output "Report: $report"
}
finally {
    $env:CARGO_HOME = $oldCargoHome
    $env:CARGO_TARGET_DIR = $oldTargetDirectory
}
