[CmdletBinding()]
param(
    [string]$SdkDirectory,
    [string]$Cargo = 'cargo',
    [string]$CargoHome,
    [string]$TargetDirectory,
    [ValidateSet('prepare','check','probe')][string]$Mode = 'prepare'
)
$ErrorActionPreference = 'Stop'
$repository = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$package = Join-Path $repository '.local/spiral-owner-state/package'
$revision = 'fdb7206517c249603b0c91b65f1f29f95272107c'
if (-not $SdkDirectory) { $SdkDirectory = Join-Path $repository '.local/private-access/sdk' }
$SdkDirectory = [IO.Path]::GetFullPath($SdkDirectory)
$actual = (& git -C $SdkDirectory rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $actual -ne $revision) { throw 'Expected exact pinned Spiral SDK checkout' }
if (& git -C $SdkDirectory status --porcelain --untracked-files=no) { throw 'SDK tracked source has modifications' }
New-Item -ItemType Directory -Force -Path (Join-Path $package 'src'), (Join-Path $package 'tests') | Out-Null
$provenance = [ordered]@{ experiment='spiral-owner-state-source'; sdk_revision=$revision; source=[ordered]@{}; sdk_source=[ordered]@{} }
foreach ($relative in @('Cargo.toml','src/lib.rs','src/main.rs','tests/recovery_contract.rs','tests/private_pir_recovery.rs','run.ps1')) {
    $source = Join-Path $PSScriptRoot $relative
    $provenance.source[$relative] = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
    if ($relative -eq 'Cargo.toml') {
        $manifest = Get-Content -LiteralPath $source -Raw
        $sdkPath = $SdkDirectory.Replace('\','/')
        $manifest = $manifest.Replace('../../.local/private-access/sdk', $sdkPath)
        [IO.File]::WriteAllText((Join-Path $package 'Cargo.toml'), $manifest, [Text.UTF8Encoding]::new($false))
    } elseif ($relative -ne 'run.ps1') {
        Copy-Item -LiteralPath $source -Destination (Join-Path $package $relative)
    }
}
foreach ($relative in @('client.rs','params.rs','discrete_gaussian.rs')) {
    $provenance.sdk_source[$relative] = (Get-FileHash -LiteralPath (Join-Path $SdkDirectory ('lib/spiral-rs/src/'+$relative)) -Algorithm SHA256).Hash
}
$lock = Join-Path $PSScriptRoot 'Cargo.lock'
if (Test-Path -LiteralPath $lock) {
    Copy-Item -LiteralPath $lock -Destination (Join-Path $package 'Cargo.lock')
    $provenance.source['Cargo.lock'] = (Get-FileHash -LiteralPath $lock -Algorithm SHA256).Hash
}
$provenance | ConvertTo-Json -Compress -Depth 5 | Write-Output
if ($Mode -eq 'prepare') { Write-Output "Prepared: $package"; return }
if (-not (Test-Path -LiteralPath $lock)) { throw 'Generate and review this isolated package Cargo.lock before check/probe' }
$oldCargoHome = $env:CARGO_HOME
$oldTarget = $env:CARGO_TARGET_DIR
try {
    if (-not $CargoHome) { $CargoHome = Join-Path $repository '.local/cargo-home' }
    if (-not $TargetDirectory) { $TargetDirectory = Join-Path $repository 'target/spiral-owner-state' }
    $env:CARGO_HOME = [IO.Path]::GetFullPath($CargoHome)
    $env:CARGO_TARGET_DIR = [IO.Path]::GetFullPath($TargetDirectory)
    $manifestPath = Join-Path $package 'Cargo.toml'
    if ($Mode -eq 'check') {
        & $Cargo test --release --locked --offline --jobs 2 --manifest-path $manifestPath -- --test-threads=1
        if ($LASTEXITCODE -ne 0) { throw 'Owner-state tests failed' }
        & $Cargo clippy --release --all-targets --locked --offline --jobs 2 --manifest-path $manifestPath -- -D warnings
        if ($LASTEXITCODE -ne 0) { throw 'Owner-state strict Clippy failed' }
    } else {
        & $Cargo run --release --locked --offline --jobs 2 --manifest-path $manifestPath
        if ($LASTEXITCODE -ne 0) { throw 'Owner-state recovery probe failed' }
    }
} finally {
    $env:CARGO_HOME = $oldCargoHome
    $env:CARGO_TARGET_DIR = $oldTarget
}
