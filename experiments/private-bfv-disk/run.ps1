[CmdletBinding()]
param(
    [ValidateRange(3,2000)][int]$Tables = 3,
    [ValidateRange(1,2)][int]$Samples = 1,
    [string]$TableIds,
    [ValidateRange(1,8)][int]$Threads = 8,
    [ValidateRange(1,13000000000)][long]$MaxCanonicalBytes = 67108864,
    [ValidateSet('official','parallel','expansion','combined')][string]$ServerSchedule = 'combined',
    [string]$Cargo = 'cargo',
    [string]$CargoHome,
    [string]$TargetDirectory,
    [string]$BfvCoreDirectory,
    [string]$PirOwnerStateDirectory,
    [string]$CacheCoreDirectory,
    [string]$CompactStoreDirectory,
    [switch]$PrepareOnly,
    [switch]$Offline
)
$ErrorActionPreference = 'Stop'
$repository = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$localRoot = Join-Path $repository '.local/private-bfv-disk'
$probeRoot = Join-Path $localRoot 'package'
$sourceRoot = Join-Path $repository '.local/private-access/sdk'
$coreRoot = Join-Path $localRoot 'core'
$ownerRoot = Join-Path $localRoot 'owner-state'
$cacheRoot = Join-Path $localRoot 'cache-core'
$storeRoot = Join-Path $localRoot 'store'
$revision = 'fdb7206517c249603b0c91b65f1f29f95272107c'
if ($Tables * 6L * 1024 * 1024 -gt $MaxCanonicalBytes) { throw 'Dataset conservative preflight exceeds the explicit byte budget' }
if (-not $BfvCoreDirectory) { $BfvCoreDirectory = Join-Path $repository 'experiments/bfv-byte-limb-core' }
if (-not $PirOwnerStateDirectory) { $PirOwnerStateDirectory = Join-Path $repository 'experiments/spiral-owner-state' }
if (-not $CacheCoreDirectory) { $CacheCoreDirectory = Join-Path $repository 'experiments/spiral-cache-core' }
if (-not $CompactStoreDirectory) { $CompactStoreDirectory = Join-Path $repository 'crates/compact-store' }
New-Item -ItemType Directory -Force -Path $localRoot, (Join-Path $probeRoot 'src'), (Join-Path $coreRoot 'src'), (Join-Path $ownerRoot 'src'), (Join-Path $cacheRoot 'src') | Out-Null
if (-not (Test-Path -LiteralPath (Join-Path $sourceRoot '.git'))) {
    if ($Offline) { throw 'Pinned SDK is absent; initial online source preparation is required' }
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $sourceRoot) | Out-Null
    & git clone --no-checkout 'https://github.com/blyssprivacy/sdk.git' $sourceRoot
    if ($LASTEXITCODE -ne 0) { throw 'PIR source clone failed' }
    & git -C $sourceRoot checkout --detach $revision
    if ($LASTEXITCODE -ne 0) { throw 'Pinned PIR source checkout failed' }
}
$actualRevision = (& git -C $sourceRoot rev-parse HEAD).Trim()
if ($actualRevision -ne $revision) { throw "Expected SDK $revision; found $actualRevision" }
if (& git -C $sourceRoot status --porcelain --untracked-files=no) { throw 'Pinned SDK tracked source has modifications' }
$provenance = [ordered]@{
    experiment = 'private-bfv-disk-source'
    sdk_revision = $revision
    core_files = [ordered]@{}
    owner_state_files = [ordered]@{}
    cache_core_files = [ordered]@{}
    compact_store_files = [ordered]@{}
    composition_files = [ordered]@{}
}
foreach ($relative in @('Cargo.toml','src/lib.rs','src/kernel.rs')) {
    $source = Join-Path $BfvCoreDirectory $relative
    $provenance.core_files[$relative] = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
    Copy-Item -LiteralPath $source -Destination (Join-Path $coreRoot $relative)
}
foreach ($binding in @(@($PirOwnerStateDirectory,$ownerRoot,'owner_state_files'),@($CacheCoreDirectory,$cacheRoot,'cache_core_files'))) {
    foreach ($relative in @('Cargo.toml','src/lib.rs')) {
        $source = Join-Path $binding[0] $relative
        $provenance[$binding[2]][$relative] = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
        $contents = Get-Content -LiteralPath $source -Raw
        if ($relative -eq 'Cargo.toml') { $contents = $contents.Replace('../../.local/private-access/sdk','../../private-access/sdk') }
        [IO.File]::WriteAllText((Join-Path $binding[1] $relative),$contents,[Text.UTF8Encoding]::new($false))
    }
}
New-Item -ItemType Directory -Force -Path (Join-Path $storeRoot 'src') | Out-Null
foreach ($relative in @('Cargo.toml','src/lib.rs','src/crypto.rs','src/format.rs','src/proof.rs','src/snapshot.rs')) {
    $source = Join-Path $CompactStoreDirectory $relative
    $provenance.compact_store_files[$relative] = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
    if ($relative -eq 'Cargo.toml') {
        $contents = Get-Content -LiteralPath $source -Raw
        $contents = $contents.Replace('edition.workspace = true','edition = "2024"').Replace('rust-version.workspace = true','rust-version = "1.99"').Replace('serde_json.workspace = true','serde_json = "=1.0.154"')
        [IO.File]::WriteAllText((Join-Path $storeRoot $relative),$contents,[Text.UTF8Encoding]::new($false))
    } else { Copy-Item -LiteralPath $source -Destination (Join-Path $storeRoot $relative) }
}
foreach ($relative in @('main.rs','disk.rs','native.rs','server_schedule.rs','expansion_schedule.rs','resources.rs','padded_index_codec.rs','padded_index_codec_tests.rs','protocol_helpers.rs')) {
    $source = Join-Path $PSScriptRoot ('src/' + $relative)
    $provenance.composition_files[$relative] = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
    Copy-Item -LiteralPath $source -Destination (Join-Path $probeRoot ('src/' + $relative))
}
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'LICENSE-BLYSS') -Destination (Join-Path $probeRoot 'LICENSE-BLYSS')
$manifest = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Cargo.toml') -Raw
$manifest = $manifest.Replace('../bfv-byte-limb-core','../core').Replace('../spiral-owner-state','../owner-state').Replace('../spiral-cache-core','../cache-core')
$manifest = $manifest.Replace('../../crates/compact-store','../store').Replace('../../.local/private-access/sdk','../../private-access/sdk')
[IO.File]::WriteAllText((Join-Path $probeRoot 'Cargo.toml'), $manifest, [Text.UTF8Encoding]::new($false))
$lockSource = Join-Path $PSScriptRoot 'Cargo.lock'
if (Test-Path -LiteralPath $lockSource) { Copy-Item -LiteralPath $lockSource -Destination (Join-Path $probeRoot 'Cargo.lock') }
$provenance | ConvertTo-Json -Depth 5 -Compress | Write-Output
if ($PrepareOnly) { Write-Output "Prepared standalone source: $probeRoot"; return }
if (-not (Test-Path -LiteralPath $lockSource)) { throw 'Reviewed composition Cargo.lock is required before execution' }
$oldCargoHome = $env:CARGO_HOME
$oldTargetDirectory = $env:CARGO_TARGET_DIR
try {
    if (-not $CargoHome) { $CargoHome = Join-Path $repository '.local/cargo-home' }
    $env:CARGO_HOME = [IO.Path]::GetFullPath($CargoHome)
    if (-not $TargetDirectory) { $TargetDirectory = Join-Path $repository 'target/private-bfv-disk' }
    $env:CARGO_TARGET_DIR = [IO.Path]::GetFullPath($TargetDirectory)
    $buildArguments = @('build','--release','--locked','--jobs','2','--manifest-path',(Join-Path $probeRoot 'Cargo.toml'))
    if ($Offline) { $buildArguments += '--offline' }
    & $Cargo @buildArguments
    if ($LASTEXITCODE -ne 0) { throw 'Private BFV disk composition build failed' }
    $executable = Join-Path $env:CARGO_TARGET_DIR 'release/private-bfv-disk.exe'
    if ($env:OS -ne 'Windows_NT') { $executable = Join-Path $env:CARGO_TARGET_DIR 'release/private-bfv-disk' }
    $stamp = [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss-fff')
    $report = Join-Path $localRoot ('disk-' + $Tables + '-s' + $Samples + '-t' + $Threads + '-' + $ServerSchedule + '-' + $stamp + '.jsonl')
    $canonicalDirectory = Join-Path $localRoot ('snapshots-' + $stamp)
    if (-not $TableIds) { $TableIds = '0,' + [Math]::Floor(($Tables-1)/2) + ',' + ($Tables-1) }
    $provenance | ConvertTo-Json -Depth 5 -Compress | Set-Content -LiteralPath $report -Encoding utf8
    & $executable $Tables $Samples $Threads $TableIds $MaxCanonicalBytes $canonicalDirectory $ServerSchedule | Tee-Object -FilePath $report -Append
    if ($LASTEXITCODE -ne 0) { throw "Private BFV disk composition failed; partial report: $report" }
    Write-Output "Report: $report"
}
finally { $env:CARGO_HOME = $oldCargoHome; $env:CARGO_TARGET_DIR = $oldTargetDirectory }