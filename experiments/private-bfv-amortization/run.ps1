[CmdletBinding()]
param(
    [ValidateRange(2,20)][int]$Tables = 20,
    [ValidateRange(1,2)][int]$Samples = 2,
    [string]$TableIds,
    [ValidateRange(1,8)][int]$Threads = 8,
    [string]$Cargo = 'cargo',
    [string]$CargoHome,
    [string]$TargetDirectory,
    [string]$BfvCoreDirectory,
    [string]$PirOwnerStateDirectory,
    [switch]$PrepareOnly,
    [switch]$Offline
)
$ErrorActionPreference = 'Stop'
$repository = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$localRoot = Join-Path $repository '.local/private-bfv-amortization'
$probeRoot = Join-Path $localRoot 'package'
$sourceRoot = Join-Path $repository '.local/private-access/sdk'
$coreRoot = Join-Path $localRoot 'core'
$ownerRoot = Join-Path $localRoot 'owner-state'
$revision = 'fdb7206517c249603b0c91b65f1f29f95272107c'
if (-not $BfvCoreDirectory) { $BfvCoreDirectory = Join-Path $repository 'experiments/bfv-byte-limb-core' }
$BfvCoreDirectory = [IO.Path]::GetFullPath($BfvCoreDirectory)
New-Item -ItemType Directory -Force -Path $localRoot, (Join-Path $probeRoot 'src'), (Join-Path $coreRoot 'src') | Out-Null
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
$coreFiles = @('Cargo.toml','src/lib.rs','src/kernel.rs')
$provenance = [ordered]@{
    experiment = 'private-bfv-amortization-source'
    sdk_revision = $revision
    core_files = [ordered]@{}
    owner_state_files = [ordered]@{}
    composition_files = [ordered]@{}
}
foreach ($relative in $coreFiles) {
    $source = Join-Path $BfvCoreDirectory $relative
    if (-not (Test-Path -LiteralPath $source)) { throw "Core source is absent: $source" }
    $provenance.core_files[$relative] = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
    Copy-Item -LiteralPath $source -Destination (Join-Path $coreRoot $relative)
}
if (-not $PirOwnerStateDirectory) { $PirOwnerStateDirectory = Join-Path $repository 'experiments/spiral-owner-state' }
$PirOwnerStateDirectory = [IO.Path]::GetFullPath($PirOwnerStateDirectory)
New-Item -ItemType Directory -Force -Path (Join-Path $ownerRoot 'src') | Out-Null
foreach ($relative in @('Cargo.toml','src/lib.rs')) {
    $source = Join-Path $PirOwnerStateDirectory $relative
    $provenance.owner_state_files[$relative] = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
    $contents = Get-Content -LiteralPath $source -Raw
    if ($relative -eq 'Cargo.toml') {
        $contents = $contents.Replace('../../.local/private-access/sdk','../../private-access/sdk')
    }
    [IO.File]::WriteAllText((Join-Path $ownerRoot $relative),$contents,[Text.UTF8Encoding]::new($false))
}
foreach ($relative in @('main.rs','resources.rs','padded_index_codec.rs','padded_index_codec_tests.rs','codec_helpers.rs')) {
    $source = Join-Path $PSScriptRoot ('src/' + $relative)
    $provenance.composition_files[$relative] = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
    Copy-Item -LiteralPath $source -Destination (Join-Path $probeRoot ('src/' + $relative))
}
$manifest = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Cargo.toml') -Raw
$manifest = $manifest.Replace('../bfv-byte-limb-core','../core')
$manifest = $manifest.Replace('../spiral-owner-state','../owner-state')
$manifest = $manifest.Replace('../../crates/compact-store','../../../crates/compact-store')
$manifest = $manifest.Replace('../../.local/private-access/sdk','../../private-access/sdk')
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
    if (-not $TargetDirectory) { $TargetDirectory = Join-Path $repository 'target/private-bfv-amortization' }
    $env:CARGO_TARGET_DIR = [IO.Path]::GetFullPath($TargetDirectory)
    $buildArguments = @('build','--release','--locked','--jobs','2','--manifest-path',(Join-Path $probeRoot 'Cargo.toml'))
    if ($Offline) { $buildArguments += '--offline' }
    & $Cargo @buildArguments
    if ($LASTEXITCODE -ne 0) { throw 'Private BFV composition build failed' }
    $executable = Join-Path $env:CARGO_TARGET_DIR 'release/private-bfv-amortization.exe'
    if ($env:OS -ne 'Windows_NT') { $executable = Join-Path $env:CARGO_TARGET_DIR 'release/private-bfv-amortization' }
    $stamp = [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss-fff')
    $report = Join-Path $localRoot ('amortization-' + $Tables + '-s' + $Samples + '-t' + $Threads + '-' + $stamp + '.jsonl')
    $canonicalDirectory = Join-Path $localRoot ('snapshots-' + $stamp)
    if (-not $TableIds) {
        if ($Tables -eq 2) { $TableIds = '0,1' }
        else { $TableIds = '0,' + [Math]::Floor(($Tables-1)/2) + ',' + ($Tables-1) }
    }
    $provenance | ConvertTo-Json -Depth 5 -Compress | Set-Content -LiteralPath $report -Encoding utf8
    & $executable $Tables $Samples $Threads $TableIds $canonicalDirectory | Tee-Object -FilePath $report -Append
    if ($LASTEXITCODE -ne 0) { throw "Private BFV composition failed; partial report: $report" }
    Write-Output "Report: $report"
}
finally {
    $env:CARGO_HOME = $oldCargoHome
    $env:CARGO_TARGET_DIR = $oldTargetDirectory
}