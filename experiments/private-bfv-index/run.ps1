[CmdletBinding()]
param(
    [ValidateRange(1000000,1000000)][int]$Rows = 1000000,
    [ValidateSet(4,8,12)][int]$Rounds = 8,
    [ValidateRange(1,8)][int]$Threads = 8,
    [string]$Cargo = 'cargo',
    [string]$CargoHome,
    [string]$TargetDirectory,
    [string]$BfvCoreDirectory,
    [switch]$PrepareOnly,
    [switch]$Offline
)
$ErrorActionPreference = 'Stop'
$repository = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$localRoot = Join-Path $repository '.local/private-bfv-index'
$probeRoot = Join-Path $localRoot 'package'
$sourceRoot = Join-Path $repository '.local/private-access/sdk'
$coreRoot = Join-Path $localRoot 'core'
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
    experiment = 'private-bfv-index-source'
    sdk_revision = $revision
    core_files = [ordered]@{}
    composition_files = [ordered]@{}
}
foreach ($relative in $coreFiles) {
    $source = Join-Path $BfvCoreDirectory $relative
    if (-not (Test-Path -LiteralPath $source)) { throw "Core source is absent: $source" }
    $provenance.core_files[$relative] = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
    Copy-Item -LiteralPath $source -Destination (Join-Path $coreRoot $relative)
}
foreach ($relative in @('main.rs','resources.rs','padded_index_codec.rs','padded_index_codec_tests.rs')) {
    $source = Join-Path $PSScriptRoot ('src/' + $relative)
    $provenance.composition_files[$relative] = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
    Copy-Item -LiteralPath $source -Destination (Join-Path $probeRoot ('src/' + $relative))
}
$manifest = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Cargo.toml') -Raw
$manifest = $manifest.Replace('../bfv-byte-limb-core','../core')
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
    if (-not $TargetDirectory) { $TargetDirectory = Join-Path $repository 'target/private-bfv-index' }
    $env:CARGO_TARGET_DIR = [IO.Path]::GetFullPath($TargetDirectory)
    $buildArguments = @('build','--release','--locked','--jobs','2','--manifest-path',(Join-Path $probeRoot 'Cargo.toml'))
    if ($Offline) { $buildArguments += '--offline' }
    & $Cargo @buildArguments
    if ($LASTEXITCODE -ne 0) { throw 'Private BFV composition build failed' }
    $executable = Join-Path $env:CARGO_TARGET_DIR 'release/private-bfv-index-composition.exe'
    if ($env:OS -ne 'Windows_NT') { $executable = Join-Path $env:CARGO_TARGET_DIR 'release/private-bfv-index-composition' }
    $report = Join-Path $localRoot ('private-bfv-index-' + $Rows + '-' + $Rounds + '-t' + $Threads + '-' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss-fff') + '.jsonl')
    $provenance | ConvertTo-Json -Depth 5 -Compress | Set-Content -LiteralPath $report -Encoding utf8
    & $executable $Rows $Rounds $Threads | Tee-Object -FilePath $report -Append
    if ($LASTEXITCODE -ne 0) { throw "Private BFV composition failed; partial report: $report" }
    Write-Output "Report: $report"
}
finally {
    $env:CARGO_HOME = $oldCargoHome
    $env:CARGO_TARGET_DIR = $oldTargetDirectory
}