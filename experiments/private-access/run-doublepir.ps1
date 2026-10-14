[CmdletBinding()]
param(
    [ValidateRange(1,1000000)][int]$Rows = 1000000,
    [ValidateRange(1,100)][int]$Rounds = 8,
    [ValidateRange(1,8)][int]$Threads = 8,
    [string]$Cargo = 'cargo',
    [string]$CargoHome,
    [string]$TargetDirectory,
    [switch]$Offline
)
$ErrorActionPreference = 'Stop'
$repository = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$localRoot = Join-Path $repository '.local/private-access'
$sourceRoot = Join-Path $localRoot 'sdk'
$probeRoot = Join-Path $localRoot 'probe'
$revision = 'fdb7206517c249603b0c91b65f1f29f95272107c'
New-Item -ItemType Directory -Force -Path $localRoot, (Join-Path $probeRoot 'src') | Out-Null
if (-not (Test-Path -LiteralPath (Join-Path $sourceRoot '.git'))) {
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
name = "private-access-probe"
version = "0.1.0"
edition = "2024"
[workspace]
[dependencies]
doublepir-rs = { path = "../sdk/lib/doublepir" }
rand = "=0.8.5"
aes = "0.8.2"
ctr = "0.9.2"
rayon = "1.11"
serde_json = "1"
'@ | Set-Content -LiteralPath (Join-Path $probeRoot 'Cargo.toml') -Encoding utf8
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'doublepir_probe.rs') -Destination (Join-Path $probeRoot 'src/main.rs')
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Cargo.lock') -Destination (Join-Path $probeRoot 'Cargo.lock')
$oldCargoHome = $env:CARGO_HOME
$oldTargetDirectory = $env:CARGO_TARGET_DIR
try {
    if ($CargoHome) { $env:CARGO_HOME = [IO.Path]::GetFullPath($CargoHome) }
    if (-not $TargetDirectory) { $TargetDirectory = Join-Path $repository 'target' }
    $env:CARGO_TARGET_DIR = [IO.Path]::GetFullPath($TargetDirectory)
    $buildArguments = @('build', '--release', '--locked', '--manifest-path', (Join-Path $probeRoot 'Cargo.toml'))
    if ($Offline) { $buildArguments += '--offline' }
    & $Cargo @buildArguments
    if ($LASTEXITCODE -ne 0) { throw 'PIR probe build failed' }
    $executable = Join-Path $env:CARGO_TARGET_DIR 'release/private-access-probe.exe'
    if ($env:OS -ne 'Windows_NT') { $executable = Join-Path $env:CARGO_TARGET_DIR 'release/private-access-probe' }
    $report = Join-Path $localRoot ('doublepir-' + $Rows + '-' + $Rounds + '-t' + $Threads + '-' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss-fff') + '.jsonl')
    & $executable $Rows $Rounds $Threads | Tee-Object -FilePath $report
    if ($LASTEXITCODE -ne 0) { throw "PIR probe failed; partial report: $report" }
    Write-Output "Report: $report"
}
finally {
    $env:CARGO_HOME = $oldCargoHome
    $env:CARGO_TARGET_DIR = $oldTargetDirectory
}
