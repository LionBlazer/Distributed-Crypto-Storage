[CmdletBinding()]
param(
    [string]$SdkDirectory,
    [string]$Cargo = 'cargo',
    [string]$CargoHome,
    [string]$TargetDirectory,
    [ValidateSet('prepare','check','bench')][string]$Mode = 'prepare'
)
$ErrorActionPreference = 'Stop'
$repository = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$local = Join-Path $repository '.local/spiral-cache-core'
$package = Join-Path $local 'package'
if (-not $SdkDirectory) { $SdkDirectory = Join-Path $repository '.local/private-access/sdk' }
$SdkDirectory = [IO.Path]::GetFullPath($SdkDirectory)
$revision = 'fdb7206517c249603b0c91b65f1f29f95272107c'
$actual = (& git -C $SdkDirectory rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $actual -ne $revision) { throw 'Expected exact pinned SDK checkout' }
if (& git -C $SdkDirectory status --porcelain --untracked-files=no) { throw 'SDK tracked source has modifications' }
$provenance = [ordered]@{ experiment='spiral-cache-core-source'; sdk_revision=$revision; source=[ordered]@{} }
foreach ($relative in @('Cargo.toml','src/lib.rs','tests/cache_contract.rs','examples/cache_setup.rs','examples/support/memory.rs','run.ps1')) {
    $source = Join-Path $PSScriptRoot $relative
    $provenance.source[$relative] = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
    if ($relative -eq 'run.ps1') { continue }
    $destination = Join-Path $package $relative
    [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($destination)) | Out-Null
    if ($relative -eq 'Cargo.toml') {
        $contents = Get-Content -LiteralPath $source -Raw
        $contents = $contents.Replace('../../.local/private-access/sdk',$SdkDirectory.Replace('\','/'))
        [IO.File]::WriteAllText($destination,$contents,[Text.UTF8Encoding]::new($false))
    } else { Copy-Item -LiteralPath $source -Destination $destination }
}
$lock = Join-Path $PSScriptRoot 'Cargo.lock'
if (Test-Path -LiteralPath $lock) {
    Copy-Item -LiteralPath $lock -Destination (Join-Path $package 'Cargo.lock')
    $provenance.source['Cargo.lock'] = (Get-FileHash -LiteralPath $lock -Algorithm SHA256).Hash
}
$provenance | ConvertTo-Json -Depth 4 -Compress | Write-Output
if ($Mode -eq 'prepare') { return }
if (-not (Test-Path -LiteralPath $lock)) { throw 'Generate/review the isolated Cargo.lock before execution' }
$oldCargoHome = $env:CARGO_HOME
$oldTarget = $env:CARGO_TARGET_DIR
try {
    if (-not $CargoHome) { $CargoHome = Join-Path $repository '.local/cargo-home' }
    if (-not $TargetDirectory) { $TargetDirectory = Join-Path $repository 'target/spiral-cache-core' }
    $env:CARGO_HOME = [IO.Path]::GetFullPath($CargoHome)
    $env:CARGO_TARGET_DIR = [IO.Path]::GetFullPath($TargetDirectory)
    $manifest = Join-Path $package 'Cargo.toml'
    if ($Mode -eq 'check') {
        & $Cargo test --release --locked --offline --jobs 2 --manifest-path $manifest -- --test-threads=1
        if ($LASTEXITCODE -ne 0) { throw 'Cache conversion tests failed' }
        & $Cargo clippy --release --locked --offline --all-targets --no-deps --jobs 2 --manifest-path $manifest -- -D warnings
        if ($LASTEXITCODE -ne 0) { throw 'Cache conversion Clippy failed' }
    } else {
        & $Cargo build --release --locked --offline --example cache_setup --jobs 2 --manifest-path $manifest
        if ($LASTEXITCODE -ne 0) { throw 'Cache setup benchmark build failed' }
        $exe = Join-Path $env:CARGO_TARGET_DIR 'release/examples/cache_setup.exe'
        $report = Join-Path $local ('cache-setup-'+[DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss-fff')+'.jsonl')
        $provenance | ConvertTo-Json -Depth 4 -Compress | Set-Content -LiteralPath $report -Encoding utf8
        foreach ($sample in @(0,1,2)) {
            $order = if ($sample % 2 -eq 0) { @('serial','parallel') } else { @('parallel','serial') }
            foreach ($implementation in $order) {
                & $exe $implementation | Tee-Object -FilePath $report -Append
                if ($LASTEXITCODE -ne 0) { throw "Cache setup benchmark failed; partial report $report" }
            }
        }
        Write-Output "Report: $report"
    }
} finally {
    $env:CARGO_HOME = $oldCargoHome
    $env:CARGO_TARGET_DIR = $oldTarget
}