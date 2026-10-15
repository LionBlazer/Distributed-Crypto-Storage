[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SourceRepository,
    [string]$OutputDirectory
)
$ErrorActionPreference='Stop'
$repository=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$source=[IO.Path]::GetFullPath($SourceRepository)
$encoding=[Text.UTF8Encoding]::new($false)
if((Get-FileHash -LiteralPath (Join-Path $source 'experiments/bfv-byte-limb-core/src/lib.rs')).Hash -cne 'F4EC7930D306AE933142AFE7455B500B61A23D53F3DBA69454E796F33EF88CCB'){
    throw 'Reviewed BFV baseline changed; inspect/re-pin before applying candidate source'
}
if((Get-FileHash -LiteralPath (Join-Path $source 'crates/compact-store/src/crypto.rs')).Hash -cne '9FC603CD9849391FBA0979ADCC46E408758CFAEAFB04519B977D71DAAC33246F'){
    throw 'Reviewed compact owner baseline changed'
}
$ownerSource=Join-Path $source 'experiments/spiral-owner-state/src/lib.rs'
if((Get-FileHash -LiteralPath $ownerSource).Hash -cne '32CF886EEAD6D14CA887E13B8A595FFAA5049E3ACB17844919A5B31F4AE25E3B'){
    throw 'Reviewed original Spiral owner contract changed'
}
$sdk=Join-Path $source '.local/private-access/sdk'
$revision=(& git -C $sdk rev-parse HEAD).Trim()
if($LASTEXITCODE-ne0 -or $revision-ne'fdb7206517c249603b0c91b65f1f29f95272107c'){
    throw 'Original SDK source pin is required'
}
if(& git -C $sdk status --porcelain --untracked-files=no){throw 'SDK tracked source changed'}
if(!$OutputDirectory){
    $stamp=[DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss-fff')
    $OutputDirectory=Join-Path $repository ".local/owner-recovery-candidate/source-$stamp"
}
$output=[IO.Path]::GetFullPath($OutputDirectory)
if(Test-Path -LiteralPath $output){throw 'Candidate output must be new; no existing artifact overwritten'}
New-Item -ItemType Directory -Path $output|Out-Null
$provenance=[ordered]@{stage='source-only-no-cargo-no-keygen-no-dataset';source_repository=$source;files=[ordered]@{};candidate=[ordered]@{}}
function Copy-SourceModule([string]$relative,[string]$destination){
    $base=Join-Path $source $relative
    New-Item -ItemType Directory -Force -Path $destination|Out-Null
    foreach($item in @('Cargo.toml','src','tests','README.md')){
        $path=Join-Path $base $item
        if(Test-Path -LiteralPath $path){Copy-Item -LiteralPath $path -Destination $destination -Recurse}
    }
    foreach($file in Get-ChildItem -LiteralPath $destination -File -Recurse){
        $name=([IO.Path]::GetRelativePath($destination,$file.FullName)).Replace('\','/')
        $provenance.files[($relative+'/'+$name)]=(Get-FileHash -LiteralPath $file.FullName).Hash
    }
}
$store=Join-Path $output 'store'
$bfv=Join-Path $output 'bfv'
$bundle=Join-Path $output 'bundle'
Copy-SourceModule 'crates/compact-store' $store
Copy-SourceModule 'experiments/bfv-byte-limb-core' $bfv
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'bundle') -Destination $output -Recurse
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'adapters/compact_owner_recovery.rs') -Destination (Join-Path $store 'src/owner_recovery.rs')
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'adapters/bfv_owner_recovery.rs') -Destination (Join-Path $bfv 'src/owner_recovery.rs')
$storeManifest=[IO.File]::ReadAllText((Join-Path $store 'Cargo.toml'))
$storeManifest=$storeManifest.Replace('name = "compact-store"','name = "compact-store-owner-recovery-candidate"')
$storeManifest=$storeManifest.Replace('edition.workspace = true','edition = "2024"').Replace('rust-version.workspace = true','rust-version = "1.99"')
$storeManifest=$storeManifest.Replace('serde_json.workspace = true','serde_json = "=1.0.154"')
$storeManifest += [Environment]::NewLine+'[workspace]'+[Environment]::NewLine+'[lib]'+[Environment]::NewLine+'name = "compact_store"'+[Environment]::NewLine
[IO.File]::WriteAllText((Join-Path $store 'Cargo.toml'),$storeManifest,$encoding)
[IO.File]::AppendAllText((Join-Path $store 'src/lib.rs'),[Environment]::NewLine+'pub const OWNER_RECOVERY_IMAGE_BYTES: usize = 80;'+[Environment]::NewLine+'pub use crypto::owner_recovery::OwnerRecoveryImage;'+[Environment]::NewLine,$encoding)
[IO.File]::AppendAllText((Join-Path $store 'src/crypto.rs'),[Environment]::NewLine+'#[path = "owner_recovery.rs"] pub(crate) mod owner_recovery;'+[Environment]::NewLine,$encoding)
$bfvManifest=[IO.File]::ReadAllText((Join-Path $bfv 'Cargo.toml')).Replace('name = "compact-bfv-byte-limb-core"','name = "compact-bfv-owner-recovery-candidate"')
$bfvManifest += [Environment]::NewLine+'[lib]'+[Environment]::NewLine+'name = "compact_bfv_byte_limb_core"'+[Environment]::NewLine
[IO.File]::WriteAllText((Join-Path $bfv 'Cargo.toml'),$bfvManifest,$encoding)
[IO.File]::AppendAllText((Join-Path $bfv 'src/lib.rs'),[Environment]::NewLine+'mod owner_recovery;'+[Environment]::NewLine+'pub use owner_recovery::{OWNER_RECOVERY_IMAGE_BYTES, OwnerRecoveryError, OwnerRecoveryImage};'+[Environment]::NewLine,$encoding)
$manifest=[IO.File]::ReadAllText((Join-Path $bundle 'Cargo.toml'))
$manifest=$manifest.Replace('compact-store = { path = "../generated-store" }','compact-store = { package = "compact-store-owner-recovery-candidate", path = "../store" }')
$manifest=$manifest.Replace('compact-bfv-byte-limb-core = { path = "../generated-bfv" }','compact-bfv-byte-limb-core = { package = "compact-bfv-owner-recovery-candidate", path = "../bfv" }')
$slashSource=$source.Replace('\','/')
$manifest=$manifest.Replace('../../spiral-owner-state',($slashSource+'/experiments/spiral-owner-state'))
$manifest=$manifest.Replace('../../spiral-cache-core',($slashSource+'/experiments/spiral-cache-core'))
$manifest=$manifest.Replace('../../../.local/private-access/sdk/lib/spiral-rs',($slashSource+'/.local/private-access/sdk/lib/spiral-rs'))
[IO.File]::WriteAllText((Join-Path $bundle 'Cargo.toml'),$manifest,$encoding)
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'locks/bfv.Cargo.lock') -Destination (Join-Path $bfv 'Cargo.lock')
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'locks/store.Cargo.lock') -Destination (Join-Path $store 'Cargo.lock')
$provenance.sdk_revision=$revision
$provenance.spiral_owner_source_sha256=(Get-FileHash -LiteralPath $ownerSource).Hash
foreach($file in Get-ChildItem -LiteralPath $output -File -Recurse){
    $provenance.candidate[([IO.Path]::GetRelativePath($output,$file.FullName)).Replace('\','/')]=(Get-FileHash -LiteralPath $file.FullName).Hash
}
[IO.File]::WriteAllText((Join-Path $output 'source-provenance.json'),($provenance|ConvertTo-Json -Depth 8),$encoding)
Write-Output "SOURCE_ONLY=$($output.Replace('\','/'))"
Write-Output "DEDICATED_TARGET=$($source.Replace('\','/'))/target/owner-recovery-candidate"
# Deliberately no Cargo, lock generation, owner generation, benchmark, secret export or dataset command.
