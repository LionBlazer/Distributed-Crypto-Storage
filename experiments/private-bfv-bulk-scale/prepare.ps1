[CmdletBinding()]
param([Parameter(Mandatory)][string]$SourceRepository,[string]$OutputDirectory)
$ErrorActionPreference='Stop'
$repository=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$source=[IO.Path]::GetFullPath($SourceRepository)
$basis=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'source-basis.json') -Raw | ConvertFrom-Json
foreach($entry in $basis.frozen_copies.PSObject.Properties){
 if((Get-FileHash -LiteralPath (Join-Path $PSScriptRoot $entry.Name) -Algorithm SHA256).Hash -cne $entry.Value){throw ('Frozen module copy changed: '+$entry.Name)}
}
foreach($entry in $basis.owning_sources.PSObject.Properties){
 if((Get-FileHash -LiteralPath (Join-Path $source $entry.Name) -Algorithm SHA256).Hash -cne $entry.Value){throw ('Reviewed owning source changed: '+$entry.Name)}
}
$sdk=Join-Path $source '.local/private-access/sdk'
if((& git -C $sdk rev-parse HEAD).Trim() -ne $basis.sdk_revision -or $LASTEXITCODE -ne 0){throw 'Pinned public Spiral SDK required'}
if(& git -C $sdk status --porcelain --untracked-files=no){throw 'Pinned SDK tracked files are dirty'}
if(!$OutputDirectory){$OutputDirectory=Join-Path $repository ('.local/private-bfv-bulk-scale/source-'+[DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss-fff'))}
$output=[IO.Path]::GetFullPath($OutputDirectory)
if(Test-Path -LiteralPath $output){throw 'Source generation must be new; no source/artifact overwritten'}
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $output) | Out-Null
New-Item -ItemType Directory -Path $output | Out-Null
foreach($name in @('Cargo.toml','Cargo.lock','README.md','source-basis.json','src')){Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination $output -Recurse}
$slash=$source.Replace('\','/')
$path=Join-Path $output 'Cargo.toml'
$manifest=[IO.File]::ReadAllText($path).Replace('../../crates/compact-query',($slash+'/crates/compact-query')).Replace('../../crates/compact-store',($slash+'/crates/compact-store')).Replace('../spiral-owner-state',($slash+'/experiments/spiral-owner-state')).Replace('../../.local/private-access/sdk/lib/spiral-rs',($slash+'/.local/private-access/sdk/lib/spiral-rs'))
[IO.File]::WriteAllText($path,$manifest,[Text.UTF8Encoding]::new($false))
$provenance=[ordered]@{status='source-only-unbuilt';source_repository=$source;files=[ordered]@{}}
foreach($file in Get-ChildItem -LiteralPath $output -File -Recurse){$provenance.files[([IO.Path]::GetRelativePath($output,$file.FullName)).Replace('\','/')]=(Get-FileHash -LiteralPath $file.FullName).Hash}
[IO.File]::WriteAllText((Join-Path $output 'source-provenance.json'),($provenance | ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false))
Write-Output ('SOURCE_ONLY='+$output.Replace('\','/'))
Write-Output ('DEDICATED_TARGET='+$slash+'/target/private-bfv-bulk-scale')
# No Cargo, key generation, fixture/dataset creation or cryptographic operation executes here.
