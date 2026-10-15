[CmdletBinding()]
param(
 [Parameter(Mandatory)][string]$SourceRepository,
 [Parameter(Mandatory)][string]$PreparedOwnerDirectory,
 [string]$OutputDirectory
)
$ErrorActionPreference='Stop'
$repository=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$source=[IO.Path]::GetFullPath($SourceRepository)
$owners=[IO.Path]::GetFullPath($PreparedOwnerDirectory)
$encoding=[Text.UTF8Encoding]::new($false)
if((Get-FileHash -LiteralPath (Join-Path $owners 'bfv/src/owner_recovery.rs')).Hash -cne '149FA91A6FF6711825F00C782DF6C5086023419278CDE09C7F3D6BA440E1C007'){throw 'Validated BFV recovery adapter changed'}
if((Get-FileHash -LiteralPath (Join-Path $owners 'store/src/owner_recovery.rs')).Hash -cne 'DFB78D40552CB97FD27FB269979DC814C490EB948CC365629EFAAC8B895D2335'){throw 'Validated compact recovery adapter changed'}
if((Get-FileHash -LiteralPath (Join-Path $source 'experiments/spiral-owner-state/src/lib.rs')).Hash -cne '32CF886EEAD6D14CA887E13B8A595FFAA5049E3ACB17844919A5B31F4AE25E3B'){throw 'Reviewed original Spiral state contract changed'}
if((Get-FileHash -LiteralPath (Join-Path $source 'experiments/spiral-cache-core/src/lib.rs')).Hash -cne '4DA15C08050DD6F55FA2B0811088513DF8A31540848A91B56F4E9B059A5E6DCE'){throw 'Reviewed NTT cache helper changed'}
$pins=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'owner-source-pins.json') -Raw|ConvertFrom-Json
foreach($entry in $pins.PSObject.Properties){
 if((Get-FileHash -LiteralPath (Join-Path $owners $entry.Name)).Hash -cne $entry.Value){throw ('Validated owning runtime source changed: '+$entry.Name)}
}

$sdk=Join-Path $source '.local/private-access/sdk'
if((& git -C $sdk rev-parse HEAD).Trim()-ne'fdb7206517c249603b0c91b65f1f29f95272107c' -or $LASTEXITCODE-ne0){throw 'Pinned original Spiral SDK required'}
if(& git -C $sdk status --porcelain --untracked-files=no){throw 'SDK tracked source is dirty'}
if(!$OutputDirectory){$OutputDirectory=Join-Path $repository ('.local/private-bfv-restart-disk/source-'+[DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss-fff'))}
$output=[IO.Path]::GetFullPath($OutputDirectory)
if(Test-Path -LiteralPath $output){throw 'Source generation must be new; no old source/artifact overwritten'}
New-Item -ItemType Directory -Path $output|Out-Null
foreach($name in @('Cargo.toml','Cargo.lock','src','bundle','LICENSE-BLYSS','source-basis.json')){
 Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination $output -Recurse
}
$generated=Join-Path $output 'owners'
New-Item -ItemType Directory -Path $generated|Out-Null
foreach($role in @('bfv','store')){
 $dest=Join-Path $generated $role
 New-Item -ItemType Directory -Path $dest|Out-Null
 foreach($item in @('Cargo.toml','src','tests','README.md')){
  $path=Join-Path (Join-Path $owners $role) $item
  if(Test-Path -LiteralPath $path){Copy-Item -LiteralPath $path -Destination $dest -Recurse}
 }
 Copy-Item -LiteralPath (Join-Path $PSScriptRoot ('locks/'+$role+'.Cargo.lock')) -Destination (Join-Path $dest 'Cargo.lock')

 $manifest=[IO.File]::ReadAllText((Join-Path $dest 'Cargo.toml')).Replace('-owner-recovery-candidate','-process-restart-candidate')
 [IO.File]::WriteAllText((Join-Path $dest 'Cargo.toml'),$manifest,$encoding)
}
$slashSource=$source.Replace('\','/')
$manifest=[IO.File]::ReadAllText((Join-Path $output 'Cargo.toml'))
$manifest=$manifest.Replace('../generated/store','owners/store').Replace('../generated/bfv','owners/bfv')
$manifest=$manifest.Replace('[workspace]','[workspace]'+[Environment]::NewLine+'exclude = ["owners/store", "owners/bfv", "bundle"]')
$manifest=$manifest.Replace('../spiral-owner-state',($slashSource+'/experiments/spiral-owner-state'))
$manifest=$manifest.Replace('../spiral-cache-core',($slashSource+'/experiments/spiral-cache-core'))
$manifest=$manifest.Replace('../../.local/private-access/sdk/lib/spiral-rs',($slashSource+'/.local/private-access/sdk/lib/spiral-rs'))
[IO.File]::WriteAllText((Join-Path $output 'Cargo.toml'),$manifest,$encoding)
$path=Join-Path $output 'bundle/Cargo.toml'
$manifest=[IO.File]::ReadAllText($path).Replace('../../generated/store','../owners/store').Replace('../../generated/bfv','../owners/bfv')
$manifest=$manifest.Replace('../../spiral-owner-state',($slashSource+'/experiments/spiral-owner-state'))
$manifest=$manifest.Replace('../../../.local/private-access/sdk/lib/spiral-rs',($slashSource+'/.local/private-access/sdk/lib/spiral-rs'))
[IO.File]::WriteAllText($path,$manifest,$encoding)
$reader=[IO.File]::ReadAllText((Join-Path $output 'src/bin/reader.rs'))
if($reader.Contains('::generate(')-or$reader.Contains('public_rows(')-or$reader.Contains('build_catalog(')){throw 'Reader must import original material, not generate fixtures or owners'}
$provenance=[ordered]@{stage='source-only';source_repository=$source;validated_owner_source=$owners;files=[ordered]@{}}
foreach($file in Get-ChildItem -LiteralPath $output -File -Recurse){
 $provenance.files[([IO.Path]::GetRelativePath($output,$file.FullName)).Replace('\','/')]=(Get-FileHash -LiteralPath $file.FullName).Hash
}
[IO.File]::WriteAllText((Join-Path $output 'source-provenance.json'),($provenance|ConvertTo-Json -Depth 8),$encoding)
Write-Output ('SOURCE_ONLY='+$output.Replace('\','/'))
Write-Output ('DEDICATED_TARGET='+$slashSource+'/target/private-bfv-process-restart-disk')
# No Cargo, key generation, dataset creation or secret export occurs in this source preparation.
