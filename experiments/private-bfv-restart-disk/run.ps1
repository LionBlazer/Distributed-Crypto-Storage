[CmdletBinding()]
param(
 [Parameter(Mandatory)][string]$PreparedDirectory,
 [Parameter(Mandatory)][string]$ArtifactRoot,
 [Parameter(Mandatory)][string]$TargetDirectory,
 [Parameter(Mandatory)][string]$CargoHome
)
$ErrorActionPreference='Stop'
$prepared=[IO.Path]::GetFullPath($PreparedDirectory)
$root=[IO.Path]::GetFullPath($ArtifactRoot)
$target=[IO.Path]::GetFullPath($TargetDirectory)
if(!(Test-Path -LiteralPath (Join-Path $prepared 'source-provenance.json'))){throw 'Explicit prepared source generation required'}
[IO.Directory]::CreateDirectory($root)|Out-Null
$env:CARGO_HOME=[IO.Path]::GetFullPath($CargoHome)
$env:CARGO_TARGET_DIR=$target
$env:CARGO_BUILD_JOBS='2'
$env:RAYON_NUM_THREADS='8'
& E:/Users/white/.cargo/bin/cargo.exe build --release --offline --locked --bins --manifest-path (Join-Path $prepared 'Cargo.toml')
if($LASTEXITCODE-ne0){throw 'Release build failed'}
$stamp=[DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss-fff')
$archive=Join-Path $root ('artifacts-'+$stamp)
if(Test-Path -LiteralPath $archive){throw 'Artifact generation must be new'}
[IO.Directory]::CreateDirectory($archive)|Out-Null
foreach($role in @('broker','writer','reader')){
 Copy-Item -LiteralPath (Join-Path $target ('release/private-bfv-restart-'+$role+'.exe')) -Destination $archive
}
$public=[ordered]@{tables=3;ids=@(0,1,2);samples=1;threads=8;max_canonical_bytes=67108864;
 directory=(Join-Path $root ('dataset-3-'+$stamp)).Replace('\','/');writer_timeout_seconds=300;reader_timeout_seconds=600}
$config=$public|ConvertTo-Json -Compress
$encoding=[Text.UTF8Encoding]::new($false)
$stream=[IO.File]::Open((Join-Path $archive 'public-config.json'),[IO.FileMode]::CreateNew)
$bytes=$encoding.GetBytes($config);$stream.Write($bytes);$stream.Dispose()
$manifest=[ordered]@{prepared_source=$prepared;files=[ordered]@{}}
foreach($f in Get-ChildItem -LiteralPath $archive -File){$manifest.files[$f.Name]=(Get-FileHash -LiteralPath $f.FullName).Hash}
[IO.File]::WriteAllText((Join-Path $archive 'public-artifact-manifest.json'),($manifest|ConvertTo-Json -Depth 6),$encoding)
# This starts the trusted broker, never an owner with a CLI/environment/file key.
& (Join-Path $archive 'private-bfv-restart-broker.exe') $config *> (Join-Path $archive 'broker.log')
$code=$LASTEXITCODE
Get-Content -LiteralPath (Join-Path $archive 'broker.log') -Tail 3
if($code-ne0){throw 'Bounded process probe failed; preserve all artifacts and do not automatically rerun'}
Write-Output ('ARTIFACTS='+$archive.Replace('\','/'))
