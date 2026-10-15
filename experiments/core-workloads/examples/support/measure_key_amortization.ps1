param(
 [Parameter(Mandatory=$true)][string]$Label,
 [int]$Tables=2, [int]$Rows=1000000, [int]$Samples=3,
 [string]$Executable=''
)
$ErrorActionPreference='Stop'
if($Label -notmatch '^[A-Za-z0-9-]+$'){throw 'Use a simple unique report label'}
if($Tables -lt 2 -or $Tables -gt 210){throw 'Tables must be2..210'}
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class AmortizationJob {
 [StructLayout(LayoutKind.Sequential)] public struct BasicLimits {
  public long ProcessTime, JobTime;
  public uint Flags;
  public UIntPtr MinimumWorkingSet, MaximumWorkingSet;
  public uint ActiveProcesses;
  public UIntPtr Affinity;
  public uint Priority, Scheduling;
 }
 [StructLayout(LayoutKind.Sequential)] public struct IoCounters {
  public ulong ReadOps, WriteOps, OtherOps, ReadBytes, WriteBytes, OtherBytes;
 }
 [StructLayout(LayoutKind.Sequential)] public struct ExtendedLimits {
  public BasicLimits Basic;
  public IoCounters Io;
  public UIntPtr ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemory, PeakJobMemory;
 }
 [StructLayout(LayoutKind.Sequential)] public struct MemoryCounters {
  public uint Size, Faults;
  public UIntPtr PeakWorkingSet, WorkingSet, PeakPaged, Paged, PeakNonpaged,
   Nonpaged, Pagefile, PeakPagefile, PrivateUsage;
 }
 [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
 public static extern IntPtr CreateJobObject(IntPtr attributes, string name);
 [DllImport("kernel32.dll", SetLastError=true)]
 public static extern bool SetInformationJobObject(IntPtr job, int infoClass, ref ExtendedLimits info, uint length);
 [DllImport("kernel32.dll", SetLastError=true)]
 public static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
 [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr handle);
 [DllImport("psapi.dll", SetLastError=true)]
 public static extern bool GetProcessMemoryInfo(IntPtr process, ref MemoryCounters counters, uint size);
}
"@
$taskRoot=(Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '../../../..')).Path
if([string]::IsNullOrWhiteSpace($Executable)){
 $targetDirectory=if([string]::IsNullOrWhiteSpace($env:CARGO_TARGET_DIR)){
  Join-Path $taskRoot 'target'
 }elseif([IO.Path]::IsPathRooted($env:CARGO_TARGET_DIR)){
  $env:CARGO_TARGET_DIR
 }else{
  Join-Path $taskRoot $env:CARGO_TARGET_DIR
 }
 $Executable=Join-Path $targetDirectory 'release/examples/key_amortization.exe'
}
$reportRoot=Join-Path $taskRoot '.local/fhe-research/key-amortization'
$null=New-Item -ItemType Directory -Force -Path $reportRoot
$job=[AmortizationJob]::CreateJobObject([IntPtr]::Zero,$null)
if($job-eq[IntPtr]::Zero){throw 'Cannot create process-local memory job'}
$child=$null
try {
 $limits=New-Object AmortizationJob+ExtendedLimits
 # Only the newly launched child is assigned. No parent/user process or global setting changes.
 $limits.Basic.Flags=0x100 -bor 0x2000 # PROCESS_MEMORY + KILL_ON_JOB_CLOSE
 $limits.ProcessMemoryLimit=[UIntPtr]::new([uint64]1850000000)
 $limitSize=[Runtime.InteropServices.Marshal]::SizeOf($limits)
 if(-not[AmortizationJob]::SetInformationJobObject($job,9,[ref]$limits,$limitSize)){throw 'Cannot set child private-commit limit'}
 $info=New-Object Diagnostics.ProcessStartInfo
 $info.FileName=$Executable
 $info.Arguments="$Tables $Rows 2048 $Samples"
 $info.WorkingDirectory=$taskRoot
 $info.UseShellExecute=$false
 $info.CreateNoWindow=$true
 $info.WindowStyle=[Diagnostics.ProcessWindowStyle]::Hidden
 $info.RedirectStandardOutput=$true
 $info.RedirectStandardError=$true
 $child=New-Object Diagnostics.Process
 $child.StartInfo=$info
 $clock=[Diagnostics.Stopwatch]::StartNew()
 $null=$child.Start()
 $nativeHandle=$child.Handle
 if(-not[AmortizationJob]::AssignProcessToJobObject($job,$nativeHandle)){
  $child.Kill()
  throw 'Cannot assign own benchmark child to bounded-memory job'
 }
 $stdout=$child.StandardOutput.ReadToEndAsync()
 $stderr=$child.StandardError.ReadToEndAsync()
 $watchdogStopped=$false
 while(-not $child.WaitForExit(25)){
  $child.Refresh()
  if($child.PeakWorkingSet64 -gt 2000000000){
   $watchdogStopped=$true
   $child.Kill()
   break
  }
 }
 $child.WaitForExit()
 $clock.Stop()
 $memory=New-Object AmortizationJob+MemoryCounters
 $memory.Size=[Runtime.InteropServices.Marshal]::SizeOf($memory)
 $memoryOk=[AmortizationJob]::GetProcessMemoryInfo($nativeHandle,[ref]$memory,$memory.Size)
 $metadata=[ordered]@{
  label=$Label;tables=$Tables;rows_per_table=$Rows;rows_per_page=2048;query_samples_per_table=$Samples
  exit_code=$child.ExitCode;wall_ms=$clock.Elapsed.TotalMilliseconds
  child_cpu_ms=$child.TotalProcessorTime.TotalMilliseconds
  process_local_job_private_commit_limit_bytes=1850000000;rss_watchdog_limit_bytes=2000000000
  watchdog_stopped=$watchdogStopped;kernel_memory_counter_success=$memoryOk
  peak_working_set_bytes=if($memoryOk){$memory.PeakWorkingSet.ToUInt64()}else{$null}
  peak_commit_bytes=if($memoryOk){$memory.PeakPagefile.ToUInt64()}else{$null}
  executable=$Executable;executable_sha256=(Get-FileHash -LiteralPath $Executable -Algorithm SHA256).Hash
  runner_sha256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash
  timestamp_utc=[DateTime]::UtcNow.ToString('o');logical_processors=[Environment]::ProcessorCount
 }
 [IO.File]::WriteAllText((Join-Path $reportRoot "$Label.jsonl"),$stdout.GetAwaiter().GetResult())
 [IO.File]::WriteAllText((Join-Path $reportRoot "$Label.stderr.txt"),$stderr.GetAwaiter().GetResult())
 [IO.File]::WriteAllText((Join-Path $reportRoot "$Label.process.json"),($metadata|ConvertTo-Json))
 $metadata|ConvertTo-Json -Compress
 if($child.ExitCode-ne0 -or $watchdogStopped){throw 'Bounded experiment child failed; preserve partial report, do not claim success'}
 if(-not $memoryOk -or $memory.PeakWorkingSet.ToUInt64()-gt2000000000 -or $memory.PeakPagefile.ToUInt64()-gt1850000000){throw 'Measured native memory gate failed'}
} finally {
 if($null-ne$child){
  if(-not $child.HasExited){$child.Kill();$child.WaitForExit()}
  $child.Dispose()
 }
 $null=[AmortizationJob]::CloseHandle($job)
}
