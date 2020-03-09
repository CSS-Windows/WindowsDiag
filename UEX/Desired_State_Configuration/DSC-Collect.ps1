$version = "DSC-Collect (20200309)"
# by Gianni Bragante - gbrag@microsoft.com

Function Write-Log {
  param( [string] $msg )
  $msg = (get-date).ToString("yyyyMMdd HH:mm:ss.fff") + " " + $msg
  Write-Host $msg
  $msg | Out-File -FilePath $outfile -Append
}

Function ExecQuery {
  param(
    [string] $NameSpace,
    [string] $Query
  )
  Write-Log ("Executing query " + $Query)
  if ($PSVersionTable.psversion.ToString() -ge "3.0") {
    $ret = Get-CimInstance -Namespace $NameSpace -Query $Query -ErrorAction Continue 2>>$errfile
  } else {
    $ret = Get-WmiObject -Namespace $NameSpace -Query $Query -ErrorAction Continue 2>>$errfile
  }
  Write-Log (($ret | measure).count.ToString() + " results")
  return $ret
}

Function ArchiveLog {
  param( [string] $LogName )
  $cmd = "wevtutil al """+ $resDir + "\" + $env:computername + "-" + $LogName + ".evtx"" /l:en-us >>""" + $outfile + """ 2>>""" + $errfile + """"
  Write-Log $cmd
  Invoke-Expression $cmd
}

Function Win10Ver {
  param(
    [string] $Build
  )
  if ($build -eq 14393) {
    return " (RS1 / 1607)"
  } elseif ($build -eq 15063) {
    return " (RS2 / 1703)"
  } elseif ($build -eq 16299) {
    return " (RS3 / 1709)"
  } elseif ($build -eq 17134) {
    return " (RS4 / 1803)"
  } elseif ($build -eq 17763) {
    return " (RS5 / 1809)"
  } elseif ($build -eq 18362) {
    return " (19H1 / 1903)"
  } elseif ($build -eq 18363) {
    return " (19H2 / 1909)"  
  }
}

Add-Type -MemberDefinition @"
[DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern uint NetApiBufferFree(IntPtr Buffer);
[DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern int NetGetJoinInformation(
  string server,
  out IntPtr NameBuffer,
  out int BufferType);
"@ -Namespace Win32Api -Name NetApi32

function GetNBDomainName {
  $pNameBuffer = [IntPtr]::Zero
  $joinStatus = 0
  $apiResult = [Win32Api.NetApi32]::NetGetJoinInformation(
    $null,               # lpServer
    [Ref] $pNameBuffer,  # lpNameBuffer
    [Ref] $joinStatus    # BufferType
  )
  if ( $apiResult -eq 0 ) {
    [Runtime.InteropServices.Marshal]::PtrToStringAuto($pNameBuffer)
    [Void] [Win32Api.NetApi32]::NetApiBufferFree($pNameBuffer)
  }
}

Function GetFileVersion($filename) {
  $getfile = Get-Item $filename
  ("""" + $filename +""",""" + $getfile.creationtime +""",""" + $getfile.VersionInfo.FileVersion + """") | Out-File ($resDir + "\FileVersions.csv") -Append
}

$myWindowsID = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal = new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
$adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
if (-not $myWindowsPrincipal.IsInRole($adminRole)) {
  Write-Output "This script needs to be run as Administrator"
  exit
}

Write-Host "This script is designed to collect information that will help Microsoft Customer Support Services (CSS) troubleshoot an issue you may be experiencing with Windows."
Write-Host "The collected data may contain Personally Identifiable Information (PII) and/or sensitive data, such as (but not limited to) IP addresses, PC names, and user names."
Write-Host "Once the tracing and data collection has completed, the script will save the data in a subfolder. This folder is not automatically sent to Microsoft."
Write-Host "You can send this folder to Microsoft CSS using a secure file transfer tool - Please discuss this with your support professional and also any concerns you may have."
Write-Host "Find our privacy statement here: https://privacy.microsoft.com/en-us/privacy"
$confirm = Read-Host ("Are you sure you want to continue[Y/N]?")
if ($confirm.ToLower() -ne "y") {exit}

$Root = Split-Path (Get-Variable MyInvocation).Value.MyCommand.Path

$resName = "DSC-Results-" + $env:computername +"-" + $(get-date -f yyyyMMdd_HHmmss)
$resDir = $Root + "\" + $resName
$outfile = $resDir + "\script-output.txt"
$errfile = $resDir + "\script-errors.txt"

New-Item -itemtype directory -path $resDir | Out-Null

Write-Log $version

Write-Log "PowerShell version"
$PSVersionTable | Out-File -FilePath ($resDir + "\PSVersion.txt") -Append

if (Test-Path -Path "C:\Program Files\WindowsPowerShell\DscService\RegistrationKeys.txt") {
  Write-Log "Registration keys"
  Copy-Item "C:\Program Files\WindowsPowerShell\DscService\RegistrationKeys.txt" ($resDir + "\RegistrationKeys.txt")
}


$DSCDb = "C:\Program Files\WindowsPowerShell\DscService\Devices.edb"
if (Test-Path -Path ($env:windir + "\System32\inetsrv\Config\ApplicationHost.config")) {
  Write-Log "IIS ApplicationHost.config"
  Copy-Item "C:\Windows\System32\inetsrv\Config\ApplicationHost.config" ($resDir + "\ApplicationHost.config")

  $doc = (Get-content ($env:windir + "\System32\inetsrv\Config\ApplicationHost.config")) -as [xml]
  $logdir = ($doc.configuration.'system.applicationHost'.log.ChildNodes[1].directory).Replace("%SystemDrive%", $env:SystemDrive)
  
  foreach ($site in $doc.configuration.'system.applicationHost'.sites.site) {
    $sitedir = $resDir + "\websites\" + $site.name
    New-Item -itemtype directory -path $sitedir | Out-Null
    write-host $site.name, $site.application.ChildNodes[0].physicalpath
    $path = ($site.application.ChildNodes[0].physicalpath).Replace("%SystemDrive%", $env:SystemDrive)
    if (Test-Path -Path ($path + "\web.config")) {
      Copy-Item -path ($path + "\web.config") -destination $sitedir -ErrorAction Continue 2>>$errfile

      $siteLogDir = ($logdir + "\W3SVC" + $site.id)
      $last = Get-ChildItem -path ($siteLogDir) | Sort CreationTime -Descending | Select Name -First 1 
      Copy-Item ($siteLogDir + "\" + $last.name) $sitedir -ErrorAction Continue 2>>$errfile

      if ($site.name -eq "PSDSCPullServer") {
        GetFileVersion ($path + "\bin\Microsoft.Powershell.DesiredStateConfiguration.Service.dll")
        $docDSC = (Get-content ($path + "\web.config")) -as [xml]
        foreach ($conf in $docDSC.configuration.appSettings.add) {
          if ($conf.key -eq "dbconnectionstr") {
            $DSCDb = $conf.value
            Write-Log ("DSC dbconnectionstr = " + $DSCDb )
          }
        }
      }
    }
  }
 }

if (Test-Path -Path "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config") {
  Write-Log "Globabl web.config"
  Copy-Item "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config" ($resDir + "\global-web.config")
}

$dir = $env:windir + "\system32\logfiles\HTTPERR"
if (Test-Path -path $dir) {
  $last = Get-ChildItem -path ($dir) | Sort CreationTime -Descending | Select Name -First 1 
  Copy-Item ($dir + "\" + $last.name) $resDir\httperr.log -ErrorAction Continue 2>>$errfile
}

if (Test-Path -Path "C:\Program Files\WindowsPowerShell\DscService\Devices.edb") {
  $cmd = "cmd.exe /c esentutl.exe /y """ + $DSCDb +  """ /vssrec"
  Write-Log $cmd
  Invoke-Expression $cmd
  Move-Item .\Devices.edb $resDir
}

Write-Log "DSC Configuration"
Copy-Item "C:\Windows\System32\Configuration" -Recurse $resDir

if (Test-Path -Path "C:\WindowsAzure\Logs\WaAppAgent.log") {
  Write-Log "Windows Azure Guest Agent log"
  Copy-Item "C:\WindowsAzure\Logs\WaAppAgent.log" ($resDir + "\WaAppAgent.log")
}

if (Test-Path -Path "C:\WindowsAzure\Logs\Plugins\Microsoft.Powershell.DSC") {
  Write-Log "Azure DSC Extension Logs"
  Copy-Item "C:\WindowsAzure\Logs\Plugins\Microsoft.Powershell.DSC" -Recurse ($resDir + "\AzureDSCLogs")
}

if (Test-Path -Path "C:\Packages\Plugins\Microsoft.Powershell.DSC") {
  Write-Log "Azure DSC Extension Package"
  Copy-Item "C:\Packages\Plugins\Microsoft.Powershell.DSC" -Recurse ($resDir + "\AzureDSCPackage")
}

if (Test-Path -Path "C:\Windows\Temp\ScriptLog.log") {
  Write-Log "Windows Virtual Desktop log"
  Copy-Item "C:\Windows\Temp\ScriptLog.log" ($resDir + "\WVD-ScriptLog.log")
}

if (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Azure\DSC") {
  Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Azure\DSC"
  $cmd = "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Azure\DSC """+ $resDir + "\AzureDSC.reg.txt"" /y >>""" + $outfile + """ 2>>""" + $errfile + """"
  Invoke-Expression $cmd
}

if (Test-Path -Path "C:\Program Files\WindowsPowerShell\DscService\Configuration") {
  Write-Log "DSC Service Configuration"
  New-Item -itemtype directory -path ($resDir + "\DscService") | Out-Null
  Copy-Item "C:\Program Files\WindowsPowerShell\DscService\Configuration" -Recurse ($resDir + "\DscService")
}

Write-Log "Installed certificates"
Get-ChildItem Cert:\LocalMachine\My\ | Out-File -FilePath ($resDir + "\CertLocalMachineMy.txt")

Write-Log "Get-Module output"
Get-Module -ListAvailable | Out-File -FilePath ($resDir + "\Get-Module.txt")

Write-Log "Get-DscResource output"
Get-DscResource | Out-File -FilePath ($resDir + "\Get-DscResource.txt")

Write-Log "Get-DscLocalConfigurationManager output"
Get-DscLocalConfigurationManager | Out-File -FilePath ($resDir + "\Get-DscLocalConfigurationManager.txt")

Write-Log "Get-DscConfiguration output"
Get-DscConfiguration | Out-File -FilePath ($resDir + "\Get-DscConfiguration.txt")

Write-Log "Get-DscConfigurationStatus output"
Get-DscConfigurationStatus -all 2>>$errfile | Out-File -FilePath ($resDir + "\Get-DscConfigurationStatus.txt")

$dir = $env:windir + "\system32\inetsrv"
if (Test-Path -Path $dir) {
  $cmd = $dir + "\appcmd list wp >""" + $resDir + "\IIS-WorkerProcesses.txt""" + $RdrErr
  Write-Log $cmd
  Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append  
}

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\HTTP"
$cmd = "reg export HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\HTTP """+ $resDir + "\HTTP.reg.txt"" /y" + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

Write-Log "Exporting ipconfig /all output"
$cmd = "ipconfig /all >""" + $resDir + "\ipconfig.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

Write-Log "Exporting Application log"
$cmd = "wevtutil epl Application """+ $resDir + "\" + $env:computername + "-Application.evtx"" >>""" + $outfile + """ 2>>""" + $errfile + """"
Write-Log $cmd
Invoke-Expression $cmd
ArchiveLog "Application"

Write-Log "Exporting System log"
$cmd = "wevtutil epl System """+ $resDir + "\" + $env:computername + "-System.evtx"" >>""" + $outfile + """ 2>>""" + $errfile + """"
Write-Log $cmd
Invoke-Expression $cmd
ArchiveLog "System"

Write-Log "Exporting WMI-Activity/Operational log"
$cmd = "wevtutil epl Microsoft-Windows-WMI-Activity/Operational """+ $resDir + "\" + $env:computername + "-WMI-Activity.evtx"" >>""" + $outfile + """ 2>>""" + $errfile + """"
Write-Log $cmd
Invoke-Expression $cmd
ArchiveLog "WMI-Activity"

Write-Log "Exporting DSC log"
$cmd = "wevtutil epl Microsoft-Windows-DSC/Operational """+ $resDir + "\" + $env:computername + "-DSC.evtx"" >>""" + $outfile + """ 2>>""" + $errfile + """"
Write-Log $cmd
Invoke-Expression $cmd
ArchiveLog "DSC"

Write-Log "Exporting DSC PullServer log"
$cmd = "wevtutil epl Microsoft-Windows-Powershell-DesiredStateConfiguration-PullServer/Operational """+ $resDir + "\" + $env:computername + "-PullServer.evtx"" >>""" + $outfile + """ 2>>""" + $errfile + """"
Write-Log $cmd
Invoke-Expression $cmd
ArchiveLog "PullServer"Write-Log "Exporting DSC PullServer log"

Write-Log "Exporting DSC FileDownloadManager log"
$cmd = "wevtutil epl Microsoft-Windows-PowerShell-DesiredStateConfiguration-FileDownloadManager/Operational """+ $resDir + "\" + $env:computername + "-FileDownloadManager.evtx"" >>""" + $outfile + """ 2>>""" + $errfile + """"
Write-Log $cmd
Invoke-Expression $cmd
ArchiveLog "FileDownloadManager"

Write-Log "Exporting ManagementOdataService log"
$cmd = "wevtutil epl Microsoft-Windows-ManagementOdataService/Operational """+ $resDir + "\" + $env:computername + "-ManagementOdataService.evtx"" >>""" + $outfile + """ 2>>""" + $errfile + """"
Write-Log $cmd
Invoke-Expression $cmd
ArchiveLog "ManagementOdataService"

Write-Log "Exporting PowerShell log"
$cmd = "wevtutil epl Microsoft-Windows-PowerShell/Operational """+ $resDir + "\" + $env:computername + "-PowerShell.evtx""" + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd
ArchiveLog "PowerShell"

Write-Log "Exporting Windows Remote Management log"
$cmd = "wevtutil epl Microsoft-Windows-WinRM/Operational """+ $resDir + "\" + $env:computername + "-WindowsRemoteManagement.evtx""" + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd
ArchiveLog "WindowsRemoteManagement"

Write-Log "WinHTTP proxy configuration"
$cmd = "netsh winhttp show proxy >""" + $resDir + "\WinHTTP-Proxy.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

Write-Log "NSLookup WPAD"
"------------------" | Out-File -FilePath ($resDir + "\WinHTTP-Proxy.txt") -Append
"NSLookup WPAD" | Out-File -FilePath ($resDir + "\WinHTTP-Proxy.txt") -Append
"" | Out-File -FilePath ($resDir + "\WinHTTP-Proxy.txt") -Append
$cmd = "nslookup wpad >>""" + $resDir + "\WinHTTP-Proxy.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

Write-Log "Collecting details about running processes"
$proc = ExecQuery -Namespace "root\cimv2" -Query "select Name, CreationDate, ProcessId, ParentProcessId, WorkingSetSize, UserModeTime, KernelModeTime, ThreadCount, HandleCount, CommandLine from Win32_Process"
if ($PSVersionTable.psversion.ToString() -ge "3.0") {
  $StartTime= @{e={$_.CreationDate.ToString("yyyyMMdd HH:mm:ss")};n="Start time"}
} else {
  $StartTime= @{n='StartTime';e={$_.ConvertToDateTime($_.CreationDate)}}
}

if ($proc) {
  $proc | Sort-Object Name |
  Format-Table -AutoSize -property @{e={$_.ProcessId};Label="PID"}, @{e={$_.ParentProcessId};n="Parent"}, Name,
  @{N="WorkingSet";E={"{0:N0}" -f ($_.WorkingSetSize/1kb)};a="right"},
  @{e={[DateTime]::FromFileTimeUtc($_.UserModeTime).ToString("HH:mm:ss")};n="UserTime"}, @{e={[DateTime]::FromFileTimeUtc($_.KernelModeTime).ToString("HH:mm:ss")};n="KernelTime"},
  @{N="Threads";E={$_.ThreadCount}}, @{N="Handles";E={($_.HandleCount)}}, $StartTime, CommandLine |
  Out-String -Width 500 | Out-File -FilePath ($resDir + "\processes.txt")

  Write-Log "Collecting services details"
  $svc = ExecQuery -NameSpace "root\cimv2" -Query "select  ProcessId, DisplayName, StartMode,State, Name, PathName, StartName from Win32_Service"

  if ($svc) {
    $svc | Sort-Object DisplayName | Format-Table -AutoSize -Property ProcessId, DisplayName, StartMode,State, Name, PathName, StartName |
    Out-String -Width 400 | Out-File -FilePath ($resDir + "\services.txt")
  }

  Write-Log "Collecting system information"
  $pad = 27
  $OS = ExecQuery -Namespace "root\cimv2" -Query "select Caption, CSName, OSArchitecture, BuildNumber, InstallDate, LastBootUpTime, LocalDateTime, TotalVisibleMemorySize, FreePhysicalMemory, SizeStoredInPagingFiles, FreeSpaceInPagingFiles, MUILanguages from Win32_OperatingSystem"
  $CS = ExecQuery -Namespace "root\cimv2" -Query "select Model, Manufacturer, SystemType, NumberOfProcessors, NumberOfLogicalProcessors, TotalPhysicalMemory, DNSHostName, Domain, DomainRole from Win32_ComputerSystem"
  $BIOS = ExecQuery -Namespace "root\cimv2" -query "select BIOSVersion, Manufacturer, ReleaseDate, SMBIOSBIOSVersion from Win32_BIOS"
  $TZ = ExecQuery -Namespace "root\cimv2" -Query "select Description from Win32_TimeZone"
  $PR = ExecQuery -Namespace "root\cimv2" -Query "select Name, Caption from Win32_Processor"

  $ctr = Get-Counter -Counter "\Memory\Pool Paged Bytes" -ErrorAction Continue 2>>$errfile
  $PoolPaged = $ctr.CounterSamples[0].CookedValue 
  $ctr = Get-Counter -Counter "\Memory\Pool Nonpaged Bytes" -ErrorAction Continue 2>>$errfile
  $PoolNonPaged = $ctr.CounterSamples[0].CookedValue 

  "Computer name".PadRight($pad) + " : " + $OS.CSName | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "Model".PadRight($pad) + " : " + $CS.Model | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "Manufacturer".PadRight($pad) + " : " + $CS.Manufacturer | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "BIOS Version".PadRight($pad) + " : " + $BIOS.BIOSVersion | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "BIOS Manufacturer".PadRight($pad) + " : " + $BIOS.Manufacturer | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "BIOS Release date".PadRight($pad) + " : " + $BIOS.ReleaseDate | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "SMBIOS Version".PadRight($pad) + " : " + $BIOS.SMBIOSBIOSVersion | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "SystemType".PadRight($pad) + " : " + $CS.SystemType | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "Processor".PadRight($pad) + " : " + $PR.Name + " / " + $PR.Caption | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "Processors physical/logical".PadRight($pad) + " : " + $CS.NumberOfProcessors + " / " + $CS.NumberOfLogicalProcessors | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "Memory physical/visible".PadRight($pad) + " : " + ("{0:N0}" -f ($CS.TotalPhysicalMemory/1mb)) + " MB / " + ("{0:N0}" -f ($OS.TotalVisibleMemorySize/1kb)) + " MB" | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "Pool Paged / NonPaged".PadRight($pad) + " : " + ("{0:N0}" -f ($PoolPaged/1mb)) + " MB / " + ("{0:N0}" -f ($PoolNonPaged/1mb)) + " MB" | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "Free physical memory".PadRight($pad) + " : " + ("{0:N0}" -f ($OS.FreePhysicalMemory/1kb)) + " MB" | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "Paging files size / free".PadRight($pad) + " : " + ("{0:N0}" -f ($OS.SizeStoredInPagingFiles/1kb)) + " MB / " + ("{0:N0}" -f ($OS.FreeSpaceInPagingFiles/1kb)) + " MB" | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "Operating System".PadRight($pad) + " : " + $OS.Caption + " " + $OS.OSArchitecture | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "Build Number".PadRight($pad) + " : " + $OS.BuildNumber + "." + (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ubr + (Win10Ver $OS.BuildNumber)| Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "Time zone".PadRight($pad) + " : " + $TZ.Description | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "Language packs".PadRight($pad) + " : " + ($OS.MUILanguages -join " ") | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "Install date".PadRight($pad) + " : " + $OS.InstallDate | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "Last boot time".PadRight($pad) + " : " + $OS.LastBootUpTime | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "Local time".PadRight($pad) + " : " + $OS.LocalDateTime | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "DNS Hostname".PadRight($pad) + " : " + $CS.DNSHostName | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "DNS Domain name".PadRight($pad) + " : " + $CS.Domain | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "NetBIOS Domain name".PadRight($pad) + " : " + (GetNBDomainName) | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  $roles = "Standalone Workstation", "Member Workstation", "Standalone Server", "Member Server", "Backup Domain Controller", "Primary Domain Controller"
  "Domain role".PadRight($pad) + " : " + $roles[$CS.DomainRole] | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append

  $drives = @()
  $drvtype = "Unknown", "No Root Directory", "Removable Disk", "Local Disk", "Network Drive", "Compact Disc", "RAM Disk"
  $Vol = ExecQuery -NameSpace "root\cimv2" -Query "select * from Win32_LogicalDisk"
  foreach ($disk in $vol) {
    $drv = New-Object PSCustomObject
    $drv | Add-Member -type NoteProperty -name Letter -value $disk.DeviceID 
    $drv | Add-Member -type NoteProperty -name DriveType -value $drvtype[$disk.DriveType]
    $drv | Add-Member -type NoteProperty -name VolumeName -value $disk.VolumeName 
    $drv | Add-Member -type NoteProperty -Name TotalMB -Value ($disk.size)
    $drv | Add-Member -type NoteProperty -Name FreeMB -value ($disk.FreeSpace)
    $drives += $drv
  }
  $drives | 
  Format-Table -AutoSize -property Letter, DriveType, VolumeName, @{N="TotalMB";E={"{0:N0}" -f ($_.TotalMB/1MB)};a="right"}, @{N="FreeMB";E={"{0:N0}" -f ($_.FreeMB/1MB)};a="right"} |
  Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
} else {
  $proc = Get-Process | Where-Object {$_.Name -ne "Idle"}
  $proc | Format-Table -AutoSize -property id, name, @{N="WorkingSet";E={"{0:N0}" -f ($_.workingset/1kb)};a="right"},
  @{N="VM Size";E={"{0:N0}" -f ($_.VirtualMemorySize/1kb)};a="right"},
  @{N="Proc time";E={($_.TotalProcessorTime.ToString().substring(0,8))}}, @{N="Threads";E={$_.threads.count}},
  @{N="Handles";E={($_.HandleCount)}}, StartTime, Path | 
  Out-String -Width 300 | Out-File -FilePath ($resDir + "\processes.txt")
}

Write-Log "Collecting the list of installed hotfixes"
Get-HotFix -ErrorAction SilentlyContinue 2>>$errfile | Sort-Object -Property InstalledOn | Out-File $resDir\hotfixes.txt
