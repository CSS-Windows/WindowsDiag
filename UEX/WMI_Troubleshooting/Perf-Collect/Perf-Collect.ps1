$version = "Perf-Collect (20200309)"
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

$tbPerfV1 = New-Object system.Data.DataTable “Perf”
$col = New-Object system.Data.DataColumn Name,([string])
$tbPerfV1.Columns.Add($col)
$col = New-Object system.Data.DataColumn Open,([string])
$tbPerfV1.Columns.Add($col)
$col = New-Object system.Data.DataColumn Close,([string])
$tbPerfV1.Columns.Add($col)
$col = New-Object system.Data.DataColumn Collect,([string])
$tbPerfV1.Columns.Add($col)
$col = New-Object system.Data.DataColumn Library,([string])
$tbPerfV1.Columns.Add($col)
$col = New-Object system.Data.DataColumn InstallType,([string])
$tbPerfV1.Columns.Add($col)
$col = New-Object system.Data.DataColumn PerfIniFile,([string])
$tbPerfV1.Columns.Add($col)
$col = New-Object system.Data.DataColumn IniExists,([string])
$tbPerfV1.Columns.Add($col)
$col = New-Object system.Data.DataColumn Disabled,([string])
$tbPerfV1.Columns.Add($col)
$col = New-Object system.Data.DataColumn FirstCounter,([string])
$tbPerfV1.Columns.Add($col)
$col = New-Object system.Data.DataColumn FirstHelp,([string])
$tbPerfV1.Columns.Add($col)
$col = New-Object system.Data.DataColumn LastCounter,([string])
$tbPerfV1.Columns.Add($col)
$col = New-Object system.Data.DataColumn LastHelp,([string])
$tbPerfV1.Columns.Add($col)
$col = New-Object system.Data.DataColumn ObjectList,([string])
$tbPerfV1.Columns.Add($col)

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

$resName = "Perf-" + $env:computername +"-" + $(get-date -f yyyyMMdd_HHmmss)
$resDir = $Root + "\" + $resName
$outfile = $resDir + "\script-output.txt"
$errfile = $resDir + "\script-errors.txt"
$RdrOut =  " >>""" + $outfile + """"
$RdrErr =  " 2>>""" + $errfile + """"

New-Item -itemtype directory -path $resDir | Out-Null

Write-Log $version

$cult = Get-Culture
$cultHex = ('{0:X4}' -f $cult.LCID)

Copy-Item ($env:SystemRoot + "\system32\perfc*.dat") $resDir
Copy-Item ($env:SystemRoot + "\system32\perfd*.dat") $resDir
Copy-Item ($env:SystemRoot + "\system32\perfh*.dat") $resDir
Copy-Item ($env:SystemRoot + "\system32\perfi*.dat") $resDir

(get-itemproperty -ErrorAction SilentlyContinue -literalpath ("HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib\CurrentLanguage")).Counter | Out-File ($resDir + "\Counter.txt")
(get-itemproperty -ErrorAction SilentlyContinue -literalpath ("HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib\CurrentLanguage")).Help | Out-File ($resDir + "\Help.txt")

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services"
$cmd = "reg export ""HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services"" """ + $resDir + "\Services.reg.txt"" /y " + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib"
$cmd = "reg export ""HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib"" """ + $resDir + "\Perflib.reg.txt"" /y " + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

Write-Log "Saving registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib"
$cmd = "reg save ""HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib"" """ + $resDir + "\Perflib.hiv"" /y " + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup"
$cmd = "reg export ""HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup"" """ + $resDir + "\FWSetup.reg.txt"" /y " + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

$svc = "HKLM:\SYSTEM\CurrentControlSet\Services"
New-PSDrive -PSProvider registry -Root HKEY_LOCAL_MACHINE -Name HKLM -ErrorAction SilentlyContinue | Out-Null
$Keys = Get-ChildItem $svc
ForEach ($Item in $Keys) {
  $perf = ($svc + "\" + $item.PSChildName + "\Performance")
  $reg = Get-ItemProperty $perf -ErrorAction SilentlyContinue
  if ($reg) {    
    Write-Log $item.PSChildName

    $row = $tbPerfV1.NewRow()

    if ($reg.PerfIniFile) {
      $inipath = ($env:windir + "\INF\" + $item.PSChildName + "\" + $cultHex + "\" + $reg.PerfIniFile).TrimEnd([char]0)
      if (Test-Path $inipath) {
        $row.IniExists = "Yes"
      } else {
        $row.IniExists = "No"
      }
    } else {
      $row.IniExists = ""
    }

    $row.Name = $item.PSChildName
    $row.Open = $reg.Open
    $row.Close = $reg.Close
    $row.Collect = $reg.Collect
    $row.Library = $reg.Library
    $row.InstallType = $reg.InstallType
    $row.PerfIniFile = $reg.PerfIniFile
    $row.Disabled = $reg.'Disable Performance Counters'
    $row.FirstCounter = $reg.'First Counter'
    $row.FirstHelp = $reg.'First Help'
    $row.LastCounter = $reg.'Last Counter'
    $row.LastHelp = $reg.'Last Help'
    $row.ObjectList = $reg.'Object List'
    $tbPerfV1.Rows.Add($row)
  }
}
$tbPerfV1 | Export-Csv $resDir"\PerfV1.csv" -noType

Write-Log "Enumerating performance counters"
$cmd = "typeperf.exe -q > """ + $resDir + "\typeperf.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

Write-Log "Enumerating performance counters with instances"
$cmd = "typeperf.exe -qx > """ + $resDir + "\typeperf-inst.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

Write-Log "Enumerating 32bit performance counters"
$cmd = $env:windir + "\SysWOW64\typeperf.exe -q > """ + $resDir + "\typeperf32.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

Write-Log "Enumerating 32bit performance counters"
$cmd = $env:windir + "\SysWOW64\typeperf.exe -qx > """ + $resDir + "\typeperf32-inst.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

Write-Log "Enumerating WMI performance classes"
Get-WmiObject -Query "select * from meta_class where __CLASS like '%Win32_Perf%'" | Select-Object -Property __CLASS | Sort-Object -Property __CLASS | Out-File ($resDir + "\WMIPerfClasses.txt")

Write-Log "Exporting Application log"
$cmd = "wevtutil epl Application """+ $resDir + "\" + $env:computername + "-Application.evtx""" + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

Write-Log "Exporting System log"
$cmd = "wevtutil epl System """+ $resDir + "\" + $env:computername + "-System.evtx""" + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

Write-Log "Collecting system information"
$pad = 27
$OS = ExecQuery -Namespace "root\cimv2" -Query "select Caption, CSName, OSArchitecture, BuildNumber, InstallDate, LastBootUpTime, LocalDateTime, TotalVisibleMemorySize, FreePhysicalMemory, SizeStoredInPagingFiles, FreeSpaceInPagingFiles from Win32_OperatingSystem"
$CS = ExecQuery -Namespace "root\cimv2" -Query "select Model, Manufacturer, SystemType, NumberOfProcessors, NumberOfLogicalProcessors, TotalPhysicalMemory, DNSHostName, Domain from Win32_ComputerSystem"
$BIOS = ExecQuery -Namespace "root\cimv2" -query "select BIOSVersion, Manufacturer, ReleaseDate, SMBIOSBIOSVersion from Win32_BIOS"
$TZ = ExecQuery -Namespace "root\cimv2" -Query "select Description from Win32_TimeZone"
$PR = ExecQuery -Namespace "root\cimv2" -Query "select Name, Caption from Win32_Processor"

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
"Free physical memory".PadRight($pad) + " : " + ("{0:N0}" -f ($OS.FreePhysicalMemory/1kb)) + " MB" | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
"Paging files size / free".PadRight($pad) + " : " + ("{0:N0}" -f ($OS.SizeStoredInPagingFiles/1kb)) + " MB / " + ("{0:N0}" -f ($OS.FreeSpaceInPagingFiles/1kb)) + " MB" | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
"Operating System".PadRight($pad) + " : " + $OS.Caption + " " + $OS.OSArchitecture | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
"Build Number".PadRight($pad) + " : " + $OS.BuildNumber | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
"Time zone".PadRight($pad) + " : " + $TZ.Description | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
"Install date".PadRight($pad) + " : " + $OS.InstallDate | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
"Last boot time".PadRight($pad) + " : " + $OS.LastBootUpTime | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
"Local time".PadRight($pad) + " : " + $OS.LocalDateTime | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
"DNS Hostname".PadRight($pad) + " : " + $CS.DNSHostName | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
"Domain".PadRight($pad) + " : " + $CS.Domain | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append