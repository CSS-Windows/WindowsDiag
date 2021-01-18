Param(
[int]$Scenario = 0,
[int]$CaptureTime = 0
)

$Global:FieldEngineering = "0"
$Global:NetLogonDBFlags = "0"
$Global:DataPath = "c:\adperfdata\temp"
$Global:Custom1644 = $false
$Global:CustomADDSUsed = $false
$Global:TriggerScenario = $false
$Global:TriggeredTimerLength = 5

function ADPerf-Menu
{
    Write-Host "============AD Perf Data Collection Tool=============="
    Write-Host "1: High CPU on Domain Controller"
    Write-Host "2: High CPU Trigger Start on Domain Controller"
    Write-Host "3: High Memory on Domain Controller"
    Write-Host "4: High Memory Trigger Start on Domain Controller"
    Write-Host "5: Out of ATQ threads (always trigger start)"
    Write-Host "6: Baseline performance of a Domain Controller (5 minutes)"
    Write-Host "7: Long Term Baseline performance of a Domain Controller"
    Write-Host "8: Stop tracing providers (run this if you previously cancelled before script completion)"
    Write-Host "q: Press Q  or Enter to quit"
}

function CommonTasksCollection
{
    
    if (!$Global:Custom1644)
    {
        Write-Host "Enabling 1644 Events...."

        Enable1644RegKeys

        Write-Host "1644 Events Enabled"
    }

    Write-Host "Turning on Netlogon Debug flags"
    
    $NetlogonParamKey = get-itemproperty  -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters"
    $Global:NetLogonDBFlags = $NetlogonParamKey.DBFlag
    New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters" -Name "DBFlag" -Value 0x2080ffff -PropertyType DWORD -Force | Out-Null

    Write-Host "Enabling the AD Data Collector Set...."

    StartADDiagnostics

    Write-Host "AD Data Collector Set Started"

    Write-Host "Starting LSA/LSP Tracing...."

    StartLSATracing

    Write-Host "LSA/LSP Tracing Started"

    Write-Host "Starting SamSrv Tracing...."

    StartSamSrvTracing

    Write-Host "SamSrv Tracing Started"

}

function HighCpuDataCollection
{
    Write-Host "Gathering Data for High CPU on Domain Controller"

    CommonTasksCollection

    Write-Host "Collecting LSASS Process Dumps...."

    GetProcDumps "lsass.exe -mp -n 2 -s 5 -AcceptEula $Global:DataPath"
    
    Write-Host "Starting Windows Performance Recording..."
    
    StartWPR "-Start GeneralProfile -Start CPU"

    Write-Host "Windows Performance Recording Started"

    StartNetTrace

    Write-Host "Starting Network Capture"

    if ($Global:TriggerScenario)
    {
        Write-Host "Collecting Data for $Global:TriggeredTimerLength minutes"
        $sleepTime = 60000 * [int]$Global:TriggeredTimerLength
        Start-Sleep -m $sleepTime
    }
    else
    {
        Read-Host "Ensure you have had enough time for the issue to reproduce and then press The Enter Key to Stop tracing..."
    }
    
    Write-Host "Stopping WPR Tracing"

    StopWPR

    WRite-Host "Stopping Network Trace"

    StopNetTrace

    Write-Host "Stopping AD Data Collector Set"

    StopADDiagnostics

}

function HighCpuDataCollectionTriggerstart
{
    Write-Host "Gathering Data for High CPU Usage"

    while ($true)
    {
        $CPUThreshold = Read-Host "CPU Percent Threshold(50-99)"

        if ([int]$CPUThreshold -gt 49 -and [int]$CPUThreshold -lt 100)
        {
            break
        }
        else
        {
            Write-Host "Invalid Input"
        }
    }

    $dataCollectionTime = Read-Host "How long in minutes to collect data after trigger is met?"

    if ([int]$dataCollectionTime -gt 0 -and [int]$dataCollectionTime -lt 31)
    {
        $Global:TriggeredTimerLength = $dataCollectionTime
    }
    
    $Global:TriggerScenario = $true

    Write-Host "Waiting for high cpu condition of greater than $CPUThreshold`0%..."

    While ($true)
    {
        $CPUValue = get-counter -Counter "\Processor Information(_Total)\% Processor Time" -SampleInterval 5 -MaxSamples 1

        if ($CPUValue.CounterSamples.CookedValue -gt $CPUThreshold)
        {
            Write-Host "CPU Usage is Greater than $CPUThreshold`0% - Starting Data Collection...."
            break
        }
    }

    HighCpuDataCollection
}

function HighMemoryDataCollection
{
    Write-Host "Gathering Data for High Memory on a Domain Controller"
    
    CommonTasksCollection

    Write-Host "Starting Windows Performance Recording..."
    
    StartWPR "-Start GeneralProfile -Start Heap -Start VirtualAllocation"

    Write-Host "Windows Performance Recording Started"

    Write-Host "Getting Arena Info and Thread State Information..."

    GetRootDSEArenaInfoAndThreadStates

    Write-Host "Collecting LSASS Process Dump...."

    GetProcDumps "lsass.exe -mp -AcceptEula $Global:DataPath"

    if ($Global:TriggerScenario)
    {
        Write-Host "Collecting Data for $Global:TriggeredTimerLength minutes"
        $sleepTime = 60000 * [int]$Global:TriggeredTimerLength
        Start-Sleep -m $sleepTime
    }
    else
    {
        Read-Host "Ensure you have had enough time for the issue to reproduce and then press The Enter Key to Stop tracing..."
    }

    Write-Host "Stopping WPR Tracing"

    StopWPR

    Write-Host "Stopping AD Data Collector Set"

    StopADDiagnostics

    Write-Host "Getting Arena Info and Thread State Information again..."

    GetRootDSEArenaInfoAndThreadStates

}

function HighMemoryDataCollectionTriggerStart
{
    Write-Host "Gathering Data for High Memory Usage" 
    
    while ($true)
    {
        $MemoryThreshold = Read-Host "Memory Percent Threshold(50-99)"

        if ([int]$MemoryThreshold -gt 49 -and [int]$MemoryThreshold -lt 100)
        {
            break
        }
        else
        {
            Write-Host "Invalid Input"
        }
    }

    $dataCollectionTime = Read-Host "How long in minutes to collect data after trigger is met?"
    
    if ([int]$dataCollectionTime -gt 0 -and [int]$dataCollectionTime -lt 31)
    {
        $Global:TriggeredTimerLength = $dataCollectionTime
    }

    $Global:TriggerScenario = $true

    Write-Host "Attempting to enable RADAR Leak Diag"

    StartRadar

    Write-Host "Waiting for high memory condition of greater than $MemoryThreshold`0%..."

    While ($true)
    {
        $CommittedBytesInUse = get-counter -Counter "\Memory\% Committed Bytes In Use" -SampleInterval 5 -MaxSamples 1

        if ($CommittedBytesInUse.CounterSamples.CookedValue -gt $MemoryThreshold)
        {
            Write-Host "Committed Bytes in Use Percentage is Greater than $MemoryThreshold`0% - Starting Data Collection...."
            break
        }
    }

    StopRadar

    HighMemoryDataCollection
}

function ATQThreadDataCollection
{
    Write-Host "Gathering Data for ATQ Thread depletion scenario"
    Write-Host ""
    WRite-Host "Waiting for ATQ Threads being exhausted..."

    While ($true)
    {
        $LdapAtqThreads = get-counter -counter "\DirectoryServices(NTDS)\ATQ Threads LDAP" -SampleInterval 5 -MaxSamples 1
        $OtherAtqThreads = Get-Counter -counter "\DirectoryServices(NTDS)\ATQ Threads Other" -SampleInterval 5 -MaxSamples 1
        $TotalAtqThreads = Get-Counter -counter "\DirectoryServices(NTDS)\ATQ Threads Total" -SampleInterval 5 -MaxSamples 1
        
        if ($LdapAtqThreads.CounterSamples.CookedValue + $OtherAtqThreads.CounterSamples.CookedValue -eq $TotalAtqThreads.CounterSamples.CookedValue)
        {
            Write-Host ATQ Threads are depleted - Starting Data Collection....
            break
        }

    }
   
   Write-Host "Collecting LSASS Process Dumps...."

   GetProcDumps "lsass.exe -mp -n 3 -s 5 -AcceptEula $Global:DataPath"
   
   CommonTasksCollection   
   
   Write-Host "Please wait around 5 minutes while we collect traces.  The collection will automatically stop after the time has elapsed"
   
   $sleepTime = 60000 * 5
   
   Start-Sleep -m $sleepTime

   Write-Host "Stopping AD Data Collector Set"

   StopADDiagnostics
}

function BaseLineDataCollection
{
    Write-Host "Gathering Baseline Performance Data of a Domain Controller"
    
    Write-Host "Enabling 1644 Events with Paremeters to collect all requests...."
    
    Enable1644RegKeys $true 1 0 0

    Write-Host "1644 Events Enabled"

    CommonTasksCollection

    Write-Host "Starting Windows Performance Recording..."
    
    StartWPR "-Start GeneralProfile -Start CPU -Start Heap -Start VirtualAllocation"

    Write-Host "Windows Performance Recording Started"

    Write-Host "Collecting LSASS Process Dumps...."

    GetProcDumps "lsass.exe -mp -n 3 -s 5 -AcceptEula $Global:DataPath"

    Write-Host "Please wait around 5 minutes while we collect performance baseline traces.  The collection will automatically stop after the time has elapsed"

    $sleepTime = 60000 * 5
    
    Start-Sleep -m $sleepTime
    
    Write-Host "Stopping WPR Tracing"

    StopWPR

    Write-Host "Stopping AD Data Collector Set"

    StopADDiagnostics

}
function LongBaseLineCollection
{
    Write-Host "Gathering Baseline Performance Data of a Domain Controller"

    GetProcDumps "lsass.exe -mp -AcceptEula $Global:DataPath"

    Write-Host "Enabling 1644 Events with Paremeters to collect all requests...."

    Enable1644RegKeys $true
    
    Write-Host "1644 Events Enabled"

    Write-Host "Starting AD Data Collector"

    StartADDiagnostics
    
    Write-Host "AD Data Collector Set Started"

    Write-Host "Starting Short and Long Perflogs"

    StartPerfLog $true

    StartPerfLog $false

    Write-host "Short and Long Perflogs started"

    $NetlogonParamKey = get-itemproperty  -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters"
    $Global:NetLogonDBFlags = $NetlogonParamKey.DBFlag

    Read-Host "Ensure you have had enough time for a good baseline and then press The Enter Key to Stop tracing..."
    
    Write-Host "Stopping AD Data Collector Set"
    StopADDiagnostics
    
    Write-Host "Stopping Perflogs"
    StopPerfLogs $true
    StopPerfLogs $false
      
}

function GetRootDSEArenaInfoAndThreadStates
{
    Import-Module ActiveDirectory

    $LdapConnection = new-object System.DirectoryServices.Protocols.LdapConnection(new-object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($env:computername, 389))
    
    $msDSArenaInfoReq = New-Object System.DirectoryServices.Protocols.SearchRequest
    $msDSArenaInfoReq.Filter = "(objectclass=*)"
    $msDSArenaInfoReq.Scope = "Base"
    $msDSArenaInfoReq.Attributes.Add("msDS-ArenaInfo") | Out-Null

    $msDSArenaInfoResp = $LdapConnection.SendRequest($msDSArenaInfoReq)

    (($msDSArenaInfoResp.Entries[0].Attributes["msds-ArenaInfo"].GetValues([string]))[0]) | Out-File $Global:DataPath\msDs-ArenaInfo.txt -Append

    Add-Content -Path $Global:DataPath\msDs-ArenaInfo.txt -Value "=========================================================="

    $msDSArenaInfoReq.Attributes.Clear()
    $msDSArenaInfoReq.Attributes.Add("msds-ThreadStates") | Out-Null

    $msDSThreadStatesResp = $LdapConnection.SendRequest($msDSArenaInfoReq)

    (($msDSThreadStatesResp.Entries[0].Attributes["msds-ThreadStates"].GetValues([string]))[0]) | Out-File $Global:DataPath\msDs-ThreadStates.txt -Append

    Add-Content -Path $Global:DataPath\msDs-ThreadStates.txt -Value "=========================================================="

}

function GetProcDumps([string]$arg)
{
    $procdump = Test-Path "$PSScriptRoot\procdump.exe"

    if ($procdump)
    {
        $ps = new-object System.Diagnostics.Process
        $ps.StartInfo.Filename = "$PSScriptRoot\procdump.exe"
        $ps.StartInfo.Arguments = $arg
        $ps.StartInfo.RedirectStandardOutput = $false
        $ps.StartInfo.UseShellExecute = $false
        $ps.start()
        $ps.WaitForExit()
    }
    else
    {
        Write-Host "Procdump.exe not found in script root - Skipping dump collection"
    }   
}

function StartRADAR
{
    $lsassProcess = Get-Process "lsass"

    $lsassPid = $lsassProcess.Id.ToString()
    
    $ps = new-object System.Diagnostics.Process
    $ps.StartInfo.Filename = "rdrleakdiag.exe"
    $ps.StartInfo.Arguments = " -p $lsassPid -enable"
    $ps.StartInfo.RedirectStandardOutput = $false
    $ps.StartInfo.UseShellExecute = $false
    $ps.start()
    $ps.WaitForExit()

}

function StopRadar
{
    $lsassProcess = Get-Process "lsass"

    $lsassPid = $lsassProcess.Id.ToString()
    
    $ps = new-object System.Diagnostics.Process
    $ps.StartInfo.Filename = "rdrleakdiag.exe"
    $ps.StartInfo.Arguments = " -p $lsassPid -snap -nowatson -nocleanup "
    $ps.StartInfo.RedirectStandardOutput = $false
    $ps.StartInfo.UseShellExecute = $false
    $ps.start()
    $ps.WaitForExit()

}

function StartWPR([string]$arg)
{
    $ps = new-object System.Diagnostics.Process
    $ps.StartInfo.Filename = "wpr.exe"
    $ps.StartInfo.Arguments = "$arg"
    $ps.StartInfo.RedirectStandardOutput = $false
    $ps.StartInfo.UseShellExecute = $false
    $ps.start()
    $ps.WaitForExit()
}
function StopWPR
{
    $ps = new-object System.Diagnostics.Process
    $ps.StartInfo.Filename = "wpr.exe"
    $ps.StartInfo.Arguments = " -Stop $Global:DataPath\WPR.ETL"
    $ps.StartInfo.RedirectStandardOutput = $false
    $ps.StartInfo.UseShellExecute = $false
    $ps.start()
    $ps.WaitForExit()
}

function StartADDiagnostics
{
    ##Import custom data collector set xml if it exists

    $customADDSxml = Test-path "$PSScriptRoot\ADDS.xml"

    $StartArgs = ' start "system\Active Directory Diagnostics" -ets'

    if ($customADDSxml)
    {
        Write-Host "Custom Data Collector Set Found - Importing..."

        $ps = new-object System.Diagnostics.Process
        $ps.StartInfo.Filename = "logman.exe"
        $ps.StartInfo.Arguments = ' -import -name "Enhanced Active Directory Diagnostics" ' +  " -xml `"$PSScriptRoot\ADDS.xml`" "
        $ps.StartInfo.RedirectStandardOutput = $false
        $ps.StartInfo.UseShellExecute = $false
        $ps.start()
        $ps.WaitForExit()

        $Global:CustomADDSUsed = $true

        Write-Host "Customer Data Collector Set Imported"

        $StartArgs = ' start "Enhanced Active Directory Diagnostics"'
    }

    $ps1 = new-object System.Diagnostics.Process
    $ps1.StartInfo.Filename = "logman.exe"
    $ps1.StartInfo.Arguments = $StartArgs
    $ps1.StartInfo.RedirectStandardOutput = $false
    $ps1.StartInfo.UseShellExecute = $false
    $ps1.start()
    $ps1.WaitForExit()

}

function StopADDiagnostics
{
    if ($Global:CustomADDSUsed)
    {
        $StartArgs = ' stop "Enhanced Active Directory Diagnostics" '
    }
    else
    {
        $StartArgs = ' stop "system\Active Directory Diagnostics" -ets'
    }
    
    $ps = new-object System.Diagnostics.Process
    $ps.StartInfo.Filename = "logman.exe"
    $ps.StartInfo.Arguments = $StartArgs
    $ps.StartInfo.RedirectStandardOutput = $false
    $ps.StartInfo.UseShellExecute = $false
    $ps.start()
    $ps.WaitForExit()

}

function StartPerfLog([bool]$Long = $false)
{
    
    if ($Long)
    {
        [string]$StartArg = ' create counter PerfLogLong -o ' + "$Global:DataPath\PerfLogLong.blg" + " -f bincirc -v mmddhhmm -max 300 -c " + "\LogicalDisk(*)\* "+ "\Memory\* \Cache\* " + "\Network Interface(*)\* " + "\NTDS(*)\* " + "\Netlogon(*)\* " + "\Database(lsass)\* " + "\Paging File(*)\* " + "\PhysicalDisk(*)\* " + "\Processor(*)\* " + "\Processor Information(*)\* " + "\Process(*)\* "+ "\Redirector\* "+ "\Server\* " + "\System\* " + "\Server Work Queues(*)\* " + "-si 00:05:00"

        $StartArg1 = 'start "PerfLogLong"'
    }
    else
    {
        [string]$StartArg = ' create counter PerfLogShort -o ' + "$Global:DataPath\PerfLogShort.blg" + " -f bincirc -v mmddhhmm -max 300 -c " + "\LogicalDisk(*)\* " + "\Memory\* \Cache\* " + "\Network Interface(*)\* " + "\NTDS(*)\* " + "\Netlogon(*)\* " + "\Database(lsass)\* " + "\Paging File(*)\* " + "\PhysicalDisk(*)\* " + "\Processor(*)\* " + "\Processor Information(*)\* " + "\Process(*)\* "+ "\Redirector\* "+ "\Server\* " + "\System\* " + "\Server Work Queues(*)\* " + "-si 00:00:05"

        $StartArg1 = ' start "PerfLogShort"'
    }

    
    $ps = new-object System.Diagnostics.Process
    $ps.StartInfo.Filename = "logman.exe"
    $ps.StartInfo.Arguments = $StartArg
    $ps.StartInfo.RedirectStandardOutput = $false
    $ps.StartInfo.UseShellExecute = $false
    $ps.start()
    $ps.WaitForExit()

    $ps1 = new-object System.Diagnostics.Process
    $ps1.StartInfo.Filename = "logman.exe"
    $ps1.StartInfo.Arguments = $StartArg1
    $ps1.StartInfo.RedirectStandardOutput = $false
    $ps1.StartInfo.UseShellExecute = $false
    $ps1.Start()
    $ps1.WaitForExit()
}

function StopPerfLogs([bool]$Long = $false)
{
    if ($Long)
    {
        $StartArgs = ' stop "PerfLogLong"'
        $StartArgs1 = ' delete "PerfLogLong"'
    }
    else
    {
        $StartArgs = ' stop "PerfLogShort"'
        $StartArgs1 = ' delete "PerfLogShort"'
    }
    
    $ps = new-object System.Diagnostics.Process
    $ps.StartInfo.Filename = "logman.exe"
    $ps.StartInfo.Arguments = $StartArgs
    $ps.StartInfo.RedirectStandardOutput = $false
    $ps.StartInfo.UseShellExecute = $false
    $ps.start()
    $ps.WaitForExit()

    $ps1 = new-object System.Diagnostics.Process
    $ps1.StartInfo.Filename = "logman.exe"
    $ps1.StartInfo.Arguments = $StartArgs1
    $ps1.StartInfo.RedirectStandardOutput = $false
    $ps1.StartInfo.UseShellExecute = $false
    $ps1.start()
    $ps1.WaitForExit()
}

function StartLSATracing
{
    $ps = new-object System.Diagnostics.Process
    $ps.StartInfo.Filename = "logman.exe"
    $ps.StartInfo.Arguments = " start LsaTrace -p {D0B639E0-E650-4D1D-8F39-1580ADE72784} 0x40141F -o $Global:DataPath\LsaTrace.etl -ets"
    $ps.StartInfo.RedirectStandardOutput = $false
    $ps.StartInfo.UseShellExecute = $false
    $ps.start()
    $ps.WaitForExit()

    $LSA = get-itemproperty  -Path Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA
	
	if ($LSA.LspDbgTraceOptions  -eq $null)
	{
		#Create the value and then set it to TRACE_OPTION_LOG_TO_FILE = 0x1,
		New-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA -name 'LspDbgTraceOptions' -PropertyType DWord -Value '0x1'
	}
	elseif ($LSA.LspDbgTraceOptions -ne '0x1')
	{
		#Set the existing value to 1
		Set-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA -name 'LspDbgTraceOptions' '0x00320001'	
	}
	if ($LSA.LspDbgInfoLevel -eq $null)
	{
		New-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA -name 'LspDbgInfoLevel' -PropertyType DWord -Value '0xF000800'
	}
	elseif ($LSA.LspDbgInfoLevel -ne '0xF000800')
	{
	    Set-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA -name 'LspDbgInfoLevel' -Value '0xF000800'
	}
}
function StopLSATracing
{
    $ps = new-object System.Diagnostics.Process
    $ps.StartInfo.Filename = "logman.exe"
    $ps.StartInfo.Arguments = ' stop LsaTrace -ets'
    $ps.StartInfo.RedirectStandardOutput = $false
    $ps.StartInfo.UseShellExecute = $false
    $ps.start()
    $ps.WaitForExit()
    Set-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA -name 'LspDbgTraceOptions'  -Value '0x0'

}

function StartSamSrvTracing
{
    $ps = new-object System.Diagnostics.Process
    $ps.StartInfo.Filename = "logman.exe"
    $ps.StartInfo.Arguments = " create trace SamSrv -p {F2969C49-B484-4485-B3B0-B908DA73CEBB} 0xffffffffffffffff 0xff -ow -o $Global:DataPath\SamSrv.etl -ets"
    $ps.StartInfo.RedirectStandardOutput = $false
    $ps.StartInfo.UseShellExecute = $false
    $ps.start()
    $ps.WaitForExit()
}

function StopSamSrvTracing
{
$ps = new-object System.Diagnostics.Process
    $ps.StartInfo.Filename = "logman.exe"
    $ps.StartInfo.Arguments = ' stop SamSrv -ets'
    $ps.StartInfo.RedirectStandardOutput = $false
    $ps.StartInfo.UseShellExecute = $false
    $ps.start()
    $ps.WaitForExit()
}

function StartNetTrace
{
    $ps = new-object System.Diagnostics.Process
    $ps.StartInfo.Filename = "netsh.exe"
    $ps.StartInfo.Arguments = " trace start scenario=netconnection capture=yes tracefile=$Global:DataPath\\nettrace.etl"
    $ps.StartInfo.RedirectStandardOutput = $false
    $ps.StartInfo.UseShellExecute = $false
    $ps.start()
    $ps.WaitForExit()
}

function StopNetTrace
{
    $ps = new-object System.Diagnostics.Process
    $ps.StartInfo.Filename = "netsh.exe"
    $ps.StartInfo.Arguments = " trace stop"
    $ps.StartInfo.RedirectStandardOutput = $false
    $ps.StartInfo.UseShellExecute = $false
    $ps.start()
    $ps.WaitForExit()
}

function Enable1644RegKeys([bool]$useCustomValues = $false, $searchTimeValue = "50", $expSearchResultsValue = "10000", $inEfficientSearchResultsValue = "1000")
{
    ##make sure the Event Log is at least 50MB

    $DirSvcLog = Get-WmiObject -Class Win32_NTEventLogFile -Filter "LogFileName = 'Directory Service'"

    $MinLogSize = 50 * 1024 * 1024

    if ($DirSvcLog.MaxFileSize -lt $MinLogSize)
    {
        Write-Host "Increasing the Directory Service Event Log Size to 50MB"
        Limit-EventLog -LogName "Directory Service" -MaximumSize 50MB
    }
    
    $registryPathFieldEngineering = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics"
    $fieldEngineering = "15 Field Engineering"
    $fieldEngineeringValue = "5"
    
    $DiagnosticsKey = get-itemproperty -Path $registryPathFieldEngineering
    $Global:FieldEngineering = $DiagnosticsKey."15 Field Engineering"
    
    ##$Global:FieldEngineering = get-itemproperty -Path $registryPathFieldEngineering -Name $fieldEngineering

    New-ItemProperty -Path $registryPathFieldEngineering -Name $fieldEngineering -Value $fieldEngineeringValue -PropertyType DWORD -Force | Out-Null
    
    
    if ($useCustomValues)
    {
        $registryPathParameters = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"

        $thresholdsKey = get-itemproperty -Path $registryPathParameters

        ##Only set custom thresholds if there are none previously defined by customer

        if (($thresholdsKey."Search Time Threshold (msecs)" -eq $null) -and ($thresholdsKey."Expensive Search Results Threshold" -eq $null) -and ($thresholdsKey."Inefficient Search Results Threshold" -eq $null))
        {
            $searchTime = "Search Time Threshold (msecs)"
            New-ItemProperty -Path $registryPathParameters -Name $searchTime -Value $searchTimeValue -PropertyType DWORD -Force | Out-Null

            $expSearchResults = "Expensive Search Results Threshold"
            New-ItemProperty -Path $registryPathParameters -Name $expSearchResults -Value $expSearchResultsValue -PropertyType DWORD -Force | Out-Null
            
            $inEfficientSearchResults = "Inefficient Search Results Threshold" 
            New-ItemProperty -Path $registryPathParameters -Name $inEfficientSearchResults -Value $inEfficientSearchResultsValue -PropertyType DWORD -Force | Out-Null
            
            $Global:Custom1644 = $true
        }
    }
    
}

function Disable1644RegKeys
{
    $registryPathFieldEngineering = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics"
    $fieldEngineering = "15 Field Engineering"
    
    New-ItemProperty -Path $registryPathFieldEngineering -Name $fieldEngineering -Value $Global:FieldEngineering -PropertyType DWORD -Force | Out-Null

    if ($Global:Custom1644)
    {
        ##Safest to just remove these entries so it reverts back to default
        $registryPathParameters = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
    
        $searchTime = "Search Time Threshold (msecs)"

        Remove-ItemProperty -Path $registryPathParameters -Name $searchTime
    
        $expSearchResults = "Expensive Search Results Threshold"

        Remove-ItemProperty -Path $registryPathParameters -Name $expSearchResults

        $inEfficientSearchResults = "Inefficient Search Results Threshold"

        Remove-ItemProperty -Path $registryPathParameters -Name $inEfficientSearchResults
    }
    
}

function CorrelateDataAndCleanup
{
    ##Copy Directory Services Event Log

    Copy-Item -Path "$env:SystemRoot\System32\Winevt\Logs\Directory Service.evtx" -dest "$Global:DataPath" -force

    Copy-Item -Path "$env:SystemRoot\Debug\Netlogon.log" -dest $Global:DataPath -Force

    $NetlogonBakExists = Test-Path "$env:SystemRoot\Debug\Netlogon.bak"

    if ($NetlogonBakExists)
    {
        Copy-Item -Path "$env:SystemRoot\Debug\Netlogon.bak" -dest $Global:DataPath -Force
    }
       
    Disable1644RegKeys

    New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters" -Name "DBFlag" -Value $Global:NetLogonDBFlags -PropertyType DWORD -Force | Out-Null

    StopLSATracing

    Copy-Item -Path "$env:SystemRoot\Debug\lsp.log" -dest $Global:DataPath -Force

    StopSamSrvTracing

    ##Do all the AD Data Collector stuff
    
    $perflogPath = "C:\PerfLogs\ADDS"
    
    if ($Global:CustomADDSUsed)
    {
        $perflogPath = "C:\PerfLogs\Enhanced-ADDS"        
    }
    
    Write-Host "Waiting for report.html creation to be complete, this process can take a while to complete..."

    $ADDataCollectorPath = Get-ChildItem $perflogPath | Sort-Object CreationTime -Descending | Select-Object -First 1 -ErrorAction SilentlyContinue

    ## just a fail safe in case for whatever reason the custom ADDS data collector import failed
    
    if (!$ADDataCollectorPath)
    {
        Write-Host "AD Data Collector path was not found... skipping"
        return
    }

    $Attempts = 0;

    while($true)
    {
        $reportcomplete = Test-Path "$perflogPath\$ADDataCollectorPath\Report.html"

        if ($reportcomplete -or [int]$Attempts -eq 120)
        {
            break
        }
        Start-Sleep -Seconds 30
        $Attempts = [int]$Attempts + 1
    }

    if ([int]$Attempts -eq 120)
    {
        Write-Host "Waited an hour and the report is still not generated, copying just the raw data that is available"
    }
    else
    {
        Write-Host "Report.html compile completed"
    }

    
    Get-ChildItem $perflogPath | Sort-Object CreationTime -Descending | Select-Object -First 1 | Copy-Item -Destination $Global:DataPath -Recurse -Force

    if ($Global:CustomADDSUsed)
    {
        ## have to clean up the source folder otherwise the subsequent runs will fail as it will try to re-use existing folder name
        Get-ChildItem $perflogPath | Sort-Object CreationTime -Descending | Select-Object -First 1 | Remove-Item -Recurse -Force
        
        $ps1 = new-object System.Diagnostics.Process
        $ps1.StartInfo.Filename = "logman.exe"
        $ps1.StartInfo.Arguments = ' delete "Enhanced Active Directory Diagnostics" '
        $ps1.StartInfo.RedirectStandardOutput = $false
        $ps1.StartInfo.UseShellExecute = $false
        $ps1.start()
        $ps1.WaitForExit()
    }

}
function StopFailedTracing
{
    ## A previous collection failed or was cancelled prematurely this option will just attempt to stop everything that might still be running

    StopWPR
    $customADDSxml = Test-path "$PSScriptRoot\ADDS.xml"
    if ($customADDSxml)
    {
        $Global:CustomADDSUsed = $true
    }
    StopADDiagnostics
    StopLSATracing
    StopSamSrvTracing
    StopPerfLogs $true
    StopPerfLogs $false

    if ($Global:CustomADDSUsed)
    {
        ## have to clean up the source folder otherwise the subsequent runs will fail as it will try to re-use existing folder name
        $perflogPath = "C:\PerfLogs\Enhanced-ADDS"
        Get-ChildItem $perflogPath | Sort-Object CreationTime -Descending | Select-Object -First 1 | Remove-Item -Recurse -Force
        $ps1 = new-object System.Diagnostics.Process
        $ps1.StartInfo.Filename = "logman.exe"
        $ps1.StartInfo.Arguments = ' delete "Enhanced Active Directory Diagnostics" '
        $ps1.StartInfo.RedirectStandardOutput = $false
        $ps1.StartInfo.UseShellExecute = $false
        $ps1.start()
        $ps1.WaitForExit()
    }
}

##MAIN   
    $ADPerfFolder = "C:\ADPerfData"

    $exists = Test-Path $ADPerfFolder
    if ($exists)
    {
        Write-Host "C:\ADPerfData Already exists - using existing folder"
    }
    else
    {
        New-Item $ADPerfFolder -type directory | Out-Null
        
        Write-Host "Created AD Perf Data Folder"
        
    }

    Write-Host ""
    Write-Host ""
    
    if ($Scenario -eq 0)
    {
        ADPerf-Menu
        $Selection = Read-Host "Choose the scenario you are troubleshooting"
    }
    else
    {
        $Selection = $Scenario
    }

    if ($CaptureTime -gt 0)
    {
        $Global:TriggerScenario = $true
        $Global:TriggeredTimerLength = $CaptureTime
    }

    $DateTime = Get-Date -Format yyyyMMddMMTHHmmss
    $Global:DataPath = "$ADPerfFolder\" + $env:computername + "_" +$DateTime + "_Scenario_" + $Selection

    if ($Selection -gt 0 -and $Selection -lt 9)
    {
        New-Item $Global:DataPath -type directory | Out-Null
    }

    switch ($Selection)
    {
        1 {HighCpuDataCollection}
        2 {HighCpuDataCollectionTriggerStart}
        3 {HighMemoryDataCollection}
        4 {HighMemoryDataCollectionTriggerStart}
        5 {ATQThreadDataCollection}
        6 {BaseLineDataCollection}
        7 {LongBaseLineCollection}
        8 {StopFailedTracing}
        'q' {}
    }

    if ($Selection -gt 0 -and $Selection -lt 8)
    {
        Write-Host "Copying Data to $ADPerfFolder and performing cleanup"

        tasklist /svc | Out-File $Global:DataPath\tasklist.txt
        tasklist /v /fo csv | Out-File $Global:DataPath\Tasklist.csv
        dcdiag /v | Out-File $Global:DataPath\DCDiag.txt
        netstat -anoq | Out-File $Global:DataPath\Netstat.txt

        CorrelateDataAndCleanup

        Copy-Item "$env:SystemRoot\system32\ntdsai.dll" -Destination $Global:DataPath
        Copy-Item "$env:SystemRoot\system32\samsrv.dll" -Destination $Global:DataPath
        Copy-Item "$env:SystemRoot\system32\lsasrv.dll" -Destination $Global:DataPath
        Copy-Item "$env:SystemRoot\system32\ntdsatq.dll" -Destination $Global:DataPath

        Copy-Item "$env:Temp\RDR*" -Destination $Global:DataPath -Recurse -Force -ErrorAction SilentlyContinue

        Write-Host "Data copy is finsihed, please zip the $Global:DataPath folder and upload to DTM"
    } 

##MAIN
