#Requires -Version 4
<#
.SYNOPSIS
   Collect traces for UEX and WPR/Netsh(packet capture)/Procmon/PSR 

.DESCRIPTION
   Collect ETW traces for UX components such as Appx/Shell/RDS/UEV/Logon/Auth/WMI etc..
   Also WPR/Netsh/Procmon/PSR can be taken at the same time.
   This script supports autologger for ETW traces. In addition to this, bootlogging
   including boottrace(WPR), persistent=yes(Netsh) and /bootloggin(procmon) are also supported.

   Run 'Get-Help uxtrace.ps1 -full' for more detail.

   USAGE SUMMARY:
   Start multiple traces, for exmple, RDS and WMI trace:
   
   PS> UXTrace.ps1 -Start -RDS -WMI

   Start traces and WPR/Netsh(packet capturing)/Procmon at the same time.
   
   PS> UXTrace.ps1 -Start -RDS -WMI -WPR General -Netsh -Procmon

   Stop all traces including WPR/Netsh/Procmon/PSR:
   
   PS> UXTrace.ps1 -Stop

   Set AutoLogger for ETW traces and WPR(boottrace), Netsh(persistent=yes) and procmon(bootlogging):
   
   PS> UXTrace.ps1 -SetAutoLogger -RDS -WPR General -Netsh -Procmon
   PS> Restart-Computer
   PS> UXTrace.ps1 -StopAutoLogger  # Stop all autologger sessions

   Collect just logs for each component:
   
   PS> UXTrace.ps1 -CollectLog IME,Print,Basic

.NOTES  
   Author     : Ryutaro Hayashi - ryhayash@microsoft.com
   Requires   : PowerShell V4(Supported from Windows 8.1/Windows Server 2012 R2)
   Last update: 06-10-2020

.PARAMETER Start
Starting RDS trace and WRP/Netsh(packet capturing)/Procmon/PSR depending on options.

.PARAMETER SetAutoLogger
Set autologger for ETW traces and WRP/Netsh(packet capturing)/Procmon.

.PARAMETER Stop
Stop all active ETW traces and WRP/Netsh(packet capturing)/Procmon/PSR.
Also this deletes AutoLogger settings if exist.

.PARAMETER StopAutoLogger
Stop all active autologger sessions and WRP(boottrace)/Netsh(persistent=yes)/Procmon(bootlogging).

.PARAMETER DeleteAutoLogger
Delete all autologger settings. 
Note this does not cancel WRP(boottrace)/Netsh(persistent=yes)/Procmon(bootlogging). 
These are stopped manually after restarting the system.

.PARAMETER WPR
Use with -Start or -SetAutoLogger(ex. UXTrace.ps1 -Start -RDS -WPR General)
Start WPR session. If use with -SetAutologger(i.e. -SetAutoLogger -WPR General), WPR boottrace is enabled.

.PARAMETER Netsh
Use with -Start or -SetAutoLogger(ex. UXTrace.ps1 -Start -RDS -Netsh)
Start Netsh(packet capturing) session. If use with -SetAutologger(i.e. -SetAutoLogger -Netsh), Netsh is started with 'Persisten=yes'.

.PARAMETER NetshScenario
Use with -Start or -SetAutoLogger(ex. UXTrace.ps1 -Start -RDS -NetshScenario InternetClient_dbg)
Start Netsh(packet capturing) session with scenario trace. If use with -SetAutologger(i.e. -SetAutoLogger -NetshScenario InternetClient_dbg), Netsh is started with 'Persisten=yes'.

.PARAMETER Procmon
Use with -Start or -SetAutoLogger(ex. UXTrace.ps1 -Start -RDS -Procmon)
Start procmon. If use with -SetAutologger(i.e. -SetAutoLogger -Procmon), bootlogging is enabled.

.PARAMETER Perf
Use with -Start (ex. UXTrace.ps1 -Start -Perf)
Enable traces and performance log.

.PARAMETER PerfInterval
Use with -Start and -Perf(ex. UXTrace.ps1 -Start -Perf -PerfInverval(second))
Specify log interval for performance log.

.PARAMETER NoWait
Use with -Start(ex. UXTrace.ps1 -Start -RDS -NoWait)
Don't wait and the script returns immediately after starting traces.

.PARAMETER Compress
Log folder('MSLOG' folder on desktop) is compressed after gathering logs.

.PARAMETER Delete
Use with -Compress. If -Delete, log foder will be deleted after compressing log folder is completed.

.PARAMETER Verbose
This script will run with verbose messages.

.PARAMETER Help
Show help message(=get-help -detailed).

.PARAMETER AsOneTrace
All ETW traces are merged into one trace file.

.PARAMETER List
List supported traces in this script.

.OUTPUTS
By default, all log files are stored in 'MSLOG' folder on your desktop.

.EXAMPLE
UXTrace.ps1 -Start -RDS -WMI               
Start multple traces.

.EXAMPLE
UXTrace.ps1 -Start -RDS -WMI -NoWait               
Start trace but the script returns immediately. You can stop the traces with '.\UXTraces.ps1 -Stop' later.

.EXAMPLE
UXTrace.ps1 -Start -RDS -WPR -Procmon
Collect RDS trace, WPR and procmon at the same time.

.EXAMPLE
UXTrace.ps1 -Start -RDS -Perf
start trace and collect performance log at the same time.

.EXAMPLE
UXTrace.ps1 -Start -RDS -WPR -Procmon -PSR
Collect traces, PSR and other tools at the same time.

.EXAMPLE
UXTrace.ps1 -Stop
Stop traces. You can use -Stop for stopping ETW traces, WPR, Netsh and procmon.
If you have a concern on some traces are still running, just run this command.

.EXAMPLE
UXTrace.ps1 -SetAutoLogger -RDS 
Enable autologger setting for RDS trace

UXTrace.ps1 -SetAutoLogger -RDS -WPR 
Enable autologger for RDS trace and WPR Boottrace 

.EXAMPLE
UXTrace.ps1 -StopAutoLogger
Stop all ETW autologger sessions started by this script. Also stops WPR(boottrace), Netsh(persistent=yes) and procmon(bootlogging).

.EXAMPLE
UXTrace.ps1 -SetAutoLogger -RDS -WPR -Netsh -Procmon
Enable autologgers. After restart the system, you can stop autologger with '.\UXTraces.ps1 -StopAutoLogger'.

.EXAMPLE
UXTrace.ps1 -DeleteAutoLogger
After enable autologger with '-SetAutoLogger' but in case you want to cancel the autologger, use this option to delete the autologger settings.
#>
Param (
    [Parameter(ParameterSetName='Start', Position=0)]
    [switch]$Start,
    [Parameter(ParameterSetName='SetAutoLogger', Position=0)]
    [switch]$SetAutoLogger,
    [Parameter(ParameterSetName='Stop', Position=0)]
    [switch]$Stop,
    [Parameter(ParameterSetName='StopAutoLogger', Position=0)]
    [switch]$StopAutoLogger,
    [Parameter(ParameterSetName='DeleteAutoLogger', Position=0)]
    [switch]$DeleteAutoLogger,
    [Parameter(ParameterSetName='Set', Position=0)]
    [String]$Set,
    [Parameter(ParameterSetName='Unset', Position=0)]
    [String]$Unset,
    [Parameter(ParameterSetName='List', Position=0)]
    [switch]$List,
    [Parameter(ParameterSetName='Help', Position=0)]
    [switch]$Help,
    [Parameter(ParameterSetName='Status', Position=0)]
    [switch]$Status,
    [Parameter(ParameterSetName='CollectLog', Position=0)]
    [String[]]$CollectLog,
    [Parameter(ParameterSetName='ListSupportedLog', Position=0)]
    [switch]$ListSupportedLog,
    [Parameter(ParameterSetName='ListSupportedNetshScenario', Position=0)]
    [switch]$ListSupportedNetshScenario,
    ### Trace switches
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$AppV,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$RDS,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$Logon,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$WMI,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$Auth,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$Net,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$UEV,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$LSA,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$CRYPT,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$COM,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$WinRM,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$AppX,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$WU,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$Store,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$Photo,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$Alarm,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$Calc,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$ContactSupport,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$Cortana,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$Speech,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$Search,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$EventLog,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$Shell,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$DWM,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$IME,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$CDP,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$Print,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$Task,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$StartMenu,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$SystemSettings,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$WPN,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$XAML,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$Shutdown,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$VSS,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$WSB,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$VDS,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$Win32k,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$Font,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$AppCompat,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$Media,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$VAN,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$UserDataAccess,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$WMIBridge,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$WER,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$CodeIntegrity,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$ClipBoard,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$MMC,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$QuickAssist,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$FSLogix,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$WSC,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$LicenseManager,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$ATAPort,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$CDROM,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$FailoverClustering,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$CSVFS,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$Dedup,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$FSRM,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$HyperV,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$VHDMP,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$ISCSI,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$NFS,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$PNP,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$StorageSpace,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$Storage,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$StorageReplica,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$Storport,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$Storsvc,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$USB,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$ServerManager,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$WVD,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$MSRA,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$DM,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$CldFlt,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$ImmersiveUI,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$HTTP,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$Camera,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$ESENT,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$CBS,
    ### Command switches
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$Netsh,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [String[]]$NetshScenario,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='TTD')]
    [String]$TTD,
    [Parameter(ParameterSetName='Start')]
    [switch]$SCM,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$Procmon,
    [Parameter(ParameterSetName='Start')]
    [switch]$Perf,
    [Parameter(ParameterSetName='Start')]
    [switch]$PSR,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [String]$WPR,
    ### Control switches
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [Parameter(ParameterSetName='NetshScenario')]
    [switch]$NoPacket,
    [Parameter(ParameterSetName='Start')]
    [Int]$PerfInterval,
    [Parameter(ParameterSetName='Start')]
    [switch]$NoWait,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='Stop')]
    [Parameter(ParameterSetName='StopAutoLogger')]
    [Parameter(ParameterSetName='CollectLog')]
    [switch]$Compress,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='Stop')]
    [Parameter(ParameterSetName='StopAutoLogger')]
    [Parameter(ParameterSetName='CollectLog')]
    [String]$LogFolderName,
    [Parameter(ParameterSetName='SetAutoLogger')]
    [String]$AutologgerFolderName,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [switch]$AsOneTrace,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='Stop')]
    [Parameter(ParameterSetName='StopAutoLogger')]
    [switch]$Delete,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='SetAutoLogger')]
    [Parameter(ParameterSetName='Stop')]
    [Parameter(ParameterSetName='StopAutoLogger')]
    [String]$ProcmonPath,
    [String]$TTDPath,
    [Parameter(ParameterSetName='Start')]
    [Parameter(ParameterSetName='TTD')]
    [Switch]$TTDOnLaunch,
    [switch]$CreateBatFile,
    [switch]$DebugMode,
    [switch]$BasicLog,  # BasicLog remains here only for backword compatibility and is no longer used.
    [switch]$NoBasicLog
)

$TraceSwitches = [Ordered]@{
    'Alarm' = 'Alarm app tracing'
    'AppCompat' = 'AppCompat and UAC tracing'
    'AppV' = 'App-V tracing'
    'AppX' = 'AppX tracing'
    'ATAPort' = 'ATA(IDE) Port tracing'
    'Auth' = 'Authentication tracing'
    'Calc' = 'Calculator app tracing'
    'Camera' = 'Camera app tracing'
    'CBS' = 'CBS tracing'
    'CDP' = 'CDP(Connected Devices Platform) tracing'
    'CDROM' = 'CDROM, DVD, UDFS tracing'
    'CodeIntegrity' = 'CodeIntegrity tracing'
    'COM' = 'COM/DCOM/WinRT/PRC tracing'
    'ContactSupport' = 'ContactSupport app tracing'
    'Cortana' = 'Cortana tracing'
    'CRYPT' = 'Crypt tracing'
    'CldFlt' = 'cldflt tracing(driver for clould file)'
    'ClipBoard' = 'Clip board tracing'
    'CSVFS' = 'CSVFS tracing'
    'Dedup' = 'Deduplication tracing'
    'DM' = 'Device Management(InstallService/EnterpriseManagement/CSP) tracing'
    'DWM' = 'DWM(Desktop Window Manager) tracing'
    'ESENT' = 'ESENT tracing'
    'EventLog' = 'EventLog tracing'
    'FailoverClustering' = 'FailoverClustering tracing'
    'Font' = 'Font tracing'
    'FSLogix' = 'FSLogix tracing'
    'FSRM' = 'FSRM tracing'
    'HTTP' = 'WinINet, WinHTTP tracing'
    'HyperV' = 'Hyper-V tracing'
    'IME' = 'IME and input tracing'
    'ImmersiveUI' = 'ImmersiveUI tracing'
    'ISCSI' = 'iSCIS tracing'
    'LicenseManager' = 'License manager tracing'
    'Logon' = 'Winlogon/LogonUI/Credential provider/LockApp/AssignedAccess tracing'
    'LSA' = 'Lsass tracing'
    'Media' = 'Media Player tracing'
    'MMC' = 'MMC tracing'
    'MSRA' = 'Remote Assistance tracing'
    'Net' = 'TCPIP/Winsock/NetIO/NDIS tracing'
    'NFS' = 'NFS tracing'
    'Nls' = 'NLS tracing (only CollectLog)'
    'Photo' = 'Photo app tracing'
    'PNP' = 'PNP tracing'
    'Print' = 'Print tracing'
    'QuickAssist' = 'QuickAssist app tracing'
    'RDS' = 'RDS tracing'
    'Search' = 'Windows search and search client(tquery.dll) tracing'
    'ServerManager' = 'Server manager(ServerManager.exe) tracing'
    'Shell' = 'Shell tracing'
    'Shutdown' = 'Shutdown tracing'
    'Speech' = 'Speech app tracing'
    'StartMenu' = 'StartMenu(ShellExperienctHost/StartMenuExperienctHost) tracing'
    'StorageSpace' = 'Storage space tracing'
    'Storage' = 'AKA SAN shotgun tracing'
    'StorageReplica' = 'Storage replica tracing'
    'Store' = 'Store app tracing'
    'Storport' = 'Storport tracing'
    'Storsvc' = 'Storsvc tracing'
    'SystemSettings' = 'SystemSettings tracing'
    'Task' = 'Task schedure/UBPM tracing'
    'UEV' = 'UE-V tracing'
    'USB' = 'USB tracing'
    'UserDataAccess' = 'UserDataAccess tracing'
    'VHDMP' = 'Virtual disk and VHDMP driver tracing'
    'VSS' = 'VSS tracing'
    'VDS' = 'Virtual Disk Service tracing'
    'WER' = 'Windows Error Reporting tracing'
    'Win32k' = 'Win32k tracing'
    'WinRM' = 'WinRM tracing'
    'WMI' = 'WMI(winmgmt) tracing. This does not contain WMI provider trace.'
    'WMIBridge' = 'WMI Bridge provider(DMWmiBridgeProv) tracing'
    'WPN' = 'WPN(Windows Platform Notification) tracing'
    'WSB' = 'Windows Server Backup tracing'
    'WSC' = 'Windows Security Center tracing'
    'WVD' = 'Windows Virtual Desktop tracing'
    'WU' = 'WU(Windows Update) tracing'
    'XAML' = 'XAML and dcomp tracing'
    'VAN' = 'View Available Network tracing'
}

$CommandSwitches = [Ordered]@{
    'Perf' = 'Performance monitor'
    'Procmon' = 'Process monitor(procmon.exe)'
    'PSR' = 'Problem Steps Recorder'
    'Netsh' = 'Netsh(Packet capture)'
    'NetshScenario' = 'Netsh client scenario trace + Packet capture'
    'SCM' = 'Setting SCM trace'
    'WPR' = 'Windows Performance Recoder(wpr.exe)'
    'TTD' = 'Collect TTD'
}

$ControlSwitches = @(
    'Start'
    'Stop'
    'SetAutoLogger'
    'DeleteAutoLogger'
    'AsOneTrace'
    'Status'
    'Help'
    'LogFolderName'
    'Compress'
    'NoWait'
    'Delete'
    'DebugMode'
    'List'
    'ProcmonPath'
    'TTDPath'
    'TTDOnLaunch'
    'CollectLog'
    'ListSupportedLog'
    'ListSupportedNetshScenario'
    'PerfInterval'
    'NoPacket'
    'Set'
    'Unset'
    'CreateBatFile'
    'BasicLog'
    'NoBasicLog'
)

# Used for -Set and -Unset
$SupportedSetOptions = [Ordered]@{
    'WER' = 'Enable WER setting'
}

$LogTypes = @(
    'ETW'
    'Command'
    'Perf'
    'Custom'
)

$TraceStatus = @{
    'Success' = 0
    'Running' = 1
    'AutoLoggerRuning' = 2
    'Started' = 3
    'Stopped' = 4
    'ErrorInStart' = 5
    'ErrorInStop' = 6
    'NotSupported' = 7
    'NoStopFunction' = 8
}

$LogLevel = @{
    'Normal' = 0
    'Info' = 1
    'Warning' = 2
    'Error' = 3
    'Debug' = 4
    'ErrorLogFileOnly' = 5
    'WarnLogFileOnly' = 6
}

<#------------------------------------------------------------------
                     PROVIDER DEFINITIONS 
------------------------------------------------------------------#>

#---  RDS PROVIDERS ---#
$RDSProviders = @(
    '{82A94E1C-C1B3-4E4A-AC87-43BD802E458E}' # KernVC
    '{FA801570-83A9-11DF-B3A9-8C26DFD72085}' # RdCentralDbPlugin
    '{D4199645-41BE-4FD5-9D71-A612C508FDC6}' # RDPApiTrace
    '{D4199645-41BE-4FD5-9D73-A612C508FDC6}' # RDPApiTraceTS
    '{796F204A-44FC-47DF-8AE4-77C210BD5AF4}' # RdpClip
    '{D4199645-41BE-4FD5-9D71-A612C508FDC7}' # RDPEncComTrace
    '{8A99FD17-7D82-45D9-A965-F9A3F9FA85E5}' # RdpFilterTrace
    '{C5615DDA-2DAC-479B-83AB-F18C95601774}' # rdpInput
    '{15D9261C-EFDF-4C4A-8D3C-098A15DC483D}' # RdpNetEmu
    '{6CDD992D-B35C-40A6-AF1E-D727C11DECFD}' # RdvgKmdTrace
    '{84214511-602B-4456-9CB9-7800ED3432F6}' # RdvgmTrace
    '{6AABAEA6-DF19-4528-97D8-3A420CEE69A0}' # RdvgUmd11Trace
    '{2A11472B-451F-4FCA-8590-9724D41C604E}' # RDVVGHelper
    '{C29D637F-AFB5-43F9-96F8-936429371F32}' # RdvVmCore
    '{482F83D3-E8CB-4727-8A28-FC51544C5A28}' # RdvVmTransport
    '{80342309-054F-4E2E-9D3D-FCCFBDCAA92F}' # CtVmtLibTraceGuid
    '{5283D5F6-65B5-425F-A30B-F16C057D6B57}' # termsrv
    '{0B938561-4D72-4312-ACF6-109D34C26148}' # CMProxyGuest
    '{5CE9C675-02A0-4B9D-89E6-77C13EF68E75}' # CMProxyHost
    '{7ADA0B31-F4C2-43F4-9566-2EBDD3A6B604}' # CentralPublishingTrace
    '{1FD4C5A9-27B7-418B-8DFC-216E7FA7B990}' # TSCPubStubTrace
    '{81B84BCE-06B4-40AE-9840-8F04DD7A8DF7}' # TSCPubWmiProvider
    '{BF936B9C-DA45-4494-A236-101FE5A2A51D}' # TSPublishingAppFilteringTrace
    '{0CEA2AEE-1A4C-4DE7-B11F-161F3BE94669}' # TSPublishingIconHelperTrace
    '{E43CAB68-0AB4-4F47-BF30-E61CAC7BBD8A}' # TSPublishingWmiProvider
    '{D2B9C1C5-0C37-47EB-AA79-CD0CF0CE2FA6}' # TSFairShare
    '{4199EE71-D55D-47D7-9F57-34A1D5B2C904}' # TerminalServer-MediaFoundationPlugin
    '{0ED38D2B-4ACC-4E23-A8EC-D0DACBC34637}' # tsprint
    '{FAC7FCCE-62FC-4BE0-BD67-311750B5BCFF}' # XPSClientPlgin
    '{5A966D1C-6B48-11DA-8BDE-F66BAD1E3F3A}' # RDPENDPTrace
    '{C127C1A8-6CEB-11DA-8BDE-F66BAD1E3F3A}' # RDPINITTrace
    '{BFA655DC-6C51-11DA-8BDE-F66BAD1E3F3A}' # RDPSHELLTrace
    '{A1F3B16A-C510-41C1-8B58-E695880F3A80}' # tsscan
    '{ECA5427C-F28F-4942-A54B-7E86DA46BDBE}' # TSUrbUtils
    '{7211AE02-1EB0-454A-88FA-EA16632DCB45}' # TSUsbBusFilter
    '{39A585FF-6C36-492B-93C0-35B71E65A345}' # TSUsbGenericDriver
    '{A0674FB6-BA0D-456F-B079-A2B029D8342C}' # TSUsbHubTrace
    '{48738267-0545-431D-8087-7349127811D0}' # TSUsbRedirectionServiceTrace
    '{600BE610-F0E8-4912-B397-D2CC76060114}' # USBDRTrace
    '{6E530C0D-677F-488B-B163-0415CB65883D}' # VMMWSFilterPluginTrace
    '{70A43AE8-E131-42BD-89E0-23704FB27C6A}' # TSWebProxyTrace
    '{070F54B9-7EB0-4C99-8DFA-2AA8D8AB0D89}' # WorkspaceTrace
    '{3C3E7039-99CF-4446-8D81-4AC5A8560E7B}' # WorkspaceRuntimeTrace(wksprt.exe)
    '{3E3E7039-99DF-4446-8C81-4AD5A8560E7B}' # WorkspaceBrokerAxTrace(wkspbrokerAx.dll)
    '{449E4E69-329E-4EB1-9DDF-809D17A2E0C1}' # sdclient(WS2016 or earlier)
    '{ae8ab061-654e-4d72-9f4b-c799ba919ec8}' # sessionmsg
    '{73BFB78F-12B5-4738-A66C-A77BCD55FA12}' # rdpdr
    '{C14F3000-0B2D-4464-99AC-FA764AF708CF}' # rdpbus
    '{4BDD50B0-BF12-4991-8B11-C455F14289DB}' # rdpvideominiport
    '{73C5EC49-C807-489D-9E45-D36D72235F84}' # UMRDPTrace
    '{2A0A7EC8-5E2B-47AB-B553-32E1C7AEF0EF}' # VmHostAgentTrace
    '{C10870A3-617D-42E9-80C7-1C4BE2709E06}' # VmPluginTrace
    '{0046A6B4-A24C-40D5-B0E6-C8EC031BD82A}' # tsrpc (WS2016 or earlier)
    '{9ED727C4-4AB6-4B66-92D7-2072E87C9124}' # tssrvlic (WS2016 or earlier)
    '{508371B1-7651-4B33-4B33-5884F824BD1B}' # TSVIPCli (WS2016 or earlier)
    '{AE4C5843-A9A3-4EB9-81F3-65D57D250180}' # TSVIPPool(WS2016 or earlier)
    '{432EEF91-C605-482B-83BE-0963604F1397}' # RDVGSMSTrace (WS2012R2 or earlier)
    '{0C38D54D-EF5F-4179-95FA-6D4EDA073000}' # RDVVGHelperSerivce (WS2012R2 or earlier)
    '{3C3E7089-99CF-4446-8D81-4AC5A8560E6A}' # SessionBrokerTrace
    '{59DE359D-EC83-445C-9323-B75E2056D5A5}' # SessionEnv
    '{986CC918-7434-4FAB-B37F-C4BA7AD1E293}' # TSSdJetTrace
    '{70DB53D8-B6F3-428D-AA33-5B2CE56718C5}' # Gateway Client Trace
    '{6F539394-F34F-45FD-B4CA-BD5C547B0BCB}' # Gateway Edge Trace
    '{909ED641-D5EF-4299-B898-F13451A59F50}' # AaTsPPTrace
    '{588F5E4C-6853-4FCB-BD7D-75F926276C20}' # TSAllowTrace
    '{28711274-D721-465E-9C7E-D359422E96CD}' # lsclientservice
    '{9EA2030F-DB66-47EF-BF2C-619CC76F3E1B}' # LSCSHostPolicy
    '{26C7EAC9-9675-43CB-9EF1-B9CD4564595F}' # lscspolicyloader
    '{97166ECD-4F97-442F-A909-9EB9AE6D2458}' # lscsvmbuspipechannel
    '{A489F3D1-F149-4968-BDCE-4F7D93516DA8}' # lserver
    '{F8FCF9E0-535A-4BA6-975F-7AC82FBDC631}' # TLSBrandTrace
    '{5F328364-2E3D-4F73-B099-0D5C839E32A0}' # CredentialsPlugin
    '{DAA6CAF5-6678-43F8-A6FE-B40EE096E00E}' # mstscax.dll
    '{DAA6CAF5-6678-43F8-A6FE-B40EE096E06E}' # mstscax.dll
    '{0C51B20C-F755-48A8-8123-BF6DA2ADC727}' # mstsc.exe
    '{62F277AE-2CCF-4AA9-A8AA-32752200BC18}' # CtDwm
    '{97E97A1E-C0A9-4B8D-87C4-42105A957D7B}' # RdpDwmDirect
    '{6165F3E2-AE38-45D4-9B23-6B4818758BD9}' # TSPkg
    '{37D2C3CD-C5D4-4587-8531-4696C44244C8}' # schannel(schannel.dll)
    '{DC1A94A6-0A1A-433E-B470-3C72353B7309}' # Microsoft.Windows.RemoteDesktop.RAIL.Server.Diagnostics(From RS5)
    '{3ec987dd-90e6-5877-ccb7-f27cdf6a976b}' # Microsoft.Windows.LogonUI.WinlogonRPC
    '{c0ac3923-5cb1-5e37-ef8f-ce84d60f1c74}' # Microsoft.Windows.TSSessionUX
    '{302383D5-5DC2-4BEA-AC7E-4154A1272583}' # Microsoft.Windows.RemoteDesktop.MultiPoint
    '{26771A7F-04D4-4597-BBF6-3AF9F7818B25}' # Microsoft.Windows.RemoteDesktop.Virtualization
    '{F115DDAF-E07E-4B15-9721-427134B41EBA}' # RDP(RDPEncryption)
    '{a8f457b8-a2b8-56cc-f3f5-3c00430937bb}' # RDP(RDPEmulation)
    '{C6FDD8E3-770B-4964-9F0C-227457146B49}' # RDP(SessEnvRpcTelemetry)
    '{89d48904-939f-4177-aad4-2fdb26b8329f}' # Microsoft.Windows.RemoteDesktop.RDSHFarm.UVhd
    '{D9F94C5A-94F8-4CD0-A054-A1EE67A2DA6B}' # Microsoft.Windows.RemoteDesktop.SessionHost
    '{da539211-d525-422a-8a92-bcbe4367159c}' # Microsoft.Windows.RemoteDesktop.RDSLSTelemetry
    '{76de1e7b-74d9-585f-1f85-affa9242808c}' # RDWin32ClientAxTelemetryProvider
    '{61dd194a-b8cb-4de5-a018-4c7f6f9e9988}' # RDP.MSTSCTelemetry
    '{76de1e7b-74d5-575e-1f81-4ffe6a42777b}' # RDWin32ClientAxTelemetryProvider
    '{7756e5a6-21b2-4c40-855e-88cf2b13c7cb}' # RDP.MSTSCAXTelemetry
    '{204AE8F0-42F7-4A13-97CD-B490927CB725}' # Microsoft.Windows.VGPU.RDVGM
    '{EB4AC9D0-AE00-4963-8435-5163ABD35572}' # Microsoft.Windows.RemoteDesktop.Gateway
    '{660cfa71-2a70-4e80-bdf3-f1424919d01c}' # Microsoft.RDS.RdClient.Client.FeedSubscription
    '{55184039-1cbe-4d35-9f9e-85d0075943df}' # Microsoft.RDS.RADC.FeedSubscription
    '{00508371-7651-4b33-4b33-5884f824bd1b}' # TSVIPCli
    '{32817e55-7bfe-45e0-af68-a413fa6e0083}' # TSMSISrv
    '{AE4C5843-A9A3-4EB9-81F3-65D57D250180}' # TSVIPPool
    '{0ba29edf-a2f4-4212-b06b-6d5712210652}' # TSVIPSrv
    '{c0c89c53-dd3f-4782-a78f-5378111a8305}' # RDSNetFairshare
    '{D2E990DA-8504-4702-A5E5-367FC2F823BF}' # AUInstallAgent(From WS2019)
    '{FB1A70CC-BE28-40C1-BD6A-47671538383A}' # Microsoft.Windows.RemoteDesktop.CertManager(From WS2019)
    '{997FB36F-0208-4ED7-865B-E19816C3782D}' # Microsoft.Windows.RemoteDesktop.SessionConfig(From WS2019)
    '{E80ADCF1-C790-4108-8BB9-8A5CA3466C04}' # Microsoft-Windows-TerminalServices-RDP-AvcSoftwareDecoder(From WS2019)
    '{D953B8D8-7EA7-44B1-9EF5-C34AF653329D}' # RDP.Graphics(From WS2019)
    '{78be48bd-5d52-4e39-823d-226cd5551f37}' # RDP.ServerStack(From WS2019)
    '{9512fdbc-24e6-44fa-a8a3-af44d3447216}' # RDP.Graphics(From WS2019)
    '{CA341B3C-B9D2-4D0F-9BD3-D88183596DB9}' # RDP.ServerStack.Diagnostics(From WS2019)
    '{8A633D91-8B07-4AAE-9A00-D07E2AFD29D6}' # RDP.Transport
    '{fdff33ec-70aa-46d3-ba65-7210009fa2a7}' # Microsoft-Windows-Hyper-V-Integration-RDV(vmicrdv.dll)
    '{77B0D57B-97B8-4f42-83B0-4FDA12D3D79A}' # Microsoft-Windows-RemoteApp and Desktop Connection Management
    '{1B8B402D-78DC-46fb-BF71-46E64AEDF165}' # Microsoft-Windows-RemoteApp and Desktop Connections(TSWorkspace.dll)
    '{1139C61B-B549-4251-8ED3-27250A1EDEC8}' # Microsoft-Windows-RemoteDesktopServices-RdpCoreTS(RdpCoreTS.dll)
    '{10d520e2-205c-4c22-b25c-ac7a779c55b2}' # Microsoft-Windows-RemoteDesktopServices-RemoteFX-Manager(rdvgm.exe)
    '{10AB3154-C36A-4F24-9D91-FFB5BCD331EF}' # Microsoft-Windows-RemoteDesktopServices-RemoteFX-SessionLicensing(LSClientService.dll)
    '{1B4F0E96-6876-49c8-BFBA-072DAE6543B3}' # Microsoft-Windows-RemoteDesktopServices-vGPU-KModeDriver(rdvgkmd.sys)
    '{5AE63087-6A35-40b0-AE15-CEA95A71A8C0}' # Microsoft-Windows-RemoteDesktopServices-vGPU-UModeDriver(rdvgumd32.dll)
    '{1deb930f-e136-4b08-9761-d7e3a5d14faa}' # Microsoft-Windows-RemoteDesktopServices-vGPU-UModeDriver64(rdvgumd64.dll)
    '{6e400999-5b82-475f-b800-cef6fe361539}' # Microsoft-Windows-TerminalServices-ClientUSBDevices(tsusbflt.sys)
    '{3f7b2f99-b863-4045-ad05-f6afb62e7af1}' # Microsoft-Windows-TerminalServices-MediaRedirection(tsmf.dll)
    '{27a8c1e2-eb19-463e-8424-b399df27a216}' # Microsoft-Windows-TerminalServices-PnPDevices(umrdp.dll)
    '{952773BF-C2B7-49BC-88F4-920744B82C43}' # Microsoft-Windows-TerminalServices-Printers(umrdp.dll)
    '{C76BAA63-AE81-421C-B425-340B4B24157F}' # Microsoft-Windows-TerminalServices-RemoteConnectionManager(termsrv.dll)
    '{dcbe5aaa-16e2-457c-9337-366950045f0a}' # Microsoft-Windows-TerminalServices-ServerUSBDevices(tsusbhub.sys)
    '{4d5ae6a1-c7c8-4e6d-b840-4d8080b42e1b}' # Microsoft-Windows-TerminalServices-Gateway(aaedge.dll)
    '{4D99F017-0EB1-4B52-8419-14AEBD13D770}' # Microsoft-Windows-TerminalServices-Licensing(lserver.dll)
    '{5d896912-022d-40aa-a3a8-4fa5515c76d7}' # Microsoft-Windows-TerminalServices-LocalSessionManager(lsm.dll)
    '{D1737620-6A25-4BEF-B07B-AAC3DF44EFC9}' # Microsoft-Windows-TerminalServices-SessionBroker(tssdis.exe)
    '{2184B5C9-1C83-4304-9C58-A9E76F718993}' # Microsoft-Windows-TerminalServices-SessionBroker-Client(tssdjet.dll)
    '{32817e55-7bfe-45e0-af68-a413fa6e0083}' # Microsoft-Windows-TerminalServices-TSAppSrv-TSMSI(TSMSISrv.dll)
    '{6ba29edf-a2f4-4212-b06b-6d5712210652}' # Microsoft-Windows-TerminalServices-TSAppSrv-TSVIP(TSVIPSrv.dll)
    '{8d83aec0-01de-4772-a317-2093b6dc3bab}' # Microsoft-Windows-TerminalServices-TSFairShare-Events(TSFairShare.sys)
    '{92618A87-2F6A-4B75-9AE2-E77BE7EAF43C}' # Microsoft-Windows-TerminalServices-TSV-VmHostAgent(tsvmhasvc.dll)
    '{28aa95bb-d444-4719-a36f-40462168127e}' # Microsoft-Windows-TerminalServices-ClientActiveXCore(mstscax.dll)
    '{8bddcf41-9630-47e8-914a-d4952112ea19}' # Microsoft-Windows-RemoteDesktopServices-RemoteFX-SessionManager(rdvgsm.dll)(WS2012R2 or earlier)
    '{7bfcf102-7378-431c-9284-0b968258991a}' # Microsoft-Windows-RemoteDesktopServices-RemoteDesktopSessionManager(RDPWD.sys)(WS2012 or ealier)
    '{b1c94ed9-ac9b-410e-aa48-4ffc5e45f4e3}' # Microsoft-Windows-TerminalServices-MediaRedirection-DShow(DShowRdpFilter.dll) (WS2008R2)
    '{D2E990DA-8504-4702-A5E5-367FC2F823BF}' # Microsoft-Windows-All-User-Install-Agent(RDSAppXHelper.dll)
    #'{127e0dc5-e13b-4935-985e-78fd508b1d80}' # Microsoft-Windows-TerminalServices-RdpSoundDriver(rdpendp.dll) => Too many logs will be recorded.
    '{1B9B72FC-678A-41C1-9365-824658F887E9}' # RDMSTrace
    '{9F58B00C-09C7-4CBC-8D19-969DCD5D5A6D}' # TSMMCTrace
    '{FB750AD9-8544-427F-B284-8ED9C6C221AE}' # Microsoft-Windows-Rdms-UI(Manifest)
    '{05da6b40-219e-4f17-92e6-d663fd87cba8}' # Microsoft-Windows-Remote-Desktop-Management-Service(rdms.dll)
    '{43471865-f3ee-5dcf-bf8b-193fcbbe0f37}' # Microsoft.Windows.RemoteDesktopServices.RailPlugin
    '{48EF6C18-022B-4394-BEE5-7B822B42AE4C}' # Microsoft.RDS.Windows.Client.MSRDC
    '{335934AA-6DD9-486C-88A5-F8D6A7D2BAEF}' # Microsoft.RDS.Windows.Client.AX
    '{4A49AFE3-776E-467A-ACA0-71F9C6C8499F}' # Microsoft.Windows.RemoteDesktop.RAIL.RdpInit
    '{39825FFA-F1B4-41B7-8221-20D4B8DBE57E}' # Microsoft.Windows.RemoteDesktop.RAIL.RdpShell
)

$AppVProviders = @(
    '{E4F68870-5AE8-4E5B-9CE7-CA9ED75B0245}' # Microsoft-AppV-Client
    '{0D21725F-A0BD-4D1D-AE8E-6910F1093419}' # Microsoft-AppV-Sequencer
    '{7561449A-FC50-469B-B76E-88F43CF79ECF}' # Microsoft-AppV-Sequencer-Debug
    '{9CC69D1C-7917-4ACD-8066-6BF8B63E551B}' # Microsoft-AppV-ServiceLog
    '{FB4A19EE-EB5A-47A4-BC52-E71AAC6D0859}' # Microsoft-AppV-SharedPerformance
    '{C901E37D-B5F4-4582-AE6E-C1459F358B30}' # Microsoft-AppV-Sequencer-PRS
    '{271aebf7-e83b-580f-7525-5e9563fe161a}' # Microsoft.Windows.AppMan.AppV
    '{582C6A21-F5B4-4E52-B592-0E8229BF1737}' # Microsoft.Windows.AppMan.Shared.Logging
    '{df9b8c8f-ed83-5cd0-acec-4790d087c32b}' # Microsoft.Windows.AppMan.AppV.Sequencer
    '{9CC69D1C-7917-4ACD-8066-6BF8B63E551B}' # Microsoft-AppV-ServiceLog
    '{28CB46C7-4003-4E50-8BD9-442086762D12}' # Microsoft-AppV-Client-StreamingUX
)

#---  LOGON PROVIDERS ---#
$LogonProviders = @(
    '{D451642C-63A6-11D7-9720-00B0D03E0347}' # WinLogon
    '{a789efeb-fc8a-4c55-8301-c2d443b933c0}' # UmsHlpr
    '{301779e2-227d-4faf-ad44-664501302d03}' # WlClNtfy
    '{5B4F9E61-4334-409F-B8F8-73C94A2DBA41}' # Userinit
    '{c2ba06e2-f7ce-44aa-9e7e-62652cdefe97}' # WinInit
    '{855ed56a-6120-4564-b083-34cb9d598a22}' # SetupLib
    '{d138f9a7-0013-46a6-adcc-a3ce6c46525f}' # WMsgSrv
    '{19d78d7d-476c-47b6-a484-285d1290a1f3}' # SysNtfy
    '{557D257B-180E-4AAE-8F06-86C4E46E9D00}' # LSM
    '{EB7428F5-AB1F-4322-A4CC-1F1A9B2C5E98}' # UserProfileService
    '{9891e0a7-f966-547f-eb21-d98616bf72ee}' # Microsoft.Windows.Shell.UserProfiles
    '{9959adbd-b5ac-5758-3ffa-ee0da5b8fe4b}' # Microsoft.Windows.ProfileService
    '{40654520-7460-5c90-3c10-e8b6c8b430c1}' # Microsoft.Windows.ProfExt
    '{D33E545F-59C3-423F-9051-6DC4983393A8}' # winsta
    '{b39b8cea-eaaa-5a74-5794-4948e222c663}' # Microsoft.Windows.Security.Winlogon
    '{8db3086d-116f-5bed-cfd5-9afda80d28ea}' # Microsoft-OSG-OSS-CredProvFramework
    '{5AA2DC10-E0E7-4BB2-A186-D230D79442D7}' # Microsoft.CAndE.ADFabric.CDJ.Recovery
    '{7ae961f7-1262-48e2-b237-acba331cc970}' # Microsoft.CAndE.ADFabric.CDJ.AzureSecureVMJoin
    '{fb3cd94d-95ef-5a73-b35c-6c78451095ef}' # Microsoft.Windows.CredProvDataModel
    '{a6c5c84d-c025-5997-0d82-e608d1abbbee}' # Microsoft.Windows.CredentialProvider.PicturePassword
    '{41ad72c3-469e-5fcf-cacf-e3d278856c08}' # Microsoft.Windows.BlockedShutdown
    '{df350158-0f8f-555d-7e4f-f1151ed14299}' # Microsoft.Windows.BioFeedback
    '{D33E545F-59C3-423F-9051-6DC4983393A8}' # winsta
    '{557D257B-180E-4AAE-8F06-86C4E46E9D00}' # LSM(From WS2019)
    '{4f7c073a-65bf-5045-7651-cc53bb272db5}' # Microsoft.Windows.LogonController
    '{3ec987dd-90e6-5877-ccb7-f27cdf6a976b}' # Microsoft.Windows.LogonUI.WinlogonRPC
    '{c0ac3923-5cb1-5e37-ef8f-ce84d60f1c74}' # Microsoft.Windows.TSSessionUX
    '{DBE9B383-7CF3-4331-91CC-A3CB16A3B538}' # Microsoft-Windows-Winlogon(Manifest)
    '{63D2BB1D-E39A-41b8-9A3D-52DD06677588}' # Microsoft-Windows-Shell-AuthUI(credprovhost.dll)
    '{DB00DFB6-29F9-4A9C-9B3B-1F4F9E7D9770}' # Microsoft-Windows-User Profiles General
    '{89B1E9F0-5AFF-44A6-9B44-0A07A7CE5845}' # Microsoft-Windows-User Profiles Service
    '{B059B83F-D946-4B13-87CA-4292839DC2F2}' # Microsoft-Windows-User-Loader
    '{EEA178E3-E9D4-41CA-BB56-CEDE1A476629}' # Microsoft-Windows-User-PnP
    '{1941DE80-2226-413B-AFA4-164FD76914C1}' # Microsoft.Windows.Desktop.Shell.WindowsUIImmersive.LockScreen
    '{176cd9c5-c90c-5471-38ba-0eeb4f7e0bd0}' # Microsoft.Windows.UI.Logon
    '{74cc4a0b-f577-5929-abcb-aa4bea374cb3}' # Microsoft.Windows.Shell.LockAppHost
    '{f8e28969-b1df-57fa-23f6-42260c77135c}' # Microsoft.Windows.ImageSanitization
    '{1915117c-a61c-54d4-6548-56cac6dbfede}' # Microsoft.Windows.Shell.AboveLockActivationManager
    '{e58f5f9c-3abb-5fc1-5ae5-dbe956bdbd33}' # Microsoft.Windows.Shell.AboveLockShellComponent
    '{b2149bc3-9dfd-5866-92a7-b556b3a6aed0}' # Microsoft.Windows.Shell.DefaultLockApp
    '{9ca921e3-25a4-5d34-39da-a59bd8bdf7a2}' # Microsoft.Windows.Shell.LockAppBroker
    '{b93d4107-dc22-5d11-c2e1-afba7a88d694}' # Microsoft.Windows.Shell.Tracing.LockAppBroker
    '{96319132-2f52-5969-f14c-0d0a171b357a}' # Microsoft.Windows.Shell.LockFrameworkUAP
    '{4191edaf-80c5-5ae3-49aa-325bd25cab2e}' # Microsoft.Windows.ComposableShell.Components.LockScreenHost.LockScreenShow
    '{355d4f62-3d5b-5372-213f-6d9d804c75df}' # Microsoft.Windows.AssignedAccess.MdmAlert
    '{94097d3d-2a5a-5b8a-cdbd-194dd2e51a00}' # Microsoft.Windows.AssignedAccess
    '{8530DB6E-51C0-43D6-9D02-A8C2088526CD}' # Microsoft-Windows-AssignedAccess
    '{F2311B48-32BE-4902-A22A-7240371DBB2C}' # Microsoft-Windows-AssignedAccessBroker
    '{5e85651d-3ff2-4733-b0a2-e83dfa96d757}' # UserMgrSvcTraceLoggingProvider
    '{077b8c4a-e425-578d-f1ac-6fdf1220ff68}' # Microsoft.Windows.Security.TokenBroker
    '{7acf487e-104b-533e-f68a-a7e9b0431edb}' # Microsoft.Windows.Security.TokenBroker.BrowserSSO
    '{BB86E31D-F955-40F3-9E68-AD0B49E73C27}' # Microsoft-Windows-User-UserManager-Events
    '{076a2c5c-40e9-5a75-73b0-8d7697c282b2}' # Microsoft.Windows.Security.Vault.RoamingSecurity
    '{a15c1ac4-a508-59ae-3158-275f96f30cb8}' # Microsoft.Windows.Security.Vault.Roaming
    '{98177d7f-7d3a-51ef-2d41-2414bb2c0bdb}' # Microsoft.Windows.Security.Wininit
    '{1ef1b3bd-ba20-5fd6-68c1-beb652b5d0c2}' # Microsoft.Windows.Shell.LockScreenContent
    '{b45275fa-3b9c-40f2-aaad-10060f77f0c0}' # Microsoft.Windows.Shell.CloudExperienceHost.DatVPrep
    '{F1C13488-91AC-4350-94DE-5F060589C584}' # Microsoft.Windows.Shell.LockScreenBoost
    '{3D14CA27-6EB2-4789-9B52-33EC88ECF5B0}' # Microsoft.Windows.Shell.LockScreenData
    '{1f44367c-cd89-5c01-ad03-bf60b9588564}' # Microsoft.Windows.LockAppBroker
    '{be69781c-b63b-41a1-8e24-a4fc7b3fc498}' # Microsoft-Windows-Sens
    '{A0CA1D82-539D-4FB0-944B-1620C6E86231}' # Microsoft-Windows-Sens/Debug
    '{2D710779-B24B-4ADB-81EF-CD6DED5A9B2A}' # Microsoft.Windows.Shell.LockScreenController
    '{75816B5C-ECD1-4DBC-B38A-47A9646E60BE}' # Microsoft.Windows.Shell.LockScreenExperienceManager
    '{68767976-7ddc-57d7-4318-9a6db4625165}' # Microsoft.Windows.Shell.WelcomeScreen
)

#---  AUTH PROVIDERS ---#
$AuthProviders = @(
    '{6165F3E2-AE38-45D4-9B23-6B4818758BD9}' # TSPkg
    '{37D2C3CD-C5D4-4587-8531-4696C44244C8}' # schannel(schannel.dll)
    '{5BBB6C18-AA45-49B1-A15F-085F7ED0AA90}' # NTLM
    '{6B510852-3583-4E2D-AFFE-A67F9F223438}' # Kerberos
    '{BBA3ADD2-C229-4CDB-AE2B-57EB6966B0C4}' # Kerberos Client
    '{CC85922F-DB41-11D2-9244-006008269001}' # LSA
    '{F33959B4-DBEC-11D2-895B-00C04F79AB69}' # NetLogon
    '{C5D1EB66-79E9-47C3-A578-A6F25DA14D49}' # SpapiWBLog
    '{5bbca4a8-b209-48dc-a8c7-b23d3e5216fb}' # Microsoft-Windows-CAPI2(crypt32.dll)
    '{1f678132-5938-4686-9fdc-c8ff68f15c85}' # Schannel(lsasrv.dll)
    '{91CC1150-71AA-47E2-AE18-C96E61736B6F}' # Microsoft-Windows-Schannel-Events(Manifest)
    '{4C88AF3D-5D47-458A-8624-515C122B7188}' # Microsoft.Windows.OneCoreUap.Shell.Auth.CredUX
    '{4b8b1947-ae4d-54e2-826a-1aee78ef05b2}' # Microsoft.Windows.WinBioDataModel
    '{a55d5a23-1a5b-580a-2be5-d7188f43fae1}' # Microsoft.Windows.Shell.BioEnrollment
    '{DC3B5BCF-BF7B-42CE-803C-71AF48F0F546}' # Microsoft.Windows.CredProviders.PasswordProvider
    '{fb3cd94d-95ef-5a73-b35c-6c78451095ef}' # Microsoft.Windows.CredProvDataModel
    '{5a4dad98-5dce-5efb-a9b2-54e8de8af594}' # Microsoft.Windows.Shell.Auth.LocalServiceCredUIBroker
    '{3bb1472f-46dc-5a12-4916-25706f703352}' # Microsoft.Windows.CredDialogBroker
    '{f2018623-63ac-5837-7cfb-f67ec5c39961}' # Microsoft.Windows.Shell.CredDialogHost
    '{d30325be-5b5e-508c-d76a-2d5e5fe60a5c}' # Microsoft.Windows.CredentialEnrollmentManager
    '{f245121c-b6d1-5f8a-ea55-498504b7379e}' # Microsoft.Windows.DeviceLockSettings
    '{350b80a3-32c3-47b3-9e58-32e5a48ce66f}' # Microsoft.Windows.SuggestedUsersDataModel
    '{c11d96bf-1615-4d64-ada3-5803cdbac698}' # Microsoft.Windows.Shell.Auth.CredUI
    '{1D86A602-D4EE-48FA-94B1-59EE686D07D0}' # MicrosoftWindowsShellAuthCredUI
    '{04063501-1c04-5e01-5e72-4e2400121550}' # Microsoft-Windows-UserTrustedSignals-CredProv
    '{5512152d-88f8-5f1e-ed9f-6412175a39dc}' # Microsoft.Windows.UI.PicturePassword
    '{462a094c-fc89-4378-b250-de552c6872fd}' # Microsoft.Windows.Shell.Auth.CredUIBroker
    '{24532ca4-409f-5d6c-3ded-e11946573f56}' # Microsoft.Windows.CredUXController
    '{4f7c073a-65bf-5045-7651-cc53bb272db5}' # Microsoft.Windows.LogonController
    '{9a7b2945-e29a-5477-e857-794ae72a85d9}' # Microsoft.Windows.AuthExt
    '{f0c781fb-3451-566e-121c-9020159a5306}' # Microsoft.Windows.SharedPC.AccountManager
    '{80B3FF7A-BAB0-4ED1-958C-E89A6D5557B3}' # Microsoft.Windows.Shell.SystemSettings.WorkAccessHandlers
    '{7fdd167c-79e5-4403-8c84-b7c0bb9923a1}' # VaultGlobalDebugTraceControlGuid
)
 
#---  LSA PROVIDERS ---#
$LSAProviders = @(
    '{D0B639E0-E650-4D1D-8F39-1580ADE72784}' # LsaTraceControlGuid
    '{DAA76F6A-2D11-4399-A646-1D62B7380F15}' # LsaAuditTraceControlGuid
    '{169EC169-5B77-4A3E-9DB6-441799D5CACB}' # LsaDsTraceControlGuid
)

#---  CRYPT PROVIDERS ---#
$CRYPTProviders = @(
    '{5BBCA4A8-B209-48DC-A8C7-B23D3E5216FB}' # Microsoft-Windows-CAPI2
    '{80DF111F-178D-44FB-AFB4-5D179DE9D4EC}' # WPP_CRYPT32_CONTROL_GUID
    '{EAC19293-76ED-48C3-97D3-70D75DA61438}' # WPP_CRYPTTPMEKSVC_CONTROL_GUID
    '{9B52E09F-0C58-4eaf-877F-70F9B54A7946}' # WPP_CHAT_CONTROL_GUID
    '{A74EFE00-14BE-4ef9-9DA9-1484D5473301}' # CNGTraceControlGuid
    '{A74EFE00-14BE-4ef9-9DA9-1484D5473302}' # CNGTraceControlGuid
    '{A74EFE00-14BE-4ef9-9DA9-1484D5473303}' # CNGTraceControlGuid
    '{A74EFE00-14BE-4ef9-9DA9-1484D5473304}' # CNGTraceControlGuid
    '{EA3F84FC-03BB-540e-B6AA-9664F81A31FB}' # DPAPIGlobalDebugTraceControlGuid
    '{9D2A53B2-1411-5C1C-D88C-F2BF057645BB}' # Microsoft.Windows.Security.Dpapi
    '{89FE8F40-CDCE-464E-8217-15EF97D4C7C3}' # Microsoft-Windows-Crypto-DPAPI
)

#---  WMI PROVIDERS ---#
$WMIProviders = @(
    '{1FF6B227-2CA7-40F9-9A66-980EADAA602E}' # WMI_Tracing_Guid
    '{8E6B6962-AB54-4335-8229-3255B919DD0E}' # WMI_Tracing_Client_Operations_Info_Guid
    '{1418EF04-B0B4-4623-BF7E-D74AB47BBDAA}' # Microsoft-Windows-WMI-Activity
    '{2CF953C0-8DF7-48E1-99B9-6816A2FBDC9F}' # Microsoft-Windows-WMIAdapter
    '{1EDEEE53-0AFE-4609-B846-D8C0B2075B1F}' # Microsoft-Windows-WMI
)

#---  NET PROVIDERS ---#
$NetProviders = @(
    '{E53C6823-7BB8-44BB-90DC-3F86090D48A6}' # Microsoft-Windows-Winsock-AFD(Winsock)
    '{EB004A05-9B1A-11D4-9123-0050047759BC}' # NetIO
    '{2F07E2EE-15DB-40F1-90EF-9D7BA282188A}' # Microsoft-Windows-TCPIP
    '{B40AEF77-892A-46F9-9109-438E399BB894}' # AFD Trace
    '{DD7A21E6-A651-46D4-B7C2-66543067B869}' # NDISTraceGuid
    '{A781472C-CFC9-42CB-BCEA-A00B916AD1BE}' # NDISIMPLAT
    '{B1809D25-B84D-4E40-8D1B-C9978D8946AB}' # LBFOProviderGUID
    '{9B5CB64B-6166-4369-98CA-986AE578E216}' # NdisImPlatformWPPGuid
)

#---  UE-V PROVIDERS ---#
$UEVProviders = @(
    "{1ED6976A-4171-4764-B415-7EA08BC46C51}" # Microsoft-User Experience Virtualization-App Agent
    "{21D79DB0-8E03-41CD-9589-F3EF7001A92A}" # Microsoft-User Experience Virtualization-IPC
    "{57003E21-269B-4BDC-8434-B3BF8D57D2D5}" # Microsoft-User Experience Virtualization-SQM Uploader
    "{61BC445E-7A8D-420E-AB36-9C7143881B98}" # Microsoft-User Experience Virtualization-Admin
    "{e4dda0af-d7b4-5d40-4174-4d0be05ae338}" # Microsoft.Windows.AppMan.UEV
)

#---  COM/DCOM/WinRT/RPC PROVIDERS ---#
$COMProviders = @(
    '{9474a749-a98d-4f52-9f45-5b20247e4f01}' # DCOMSCM
    '{bda92ae8-9f11-4d49-ba1d-a4c2abca692e}' # OLE32(combase.dll)
    '{d4263c98-310c-4d97-ba39-b55354f08584}' # Microsoft-Windows-COM(advapi32.dll)
    '{0f177893-4a9c-4709-b921-f432d67f43d5}' # Microsoft-Windows-Complus(comres.dll)
    '{1B562E86-B7AA-4131-BADC-B6F3A001407E}' # Microsoft-Windows-DistributedCOM(combase.dll)
    '{B46FA1AD-B22D-4362-B072-9F5BA07B046D}' # COMSVCS(COM+)
    '{A0C4702B-51F7-4ea9-9C74-E39952C694B8}' # COMADMIN(COM+)
    '{1AFF6089-E863-4D36-BDFD-3581F07440BE}' # CombaseTraceLoggingProvider 
    '{6AD52B32-D609-4BE9-AE07-CE8DAE937E39}' # Microsoft-Windows-RPC(rpcrt4.dll)
    '{F4AED7C7-A898-4627-B053-44A7CAA12FCD}' # Microsoft-Windows-RPC-Events(rpcrt4.dll)
    '{d8975f88-7ddb-4ed0-91bf-3adf48c48e0c}' # Microsoft-Windows-RPCSS(RpcEpMap.dll)
    '{097d1686-4038-46be-b551-10fda0387165}' # CLBCATQ
    '{A86F8471-C31D-4FBC-A035-665D06047B03}' # Microsoft-Windows-WinRT-Error
    '{bf406804-6afa-46e7-8a48-6c357e1d6d61}' # Microsoft-Windows-COMRuntime
    '{7913ac64-a5cd-40cd-b096-4e8c4028eaab}' # Microsoft-Windows-WinTypes-Perf
    '{f0558438-f56a-5987-47da-040ca757ef05}' # Microsoft.Windows.WinRtClassActivation
    '{53201895-60E8-4fb0-9643-3F80762D658F}' # COM+ Services
    '{272A979B-34B5-48EC-94F5-7225A59C85A0}' # Microsoft-Windows-RPC-Proxy-LBS
    '{879b2576-39d1-4c0f-80a4-cc086e02548c}' # Microsoft-Windows-RPC-Proxy
    '{536caa1f-798d-4cdb-a987-05f79a9f457e}' # Microsoft-Windows-RPC-LBS
)

#---  Appx + ShellExperienceHost PROVIDERS ---#
$AppxProviders = @(
    '{BA44067A-3C4B-459C-A8F6-18F0D3CF0870}' # AppXDeployment WPP tracing
    '{8127F6D4-59F9-4abf-8952-3E3A02073D5F}' # Microsoft-Windows-AppXDeployment
    '{3F471139-ACB7-4A01-B7A7-FF5DA4BA2D43}' # Microsoft-Windows-AppXDeployment-Server
    '{fe762fb1-341a-4dd4-b399-be1868b3d918}' # Microsoft.Windows.AppXDeploymentServer
    '{BA723D81-0D0C-4F1E-80C8-54740F508DDF}' # Microsoft-Windows-AppxPackagingOM
    '{f0be35f8-237b-4814-86b5-ade51192e503}' # Microsoft-Windows-AppReadiness
    '{C567E5D7-A908-49C0-8C2C-A8DC3E8F0CF6}' # Microsoft.Windows.ARS.Tiles
    '{594bf743-ce2e-48ee-83ee-3d50a0add692}' # Microsoft.Windows.AppModel.TileDataModel
    '{3d6120a6-0986-51c4-213a-e2975903051d}' # Microsoft-Windows-Shell-Launcher
    '{39ddcb8d-ef82-5c84-89ca-09580bf0a947}' # Microsoft-Windows-Shell-AppResolver
    '{F84AA759-31D3-59BF-2C89-3748CF17FD7E}' # Microsoft-Windows-Desktop-Shell-Windowing
    '{3C42000F-CC27-48C3-A005-48F6E38B131F}' # Microsoft-WindowsPhone-AppPlatProvider
    '{15322370-3694-59f5-f979-0c7a918b81da}' # Microsoft.Windows.Desktop.Shell.ViewManagerInterop
    '{D75DF9F1-5F3D-49D0-9D15-2A55BD1C012E}' # ViewManagerInterop
    '{EF00584A-2655-462C-BC24-E7DE630E7FBF}' # Microsoft.Windows.AppLifeCycle
    '{58E68FB9-538C-47FA-8CEC-BC112DC6264A}' # EventProvider_IAM
    '{5C6E364D-3A8F-41D4-B7BB-2B03432CB665}' # VIEWMGRLIB(WPP)
    '{9C6FC32A-E17A-11DF-B1C4-4EBADFD72085}' # PLM
    '{29CFB5C5-E518-4960-A985-E18E570F935B}' # ACTIVATIONLIB(WPP)
    '{cf7f94b3-08dc-5257-422f-497d7dc86ab3}' # ActivationManager
    '{F1EF270A-0D32-4352-BA52-DBAB41E1D859}' # Microsoft-Windows-AppModel-Runtime
    '{BFF15E13-81BF-45EE-8B16-7CFEAD00DA86}' # Microsoft-Windows-AppModel-State
    '{41B5F6E6-F53C-4645-A991-135C2011C074}' # Microsoft.Windows.AppModel.StateManagerTelemetry
    '{5B5AB841-7D2E-4A95-BB4F-095CDF66D8F0}' # Microsoft-Windows-Roaming
    '{EB65A492-86C0-406A-BACE-9912D595BD69}' # Microsoft-Windows-AppModel-Exec
    '{315a8872-923e-4ea2-9889-33cd4754bf64}' # Microsoft-Windows-Immersive-Shell
    '{5F0E257F-C224-43E5-9555-2ADCB8540A58}' # Microsoft-Windows-Immersive-Shell-API
    '{8360D517-2805-4654-AA04-E9985B4433B4}' # Microsoft-Windows-AppModel-CoreApplication
    '{35D4A1FA-4036-40DC-A907-E330F3104E24}' # Microsoft-Windows-Desktop-ApplicationManager
    '{076A5FE9-E0F4-43DC-B246-9EA382B5C69F}' # Microsoft.Windows.Desktop.Shell.ViewManagement
    '{8BFE6B98-510E-478D-B868-142CD4DEDC1A}' # Windows.Internal.Shell.ModalExperience
    '{fa386406-8e25-47f7-a03f-413635a55dc0}' # TwinUITraceLoggingProvider
    '{c17f56cb-764e-5d2d-3b4e-0711ad368aaf}' # Microsoft.Windows.Shell.ApplicationHost
    '{4fc2cbef-b755-5b53-94db-8d816ca8c9cd}' # Microsoft.Windows.Shell.WindowMessageService
    '{072665fb-8953-5a85-931d-d06aeab3d109}' # Microsoft.Windows.ProcessLifetimeManager
    '{678e492b-5de1-50c5-7219-ae4aa7d6a141}' # Microsoft-Windows-Desktop-ApplicationFrame
    '{f6a774e5-2fc7-5151-6220-e514f1f387b6}' # Microsoft.Windows.HostActivityManager
    '{D2440861-BF3E-4F20-9FDC-E94E88DBE1F6}' # BiCommonTracingGuid(WPP)
    '{e6835967-e0d2-41fb-bcec-58387404e25a}' # Microsoft-Windows-BrokerInfrastructure
    '{63b6c2d2-0440-44de-a674-aa51a251b123}' # Microsoft.Windows.BrokerInfrastructure
    '{1941f2b9-0939-5d15-d529-cd333c8fed83}' # Microsoft.Windows.BackgroundManager
    '{d82215e3-bddf-54fa-895b-685099453b1c}' # Microsoft.Windows.BackgroundActivityModerator
    '{4a743cbb-3286-435c-a674-b428328940e4}' # PsmTrace(WPP)
    '{d49918cf-9489-4bf1-9d7b-014d864cf71f}' # Microsoft-Windows-PSM-Legacy(ProcessStateManager)
    '{0001376b-930d-50cd-2b29-491ca938cd54}' # Microsoft-Windows-PSM
    '{4180c4f7-e238-5519-338f-ec214f0b49aa}' # Microsoft-Windows-ResourceManager
    '{e8109b99-3a2c-4961-aa83-d1a7a148ada8}' # BrokerCommon(WPP)
    '{369f0950-bf83-53a7-b3f0-771a8926329d}' # Microsoft-Windows-Shell-ServiceHostBuilder
    '{3B3877A1-AE3B-54F1-0101-1E2424F6FCBB}' # SIHost
    '{770CA594-B467-4811-B355-28F5E5706987}' # Microsoft-Windows-ApplicationResourceManagementSystem
    '{a0b7550f-4e9a-4f03-ad41-b8042d06a2f7}' # Microsoft-Windows-CoreUIComponents
    '{89592015-D996-4636-8F61-066B5D4DD739}' # Microsoft.Windows.StateRepository
    '{1ded4f74-5def-425d-ae55-4fd4e9bbe0a7}' # Microsoft.Windows.StateRepository.Common
    '{a89336e8-e6cf-485c-9c6a-ddb6614f278a}' # Microsoft.Windows.StateRepository.Client
    '{312326fa-036d-4888-bc77-c3de2ff9ae06}' # Microsoft.Windows.StateRepository.Broker
    '{551ff9b3-0b7e-4408-b008-0068c8da2ff1}' # Microsoft.Windows.StateRepository.Service
    '{7237c668-b9a2-4fbd-9987-87d4502b9e00}' # Microsoft.Windows.StateRepository.Tools
    '{80a49605-87cb-4480-be97-d6ccb3dde5f2}' # Microsoft.Windows.StateRepository.Upgrade
    '{bf4c9654-66d1-5720-7b51-d2ae226735ea}' # Microsoft.Windows.ErrorHandling.Fallback
    '{CC79CF77-70D9-4082-9B52-23F3A3E92FE4}' # Microsoft.Windows.WindowsErrorReporting
    '{1AFF6089-E863-4D36-BDFD-3581F07440BE}' # CombaseTraceLoggingProvider
    '{f0558438-f56a-5987-47da-040ca757ef05}' # Microsoft.Windows.WinRtClassActivation
    '{5526aed1-f6e5-5896-cbf0-27d9f59b6be7}' # Microsoft.Windows.ApplicationModel.DesktopAppx
    '{fe0ab4b4-19b6-485b-89bb-60fd931fdd56}' # Microsoft.Windows.AppxPackaging
    '{19c13211-dec8-42d5-885a-c4cfa82ea1ed}' # Microsoft.Windows.Mrt.Runtime
    '{932a397d-97ed-50f9-29ab-051457f7af3e}' # Microsoft.Windows.Desktop.LanguageBCP47
    '{aa1b41d3-d193-4660-9b47-dd701ba55841}' # Microsoft-Windows-AppXDeploymentFallback
    '{BB86E31D-F955-40F3-9E68-AD0B49E73C27}' # Microsoft-Windows-User-UserManager-Events
    '{8CCCA27D-F1D8-4DDA-B5DD-339AEE937731}' # Microsoft.Windows.Compatibility.Apphelp
    '{b89fa39d-0d71-41c6-ba55-effb40eb2098}' # Microsoft.Windows.AppXDeploymentClient
    '{d9e5f8fb-06b1-4796-8fa8-abb07f4fc662}' # Microsoft.Windows.AppXDeploymentExtensions
    '{2f29dca8-fbb3-4944-8953-2d390f0fe746}' # DEPLOYMENT_WPP_GUID
    '{4dab1c21-6842-4376-b7aa-6629aa5e0d2c}' # Microsoft.Windows.AppXAllUserStore
    '{AF9FB9DF-E373-4653-84CE-01D8857E79FD}' # Microsoft.Windows.AppxMigrationPlugin
    '{8FD4B82B-602F-4470-8577-CBB56F702EBF}' # Microsoft.Windows.AppXDeploymentClient.WPP
)

$StartMenuProviders = @(
    '{a5934a92-d47c-55c9-7a3d-4f9acb7f44fe}' # Microsoft.Windows.Shell.StartMenu.Frame(Until RS2)
    '{d3e36643-28fd-5ccd-99b7-3b13c721ee51}' # Microsoft.Windows.Shell.StartMenu.Experience
    '{2ca51213-29c5-564f-fd60-355148e8b47f}' # Microsoft.Windows.Shell.SingleViewExperience
    '{53E167D9-E368-4150-9563-4ED25700CCC7}' # Microsoft.Windows.Shell.ExperienceHost
    '{66FEB609-F4B6-4224-BF13-121F8A4829B4}' # Microsoft.Windows.Start.SharedStartModel.Cache
    '{45D87330-FFEC-4A95-9F07-206A4452555D}' # Microsoft.Windows.Start.ImageQueueManager
    '{e7137ec0-0e64-4c48-a590-5b62661d3abc}' # Microsoft.Windows.ShellCore.SharedVerbProvider
    '{65cacb72-8567-457a-bc48-e16b67fb3e27}' # Microsoft.Windows.ShellCore.StartLayoutInitialization
    '{8d43f18f-af82-450a-bfb7-d6f1b53570ba}' # Microsoft.Windows.ShellCore.SharedModel
    '{36F1D421-D446-43AE-8AA7-A4F85CB176D3}' # Microsoft.Windows.UI.Shell.StartUI.WinRTHelpers
    '{9BB1A5A5-ABD6-4F8E-9507-12CC2B314896}' # Microsoft.Windows.Shell.TileDataLayerItemWrappers
    '{a331d81d-2f6f-50de-2461-a5530d0465d7}' # Microsoft.Windows.Shell.DataStoreCache
    '{6cfc5fc0-7e30-51e0-898b-57ac43152695}' # Microsoft.Windows.Shell.DataStoreTransformers
    '{2d069757-4018-5cf0-e4a2-bf70a1a0183c}' # Microsoft.Windows.Shell.MRTTransformer
    '{F2CDC8A0-AF2C-450F-9859-3251CCE0D234}' # WindowsInternal.Shell.UnifiedTile
    '{97CA8142-10B1-4BAA-9FBB-70A7D11231C3}' # Microsoft-Windows-ShellCommon-StartLayoutPopulation
    '{98CCAAD9-6464-48D7-9A66-C13718226668}' # Microsoft.Windows.AppModel.Tiles
    '{1a554939-2d19-5b10-ceda-ee4dd6910d59}' # Microsoft.Windows.ShellCommon.StartLayout
    '{8cba0f81-8ad7-5395-2125-5703822c822a}' # Microsoft.Windows.ContentDeliveryManager
    '{4690f625-1ceb-402e-acef-db8f00f3a446}' # Microsoft.Windows.Shell.TileControl
    '{c8416d9b-12d3-41f8-9a4c-c8d7033f4d30}' # Microsoft-Windows-Shell-Launcher-Curation
    '{c6ba71ae-658c-5a9b-94f5-b2026290198a}' # Microsoft.Windows.Desktop.Shell.QuickActions
    '{7B434BC1-8EFF-41A3-87E9-5D8AF3099784}' # Microsoft.Windows.Shell.KeyboardHosting.ShellKeyboardManager
    '{cbc427d6-f93e-5bcf-3137-d22fe2305d1f}' # Microsoft.Windows.Shell.ClockCalendar
    '{F84AA759-31D3-59BF-2C89-3748CF17FD7E}' # Microsoft-Windows-Desktop-Shell-Windowing
    '{BAA05370-7451-48D2-8F38-778380946CE9}' # Microsoft.Windows.SharedStartModel.NotificationQueueManager
    '{462B9C75-E5D7-4E0D-8AA1-294D175566BB}' # Microsoft-Windows-Shell-ActionCenter
    '{2c00a440-76de-4fe3-856f-00557535be83}' # Microsoft.Windows.Shell.ControlCenter
)

$CortanaProviders = @(
    '{E34441D9-5BCF-4958-B787-3BF824F362D7}' # Microsoft.Windows.Shell.CortanaSearch
    '{0FE37773-6C29-5233-0DD0-50E974F24203}' # Microsoft-Windows-Shell-CortanaDss
    '{2AF7F6B8-E17E-52A1-F715-FA43D637798A}' # Microsoft-Windows-Shell-CortanaHistoryUploader
    '{66f03b1f-1aec-5184-d349-a81761122be4}' # Microsoft.Windows.Shell.CortanaHome
    '{c0d0fe1d-53e4-5b98-71d7-c51fe5c10003}' # Microsoft-Windows-Shell-CortanaNL
    '{b9ca7b47-8bad-5693-9481-028527614d30}' # Microsoft.Windows.Shell.CortanaNotebook
    '{8E6931A7-4C49-5FB7-A500-65B951D7652F}' # Microsoft.Windows.Shell.CortanaPersonality
    '{5B7144A2-F0F6-4F99-A66D-FB2477E4CEE6}' # Microsoft.Windows.Shell.CortanaPlaces
    '{0E6F34B3-0637-55AB-F0BB-8B8FA83EDA04}' # Microsoft-Windows-Shell-CortanaProactive
    '{94041064-dbc2-4668-a729-b7b82747a0c2}' # Microsoft.Windows.Shell.CortanaReminders
    '{9B3FE00F-DAC4-4437-A77B-DE27B87046D4}' # Microsoft.Windows.Shell.CortanaSearch
    '{d8caafb9-7211-5dc8-7c1f-8027d50640ec}' # Microsoft.Windows.Shell.CortanaSignals
    '{a1f18f1f-bf5c-54d1-214d-8e1d3fe8427f}' # Microsoft-Windows-Shell-CortanaValidation
    '{2AEDC292-3FA5-472A-8EB4-33978D449853}' # Microsoft.Windows.Shell.CortanaSync
    '{92F43F71-2741-40B2-A566-70EEBCF2D181}' # Microsoft-Windows-Shell-CortanaValidation
    '{1aea69ee-2cfc-5eb1-f1f6-18f99a528b11}' # Microsoft-Windows-Shell-Cortana-IntentExtraction
    '{88BCD62D-F7AE-45B7-B578-4BF2B8AB867B}' # Microsoft-Windows-Shell-CortanaTrace
    '{ff32ada1-5a4b-583c-889e-a3c027b201f5}' # Microsoft.Web.Platform
    '{FC7BA620-EB50-483D-97A0-72D8268A14B5}' # Microsoft.Web.Platform.Chakra
    '{F65B3890-19BA-486E-A5F6-0378B356E0CE}' # Microsoft.Windows.UserSpeechPreferences
    '{adbb52ad-4e74-56c1-ecbe-cc4539ac4b2d}' # Microsoft.Windows.SpeechPlatform.Settings
    # '{57277741-3638-4A4B-BDBA-0AC6E45DA56C}' # Microsoft-JScript(chakra.dll)  // Too many logs will be recorded.
)

$WinRMProviders = @(
    '{A7975C8F-AC13-49F1-87DA-5A984A4AB417}' # Microsoft-Windows-WinRM
    '{04C6E16D-B99F-4A3A-9B3E-B8325BBC781E}' # WinRM(WPP)
    '{72B18662-744E-4A68-B816-8D562289A850}' # Windows HTTP Services
    '{7D44233D-3055-4B9C-BA64-0D47CA40A232}' # Microsoft-Windows-WinHttp
    '{B3A7698A-0C45-44DA-B73D-E181C9B5C8E6}' # WinHttp(WPP)
    '{4E749B6A-667D-4C72-80EF-373EE3246B08}' # WinInet(WPP)
    '{DD5EF90A-6398-47A4-AD34-4DCECDEF795F}' # Microsoft-Windows-HttpService
    '{20F61733-57F1-4127-9F48-4AB7A9308AE2}' # UxWppGuid(HTTP.sys - WPP)
    '{C42A2738-2333-40A5-A32F-6ACC36449DCC}' # Microsoft-Windows-HttpLog
    '{DD5EF90A-6398-47A4-AD34-4DCECDEF795F}' # Microsoft-Windows-HttpService
    '{7B6BC78C-898B-4170-BBF8-1A469EA43FC5}' # Microsoft-Windows-HttpEvent
    '{F5344219-87A4-4399-B14A-E59CD118ABB8}' # Microsoft-Windows-Http-SQM-Provider
    '{c0a36be8-a515-4cfa-b2b6-2676366efff7}' # WinRSMgr
    '{f1cab2c0-8beb-4fa2-90e1-8f17e0acdd5d}' # WinRSexe
    '{03992646-3dfe-4477-80e3-85936ace7abb}' # WinRSCmd
    '{651d672b-e11f-41b7-add3-c2f6a4023672}' # IPMIPrv
    '{D5C6A3E9-FA9C-434e-9653-165B4FC869E4}' # IpmiDrv
    '{6e1b64d7-d3be-4651-90fb-3583af89d7f1}' # WSManProvHost
    '{D5C6A3E9-FA9C-434e-9653-165B4FC869E4}' # IpmiDrv
    '{6FCDF39A-EF67-483D-A661-76D715C6B008}' # Event Forwarding
)

$DWMProviders = @(
    '{d29d56ea-4867-4221-b02e-cfd998834075}' # Microsoft-Windows-Dwm-Dwm(dwm.exe)
    '{9e9bba3c-2e38-40cb-99f4-9e8281425164}' # Microsoft-Windows-Dwm-Core
    '{292a52c4-fa27-4461-b526-54a46430bd54}' # Microsoft-Windows-Dwm-Api
    '{31f60101-3703-48ea-8143-451f8de779d2}' # Microsoft-Windows-DesktopWindowManager-Diag
    '{802ec45a-1e99-4b83-9920-87c98277ba9d}' # Microsoft-Windows-DxgKrnl
    '{93112de2-0aa3-4ed7-91e3-4264555220c1}' # Microsoft.Windows.Dwm.DComp
    '{504665a2-31f7-4b2f-bf1b-9635312e8088}' # Microsoft.Windows.Dwm.DwmApi
    '{1bf43430-9464-4b83-b7fb-e2638876aeef}' # Microsoft.Windows.Dwm.DwmCore
    '{45ac0c12-fa92-4407-bc96-577642890490}' # Microsoft.Windows.Dwm.DwmInit
    '{707d4382-a144-4d0a-827c-3f4422b5cf1f}' # Microsoft.Windows.Dwm.GhostWindow
    '{289E2456-EE16-4C81-AAF1-7414D66CA0BE}' # WindowsDwmCore
    '{c7a6e2fd-24f6-48fd-aad8-03ee14faf5ce}' # Microsoft.Windows.Dwm.WindowFrame
    '{11a377e3-be1e-4ee7-abda-81c6eda62e71}' # DwmAltTab
    '{25bd019c-3858-4ea4-a7b3-55b9ec8977e5}' # DwmRedir
    '{57e0b31d-de8c-4181-bcd1-f70e880b49fc}' # Microsoft-Windows-Dwm-Redir
    '{8c416c79-d49b-4f01-a467-e56d3aa8234c}' # DwmWin32kWin8
    '{8c9dd1ad-e6e5-4b07-b455-684a9d879900}' # Microsoft-Windows-Dwm-Core-Win7
    '{8cc44e31-7f28-4f45-9938-4810ff517464}' # DwmScheduler
    '{92ae46d7-6d9c-4727-9ed5-e49af9c24cbf}' # Microsoft-Windows-Dwm-Api-Win7
    '{98583af0-fc93-4e71-96d5-9f8da716c6b8}' # Microsoft-Windows-Dwm-Udwm
    '{bc2eeeec-b77a-4a52-b6a4-dffb1b1370cb}' # Microsoft-Windows-Dwm-Dwm
    '{e7ef96be-969f-414f-97d7-3ddb7b558ccc}' # DwmWin32k
    '{ed56cd5c-617b-49a5-9b80-eca3e02414bd}' # Dw
    '{72AB269D-8B68-4A17-B599-FCB1226A0319}' # Microsoft_Windows_Dwm_Udwm_Provider
    '{0C24D94B-8305-4D60-9765-5AFFD5462872}' # Microsoft.Windows.Udwm
    '{1a289bed-9134-4b49-9c10-4f98675cad08}' # Microsoft.Windows.Dwm.DwmRedir
)

$EventLogProviders = @(
    '{FC65DDD8-D6EF-4962-83D5-6E5CFE9CE148}' # Microsoft-Windows-Eventlog
    '{B0CA1D82-539D-4FB0-944B-1620C6E86231}' # WMI EventLogTrace
    '{565BBECA-5B04-49BB-81C6-3E21527FCC8A}' # Microsoft-Windows-Eventlog-ForwardPlugin
    '{35AC6CE8-6104-411D-976C-877F183D2D32}' # Microsoft-Windows-EventLog-WMIProvider
    '{899DAACE-4868-4295-AFCD-9EB8FB497561}' # Microsoft-Windows-EventSystem
)

$ShellProviders = @(
    # Shell
    '{30336ed4-e327-447c-9de0-51b652c86108}' # Microsoft-Windows-Shell-Core(shsvcs.dll) => Too many logs will be logged.
    '{46FCB024-5EA4-446C-B6C4-C7A4EE784198}' # ShellTraceProvider
    '{687AE510-1C00-4108-A958-ACFA78ECCCD5}' # Microsoft.Windows.Shell.AccountsControl
    '{c6fe0c47-96ef-5d29-c249-c3cecc6f9930}' # Microsoft.Windows.Shell.SyncPartnership.Api
    '{DC3B5BCF-BF7B-42CE-803C-71AF48F0F546}' # Microsoft.Windows.CredProviders.PasswordProvider
    '{d0034f5e-3686-5a74-dc48-5a22dd4f3d5b}' # Microsoft.Windows.Shell.CloudExperienceHost
    '{ff91e668-f7be-577e-14a3-44d801cccfa0}' # Microsoft.Windows.Shell.CloudExperienceHostCore
    '{f385e1a5-0346-5411-11a2-e8c8afe3b6ca}' # Microsoft.Windows.Desktop.Shell.CloudExperienceHostSpeech
    '{e305fb0f-da8e-52b5-a918-7a4f17a2531a}' # Microsoft.Windows.Shell.DefaultAssoc
    '{ee97cdc4-b095-5c70-6e37-a541eb74c2b5}' # Microsoft.Windows.AppLifeCycle.UI
    '{df8dab3f-b1c9-58d3-2ea1-4c08592bb71b}' # Microsoft.Windows.Shell.Taskbar
    '{653fe5bd-e1d2-5d40-d93c-a551a97cd49a}' # Microsoft.Windows.Desktop.Shell.NotificationArea
    '{5AFB7971-45E5-4d49-AAEB-1B04D39872CF}' # Microsoft.Windows.MobilityExperience
    '{7ca6a4dd-dae5-5fb7-ec8e-4a6c648fadf9}' # Microsoft.Windows.ShellPlacements
    '{55e357f8-ef0d-5ffd-a4dd-50e3d8f707cb}' # Microsoft.Windows.Desktop.Shell.CoreApplication.CoreApplicationView
    '{5487F421-E4DE-41D4-BFF3-72A4D6584898}' # Microsoft.Windows.Shell.SystemSettings.SettingHandlersSystem
    '{79c43bcd-08ea-5914-1e38-9e3008863a0c}' # Microsoft.Windows.Settings.Accessibility
    '{571ac9d5-12fd-4438-b630-61fb26bbb0ac}' # Microsoft.Windows.Shell.SystemSettings.BatterySaver
    '{e04d85e2-56a2-5bb7-5dab-6f761366a4c2}' # Microsoft.Windows.Shell.SystemSettings.BatterySaver.Desktop
    '{d43920c8-d57d-4e58-9283-f0fddd4afdcb}' # WindowsFlightingSettings
    '{080e197d-7cc1-54a3-e889-27636425992a}' # Microsoft.Windows.Shell.ShareUXSettings
    '{DB7BD825-B56F-48c4-8196-22BC145DDB08}' # Microsoft.Windows.Shell.SystemSettings.SIUF
    '{830a1f34-7797-4e31-9b75-c82056330051}' # Microsoft.Windows.Shell.SystemSettings.StorageSense
    '{0e6f34b3-0637-55ab-f0bb-8b8fa83eda04}' # Microsoft-Windows-Shell-CortanaProactive
    '{C11543B0-3A34-4F10-B50B-4DDB76FF2C6E}' # Microsoft.Windows.Shell.ThumbnailCache
    '{382B5E24-181E-417F-A8D6-2155F749E724}' # Microsoft.Windows.ShellExecute
    # Windows.Storage.dll
    '{79172b48-631e-5d2c-9f04-1ad99f6e1046}' # Microsoft.Windows.Desktop.Shell.Shell32
    '{9399df73-403c-5d8f-70c7-25aa3184c6f3}' # Microsoft.Windows.Shell.Libraries
    '{f168d2fa-5642-58bb-361e-127980c64a1b}' # Microsoft.Windows.Shell.OpenWith
    '{59a3be04-f025-4585-acfc-34456b550813}' # Microsoft.Windows.Shell.Edp
    '{8e12dcd2-fe15-5af4-2a6a-e707d9dc7de5}' # MicrosoftWindowsFileExplorer
    '{A40B455C-253C-4311-AC6D-6E667EDCCEFC}' # CloudFileAggregateProvider
    '{32980F26-C8F5-5767-6B26-635B3FA83C61}' # FileExplorerAggregateProvider
    '{8939299F-2315-4C5C-9B91-ABB86AA0627D}' # Microsoft-Windows-KnownFolders
    '{E0142D4F-9E39-5B3B-9DEB-8B576025FF5E}' # Microsoft.Windows.CentennialActivation
    '{3889f5d8-66b1-44d9-b52c-48ca283ac5d8}' # Microsoft.Windows.DataPackage
    '{e1fa35be-5192-5b1e-f23e-e2a38f6414b9}' # Microsoft.Windows.FileExplorerPerf
    '{B87CF16B-0BF8-4492-A510-D5F59626B033}' # Microsoft.Windows.FileExplorerErrorFallback
    '{08f5d47e-67d3-4ee0-8e0c-cbd309ab5d1b}' # Microsoft.Windows.Shell.CloudFiles
    '{f85b4793-1347-5620-7572-b79d5a28da82}' # Microsoft.Windows.Shell.DataLayer
    '{4E21A072-576A-4254-838B-059D479563BA}' # Microsoft.Windows.ComposableShell.Components.ContextMenu
    '{783f30af-5514-51bc-5b99-5d33b678539b}' # Microsoft.Windows.Shell.StorageSearch
    '{E5067383-0952-468C-9399-2E963F38B097}' # Microsoft\\ThemeUI
    '{869FB599-80AA-485D-BCA7-DB18D72B7219}' # Microsoft-Windows-ThemeUI
    '{61F044AF-9104-4CA5-81EE-CB6C51BB01AB}' # Microsoft-Windows-ThemeCPL
    '{D3F64994-CCA2-4F97-8622-07D451397C09}' # MicrosoftWindowsShellUserInfo
    '{1941DE80-2226-413B-AFA4-164FD76914C1}' # Microsoft.Windows.Desktop.Shell.WindowsUIImmersive.LockScreen
    '{9dc9156d-fbd5-5780-bd80-b1fd208442d6}' # Windows.UI.Popups
    '{46668d11-2db1-5756-2a4b-98fce8b0375f}' # Microsoft.Windows.Shell.Windowing.LightDismiss
    '{f8e28969-b1df-57fa-23f6-42260c77135c}' # Microsoft.Windows.ImageSanitization
    '{239d82f3-77e1-541b-2cbc-50274c47b5f7}' # Microsoft.Windows.Shell.BridgeWindow
    '{4fc2cbef-b755-5b53-94db-8d816ca8c9cd}' # Microsoft.Windows.Shell.WindowMessageService
    '{d2ff0031-cf02-500b-5898-8af98680cedb}' # Microsoft.Windows.Shell.ProjectionManager
    '{3635a139-1289-567e-b0ef-71e7adf3adf2}' # Microsoft.Windows.Shell.PlayToReceiverManager
    '{f71512b7-5d8e-41ee-aad8-4a6aebd29d4e}' # Microsoft.Windows.Shell.InkWorkspaceHostedAppsManager
    '{50c2b532-05e6-4616-ae28-2a023fe55216}' # Microsoft.Windows.Shell.PenSignalManager
    '{69ecab7c-aa2d-5d2e-e85c-debcf6fc9016}' # Microsoft.Windows.Desktop.OverrideScaling
    '{C127316F-7E36-5489-189A-99E57A8E788D}' # Microsoft-Windows-Explorer-ThumbnailMTC
    '{8911c0ab-6f93-4513-86d5-3de7175dd720}' # Microsoft.Windows.Shell.NotesManager
    '{08194E35-5511-4C06-9008-8C2CE1FE6B52}' # Microsoft.Windows.Shell.MSAWindowManager
    '{158715e0-18df-56cb-1a2e-d29da8fb9973}' # Microsoft.Windows.Desktop.Shell.MonitorManager
    '{D81F69FC-478D-4631-AD03-44046980BBFA}' # MicrosoftWindowsTwinUISwitcher
    '{ED576CEC-4ED0-4E09-9291-67EAD252DDE2}' # Microsoft.Windows.Desktop.Shell.KeyboardOcclusionMitigation
    '{34581546-9f8e-45f4-b73c-1c0ac79f7b20}' # Microsoft.Windows.Shell.PenWorkspace.ExperienceManager
    '{2ca51213-29c5-564f-fd60-355148e8b47f}' # Microsoft.Windows.Shell.SingleViewExperience
    '{F84AA759-31D3-59BF-2C89-3748CF17FD7E}' # Microsoft-Windows-Desktop-Shell-Windowing
    '{4cd50c2c-1018-53d5-74a1-4214e0941c20}' # Microsoft.Windows.Shell.ClickNote
    '{1608b891-0406-5011-1238-3e93b292a6ef}' # Microsoft.Windows.Shell.Autoplay
    '{7B0C2561-285F-46BB-9229-09D11947AE28}' # Microsoft.Windows.Desktop.Shell.AccessibilityDock
    '{6924642c-34a3-5050-2915-053f31e18534}' # Microsoft.Windows.Shell.CoreApplicationBridge
    '{64aa695c-9c53-58ad-2fe7-9358ab788507}' # Microsoft.Windows.Shell.Desktop.Themes
    '{dc140d17-88f7-55d0-fcb1-068435d69c4b}' # Microsoft.Windows.Shell.RunDialog
    '{75d2b56f-3f9d-5b1c-0792-d243507f67ce}' # Microsoft.Windows.Shell.PostBootReminder
    '{8D07CB9D-CA74-44E4-B389-C7068A51393E}' # Microsoft.Windows.Shell.IconCache
    '{4a9fe8c1-cde0-5f0a-f472-69b949097daf}' # Microsoft.Windows.Shell.Desktop.IconLayout
    '{59a36fc6-225a-41bf-b1b4-b558a37798cd}' # Microsoft.Windows.Shell.CoCreateInstanceAsSystemTaskServer
    '{44db9cfe-6db3-4a53-be9a-3057fa778b50}' # Microsoft.Windows.Shell.FileExplorer.Banners
    '{3d4b08aa-1df6-4549-b479-cf49b47cfcd3}' # Microsoft-Windows-BackupAndRoaming-SyncHandlers
    '{6e43b858-f3d9-5db1-0070-f99259784399}' # Microsoft.Windows.Desktop.Shell.LanguageOptions
    '{2446bc6d-2a96-5948-96ba-db27816dee43}' # Microsoft.Windows.Shell.SharingWizard
    '{45896826-7c5e-5a91-763d-67db83540f1b}' # Microsoft.Windows.Desktop.Shell.FontFolder
    '{9a9d6c4e-0c84-5401-7148-5d809fa78018}' # Microsoft.Windows.Desktop.Shell.RegionOptions
    '{ed7432ee-0f83-5083-030b-39f66ba307c5}' # Microsoft.Windows.Desktop.ScreenSaver
    '{8fe8ebd4-0f51-5f91-9481-cd2cfefdf96e}' # Microsoft.Windows.Desktop.Shell.Charmap
    '{28e9d7c3-908a-5980-90cc-1581dd9d451d}' # Microsoft.Windows.Desktop.Shell.EUDCEditor
    '{6d960cb7-fb14-5ed4-95fd-4d157414ecdb}' # Microsoft.Windows.Desktop.Shell.OOBEMonitor
    '{5391f591-9ca5-5833-7c1d-ad0ddec652cd}' # Microsoft.Windows.Desktop.Shell.MachineOOBE
    '{2cfa8474-fc39-51c6-c0ac-f08e5da70d91}' # Microsoft.Windows.Shell.Desktop.FirstLogonAnim
    '{451ceb17-c9c0-596d-78a3-df866a3867fb}' # Microsoft.Windows.Desktop.DesktopShellHostExtensions
    '{b93d4107-dc22-5d11-c2e1-afba7a88d694}' # Microsoft.Windows.Shell.Tracing.LockAppBroker
    '{e58f5f9c-3abb-5fc1-5ae5-dbe956bdbd33}' # Microsoft.Windows.Shell.AboveLockShellComponent
    '{1915117c-a61c-54d4-6548-56cac6dbfede}' # Microsoft.Windows.Shell.AboveLockActivationManager
    '{b82b78d7-831a-4747-bce9-ccc6d109ecf3}' # Microsoft.Windows.Shell.Prerelease
    '{2de4263a-8b3d-5824-1c83-6182d50c5356}' # Microsoft.Windows.Shell.Desktop.LogonAnaheimPromotion
    '{F1C13488-91AC-4350-94DE-5F060589C584}' # Microsoft.Windows.Shell.LockScreenBoost
    '{a51097ad-c000-5ea3-bbd4-863addaedd23}' # Microsoft.Windows.Desktop.Shell.ImmersiveIcons
    '{ffe467f7-4f51-4061-82be-c2ed8946a961}' # Microsoft.Windows.Shell.CoCreateInstanceAsSystem
    '{8A5010B1-0DCD-5AA6-5390-B288A15AC820}' # Microsoft-Windows-LockScreen-MediaTransportControlsUI
    '{C0B1CBF9-F523-51C9-15B0-02351517DAF8}' # Microsoft-Windows-Explorer-MediaTransportControlsUI
    '{1EE8CA37-11AE-4815-800E-58D6BAE1FEF9}' # Microsoft.Windows.Shell.SystemSettings.SettingsPane
    '{1ABBDEEA-0CF0-46B1-8EC2-DAAD6F165F8F}' # Microsoft.Windows.Shell.SystemSettings.HotKeyActivation
    '{7e8b48e9-dfa1-5073-f3f2-6251909a4d9d}' # Microsoft.Windows.BackupAndRoaming.Restore
    '{58b09b7d-fd44-5a27-101d-5d2472a7bb42}' # Microsoft.Windows.Shell.PrivacyConsentLogging
    '{04d28e21-00aa-5228-cfd0-d70863aa5ce9}' # Microsoft.Windows.Shell.Desktop.LogonFramework
    '{24fd15bb-a367-42b2-9210-e39c6467bf3a}' # Microsoft.Windows.Shell.Homegroup
    '{1d6a5020-c697-53bf-0f85-ae99be728db3}' # Microsoft.Windows.Shell.Display
    '{6b2cb30d-2176-5de5-c0f5-65aedfbb1b1f}' # Microsoft-Windows-Desktop-Shell-Personalization
    '{15584c9b-7d86-5fe0-a123-4a0f438a82c0}' # Microsoft.Windows.Shell.ServiceProvider
    '{354F4275-62B7-51B3-44C3-A1CB50CA4BC5}' # Microsoft-Windows-WebServicesWizard-OPW
    '{9cd954e1-c547-52c4-50c7-1a3f5df69321}' # Microsoft.Windows.Shell.SystemTray
    '{9d9f8d9d-81f1-4173-a667-4c54a4831dba}' # Microsoft.Windows.Shell.NetPlWiz
    '{397fe846-4109-5a9b-f2eb-c1d3b72630fd}' # Microsoft.Windows.Desktop.TextInput.InputSwitch
    '{feabe86d-d7a7-5e6d-9665-92819bc73768}' # Microsoft.Windows.Desktop.Shell.TimeDateOptions
    '{9493aaa3-34b7-5b53-daf1-cb9b80c7e772}' # Microsoft.Windows.Shell.DesktopUvc
    '{69219098-3c47-5f65-4b95-2e2ae89c07fc}' # WindowsInternal.Shell.Start.TraceLoggingProvider
    '{f0c781fb-3451-566e-121c-9020159a5306}' # Microsoft.Windows.SharedPC.AccountManager
    '{e49b2c1a-1ad0-505c-a11a-73dba0c60f50}' # Microsoft.Windows.Shell.Theme
    '{2c00a440-76de-4fe3-856f-00557535be83}' # Microsoft.Windows.Shell.ControlCenter
    '{462B9C75-E5D7-4E0D-8AA1-294D175566BB}' # Microsoft-Windows-Shell-ActionCenter
    '{f401924c-6fb0-5abb-be79-b010fb9ba7d4}' # Microsoft.Windows.Shell.FilePicker
    '{d173c6af-d86c-5327-17b8-5dcc03543da5}' # Microsoft.Windows.Mobile.Shell.FileExplorer
    '{813552F2-2082-4873-8E75-2DE43AA7B725}' # Microsoft.Windows.Mobile.Shell.Share
    '{08f5d47e-67d3-4ee0-8e0c-cbd309ab5d1b}' # Microsoft.Windows.Shell.CloudFiles
    '{c45c91e9-3750-5f9d-63c2-ec9d4991fcda}' # Microsoft.Windows.Shell.CloudStore.Internal
    # CLDAPI.DLL
    '{62e03996-3f13-473b-ba8c-9a507277abf8}' # Microsoft-OneCore-SyncEngine-Service
    '{6FDFA2FD-23C7-5152-1A51-618729D0E93D}' # Microsoft.Windows.FileSystem.CloudFiles
    # OneDriveSettingSyncProvider.dll
    '{F43C3C35-22E2-53EB-F169-07594054779E}' # Microsoft-Windows-SettingSync-OneDrive
)

$CldFltProviders = @(
    '{d8de3faf-8a2e-4a80-aedb-c86c7cc02a73}' # CldFltLogGuid
)

$IMEProviders = @(
    '{E2242B38-9453-42FD-B446-00746E76EB82}' # Microsoft-Windows-IME-CustomerFeedbackManager
    '{31BCAC7F-4AB8-47A1-B73A-A161EE68D585}' # Microsoft-Windows-IME-JPAPI
    '{3AD571F3-BDAE-4942-8733-4D1B85870A1E}' # Microsoft-Windows-IME-JPPRED
    '{8C8A69AD-CC89-481F-BBAD-FD95B5006256}' # Microsoft-Windows-IME-JPTIP
    '{BDD4B92E-19EF-4497-9C4A-E10E7FD2E227}' # Microsoft-Windows-IME-TIP
    '{FD44A6E7-580F-4A9C-83D9-D820B7D3A033}' # Microsoft-Windows-IME-OEDCompiler
    '{4FBA1227-F606-4E5F-B9E8-FAB9AB5740F3}' # Microsoft-Windows-TSF-msctf
    '{ebadf775-48aa-4bf3-8f8e-ec68d113c98e}' # TextInput
    '{7B434BC1-8EFF-41A3-87E9-5D8AF3099784}' # Microsoft-Windows-Shell-KeyboardHosting-ShellKeyboardManager
    '{34c25d46-d194-5918-c399-d3641f0c609d}' # Microsoft-Windows-ComposableShell-Components-InputHost
    '{5C3E3AA8-3BA4-43CD-A7DE-3BF5F70F9CA4}' # Microsoft-Windows-Shell-TextInput-InputPanel
    '{7e6b69b9-2aec-4fb3-9426-69a0f2b61a86}' # win32kbaseinput
    '{74B655A2-8958-410E-80E2-3457051B8DFF}' # Microsoft-Windows-TSF-msutb
    '{4DD778B8-379C-4D8C-B659-517A43D6DF7D}' # Microsoft-Windows-TSF-UIManager
    '{39A63500-7D76-49CD-994F-FFD796EF5A53}' # Microsoft-Windows-TextPredictionEngine
    '{E2C15FD7-8924-4C8C-8CFE-DA0BE539CE27}' # Microsoft-Windows-IME-Broker
    '{7C4117B1-ED82-4F47-B2CA-29E4E25719C7}' # Microsoft-Windows-IME-CandidateUI
    '{1B734B40-A458-4B81-954F-AD7C9461BED8}' # Microsoft-Windows-IME-CustomerFeedbackManagerUI
    '{DBC388BC-89C2-4FE0-B71F-6E4881FB575C}' # Microsoft-Windows-IME-JPLMP
    '{14371053-1813-471A-9510-1CF1D0A055A8}' # Microsoft-Windows-IME-JPSetting
    '{7562948E-2671-4DDA-8F8F-BF945EF984A1}' # Microsoft-Windows-IME-KRAPI
    '{E013E74B-97F4-4E1C-A120-596E5629ECFE}' # Microsoft-Windows-IME-KRTIP
    '{F67B2345-47FA-4721-A6FB-FE08110EECF7}' # Microsoft-Windows-IME-TCCORE
    '{D5268C02-6F51-436F-983B-74F2EFBFAF3A}' # Microsoft-Windows-IME-TCTIP
    '{28e9d7c3-908a-5980-90cc-1581dd9d451d}' # Microsoft.Windows.Desktop.Shell.EUDCEditor
    '{397fe846-4109-5a9b-f2eb-c1d3b72630fd}' # Microsoft.Windows.Desktop.TextInput.InputSwitch
    '{c442c41d-98c0-4a33-845d-902ed64f695b}' # Microsoft.Windows.TextInput.ImeSettings
)

$PrintProviders = @(
    '{C9BF4A01-D547-4D11-8242-E03A18B5BE01}' # LOCALSPL
    '{C9BF4A02-D547-4D11-8242-E03A18B5BE01}' # WINSPOOL
    '{C9BF4A03-D547-4D11-8242-E03A18B5BE01}' # WIN32SPL
    '{C9BF4A04-D547-4D11-8242-E03A18B5BE01}' # BIDISPL
    '{C9BF4A05-D547-4D11-8242-E03A18B5BE01}' # SPLWOW64
    '{C9BF4A06-D547-4D11-8242-E03A18B5BE01}' # SPLLIB
    '{C9BF4A07-D547-4D11-8242-E03A18B5BE01}' # PERFLIB
    '{C9BF4A08-D547-4D11-8242-E03A18B5BE01}' # ASYNCNTFY
    '{C9BF4A09-D547-4D11-8242-E03A18B5BE01}' # REMNTFY
    '{C9BF4A0A-D547-4D11-8242-E03A18B5BE01}' # GPPRNEXT
    '{C9BF4A0B-D547-4D11-8242-E03A18B5BE01}' # SANDBOX
    '{C9BF4A0C-D547-4D11-8242-E03A18B5BE01}' # SANDBOXHOST
    '{C9BF4A0D-D547-4d11-8242-E03A18B5BE01}' # MSW3PRT
    '{C9BF4A9E-D547-4D11-8242-E03A18B5BE01}' # SPOOLSV
    '{C9BF4A9F-D547-4D11-8242-E03A18B5BE01}' # SPOOLSS
    '{09737B09-A25E-44D8-AA75-07F7572458E2}' # PRNNTFY
    '{301CCC25-D58B-4C5E-B6A5-15BCF8B0077F}' # INETPPUI
    '{34F7D4F8-CD95-4B06-8BF6-D929DE4AD9DE}' # PRNCACHE
    '{528F557E-A4D4-4063-A17A-9F45FAF8C042}' # HGPRINT
    '{3EA31F33-8F51-481D-AEB7-4CA37AB12E48}' # LPDSVC
    '{62A0EB6C-3E3E-471D-960C-7C574A72534C}' # TCPMon
    '{6D1E0446-6C52-4B85-840D-D2CB10AF5C63}' # WSDPrPxy
    '{836767A6-AF31-4938-B4C0-EF86749A9AEF}' # WSDMON
    '{9558985E-3BC8-45EF-A2FD-2E6FF06FB886}' # WSDPRINT
    '{9677DFEF-EACF-4173-8977-FFB0086B11E6}' # BridgeGuid
    '{99F5F45C-FD1E-439F-A910-20D0DC759D28}' # USBMon
    '{9E6D0D9B-1CE5-44B5-8B98-F32ED89077EC}' # LPRHelp
    '{A83C80B9-AE01-4981-91C6-94F00C0BB8AA}' # printui
    '{AAED978E-5B0C-4F71-B35C-16E9C0794FF9}' # CommonGuid
    '{B42BD277-C2BA-468B-AB3D-05B1A1714BA3}' # PRINTLIB
    '{B795C7DF-07BC-4362-938E-E8ABD81A9A01}' # NTPRINT
    '{C9BF4A9E-D547-4D11-8242-E03A18B5BEEE}' # INETPP
    '{CE444D6A-F287-4977-BBBD-89A0DD65B71D}' # CDIGuid
    '{D34AE79A-15FB-44F9-9FD8-3098E6FFFD49}' # D34AE79A
    '{EB4C6075-0B67-4A79-A0A3-7CD9DF881194}' # XpsRasFilter
    '{EE7E960D-5E42-4C28-8F61-D8FA8B0DD84D}' # ServerGuid
    '{F30FAB8E-84BB-48D4-8E80-F8967EF0FE6A}' # LPRMon
    '{F4DF4FA4-66C2-4C14-ABB1-19D099D7E213}' # COMPONENTGuid
    '{34F7D4F8-CD95-4B06-8BF6-D929DE4AD9DE}' # PRNCACHE
    '{883DFB21-94EE-4C9B-9922-D5C42B552E09}' # PRNFLDR
    '{3048407B-56AA-4D41-82B2-7D5F4B1CDD39}' # DAFPRINT
    '{2F6A026F-D4C4-41B8-A59E-2EC834419B67}' # PUIOBJ
    '{79B3B0B7-F082-4CEC-91BC-5E4B9CC3033A}' # FDPRINT
    '{CAC16EB2-12D0-46B8-B484-F179C900772B}' # PMCSNAP
    '{0DC96237-BBD4-4BC9-8184-46DF83B1F1F0}' # DOXXPS
    '{0675CF90-F2B8-11DB-BB42-0013729B82C4}' # DOXPKG
    '{986DE178-EA3F-4E27-BBEE-34E0F61535DD}' # XpsRchVw
    '{64F02056-AFD9-42D9-B221-6C94733B09B1}' # XpsIFilter
    '{2BEADE0B-84CD-44A5-90A7-5B6FB2FF83C8}' # XpsShellExt
    '{AAACB431-6067-4A42-8883-3C01526DD43A}' # XpsRender
    '{0DC96237-BBD4-4BC9-8184-46DF83B1F1F0}' # DOXXPS
    '{986DE178-EA3F-4E27-BBEE-34E0F61535DD}' # XpsRchVw
    '{12DC38E3-E395-4C8E-9156-B5642057F5FA}' # Microsoft-Windows-PrintDialogs3D
    '{27E76321-1E5B-4A82-BA0C-26E978F15072}' # Microsoft-Windows-PrintDialogs
    '{747EF6FD-E535-4D16-B510-42C90F6873A1}' # Microsoft-Windows-PrintService
    '{7F812073-B28D-4AFC-9CED-B8010F914EF6}' # Microsoft-Windows-PrintService-USBMon
    '{952773BF-C2B7-49BC-88F4-920744B82C43}' # Microsoft-Windows-TerminalServices-Printers
    '{0ED38D2B-4ACC-4E23-A8EC-D0DACBC34637}' # tsprint
    '{9B4A618C-07B8-4182-BA5A-5B1943A92EA1}' # MSXpsFilters
    '{A6D25EF4-A3B3-4E5F-A872-24E71103FBDC}' # MicrosoftRenderFilter
    '{AEFE45F4-8548-42B4-B1C8-25673B07AD8B}' # PrintFilterPipelinesvc
    '{BE967569-E3C8-425B-AD0E-4F2C790B1848}' # Microsoft-Windows-Graphics-Printing3D
    '{CF3F502E-B40D-4071-996F-00981EDF938E}' # Microsoft-Windows-PrintBRM
    '{E7AA32FB-77D0-477F-987D-7E83DF1B7ED0}' # Microsoft-Windows-Graphics-Printing
    '{7672778D-86FE-41D0-85C8-82CAA8CE6168}' # ESUPDATE(Maybe not used now)
    '{7663DA2F-1594-4C33-83DD-D5C64BBED68A}' # ObjectsGuid
    '{5ED940EB-18F9-4227-A454-8EF1CE5B3272}' # SetupLPR
    '{27239FD0-425E-11D8-9E39-000039252FD8}' # COMMONGuid
    '{04160794-60B6-4EC7-96FF-4953691F94AA}' # SetupIPP
)

$TaskProviders = @(
     '{077E5C98-2EF4-41D6-937B-465A791C682E}' # Microsoft-Windows-DesktopActivityBroker
     '{6A187A25-2325-45F4-A928-B554329EBD51}' # Scheduler
     '{047311A9-FA52-4A68-A1E4-4E289FBB8D17}' # TaskEng_JobCtlGuid
     '{10FF35F4-901F-493F-B272-67AFB81008D4}' # UBPM
     '{19043218-3029-4BE2-A6C1-B6763CECB3CC}' # EventAggregation
     '{DE7B24EA-73C8-4A09-985D-5BDADCFA9017}' # Microsoft-Windows-TaskScheduler
     '{6966FE51-E224-4BAA-99BC-897B3ED3B823}' # Microsoft.Windows.BrokerBase
     '{0657ADC1-9AE8-4E18-932D-E6079CDA5AB3}' # Microsoft-Windows-TimeBroker
     '{E8109B99-3A2C-4961-AA83-D1A7A148ADA8}' # System/TimeBroker WPP
)

$SearchProviders = @(
    '{44e18db2-6cfd-4a07-8fe7-6073794c531a}' # Microsoft.Windows.Search.Indexer
    '{CA4E628D-8567-4896-AB6B-835B221F373F}' # Microsoft-Windows-Search(tquery.dll)
    '{dab065a9-620f-45ba-b5d6-d6bb8efedee9}' # Microsoft-Windows-Search-ProtocolHandlers
    '{49c2c27c-fe2d-40bf-8c4e-c3fb518037e7}' # Microsoft-Windows-Search-Core
    '{FC6F77DD-769A-470E-BCF9-1B6555A118BE}' # Microsoft-Windows-Search-ProfileNotify
)

$PhotoProviders = @(
    '{054B421C-7DEF-54EF-EF59-41B32C8F94BC}'
    '{6A1E3074-FFEE-5D94-F0B9-F1E92857AC55}'
    '{3C20A2BD-0497-5E1D-AD49-7B789B9D7318}'
    '{1EE9AB78-81DE-5903-9F1B-4C73E2F3501D}'
    '{8F4FD2AF-C8DB-5CC1-27EC-54A4BCF3AAB5}'
    '{EBDDC69C-80FB-5062-B3BA-C203645A72EE}'
    '{DCA2B5B9-047F-5768-688F-9B4C705B541F}'
)

$AlarmProviders = @(
    '{B333D303-D0C7-4D0B-A417-D331DA97E7D3}' # Microsoft.Windows.AlarmsAndClock
)

$CalcProviders = @(
    '{0905CA09-610E-401E-B650-2F212980B9E0}' # MicrosoftCalculator
)

$StoreProviders = @(
    '{53e3d721-2aa0-4743-b2db-299d872b8e3d}' # Microsoft_Windows_Store_Client_UI
    '{945a8954-c147-4acd-923f-40c45405a658}' # Microsoft-Windows-WindowsUpdateClient
    '{9c2a37f3-e5fd-5cae-bcd1-43dafeee1ff0}' # Microsoft-Windows-Store
    '{5F0B026E-BCC1-5001-95D3-65E170A11EFA}' # Microsoft.Store
    '{6938F4E9-4F5F-54FE-EDFF-7D728ACECA12}' # Microsoft.Windows.Store.Partner
    '{9bfa0c89-0339-4bd1-b631-e8cd1d909c41}' # Microsoft.Windows.StoreAgent.Telemetry
    '{FF79A477-C45F-4A52-8AE0-2B324346D4E4}' # Windows-ApplicationModel-Store-SDK
    '{f4b9ce38-744d-4916-b645-f1574e19bbaa}' # Microsoft.Windows.PushToInstall
    '{DD2E708D-F725-5C93-D0D1-91C985457612}' # Microsoft.Windows.ApplicationModel.Store.Telemetry
    '{13020F14-3A73-4DB1-8BE0-679E16CE17C2}' # Microsoft.Windows.Store.LicenseManager.UsageAudit
    '{AF9F58EC-0C04-4BE9-9EB5-55FF6DBE72D7}' # Microsoft.Windows.LicenseManager.Telemetry
    '{4DE9BC9C-B27A-43C9-8994-0915F1A5E24F}' # Microsoft.Windows.AAD
    '{84C5F702-EB27-41CB-AED2-64AA9850C3D0}' # CryptNgcCtlGuid(Until RS4)
    '{B66B577F-AE49-5CCF-D2D7-8EB96BFD440C}' # Microsoft.Windows.Security.NGC.KspSvc
    '{CAC8D861-7B16-5B6B-5FC0-85014776BDAC}' # Microsoft.Windows.Security.NGC.CredProv
    '{6D7051A0-9C83-5E52-CF8F-0ECAF5D5F6FD}' # Microsoft.Windows.Security.NGC.CryptNgc
    '{0ABA6892-455B-551D-7DA8-3A8F85225E1A}' # Microsoft.Windows.Security.NGC.NgcCtnr
    '{9DF6A82D-5174-5EBF-842A-39947C48BF2A}' # Microsoft.Windows.Security.NGC.NgcCtnrSvc
    '{9B223F67-67A1-5B53-9126-4593FE81DF25}' # Microsoft.Windows.Security.NGC.KeyStaging
    '{89F392FF-EE7C-56A3-3F61-2D5B31A36935}' # Microsoft.Windows.Security.NGC.CSP
    '{CDD94AC7-CD2F-5189-E126-2DEB1B2FACBF}' # Microsoft.Windows.Security.NGC.LocalAccountMigPlugin
    '{2056054C-97A6-5AE4-B181-38BC6B58007E}' # Microsoft.Windows.Security.NGC.NgcIsoCtnr
    '{786396CD-2FF3-53D3-D1CA-43E41D9FB73B}' # Microsoft.Windows.Security.CryptoWinRT
    '{9D4CA978-8A14-545E-C047-A45991F0E92F}' # Microsoft.Windows.Security.NGC.Recovery
    '{507C53AE-AF42-5938-AEDE-4A9D908640ED}' # Microsoft.Windows.Security.Credentials.UserConsentVerifier
    '{CDC6BEB9-6D78-5138-D232-D951916AB98F}' # Microsoft.Windows.Security.NGC.NgcIsoCtnr
    '{C0B2937D-E634-56A2-1451-7D678AA3BC53}' # Microsoft.Windows.Security.Ngc.Truslet
    '{34646397-1635-5d14-4d2c-2febdcccf5e9}' # Microsoft.Windows.Security.NGC.KeyCredMgr
    '{3b9dbf69-e9f0-5389-d054-a94bc30e33f7}' # Microsoft.Windows.Security.NGC.Local
    '{1D6540CE-A81B-4E74-AD35-EEF8463F97F5}' # CryptNgcCtlGuid(WPP -> Until RS4)
    '{3A8D6942-B034-48e2-B314-F69C2B4655A3}' # TpmCtlGuid(WPP)
    '{D5A5B540-C580-4DEE-8BB4-185E34AA00C5}' # Microsoft.Windows.DeviceManagement.SCEP
    '{7955d36a-450b-5e2a-a079-95876bca450a}' # Microsoft.Windows.Security.DevCredProv
    '{c3feb5bf-1a8d-53f3-aaa8-44496392bf69}' # Microsoft.Windows.Security.DevCredSvc
    '{78983c7d-917f-58da-e8d4-f393decf4ec0}' # Microsoft.Windows.Security.DevCredClient
    '{36FF4C84-82A2-4B23-8BA5-A25CBDFF3410}' # Microsoft.Windows.Security.DevCredWinRt
    '{5bbca4a8-b209-48dc-a8c7-b23d3e5216fb}' # Microsoft-Windows-CAPI2
    '{73370BD6-85E5-430B-B60A-FEA1285808A7}' # Microsoft-Windows-CertificateServicesClient
    '{F0DB7EF8-B6F3-4005-9937-FEB77B9E1B43}' # Microsoft-Windows-CertificateServicesClient-AutoEnrollment
    '{54164045-7C50-4905-963F-E5BC1EEF0CCA}' # Microsoft-Windows-CertificateServicesClient-CertEnroll
    '{89A2278B-C662-4AFF-A06C-46AD3F220BCA}' # Microsoft-Windows-CertificateServicesClient-CredentialRoaming
    '{BC0669E1-A10D-4A78-834E-1CA3C806C93B}' # Microsoft-Windows-CertificateServicesClient-Lifecycle-System
    '{BEA18B89-126F-4155-9EE4-D36038B02680}' # Microsoft-Windows-CertificateServicesClient-Lifecycle-User
    '{B2D1F576-2E85-4489-B504-1861C40544B3}' # Microsoft-Windows-CertificateServices-Deployment
    '{98BF1CD3-583E-4926-95EE-A61BF3F46470}' # Microsoft-Windows-CertificationAuthorityClient-CertCli
    '{AF9CC194-E9A8-42BD-B0D1-834E9CFAB799}' # Microsoft-Windows-CertPolEng
    '{d0034f5e-3686-5a74-dc48-5a22dd4f3d5b}' # Microsoft-Windows-Shell-CloudExperienceHost
    '{aa02d1a4-72d8-5f50-d425-7402ea09253a}' # Microsoft.Windows.Shell.CloudDomainJoin.Client
    '{9FBF7B95-0697-4935-ADA2-887BE9DF12BC}' # Microsoft-Windows-DM-Enrollment-Provider
    '{3DA494E4-0FE2-415C-B895-FB5265C5C83B}' # Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider
    '{8db3086d-116f-5bed-cfd5-9afda80d28ea}' # Microsoft-OSG-OSS-CredProvFramework
    '{7D44233D-3055-4B9C-BA64-0D47CA40A232}' # Microsoft-Windows-WinHttp
)

$ContactSupportProviders = @(
    '{B6CC0D55-9ECC-49A8-B929-2B9022426F2A}' # Microsoft-Client-Licensing-Platform-Instrumentation
    '{8127F6D4-59F9-4ABF-8952-3E3A02073D5F}' # Microsoft-Windows-AppXDeployment
    '{3F471139-ACB7-4A01-B7A7-FF5DA4BA2D43}' # Microsoft-Windows-AppXDeployment-Server
    '{8FD4B82B-602F-4470-8577-CBB56F702EBF}' # Microsoft.Windows.AppXDeploymentClient.WPP
    '{FE762FB1-341A-4DD4-B399-BE1868B3D918}' # Microsoft.Windows.AppXDeploymentServer
    '{BA44067A-3C4B-459C-A8F6-18F0D3CF0870}' # DEPLOYMENT_WPP_GUID
    '{B9DA9FE6-AE5F-4F3E-B2FA-8E623C11DC75}' # Microsoft-Windows-SetupPlatform-AutoLogger
    '{9213C3E1-0D6C-52DD-78EA-F3B082111406}' # Microsoft-Windows-PriResources-Deployment
    '{06184C97-5201-480E-92AF-3A3626C5B140}' # Microsoft-Windows-Services-Svchost
    '{89592015-D996-4636-8F61-066B5D4DD739}' # Microsoft.Windows.StateRepository
    '{551FF9B3-0B7E-4408-B008-0068C8DA2FF1}' # Microsoft.Windows.StateRepository.Service
    '{DB00DFB6-29F9-4A9C-9B3B-1F4F9E7D9770}' # Microsoft-Windows-User Profiles General
    '{6AF9E939-1D95-430A-AFA3-7526FADEE37D}' # ClipSvcProvider
    '{B94D76C5-9D56-454A-8D1B-6CA30898160E}' # Microsoft.ClipSvc
    '{9A2EDB8F-5883-499F-ACED-6E4B69D43DDF}' # WldpTraceLoggingProvider
    '{A323CDC2-81B0-48B2-80C8-B749A221478A}' # Castle(WPP)
    '{A74EFE00-14BE-4EF9-9DA9-1484D5473302}' # CNGTraceControlGuid
    '{F0558438-F56A-5987-47DA-040CA75AEF05}' # Microsoft.Windows.WinRtClassActivation
    '{F25BCD2E-2690-55DC-3BC4-07B65B1B41C9}' # Microsoft.Windows.User32
    '{30336ED4-E327-447C-9DE0-51B652C86108}' # Microsoft-Windows-Shell-Core 
    '{1AFF6089-E863-4D36-BDFD-3581F07440BE}' # ComBaseTraceLoggingProvider
    '{6AD52B32-D609-4BE9-AE07-CE8DAE937E39}' # Microsoft-Windows-RPC
    '{F4AED7C7-A898-4627-B053-44A7CAA12FCD}' # Microsoft-Windows-RPC-Events 
    '{A86F8471-C31D-4FBC-A035-665D06047B03}' # Microsoft-Windows-WinRT-Error
    '{BDA92AE8-9F11-4D49-BA1D-A4C2ABCA692E}' # Microsoft-Windows-COMbase
)

$SpeechProviders = @(
    '{7f02214a-4eb1-50e4-adff-62654d1e42f6}'  # NLClientPlatformAPI
    '{a9da5902-9012-4f82-bdc8-905c88db93ee}'  # Bing-Platform-ConversationalUnderstanding-Client
    '{8eb79eb6-8701-4d39-9196-9efc81a31489}'  # Microsoft-Speech-SAPI
    '{46f27ed9-a8d6-5c0c-8c30-6e846b4c4e46}'  # Windows.ApplicationModel.VoiceCommands.VoiceCommandServiceConnection
    '{70400dee-6c5b-5209-4052-b9f8cf41b7d7}'  # Microsoft.Windows.ReactiveAgentFramework
    '{5656A338-AC25-4E57-93DC-4703091CB85A}'  # Microsoft-Windows-NUI-Audio
    '{E5514D5F-A8E4-4658-B381-63227E390476}'  # Microsoft-WindowsPhone-Speech-Ux
    '{614f2573-da68-5a1b-c2c6-cba6de5de7f8}'  # Microsoft.Windows.Media.Speech.Internal.SoundController.WinRT
    '{E6C38788-C835-4D10-B26E-5920C34E5F20}'  # Microsoft-Speech-WinRT
    '{07f283ce-2538-5e77-44d2-04212575a63d}'  # Microsoft.Windows.Analog.Speech.RecognizerClient
    '{2a8bc2a0-4cf9-5429-c90c-f5cd30dc6dd1}'  # Microsoft.Windows.Analog.Speech.RecognizerServer
)

$WUProviders = @(
    '{0b7a6f19-47c4-454e-8c5c-e868d637e4d8}' # WUTraceLogging
    '{9906081d-e45a-4f41-a53f-2ac2e0225de1}' # SIHTraceLoggingProviderGuid
    '{5251FD36-A05A-4033-ADAD-FA409644E282}' # SIHTraceLoggingSessionGuid
    '{D48679EB-8AA3-4138-BE24-F1648C874E49}' # SoftwareUpdateClientTelemetry
) 

$CDPProviders = @(
    '{4a16abff-346d-56dc-fa87-eb1e29fe670a}' # Microsoft.Windows.CDP.Service
    '{ed1640e7-9dc0-45b5-a1ef-88b70cf1742c}' # Microsoft.Windows.CDP.UserService
    '{9f4cc6dc-1bab-5772-0c71-a89954718d66}' # Microsoft.Windows.CDP
    '{bc1826c8-369c-5b0b-4cd1-3c6ae5bfe2e7}' # Microsoft.Windows.CDP.Aggr
    '{5fe36556-c4cd-509a-8c3e-2a547ea568ae}' # Microsoft.Windows.CDP.AFS
    '{ABB10A7F-67B4-480C-8834-8B049C428715}' # Microsoft.Windows.CDP.Core
    '{A1EA5EFC-402E-5285-3898-22A5ACCE1B76}' # Microsoft.Windows.CDP.Core.Error
    '{633383CB-D7A9-4964-876A-66B7DC98C0FE}' # Microsoft.Windows.RemoteSystems.CDPRT
    '{A29339AD-B137-486C-A8F3-88C9738E5379}' # Microsoft.Windows.ApplicationModel.DataTransfer.CloudClipboard
    '{f06690ca-9325-5dcf-65bc-fc3164fa8acc}' # Microsoft.Windows.Application.NearSharePlatform
    '{A48E7274-BB8F-520D-7E6F-1737E9D68491}' # Microsoft.Windows.System.RemoteSystem
    '{D229987F-EDC3-5274-26BF-82BE01D6D97E}' # Microsoft.Windows.System.RemoteSystemSession
    '{833E7812-D1E2-5172-66FD-4DD4B255A3BB}' # Microsoft.Windows.ApplicationModel.UserActivities
    '{30AD9F59-EC19-54B2-4BDF-76DBFC7404A6}' # Microsoft.Windows.CDP.Session
)

$SystemSettingsProviders = @(
    '{c1be8ae8-b6b1-566a-8453-ec627f8eb2de}' # Microsoft.Windows.Shell.MockDataSystemSettings
    '{B7AFA6AF-AAAB-4F50-B7DC-B61D4DDBE34F}' # Microsoft.Windows.Shell.SystemSettings.SettingsAppActivity
    '{8BCDF442-3070-4118-8C94-E8843BE363B3}' # Microsoft-Windows-SystemSettingsThreshold
    '{1EE8CA37-11AE-4815-800E-58D6BAE1FEF9}' # Microsoft.Windows.Shell.SystemSettings.SettingsPane
    '{1ABBDEEA-0CF0-46B1-8EC2-DAAD6F165F8F}' # Microsoft.Windows.Shell.SystemSettings.HotKeyActivation
    '{80B3FF7A-BAB0-4ED1-958C-E89A6D5557B3}' # Microsoft.Windows.Shell.SystemSettings.WorkAccessHandlers
    '{68D9DE11-9358-4C97-8B72-A7CE49EF593C}' # Wi-Fi Calling Logging
    '{0ae9ad8e-d4d3-5486-f015-498e0b6860ef}' # Microsoft.Windows.Shell.SystemSettings.UserPage
    '{44f1a90c-4250-5bab-f09b-df45384c6951}' # Microsoft.Windows.Shell.SystemSettings.RegionSettings
    '{6bee332c-7ddb-5ec2-dec4-91b8be7612f8}' # Microsoft.Windows.Shell.PersonalizeSettingsTelemetry
    '{f323b60d-51ff-5c64-f7d1-f8149e2b3d81}' # Microsoft.Windows.Shell.SystemSettings.Pen
    '{6b2dfe1c-ae63-55d0-edea-60c166860d63}' # Microsoft.Windows.Shell.SystemSettings.OtherPeoplePage
    '{e613a5d7-363e-5200-b311-02b426d8a73b}' # Microsoft.Windows.Desktop.Shell.LanguageFeaturesOnDemandSettings
    '{c442c41d-98c0-4a33-845d-902ed64f695b}' # Microsoft.Windows.TextInput.ImeSettings
    '{9a35425e-61bc-4d68-8542-568a28963abe}' # Microsoft.Windows.Shell.SystemSettings.AdvancedGraphics
    '{ec696ee4-fac7-4df4-9aaa-3862cb16eb4b}' # Microsoft.Windows.Shell.SystemSettings.FontPreview
    '{23cd8d50-ed49-5a0b-4562-65dff962d5f1}' # Microsoft.Windows.Mobile.Shell.DisplaySettings
    '{55f422c8-0aa0-529d-95f5-8e69b6a29c98}' # Microsoft.Windows.Shell.SystemSettings.SignInOptionsPage
    '{e3bfeaae-cb1d-5f12-e2e5-b9d2d7ca7bf0}' # Microsoft.Windows.Shell.SystemSettings.Devices
    '{17d6a222-af97-560b-6f18-389900d6ad1e}' # Microsoft.Windows.Desktop.Shell.LanguagePackInstallSettings
    '{8b5a39e9-7fc8-5ccb-18c9-d410973436a9}' # Microsoft.Windows.Shell.TabShell
    '{56143DD6-AD65-4FB1-972C-6DFA2BEF0916}' # Microsoft.Windows.Shell.SystemSettings.BluetoothHandler
    '{6cd9d548-4f28-5e7c-503d-86e3cd9db63d}' # Microsoft.Windows.DeveloperPlatform.DeveloperOptions
    '{4b82b48e-8625-5aba-2a86-b5266e869e10}' # Microsoft.Windows.Shell.SystemSettings.KeyboardSettings
    '{fc27cce8-72b0-5a6f-8fe3-22bfcfefd495}' # Microsoft.Windows.Shell.SystemSettings.MediaRadioManagerSink
    '{35a6b23c-c542-5414-bc49-b0f81b96a266}' # Microsoft.Windows.Shell.SystemSettings.OneDriveBackup
    '{e2a3ad70-42b5-452c-a113-20476e27e37c}' # Microsoft.Windows.Desktop.Shell.SystemSettingsThreshold.Handlers
    '{3A245D5A-F00F-48F6-A94B-C51CDD290F18}' # Microsoft-Windows-Desktop-Shell-SystemSettingsV2-Handlers
    '{068b0237-1f0a-593a-bc39-5155685f1bef}' # Microsoft.PPI.Settings.AdminFlow
    '{57d940ae-e2fc-55c3-f31b-253c5b172135}' # Microsoft.Windows.Shell.SystemSettings.ManageUser
    '{e6fcf13b-1ab7-4236-823b-0c0cf5c589d5}' # Microsoft.Windows.Upgrade.Uninstall
    '{e881df47-b77c-48c5-b321-1454b88fdd6b}' # Microsoft.Windows.Shell.SystemSettings.ManageOrganization
    '{2e07964e-7d10-5d8e-761d-99b038f42bb6}' # Microsoft.Windows.Shell.SystemSettings.AdminFlow
    '{e881df47-b77c-48c5-b321-1454b88fdd6b}' # Microsoft.Windows.Shell.SystemSettings.ManageOrganization
    '{3e8fb07b-3e10-5981-01a9-fbd924fd5436}' # Microsoft.Windows.Shell.AssignedAccessSettings
    '{a306fcf9-ad27-5c4d-f69a-22506ef908ad}' # Microsoft.Windows.Shell.SystemSettings.RemoteDesktopAdminFlow
)

$WPNProviders = @(
    '{F0AE506B-805E-434A-A005-7971D555179C}' # Wpn(WPP)
    '{4ff58fbe-3d4d-447a-ac26-7da2c51f4b7d}' # WpnSrum(WPP)
    '{2FDB1F25-8DE1-4BC1-BAC2-E445E5B38743}' # Microsoft.Windows.Notifications.WpnApps
    '{B92D1FF0-92EC-444D-B7EC-C016F971C000}' # Microsoft.Windows.Notifications.WpnCore
    '{EE845016-EBE1-41EB-BE52-5E3AE58339F2}' # WNSCP
    '{833c9bbd-6422-59cb-83bb-c695934a0cf5}' # Microsoft.Windows.PerProcessSystemDpi
    '{5cad3597-5fec-4c62-9ce1-9d7abc723d3a}' # Microsoft-Windows-PushNotifications-Developer
    '{815a1f4a-3f8d-4b37-9b31-5142f9d724a5}' # Microsoft-Windows-PushNotifications-InProc
    '{88cd9180-4491-4640-b571-e3bee2527943}' # Microsoft-Windows-PushNotifications-Platform
    '{eb3540f2-1909-5d51-b72d-a3ecb0b9bf08}' # Microsoft.Windows.Shell.NotificationController
    '{33b3eaa6-d8dd-5096-8687-6f520d32fc9e}' # Microsoft.Windows.Shell.NotificationSettings
    '{4bfe0fde-99d6-5630-8a47-da7bfaefd876}' # Microsoft-Windows-Shell-NotificationCenter
    '{7145ABF9-99F5-4CCF-A2B6-C9B2E05BA8B3}' # Microsoft.Windows.Shell.NotificationQuietHours
    '{ce575084-01be-5ef2-75f2-2d822e70cec9}' # Microsoft.Windows.Internal.Shell.Session.WnfPolicy
    '{1870FBB0-2247-44D8-BF46-B02130A8A477}' # Microsoft.Windows.Notifications.WpnApis
)

$XAMLProviders = @(
    '{59E7A714-73A4-4147-B47E-0957048C75C4}' # Microsoft-Windows-XAML-Diagnostics
    '{922CDCF3-6123-42DA-A877-1A24F23E39C5}' # Microsoft-WindowsPhone-CoreMessaging
    '{A0B7550F-4E9A-4F03-AD41-B8042D06A2F7}' # Microsoft-WindowsPhone-CoreUIComponents
    '{DB6F6DDB-AC77-4E88-8253-819DF9BBF140}' # Microsoft-Windows-Direct3D11
    '{C44219D0-F344-11DF-A5E2-B307DFD72085}' # Microsoft-Windows-DirectComposition
    '{5786E035-EF2D-4178-84F2-5A6BBEDBB947}' # Microsoft-Windows-DirectManipulation
    '{8360BD0F-A7DC-4391-91A7-A457C5C381E4}' # Microsoft-Windows-DUI
    '{8429E243-345B-47C1-8A91-2C94CAF0DAAB}' # Microsoft-Windows-DUSER
    '{292A52C4-FA27-4461-B526-54A46430BD54}' # Microsoft-Windows-Dwm-Api
    '{CA11C036-0102-4A2D-A6AD-F03CFED5D3C9}' # Microsoft-Windows-DXGI
)

$ShutdownProviders = @(
    '{206f6dea-d3c5-4d10-bc72-989f03c8b84b}' # WinInit
    '{e8316a2d-0d94-4f52-85dd-1e15b66c5891}' # CsrEventProvider
    '{9D55B53D-449B-4824-A637-24F9D69AA02F}' # WinsrvControlGuid
    '{dbe9b383-7cf3-4331-91cc-a3cb16a3b538}' # Microsoft-Windows-Winlogon 
    '{e8316a2d-0d94-4f52-85dd-1e15b66c5891}' # Microsoft-Windows-Subsys-Csr
    '{331c3b3a-2005-44c2-ac5e-77220c37d6b4}' # Microsoft-Windows-Kernel-Power
    '{23b76a75-ce4f-56ef-f903-c3a2d6ae3f6b}' # Microsoft.Windows.Kernel.BootEnvironment
    '{a68ca8b7-004f-d7b6-a698-07e2de0f1f5d}' # Microsoft-Windows-Kernel-General
    '{15ca44ff-4d7a-4baa-bba5-0998955e531e}' # Microsoft-Windows-Kernel-Boot
)

$VSSProviders = @(
    '{9138500E-3648-4EDB-AA4C-859E9F7B7C38}' # VSS tracing provider
    '{77D8F687-8130-4A14-B8A6-3B922E05B99C}' # VSS tracing event
    '{f3625a85-421c-4a1e-a54f-6b65c0276c1c}' # VirtualBus
    '{6407345b-94f2-44c8-b3db-4e076be46816}' # WPP_GUID_ASR
    '{89300202-3cec-4981-9171-19f59559e0f2}' # Microsoft-Windows-FileShareShadowCopyProvider
    '{a0d45273-3386-4f3a-b344-0d8fee74e06a}' # Microsoft-Windows-FileShareShadowCopyAgent
    '{67FE2216-727A-40CB-94B2-C02211EDB34A}' # Microsoft-Windows-VolumeSnapshot-Driver
    '{CB017CD2-1F37-4E65-82BC-3E91F6A37559}' # Volsnap(manifest based)
)

$WSBProviders = @(
    '{6B1DB052-734F-4E23-AF5E-6CD8AE459F98}' # WPP_GUID_UDFS
    '{944a000f-5f60-4e5a-86fd-d55b84b543e9}' # WPP_GUID_UDFD
    '{6407345b-94f2-44c8-b3db-4e076be46816}' # WPP_GUID_ASR
    '{7e9fb43e-a801-430c-9f36-c1146a51ed07}' # WPP_GUID_DSM
    '{4B966436-6781-4906-8035-9AF94B32C3F7}' # WPP_GUID_SPP
    '{1DB28F2E-8F80-4027-8C5A-A11F7F10F62D}' # Microsoft-Windows-Backup
    '{5602c36e-b813-49d1-a1aa-a0c2d43b4f38}' # BLB
    '{864d2d93-276f-4a88-8bce-d8d174e39c4d}' # Microsoft.Windows.SystemImageBackup.Engine
    '{9138500E-3648-4EDB-AA4C-859E9F7B7C38}' # VSS tracing provider
    '{67FE2216-727A-40CB-94B2-C02211EDB34A}' # Microsoft-Windows-VolumeSnapshot-Driver
    '{CB017CD2-1F37-4E65-82BC-3E91F6A37559}' # Volsnap(manifest based)
)

$VDSProviders = @(
    '{012F855E-CC34-4DA0-895F-07AF2826C03E}' # VDS
    '{EAD10F56-E9D4-4B29-A44F-C97299DE5085}' # Microsoft.Windows.Storage.VDS.Service
    '{F5204334-1420-479B-8389-54A4A6BF6EF8}' # volmgr
    '{945186BF-3DD6-4F3F-9C8E-9EDD3FC9D558}' # WPP_GUID_DISK
    '{467C1914-37F0-4C7D-B6DB-5CD7DFE7BD5E}' # Mount Manager Trace
    '{A8169755-BD1C-49a4-B346-4602BCB940AA}' # DISKMGMT
    '{EAD10F56-E9D4-4B29-A44F-C97299DE5086}' # Microsoft.Windows.Storage.DiskManagement
    '{EAD10F56-E9D4-4B29-A44F-C97299DE5088}' # Microsoft.Windows.Storage.DiskRaid
    '{EAD10F56-E9D4-4B29-A44F-C97299DE5090}' # Microsoft.Windows.Storage.VDS.BasicDisk
)

$Win32kProviders = @(
    '{487d6e37-1b9d-46d3-a8fd-54ce8bdf8a53}' # Win32kTraceLogging
    '{e75a83ec-ef30-4e3c-a5fb-1e7626e48f43}' # Win32kPalmMetrics
    '{72a4952f-db5c-4d90-8f9d-0ed3465b315e}' # Win32kDeadzonePalmTelemetryProvider
    '{7e6b69b9-2aec-4fb3-9426-69a0f2b61a86}' # Microsoft.Windows.Win32kBase.Input
    '{ce20d1cc-faee-4ef6-9bf2-2837cef71258}' # Win32kSyscallLogging
    '{deb96c0a-d2d9-5868-a5d5-50ee13513c8b}' # Microsoft.Windows.Graphics.Display
    '{703fcc13-b66f-5868-ddd9-e2db7f381ffb}' # Microsoft.Windows.TlgAggregateInternal
    '{aad8d3a1-0ce4-4c7e-bf32-15b2836659b7}' # Microsoft.Windows.WER.MTT
    '{6d1b249d-131b-468a-899b-fb0ad9551772}' # TelemetryAssert
    '{03914e49-f3dd-40b9-bb7f-9445bf46d43e}' # Win32kMinTraceGuid(WPP)
)

$FontProviders = @(
    '{8479f1a8-524e-5226-d27e-05636c12b837}' # Microsoft.Windows.Desktop.Fonts.FontManagementSystem
    '{0ae92c9d-6960-566e-221f-5784660d04c3}' # Microsoft.Windows.Fonts.FontEmbedding
    '{E856C26A-E105-4683-A948-6920DCC42E45}' # Microsoft-Windows-DirectWrite-FontCache
    '{487d6e37-1b9d-46d3-a8fd-54ce8bdf8a53}' # Win32kTraceLogging
)

$AppCompatProviders = @(
    '{EEF54E71-0661-422d-9A98-82FD4940B820}' # Microsoft-Windows-Application-Experience
    '{4CB314DF-C11F-47d7-9C04-65FB0051561B}' # Microsoft-Windows-Program-Compatibility-Assistant
    '{DD17FA14-CDA6-7191-9B61-37A28F7A10DA}' # Microsoft.Windows.Appraiser.General
    '{03A70C9D-084B-4905-B341-F6377E734858}' # Microsoft.Windows.Appraiser.Instrumentation
    '{CAEA06A5-D164-4AFA-8CDF-444E3AE008A0}' # Microsoft.Windows.Appraiser.Critical
    '{F5647876-050D-4CF0-BA2F-C498B41C152A}' # DPIScalingProvider
    '{1f87779d-1ad0-45cd-8d2e-0ac9406bc878}' # Microsoft.Windows.Compatibility.Inventory.Agent
    '{32c3bee9-e3f4-4757-95a3-90e6d43299ec}' # Microsoft.Windows.Compatibility.Inventory.WMI
    '{9EFCB348-D13C-4B3A-8AB1-869AAB424C34}' # Microsoft.Windows.Inventory.General
    '{45D5CCD7-6E27-4318-82DD-69BD83A8F672}' # Microsoft.Windows.Inventory.Indicators
    '{407C75AC-661F-4C74-A4B0-ACDD9A643E42}' # Microsoft.Windows.PCA.PushApphelp
    '{95ABB8AF-1790-48BD-85AC-5FEED398DD9E}' # Microsoft.Windows.PCA.Siuf
    '{511A5C98-B374-446E-9625-108624A3CCAA}' # Microsoft.Windows.Compatibility.PCA
    '{74791F71-8F1E-4D6A-AA73-AE7FB15B0D24}' # Microsoft.Windows.AppHelp.Dialog
    '{E7558269-3FA5-46ed-9F4D-3C6E282DDE55}' # Microsoft-Windows-UAC
    '{b059b83f-d946-4b13-87ca-4292839dc2f2}' # Microsoft-Windows-User-Loader 
    '{c02afc2b-e24e-4449-ad76-bcc2c2575ead}' # Microsoft-Windows-UAC-FileVirtualization
    '{AD8AA069-A01B-40A0-BA40-948D1D8DEDC5}' # Microsoft-Windows-WER-Diagnostics
)

$MediaProviders = @(
    '{F3F14FF3-7B80-4868-91D0-D77E497B025E}' # Microsoft-Windows-WMP
    '{AE4BD3BE-F36F-45B6-8D21-BDD6FB832853}' # Microsoft-Windows-Audio
    '{7C314E58-8246-47D1-8F7A-4049DC543E0B}' # Microsoft-Windows-WMPNSSUI
    '{614696C9-85AF-4E64-B389-D2C0DB4FF87B}' # Microsoft-Windows-WMPNSS-PublicAPI
    '{BE3A31EA-AA6C-4196-9DCC-9CA13A49E09F}' # Microsoft-Windows-Photo-Image-Codec
    '{02012A8A-ADF5-4FAB-92CB-CCB7BB3E689A}' # Microsoft-Windows-ShareMedia-ControlPanel
    '{B20E65AC-C905-4014-8F78-1B6A508142EB}' # Microsoft-Windows-MediaFoundation-Performance-Core
    '{3F7B2F99-B863-4045-AD05-F6AFB62E7AF1}' # Microsoft-Windows-TerminalServices-MediaRedirection
    '{42D580DA-4673-5AA7-6246-88FDCAF5FFBB}'
    '{1F930302-F484-4E01-A8A7-264354C4B8E3}'
    '{596426A4-3A6D-526C-5C63-7CA60DB99F8F}'
    '{E27950EB-1768-451F-96AC-CC4E14F6D3D0}'
    '{A9C1A3B7-54F3-4724-ADCE-58BC03E3BC78}' # Windows Media Player Trace
    '{E2821408-C59D-418F-AD3F-AA4E792AEB79}'
    '{6E7B1892-5288-5FE5-8F34-E3B0DC671FD2}'
    '{AAC97853-E7FC-4B93-860A-914ED2DEEE5A}'
    '{E1CCD9F8-6E9F-43ad-9A32-8DBEBE72A489}'
    '{d3045008-e530-485e-81b7-c6d54dbd9044}'
    '{00000000-0dc9-401d-b9b8-05e4eca4977e}'
    '{00000001-0dc9-401d-b9b8-05e4eca4977e}'
    '{00000002-0dc9-401d-b9b8-05e4eca4977e}'
    '{00000003-0dc9-401d-b9b8-05e4eca4977e}'
    '{00000004-0dc9-401d-b9b8-05e4eca4977e}'
    '{00000005-0dc9-401d-b9b8-05e4eca4977e}'
    '{00000006-0dc9-401d-b9b8-05e4eca4977e}'
    '{00000007-0dc9-401d-b9b8-05e4eca4977e}'
    '{00000008-0dc9-401d-b9b8-05e4eca4977e}'
    '{C9C074D2-FF9B-410F-8AC6-81C7B8E60D0F}'
    '{982824E5-E446-46AE-BC74-836401FFB7B6}' # Microsoft-Windows-Media-Streaming
    '{8F2048E0-F260-4F57-A8D1-932376291682}' # Microsoft-Windows-MediaEngine
    '{8F0DB3A8-299B-4D64-A4ED-907B409D4584}' # Microsoft-Windows-Runtime-Media
)

$VANProviders = @(
    '{111FFC99-3987-4bf8-8398-61853120CB3D}' # PNIandNetcenterGUID
    '{9A59814D-6DF5-429c-BD0D-2D41B4A5E9D3}' # PNIandNetcenterGUID
    '{2c929297-cd5c-4187-b508-51a2754a95a3}' # VAN WPP
    '{e6dec100-4e0f-4927-92be-e69d7c15c821}' # WlanMM WPP
)

$UserDataAccessProviders = @(
    '{D1F688BF-012F-4AEC-A38C-E7D4649F8CD2}' # Microsoft-Windows-UserDataAccess-UserDataUtils
    '{fb19ee2c-0d22-4a2e-969e-dd41ae0ce1a9}' # Microsoft-Windows-UserDataAccess-UserDataService
    '{56f519ab-9df6-4345-8491-a4ba21ac825b}' # Microsoft-Windows-UserDataAccess-UnifiedStore
    '{99C66BA7-5A97-40D5-AA01-8A07FB3DB292}' # Microsoft-Windows-UserDataAccess-PimIndexMaintenance
    '{B9B2DE3C-3FBD-4F42-8FF7-33C3BAD35FD4}' # Microsoft-Windows-UserDataAccess-UserDataApis
    '{0BD19909-EB6F-4b16-8074-6DCE803F091D}' # Microsoft-Windows-UserDataAccess-Poom
    '{83A9277A-D2FC-4b34-BF81-8CEB4407824F}' # Microsoft-Windows-UserDataAccess-CEMAPI
    '{f5988abb-323a-4098-8a34-85a3613d4638}' # Microsoft-Windows-UserDataAccess-CallHistoryClient
    '{15773AD5-AA2F-422A-9129-4A83F4C19DB0}' # Microsoft.Windows.UserDataAccess.UserDataService
    '{cb76d769-a1ed-4fb1-98c3-266951610fd8}' # Microsoft.Windows.UserDataAccess.Unistore
    '{0a0a7808-8dda-4ba0-a656-b2c740ab9108}' # Microsoft.Windows.UserDataAccess.UserDataApisBase
    '{553ebe04-ceb2-47ee-b394-bb83b97de219}' # Microsoft.Windows.UserDataAccess.UserDataAccounts
    '{d6eac963-c24f-434d-be23-4aa21904148f}' # Microsoft.Windows.UserDataAccess.TaskApis
    '{ee3112cb-4b76-49eb-a73b-712ad05e18cb}' # Microsoft.Windows.UserDataAccess.EmailApis
    '{3f7fafe6-1dd2-4720-b75b-e3268a0e6120}' # Microsoft.Windows.UserDataAccess.ContactApis
    '{412f73f7-ebf9-466f-90e7-606accdbcd15}' # Microsoft.Windows.UserDataAccess.Cemapi
    '{a94f431e-5460-465f-bf2e-6245b56d6ce9}' # Microsoft.Windows.UserDataAccess.AppointmentApis
    '{E0A18F5C-07F3-4A44-B149-0F8F13EF6887}' # Microsoft.Windows.ApplicationModel.Chat.ChatMessageBlocking
    '{FCC174D3-8890-434A-812D-BDED72EDE356}' # Microsoft.Windows.Unistack.FailureTrigger
    '{870ac05a-7777-5c66-c3f0-c1f6b7129ef6}' # Microsoft.Windows.Messaging.Service
    '{1e2462be-b025-48da-8c1f-7b60b8ccae53}' # microsoft-windows-appmodel-messagingdatamodel
    '{3da5aa05-5152-551f-a243-80a4e743c70e}' # Microsoft.Windows.Messaging.App
)

$WMIBridgeProviders = @(
    '{A76DBA2C-9683-4BA7-8FE4-C82601E117BB}' # Microsoft.Windows.DeviceManagement.WmiBridge
)

$WERProviders = @(
    '{E46EEAD8-0C54-4489-9898-8FA79D059E0E}' # Microsoft-Windows-Feedback-Service-TriggerProvider
    '{2E4201B6-4891-4912-A139-23268D5EB46E}' # WerFaultTracingGuid
    '{31EC0DFD-E734-4181-9C80-C9974C40BCEB}' # TpClientWppGuid
    '{36082273-7635-44A5-8D35-D2A266538B00}' # WerMgrTracingGuid
    '{3E19A300-75D9-4027-86BA-948B70416220}' # WerConsoleTracingGuid
    '{5EF9EC44-FB87-4F51-AF4E-CED084013281}' # FaultRepTracingGuid
    '{6851ADEB-79DA-4250-A440-F1F52D28711D}' # WerSvcTracingGuid
    '{75638A28-E9ED-42B2-9F8F-C2B1F89CF5EE}' # InfraTracingGuid
    '{7930F74B-E328-4350-89C6-11FD93771488}' # WerFaultTracingGuid
    '{9760D9C2-2FBF-4CDA-889F-8DAB2BDD98B0}' # DWTracingGuid
    '{A0EF609D-0A14-424C-9270-3B2691A0A394}' # ErcLuaSupportTracingGuid
    '{DC02AB24-0AA6-4499-8D86-A8E5F83741F5}' # HangRepTracingGuid
    '{E2821408-C59D-418F-AD3F-AA4E792AEB79}' # SqmClientTracingGuid
    '{F904D5CC-2CCA-47B0-A3CE-A05944692545}' # WerFaultSilentProcessExitLibTracingGuid
    '{FCD00FEF-04FA-41C0-889E-AE613D97602B}' # WerUITracingGuid
    '{1377561D-9312-452C-AD13-C4A1C9C906E0}' # FaultReportingTracingGuid
    '{CC79CF77-70D9-4082-9B52-23F3A3E92FE4}' # WindowsErrorReportingTracingGuid
    '{97945555-b04c-47c0-b399-e453d509a5f0}' # WERSecureVerticalTracingGuid
    '{2b87e57e-7bd0-43a3-a278-02e62d59b2b1}' # WERVerticalTracingGuid
    '{3E0D88DE-AE5C-438A-BB1C-C2E627F8AECB}' # HangReporting
    '{4A743CBB-3286-435C-A674-B428328940E4}' # PSMTracingGuid
    '{D2440861-BF3E-4F20-9FDC-E94E88DBE1F6}' # BrokerInfrastructureWPP
    '{9C6FC32A-E17A-11DF-B1C4-4EBADFD72085}' # PLM WPP tracing
    '{EB65A492-86C0-406A-BACE-9912D595BD69}' # Microsoft-Windows-AppModel-Exec
)

$CodeIntegrityProviders = @(
    '{DDD9464F-84F5-4536-9F80-03E9D3254E5B}' # MicrosoftWindowsCodeIntegrityTraceLoggingProvider
    '{2e1eb30a-c39f-453f-b25f-74e14862f946}' # MicrosoftWindowsCodeIntegrityAuditTraceLoggingProvider
    '{4EE76BD8-3CF4-44a0-A0AC-3937643E37A3}' # Microsoft-Windows-CodeIntegrity
    '{EB65A492-86C0-406A-BACE-9912D595BD69}' # Microsoft-Windows-AppModel-Exec
    '{EF00584A-2655-462C-BC24-E7DE630E7FBF}' # Microsoft.Windows.AppLifeCycle
    '{382B5E24-181E-417F-A8D6-2155F749E724}' # Microsoft.Windows.ShellExecute
    '{072665fb-8953-5a85-931d-d06aeab3d109}' # Microsoft.Windows.ProcessLifetimeManager
)

$ClipboardProviders = @(
    '{f917a1ee-0a04-5157-9a8b-9ba716e318cb}' # Microsoft.Windows.ClipboardHistory.UI
    '{e0be2aaa-b6c3-5f17-4e86-1cde27b51ac1}' # Microsoft.Windows.ClipboardHistory.Service
    '{28d62fb0-2131-41d6-84e8-e2325867964c}' # Microsoft.Windows.AppModel.Clipboard
    '{3e0e3a92-b00b-4456-9dee-f40aba77f00e}' # Microsoft.Windows.OLE.Clipboard
    '{A29339AD-B137-486C-A8F3-88C9738E5379}' # Microsoft.Windows.ApplicationModel.DataTransfer.CloudClipboard
    '{ABB10A7F-67B4-480C-8834-8B049C428715}' # Microsoft.Windows.CDP.Core
    '{796F204A-44FC-47DF-8AE4-77C210BD5AF4}' # RdpClip
)

$MMCProviders = @(
    '{9C88041D-349D-4647-8BFD-2C0A167BFE58}' # MMC
)

$QuickAssistProviders = @(
    '{91558F59-B78A-4994-8B64-8067B33BDD71}' # Microsoft.RemoteAssistance
)

$FSLogixProviders = @(
    '{9a2c09eb-fbd6-5127-090f-402799cb18a2}' # Microsoft.FSLogix.Frxsvc
    '{5f7d6ea0-7bfa-5c0a-4674-acce76757f19}' # Microsoft.FSLogix.Frxccds
    '{83afe79f-c9c6-5152-3636-05de47c1fa72}' # Microsoft.FSLogix.Search
    '{65fa0e9f-db27-5053-a4e0-e40c42ba5271}' # Microsoft.FSLogix.UsermodeDll
    '{578c4cac-e98c-5315-f3e6-fbc0a97b286f}' # Microsoft.FSLogix.ConfigurationTool
    '{048a4a25-ff60-5d27-8f58-71c0f9d3fc92}' # Microsoft.FSLogix.RuleEditor
    '{f1a8d80a-2d4d-5dfc-7c26-88b5cce761c9}' # Microsoft.FSLogix.JavaRuleEditor
    '{6d14bf0a-be6f-592f-cbcc-61b5e8d18c5c}' # Microsoft.FSLogix.IE_Plugin
    '{f9317b16-badc-55b3-a0cf-9a0a126e12fd}' # Microsoft.FSLogix.FrxLauncher
    '{220d0827-a763-50ac-6999-a59a7ca5d316}' # Microsoft.FSLogix.TrayTool
    '{e5cd7d19-e708-5957-ba97-11858c57eb80}' # Microsoft.FSLogix.Frxdrvvt
    '{6352de6a-8fc2-5afe-a709-fb70e825dc24}' # Microsoft.FSLogix.Frxdrv
)

$WSCProviders = @(
    '{1B0AC240-CBB8-4d55-8539-9230A44081A5}' # SecurityCenter
    '{9DAC2C1E-7C5C-40eb-833B-323E85A1CE84}' # WSCInterop
    '{e6b5b34f-bd4d-5cdc-8346-ef4dc6cf1927}' # Microsoft.Windows.Security.WSC
)

$LicenseManagerProviders = @(
    '{5e30c57a-8730-4809-945e-0d5df7aa58e5}' # Microsoft.ClientLicensing.InheritedActivation
    '{CFBEA673-BF20-4BD8-B595-29B82D43DF39}' # Microsoft.ClipUp
    '{466F3B39-9929-45E6-B891-D867BD20B738}' # Microsoft.Windows.Licensing.UpgradeSubscription
    '{B94D76C5-9D56-454A-8D1B-6CA30898160E}' # Microsoft.ClipSvc
    '{4b0cf5b8-5962-479b-9635-7dfb7c8265bc}' # ClipCLoggingProvider
    '{961d7772-0a35-4869-89ad-056fbfc0e51f}' # Microsoft.Windows.LicensingCSP
    '{B4B126DE-32FE-4591-9AC5-B0778D79A0E7}' # Microsoft.ClipSp
    '{ED0C10A5-5396-4A96-9EE3-6F4AA0D1120D}' # Microsoft.ClipC
)

$ATAPortProviders = @(
    '{cb587ad1-cc35-4ef1-ad93-36cc82a2d319}' # Microsoft-Windows-ATAPort
    '{d08bd885-501e-489a-bac6-b7d24bfe6bbf}' # ataport guid
)

$CDROMProviders = @(
    '{9b6123dc-9af6-4430-80d7-7d36f054fb9f}' # Microsoft-Windows-CDROM
    '{A4196372-C3C4-42D5-87BF-7EDB2E9BCC27}' # cdrom.sys
    '{944a000f-5f60-4e5a-86fd-d55b84b543e9}' # WPP_GUID_UDFD
    '{6B1DB052-734F-4E23-AF5E-6CD8AE459F98}' # WPP_GUID_UDFS
    '{F8036571-42D9-480A-BABB-DE7833CB059C}' # IMAPI2FS Tracing
    '{0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E9D}' # IMAPI2 Concatenate Stream
    '{0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E91}' # IMAPI2 Disc Master
    '{0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E93}' # IMAPI2 Disc Recorder
    '{0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E92}' # IMAPI2 Disc Recorder Enumerator
    '{0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E90}' # IMAPI2 dll
    '{0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E9E}' # IMAPI2 Interleave Stream
    '{0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E97}' # IMAPI2 Media Eraser
    '{0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E9F}' # IMAPI2 MSF
    '{0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7EA0}' # IMAPI2 Multisession Sequential
    '{0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E9C}' # IMAPI2 Pseudo-Random Stream
    '{0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E9A}' # IMAPI2 Raw CD Writer
    '{0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E98}' # IMAPI2 Standard Data Writer
    '{0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E99}' # IMAPI2 Track-at-Once CD Writer
    '{0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E94}' # IMAPI2 Utilities
    '{0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E96}' # IMAPI2 Write Engine
    '{0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E9B}' # IMAPI2 Zero Stream
)

$FailoverClusteringProviders = @(
    '{9F7FE238-9505-4B84-8B33-268C9204268E}' # Microsoft.Windows.Clustering.ClusterResource
    '{50d577a6-b3e7-4642-9e4d-05200376a5cf}' # Microsoft.Windows.Server.FailoverClustering.Failure
    '{f40422bd-f483-449a-99c7-c4546950112c}' # Microsoft.Windows.Server.FailoverClusteringDevelop
    '{3122168f-2432-45f0-b91c-3af363c14999}' # ClusApiTraceLogProvider
    '{8bdb2a89-5d40-4a5f-afd8-8b1e0ce3abc9}' # Microsoft-Windows-WSDR
    '{baf908ea-3421-4ca9-9b84-6689b8c6f85f}' # Microsoft-Windows-FailoverClustering
    '{a82fda5d-745f-409c-b0fe-18ae0678a0e0}' # Microsoft-Windows-FailoverClustering-Client
    '{0DAD9561-2E3B-49BB-93D7-B49603BA6173}' # DVFLT
    '{0461be3c-bc15-4bad-9a9e-51f3fadfec75}' # Microsoft-Windows-FailoverClustering-WMIProvider(nano server)
    '{b529c110-72ba-4e7f-8ba7-366e3f5faeb0}' # Microsoft.Windows.Clustering.WmiProvider
    '{282968B4-215F-4568-B4A5-C2E5467C301E}' # Microsoft.Windows.Clustering.ClusterService
    '{60431de6-ecae-4926-8e10-0918d219a0a1}' # Microsoft.Windows.Server.FailoverClustering.Set.Critical
    '{49F59745-7F56-4082-A01A-83BC089D1ADD}' # Microsoft.Windows.Health
    '{372968B4-215F-4568-B4A5-C2E5467C301E}' # Microsoft.Windows.Clustering.EbodTargetMgr
    '{1de9cea2-60ce-49fa-a8b7-84139ac12b31}' # Microsoft.Windows.Clustering.S2DCache
    '{0461be3c-bc15-4bad-9a9e-51f3fadfec75}' # Microsoft-Windows-FailoverClustering-WMIProvider
    '{ff3e7036-643f-430f-b015-2933466ff0fd}' # Microsoft-Windows-FailoverClustering-WMI
    '{11B3C6B7-E06F-4191-BBB9-7099FFF55614}' # Microsoft-Windows-FailoverClustering-Manager
    '{f0a43898-4017-4d3b-acac-ff7fb8ac63cd}' # Microsoft-Windows-Health
    '{C1FCCEB3-3F19-42A9-95B9-27B550FA1FBA}' # Microsoft-Windows-FailoverClustering-NetFt
    '{10629806-46F2-4366-9092-53025E067E8C}' # Microsoft-Windows-ClusterAwareUpdating
    '{9B9E93D6-5569-4179-8C8A-5201CB2B9536}' # Microsoft-Windows-ClusterAwareUpdating-Management
    '{7FEF367F-E76C-4592-9912-E12B36A99780}' # Microsoft-Windows-FailoverClustering-ClusDisk-Diagnostic
    '{5d9e8ca1-8634-457b-8d0b-3ba944bc2ff0}' # Microsoft-Windows-FailoverClustering-TargetMgr-Diagnostic
    '{6F0771DD-4096-4E5E-A549-FC1238F5A1B2}' # Microsoft-Windows-FailoverClustering-ClusTflt-Diagnostic
    '{29c07d0e-e5a0-4e85-a004-1f668531ce22}' # Microsoft-Windows-FailoverClustering-Clusport-Diagnostic
    '{4339CD79-93D6-4F55-A96A-F7762E8AF2DE}' # Microsoft-Windows-FailoverClustering-ClusPflt-Diagnostic
    '{40CB8729-8896-4CAB-90E0-2A3AEBA730C2}' # Microsoft-Windows-FailoverClustering-ClusHflt-Diagnostic
    '{E68AB9C0-49F4-4786-A6E0-F323E0BE590C}' # Microsoft-Windows-FailoverClustering-ClusDflt-Diagnostic
    '{53A840C4-8E2B-4D39-A3F6-708834AA4620}' # Microsoft-Windows-FailoverClustering-ClusCflt-Diagnostic
    '{923BCB94-58D2-42BE-BBA9-B1315F363838}' # Microsoft-Windows-FailoverClustering-ClusBflt-Diagnostic
    '{0ac0708a-a44e-49ef-aa7e-fbe8ccc603a6}' # Microsoft-Windows-FailoverClustering-SoftwareStorageBusTarget
    '{7F8DA3B5-A58F-481E-9637-D41435AE6D8B}' # Microsoft-Windows-SDDC-Management
    '{6e580567-c67c-4b96-934e-fc2996e103ae}' # ClusDiskLogger
    '{BBB672F4-E56A-4529-90C0-1421E27DE4BE}' # svhdxpr
    '{b6c164c7-4152-4b94-af14-0dac3d0556a3}' # StorageQoSTraceGuid
    '{7e66368d-b895-45f2-811f-fb37940421a6}' # NETFT
    '{8a391cc0-6303-4a25-833f-e7db345941d6}' # VBus
    '{f8f6ae53-b3b3-451f-b204-6b62550efb5c}' # cbflt
    '{EB94F195-9596-49EC-825D-6329F48BD6E9}' # cdflt
    '{7ba7dbd4-e7a9-47db-ac47-4ac1182a82f5}' # cbflt
    '{88AE0E2D-0377-48A1-85C5-FBCC32ACB6BA}' # SddcResGuid
    '{4FA1102E,CC1D,4509,A69F,121E2CC96F9C}' # SddcWmiGuid
)

$CSVFSProviders = @(
    '{0cfda7f5-7549-575e-d095-dcc1e4fbaa3f}' # Microsoft.Windows.Server.CsvFsCritical
    '{4e6177a5-c0a7-4d9b-a686-56ed5435a908}' # nflttrc
    '{B421540C-1FC8-4c24-90CC-C5166E1DE302}' # CSVFLT
    '{d82dba12-8b70-49ee-b844-44d0885951d2}' # CSVFLT
    '{4e6177a5-c0a7-4d9b-a686-56ed5435a904}' # VBus
    '{af14af06-a558-4ff0-a061-9080e33212d6}' # CsvCache
    '{151D3C03-E442-4C4F-AF20-BD48FF41F793}' # Microsoft-Windows-FailoverClustering-CsvFlt-Diagnostic
    '{6a86ae90-4e9b-4186-b1d1-9ce0e02bcbc1}' # Microsoft-Windows-FailoverClustering-CsvFs-Diagnostic
)

$DedupProviders = @(
    '{F9FE3908-44B8-48D9-9A32-5A763FF5ED79}' # Microsoft-Windows-Deduplication
    '{1D5E499D-739C-45A6-A3E1-8CBE0A352BEB}' # Microsoft-Windows-Deduplication-Change
    '{5ebb59d1-4739-4e45-872d-b8703956d84b}' # SrmTracingProviderGuid
    '{c503ed7b-d3d1-421b-97cd-22f4e7445f2a}' # Microsoft.Windows.Deduplication.Service
    '{c503ed7b-d3d1-421b-97cd-22f4e7455f2a}' # Microsoft.Windows.Deduplication.Pipeline/Store/DataPort/Scanner
    '{611b641a-8c01-449b-ab5b-a9f18adc4e3c}' # DdpFltLogGuid
    '{767c881e-f7f5-418e-a428-a113c3a8630a}' # DdpFltTraceGuid
)

$FSRMProviders = @(
    '{39af31ab-064d-494b-a0f7-cc90215bdac0}' # Microsoft.Windows.FSRM
    '{3201c659-d580-4833-b17d-1adaf643c64c}' # SrmTracingProviderGuid
    '{6e82d70f-403d-4194-b724-85109b2f2028}' # SrmTracingEventGuid
    '{1214600f-df79-4a03-94f5-65d7cab4fd16}' # Quota
    '{DB4A5343-AC92-4B83-9D84-7ED8FADD7AA5}' # Datascrn
    '{1C7BC728-8199-48BE-BD4D-406A63303C8D}' # Cbafilt
    '{F3C5E28E-63F6-49C7-A204-E48A1BC4B09D}' # Microsoft-Windows-FilterManager
)

$HyperVProviders = @(
    '{AE7E4D1D-16C7-4807-A2E4-980EDF16D031}' # Microsoft.Windows.HyperV.SysprepProvider
    '{949B9EDC-ADDA-4712-A3E7-D2DCA33E84E8}' # Microsoft.Windows.HyperV.UpgradeComplianceCheck
    '{4DDF50D0-75DE-4FBE-8F08-F8936638E7A1}' # Microsoft.Windows.HyperV.Management
    '{85A7888C-4EF7-5C56-643F-FBD6DC10FEBE}' # Microsoft.Windows.HyperV.KvpExchange
    '{d90b9468-67f0-5b3b-42cc-82ac81ffd960}' # Microsoft.Windows.Subsystem.Lxss
    '{b99cdb5a-039c-5046-e672-1a0de0a40211}' # Microsoft.Windows.Lxss.Manager
    '{06C601B3-6957-4F8C-A15F-74875B24429D}' # Microsoft.Windows.HyperV.Worker
    '{7568b40b-dc66-5a30-55a1-d0ef61b56ac8}' # Microsoft.Windows.HyperV.Worker.Intercepts
    '{5e01db5e-1944-5314-c040-c90b965ea3d3}' # Microsoft.Windows.HyperV.Worker.MemoryManager
    '{1111450B-DACC-40A3-84AB-F7DBA4A6E63A}' # Microsoft.Windows.HyperV.VID
    '{5931D877-4860-4ee7-A95C-610A5F0D1407}' # Microsoft-Windows-Hyper-V-VID
    '{f83552c4-a4e8-50f7-b2d4-a9705c474490}' # Microsoft.Windows.HyperV.TimeSync
    '{a20b1fd7-ac6e-4e79-81c9-23b3c5e97444}' # Microsoft.Windows.HyperV.PCIProxy
    '{b2ed3bdb-cd74-5b2c-f660-85079ca074b3}' # Microsoft.Windows.HyperV.Socket
    '{544d0787-9f6d-432e-8414-e035a8b0541d}' # Microsoft.Windows.HyperV.Storvsp
    '{8dfb8c22-55c0-494d-8c75-a4cc35b0c535}' # Microsoft.Windows.HyperV.Vsmb
    '{2174371b-d5f6-422b-bfc4-bb6f97ddaa84}' # Microsoft.Windows.HyperV.Storage
    '{D0E4BC17-34C7-43fc-9A72-D89A59D6979A}' # Microsoft.Windows.HostNetworkingService.PrivateCloudPlugin
    '{6C28C7E5-331B-4437-9C69-5352A2F7F296}' # Microsoft-Windows-Hyper-V-VmsIf
    '{67DC0D66-3695-47C0-9642-33F76F7BD7AD}' # Microsoft.Windows.Hyper-V.VmSwitch
    '{152FBE4B-C7AD-4f68-BADA-A4FCC1464F6C}' # Microsoft.Windows.Hyper-V.NetVsc
    '{93f693dc-9163-4dee-af64-d855218af242}' # Microsoft-Windows-Hyper-V-NetMgmt
    '{0b4745b0-c990-4780-965a-391afd9424b8}' # Microsoft.Windows.HyperV.NetworkMigrationPlugin
    '{F20F4146-DB1D-4FE8-8C86-49BF5CF7390D}' # L2BridgeTraceLoggingProvider
    '{0c885e0d-6eb6-476c-a048-2457eed3a5c1}' # Microsoft-Windows-Host-Network-Service
    '{f5bf2dc5-fd9c-546d-f37b-9cbe631a065b}' # Microsoft.Windows.HyperV.DynamicMemory
    '{4f542162-e9cf-5eca-7f74-1fb63a59a6c2}' # Microsoft.Windows.HyperV.GuestCrashDump
    '{a572eeb4-c3f7-5b0e-b669-bb200931d134}' # Microsoft.Windows.HyperV.Worker.VmbusPipeIO
    '{51ddfa29-d5c8-4803-be4b-2ecb715570fe}' # Microsoft-Windows-Virtualization-Worker
    '{e5ea3ca6-5eb0-597d-504a-2fd09ccdefda}' # ICVdevDeviceEtwTrace
    '{339aad0a-4124-4968-8147-4cbbb1f8b3d5}' # Microsoft-Windows-Virtualization-UiDevices
    '{13eae551-76ca-4ddc-b974-d3a0f8d44a03}' # Microsoft-Windows-Virtualization-Tpm
    '{7b0ea079-e3bc-424a-b2f0-e3d8478d204b}' # Microsoft-Windows-VStack-VSmb
    '{4D20DF22-E177-4514-A369-F1759FEEDEB3}' # Microsoft-Windows-VIRTDISK
    '{EDACD782-2564-4497-ADE6-7199377850F2}' # Microsoft-Windows-VStack-SynthStor
    '{6c3e21aa-36c0-5476-818a-3d71fc67c9e8}' # Microsoft-Windows-Hyper-V-NvmeDirect
    '{8f9df503-1d12-49ec-bb28-f6ec42d361d4}' # Microsoft-Windows-Virtualization-serial
    '{c29c4fb7-b60e-4fff-9af9-cf21f9b09a34}' # Microsoft-Windows-VStack-SynthNic
    '{a86e166e-7d3c-402d-8fe0-2a3e62c93864}' # Microsoft-Windows-Virtualization-Worker-GPUP
    '{B1D080A6-F3A5-42F6-B6F1-B9FD86C088DA}' # Microsoft-Windows-Hyper-V-DynMem
    '{c7c9e4f7-c41d-5c68-f104-d72a920016c7}' # Microsoft-Windows-Hyper-V-CrashDump
    '{de9ba731-7f33-4f44-98c9-6cac856b9f83}' # Microsoft-Windows-Virtualization-Chipset
    '{02f3a5e3-e742-4720-85a5-f64c4184e511}' # Microsoft-Windows-Virtualization-Config
    '{17103E3F-3C6E-4677-BB17-3B267EB5BE57}' # Microsoft-Windows-Hyper-V-Compute
    '{45F54D37-2377-4B64-B396-370E31ACB204}' # Microsoft-Windows-Hyper-V-ComputeCExec
    '{AF7FD3A7-B248-460C-A9F5-FEC39EF8468C}' # Microsoft-Windows-Hyper-V-ComputeLib
    '{6066F867-7CA1-4418-85FD-36E3F9C0600C}' # Microsoft-Windows-Hyper-V-VMMS
    '{0461BE3C-BC15-4BAD-9A9E-51F3FADFEC75}' # Microsoft-Windows-FailoverClustering-WMIProvider
    '{FF3E7036-643F-430F-B015-2933466FF0FD}' # Microsoft-Windows-FailoverClustering-WMI
    '{177D1599-9764-4E3A-BF9A-C86887AADDCE}' # Microsoft-Windows-Hyper-V-VmbusVdev
    '{09242393-1349-4F4D-9FD7-59CC79F553CE}' # Microsoft-Windows-Hyper-V-EmulatedNic
    '{2ED5C5DF-6026-4E25-9FB1-9A08701125F3}' # Microsoft.Windows.HyperV.VMBus
    '{2B74A015-3873-4C56-9928-EA80C58B2787}' # Heartbeat VDEV (vmicheartbeat)
    '{1CEB22B1-97FF-4703-BEB2-333EB89B522A}' # Microsoft-Windows-Hyper-V-VMSP (VM security process implementation)
    '{AE3F5BF8-AB9F-56D6-29C8-8C312E2FAEC2}' # Microsoft-Windows-Hyper-V-Virtual-PMEM
    '{DA5A028B-B248-4A75-B60A-024FE6457484}' # Microsoft-Windows-Hyper-V-EmulatedDevices
    '{6537FFDF-5765-517E-C03C-55A8E5A97C10}' # Microsoft-Windows-Hyper-V-KernelInt
    '{52FC89F8-995E-434C-A91E-199986449890}' # Microsoft-Windows-Hyper-V-Hypervisor
    '{82DA50E7-D261-4BD1-BBB9-3213E0EFE360}' # Microsoft.Windows.HyperV.MigrationPlugin
    '{C3A331B2-AF4F-5472-FD2F-4313035C4E77}' # Microsoft.Windows.HyperV.GpupVDev
    '{06C601B3-6957-4F8C-A15F-74875B24429D}' # VmwpTelemetryProvider (VmWpStateChange)
    '{8B0287F8-755D-4BC8-BD76-4CE327C4B78B}' # Microsoft-Windows-Hyper-V-WorkerManager
    '{9193A773-E60D-4171-8468-05C000581B71}' # Image Management Service (vhdsvc)
    '{0A18FF18-5362-4739-9671-78023D747B70}' # Virtual Network Management Service (nvspwmi)
    '{86E15E01-EDF1-4AC7-89CF-B19563FD6894}' # Emulated Storage VDEV (emulatedstor)
    '{82D60869-5ADA-4D49-B76A-309B09666584}' # KVP Exchange VDEV (vmickvpexchange)
    '{BC714241-8EDC-4CE3-8714-AA0B51F98FDF}' # Shutdown VDEV (vmicshutdown)
    '{F152DC14-A3A0-4258-BECE-69A3EE4C2DE8}' # Time Synchronization VDEV (vmictimesync)
    '{67E605EE-A4D8-4C46-AE50-893F31E13963}' # VSS VDEV (vmicvss)
    '{64E92ABC-910C-4770-BD9C-C3C54699B8F9}' # Clustering Resource DLL (vmclusres)
    '{5B621A17-3B58-4D03-94F0-314F4E9C79AE}' # Synthetic Fibre Channel VDEV (synthfcvdev)
    '{6357c13a-2eb3-4b91-b580-79682eb76986}' # Virtual FibreChannel Management Service (fcvspwmi)
    '{2ab5188c-5915-4629-9f8f-b3b20c78d1b0}' # VM Memory-Preserving Host Update DLL (vmphu)
)

$VHDMPProviders = @(
    '{A9AB8791-8619-4FFF-9F24-E1BB60075972}' # Microsoft-Windows-Hyper-V-VHDMP(WinBlue)
    '{3C70C3B0-2FAE-41D3-B68D-8F7FCAF79ADB}' # Microsoft-Windows-Hyper-V-VHDMP
    '{e14dcdd9-d1ec-4dc3-8395-a606df8ef115}' # virtdisk
    '{9193A773-E60D-4171-8468-05C000581B71}' # Image Management Service (vhdsvc)
    '{f96abc17-6a5e-4a49-a3f4-a2a86fa03846}' # storvsp
    '{52323364-b587-4b4c-9293-ca9904a5c04f}' # storqosflt
)

$ISCSIProviders = @(
    '{1babefb4-59cb-49e5-9698-fd38ac830a91}' # iScsi
)

$NFSProviders = @(
    '{3c33d8b3-66fa-4427-a31b-f7dfa429d78f}' # NfsSvrNfsGuid
    '{fc33d8b3-66fa-4427-a31b-f7dfa429d78f}' # NfsSvrNfsGuid2
    '{57294EFD-C387-4e08-9144-2028E8A5CB1A}' # NfsSvrNlmGuid
    '{CC9A5284-CC3E-4567-B3F6-3EB24E7CFEC5}' # MsNfsFltGuid
    '{f3bb9731-1d9f-4b8e-a42e-203bf1a32300}' # Nfs4SvrGuid
    '{53c16bac-175c-440b-a266-1e5d5f38313b}' # OncRpcXdrGuid
    '{94B45058-6F59-4696-B6BC-B23B7768343D}' # rpcxdr
    '{e18a05dc-cce3-4093-b5ad-211e4c798a0d}' # PortMapGuid
    '{355c2284-61cb-47bb-8407-4be72b5577b0}' # NfsRdrGuid
    '{6361f674-c2c0-4f6b-ae19-8c62f47ae3fb}' # NfsClientGuid
    '{c4c52165-ad74-4b70-b62f-a8d35a135e7a}' # NfsClientGuid
    '{746A1133-BC1E-47c7-8C95-3D52C39114F9}' # Microsoft-Windows-ServicesForNFS-Client
    '{6E1CBBE9-8C4B-4003-90E2-0C2D599A3EDC}' # Microsoft-Windows-ServicesForNFS-Portmapper
    '{F450221A-07E5-403A-A396-73923DFB2CAD}' # Microsoft-Windows-ServicesForNFS-NFSServerService
    '{3D888EE4-5A93-4633-91E7-FFF8AFD89A7B}' # Microsoft-Windows-ServicesForNFS-ONCRPC
    '{A0CC474A-06CA-427C-BDFF-84733163E262}' # Microsoft-Windows-ServicesForNFS-Cluster
)

$PNPProviders = @(
    '{63aeffcd-648e-5fc0-b4e7-a39a4e6612f8}' # Microsoft.Windows.InfRemove
    '{2E5950B2-1F5D-4A52-8D1F-4E656C915F57}' # Microsoft.Windows.PNP.DeviceManager
    '{F52E9EE1-03D4-4DB3-B2D4-1CDD01C65582}' # PnpInstal
    '{9C205A39-1250-487D-ABD7-E831C6290539}' # Microsoft-Windows-Kernel-PnP
    '{8c8ebb7e-a4b7-4336-bddb-4a0aea0f535a}' # Microsoft.Windows.Sysprep.PnP
    '{0e0fe12b-e926-44d2-8cf1-8a62a6d44036}' # Microsoft.Windows.DriverStore
    '{139299bb-9394-5058-dd33-9422e5903fc3}' # Microsoft.Windows.SetupApi
    '{a23bd382-12ab-4f02-a0d7-273153f8b65a}' # Microsoft.Windows.DriverInstall
    '{059a2460-1077-4446-bdeb-5221de48b9e4}' # Microsoft.Windows.DriverStore.DriverPackage
    '{96F4A050-7E31-453C-88BE-9634F4E02139}' # Microsoft-Windows-UserPnp
    '{A676B545-4CFB-4306-A067-502D9A0F2220}' # PlugPlay
    '{84051b98-f508-4e54-82fa-8865c697c3b1}' # Microsoft-Windows-PnPMgrTriggerProvider
    '{96F4A050-7E31-453C-88BE-9634F4E02139}' # Microsoft-Windows-UserPnp
    '{D5EBB80C-4407-45E4-A87A-015F6AF60B41}' # Microsoft-Windows-Kernel-PnPConfig
    '{FA8DE7C4-ACDE-4443-9994-C4E2359A9EDB}' # claspnp
    '{F5D05B38-80A6-4653-825D-C414E4AB3C68}' # Microsoft-Windows-StorDiag
    '{5590bf8b-9781-5d78-961f-5bb8b21fbaf6}' # Microsoft.Windows.Storage.Classpnp
)

$StorageSpaceProviders = @(
    '{595f7f52-c90a-4026-a125-8eb5e083f15e}' # Microsoft-Windows-StorageSpaces-Driver
    '{aa4c798d-d91b-4b07-a013-787f5803d6fc}' # Microsoft-Windows-StorageSpaces-ManagementAgent
    '{69c8ca7e-1adf-472b-ba4c-a0485986b9f6}' # Microsoft-Windows-StorageSpaces-SpaceManager
    '{A9C7961E-96A0-4E3F-9066-7734A13101C1}' # Microsoft.Windows.Storage.SpaceControl
    '{0254f21f-4809-477e-ad36-c812a8c631a1}' # Microsoft.Windows.Storage.Spaceman
    '{e7d0ad21-b086-406d-be46-a701a86a5f0a}' # Microsoft.Windows.Storage.Spaceport
    '{929c083b-4c64-410a-bfd4-8ca1b6fce362}' # Spaceport
)

$StorageProviders = @(
    '{F96ABC17-6A5E-4A49-A3F4-A2A86FA03846}' # StorVspDriverTraceGuid
    '{8B86727C-E587-4B89-8FC5-D1F24D43F69C}' # storswtr
    '{8E9AC05F-13FD-4507-85CD-B47ADC105FF6}' # mplib
    '{DEDADFF5-F99F-4600-B8C9-2D4D9B806B5B}' # msdsm
    '{1BABEFB4-59CB-49E5-9698-FD38AC830A91}' # iScsi
    '{945186BF-3DD6-4F3F-9C8E-9EDD3FC9D558}' # Disk Class Driver Tracing Provider
    '{FA8DE7C4-ACDE-4443-9994-C4E2359A9EDB}' # Classpnp Driver Tracing Provider
    '{467C1914-37F0-4C7D-B6DB-5CD7DFE7BD5E}' # Mountmgr
    '{E3BAC9F8-27BE-4823-8D7F-1CC320C05FA7}' # Microsoft-Windows-MountMgr
    '{F5204334-1420-479B-8389-54A4A6BF6EF8}' # VolMgr
    '{9f7b5df4-b902-48bc-bc94-95068c6c7d26}' # Microsoft-Windows-Volume
    '{0BEE3BC5-A50C-4EC3-A0E0-5AD11F2455A3}' # Partmgr
    '{da58fbef-c209-4bee-84ed-027c421f31bf}' # Volsnap(wpp)
    '{67FE2216-727A-40CB-94B2-C02211EDB34A}' # Microsoft-Windows-VolumeSnapshot-Driver
    '{CB017CD2-1F37-4E65-82BC-3E91F6A37559}' # Volsnap(manifest based)
    '{6E580567-C67C-4B96-934E-FC2996E103AE}' # ClusDiskLogger
    '{C9C5D896-6FA9-49CD-9BFD-BF5C232C1124}' # Microsoft.Windows.Storage.Msdsm
    '{2CC00407-E9D9-4B5E-A760-F4217C9B0170}' # Microsoft.Windows.Storage.Mpio
    '{cc7b00d3-75c9-42cc-ae56-bf6d66a9d15d}' # Microsoft-Windows-MultipathIoControlDriver
    '{9282168F-2432-45F0-B91C-3AF363C149DD}' # StorageWMI
    '{1B992FD1-0CDD-4D6A-B55E-08C61E78D2C2}' # Microsoft.Windows.Storage.MiSpace
)

$StorageReplicaProviders = @(
    '{35a2925c-30a3-43eb-b737-03e9659955e2}' # Microsoft-Windows-StorageReplica-Cluster
    '{f661b376-6e59-4483-89f8-d5aca1816ead}' # Microsoft-Windows-StorageReplica
    '{ce171fd7-a5ba-4d95-926b-6dc4d89e8171}' # Microsoft-Windows-StorageReplica-Service
    '{fadca505-ad5e-47a8-9047-b3888ba4a8fc}' # WvrCimGuid
    '{634af965-fe67-49cf-8268-af99f62d1a3e}' # WvrFltGuid
    '{8e37fc9c-8656-46da-b40d-34d97a532d09}' # WvrFltGuid
    '{0e0d5a31-e93f-40d6-83bb-e7663a4f54e3}' # Microsoft.Windows.Server.StorageReplicaCritical
)

$StorportProviders = @(
    '{8B86727C-E587-4B89-8FC5-D1F24D43F69C}' # storport
    '{4EEB8774-6C4C-492F-8F2F-5EE4721B7BF7}' # Microsoft.Windows.Storage.Storport
    '{C4636A1E-7986-4646-BF10-7BC3B4A76E8E}' # Microsoft-Windows-StorPort
)

$StorsvcProviders = @(
    '{AEA3A1A8-EA43-4802-B750-2DD678910779}' # StorageServiceProvider
    '{A963A23C-0058-521D-71EC-A1CCE6173F21}' # Microsoft-Windows-Storsvc	
)

$USBProviders = @(
    '{C88A4EF5-D048-4013-9408-E04B7DB2814A}' # Microsoft-Windows-USB-USBPORT
    '{7426a56b-e2d5-4b30-bdef-b31815c1a74a}' # Microsoft-Windows-USB-USBHUB
    '{D75AEDBE-CFCD-42B9-94AB-F47B224245DD}' # usbport
    '{B10D03B8-E1F6-47F5-AFC2-0FA0779B8188}' # usbhub
    '{30e1d284-5d88-459c-83fd-6345b39b19ec}' # Microsoft-Windows-USB-USBXHCI
    '{36da592d-e43a-4e28-af6f-4bc57c5a11e8}' # Microsoft-Windows-USB-UCX
    '{AC52AD17-CC01-4F85-8DF5-4DCE4333C99B}' # Microsoft-Windows-USB-USBHUB3
    '{6E6CC2C5-8110-490E-9905-9F2ED700E455}' # USBHUB3
    '{6fb6e467-9ed4-4b73-8c22-70b97e22c7d9}' # UCX
    '{9F7711DD-29AD-C1EE-1B1B-B52A0118A54C}' # USBXHCI
    '{04b3644b-27ca-4cac-9243-29bed5c91cf9}' # UsbNotificationTask
    '{468D9E9D-07F5-4537-B650-98389559206E}' # UFX01000
    '{8650230d-68b0-476e-93ed-634490dce145}' # SynopsysWPPGuid
    '{B83729F3-8D84-4BEA-897B-CD9FD667BA01}' # UsbFnChipidea
    '{0CBB6922-F6B6-4ACA-8BF0-81624B491364}' # UsbdTraceGuid
    '{bc6c9364-fc67-42c5-acf7-abed3b12ecc6}' # USBCCGP
    '{3BBABCCA-A210-4570-B501-0E34D88A88FB}' # SDFUSBXHCI
    '{f3006b12-1d83-48d2-948d-6bcd002c14dc}' # UDEHID
    # There are too many GUIDs for USB. So need review on which GUIDs is helpful.
)

$ServerManagerProviders = @(
    '{C2E6D0D9-5DF8-4C77-A82B-C96C84579543}' # Microsoft-Windows-ServerManager-ManagementProvider
    '{D8D37081-10BD-4A89-A971-1CDA6899BDB3}' # Microsoft-Windows-ServerManager-MultiMachine
    '{66AF9A38-2D94-11E0-A076-8534E0D72085}' # Microsoft-Windows-ServerManager-DeploymentProvider
    '{6e27f02d-8a55-477e-88b5-6f1ba07e14b4}' # Microsoft-Windows-ServerManager-ConfigureSMRemoting
)

$WVDProviders = @(
    '{C3B02229-FF93-4D28-ACFC-4FB28AC6CDB5}' # RdClientWinRT
    '{97A820E5-5F64-4573-8114-99B450D0B067}' # RDCoreApp
    '{6FA2A01C-9F89-474B-A71A-A783925EFE45}' # RDCoreNanoCom
)

$MSRAProviders = @(
    '{5b0a651a-8807-45cc-9656-7579815b6af0}' # Microsoft-Windows-RemoteAssistance
)

$DMProviders = @(
    '{9bfa0c89-0339-4bd1-b631-e8cd1d909c41}' # Microsoft.Windows.StoreAgent.Telemetry
    '{E0C6F6DE-258A-50E0-AC1A-103482D118BC}' # Microsoft-Windows-Install-Agent
    '{F36F2574-AC04-4A3D-8263-B97DA864B0BC}' # Microsoft-WindowsPhone-EnrollmentClient-Provider
    '{0e71a49b-ca69-5999-a395-626493eb0cbd}' # Microsoft.Windows.EnterpriseModernAppManagement
    '{FADD8651-7B42-423F-B37D-3B98B9E81560}' # Microsoft.Windows.DeviceManagement.SyncMLDpu
    '{18F2AB69-92B9-47E4-B9DB-B4AC2E4C7115}' # Microsoft.Windows.DeviceManagement.WAPDpu
    '{F9E3B648-9AF1-4DC3-9A8E-BF42C0FBCE9A}' # Microsoft.Windows.EnterpriseManagement.Enrollment
    '{E74EFD1A-B62D-4B83-AB00-66F4A166A2D3}' # Microsoft.Windows.EMPS.Enrollment
    '{0BA3FB88-9AF5-4D80-B3B3-A94AC136B6C5}' # Microsoft.Windows.DeviceManagement.ConfigManager2"
    '{76FA08A3-6807-48DB-855D-2C12702630EF}' # Microsoft.Windows.EnterpriseManagement.ConfigManagerHook
    '{FFDB0CFD-833C-4F16-AD3F-EC4BE3CC1AF5}' # Microsoft.Windows.EnterpriseManagement.PolicyManager
    '{5AFBA129-D6B7-4A6F-8FC0-B92EC134C86C}' # Microsoft.Windows.EnterpriseManagement.DeclaredConfiguration
    '{F058515F-DBB8-4C0D-9E21-A6BC2C422EAB}' # Microsoft.Windows.DeviceManagement.SecurityPolicyCsp
    '{33466AA0-09A2-4C47-9B7B-1B8A4DC3A9C9}' # Microsoft-Windows-DeviceManagement-W7NodeProcessor
    '{F5123688-4272-436C-AFE1-F8DFA7AB39A8}' # Microsoft.Windows.DeviceManagement.DevDetailCsp
    '{FE5A93CC-0B38-424A-83B0-3C3FE2ACB8C9}' # Microsoft.Windows.DeviceManagement.DevInfo
    '{E1A8D70D-11F0-420E-A170-29C6B686342D}' # Microsoft.Windows.DeviceManagement.DmAccCsp
    '{6222F3F1-237E-4B0F-8D12-C20072D42197}' # Microsoft.Windows.EnterpriseManagement.ResourceManagerUnenrollHook
    '{6B865228-DEFA-455A-9E25-27D71E8FE5FA}' # Microsoft.Windows.EnterpriseManagement.ResourceManager
    '{797C5746-634F-4C59-8AE9-93F900670DCC}' # Microsoft.Windows.DeviceManagement.OMADMPRC
    '{0EC685CD-64E4-4375-92AD-4086B6AF5F1D}' # Microsoft.Windows.DeviceManagement.OmaDmClient
    '{F3B5BC3C-A182-4F7D-806D-070012D8D16D}' # Microsoft.Windows.DeviceManagement.SessionManagement
    '{86625C04-72E1-4D36-9C86-CA142FD0A946}' # Microsoft.Windows.DeviceManagement.OmaDmApiProvider
)

$ImmersiveUIProviders = @(
    '{74827cbb-1e0f-45a2-8523-c605866d2f22}' # Microsoft-Windows-WindowsUIImmersive
    '{ee818f02-698c-48be-8ff2-326c6dd34db5}' # SystemInitiatedFeedbackLoggingProvider
    '{EE9969D1-3438-42EA-B879-1AA52A135844}' # HostingFramework
    '{7D45E281-B342-4B07-9061-43056E1C4BA4}' # PopupWindow
)

$HTTPProviders = @(
    '{1a211ee8-52db-4af0-bb66-fb8c9f20b0e2}' # Microsoft.OSG.Web.WinInet
    '{43D1A55C-76D6-4f7e-995C-64C711E5CAFE}' # Microsoft-Windows-WinINet
    '{4E749B6A-667D-4c72-80EF-373EE3246B08}' # WinInet
    '{1070f044-721c-504b-c01c-671dadcbc77d}' # WinHTTP(Tracelogging)
    '{7D44233D-3055-4B9C-BA64-0D47CA40A232}' # Microsoft-Windows-WinHttp
    '{5402E5EA-1BDD-4390-82BE-E108F1E634F5}' # Microsoft-Windows-WinINet-Config
    '{B3A7698A-0C45-44DA-B73D-E181C9B5C8E6}' # WinHttp(WPP)
)

$CameraProviders = @(
    '{e647b5bf-99a4-41fe-8789-56c6bb3fa9c8}' # Microsoft.Windows.Apps.Camera
    '{f4296e10-4a0a-506c-7899-eb93382208e6}' # Microsoft.Windows.Apps.Camera
    '{EF00584A-2655-462C-BC24-E7DE630E7FBF}' # Microsoft.Windows.AppLifeCycle
    '{4f50731a-89cf-4782-b3e0-dce8c90476ba}' # TraceLoggingOptionMicrosoftTelemetry
    '{c7de053a-0c2e-4a44-91a2-5222ec2ecdf1}' # TraceLoggingOptionWindowsCoreTelemetry
    '{B8197C10-845F-40ca-82AB-9341E98CFC2B}' # Microsoft-Windows-MediaFoundation-MFCaptureEngine
    '{B20E65AC-C905-4014-8F78-1B6A508142EB}' # Microsoft-Windows-MediaFoundation-Performance-Core
    '{548C4417-CE45-41FF-99DD-528F01CE0FE1}' # Microsoft-Windows-Ks(Kernel Streaming)
    '{8F0DB3A8-299B-4D64-A4ED-907B409D4584}' # Microsoft-Windows-Runtime-Media
    '{A4112D1A-6DFA-476E-BB75-E350D24934E1}' # Microsoft-Windows-MediaFoundation-MSVProc
    '{AE5C851E-B4B0-4F47-9D6A-2B2F02E39A5A}' # Microsoft.Windows.Sensors.SensorService
    '{A676B545-4CFB-4306-A067-502D9A0F2220}' # PlugPlayControlGuid
)

$ESENTProviders = @(
    '{478EA8A8-00BE-4BA6-8E75-8B9DC7DB9F78}' # Microsoft-ETW-ESE
    '{02f42b1b-4b78-48ce-8cdf-d98f8b443b93}' # Microsoft.Windows.ESENT.TraceLogging
)

$CBSProviders = @(
    '{5fc48aed-2eb8-4cd4-9c87-54700c4b7b26}' # CbsServicingProvider
    '{bd12f3b8-fc40-4a61-a307-b7a013a069c1}' # Microsoft-Windows-Servicing
    '{34c6b9f6-c1cf-4fe5-a133-df6cb085ec67}' # CBSTRACEGUID
)

<#------------------------------------------------------------------
                             FUNCTIONS 
------------------------------------------------------------------#>
Function EnterFunc([String]$FunctionName){
    LogMessage $LogLevel.Debug "---> [$FunctionName]" "Cyan"
}

Function EndFunc([String]$FunctionName){
    LogMessage $LogLevel.Debug "<--- [$FunctionName]" "Cyan"
}

Function Line{
    Return($MyInvocation.ScriptLineNumber.ToString())
}

function Is-Elevated
{
    $currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent();
    $currentPrincipal = New-Object System.Security.Principal.WindowsPrincipal($currentIdentity);
    $administratorRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator;
    return $currentPrincipal.IsInRole($administratorRole);
}

Function LogMessage{
    param(
        [ValidateNotNullOrEmpty()]
        [Int]$Level,
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$Message,
        [ValidateNotNullOrEmpty()]
        [String]$Color
    )

    If($Level -eq $Null){
        $Level = $LogLevel.Normal
    }

    If(($Level -eq $LogLevel.Debug) -and !($DebugMode.IsPresent)){
        Return # Early return. This is LogMessage $LogLevel.Debug but DebugMode swith is not set.
    }

    $Message = (Get-Date).ToString("HH:mm:ss.fff") + " " + $Message

    Switch($Level){
        '0'{ # Normal
            $MessageColor = 'White'
            $LogConsole = $True
            $LogMessage = $Message
        }
        '1'{ # Info / Normal console message
            $MessageColor = 'Yellow'
            $LogConsole = $True
            $LogMessage = $Message  # Simeple message
        }
        '2'{ # Warning
            $Levelstr = 'WARNING'
            $MessageColor = 'Magenta'
            $LogConsole = $True
        }
        '3'{ # Error
            $Levelstr = 'ERROR'
            $MessageColor = 'Red'
            $LogConsole = $True
        }
        '4'{ # Debug
            $Levelstr = 'DEBUG'
            $MessageColor = 'Green'
            If($DebugMode.IsPresent){
                $LogConsole = $True
            }Else{
                $LogConsole = $False
            }
        }
        '5'{ # ErrorLogFileOnly
            $Levelstr = 'ERROR'
            $LogConsole = $False
        }
        '6'{ # WarnLogFileOnly
            $Levelstr = 'WARNING'
            $LogConsole = $False
        }
    }

    # If color is specifed, overwrite it.
    If($Color -ne $Null -and $Color.Length -ne 0){
        $MessageColor = $Color
    }

    $Index = 0
    # In case of Warning/Error/Debug, add line and function name to message.
    If($Level -eq $LogLevel.Warning -or $Level -eq $LogLevel.Error -or $Level -eq $LogLevel.Debug -or $Level -eq $LogLevel.ErrorLogFileOnly -or $Level -eq $LogLevel.WarnLogFileOnly){
        $CallStack = Get-PSCallStack
        $CallerInfo = $CallStack[$Index]

        If($CallerInfo.FunctionName -eq "LogMessage"){
            $CallerInfo = $CallStack[$Index+1]
        }

        If($CallerInfo.FunctionName -eq "LogException"){
            $CallerInfo = $CallStack[$Index+2]
        }

        $FuncName = $CallerInfo.FunctionName
        If($FuncName -eq "<ScriptBlock>"){
            $FuncName = "Main"
        }
        $LogMessage = ($Levelstr + ': [' + $FuncName + '(' + $CallerInfo.ScriptLineNumber + ')] ' + $Message)
    }

    If($LogConsole){
        Write-Host $LogMessage -ForegroundColor $MessageColor
    }

    # In case of error, warning and ErrorLogFileOnly, we log the message to error log file.
    If($Level -eq $LogLevel.Warning -or $Level -eq $LogLevel.Error -or $Level -eq $LogLevel.ErrorLogFileOnly -or $Level -eq $LogLevel.WarnLogFileOnly){
        If(!(Test-Path -Path $LogFolder)){
            CreateLogFolder $LogFolder
        }
        $LogMessage | Out-File -Append $ErrorLogFile
    }
}

Function LogException{
    param(
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$Message,
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.ErrorRecord]$ErrObj,
        [Bool]$fErrorLogFileOnly
    )
    $ErrorCode = "0x" + [Convert]::ToString($ErrObj.Exception.HResult,16)
    $ExternalException = [System.ComponentModel.Win32Exception]$ErrObj.Exception.HResult
    $ErrorMessage = $Message + "`n" `
        + "Command/Function: " + $ErrObj.CategoryInfo.Activity + " failed with $ErrorCode => " + $ExternalException.Message + "`n" `
        + $ErrObj.CategoryInfo.Reason + ": " + $ErrObj.Exception.Message + "`n" `
        + "ScriptStack:" + "`n" `
        + $ErrObj.ScriptStackTrace
    If($fErrorLogFileOnly){
        LogMessage $LogLevel.ErrorLogFileOnly $ErrorMessage
    }Else{
        LogMessage $LogLevel.Error $ErrorMessage
    }
}


# Common utilities
Function IsSupportedOSVersion{
    [OutputType([Bool])]
    param(
        [parameter(Mandatory=$true)]
        [AllowNull()]
        [Hashtable]$SupportedOSVersion
    )
    EnterFunc $MyInvocation.MyCommand.Name

    [Version]$OSVersion = [environment]::OSVersion.Version
    [Bool]$fResult = $False

    If($OSVersion -eq $Null){
        $fResult = $True 
        $SupportVersionStr = 'Any'
    }Else{
        $SupportVersionStr = $SupportedOSVersion.OS.ToString() + "." + $SupportedOSVersion.Build.ToString()
    }
    LogMessage $LogLevel.Debug ("Current OS = " + $OSVersion.Major + "." + $OSVersion.Build + "   Supported OS = " + $SupportVersionStr)

    If($OSVersion.Major -ge $SupportedOSVersion.OS -and $OSVersion.Build -ge $SupportedOSVersion.Build){
        $fResult =  $True
    }
    If($fResult){
        LogMessage $LogLevel.Debug ('This command is supported.')
    }Else{
        LogMessage $LogLevel.Debug ('Warning: This command not supported.')
    }
    EndFunc $MyInvocation.MyCommand.Name  
    Return $fResult
}

Function SearchProcmon{
    [OutputType([String])]
    Param()
    EnterFunc $MyInvocation.MyCommand.Name

    $ProcmonSearchPath = @(
        "$env:userprofile\desktop"
        'C:\program files\SysinternalsSuite',
        'C:\Program Files (x86)\SysinternalsSuite',
        'C:\temp'
    )

    # If -ProcmonPath exists, just set it to $ProcmonCMDPath. Otherwise search it.
    If($ProcmonPath -ne $Null -and $ProcmonPath -ne ''){
        $Path = Join-Path -Path $ProcmonPath "procmon.exe"
        LogMessage $LogLevel.Debug ("ProcmonPath is $Path")
        If(Test-Path -Path $Path){
            $ProcmonCMDPath = $Path
            $script:fProcmonExist = $True
        }Else{
            LogMessage $LogLevel.Info "$Path does not exist" "Red"
            Return $Null
        }
    }Else{
        ForEach($Path in $ProcmonSearchPath){
            LogMessage $LogLevel.Debug ("Searching in $Path")
            If(!(Test-Path -Path $Path)){
                Continue
            }
            Try{
                $FilePath = Get-ChildItem $Path 'procmon.exe' -ErrorAction SilentlyContinue  # -Depth does not supported on 2012 R2
            }Catch{
                LogMessage $LogLevel.Debug ("An exception happened in Get-ChildItem $Path") $_
                Return $Null
            }
            If($FilePath.Count -ne 0){
                $ProcmonCMDPath = $FilePath[0].fullname 
                $script:fProcmonExist = $True
                break
            }
        }
    }

    If($script:fProcmonExist){
        LogMessage $LogLevel.Debug ("Found procmon. Path=$ProcmonCMDPath")
    }Else{
        $ProcmonCMDPath = $Null
    } 
    EndFunc $MyInvocation.MyCommand.Name
    Return $ProcmonCMDPath
}

Function SearchTTTracer{
    [OutputType([String])]
    Param()
    EnterFunc $MyInvocation.MyCommand.Name

    # First, seach path specified with '-TTDPath'
    $TTDFullPath = Join-Path -Path $TTDPath "TTTracer.exe"
    If(!(Test-Path -path $TTDFullPath)){
        
        # Seach a bit more as TTTDPath mitgh have been specified with upper folder.
        $TTTracers = Get-ChildItem $TTDPath 'TTTracer.exe' -Recurse -ErrorAction SilentlyContinue

        If($f64bitOS){
           $PathWithArch = "amd64\TTD\TTTracer.exe"
        }Else{
           $PathWithArch = "x86\TTD\TTTracer.exe"
        }
        
        ForEach($TTTracer in $TTTracers){
            If($($TTTracer.FullName).contains($PathWithArch)){
                $TTDFullPath = $TTTracer.FullName
                $fFound = $True
            }Else{
                Continue
            }
        }
    }Else{
        $fFound = $True
    }

    If(!$fFound){
        $TTDFullPath = $Null
    }

    EndFunc $MyInvocation.MyCommand.Name
    Return $TTDFullPath
}

Function ShowProcmonErrorMessage{
    Write-Host('ERROR: procmon.exe does not exist. Please download it from below link and place procmon.exe to desktop.') -ForegroundColor Red
    Write-Host('Download link: https://docs.microsoft.com/en-us/sysinternals/downloads/procmon') -ForegroundColor Yellow
    Write-Host('Or, run script with -ProcmonPath <FolderName procmon.exe exists on>')
    If($StopAutoLogger.IsPresent){
        Write-Host("Example: .\$ScriptName -StopAutoLogger -ProcmonPath E:\tools") -ForegroundColor Yellow
    }ElseIf($StopAutoLogger.IsPresent){
        Write-Host("Example: .\$ScriptName -Stop -ProcmonPath E:\tools") -ForegroundColor Yellow
    }ElseIf($Start.IsPresent){
        Write-Host("Example: .\$ScriptName -Start -Procmon -ProcmonPath E:\tools") -ForegroundColor Yellow
    }
}

# Core functions
Function CreateETWTraceProperties{
    param(
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [System.Collections.Generic.List[Object]]$TraceDefinitionArray,
        [Bool]$fMergedTrace 
    )
    EnterFunc $MyInvocation.MyCommand.Name

    If($TraceDefinitionArray.Count -eq 0 -or $TraceDefinitionArray -eq $Null){
        Throw '$ETWTraceList is null.'
    }

    # -AsOneTrace case
    If($fMergedTrace){
        $TraceProviders = @()
        ForEach($TraceDefinition in $TraceDefinitionArray){
            $TraceProviders += $TraceDefinition.Provider
        }
        $MergedTraceName = $MergedTracePrefix + 'Trace'
        $Property = @{
            Name = $MergedTracePrefix
            TraceName = $MergedTraceName
            LogType = 'ETW'
            CommandName = $Null
            Providers = $TraceProviders
            LogFileName = "`"$LogFolder\$MergedTraceName$LogSuffix.etl`""
            StartOption = $Null
            StopOption = $Null
            PreStartFunc = $Null
            StartFunc = $Null
            StopFunc = $Null
            PostStopFunc = $Null
            DetectionFunc = $Null
            AutoLogger =  @{
                AutoLoggerEnabled = $Null
                AutoLoggerLogFileName = "`"$AutoLoggerLogFolder\$MergedTraceName-AutoLogger.etl`""
                AutoLoggerSessionName = $AutoLoggerPrefix + $MergedTraceName
                AutoLoggerStartOption = $Null
                AutoLoggerStopOption = $Null
                AutoLoggerKey = $AutoLoggerBaseKey + $MergedTraceName
            }
            Wait = $Null
            SupprotedOSVersion = $Null # Any OSes
            Status = $TraceStatus.Success
        }
        LogMessage $LogLevel.Debug ('Adding ' + $Property.Name + ' to PropertyArray')
        $script:ETWPropertyList.Add($Property)
    # Normal case    
    }Else{
        Try{
            LogMessage $LogLevel.Debug ('Adding below traces to PropertyArray')
            ForEach($TraceDefinition in $TraceDefinitionArray)
            {
                $TraceName = $TraceDefinition.Name + 'Trace'
                $Property = @{
                    Name = $TraceDefinition.Name
                    TraceName = $TraceName
                    LogType = 'ETW'
                    CommandName = $Null
                    Providers = $TraceDefinition.Provider
                    LogFileName = "`"$LogFolder\$TraceName$LogSuffix.etl`""
                    StartOption = $Null
                    StopOption = $Null
                    PreStartFunc = $TraceDefinition.PreStartFunc
                    StartFunc = $Null
                    StopFunc = $Null
                    PostStopFunc = $TraceDefinition.PostStopFunc
                    DetectionFunc = $Null
                    AutoLogger =  @{
                        AutoLoggerEnabled = $Null
                        AutoLoggerLogFileName = "`"$AutoLoggerLogFolder\$TraceName-AutoLogger.etl`""
                        AutoLoggerSessionName = $AutoLoggerPrefix + $TraceName
                        AutoLoggerStartOption = $Null
                        AutoLoggerStopOption = $Null
                        AutoLoggerKey = $AutoLoggerBaseKey + $TraceName
                    }
                    Wait = $Null
                    SupprotedOSVersion = $Null # Any OSes
                    Status = $TraceStatus.Success
                }
                LogMessage $LogLevel.Debug ($Property.Name)
                $script:ETWPropertyList.Add($Property)
            }
        }Catch{
            Throw ('An error happened during creating property for ' + $TraceDefinition.Name)
        }
    }

    If($script:ETWPropertyList.Count -eq 0){
        Throw ('Failed to create ETWPropertyList. ETWPropertyList.Count is 0. Maybe bad entry in $ETWTraceList caused this.')
    }
    LogMessage $LogLevel.Debug ('Returning ' + $script:ETWPropertyList.Count  + ' properties.')
    EndFunc $MyInvocation.MyCommand.Name
}

Function AddTraceToLogCollector{
    param(
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$TraceName
    )
    EnterFunc ($MyInvocation.MyCommand.Name + ' with ' + $TraceName)

    $TraceObject = $GlobalTraceCatalog | Where-Object{$_.Name -eq $TraceName}
    If($TraceObject -eq $Null){
        Throw 'Trace ' + $TraceName + ' is not registered in tracde catalog.'
    }

    If($TraceObject.SupprotedOSVersion -ne $Null){
        If(!(IsSupportedOSVersion $TraceObject.SupprotedOSVersion)){
            $ErrorMessage = $TraceObject.Name + ' is not supported on this OS. Supported Version is [Windows ' + $TraceObject.SupprotedOSVersion.OS + ' Build ' + $TraceObject.SupprotedOSVersion.Build + '].'
            LogMessage $LogLevel.Error $ErrorMessage
            Exit # Early return as non support option is specified.
        }
    }

    LogMessage $LogLevel.Debug ('Adding ' + $TraceObject.Name + ' to GlobalTraceCatalog')
    $LogCollector.Add($TraceObject)
    EndFunc $MyInvocation.MyCommand.Name
    Return
}

Function DumpCollection{
    param(
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [Object[]]$Collection
    )
    EnterFunc $MyInvocation.MyCommand.Name

    LogMessage $LogLevel.Debug '--------------------------------------------------'
    ForEach($TraceObject in $Collection){
       LogMessage $LogLevel.Debug ('Name              : ' + $TraceObject.Name)
       LogMessage $LogLevel.Debug ('TraceName         : ' + $TraceObject.TraceName)
       LogMessage $LogLevel.Debug ('LogType           : ' + $TraceObject.LogType)
       LogMessage $LogLevel.Debug ('CommandName       : ' + $TraceObject.CommandName)
       If($TraceObject.Providers -eq $Null){
           $ProviderProp = ''
       }Else{
           $ProviderProp = $TraceObject.Providers[0] + '...  --> ' + $TraceObject.Providers.Count + ' providers'
       }
       LogMessage $LogLevel.Debug ('Providers         : ' + $ProviderProp)
       LogMessage $LogLevel.Debug ('LogFileName       : ' + $TraceObject.LogFileName)
       LogMessage $LogLevel.Debug ('StartOption       : ' + $TraceObject.StartOption)
       LogMessage $LogLevel.Debug ('StopOption        : ' + $TraceObject.StopOption)
       LogMessage $LogLevel.Debug ('PreStartFunc      : ' + $TraceObject.PreStartFunc)
       LogMessage $LogLevel.Debug ('StartFunc         : ' + $TraceObject.StartFunc)
       LogMessage $LogLevel.Debug ('StopFunc          : ' + $TraceObject.StopFunc)
       LogMessage $LogLevel.Debug ('PostStopFunc      : ' + $TraceObject.PostStopFunc)
       LogMessage $LogLevel.Debug ('DetectionFunc     : ' + $TraceObject.DetectionFunc)
       LogMessage $LogLevel.Debug ('AutoLogger        : ' + $TraceObject.AutoLogger)
       If($TraceObject.AutoLogger -ne $Null){
           LogMessage $LogLevel.Debug ('    - AutoLoggerEnabled     : ' + $TraceObject.AutoLogger.AutoLoggerEnabled)
           LogMessage $LogLevel.Debug ('    - AutoLoggerLogFileName : ' + $TraceObject.AutoLogger.AutoLoggerLogFileName)
           LogMessage $LogLevel.Debug ('    - AutoLoggerSessionName : ' + $TraceObject.AutoLogger.AutoLoggerSessionName)
           LogMessage $LogLevel.Debug ('    - AutoLoggerStartOption : ' + $TraceObject.AutoLogger.AutoLoggerStartOption)
           LogMessage $LogLevel.Debug ('    - AutoLoggerStopOption  : ' + $TraceObject.AutoLogger.AutoLoggerStopOption)
           LogMessage $LogLevel.Debug ('    - AutoLoggerKey         : ' + $TraceObject.AutoLogger.AutoLoggerKey)
       }
       LogMessage $LogLevel.Debug ('Wait              : ' + $TraceObject.Wait)
       If($TraceObject.SupprotedOSVersion -ne $Null){
           $OSver = $TraceObject.SupprotedOSVersion.OS
           $Build = $TraceObject.SupprotedOSVersion.Build
           $VersionStr = 'Windows ' + $OSver + ' Build ' + $Build
       }Else{
            $VersionStr = ''
       }
       LogMessage $LogLevel.Debug ('SupprotedOSVersion: ' + $VersionStr)
       LogMessage $LogLevel.Debug ('Status            : ' + $TraceObject.Status)
       LogMessage $LogLevel.Debug ('--------------------------------------------------')
    }
    EndFunc $MyInvocation.MyCommand.Name
}

# We will carefully check property as this is key data for all traces/logs.
Function InspectProperty{
    param(
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]$Property
    )
    #EnterFunc $MyInvocation.MyCommand.Name
    # Name
    If($Property.Name -eq $Null -or $Property.Name -eq ''){
        Throw 'ERRRO: Object name is null.'
    }

    # TraceName
    If($Property.TraceName -eq $Null -or $Property.TraceName -eq ''){
        Throw 'ERRRO: TraceName is null.'
    }

    # LogType
    ForEach($LogType in $script:LogTypes){
        If($Property.LogType -eq $LogType){
            $fResult = $True
            Break
        } 
    }
    If(!$fResult){
        Throw 'ERROR: unknown log type: ' + $Property.LogType
    }

    Switch($Property.LogType){
        # ETW must have:
        #   - providers
        #   - autologger
        #   - AutoLoggerLogFileName/AutoLoggerSessionName
        'ETW' {
            If($Property.Providers -eq $Null){
                Throw 'ERROR: Log type is ' + $Property.LogType + ' but there is no providers.'
            }
            If($Property.AutoLogger -eq $Null){
                Throw 'ERROR: Log type is ' + $Property.LogType + ' but autologger is no set.'
            }Else{
                If($Property.AutoLogger.AutoLoggerLogFileName -eq $Null){
                    Throw 'ERROR: Log type is ' + $Property.LogType + ' but AutoLoggerLogFileName is not specified in this property.'
                }
                If($Property.AutoLogger.AutoLoggerSessionName -eq $Null){
                    Throw 'ERROR: Log type is ' + $Property.LogType + ' but AutoLoggerLogFileName is not specified in this property.'
                }
            }
        }
        # Command must have:
        #   - CommandName
        #   - StartOption/StopOption
        #   - If autologger is supported:
        #       - must have AutoLoggerLogFileName/AutoLoggerStartOption/AutoLoggerStopOption
        'Command' {
            If($Property.CommandName -eq $Null){
                Throw 'ERROR: Log type is ' + $Property.LogType + " but 'CommandName' is not specified in this property."
            }
            If($Property.LogType -eq 'Command' -and ($Property.StartOption -eq $Null -or $Property.StopOption -eq $Null)){
                Throw 'ERROR: Log type is ' + $Property.LogType + ' but StartOption/StopOption is not specified in this property.'
            }
            If($Property.AutoLogger -ne $Null){
                If($Property.AutoLogger.AutoLoggerLogFileName -eq $Null){
                    Throw 'ERROR: Log type is ' + $Property.LogType + ' but AutoLoggerLogFileName is not specified in this property.'
                }
                If($Property.AutoLogger.AutoLoggerStartOption -eq $Null){
                    Throw 'ERROR: Log type is ' + $Property.LogType + ' but AutoLoggerStartOption is not specified in this property.'
                }
                If($Property.AutoLogger.AutoLoggerStopOption -eq $Null){
                    Throw 'ERROR: Log type is ' + $Property.LogType + ' but AutoLoggerStopOption is not specified in this property.'
                }
            }
        }
        'Custom' {
            If($Property.StartFunc -ne $Null){
                Try{
                    Get-Command $Property.StartFunc -CommandType Function -ErrorAction Stop | Out-Null
                }Catch{
                    Throw 'ERROR: ' + $Property.StartFunc + ' is not implemented in this script.'
                }
            }
            If($Property.StopFunc -ne $Null){
                Try{
                    Get-Command $Property.StopFunc -CommandType Function -ErrorAction Stop | Out-Null
                }Catch{
                    Throw 'ERROR: ' + $Property.StopFunc + ' is not implemented in this script.'
                }
            }
            If($Property.DetectionFunc -ne $Null){
                Try{
                    Get-Command $Property.DetectionFunc -ErrorAction Stop | Out-Null
                }Catch{
                    Throw 'ERROR: ' + $Property.DetectionFunc + ' is not implemented in this script.'
                }
            }

            If($Property.Status -eq $Null){
                Throw('ERROR: Status is not initialized.')
            }
            # No additonal tests needed for Custom object
            Return
        }
    }

    # LogFileName
    If($Property.LogFileName -eq $Null){
        Throw 'ERROR: LogFileName must be specified.'
    }

    # Commented out code for checking prestart/poststop function as this takes time.
    # Component specific function
    #If($Property.PreStartFunc -ne $Null){
    #    Try{
    #        Get-Command $Property.PreStartFunc -ErrorAction Stop | Out-Null
    #    }Catch{
    #        $Property.PreStartFunc = $Null # fix up PreStartFunc
    #    }
    #}
    #If($Property.PostStopFunc -ne $Null){
    #    Try{
    #        Get-Command $Property.PostStopFunc -ErrorAction Stop | Out-Null
    #    }Catch{
    #        $Property.PreStartFunc = $Null # fix up PostStopFunc
    #    }
    #}

    If($Property.Status -eq $Null){
        Throw('ERROR: Status is not initialized.')
    }
    #EndFunc $MyInvocation.MyCommand.Name    
}

Function ValidateCollection{
    [OutputType([Bool])]
    param(
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [Object[]]$Collection
    )
    EnterFunc $MyInvocation.MyCommand.Name
    $ErrorCount=0

    ForEach($TraceObject in $Collection){
        # Name
        LogMessage $LogLevel.Debug ('Instpecting ' + $TraceObject.Name)
        If($TraceObject.Name -eq $Null -or $TraceObject.Name -eq '')
        {
            LogMessage $LogLevel.Debug ('Name is null.')
            $ErrorCount++
        }
        # LogType
        $fValidLogType = $False
        ForEach($LogType in $LogTypes){
            If($TraceObject.LogType -eq $LogType){
                $fValidLogType = $True
                Break
            } 
        }
        If(!$fValidLogType){
            LogMessage $LogLevel.Debug ('unknown log type: ' + $TraceObject.LogType)
            $ErrorCount++
        }

        # LogFileName/Providers/AutoLogger/AutoLoggerLogFileName/AutoLoggerSessionName
        # => These may be null in some cases. We don't check them.

        # Command
        If($TraceObject.LogType -eq 'Command' -and $TraceObject.CommandName -eq $Null){
            LogMessage $LogLevel.Debug ("Log type is Commad but 'CommandName' is not specified in this TraceObject.")
            $ErrorCount++
        }
    }

    # Component specific function
    #If($TraceObject.PreStartFunc -ne $Null){
    #    Try{
    #        Get-Command $TraceObject.PreStartFunc -ErrorAction Stop | Out-Null
    #    }Catch{
    #        LogMessage $LogLevel.Debug ($TraceObject.PreStartFunc + ' is not implemented in this script.')
    #        $ErrorCount++
    #    }
    #}
    #If($TraceObject.PostStopFunc -ne $Null){
    #    Try{
    #        Get-Command $TraceObject.PostStopFunc -ErrorAction Stop | Out-Null
    #    }Catch{
    #        LogMessage $LogLevel.Debug ($TraceObject.PostStopFunc + ' is not implemented in this script.')
    #        $ErrorCount++
    #    }
    #}

    # For custom object
    If($TraceObject.StartFunc -ne $Null){
        Try{
            Get-Command $TraceObject.StartFunc -ErrorAction Stop | Out-Null
        }Catch{
            LogMessage $LogLevel.Debug ('ERROR: ' + $TraceObject.StartFunc + ' is not implemented in this script.')
            $ErrorCount++
        }
    }
    If($TraceObject.StopFunc -ne $Null){
        Try{
            Get-Command $TraceObject.StopFunc -ErrorAction Stop | Out-Null
        }Catch{
            LogMessage $LogLevel.Debug ('ERROR: ' + $TraceObject.StopFunc + ' is not implemented in this script.')
            $ErrorCount++
        }
    }

    LogMessage $LogLevel.Debug ('Log collection was validated and found ' + $ErrorCount + ' issue(s).')
    
    If($ErrorCount -eq 0){
        $fResult = $True  # Normal
    }Else{
        $fResult = $False # Error
    }

    EndFunc $MyInvocation.MyCommand.Name
    Return $fResult
}

Function GetExistingTraceSession{
    [OutputType("System.Collections.Generic.List[PSObject]")]
    Param()
    EnterFunc $MyInvocation.MyCommand.Name

    If($GlobalTraceCatalog.Count -eq 0){
        LogMessage $LogLevel.Info 'No traces in GlobalTraceCatalog.' "Red"
        CleanUpandExit
    }

    If(!(ValidateCollection $GlobalTraceCatalog)){
        LogMessage $LogLevel.Info 'there is errro(s) in GlobalTraceCatalog.' "Red"
        CleanUpandExit
    }

    $RunningTraces = New-Object 'System.Collections.Generic.List[PSObject]'
    $ETWSessionList = logman -ets | Out-String
    $CurrentSessinID = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
    $Processes = Get-Process | Where-Object{$_.SessionID -eq $CurrentSessinID}

    $i = 0
    ForEach($TraceObject in $GlobalTraceCatalog){
        $i++
        Write-Progress -Activity ('Checking running ETW session(' + $TraceObject.Name + ')') -Status 'Progress:' -PercentComplete ($i/$GlobalTraceCatalog.count*100)

        Switch($TraceObject.LogType) {
            'ETW' {
                LogMessage $LogLevel.Debug ('Checking existing sessesion of ' + $TraceObject.TraceName)

                ForEach($Line in ($ETWSessionList -split "`r`n")){
                    $Token = $Line -Split '\s+'
                    If($Token[0] -eq $TraceObject.TraceName){
                        LogMessage $LogLevel.Debug ('Found running trace session ' + $TraceObject.Name) "Yellow"
                        $RunningTraces.Add($TraceObject)
                        Break
                    }
                }
            }
            'Command' {
                LogMessage $LogLevel.Debug ('Enter [Command] section in GetExistingTraceSession. Checking ' + $TraceObject.Name)
                Switch($TraceObject.Name) {
                    'WPR' {
                        ForEach($Line in ($ETWSessionList -split "`r`n")){
                            $Token = $Line -Split '\s+'
                            If($Token[0] -eq 'WPR_initiated_WprApp_WPR' -or $Token[0] -eq 'WPR_initiated_WprApp_boottr_WPR'){
                                LogMessage $LogLevel.Debug ('Found existing ' + $TraceObject.Name + ' session.') "Yellow"
                                $RunningTraces.Add($TraceObject)
                                Break
                            }
                        }                            
                    }
                    'Netsh' {
                        $NetshSessionName = 'NetTrace'
                        ForEach($Line in ($ETWSessionList -split "`r`n")){
                            $Token = $Line -Split '\s+'                            
                            If($Token[0].Contains($NetshSessionName)){
                                $RunningTraces.Add($TraceObject)
                                LogMessage $LogLevel.Debug ('Found existing ' + $TraceObject.Name + ' session.') "Yellow"
                                Break
                            }
                        }
                    }
                    'Procmon' {
                        $Prcmon = $Processes | Where-Object{$_.Name.ToLower() -eq 'procmon'}
                        If($Prcmon.Count -ne 0){
                            $RunningTraces.Add($TraceObject)
                            LogMessage $LogLevel.Debug ('Found existing ' + $TraceObject.Name + ' session.') "Yellow"
                        }
                    }
                    'PSR' {
                        $PSRProcess = $Processes | Where-Object{$_.Name.ToLower() -eq 'psr'}
                        If($PSRProcess.Count -ne 0){
                            $RunningTraces.Add($TraceObject)
                            LogMessage $LogLevel.Debug ('Found existing ' + $TraceObject.Name + ' session.') "Yellow"
                        }
                    }
                }
            }
            'Perf' {
                LogMessage $LogLevel.Debug ('Enter [Command] section in GetExistingTraceSession. Checking ' + $TraceObject.Name)
                $datacollectorset = new-object -COM Pla.DataCollectorSet
                Try{  
                    $datacollectorset.Query($TraceObject.Name, $env:computername)
                }Catch{
                    # If 'Perf' is not running, exception happens and this is acutlly not error. So just log it if -DebugMode.
                    LogMessage $LogLevel.Debug ('INFO: An Exception happened in Pla.DataCollectorSet.Query for ' + $TraceObject.Name)
                    Break
                }
            
                #Status ReturnCodes: 0=stopped 1=running 2=compiling 3=queued (legacy OS) 4=unknown (usually autologger)
                If($datacollectorset.Status -ne 1){
                    LogMessage $LogLevel.Debug ('Perf status is ' + $datacollectorset.Status)
                    Break
                }
                $RunningTraces.Add($TraceObject)
                LogMessage $LogLevel.Debug ('Found existing ' + $TraceObject.Name + ' session.')
            }
            'Custom' {
                LogMessage $LogLevel.Debug ('Enter [Custom] section in GetExistingTraceSession. Checking ' + $TraceObject.Name)
                If($TraceObject.DetectionFunc -ne $Null){
                    $fResult = & $TraceObject.DetectionFunc
                    If($fResult){
                        $RunningTraces.Add($TraceObject)
                        LogMessage $LogLevel.Debug ('Found existing ' + $TraceObject.Name + ' session.')
                    }
                }Else{
                    LogMessage $LogLevel.Debug ($TraceObject.Name + ' does not have detection function.')
                }
            }
            Default {
                LogMessage $LogLevel.Info ('Unknown log name ' + $TraceObject.LogType) "Red"
            }
        }
    }
    Write-Progress -Activity 'Checking  running autologger session' -Status 'Progress:' -Completed

    EndFunc $MyInvocation.MyCommand.Name
    Return $RunningTraces
}

Function GetEnabledAutoLoggerSession{
    [OutputType("System.Collections.Generic.List[PSObject]")]
    Param()

    EnterFunc $MyInvocation.MyCommand.Name
    $fExist = $False

    $AutoLoggerTraces = New-Object 'System.Collections.Generic.List[PSObject]'

    $i = 0
    ForEach($TraceObject in $GlobalTraceCatalog){
        $i++
        Write-Progress -Activity ('Checking running autologger session(' + $TraceObject.Name + ')') -Status 'Progress:' -PercentComplete ($i/$GlobalTraceCatalog.count*100)

        # This object does not support autologger.
        If($TraceObject.AutoLogger -eq $Null){
            LogMessage $LogLevel.Debug ('Skipping ' + $TraceObject.Name + ' as this does not support autologger.')
            Continue
        }
        # This has autologger but it is not enabled.
        If(!(Test-Path -Path $TraceObject.AutoLogger.AutoLoggerKey)){
            LogMessage $LogLevel.Debug ('Skipping ' + $TraceObject.Name + ' as autologger is not enabled.')
            $TraceObject.AutoLogger.AutoLoggerEnabled = $False
            Continue
        }

        # Check start value.
        Try{
            $RegValue = Get-ItemProperty -Path $TraceObject.AutoLogger.AutoLoggerKey -Name 'Start' -ErrorAction Stop
        }Catch{
            # We cannot use stream as this function returns object. So this is error but just logs with debugmode.
            LogMessage $LogLevel.Debug ($TraceObject.Name + " does not have autologger start registry(" + $TraceObject.AutoLogger.AutoLoggerKey + "\Start)") 
            Continue
        }

        # Now this object has start value so check it.
        # Procmon is tricky and if it is 0 or 3, which means bootlogging enabled.
        If($TraceObject.Name -eq 'Procmon' -and ($RegValue.Start -eq 3 -or $RegValue.Start -eq 0)){
            LogMessage $LogLevel.Debug ('Autologger for ' + $TraceObject.Name + ' is enabled.') "Yellow"
            $fExist = $True
            $TraceObject.AutoLogger.AutoLoggerEnabled = $True
            $AutoLoggerTraces.Add($TraceObject)
            Continue
        }

        If($RegValue.Start -eq 1){
            LogMessage $LogLevel.Debug ('Autologger for ' + $TraceObject.Name + ' is enabled.') "Yellow"
            $fExist = $True
            $TraceObject.AutoLogger.AutoLoggerEnabled = $True
            $AutoLoggerTraces.Add($TraceObject)
        }Else{
            $TraceObject.AutoLogger.AutoLoggerEnabled = $False
        }
    }
    Write-Progress -Activity 'Checking  running autologger session' -Status 'Progress:' -Completed


    If($fExist){
        LogMessage $LogLevel.Debug ('Found autologger settings. Setting $fAutoLoggerExist to $True.')
        $script:fAutoLoggerExist = $True
    }Else{
        $script:fAutoLoggerExist = $False
    }
    EndFunc $MyInvocation.MyCommand.Name
    Return $AutoLoggerTraces
}

# Start/Stop functions
Function StartTraces{
    EnterFunc $MyInvocation.MyCommand.Name
    ForEach($TraceObject in $LogCollector)
    {
        # Check if the trace has pre-start function. If so, just call it.
        $ComponentPreStartFunc = $TraceObject.Name + 'PreStart'
        $Func = $Null
        $Func = Get-Command $ComponentPreStartFunc  -CommandType Function -ErrorAction SilentlyContinue # Ignore exception

        If($Func -ne $Null){
            Try{
                LogMessage $LogLevel.Info ('[' + $TraceObject.Name + "] Calling pre-start function $ComponentPreStartFunc")
                & $ComponentPreStartFunc
            }Catch{
                LogMessage $LogLevel.Warning ('[' + $TraceObject.Name + '] Error happens in pre-start function(' + $ComponentPreStartFunc + '). Skipping this trace.')
                LogException ("An error happened in $ComponentPreStartFunc") $_ $fLogFileOnly
                $TraceObject.Status = $TraceStatus.ErrorInStart
                Continue
            }
        }

        Switch($TraceObject.LogType){
            'ETW' {
                LogMessage $LogLevel.Debug ('Enter [ETW] section in StartTraces. Starting ' + $TraceObject.Name)
                If($SetAutoLogger.IsPresent){
                    $TraceName = $TraceObject.AutoLogger.AutoLoggerSessionName
                }Else{    
                    $TraceName = $TraceObject.TraceName
                }

                # This throws an exception and will be handled in main
                RunCommands "ETW" "logman create trace $TraceName -ow -o $($TraceObject.LogFileName) -mode Circular -bs 64 -f bincirc -max $MAXLogSize -ft 60 -ets" -ThrowException:$True -ShowMessage:$True

                # Adding all providers to the trace session
                $i=0
                ForEach($Provider in $TraceObject.Providers){
                    Write-Progress -Activity ('Adding ' + $Provider + ' to ' + $TraceName) -Status 'Progress:' -PercentComplete ($i/$TraceObject.Providers.count*100)
                    RunCommands "ETW" "logman update trace $TraceName -p `"$Provider`" 0xffffffffffffffff 0xff -ets" -ThrowException:$False -ShowMessage:$False
                    $i++
                }
                Write-Progress -Activity 'Updating providers' -Status 'Progress:' -Completed

                # If autologger, create registry key
                If($SetAutoLogger.IsPresent -and $TraceObject.AutoLogger -ne $Null){
                    If(Test-Path -Path $TraceObject.AutoLogger.AutoLoggerKey){
                        # Set maximum number of instances of the log file to 5
                        Try{
                            New-ItemProperty -Path $TraceObject.AutoLogger.AutoLoggerKey -Name 'FileMax' -PropertyType DWord -Value 5 -force -ErrorAction SilentlyContinue | Out-Null
                        }Catch{
                            LogMessage $LogLevel.Warning ('Unable to update ' + $TraceObject.AutoLogger.AutoLoggerKey)
                        }
                    }Else{
                        LogMessage $LogLevel.Warning ($TraceObject.AutoLogger.AutoLoggerKey + ' does not exist.')
                    }
                    LogMessage $LogLevel.Info ('=> Updating log file to ' + $TraceObject.AutoLogger.AutoLoggerLogFileName)
                    Try{
                        RunCommands "ETW" "logman update trace $TraceName -o $($TraceObject.AutoLogger.AutoLoggerLogFileName)" -ThrowException:$True -ShowMessage:$False
                    }Catch{
                        LogMessage $LogLevel.Warning ('Warning: unable to update logfolder for autologger. Trace will continue with default location where this script is run.')
                    }
                }
                $TraceObject.Status = $TraceStatus.Started
            }
            'Perf' {
                LogMessage $LogLevel.Debug ('Enter [Perf] section in StartTraces. Starting ' + $TraceObject.TraceName)
                Try{
                    StartPerfLog  $TraceObject  # This may throw an exception.
                }Catch{
                    $TraceObject.Status = $TraceStatus.ErrorInStart
                    $ErrorMessage = 'An exception happened during starting performance log.'
                    LogException $ErrorMessage $_
                    Throw ($ErrorMessage)
                }
                $TraceObject.Status = $TraceStatus.Started
            }
            'Command' {
                LogMessage $LogLevel.Debug ('Enter [Command] section in StartTraces. Start processing ' + $TraceObject.TraceName)

                # Supported version check
                If($TraceObject.SupprotedOSVersion -ne $Null){
                    If(!(IsSupportedOSVersion $TraceObject.SupprotedOSVersion)){
                        LogMessage $LogLevel.Warning ($TraceObject.Name + ' is not supported on this OS. Supported Version is [Windows ' + $TraceObject.SupprotedOSVersion.OS + ' Build ' + $TraceObject.SupprotedOSVersion.Build + '] Skipping this trace.')
                        $TraceObject.Status = $TraceStatus.NotSupported
                        Break # This is not critical and continue another traces.
                    }
                }

                # Check if the command exists.
                If(!(Test-Path -Path (Get-Command $TraceObject.CommandName).Path)){
                    LogMessage $LogLevel.Warning ('Warning: ' + $TraceObject.CommandName + ' not found. Skipping ' + $TraceObject.Name)
                    $TraceObject.Status = $TraceStatus.ErrorInStart
                    Break
                }

                # Normal case.
                If(!$SetAutoLogger.IsPresent){ 
                    LogMessage $LogLevel.Info ('[' + $TraceObject.Name + '] Running ' + $TraceObject.CommandName + ' ' + $TraceObject.Startoption)
                    If($TraceObject.Wait){
                        $Proccess = Start-Process -FilePath $TraceObject.CommandName -ArgumentList $TraceObject.Startoption -RedirectStandardOutput $env:temp\StartProcess-output.txt -RedirectStandardError $env:temp\StartProcess-err.txt -PassThru -Wait
                        If($Proccess.ExitCode -ne 0){
                            Get-Content $env:temp\StartProcess-output.txt
                            Get-Content $env:temp\StartProcess-err.txt
                            Remove-Item $env:temp\StartProcess*
                            $TraceObject.Status = $TraceStatus.ErrorInStart
                            $ErrorMessage = ('An error happened in ' + $TraceObject.CommandName + ' (Error=0x' + [Convert]::ToString($Proccess.ExitCode,16) + ')')
                            LogMessage $LogLevel.Error $ErrorMessage
                            Throw ($ErrorMessage)
                        }
                    }Else{
                        $Proccess = Start-Process -FilePath $TraceObject.CommandName -ArgumentList $TraceObject.Startoption
                    }
                    $TraceObject.Status = $TraceStatus.Started
                # Autologger case.
                }Else{ 
                    # WPR -boottrace does not support RS1 or earlier.
                    If($TraceObject.Name -eq 'WPR'){
                        LogMessage $LogLevel.Debug ('Enter [WPR] Current OS build=' + $Version.Build + ' WPR supported build=' + $WPRBoottraceSupprotedVersion.Build)
                        If($Version.Build -lt $WPRBoottraceSupprotedVersion.Build){
                            $TraceObject.Status = $TraceStatus.NotSupported
                            Throw ($TraceObject.Name + ' -boottrace is not supported on this OS. Supported Version is Windows ' + $WPRBoottraceSupprotedVersion.OS  + ' Build ' + $WPRBoottraceSupprotedVersion.Build + ' or later.')
                        }
                    }

                    If($TraceObject.Name -eq 'Netsh'){
                        LogMessage $LogLevel.Debug ('Enter [Netsh] Checking if there is running session.')
                        $NetshSessionName = 'NetTrace'
                        ForEach($Line in ($ETWSessionList -split "`r`n")){
                            $Token = $Line -Split '\s+'
                            If($Token[0].Contains($NetshSessionName)){
                                $TraceObject.Status = $TraceStatus.ErrorInStart
                                Throw ($TraceObject.Name + ' is already running.')
                            }
                        }
                    }

                    LogMessage $LogLevel.Info ('[' + $TraceObject.Name + '] Running ' + $TraceObject.CommandName + ' ' + $TraceObject.AutoLogger.AutoLoggerStartOption)
                    If($TraceObject.Wait){
                        $Proccess = Start-Process -FilePath $TraceObject.CommandName -ArgumentList $TraceObject.AutoLogger.AutoLoggerStartOption -RedirectStandardOutput $env:temp\StartProcess-output.txt -RedirectStandardError $env:temp\StartProcess-err.txt -PassThru -Wait
                        If($Proccess.ExitCode -ne 0){
                            $TraceObject.Status = $TraceStatus.ErrorInStart
                            Get-Content $env:temp\StartProcess-output.txt
                            Get-Content $env:temp\StartProcess-err.txt
                            Remove-Item $env:temp\StartProcess*
                            $ErrorMessage = ('An error happened in ' + $TraceObject.CommandName + ' (Error=0x' + [Convert]::ToString($Proccess.ExitCode,16) + ')')
                            LogMessage $LogLevel.Error $ErrorMessage
                            Throw ($ErrorMessage)
                        }
                    }Else{
                        $Proccess = Start-Process -FilePath $TraceObject.CommandName -ArgumentList $TraceObject.AutoLogger.AutoLoggerStartOption
                        # Unfortunately we don't know if it starts without error as the process is stared as background process.
                    }
                    $TraceObject.Status = $TraceStatus.Started
                }
            }
            'Custom' {
                # Supported version check
                If($TraceObject.SupprotedOSVersion -ne $Null){
                    If(!(IsSupportedOSVersion $TraceObject.SupprotedOSVersion)){
                        $ErrorMessage = $TraceObject.Name + ' is not supported on this OS. Supported Version is [Windows ' + $TraceObject.SupprotedOSVersion.OS + ' Build ' + $TraceObject.SupprotedOSVersion.Build + '].'
                        LogMessage $LogLevel.Error $ErrorMessage
                        $TraceObject.Status = $TraceStatus.NotSupported
                        Throw ($ErrorMessage) 
                    }
                }
                LogMessage $LogLevel.Debug ('Enter [Custom] section in StartTraces. Start processing ' + $TraceObject.TraceName)
                # Check if the trace has pre-start function. If so, just call it.
                LogMessage $LogLevel.Debug ('[' + $TraceObject.Name + ']' + ' calling start function ' + $TraceObject.StartFunc)
                Try{
                    & $TraceObject.StartFunc
                }Catch{
                    $TraceObject.Status = $TraceStatus.ErrorInStart
                    $ErrorMessage = '[' + $TraceObject.Name + '] An error happened in start function(' + $TraceObject.StartFunc + ').'
                    Throw ($ErrorMessage)
                }
                $TraceObject.Status = $TraceStatus.Started
            }
            Default {
                $TraceObject.Status = $TraceStatus.ErrorInStart
                LogMessage $LogLevel.Error ('Unknown log type ' + $TraceObject.LogType)
            }
        }            
    }
    EndFunc $MyInvocation.MyCommand.Name
}

Function WUStartTrace{
    EnterFunc $MyInvocation.MyCommand.Name
    $WUServices = @('uosvc','wuauserv')
    $WUTraceKey = 'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Trace'
    ForEach($WUService in $WUServices){
        $Service = Get-Service -Name $WUService -ErrorAction SilentlyContinue
        If($Service -eq $Null){
            LogMessage $LogLevel.Debug ('[WindowsUpdate] ' + $WUService + ' does not exist in this system.')
            Continue
        }
        If($Service.Status -eq 'Running'){
            LogMessage $LogLevel.Info ('[WindowsUpdate] Stopping ' + $Service.Name + ' service to enable verbose mode.')
            Stop-Service -Name $Service.Name
            $Service.WaitForStatus('Stopped', '00:01:00')
        }
        $Service = Get-Service -Name $Service.Name
        If($Service.Status -ne 'Stopped'){
            $ErrorMessage = ('[WindowsUpdate] Failed to stop ' + $Service.Name + ' service. Skipping Windows Update trace.')
            LogException $ErrorMessage $_ $fLogFileOnly
            Throw ($ErrorMessage)    
        }
        LogMessage $LogLevel.Debug ('[WindowsUpdate] ' + $WUService + ' was stopped.')
    }
  
    If(!(Test-Path -Path $WUTraceKey)){
        Try{
            New-Item -Path 'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Trace' -ErrorAction Stop | Out-Null
        }Catch{
            $ErrorMessage = 'An exception happened in New-ItemProperty'
            LogException $ErrorMessage $_ $fLogFileOnly
            Throw ($ErrorMessage)    
        }
    }

    Try{
        New-ItemProperty -Path $WUTraceKey -Name 'WPPLogDisabled' -PropertyType DWord -Value 1 -force -ErrorAction Stop | Out-Null
    }Catch{
        $ErrorMessage = 'An exception happened in New-ItemProperty'
        LogException $ErrorMessage $_ $fLogFileOnly
        Throw ($ErrorMessage)    
    }
    LogMessage $LogLevel.Debug ('[WindowsUpdate] ' + $WUTraceKey + '\WPPLogDisabled was set to 1.')
    EndFunc $MyInvocation.MyCommand.Name
}

Function WUStopTrace{
    EnterFunc $MyInvocation.MyCommand.Name
    $WUTraceKey = 'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Trace'
    Try{
        Remove-Item -Path $WUTraceKey -Recurse -force -ErrorAction Stop | Out-Null
    }Catch{
        $ErrorMessage = ("[WUStopTrace] Unable to delete $WUTraceKey")
        LogException $ErrorMessage $_ $fLogFileOnly
        Throw ($ErrorMessage)    
    }
    LogMessage $LogLevel.Debug ('[WindowsUpdate] ' + $WUTraceKey + ' was deleted.')

    $WUServices = @('uosvc','wuauserv')
    ForEach($WUService in $WUServices){
        $Service = Get-Service -Name $WUService -ErrorAction SilentlyContinue
        If($Service -eq $Null){
            LogMessage $LogLevel.Debug ('[WindowsUpdate] ' + $WUService + ' does not exist in this system.')
            Continue
        }
        If($Service.Status -eq 'Running'){
            LogMessage $LogLevel.Info ('[WindowsUpdate] Stopping ' + $Service.Name + ' service to enable verbose mode.')
            Stop-Service -Name $Service.Name
            $Service.WaitForStatus('Stopped', '00:01:00')
        }
        $Service = Get-Service -Name $Service.Name
        If($Service.Status -ne 'Stopped'){
            $ErrorMessage = ('[WindowsUpdate] Failed to stop ' + $Service.Name + ' service. Skipping Windows Update trace.')
            LogException $ErrorMessage $_ $fLogFileOnly
            Throw ($ErrorMessage)    
        }
            LogMessage $LogLevel.Debug ('[WindowsUpdate] ' + $Service.Name + ' service was stopped.')
    }
    EndFunc $MyInvocation.MyCommand.Name
}

### Stop All traces in $LogCollector
Function StopTraces{
    param(
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [Object[]]$TraceCollection
    )
    EnterFunc $MyInvocation.MyCommand.Name

    LogMessage $LogLevel.Info ('Stopping traces.')
    LogMessage $LogLevel.Debug ('Getting existing ETW sessions.')

    # Use logman -ets to know running ETW sessions. Get-EtwTraceSession is buggy and sometimes it returns null. So we use logman.
    $ETWSessionList = logman -ets | Out-String

    # Get all processes running on current user session.
    $CurrentSessinID = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
    $Processes = Get-Process | Where-Object{$_.SessionID -eq $CurrentSessinID}
    
    ForEach($TraceObject in $TraceCollection){
        Switch($TraceObject.LogType) {
            'ETW' {
                LogMessage $LogLevel.Debug ('Searching ' + $TraceObject.TraceName + ' in CimInstances')
                $fFound = $False
                ForEach($Line in ($ETWSessionList -split "`r`n")){
                    $Token = $Line -Split '\s+'
                    If($Token[0] -eq $TraceObject.TraceName){
                        Try{
                            RunCommands "ETW" "logman stop $($TraceObject.TraceName) -ets" -ThrowException:$True -ShowMessage:$True
                        }Catch{
                            LogException ("An error happened in `'logman stop $($TraceObject.TraceName)`'") $_
                            Continue
                        }
                        $fFound = $True
                        $StoppedTraceList.Add($TraceObject)
                        $TraceObject.Status = $TraceStatus.Stopped
                        Break
                    }
                }
                If(!$fFound){
                    # Trace is not running.
                    $TraceObject.Status = $TraceStatus.Stopped
                }
            }
            'Command' {
                If($TraceObject.SupprotedOSVersion -ne $Null){
                    If(!(IsSupportedOSVersion $TraceObject.SupprotedOSVersion)){
                        LogMessage $LogLevel.Info ($TraceObject.Name + ' is not supported on this OS. Supported Version is [Windows ' + $TraceObject.SupprotedOSVersion.OS + ' Build ' + $TraceObject.SupprotedOSVersion.Build + ']')
                        $TraceObject.Status = $TraceStatus.NotSupported
                        Break
                    }
                }
                LogMessage $LogLevel.Debug ('Enter [Command] section in StopTraces. Stopping ' + $TraceObject.Name)
                Try{
                    Get-Command $TraceObject.CommandName -ErrorAction Stop | Out-Null
                }Catch{
                    If($TraceObject.Name -eq 'Procmon' -and $TraceObject.AutoLogger.AutoLoggerEnabled -eq $True){
                        LogMessage $LogLevel.Debug ('[Procmon] setting $fDonotDeleteProcmonReg to $True.')
                        $script:fDonotDeleteProcmonReg = $True
                    }
                    LogMessage $LogLevel.Error ($TraceObject.CommandName + ' not found. Please stop ' + $TraceObject.Name + ' manually.')
                    $TraceObject.Status = $TraceStatus.ErrorInStop
                    Break
                }

                $fFoundExistingSession = $False
                Switch($TraceObject.Name) {
                    'WPR' {
                        # Normal case.
                        If(!$StopAutoLogger.IsPresent){
                            $WPRSessionName = 'WPR_initiated_WprApp_WPR'
                        # AutoLogger case.
                        }Else{
                            $WPRSessionName = 'WPR_initiated_WprApp_boottr_WPR'
                        }

                        LogMessage $LogLevel.Debug ('Searching ' + $WPRSessionName + ' in CimInstances')

                        $fFound = $False
                        ForEach($Line in ($ETWSessionList -split "`r`n")){
                            $Token = $Line -Split '\s+'
                            If($Token[0] -eq $WPRSessionName){
                                $fFound = $True
                                $fFoundExistingSession = $True
                                LogMessage $LogLevel.Debug ('[WPR] Found existing ' + $WPRSessionName + ' session.')
                                Break
                            }
                        }
                        If(!$fFound){
                            # WPR is not running
                            $TraceObject.Status = $TraceStatus.Stopped
                        }
                    }
                    'Netsh' {
                        $NetshSessionName = 'NetTrace'
                        $fFound = $False
                        ForEach($Line in ($ETWSessionList -split "`r`n")){
                            $Token = $Line -Split '\s+'
                            If($Token[0].Contains($NetshSessionName)){
                                $fFound = $True
                                $fFoundExistingSession = $True
                                LogMessage $LogLevel.Debug ('[Netsh] Found existing ' + $Token[0] + ' session.')
                                Break
                            }
                        }
                        If(!$fFound){
                            # Netsh is not running
                            $TraceObject.Status = $TraceStatus.Stopped
                        }
                    }
                    'Procmon' {
                        $Prcmon = $Processes | Where-Object{$_.Name.ToLower() -eq 'procmon'}
                        If($Prcmon.Count -ne 0){
                            $fFoundExistingSession = $True
                            LogMessage $LogLevel.Debug ('[Procmon] procmon is runing as active session.')
                            Break
                        }
                        If($StopAutoLogger.IsPresent){
                            If(Test-Path -Path $TraceObject.AutoLogger.AutoLoggerKey){
                                Try{
                                    $Value = Get-Itemproperty -name 'Start' -path $TraceObject.AutoLogger.AutoLoggerKey -ErrorAction SilentlyContinue
                                }Catch{
                                    LogMessage $LogLevel.Debug ('[Procmon] Start registry for procmon does not exist. Skipping procmon.')
                                    $fFoundExistingSession = $False 
                                    Break
                                }
                                # Start = 3 means this is first boot after bootlogging.
                                If($Value.Start -ne $NULL -and ($Value.Start -eq 3 -or $Value.Start -eq 0)){
                                    LogMessage $LogLevel.Debug ('[Procmon] Bootlogging detected.')
                                    $fFoundExistingSession = $True 
                                }Else{
                                    LogMessage $LogLevel.Debug ('[Procmon] Start registry = ' + $Value.Start)
                                }
                            }
                        }
                    }
                    'PSR' {
                        $PSRProcess = $Processes | Where-Object{$_.Name.ToLower() -eq 'psr'}
                        If($PSRProcess.Count -ne 0){
                            $fFoundExistingSession = $True
                            LogMessage $LogLevel.Debug ('[PSR] Found existing ' + $TraceObject.Name + ' session.')
                        }
                    }
                }

                If(!$fFoundExistingSession){
                    LogMessage $LogLevel.Debug ('Skipping stopping ' + $TraceObject.Name + ' as it is not running')
                    Continue
                }

                # Normal case. Perform actual stop function here.
                If(!$StopAutoLogger.IsPresent){
                    LogMessage $LogLevel.Info ('[' + $TraceObject.Name + '] Running ' + $TraceObject.CommandName + ' ' + $TraceObject.StopOption)
                    Start-Job -Name ($TraceObject.Name) -ScriptBlock {
                        Start-Process -FilePath $Using:TraceObject.CommandName -ArgumentList $Using:TraceObject.StopOption -PassThru -wait
                    } | Out-Null
                # Autologger case.
                }Else{ 
                    LogMessage $LogLevel.Info ('[' + $TraceObject.Name + '] Running ' + $TraceObject.CommandName + ' ' + $TraceObject.AutoLogger.AutoLoggerStopOption)
                    Start-Job -Name ($TraceObject.Name) -ScriptBlock {
                        Start-Process -FilePath $Using:TraceObject.CommandName -ArgumentList $Using:TraceObject.AutoLogger.AutoLoggerStopOption -PassThru -wait
                    } | Out-Null

                    If($TargetObject.Name -eq 'Procmon' -and $StopAutoLogger.IsPresent){
                        Try{
                            LogMessage $LogLevel.Debug ('Deleting procmon registries')
                            Remove-ItemProperty -Path $TraceObject.AutoLogger.AutoLoggerKey -Name 'Start' -ErrorAction SilentlyContinue
                            Remove-ItemProperty -Path $TraceObject.AutoLogger.AutoLoggerKey -Name 'Type'  -ErrorAction SilentlyContinue
                        }Catch{
                            # Do Nothing.
                            LogMessage $LogLevel.Warning ('Failed to delete procmon registries for ' + $TraceObject.AutoLogger.AutoLoggerKey)
                        }
                    }
                }
                $TraceObject.Status = $TraceStatus.Stopped
                $StoppedTraceList.Add($TraceObject)
            }
            'Perf' {
                LogMessage $LogLevel.Debug ('Enter [Perf] section in StopTraces. Name = ' + $TraceObject.Name)
                $datacollectorset = new-object -COM Pla.DataCollectorSet
                Try{  
                    $datacollectorset.Query($TraceObject.Name, $env:computername)
                }Catch{
                    LogMessage $LogLevel.Info ('Skipping stopping ' + $TraceObject.Name + ' as it is not running')
                    Break
                }

                #Status ReturnCodes: 0=stopped 1=running 2=compiling 3=queued (legacy OS) 4=unknown (usually autologger)
                If($datacollectorset.Status -ne 1){
                    LogMessage $LogLevel.Debug ('Skipping stopping ' + $TraceObject.Name + ' as it is not running')
                    Break
                }
                LogMessage $LogLevel.Info ('[' + $TraceObject.Name + '] Running logman stop ' + $TraceObject.Name)
                logman stop $TraceObject.Name | Out-Null
                If($LASTEXITCODE -ne 0){
                    LogMessage $LogLevel.Error ('[' + $TraceObject.Name + '] Failed to stop perfomance log.')
                    $TraceObject.Status = $TraceStatus.ErrorInStop
                }
                LogMessage $LogLevel.Info ('[' + $TraceObject.Name + '] Running logman delete ' + $TraceObject.Name)
                logman delete $TraceObject.Name | Out-Null
                If($LASTEXITCODE -ne 0){
                    LogMessage $LogLevel.Error ('[' + $TraceObject.Name + '] Failed to delete perfomance log.')
                    $TraceObject.Status = $TraceStatus.ErrorInStop
                }Else{
                    LogMessage $LogLevel.Debug ('[Perf] perf was successfully stopped.')
                    $TraceObject.Status = $TraceStatus.Stopped
                    $StoppedTraceList.Add($TraceObject)
                }
            }
            'Custom' {
                If($TraceObject.SupprotedOSVersion -ne $Null){
                    If(!(IsSupportedOSVersion $TraceObject.SupprotedOSVersion)){
                        $ErrorMessage = $TraceObject.Name + ' is not supported on this OS. Supported Version is [Windows ' + $TraceObject.SupprotedOSVersion.OS + ' Build ' + $TraceObject.SupprotedOSVersion.Build + '].'
                        LogMessage $LogLevel.Debug $ErrorMessage
                        $TraceObject.Status = $TraceStatus.NotSupported
                        Break
                    }
                }
                LogMessage $LogLevel.Debug ('Enter [Custom] section in StopTraces. Start processing ' + $TraceObject.TraceName)
                # Check if the trace has pre-start function. If so, just call it.
                LogMessage $LogLevel.Debug ('[' + $TraceObject.Name + ']' + ' calling stop function ' + $TraceObject.StopFunc)
                Try{
                    If($TraceObject.StopFunc -ne $Null){
                        & $TraceObject.StopFunc
                        $fCustomStopFuncStarted = $True
                    }Else{
                        $TraceObject.Status = $TraceStatus.NoStopFunction
                    }
                }Catch{
                    LogException ('[' + $TraceObject.Name + '] An error happened in stop function(' + $TraceObject.StopFunc + ').') $_
                    $TraceObject.Status = $TraceStatus.ErrorInStop
                    Continue
                }
                If($fCustomStopFuncStarted){
                    $TraceObject.Status = $TraceStatus.Stopped
                    $StoppedTraceList.Add($TraceObject)
                }
            }
            Default {
                LogMessage $LogLevel.Error ('Unknown log type ' + $TraceObject.LogType)
            }
        }

        # Check if the trace has post-stop function. If so, just call it.
        $ComponentPostStopFunc = $TraceObject.Name + 'PostStop'
        $Func = $Null
        Try{
            $Func = Get-Command $ComponentPostStopFunc -CommandType Function -ErrorAction Stop
        }Catch{
            # Do nothing
        }

        If($Func -ne $Null){
            Try{
                LogMessage $LogLevel.Info ('[' + $TraceObject.Name + "] Calling post-stop function $ComponentPostStopFunc")
                & $ComponentPostStopFunc
            }Catch{
                LogMessage $LogLevel.Warning ('[' + $TraceObject.Name + '] Error happens in pre-start function(' + $ComponentPostStopFunc + '). Skipping this trace.')
                LogException ("An error happened in $ComponentPostStopFunc") $_ $fLogFileOnly
            }
        }
    }

    # Won't collect basic logs if we are in recovery process.
    If(!$fInRecovery){
        # Now call component specific log function and CollectBasicLog
        # The naming convention of the function is 'Collect' + $TraceObject.Name + 'Log'(ex. CollectRDSLog)
        ForEach($StoppedTrace in $StoppedTraceList){

            # In case of RDS or Logon Object, collect exisisting umstartup.
            If($StoppedTrace.Name -eq 'RDS' -or $StoppedTrace.Name -eq 'Logon' -and !$fStopUmstartupDone){

                LogMessage $LogLevel.Info ('[' + $StoppedTrace.Name + '] Stopping existing umstartup trace')
                logman stop 'umstartup' -ets | Out-Null
                $fStopUmstartupDone = $True

                LogMessage $LogLevel.Debug ('Copying umstartup')
                $UmstartupFiles = "C:\Windows\System32\umstartup*"
                If(Test-Path -Path $UmstartupFiles){
                    Try{
                        Copy-Item 'C:\Windows\System32\umstartup*' $LogFolder -ErrorAction Stop
                    }Catch{
                        LogException  ('Unable to copy umstartup:' + $_.Exception.Message) $_ $fLogFileOnly
                    }
                }Else{
                    LogMessage $LogLevel.Debug ('Umstartup is not running.') # we don't care any error so no handler for this.
                }
            }

            # Calling component callback function
            $ComponentSpecificFunc = 'Collect' + $StoppedTrace.Name + 'Log'
            Try{
                 Get-Command $ComponentSpecificFunc -ErrorAction Stop | Out-Null
            }Catch{
                 LogMessage $LogLevel.Debug ('Component specific function ' + $ComponentSpecificFunc + ' is not defined in this script.')
                 Continue
            }
            LogMessage $LogLevel.Debug ('Component specific function ' + $ComponentSpecificFunc + ' is being called.')
            Try{
                & $ComponentSpecificFunc  # Calling CollectRDSLog, CollectLogonLog etc..
            }Catch{
                LogException  ('An exception happens in ' + $ComponentSpecificFunc) $_ 
            }
        }
        # Always collect basic log
        If(!$NoBasicLog.IsPresent){
            CollectBasicLog
        }
    }

    $Jobs = Get-Job
    If($Jobs.Count -ne 0){
        LogMessage $LogLevel.Info ('Stopping jobs may take a few minutes. Please wait a while.')
        ForEach($Job in $Jobs){
            LogMessage $LogLevel.Info ('Stopping ' + $Job.Name + '...')
        }
    }

    # Start wating for jobs to be completed.
    While($Jobs.Count -ne 0){
        Write-Host('.') -NoNewline
        ForEach($Job in $Jobs){
            Switch($Job.State){
                'Completed'{
                    LogMessage $LogLevel.Info ($Job.Name + ' is completed.')
                    Remove-Job $Job
                    $TraceObject = $TraceCollection | Where-Object {$_.Name -eq $Job.Name}
                    $TraceObject.Status = $TraceStatus.Stopped
                }
                'Failed'{
                    LogMessage $LogLevel.Error ($Job.Name + ' failed.' + "`n" + $job.ChildJobs[0].JobStateInfo.Reason.Message)
                    Remove-Job $Job
                    $TraceObject = $TraceCollection | Where-Object {$_.Name -eq $Job.Name}
                    $TraceObject.Status = $TraceStatus.ErrorInStop
                }
                'Running'{
                    #Write-Host($Job.Name + ' is still running. Wait a while.')
                }
                Default {
                    LogMessage $LogLevel.Info ($Job.Name + ' is in ' + $Job.State + '. This is not normal. If this state keeps showing. please stop the job with below command.')
                    LogMessage $LogLevel.Info ('Stop command: ')
                    LogMessage $LogLevel.Info ('    Stop-Job -Name ' + $Job.Name)
                    LogMessage $LogLevel.Info ('    Remove-Job -Name ' + $Job.Name)
                }
            }
        }
        $Jobs = Get-Job
        Start-Sleep 5
    }

    Write-Host('')
    #LogMessage $LogLevel.Info ($StoppedTraceList.Count.ToString() + ' trace(s) are stopped.')
    EndFunc $MyInvocation.MyCommand.Name
}

Function StopAllTraces{
    StopTraces $GlobalTraceCatalog
}

Function DeleteAutoLogger{
    EnterFunc $MyInvocation.MyCommand.Name
    LogMessage $LogLevel.Debug ("fPreparationCompleted is $script:fPreparationCompleted")
    If(!$script:fPreparationCompleted){
        Try{
            RunPreparation
        }Catch{
            LogMessage $LogLevel.Error ('Error happend while setting trace properties. Exiting...')
            CleanUpandExit
        }
    }

    $Count=0
    $EnabledAutoLoggerSessions = GetEnabledAutoLoggerSession
    ForEach($TraceObject in $EnabledAutoLoggerSessions){

        If($TraceObject.AutoLogger -eq $Null -or !$TraceObject.AutoLogger.AutoLoggerEnabled){
            Continue
        }

        LogMessage $LogLevel.Debug ('Processing deleting autologger setting for ' + $TraceObject.Name)
        Try{
            Switch($TraceObject.LogType){
                'ETW' {
                    LogMessage $LogLevel.Info ('[ETW] Deleting ' + $TraceObject.AutoLogger.AutoLoggerSessionName)
                    logman stop $TraceObject.Name -ets | Out-Null
                    logman delete $TraceObject.AutoLogger.AutoLoggerSessionName | Out-Null
                    If($LASTEXITCODE -ne 0){
                        Throw('Error happens in logman delete ' + $TraceObject.AutoLogger.AutoLoggerSessionName)
                    }
                }
                'Command' {
                    Switch($TraceObject.Name) {
                        'WPR' {
                            LogMessage $LogLevel.Info ('[' + $TraceObject.Name + '] Canceling boottrace.')
                            wpr.exe -boottrace -cancelboot
                             If($LASTEXITCODE -ne 0){
                                 $ErrorMssage = 'Error happens in wpr.exe -boottrace -cancelboot'
                                 LogMessage $LogLevel.Error $ErrorMssage 
                                 Throw($ErrorMssage)
                             }
                        }
                        'Netsh' {
                             netsh trace show status  | Out-Null
                             If($LASTEXITCODE -ne 0){
                                 LogMessage $LogLevel.Debug ('[' + $MyInvocation.MyCommand.Name + '] Netsh is not running') 
                                 Continue
                             }
                             LogMessage $LogLevel.Info ('[' + $TraceObject.Name + '] Running ' + $TraceObject.CommandName + ' ' + $TraceObject.AutoLogger.AutoLoggerStopOption)
                             Start-Process -FilePath $TraceObject.CommandName -ArgumentList $TraceObject.AutoLogger.AutoLoggerStopOption -PassThru -wait | Out-Null
                        }
                        'Procmon' {
                            If($script:fDonotDeleteProcmonReg){
                                Break
                            }
                            LogMessage $LogLevel.Info ('[Procmon] Deleting procmon registries(' + $TraceObject.AutoLogger.AutoLoggerKey + '\Start and Type)')
                            Remove-ItemProperty -Path $TraceObject.AutoLogger.AutoLoggerKey -Name 'Start' -ErrorAction SilentlyContinue
                            Remove-ItemProperty -Path $TraceObject.AutoLogger.AutoLoggerKey -Name 'Type' -ErrorAction SilentlyContinue
                        }
                    }
                }
            }
        }Catch{
            LogException ('An exception happens during deleting autologger setting for ' + $TraceObject.Name) $_
            Continue
        }
        $Count++
    }

    If($Count -ne 0){
        LogMessage $LogLevel.Info ($Count.ToString() + ' autosession traces are deleted.')
    }Else{
        LogMessage $LogLevel.Info ('No autologger session was found.')
    }
    EndFunc $MyInvocation.MyCommand.Name
}

Function StartPerfLog{
    param(
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [Object]$TraceObject
    )
    EnterFunc $MyInvocation.MyCommand.Name
    LogMessage $LogLevel.Debug ('Starting performance log.')
    If($TraceObject.LogType -ne 'Perf' -or $TraceObject.Providers.Length -eq 0){
        $ErrorMessage = ('Invalid object(LogType:' + $TraceObject.LogType + ') was passed to StartPerfLog.')
        LogMessage $LogLevel.Error $ErrorMessage
        Throw($ErrorMessage)
    }

    ForEach($PerfCounter in $TraceObject.Providers){
        $AllCounters += "`"" + $PerfCounter + "`""  + " "
    }
    
    $Perfcmd = "logman create counter " + $TraceObject.Name + " -o `"" + $TraceObject.LogFileName + "`" -si $PerflogInterval -c $AllCounters" # | Out-Null"
    LogMessage $LogLevel.Info ("[Perf] Runing $Perfcmd")
    Try{
        Invoke-Expression $Perfcmd -ErrorAction Stop | Out-Null
    }Catch{
        $ErrorMessage = ('An exception happened in logman create counter.')
        LogException ($ErrorMessage) $_ $fLogFileOnly
        Throw($ErrorMessage)
    }

    logman start $TraceObject.Name  | Out-Null
    If($LASTEXITCODE -ne 0){
        $ErrorMessage = ('An error happened during starting ' + $TraceObject.Name + '(Error=' + [Convert]::ToString($LASTEXITCODE,16) + ')')
        LogMessage $LogLevel.Error $ErrorMessage
        Throw($ErrorMessage)
    }
    EndFunc $MyInvocation.MyCommand.Name
}

Function RunCommands{
    param(
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$LogPrefix,
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String[]]$CmdletArray,
        [parameter(Mandatory=$true)]
        [Bool]$ThrowException,
        [parameter(Mandatory=$true)]
        [Bool]$ShowMessage
    )

    ForEach($CommandLine in $CmdletArray){
        $tmpMsg = $CommandLine -replace "\| Out-File.*$",""
        $tmpMsg = $tmpMsg -replace "\| Out-Null.*$",""
        $tmpMsg = $tmpMsg -replace "\-ErrorAction Stop",""
        $tmpMsg = $tmpMsg -replace "\-ErrorAction SilentlyContinue",""
        $CmdlineForDisplayMessage = $tmpMsg -replace "2>&1",""
        Try{
            If($ShowMessage){
                LogMessage $LogLevel.Info ("[$LogPrefix] Running $CmdlineForDisplayMessage")
            }
            # Run actual command here.
            $LASTEXITCODE = 0
            Invoke-Expression -Command $CommandLine -ErrorAction Stop | Out-Null
            If($LASTEXITCODE -ne 0){
                Throw("An error happened during running `'$CommandLine` " + '(Error=0x' + [Convert]::ToString($LASTEXITCODE,16) + ')')
            }
        }Catch{
            If($ThrowException){
                Throw $_   # Leave the error handling to upper function.
            }Else{
                LogException ("An error happened in $CommandLine") $_ $fLogFileOnly
                Continue
            }
        }
    }
}

Function ExportRegistry{
    param(
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$LogPrefix,
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [Array]$RegistryKeys
    )
    ForEach($RegistryKey in $RegistryKeys){
        $ExportKey = $RegistryKey[0]
        $LogFile = $RegistryKey[1]
        LogMessage $LogLevel.debug ("Exporting Reg=$ExportKey" + " LogFile=$LogFile")

        If(!(Test-Path -Path $ExportKey)){
            Continue
        }
        LogMessage $LogLevel.Info ("[$LogPrefix] Exporting $ExportKey")
        Try{
            $Key = Get-Item $ExportKey -ErrorAction Stop
        }Catch{
            LogException ("Error: An exception happens in Get-Item $RegistryKey.") $_ $fLogFileOnly
            Continue
        }
       
        Write-Output("[" + $Key.Name + "]") | Out-File -Append $LogFile
        ForEach($Property in $Key.Property){
            Write-Output($Property + "=" + $Key.GetValue($Property)) | Out-File -Append $LogFile
        }

        Try{
            $ChildKeys = Get-ChildItem $ExportKey -Recurse -ErrorAction Stop
        }Catch{
            LogException ("Error: An exception happens in Get-ChildItem $RegistryKey.") $_ $fLogFileOnly
            Continue 
        }

        ForEach($ChildKey in $ChildKeys){
            Write-Output("[" + $ChildKey.Name + "]") | Out-File -Append $LogFile
            Try{
                $Key = Get-Item $ChildKey.PSPath -ErrorAction Stop
            }Catch{
                LogException ("Error: An exception happens in Get-Item $RegistryKey.") $_ $fLogFileOnly
                Continue
            }
            ForEach($Property in $Key.Property){
                Try{
                    Write-Output($Property + "=" + $Key.GetValue($Property)) | Out-File -Append $LogFile
                }Catch{
                    LogException ("Error: An exception happens in Write-Output $Key.") $_ $fLogFileOnly
                }
            }
        }
    }
}

Function ExportRegistryToOneFile{
    param(
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$LogPrefix,
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [Array]$RegistryKeys,
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$LogFile
    )

    ForEach($RegistryKey in $RegistryKeys){
        LogMessage $LogLevel.debug ("Exporting Reg=$RegistryKey" + " LogFile=$LogFile")
        If(!(Test-Path -Path $RegistryKey)){
            Continue
        }
        LogMessage $LogLevel.Info ("[$LogPrefix] Exporting $RegistryKey")
        Try{
            $Key = Get-Item $RegistryKey -ErrorAction Stop
        }Catch{
            LogException ("Error: An exception happens in Get-Item $RegistryKey.") $_ $fLogFileOnly
            Continue
        }
       
        Write-Output("[" + $Key.Name + "]") | Out-File -Append $LogFile
        ForEach($Property in $Key.Property){
            Write-Output($Property + "=" + $Key.GetValue($Property)) | Out-File -Append $LogFile
        }

        Try{
            $ChildKeys = Get-ChildItem $RegistryKey -Recurse -ErrorAction Stop
        }Catch{
            LogException ("Error: An exception happens in Get-ChildItem $RegistryKey.") $_ $fLogFileOnly
            Return # This is critical and return.
        }

        ForEach($ChildKey in $ChildKeys){
            Write-Output("[" + $ChildKey.Name + "]") | Out-File -Append $LogFile
            Try{
                $Key = Get-Item $ChildKey.PSPath -ErrorAction Stop
            }Catch{
                LogException ("Error: An exception happens in Get-Item $RegistryKey.") $_ $fLogFileOnly
                Continue
            }
            ForEach($Property in $Key.Property){
                Try{
                    Write-Output($Property + "=" + $Key.GetValue($Property)) | Out-File -Append $LogFile
                }Catch{
                    LogException ("Error: An exception happens in Write-Output $Key.") $_ $fLogFileOnly
                }
            }
        }
    }
}

Function ExportEventlog{
    param(
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$LogPrefix,
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [Array]$EventLogs,
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$LogFolder
    )

    ForEach($EventLog in $EventLogs){
        LogMessage $LogLevel.Info ("[$LogPrefix] Exporting $EventLog")

        $tmpStr = $EventLog.Replace('/','-')
        $EventLogName = ($tmpStr.Replace(' ','-') + '.evtx')
        $CommandLine = "wevtutil epl $EventLog $LogFolder/$EventLogName 2>&1 | Out-Null"
        LogMessage $LogLevel.Debug ("Running $CommandLine")
        Try{
            Invoke-Expression $CommandLine
        }Catch{
            LogException ("An error happened in $CommandLine") $_ $fLogFileOnly
            Continue
        }
    }
}

# This function disable quick edit mode. If the mode is enabled, 
# console output will hang when key input or strings are selected. 
# So disable the quick edit mode druing running script and 
# re-enable it after script is finished.
$QuickEditCode=@"
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using System.Runtime.InteropServices;


public static class DisableConsoleQuickEdit
{

    const uint ENABLE_QUICK_EDIT = 0x0040;

    // STD_INPUT_HANDLE (DWORD): -10 is the standard input device.
    const int STD_INPUT_HANDLE = -10;

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr GetStdHandle(int nStdHandle);

    [DllImport("kernel32.dll")]
    static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);

    [DllImport("kernel32.dll")]
    static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);

    public static bool SetQuickEdit(bool SetEnabled)
    {

        IntPtr consoleHandle = GetStdHandle(STD_INPUT_HANDLE);

        // get current console mode
        uint consoleMode;
        if (!GetConsoleMode(consoleHandle, out consoleMode))
        {
            // ERROR: Unable to get console mode.
            return false;
        }

        // Clear the quick edit bit in the mode flags
        if (SetEnabled)
        {
            consoleMode &= ~ENABLE_QUICK_EDIT;
        }
        else
        {
            consoleMode |= ENABLE_QUICK_EDIT;
        }

        // set the new mode
        if (!SetConsoleMode(consoleHandle, consoleMode))
        {
            // ERROR: Unable to set console mode
            return false;
        }

        return true;
    }
}
"@
Try{
    $QuickEditMode = add-type -TypeDefinition $QuickEditCode -Language CSharp -ErrorAction Stop
    $fQuickEditCodeExist = $True
}Catch{
    $fQuickEditCodeExist = $False
}
Function SetEventLog{
    param(
        [parameter(Mandatory=$true)]
        [String]$EventLogName
    )
    EnterFunc $MyInvocation.MyCommand.Name
    LogMessage $LogLevel.Debug ("Changing event log setting for $EventLogName")

    $fChanged = $False

    Try{
        $logDetails = Get-LogProperties -Name $EventLogName -ErrorAction Stop
    }Catch{
        $ErrorMessage = '[SetEventLog] An Exception happened in Get-LogProperties.' + 'HResult=0x' + [Convert]::ToString($_.Exception.HResult,16) + 'Exception=' + $_.CategoryInfo.Reason + ' Eventlog=' + $EventLogName
        LogException $ErrorMessage $_ $fLogFileOnly
        Throw($ErrorMessage)
    }

    If(-Not($logDetails.Enabled)){
        $fChanged = $True
        $logDetails.Enabled = $True
    }

    If($fChanged) {
        Try {
            # Save registry key for this event log.
            New-Item -Path "HKLM:\SOFTWARE\Microsoft\UXTrace\EventLog" -Force -ErrorAction Stop | Out-Null
            Copy-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\$EventLogName" -Destination "HKLM:\SOFTWARE\Microsoft\UXTrace\EventLog" -ErrorAction Stop | Out-Null

            # Change event log settings.
            Set-LogProperties -LogDetails $logDetails -Force -ErrorAction Stop | Out-Null
        } Catch {
            $ErrorMessage = '[SetEventLog] ERROR: Encountered an error during changing event log ' + $EventLogName
            LogException $ErrorMessage $_ $fLogFileOnly
            Throw($ErrorMessage)
        }
    }
    EndFunc $MyInvocation.MyCommand.Name
}

Function ResetEventLog{
    param(
        [parameter(Mandatory=$true)]
        [String]$EventLogName
    )
    EnterFunc $MyInvocation.MyCommand.Name
    LogMessage $LogLevel.Debug ("Restoring event log setting for $EventLogName")
    Try{
        $regKey = Get-Item "HKLM:\SOFTWARE\Microsoft\UXTrace\EventLog\$EventLogName" -ErrorAction Stop
    }Catch{
        # It seems no change was made when SetEventLog. So just return.
        Return
    }

    Try{
        $logDetails = Get-LogProperties -Name $EventLogName -ErrorAction Stop
    }Catch{
        $ErrorMessage = '[ResetEventLog] An exception happened in Get-LogProperties.'  + 'HResult=0x' + [Convert]::ToString($_.Exception.HResult,16) + 'Exception=' + $_.CategoryInfo.Reason + ' Eventlog=' + $EventLogName
        LogException $ErrorMessage $_ $fLogFileOnly
        Throw($ErrorMessage)
    }

    $enabled = $regKey.GetValue("Enabled")
    If($enabled -eq 0){
        $logDetails.Enabled = $False;
    }

    Try{
        # Restore event log settings.
        Set-LogProperties -LogDetails $logDetails -Force | Out-Null

        # Remove saved registry key for this event log.
        Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\UXTrace\EventLog\$EventLogName" -ErrorAction Stop | Out-Null
    }Catch{
        $ErrorMessage = '[ResetEventLog] ERROR: Encountered an error during restoring event log. Eventlog=' + $EventLogName + ' Command=' + $_.CategoryInfo.Activity + ' HResult=0x' + [Convert]::ToString($_.Exception.HResult,16) + ' Exception=' + $_.CategoryInfo.Reason
        LogException $ErrorMessage $_ $fLogFileOnly
        Throw($ErrorMessage)
    }

    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\UXTrace\EventLog" -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\UXTrace" -ErrorAction SilentlyContinue | Out-Null
    EndFunc $MyInvocation.MyCommand.Name
}

Function FileVersion {
    param(
      [string] $FilePath
    )
    EnterFunc $MyInvocation.MyCommand.Name

    if (Test-Path -Path $FilePath) {
        Try{
            $fileobj = Get-item $FilePath -ErrorAction Stop
            $filever = $fileobj.VersionInfo.FileMajorPart.ToString() + "." + $fileobj.VersionInfo.FileMinorPart.ToString() + "." + $fileobj.VersionInfo.FileBuildPart.ToString() + "." + $fileobj.VersionInfo.FilePrivatepart.ToString()
            $FilePath + "," + $filever + "," + $fileobj.CreationTime.ToString("yyyyMMdd HH:mm:ss")
        }Catch{
            # Do nothing
        }
    }

    EndFunc $MyInvocation.MyCommand.Name
}

Function CollectBasicLog{
    EnterFunc $MyInvocation.MyCommand.Name
    $LogPrefix = 'BasicLog'
    $BasicLogFolder = "$LogFolder\BasicLog$LogSuffix"
    $EventLogFolder = "$BasicLogFolder\EventLogs"
    $SetupLogFolder = "$BasicLogFolder\Setup"
    Try{
        CreateLogFolder $BasicLogFolder
        CreateLogFolder $EventLogFolder
        CreateLogFolder $SetupLogFolder
    }Catch{
        LogMessage $LogLevel.Error ("Unable to create log folder." + $_.Exception.Message)
        Return
    }

    Try{
        $fServerSKU = (Get-CimInstance -Class CIM_OperatingSystem -ErrorAction Stop).Caption -like "*Server*"
    }Catch{
        LogMessage $LogLevel.ErrorLogFileonly ("Get-CimInstance for CIM_OperatingSystem failed.`n" + 'Command=' + $_.CategoryInfo.Activity + ' HResult=0x' + [Convert]::ToString($_.Exception.HResult,16) + ' Exception=' + $_.CategoryInfo.Reason + ' Message=' + $_.Exception.Message)
        $fServerSKU = $False
    }

    #------ Basic ------#
    LogMessage $LogLevel.Info ('[BasicLog] Obtaining system basic info using WMI')
    $Commands = @(
        # Basic
        "Get-CimInstance -Class CIM_Processor -ErrorAction Stop | fl * | Out-File -Append $BasicLogFolder\Basic_CPU_info.txt"
        "Get-CimInstance -Class CIM_OperatingSystem -ErrorAction Stop | fl * | Out-File -Append $BasicLogFolder\Basic_OS_info.txt"
        "Get-CimInstance -Class CIM_ComputerSystem -ErrorAction Stop | fl * | Out-File -Append $BasicLogFolder\Basic_Computer_info.txt"
        # Hotfix
        "Get-Hotfix -ErrorAction Stop | Sort-Object -Property HotFixID -Descending | Out-File -Append $BasicLogFolder\Basic_Hotfix.txt"
        # User and profile
        "Whoami /user 2>&1 | Out-File -Append  $BasicLogFolder\Basic_Whoami.txt"
        "gwmi -Class Win32_UserProfile -ErrorAction Stop | Out-File -Append $BasicLogFolder\Basic_Win32_UserProfile.txt"
        "Get-ChildItem `'HKLM:Software\Microsoft\Windows NT\CurrentVersion\ProfileList`' -Recurse | Out-File -Append $BasicLogFolder\Basic_Profilelist_reg.txt"
        # WER
        "Get-ChildItem `'HKLM:Software\Microsoft\Windows\Windows Error Reporting`' -Recurse | Out-File -Append $BasicLogFolder\Basic_WER_reg.txt"
        "Get-ItemProperty `'HKLM:System\CurrentControlSet\Control\CrashControl`' | Out-File -Append $BasicLogFolder\Basic_Dump_reg.txt"
        "Copy-Item `'C:\ProgramData\Microsoft\Windows\WER`' $BasicLogFolder -Recurse -ErrorAction SilentlyContinue"
        # Powercfg
        "powercfg /list 2>&1 | Out-File -Append $BasicLogFolder\Basic_powercfg.txt"
        "powercfg /qh 2>&1 | Out-File -Append $BasicLogFolder\Basic_powercfg.txt"
        "powercfg /a 2>&1 | Out-File -Append $BasicLogFolder\Basic_powercfg.txt"
        # TPM
        "Get-Tpm -ErrorAction Stop | Out-File -Append $BasicLogFolder\Basic_TPM.txt"
        # BCDEdit
        "bcdedit /enum 2>&1 | Out-File -Append $BasicLogFolder\Basic_Bcdedit.txt"
        "bcdedit /enum all 2>&1 | Out-File -Append $BasicLogFolder\Basic_Bcdedit-all.txt"
        "bcdedit /enum all /v 2>&1 | Out-File -Append $BasicLogFolder\Basic_Bcdedit-all-v.txt"
    )

    If($fServerSKU){
         $Commands += "Get-WindowsFeature -ErrorAction Stop | Out-File -Append $BasicLogFolder\Basic_Installed_Roles.txt"
    }

    # OS version with build number
    $VersionReg = Get-ItemProperty -Path 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    If($Version.Major -ge 10){
        'OS Version: ' + $VersionReg.ReleaseID + '(OS Build ' + $VersionReg.CurrentMajorVersionNumber + '.' + $VersionReg.CurrentMinorVersionNumber + '.' + $VersionReg.CurrentBuildNumber + '.' + $VersionReg.UBR + ')' | Out-File -Append "$BasicLogFolder\Basic_OSVersion.txt"
    }Else{
        'OS Version: ' + $VersionReg.CurrentVersion + '.' + $VersionReg.CurrentBuild | Out-File -Append "$BasicLogFolder\Basic_OSVersion.txt"
    }

    # Commands from Windows 10
    If($Version.Major -ge 10){
        $Commands += @(
            "Get-MpComputerStatus -ErrorAction Stop | Out-File -Append $BasicLogFolder\WindowsDefender.txt",
            "Get-MpPreference -ErrorAction Stop | Out-File -Append $BasicLogFolder\WindowsDefender.txt",
            "dsregcmd /status | Out-File $BasicLogFolder/Basic_dsregcmd.txt"
        )
    }
    RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$True

    # Driver info
    $Commands = @("driverquery /v | Out-File $BasicLogFolder/Basic_driverinfo.txt")
    RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$True

    # Prodct info
    Write-Output "===== 32bit applications =====" | Out-File "$BasicLogFolder\Basic_products.txt"
    Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Out-File -Append "$BasicLogFolder\Basic_products.txt"
    Write-Output "`n===== 64bit applications =====" | Out-File -Append "$BasicLogFolder\Basic_products.txt"
    Get-ItemProperty "HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Out-File -Append "$BasicLogFolder\Basic_products.txt"

    # Tasklist
    LogMessage $LogLevel.Info ('[BasicLog] Creating process list...')
    $Processes = Get-Process
    Write-Output(' ID         ProcessName') | Out-File -Append "$BasicLogFolder\Basic_tasklist.txt"
    Write-Output('---------------------------') | Out-File -Append "$BasicLogFolder\Basic_tasklist.txt"
    ForEach($Process in $Processes){
        $PID16 = '0x' + [Convert]::ToString($Process.ID,16)
        Write-Output(($Process.ID).ToString() + '(' + $PID16 + ')    '  + $Process.ProcessName) | Out-File -Append "$BasicLogFolder\Basic_tasklist.txt"
    }
    Write-Output('=========================================================================') | Out-File -Append "$BasicLogFolder\Basic_tasklist.txt"
    tasklist /svc 2>&1 | Out-File -Append "$BasicLogFolder\Basic_tasklist.txt"
    LogMessage $LogLevel.Info ('[BasicLog] Running tasklist -v.')
    tasklist /v 2>&1 | Out-File -Append "$BasicLogFolder\Basic_tasklist-v.txt"

    # .NET version
    If(test-path -path "HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full"){
        $Full = Get-ItemProperty "HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full"
        Write-Output(".NET version: $($Full.Version)") | Out-File -Append "$BasicLogFolder\Basic_DotNet-Version.txt"
        Write-Output("") | Out-File -Append "$BasicLogFolder\Basic_DotNet-Version.txt"
    }
    ExportRegistryToOneFile $LogPrefix 'HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP' "$BasicLogFolder\Basic_DotNet-Version.txt"

    # Installed .NET KB
    $DotNetVersions = Get-ChildItem HKLM:\SOFTWARE\WOW6432Node\Microsoft\Updates | Where-Object {$_.name -like "*.NET Framework*"}

    ForEach($Version in $DotNetVersions){
    
        $Updates = Get-ChildItem $Version.PSPath
        $Version.PSChildName | Out-File -Append "$BasicLogFolder\Basic_Installed_DotNetKB.txt"
        ForEach ($Update in $Updates){
            $Update.PSChildName | Out-File -Append "$BasicLogFolder\Basic_Installed_DotNetKB.txt"
        }
    }

    # msinfo32
    LogMessage $LogLevel.Info ('[BasicLog] Running msinfo32 /nfo ' + (Join-Path $BasicLogFolder 'Basic_msinfo32.nfo'))
    $msinfoTimeout = 300
    $msinfo32 = Start-Process -FilePath 'msinfo32' -ArgumentList "/nfo $BasicLogFolder\Basic_msinfo32.nfo" -PassThru

    # Basic registries
    LogMessage $LogLevel.Info ('[BasicLog] Obtaining recovery info')
    $RecoveryKeys = @(
        ('HKLM:System\CurrentControlSet\Control\CrashControl', "$BasicLogFolder\Basic_Registry_CrashControl.txt"),
        ('HKLM:System\CurrentControlSet\Control\Session Manager\Memory Management', "$BasicLogFolder\Basic_Registry_MemoryManagement.txt"),
        ('HKLM:Software\Microsoft\Windows NT\CurrentVersion\AeDebug', "$BasicLogFolder\Basic_Registry_AeDebug.txt"),
        ('HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Option', "$BasicLogFolder\Basic_Registry_ImageFileExecutionOption.txt"),
        ('HKLM:System\CurrentControlSet\Control\Session Manager\Power', "$BasicLogFolder\Basic_Registry_Power.txt")
    )
    ExportRegistry $LogPrefix $RecoveryKeys

    # RunOnece
    $StartupKeys = @(
        "HKCU:Software\Microsoft\Windows\CurrentVersion\Run"
        "HKCU:Software\Microsoft\Windows\CurrentVersion\Runonce"
        "HKCU:Software\Microsoft\Windows\CurrentVersion\RunonceEx"
        "HKCU:Software\Microsoft\Windows\CurrentVersion\RunServices"
        "HKCU:Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"
        "HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\Run"
        "HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        "HKLM:Software\Microsoft\Windows\CurrentVersion\Runonce"
        "HKLM:Software\Microsoft\Windows\CurrentVersion\RunonceEx"
        "HKLM:Software\Microsoft\Windows\CurrentVersion\RunServices"
        "HKLM:Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"
        "HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad"
    )
    ExportRegistryToOneFile $LogPrefix $StartupKeys "$BasicLogFolder\Basic_Registry_RunOnce_reg.txt"

    $WinlogonKeys = @(
        'HKCU:Software\Microsoft\Windows NT\CurrentVersion'
        'HKCU:Software\Microsoft\Windows NT\CurrentVersion\Windows'
        'HKCU:Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
        'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    )
    ExportRegistryToOneFile $LogPrefix $WinlogonKeys "$BasicLogFolder\Basic_Registry_Winlogon_reg.txt"

    # Installed product
    If(Is-Elevated){
        LogMessage $LogLevel.Info ('[BasicLog] Getting installed product info')
        $UninstallKey = 'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
        $Registries = Get-ChildItem $UninstallKey | Get-ItemProperty
        "Install date`tVersion`t`tProdcut Name" | Out-File -Append "$BasicLogFolder\Basic_Installed_Product.txt"
        ForEach($Registry in $Registries){
            If(($Registry.InstallSource -ne $Null -and $Registry.InstallSource -ne '') -and (Test-Path -Path $Registry.InstallSource)){
               $Registry.InstallDate + "`t" + $Registry.Version + "`t" + $Registry.DisplayName | Out-File -Append "$BasicLogFolder\Basic_Installed_Product.txt"
            }
        }
    }

    # Group policy
    LogMessage $LogLevel.Info ('[BasicLog] Obtaining group policy')
    $Commands = @(
        "gpresult /h $BasicLogFolder\Policy_gpresult.html 2>&1 | Out-Null"
        "gpresult /z 2>&1 | Out-File $BasicLogFolder\Policy_gpresult-z.txt"
    )
    RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$True

    $PoliciesKeys = @(
        'HKCU:Software\Policies'
        'HKLM:Software\Policies'
        'HKCU:Software\Microsoft\Windows\CurrentVersion\Policies'
        'HKLM:Software\Microsoft\Windows\CurrentVersion\Policies'
    )
    ExportRegistryToOneFile $LogPrefix $PoliciesKeys "$BasicLogFolder\Policy_reg.txt"

    # Eventlog
    $EventLogs = Get-WinEvent -ListLog * -ErrorAction SilentlyContinue
    LogMessage $LogLevel.Info ('[BasicLog] Exporting ' + $EventLogs.Count + ' event logs')
    ForEach($EventLog in $EventLogs){
        $tmpStr = $EventLog.LogName.Replace('/','-')
        $EventLogName = ($tmpStr.Replace(' ','-') + '.evtx')
        wevtutil epl $EventLog.LogName "$EventLogFolder\$EventLogName" 2>&1 | Out-Null
    }

    #------ Setup ------#
    LogMessage $LogLevel.Info ('[BasicLog] Copying setup files')
    $ServicingFiles = @(
        "C:\Windows\INF\Setupapi.*"  # Test-path can use wild card.
        "C:\Windows\Logs\CBS\*.Log"
        "C:\Windows\Logs\DISM\*"
        "C:\Windows\winsxs\pending.xml"
        "C:\Windows\winsxs\pending.xml.bad"
        "C:\Windows\winsxs\poqexec.log"
        "C:\Windows\logs\DPX\setupact.log"
        "C:\Windows\logs\CBS\CheckSUR.log"
        "C:\Windows\SoftwareDistribution\ReportingEvents.log"
        "C:\Windows\servicing\Sessions.xml"
        "C:\Windows\servicing\Sessions\*.*"
        "C:\Windows\winsxs\reboot.xml"
        "C:\Windows\system32\driverstore\drvindex.dat"
        "C:\Windows\system32\driverstore\INFCACHE.1"
        "C:\Windows\system32\driverstore\infpub.dat"
        "C:\Windows\system32\driverstore\infstor.dat"
        "C:\Windows\system32\driverstore\infstrng.dat"
        "C:\Windows\Setup\State\State.ini"
        "C:\Windows\Panther\*.log"
    )
    ForEach($ServicingFile in $ServicingFiles){
        If(Test-Path -Path $ServicingFile){
            Copy-Item $ServicingFile $SetupLogFolder -ErrorAction SilentlyContinue
        }
    }
    LogMessage $LogLevel.Info ('[BasicLog] Exporting setup registries and getting package info')
    #reg save "HKLM\COMPONENTS" "$SetupLogFolder\COMPONENT.HIV"
    reg save "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing" "$SetupLogFolder\Component Based Servicing.HIV" 2>&1 | Out-Null
    ExportRegistryToOneFile $LogPrefix "HKLM:SYSTEM\CurrentControlSet\services\TrustedInstaller" "$BasicLogFolder\TrustedInstaller_reg.txt"
    ExportRegistryToOneFile $LogPrefix "HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\State" "$BasicLogFolder\State_reg.txt"
    dism /online /get-packages 2>&1| Out-File "$SetupLogFolder\dism-get-package.txt" 

    #------- Networking --------#
    # TCP/IP
    LogMessage $LogLevel.Info ('[BasicLog] Gathering networking info')
    $Commands = @(
        "ipconfig /all 2>&1 | Out-File -Append $BasicLogFolder\Net_TCPIP_info.txt"
        "route print 2>&1 | Out-File -Append $BasicLogFolder\Net_TCPIP_info.txt"
        "arp -a 2>&1 | Out-File -Append $BasicLogFolder\Net_TCPIP_info.txt"
        "netstat -nato 2>&1 | Out-File -Append $BasicLogFolder\Net_TCPIP_info.txt"
        "netstat -anob 2>&1 | Out-File -Append $BasicLogFolder\Net_TCPIP_info.txt"
        "netstat -es 2>&1 | Out-File -Append $BasicLogFolder\Net_TCPIP_info.txt"
        "netsh int tcp show global 2>&1 | Out-File -Append $BasicLogFolder\Net_TCPIP_offload.txt"
        "netsh int ipv4 show offload 2>&1 | Out-File -Append $BasicLogFolder\Net_TCPIP_offload.txt"
        "netstat -nato -p tcp 2>&1 | Out-File -Append $BasicLogFolder\Net_TCPIP_offload.txt"
        "Get-NetIPAddress -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_TCPIP_pscmdlets.txt"
        "Get-NetIPInterface -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_TCPIP_pscmdlets.txt"
        "Get-NetIPConfiguration -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_TCPIP_pscmdlets.txt"
        "Get-NetIPv4Protocol -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_TCPIP_pscmdlets.txt"
        "Get-NetIPv6Protocol  -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_TCPIP_pscmdlets.txt"
        "Get-NetOffloadGlobalSetting -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_TCPIP_pscmdlets.txt"
        "Get-NetPrefixPolicy -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_TCPIP_pscmdlets.txt"
        "Get-NetRoute -IncludeAllCompartments -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_TCPIP_pscmdlets.txt"
        "Get-NetTCPConnection -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_TCPIP_pscmdlets.txt"
        "Get-NetTransportFilter -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_TCPIP_pscmdlets.txt"
        "Get-NetTCPSetting -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_TCPIP_pscmdlets.txt"
        "Get-NetUDPEndpoint -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_TCPIP_pscmdlets.txt"
        "Get-NetUDPSetting -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_TCPIP_pscmdlets.txt"
        # Firewall
        "Show-NetIPsecRule -PolicyStore ActiveStore -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_Firewall_info_pscmdlets.txt"
        "Get-NetIPsecMainModeSA -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_Firewall_info_pscmdlets.txt"
        "Get-NetIPsecQuickModeSA -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_Firewall_info_pscmdlets.txt"
        "Get-NetFirewallProfile -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_Firewall_info_pscmdlets.txt"
        "Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_Firewall_Get-NetFirewallRule.txt"
        "netsh advfirewall show allprofiles 2>&1 | Out-File -Append $BasicLogFolder\Net_Firewall_advfirewall.txt"
        "netsh advfirewall show allprofiles state 2>&1 | Out-File -Append $BasicLogFolder\Net_Firewall_advfirewall.txt"
        "netsh advfirewall show currentprofile 2>&1 | Out-File -Append $BasicLogFolder\Net_Firewall_advfirewall.txt"
        "netsh advfirewall show domainprofile 2>&1 | Out-File -Append $BasicLogFolder\Net_Firewall_advfirewall.txt"
        "netsh advfirewall show global 2>&1 | Out-File -Append $BasicLogFolder\Net_Firewall_advfirewall.txt"
        "netsh advfirewall show privateprofile 2>&1 | Out-File -Append $BasicLogFolder\Net_Firewall_advfirewall.txt"
        "netsh advfirewall show publicprofile 2>&1 | Out-File -Append $BasicLogFolder\Net_Firewall_advfirewall.txt"
        "netsh advfirewall show store 2>&1 | Out-File -Append $BasicLogFolder\Net_Firewall_advfirewall.txt"
        "Copy-Item C:\Windows\System32\LogFiles\Firewall\pfirewall.log $BasicLogFolder\Net_Firewall_pfirewall.log -ErrorAction SilentlyContinue"
        # SMB
        "Get-SmbMapping -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_SMB_Client_info.txt"
        "Get-SmbClientConfiguration -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_SMB_Client_info.txt"
        "Get-SmbClientNetworkInterface -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_SMB_Client_info.txt"
        "Get-SmbConnection -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_SMB_Client_info.txt"
        "Get-SmbMultichannelConnection -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_SMB_Client_info.txt"
        "Get-SmbMultichannelConstraint -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_SMB_Client_info.txt"
        "net config workstation 2>&1 | Out-File -Append $BasicLogFolder\Net_SMB_Client_net_command.txt"
        "net statistics workstation 2>&1 | Out-File -Append $BasicLogFolder\Net_SMB_Client_net_command.txt"
        "net use 2>&1 | Out-File -Append $BasicLogFolder\Net_SMB_Client_net_command.txt"
        "net accounts 2>&1 | Out-File -Append $BasicLogFolder\Net_SMB_Client_net_command.txt"
        "Get-SmbServerConfiguration -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_SMB_Server_info.txt"
        "Get-SmbServerNetworkInterface -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_SMB_Server_info.txt"
        "Get-SmbShare -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_SMB_Server_info.txt"
        "Get-SmbMultichannelConnection -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_SMB_Server_info.txt"
        "Get-SmbMultichannelConstraint -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_SMB_Server_info.txt"
        "Get-SmbOpenFile -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_SMB_Server_info.txt"
        "Get-SmbSession -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_SMB_Server_info.txt"
        "Get-SmbWitnessClient -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_SMB_Server_info.txt"
        "net config server 2>&1 | Out-File -Append $BasicLogFolder\Net_SMB_Server_net_command.txt"
        "net session 2>&1 | Out-File -Append $BasicLogFolder\Net_SMB_Server_net_command.txt"
        "net files 2>&1 | Out-File -Append $BasicLogFolder\Net_SMB_Server_net_command.txt"
        "net share 2>&1 | Out-File -Append $BasicLogFolder\Net_SMB_Server_net_command.txt"
        # LBFO
        "Get-NetLbfoTeam -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_NetLbfo.txt"
        "Get-NetLbfoTeamMember -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_NetLbfo.txt"
        "Get-NetLbfoTeamNic -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_NetLbfo.txt"
        # NIC
        "Get-NetAdapter -IncludeHidden -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_NetAdapterInfo.txt"
        "Get-NetAdapterAdvancedProperty -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_NetAdapterInfo.txt"
        "Get-NetAdapterBinding -AllBindings -IncludeHidden -ErrorAction Stop | select Name, InterfaceDescription, DisplayName, ComponentID, Enabled | Out-File -Append $BasicLogFolder\Net_NetAdapterInfo.txt"
        "Get-NetAdapterChecksumOffload -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_NetAdapterInfo.txt"
        "Get-NetAdapterEncapsulatedPacketTaskOffload -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_NetAdapterInfo.txt"
        "Get-NetAdapterHardwareInfo -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_NetAdapterInfo.txt"
        "Get-NetAdapterIPsecOffload -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_NetAdapterInfo.txt"
        "Get-NetAdapterLso -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_NetAdapterInfo.txt"
        "Get-NetAdapterPowerManagement -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_NetAdapterInfo.txt"
        "Get-NetAdapterQos -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_NetAdapterInfo.txt"
        "Get-NetAdapterRdma -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_NetAdapterInfo.txt"
        "Get-NetAdapterRsc -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_NetAdapterInfo.txt"
        "Get-NetAdapterRss -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_NetAdapterInfo.txt"
        "Get-NetAdapterSriov -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_NetAdapterInfo.txt"
        "Get-NetAdapterSriovVf -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_NetAdapterInfo.txt"
        "Get-NetAdapterStatistics -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_NetAdapterInfo.txt"
        "Get-NetAdapterVmq -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_NetAdapterInfo.txt"
        "Get-NetAdapterVmqQueue -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_NetAdapterInfo.txt"
        "Get-NetAdapterVPort -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_NetAdapterInfo.txt"
        # COM/DCOM/RPC
        "netsh rpc show int 2>&1 | Out-File -Append $BasicLogFolder\Net_rpcinfo.txt"
        "netsh rpc show settings 2>&1 | Out-File -Append $BasicLogFolder\Net_rpcinfo.txt"
        "netsh rpc filter show filter 2>&1 | Out-File -Append $BasicLogFolder\Net_rpcinfo.txt"
    )
    If($fServerSKU){
        $Commands += "net statistics server 2>&1 | Out-File -Append $BasicLogFolder\Net_SMB_Server_net_command.txt"
    }Else{
        $Commands += "net statistics WorkStation 2>&1 | Out-File -Append $BasicLogFolder\Net_SMB_Server_net_command.txt"
    }
    RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$True

    # TCPIP registries
    LogMessage $LogLevel.Info ('[BasicLog] Gathering TCP/IP registryies')
    $TCPIPKeys = @(
        "HKLM:SOFTWARE\Policies\Microsoft\Windows\TCPIP"
        "HKLM:SYSTEM\CurrentControlSet\services\TCPIP"
        "HKLM:SYSTEM\CurrentControlSet\Services\Tcpip6"
        "HKLM:SYSTEM\CurrentControlSet\Services\tcpipreg"
        "HKLM:SYSTEM\CurrentControlSet\Services\iphlpsvc"
    )
    ExportRegistryToOneFile $LogPrefix $TCPIPKeys "$BasicLogFolder\Net_TCPIP_reg.txt"

    # SMB
    LogMessage $LogLevel.Info ('[BasicLog] Gathering SMB registries')
    $SMBKeys = @(
        "HKLM:SYSTEM\CurrentControlSet\services\LanManWorkstation"
        "HKLM:SYSTEM\CurrentControlSet\services\lmhosts"
        "HKLM:SYSTEM\CurrentControlSet\services\MrxSmb"
        "HKLM:SYSTEM\CurrentControlSet\services\MrxSmb10"
        "HKLM:SYSTEM\CurrentControlSet\services\MrxSmb20"
        "HKLM:SYSTEM\CurrentControlSet\services\MUP"
        "HKLM:SYSTEM\CurrentControlSet\services\NetBIOS"
        "HKLM:SYSTEM\CurrentControlSet\services\NetBT"
        "HKCU:Network"
        "HKLM:SYSTEM\CurrentControlSet\Control\NetworkProvider"
        "HKLM:SYSTEM\CurrentControlSet\services\Rdbss"
        "HKLM:SYSTEM\CurrentControlSet\Control\SMB"
    )
    ExportRegistryToOneFile $LogPrefix $SMBKeys "$BasicLogFolder\Net_SMB_Client_reg.txt"

    $SMBServerKeys = @(
        "HKLM:SYSTEM\CurrentControlSet\services\LanManServer"
        "HKLM:SYSTEM\CurrentControlSet\services\SRV"
        "HKLM:SYSTEM\CurrentControlSet\services\SRV2"
        "HKLM:SYSTEM\CurrentControlSet\services\SRVNET"
    )
    ExportRegistryToOneFile $LogPrefix $SMBServerKeys "$BasicLogFolder\Net_SMB_Server_reg.txt"

    LogMessage $LogLevel.Info ('[BasicLog] Gathering PRC registries')
    $RPCKeys = @(
        'HKLM:Software\Microsoft\Rpc'
        'HKLM:SYSTEM\CurrentControlSet\Services\RpcEptMapper'
        'HKLM:SYSTEM\CurrentControlSet\Services\RpcLocator'
        'HKLM:SYSTEM\CurrentControlSet\Services\RpcSs'
    )
    ExportRegistryToOneFile $LogPrefix $RPCKeys "$BasicLogFolder\Net_Reigstry_RPC.txt"

    LogMessage $LogLevel.Info ('[BasicLog] Exporting Ole registry')
    ExportRegistryToOneFile $LogPrefix 'HKLM:Software\Microsoft\Ole' "$BasicLogFolder\Net_Reigstry_Ole.txt"

    #------- UEX --------#
    LogMessage $LogLevel.Info ('[BasicLog] Gathering UEX info')

    $Commands = @(
        "schtasks.exe /query /fo CSV /v 2>&1 | Out-File -Append $BasicLogFolder\UEX_schtasks_query.csv"
        "schtasks.exe /query /v 2>&1 | Out-File -Append $BasicLogFolder\UEX_schtasks_query.txt"
    )
    RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$True

    If($Version.Major -eq 10){
        LogMessage $LogLevel.Info ('[BasicLog] Gathering MDM info')
        If($Version.Build -le 14393){
            $MDMCmdLine = "MdmDiagnosticsTool.exe $BasicLogFolder\MdmDiagnosticsTool.xml | Out-Null"
        }Else{
            $MDMCmdLine = "MdmDiagnosticsTool.exe -out $BasicLogFolder\MDM  | Out-Null"
        }
        RunCommands $LogPrefix $MDMCmdLine -ThrowException:$False -ShowMessage:$True
    }

    #------- Storage --------#
    LogMessage $LogLevel.Info ('[BasicLog] Gathering Storage info')
    $Commands = @(
        "fltmc 2>&1 | Out-File -Append $BasicLogFolder\Storage_fltmc.txt"
        "fltmc Filters 2>&1 | Out-File -Append $BasicLogFolder\Storage_fltmc.txt"
        "fltmc Instances 2>&1 | Out-File -Append $BasicLogFolder\Storage_fltmc.txt"
        "fltmc Volumes 2>&1 | Out-File -Append $BasicLogFolder\Storage_fltmc.txt"
        "vssadmin list volumes 2>&1 | Out-File -Append $BasicLogFolder\Storage_VSSAdmin.txt"
        "vssadmin list writers 2>&1 | Out-File -Append $BasicLogFolder\Storage_VSSAdmin.txt"
        "vssadmin list providers 2>&1 | Out-File -Append $BasicLogFolder\Storage_VSSAdmin.txt"
        "vssadmin list shadows 2>&1 | Out-File -Append $BasicLogFolder\Storage_VSSAdmin.txt"
    )
    RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$True

    # msinfo32 is background process and wait until completed.
    $msinfo32Proc = Get-Process -Id $msinfo32.Id -ErrorAction SilentlyContinue
    If($msinfo32Proc -ne $Null){
        Try{
            LogMessage $LogLevel.Normal ('[BasicLog] Waiting for msinfo32 to be completed for 5 minutes.')
            Wait-Process -id $msinfo32.Id -Timeout $msinfoTimeout -ErrorAction Stop
        }Catch{
            LogMessage $LogLevel.Error ('msinfo32 is running more than 5 minutes, so stopping the process.')
            $msinfo32.kill()
        }
    }

    LogMessage $LogLevel.Normal ("[BasicLog] msinfo32 completed.")
    EndFunc $MyInvocation.MyCommand.Name
}

Function CollectLogonLog{
    EnterFunc $MyInvocation.MyCommand.Name
    $LogonLogFolder = "$LogFolder\LogonLog$LogSuffix"
    $LogPrefix = 'Logon'
    
    Try{
        CreateLogFolder $LogonLogFolder
    }Catch{
        LogException  ("Unable to create $LogonLogFolder.") $_
        Return
    }

    $LogonRegistries = @(
        ('HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication', "$LogonLogFolder\Logon_Reg.txt"),
        ('HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon', "$LogonLogFolder\Winlogon_Reg.txt"),
        ('HKLM:SOFTWARE\Microsoft\Windows\AssignedAccessConfiguration', "$LogonLogFolder\AssignedAccess_Reg.txt"),
        ('HKLM:SOFTWARE\Microsoft\Windows\AssignedAccessCsp', "$LogonLogFolder\AssignedAccessCsp_Reg.txt")
    )
    ExportRegistry $LogPrefix $LogonRegistries

    Try{
        Get-AssignedAccess -ErrorAction Stop| Out-File -Append $LogonLogFolder\Get-AssignedAccess.txt
    }Catch{
        LogException  ("An error happened in Get-AssignedAccess") $_ $fLogFileOnly
    }
    EndFunc $MyInvocation.MyCommand.Name
}

Function CollectShellLog{
    EnterFunc $MyInvocation.MyCommand.Name
    $ShellLogFolder = "$LogFolder\ShellLog$LogSuffix"
    $LogPrefix = 'Shell'
    
    Try{
        CreateLogFolder $ShellLogFolder
    }Catch{
        LogException  ("Unable to create $ShellLogFolder.") $_
        Return
    }

    $ShellRegistries = @(
        ('HKLM:Software\Policies\Microsoft\Windows\Explorer', "$ShellLogFolder\ExplorerPolicy_HKLM-Reg.txt"),
        ('HKCU:Software\Microsoft\Windows\CurrentVersion\Policies\Explorer', "$ShellLogFolder\ExplorerPolicy_HKCU-Reg.txt"),
        ("HKCU:Software\Microsoft\Windows\Shell\Associations", "$ShellLogFolder\HKCU-Associations_Reg.txt"),
        ("HKCU:Software\Microsoft\Windows\CurrentVersion\FileAssociations", "$ShellLogFolder\HKCU-FileAssociations_Reg.txt"),
        ("HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\ThumbnailCache", "$ShellLogFolder\HKCU-ThumbnailCache_Reg.txt")
    )
    ExportRegistry $LogPrefix $ShellRegistries

    # Explorer reg
    REG SAVE 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer' "$ShellLogFolder\HKCU-Explorer_Reg.HIV" 2>&1 | Out-Null
    REG SAVE 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' "$ShellLogFolder\HKLM-Explorer_Reg.HIV" 2>&1 | Out-Null

    # ARCache. Use ARCacheDump.exe to dump ARCache({GUID}.X.ver0x000000000000000X.db)
    LogMessage $LogLevel.Info ("[Shell] Copying ARCache.")
    Try{
        New-Item "$ShellLogFolder\ARCache" -ItemType Directory -ErrorAction Stop | Out-Null
        Copy-Item "$env:userprofile\AppData\Local\Microsoft\Windows\Caches\*" "$ShellLogFolder\ARCache" 
    }Catch{
        LogException  ("Unable to copy ARCache.") $_ $fLogFileOnly
    }

    LogMessage $LogLevel.Info ("[Shell] Copying program shurtcut files.")
    Copy-Item "$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs" "$ShellLogFolder\Programs-user" –Recurse
    Copy-Item "C:\ProgramData\Microsoft\Windows\Start Menu\Programs" "$ShellLogFolder\Programs-system" –Recurse

    EndFunc $MyInvocation.MyCommand.Name
}

Function CollectCortanaLog{
    EnterFunc $MyInvocation.MyCommand.Name
    $LogPrefix = 'Cortana'
    $ComponentLogFolder = "$LogFolder\$LogPrefix"+ "Log" + $LogSuffix
    
    Try{
        CreateLogFolder $ComponentLogFolder
    }Catch{
        LogException  ("Unable to create $ComponentLogFolder.") $_
        Return
    }

    $CortanaRegistries = @(
        ("HKLM:SOFTWARE\Policies\Microsoft\Windows\Windows Search" ,"$ComponentLogFolder\CortanaPolicy_Reg.txt"),
        ("HKLM:SOFTWARE\Microsoft\Windows Search", "$ComponentLogFolder\HKLM-Cortana_Reg.txt"),
        ("HKCU:Software\Microsoft\Windows\CurrentVersion\Search", "$ComponentLogFolder\HKCU-Cortana_Reg.txt")
    )
    ExportRegistry $LogPrefix $CortanaRegistries

    EndFunc $MyInvocation.MyCommand.Name
}

Function CollectUEVLog{
    EnterFunc $MyInvocation.MyCommand.Name
    $Status = Get-UevStatus
    If(!$Status.UevEnabled){
        LogMessage $LogLevel.Warning ("UEV is not enabled.")
        Return
    }

    $UEVTasks =@(
        "Monitor Application Settings",
        "Sync Controller Application",
        "Synchronize Settings at Logoff",
        "Template Auto Update"
    )

    $UEVLogFolder = "$LogFolder\UEVLog$LogSuffix"
    Try{
        CreateLogFolder $UEVLogFolder
    }Catch{
        LogException  ("Unable to create $UEVLogFolder.") $_
        Return
    }

    Try{
        $RegistryFolder = Join-Path $UEVLogFolder "Registry" 
        New-Item $RegistryFolder -ItemType Directory -ErrorAction Stop | Out-Null
        $SchedulerFolder = Join-Path $UEVLogFolder "TaskScheduler" 
        New-Item $SchedulerFolder -ItemType Directory -ErrorAction Stop | Out-Null
        $TemplateFolder = Join-Path $UEVLogFolder "UEV-Templates" 
        New-Item $TemplateFolder -ItemType Directory -ErrorAction Stop | Out-Null
        $PackageFolder = Join-Path $UEVLogFolder "UEV-Packages" 
        New-Item $PackageFolder -ItemType Directory -ErrorAction Stop | Out-Null
        #$EventLogFolder = Join-Path $UEVLogFolder "EventLogs" 
        #New-Item $EventLogFolder -ItemType Directory | Out-Null
    }Catch{
        LogException ("An exception happened during creation of logfoler") $_
        Return
    }

    LogMessage $LogLevel.Info ("[UEV] Exporting UE-V regstries.")
    reg export "HKLM\SOFTWARE\Microsoft\UEV" (Join-Path $RegistryFolder "UEV.reg") | Out-Null
    reg export "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule" (Join-Path $RegistryFolder "Schedule.reg")| Out-Null
    reg save "HKLM\SYSTEM" (Join-Path $RegistryFolder "SYSTEM.hiv")| Out-Null
    reg save "HKLM\Software" (Join-Path $RegistryFolder "Software.hiv")| Out-Null

    # UEV Tasks
    LogMessage $LogLevel.Info ("[UEV] Exporting UE-V tasks.")
    ForEach($UEVTask in $UEVTasks){
        schtasks /query /xml /tn ("\Microsoft\UE-V\" + $UEVTask) > ($SchedulerFolder + "\" + $UEVTask + ".xml")
    }

    # UEV configuration
    LogMessage $LogLevel.Info ("[UEV] Running UE-V commandlets")
    Get-UEVStatus | Out-File (Join-Path $UEVLogFolder "Get-UevStatus.txt")
    Get-UEVConfiguration | Out-File (Join-Path $UEVLogFolder "Get-UEVConfiguration.txt")
    Get-UEVTemplate  | Out-File (Join-Path $UEVLogFolder "Get-UEVTemplate.txt")

    # UEV template
    LogMessage $LogLevel.Info ("[UEV] Copying all templates to log folder.")
    Copy-Item  ("C:\ProgramData\Microsoft\UEV\Templates\*") $TemplateFolder -Recurse

    # UEV package
    $UEVConfig = Get-UEVConfiguration

    If($UEVConfig.SettingsStoragePath.Length -ne 0){
        $PackagePath = [System.Environment]::ExpandEnvironmentVariables($UEVConfig.SettingsStoragePath + "\SettingsPackages")

        If($PackagePath -ne $Null){
            LogMessage $LogLevel.Info ("[UEV] Found package path: $PackagePath")
            If(Test-Path -Path $PackagePath){
                $PackageFiles = Get-ChildItem $PackagePath "*.pkgx" -Recurse -Depth 5
                If($PackageFiles.Length -ne 0 -and $PackageFiles -ne $Null){
                    LogMessage $LogLevel.Info ('[UEV] Copying UE-V packages')
                    ForEach($PackageFile in $PackageFiles){
                        Copy-Item  $PackageFile.fullname $PackageFolder -Recurse
                    }
                }
            }
        }
    }
    EndFunc $MyInvocation.MyCommand.Name
}

Function CollectAppXLog{
    EnterFunc $MyInvocation.MyCommand.Name
    $AppXLogFolder = "$LogFolder\AppXLog$LogSuffix"
    Try{
        CreateLogFolder $AppXLogFolder
    }Catch{
        LogException ("Unable to create $AppXLogFolder.") $_
        Return
    }

    LogMessage $LogLevel.Info ("[AppX] Running Get-AppxPackage")
    ForEach ($p in $(Get-AppxPackage)){ 
        ForEach ($n in ($p).Dependencies.PackageFullName){ 
            $p.packagefullname + '--' + $n | Out-File -Append "$AppXLogFolder\appxpackage_output.txt"
        }
    }

    If(Is-Elevated){
        LogMessage $LogLevel.Info ("[AppX] Running Get-AppxPackage -allusers")
        Try{
            ForEach ($p in $(Get-AppxPackage -AllUsers)){
                ForEach ($n in ($p).PackageUserInformation){
                    $p.packagefullname + ' -- ' + $n.UserSecurityId.Sid + ' [' + $n.UserSecurityId.UserName + '] : ' + $n.InstallState | Out-File -Append "$AppXLogFolder/Get-Appxpackage-installeduser.txt"
                }
            }
        }Catch{
            LogException  ("An error happened in Get-AppxPackage.") $_ $fLogFileOnly
        }
        Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Out-File (Join-Path $AppXLogFolder 'Get-AppxProvisionedPackage-online.txt')
    }

    LogMessage $LogLevel.Info ("[AppX] Exporting event logs.")
    $AppXEventlogs = @(
    "Microsoft-Windows-Shell-Core/Operational"
    "Microsoft-Windows-ShellCommon-StartLayoutPopulation/Operational"
    "Microsoft-Windows-TWinUI/Operational"
    "Microsoft-Windows-AppModel-RunTime/Admin"
    "Microsoft-Windows-AppReadiness/Operational"
    "Microsoft-Windows-AppReadiness/Admin"
    "Microsoft-Windows-AppXDeployment/Operational"
    "Microsoft-Windows-AppXDeploymentServer/Operational"
    "Microsoft-Windows-AppxPackaging/Operational"
    "Microsoft-Windows-BackgroundTaskInfrastructure/Operational"
    "Microsoft-Windows-StateRepository/Operational"
    "Microsoft-Windows-Store/Operational"
    "Microsoft-Windows-CloudStore/Operational"
    "Microsoft-Windows-CoreApplication/Operational"
    "Microsoft-Windows-CodeIntegrity/Operational"
    "Microsoft-Windows-PushNotification-Platform/Operational"
    "Microsoft-Windows-ApplicationResourceManagementSystem/Operational"
    )
    ExportEventLog "AppX" $AppXEventlogs $AppXLogFolder

    LogMessage $LogLevel.Info ("[AppX] Exporting registries.")
    $AppxRegistries = @(
        ("HKLM:Software\Microsoft\Windows\CurrentVersion\AppModel", "$AppXLogFolder\reg-HKLM-AppModel.txt"),
        ("HKCU:Software\Microsoft\Windows\CurrentVersion\AppModel", "$AppXLogFolder\reg-HKCU-AppModel.txt"),
        ("HKCU:Software\Classes\Extensions\ContractId\Windows.Launch", "$AppXLogFolder\reg-HKCU-WindowsLaunch.txt"),
        ("HKLM:Software\Microsoft\Windows\CurrentVersion\Policies", "$AppXLogFolder\reg-HKLM-Policies.txt"),
        ("HKLM:Software\Microsoft\Windows\CurrentVersion\Policies", "$AppXLogFolder\reg-HKLM-Policies.txt"),
        ("HKLM:Software\Policies\Microsoft\Windows\AppX", "$AppXLogFolder\reg-HKLM-AppXPolicy.txt"),
        ("HKLM:Software\Microsoft\Windows\CurrentVersion\SystemProtectedUserData" , "$AppXLogFolder\reg-HKLM-SystemProtectedUserData.txt"),
        ("HKEY_CLASSES_ROOT:Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel", "$AppXLogFolder\reg-HKCR-AppModel.txt")
    )
    ExportRegistry "AppX" $AppxRegistries

    # Size of these keys are large so use reg export to shorten export time.
    $Commands = @(
        "Get-ChildItem `"c:\program files\windowsapps`" -Recurse -ErrorAction Stop | Out-File $AppXLogFolder\dir-windowsapps.txt",
        "Get-ChildItem `"c:\Windows\SystemApps`" -Recurse -ErrorAction Stop | Out-File -Append $AppXLogFolder\dir-systemapps.txt",
        "Get-Appxpackage -ErrorAction Stop | Out-File $AppXLogFolder\Get-Appxpackage.txt"
        "Get-AppxPackage -alluser -ErrorAction Stop | Out-File $AppXLogFolder\Get-AppxPackage-alluser.txt",
        "New-Item $AppXLogFolder\Panther -ItemType Directory -ErrorAction Stop | Out-Null",
        "Copy-Item C:\Windows\Panther\*.log $AppXLogFolder\Panther -ErrorAction SilentlyContinue | Out-Null",
        "Copy-Item $env:ProgramData\Microsoft\Windows\AppXProvisioning.xml $AppXLogFolder -ErrorAction SilentlyContinue | Out-Null",
        "whoami /user /fo list | Out-File $AppXLogFolder\userinfo.txt",
        "New-Item $AppXLogFolder\ARCache -ItemType Directory -ErrorAction Stop | Out-Null",
        "Copy-Item $env:userprofile\AppData\Local\Microsoft\Windows\Caches\* $AppXLogFolder\ARCache",
        "REG EXPORT HKLM\Software\Microsoft\windows\currentversion\appx $AppXLogFolder\reg-HKLM-appx.txt 2>&1 | Out-Null",
        "REG EXPORT HKLM\System\SetUp\Upgrade\AppX $AppXLogFolder\reg-HKLM-AppXUpgrade.txt 2>&1 | Out-Null",
        "REG EXPORT HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository $AppXLogFolder\reg-HKLM-StateRepository.txt 2>&1 | Out-Null",
        "REG EXPORT `"HKLM\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel`" $AppXLogFolder\reg-LM-AppModel.txt 2>&1 | Out-Null",
        "REG EXPORT `"HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel`" $AppXLogFolder\reg-HKCU-AppModel.txt 2>&1 | Out-Null",
        "REG SAVE `"HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer`" $AppXLogFolder\reg-HKCU-AppContainer.hiv 2>&1 | Out-Null",
        "tree $env:USERPROFILE\AppData\Local\Microsoft\Windows\Shell /f | Out-File $AppXLogFolder\tree_UserProfile_Shell.txt",
        "tree $env:USERPROFILE\AppData\Local\Packages /f | Out-File $AppXLogFolder\tree_UserProfile_Packages.txt",
        "tree `"C:\Program Files\WindowsApps`" /f | Out-File $AppXLogFolder\tree_ProgramFiles_WindowsApps.txt",
        "ls `"C:\Program Files\WindowsApps`" -Recurse -ErrorAction SilentlyContinue | Out-File $AppXLogFolder\dir_ProgramFiles_WindowsApps.txt",
        "tree `"C:\Users\Default\AppData\Local\Microsoft\Windows\Shell`" /f | Out-File $AppXLogFolder\tree_Default_Shell.txt"
    )
    RunCommands "AppX" $Commands -ThrowException:$False -ShowMessage:$True

    EndFunc $MyInvocation.MyCommand.Name
}

function InvokeUnicodeTool($ToolString) {
    # Switch output encoding to unicode and then back to the default for tools
    # that output to the command line as unicode.
    $oldEncoding = [console]::OutputEncoding
    [console]::OutputEncoding = [Text.Encoding]::Unicode
    iex $ToolString
    [console]::OutputEncoding = $oldEncoding
}

Function CollectStartMenuLog{
    EnterFunc $MyInvocation.MyCommand.Name
    $StartLogFolder = "$LogFolder\StaretMenuLog$LogSuffix"
    Try{
        CreateLogFolder $StartLogFolder
    }Catch{
        LogException ("Unable to create $StartLogFolder.") $_
        Return
    }

    $cacheDumpToolPath = "$env:windir\system32\datastorecachedumptool.exe"

    ### Data Layer State ###
    LogMessage $LogLevel.Info ("[StartMenu] Collecting data for DataLayerState.")
    mkdir "$StartLogFolder\DataLayerState" | Out-Null
    Copy "$Env:LocalAppData\Microsoft\Windows\appsfolder*" "$StartLogFolder\DataLayerState\" -ErrorAction SilentlyContinue | Out-Null
    Copy "$Env:LocalAppData\Microsoft\Windows\Caches\`{3D*" "$StartLogFolder\DataLayerState\" -ErrorAction SilentlyContinue | Out-Null
    Copy "$env:LocalAppData\Microsoft\Windows\Application Shortcuts\" "$StartLogFolder\DataLayerState\Shortcuts\ApplicationShortcuts\" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
    Copy "$env:ProgramData\Microsoft\Windows\Start Menu\" "$StartLogFolder\DataLayerState\Shortcuts\CommonStartMenu\" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
    Copy "$env:APPDATA\Microsoft\Windows\Start Menu\" "$StartLogFolder\DataLayerState\Shortcuts\StartMenu\" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null

    if (Test-Path ("$env:windir\panther\miglog.xml")) {
        copy "$env:windir\panther\miglog.xml" "$StartLogFolder\DataLayerState" -ErrorAction SilentlyContinue  | Out-Null
    } else {
        "No miglog.xml present on system. Probably not an upgrade" > "$StartLogFolder\DataLayerState\miglog_EMPTY.txt"
    }

    ### Trace ###
    LogMessage $LogLevel.Info ("[StartMenu] Collecting trace files.")
    mkdir "$StartLogFolder\Trace" | Out-Null
    Copy "$env:LocalAppData\Packages\Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy\TempState\StartUiTraceloggingSession*" "$StartLogFolder\Trace" -ErrorAction SilentlyContinue | Out-Null
    Copy "$env:LocalAppData\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\TempState\StartUiTraceloggingSession*" "$StartLogFolder\Trace" -ErrorAction SilentlyContinue | Out-Null

    ### Tile Cache ###
    LogMessage $LogLevel.Info ("[StartMenu] Collecting data for Tile Cache.")
    mkdir "$StartLogFolder\TileCache" | Out-Null
    mkdir "$StartLogFolder\TileCache\ShellExperienceHost" | Out-Null
    mkdir "$StartLogFolder\TileCache\StartMenuExperienceHost" | Out-Null

    Copy "$env:LocalAppData\Packages\Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy\TempState\Tile*" "$StartLogFolder\TileCache\ShellExperienceHost" -Force -ErrorAction SilentlyContinue | Out-Null
    Copy "$env:LocalAppData\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\TempState\Tile*" "$StartLogFolder\TileCache\StartMenuExperienceHost" -Force -ErrorAction SilentlyContinue | Out-Null

    # After copying off the cache files we should attempt to dump them.  This functionality was added to DataStoreCacheDumpTool.exe in late RS4 and will silently NOOP for
    # builds older than that.
    if (Test-Path -PathType Leaf $cacheDumpToolPath) {
        $allTileCaches = Get-ChildItem -Recurse "$StartLogFolder\TileCache\TileCache*Header.bin";
        foreach ($cache in $allTileCaches) {
            InvokeUnicodeTool("$cacheDumpToolPath -v $cache > $cache.html");
        }
    }

    ### Upgrade dumps ###
    $dump_files = Get-ChildItem "$env:LocalAppData\Packages\Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy\TempState\" -Filter *.archive
    if ($dump_files.count -gt 0)
    {
        LogMessage $LogLevel.Info ("[StartMenu] Collecting data for UpgradeDumps.")
        mkdir "$StartLogFolder\UpgradeDumps" | Out-Null
        Copy "$env:LocalAppData\Packages\Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy\TempState\*.archive" "$StartLogFolder\UpgradeDumps\" -Force -ErrorAction SilentlyContinue | Out-Null
    }

    ### UTM ###
    LogMessage $LogLevel.Info ("[StartMenu] Collecting data for UTM.")
    $UTMLogFolder = "$StartLogFolder\UnifiedTileModel"
    mkdir "$UTMLogFolder\ShellExperienceHost" | Out-Null
    mkdir "$UTMLogFolder\StartMenuExperienceHost" | Out-Null

    Copy "$env:LocalAppData\Packages\Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy\TempState\StartUnifiedTileModelCache*" "$UTMLogFolder\ShellExperienceHost" -Force -ErrorAction SilentlyContinue | Out-Null
    Copy "$env:LocalAppData\Packages\Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy\TempState\UnifiedTileCache*" "$UTMLogFolder\ShellExperienceHost" -Force -ErrorAction SilentlyContinue | Out-Null
    Copy "$env:LocalAppData\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\TempState\StartUnifiedTileModelCache*" "$UTMLogFolder\StartMenuExperienceHost" -Force -ErrorAction SilentlyContinue | Out-Null

    if (Test-Path -PathType Leaf $cacheDumpToolPath) {
        LogMessage $LogLevel.Info ("[StartMenu] Dumping the tile cache with datastorecachedumptool.exe.")
        # The cache dump tool is present in the OS image.  Use it.  If the cache file exists then dump it.  Regardless of whether it exists also take
        # a live dump.
        if (Test-Path -PathType Leaf "$UTMLogFolder\ShellExperienceHost\StartUnifiedTileModelCache.dat") {
            InvokeUnicodeTool("$cacheDumpToolPath -f $UTMLogFolder\ShellExperienceHost\StartUnifiedTileModelCache.dat") | Out-File "$UTMLogFolder\ShellExperienceHost\StartUnifiedTileModelCacheDump.log"
        }
        elseif (Test-Path -PathType Leaf "$UTMLogFolder\ShellExperienceHost\UnifiedTileCache.dat") {
            InvokeUnicodeTool("$cacheDumpToolPath -f $UTMLogFolder\ShellExperienceHost\UnifiedTileCache.dat") | Out-File "$UTMLogFolder\ShellExperienceHost\UnifiedTileCacheDump.log"
        }

        if (Test-Path -PathType Leaf "$UTMLogFolder\StartMenuExperienceHost\StartUnifiedTileModelCache.dat") {
            InvokeUnicodeTool("$cacheDumpToolPath -f $UTMLogFolder\StartMenuExperienceHost\StartUnifiedTileModelCache.dat") | Out-File "$UTMLogFolder\StartMenuExperienceHost\StartUnifiedTileModelCacheDump.log"
        }
    }

    ### CDSData ###
    LogMessage $LogLevel.Info ("[StartMenu] Collecting data for CloudDataStore.")
    mkdir "$StartLogFolder\CloudDataStore" | Out-Null
    Invoke-Expression "reg.exe export HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store $StartLogFolder\CloudDataStore\Store.txt 2>&1" | Out-Null
    Invoke-Expression "reg.exe export HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore $StartLogFolder\CloudDataStore\CloudStore.txt 2>&1" | Out-Null
    Invoke-Expression "reg.exe export HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CuratedTileCollections $StartLogFolder\CloudDataStore\CuratedTileCollections.txt 2>&1" | Out-Null

    ### DefaultLayout ###
    LogMessage $LogLevel.Info ("[StartMenu] Collecting data for DefaultLayout.")
    mkdir "$StartLogFolder\DefaultLayout" | Out-Null
    Copy "$env:LocalAppData\Microsoft\windows\shell\*" "$StartLogFolder\DefaultLayout" -Force -ErrorAction SilentlyContinue

    ### ContentDeliveryManagagerData ###
    LogMessage $LogLevel.Info ("[StartMenu] Collecting data for ContentDeliveryManager.")
    $cdmLogDirectory = "$StartLogFolder\ContentDeliveryManager"
    mkdir $cdmLogDirectory | Out-Null

    $cdmLocalStateDirectory = "$env:LocalAppData\Packages\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy\LocalState\";

    # Copy the entire cdm local state directory
    Copy $cdmLocalStateDirectory $cdmLogDirectory -Recurse -Force -ErrorAction SilentlyContinue

    # Extract and highlight key start files
    $cdmExtractedLogDirectory = (Join-Path $cdmLogDirectory "Extracted");
    mkdir $cdmExtractedLogDirectory | Out-Null

    # Collection of folders to extract and give readable names. The last number in most of these is the subscription ID.
    Try{
        @(
            @{'SourceName'    = "TargetedContentCache\v3\314558"
              'ExtractedName' = "TargetedContentCache PgStart Internal"},
            @{'SourceName'    = "TargetedContentCache\v3\314559"
              'ExtractedName' = "TargetedContentCache PgStart External"},
            @{'SourceName'    = "TargetedContentCache\v3\338381"
              'ExtractedName' = "TargetedContentCache Start Suggestions Internal"},
            @{'SourceName'    = "TargetedContentCache\v3\338388"
              'ExtractedName' = "TargetedContentCache Start Suggestions External"},
            @{'SourceName'    = "ContentManagementSDK\Creatives\314558"
              'ExtractedName' = "ContentManagementSDK PgStart Internal"},
            @{'SourceName'    = "ContentManagementSDK\Creatives\314559"
              'ExtractedName' = "ContentManagementSDK PgStart External"},
            @{'SourceName'    = "ContentManagementSDK\Creatives\338381"
              'ExtractedName' = "ContentManagementSDK Start Suggestions Internal"},
            @{'SourceName'    = "ContentManagementSDK\Creatives\338388"
              'ExtractedName' = "ContentManagementSDK Start Suggestions External"}
              
        ) | %{
            $sourceLogDirectory = (Join-Path $cdmLocalStateDirectory $_.SourceName);

            if (Test-Path -Path $sourceLogDirectory -PathType Container)
            {
                $extractedLogDirectory = Join-Path $cdmExtractedLogDirectory $_.ExtractedName;
    
                mkdir $extractedLogDirectory | Out-Null
    
                Get-ChildItem $sourceLogDirectory | Foreach-Object {
                    $destinationLogFilePath = Join-Path $extractedLogDirectory "$($_.BaseName).json"
                    Get-Content $_.FullName | ConvertFrom-Json | ConvertTo-Json -Depth 10 > $destinationLogFilePath;
                }
            }
            else
            {
                $extractedLogFilePath = Join-Path $cdmExtractedLogDirectory "NoFilesFor_$($_.ExtractedName)";
                $null > $extractedLogFilePath;
            }
        }
    }Catch{
        LogException ("An error happened during converting JSON data.") $_
    }

    Invoke-Expression "reg.exe query HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager /s >> $cdmLogDirectory\Registry.txt"

    ### App Resolver Cache ###
    LogMessage $LogLevel.Info ("[StartMenu] Copying ARCache.")
    Try{
        New-Item "$StartLogFolder\ARCache" -ItemType Directory -ErrorAction Stop | Out-Null
        Copy-Item "$env:userprofile\AppData\Local\Microsoft\Windows\Caches\*" "$StartLogFolder\ARCache" 
    }Catch{
        LogException  ("Unable to copy ARCache.") $_ $fLogFileOnly
    }

    ### Program shurtcut ###
    LogMessage $LogLevel.Info ("[StartMenu] Copying program shurtcut files.")
    Copy-Item "$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs" "$StartLogFolder\Programs-user" –Recurse
    Copy-Item "C:\ProgramData\Microsoft\Windows\Start Menu\Programs" "$StartLogFolder\Programs-system" –Recurse

    whoami /user /fo list | Out-File (Join-Path $StartLogFolder 'userinfo.txt')

    EndFunc $MyInvocation.MyCommand.Name
}

Function CollectWinRMLog{
    EnterFunc $MyInvocation.MyCommand.Name
    $WinRMLogFolder = "$LogFolder\WinRMLog$LogSuffix"
    Try{
        CreateLogFolder $WinRMLogFolder
    }Catch{
        LogException ("Unable to create $WinRMLogFolder.") $_
        Return
    }

    If(!(Is-Elevated)){
        LogMessage $LogLevel.Warning ("[WinRM] Collecting WinRM log needs administrative privilege.")
        Return
    }

    LogMessage $LogLevel.Info ("[WinRM] Collecting WinRM configuration.")
    ipconfig /all | Out-File (Join-Path $WinRMLogFolder 'ipconfig-all.txt')
    $WinRMService = Get-Service | Where-Object {$_.Name -eq 'WinRM'}
    If($WinRMService -ne $Null){

        If($WinRMService.Status -eq 'Stopped'){
            LogMessage $LogLevel.Normal ('[WinRM] Starting WinRM service as it was not running.')
            Start-Service $WinRMService.Name
        }

        $Service = Get-Service $WinRMService.Name
        $Service.WaitForStatus('Running','00:00:05')

        If($Service.Status -eq 'Running'){
            WinRM get 'winrm/config'  | Out-File (Join-Path $WinRMLogFolder 'WinRMconfig.txt')
            WinRM enumerate 'winrm/config/listener' | Out-File (Join-Path $WinRMLogFolder 'WinRMconfig-listener.txt')
            WinRM get 'winrm/config/client' | Out-File (Join-Path $WinRMLogFolder 'WinRMconfig-client.txt')
        }
    }
    reg query 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN' /s | Out-File (Join-Path $WinRMLogFolder 'reg-winrm.txt')
    LogMessage $LogLevel.Info ("[WinRM] Collecting http configuration.")
    netsh http show iplisten | Out-File (Join-Path $WinRMLogFolder 'iplisten.txt')
    netsh winhttp show proxy | Out-File (Join-Path $WinRMLogFolder 'proxy.txt')
    netstat -a | Out-File (Join-Path $WinRMLogFolder 'netstat.txt')
    setspn -L $env:COMPUTERNAME | Out-File (Join-Path $WinRMLogFolder 'spn.txt')
    netsh advfirewall show currentprofile  | Out-File (Join-Path $WinRMLogFolder 'firewall-currentprofile.txt')
    netsh advfirewall firewall show rule name=all dir=in | Out-File (Join-Path $WinRMLogFolder 'firewall-allinrules.txt')
    netsh advfirewall firewall show rule name=all dir=out | Out-File (Join-Path $WinRMLogFolder 'firewall-alloutrules.txt')
    wevtutil epl "Microsoft-Windows-WinRM/Operational" (Join-Path $WinRMLogFolder 'Microsoft-Windows-WinRM-Operational.evtx')
    EndFunc $MyInvocation.MyCommand.Name
}

Function CollectTaskLog{
    EnterFunc $MyInvocation.MyCommand.Name
    $TaskLogFolder = "$LogFolder\TaskLog$LogSuffix"
    Try{
        CreateLogFolder $TaskLogFolder
    }Catch{
        LogException ("Unable to create $TaskLogFolder.") $_
        Return
    }

    LogMessage $LogLevel.Info ("[Task] Collecting Task files.")
    $FolderHash = @{
        "C:\Windows\System32\Tasks" = "$TaskLogFolder\Tasks";
        "C:\Windows\Tasks"          = "$TaskLogFolder\Jobs";
    };
    foreach($CopyFrom in $FolderHash.Keys){
        $CopyTo = $FolderHash[$CopyFrom];
        Try{
            New-Item $CopyTo -ItemType Directory -ErrorAction Stop | Out-Null
            Copy-Item "$CopyFrom\*" $CopyTo -Recurse
        }Catch{
            LogException  ("Unable to copy files from $CopyFrom.") $_ $fLogFileOnly
        }
    }

    LogMessage $LogLevel.Info ("[Task] Collecting schtasks command outputs.")
    schtasks.exe /query /xml | Out-File -Append "$TaskLogFolder\schtasks_query.xml"
    schtasks.exe /query /fo CSV /v | Out-File -Append "$TaskLogFolder\schtasks_query.csv"
    schtasks.exe /query /v | Out-File -Append "$TaskLogFolder\schtasks_query.txt"

    LogMessage $LogLevel.Info ("[Task] Collecting powercfg command outputs.")
    powercfg /LIST                 | Out-File -Append "$TaskLogFolder\powercfg_list.txt"
    powercfg /QUERY SCHEME_CURRENT | Out-File -Append "$TaskLogFolder\powercfg_query_scheme_current.txt"
    powercfg /AVAILABLESLEEPSTATES | Out-File -Append "$TaskLogFolder\powercfg_availablesleepstates.txt"
    powercfg /LASTWAKE             | Out-File -Append "$TaskLogFolder\powercfg_lastwake.txt"
    powercfg /WAKETIMERS           | Out-File -Append "$TaskLogFolder\powercfg_waketimers.txt"

    LogMessage $LogLevel.Info ("[Task] Exporting event logs.")
    wevtutil epl Microsoft-Windows-TaskScheduler/Operational "$TaskLogFolder\TaskScheduler-Operational.evtx"
    wevtutil epl Microsoft-Windows-TaskScheduler/Maintenance "$TaskLogFolder\TaskScheduler-Maintenance.evtx"

    LogMessage $LogLevel.Info ("[Task] Exporting registries.")
    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule" /s | Out-File "$TaskLogFolder\reg-HKLM-Schedule.txt"
    EndFunc $MyInvocation.MyCommand.Name
}

Function CollectPrintLog{
    EnterFunc $MyInvocation.MyCommand.Name
    $PrintLogFolder = "$LogFolder\PrintLog$LogSuffix"
    Try{
        CreateLogFolder $PrintLogFolder
    }Catch{
        LogException ("Unable to create $PrintLogFolder.") $_
        Return
    }

    LogMessage $LogLevel.Info ("[Print] Exporting registries.")
    reg query "HKCU\Printers" /s | Out-File "$PrintLogFolder\reg-HKCU-Printers.txt"
    reg query "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /s | Out-File "$PrintLogFolder\reg-HKCU-Windows.txt"
    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print" /s | Out-File "$PrintLogFolder\reg-HKLM-Software-Print.txt"
    reg query "HKLM\SYSTEM\CurrentControlSet\Control\Print" /s | Out-File "$PrintLogFolder\reg-HKLM-System-Print.txt"
    reg query "HKLM\SYSTEM\CurrentControlSet\Control\DeviceClasses" /s | Out-File "$PrintLogFolder\reg-HKLM-System-DeviceClasses.txt"
    reg query "HKLM\SYSTEM\CurrentControlSet\Control\DeviceContainers" /s | Out-File "$PrintLogFolder\reg-HKLM-System-DeviceContainers.txt"
    reg query "HKLM\SYSTEM\CurrentControlSet\Enum\SWD" /s | Out-File "$PrintLogFolder\reg-HKLM-System-SWD.txt"
    reg query "HKLM\SYSTEM\DriverDatabase" /s | Out-File "$PrintLogFolder\reg-HKLM-System-DriverDatabase.txt"

    LogMessage $LogLevel.Info ("[Print] Collecting command outputs.")
    cscript C:\Windows\System32\Printing_Admin_Scripts\en-US\prndrvr.vbs -l | Out-File -Append "$PrintLogFolder\prndrvr_en.txt"
    cscript C:\Windows\System32\Printing_Admin_Scripts\en-US\prnmngr.vbs -l | Out-File -Append "$PrintLogFolder\prnmngr_en.txt"
    cscript C:\Windows\System32\Printing_Admin_Scripts\en-US\prnjobs.vbs -l | Out-File -Append "$PrintLogFolder\prnjobs_en.txt"
    cscript C:\Windows\System32\Printing_Admin_Scripts\en-US\prnport.vbs -l | Out-File -Append "$PrintLogFolder\prnport_en.txt"
    cscript C:\Windows\System32\Printing_Admin_Scripts\ja-JP\prndrvr.vbs -l | Out-File -Append "$PrintLogFolder\prndrvr_ja.txt"
    cscript C:\Windows\System32\Printing_Admin_Scripts\ja-JP\prnmngr.vbs -l | Out-File -Append "$PrintLogFolder\prnmngr_ja.txt"
    cscript C:\Windows\System32\Printing_Admin_Scripts\ja-JP\prnjobs.vbs -l | Out-File -Append "$PrintLogFolder\prnjobs_ja.txt"
    cscript C:\Windows\System32\Printing_Admin_Scripts\ja-JP\prnport.vbs -l | Out-File -Append "$PrintLogFolder\prnport_ja.txt"
    tree C:\Windows\Inf /f | Out-File -Append "$PrintLogFolder\tree_inf.txt"
    tree C:\Windows\System32\DriverStore /f | Out-File -Append "$PrintLogFolder\tree_DriverStore.txt"
    tree C:\Windows\System32\spool /f | Out-File -Append "$PrintLogFolder\tree_spool.txt"

    LogMessage $LogLevel.Info ("[Print] Collecting Inf files.")
    $PrintInfLogFolder = "$PrintLogFolder\inf"
    Try{
        New-Item $PrintInfLogFolder -ItemType Directory -ErrorAction Stop | Out-Null
        Copy-Item "C:\Windows\Inf\oem*.inf" $PrintInfLogFolder
        Copy-Item "C:\Windows\inf\Setupapi*" $PrintInfLogFolder
    }Catch{
        LogException ("ERROR: Copying files from C:\Windows\Inf") $_ $fLogFileOnly
    }

    # HKLM\DRIVERS registry hive will have been mounted only when it needed. So the reg query command is placed after pnputil command.
    LogMessage $LogLevel.Info ("[Print] Collecting driver info.")
    pnputil /export-pnpstate "$PrintLogFolder\pnputil_pnpstate.pnp" | Out-Null
    pnputil -e | Out-File -Append "$PrintLogFolder\pnputil_e.txt"
    reg query "HKLM\DRIVERS\DriverDatabase" /s | Out-File "$PrintLogFolder\reg-HKLM-Drivers-DriverDatabase.txt"
    EndFunc $MyInvocation.MyCommand.Name
}

Function CollectIMELog{
    EnterFunc $MyInvocation.MyCommand.Name
    $IMELogFolder = "$LogFolder\IMELog$LogSuffix"
    Try{
        CreateLogFolder $IMELogFolder
    }Catch{
        LogException ("Unable to create $IMELogFolder.") $_
        Return
    }

    LogMessage $LogLevel.Info ("[IME] Exporting registries.")
    reg query "HKCU\Keyboard Layout" /s | Out-File "$IMELogFolder\reg-HKCU_KeyboardLayout.txt"
    reg query "HKCU\Software\Microsoft\CTF" /s | Out-File "$IMELogFolder\reg-HKCU_CTF.txt"
    reg query "HKCU\Software\Microsoft\IME" /s | Out-File "$IMELogFolder\reg-HKCU_IME.txt"
    reg query "HKCU\Software\AppDataLow\Software\Microsoft\IME" /s | Out-File "$IMELogFolder\reg-HKCU_IME2.txt"
    reg query "HKCU\Software\Policies" /s | Out-File "$IMELogFolder\reg-HKCU_Policies.txt"
    reg query "HKLM\SOFTWARE\Policies" /s | Out-File "$IMELogFolder\reg-HKLM_Policies.txt"
    reg query "HKLM\SOFTWARE\Microsoft\IME" /s | Out-File "$IMELogFolder\reg-HKLM_IME.txt"
    reg query "HKLM\SOFTWARE\Microsoft\PolicyManager" /s | Out-File "$IMELogFolder\reg-HKLM_PolicyManager.txt"
    reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies" /s | Out-File "$IMELogFolder\reg-HKLM_Policies2.txt"

    LogMessage $LogLevel.Info ("[IME] Collecting command outputs.")
    tasklist /M MsCtfMonitor.dll | Out-File -Append "$IMELogFolder\tasklist_MsCtfMonitor.txt"
    tree "%APPDATA%\Microsoft\IME" /f | Out-File -Append "$IMELogFolder\tree_APPDATA_IME.txt"
    tree "%APPDATA%\Microsoft\InputMethod" /f | Out-File -Append "$IMELogFolder\tree_APPDATA_InputMethod.txt"
    tree "%LOCALAPPDATA%\Microsoft\IME" /f | Out-File -Append "$IMELogFolder\tree_LOCALAPPDATA_IME.txt"
    tree "C:\windows\system32\ime" /f | Out-File -Append "$IMELogFolder\tree_windows_system32_ime.txt"
    tree "C:\windows\ime" /f | Out-File -Append "$IMELogFolder\tree_windows_ime.txt"
    EndFunc $MyInvocation.MyCommand.Name
}

Function CollectFontLog{
    EnterFunc $MyInvocation.MyCommand.Name
    $FontLogFolder = "$LogFolder\FontLog$LogSuffix"
    Try{
        CreateLogFolder $FontLogFolder
    }Catch{
        LogException ("Unable to create $FontLogFolder.") $_
        Return
    }

    LogMessage $LogLevel.Info ("[Font] Exporting registries.")
    reg query "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Font Management" /s | Out-File "$FontLogFolder\reg-HKCU_FontManagement.txt"
    reg query "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /s | Out-File "$FontLogFolder\reg-HKCU_Fonts.txt"

    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers" /s | Out-File "$FontLogFolder\reg-HKLM_FontDrivers.txt"
    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Management" /s | Out-File "$FontLogFolder\reg-HKLM_FontManagement.txt"
    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\FontDPI" /s | Out-File "$FontLogFolder\reg-HKLM_FontDPI.txt"
    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\FontIntensityCorrection" /s | Out-File "$FontLogFolder\reg-HKLM_FontIntensityCorrection.txt"
    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\FontLink" /s | Out-File "$FontLogFolder\reg-HKLM_FontLink.txt"
    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\FontMapper" /s | Out-File "$FontLogFolder\reg-HKLM_FontMapper.txt"
    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\FontMapperFamilyFallback" /s | Out-File "$FontLogFolder\reg-HKLM_FontMapperFamilyFallback.txt"
    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts" /s | Out-File "$FontLogFolder\reg-HKLM_Fonts.txt"
    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\FontSubstitutes" /s | Out-File "$FontLogFolder\reg-HKLM_FontSubstitetes.txt"
}

Function CollectNlsLog{
    EnterFunc $MyInvocation.MyCommand.Name
    $NlsLogFolder = "$LogFolder\NlsLog$LogSuffix"
    Try{
        CreateLogFolder $NlsLogFolder
    }Catch{
        LogException ("Unable to create $NlsLogFolder.") $_
        Return
    }

    LogMessage $LogLevel.Info ("[Nls] Exporting registries.")
    $NlsRegLogFolder = "$NlsLogFolder\Reg"
    Try{
        New-Item $NlsRegLogFolder -ItemType Directory -ErrorAction Stop | Out-Null
        reg save "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion" $NlsRegLogFolder\Software.hiv 2>&1 | Out-Null
        reg save "HKLM\SOFTWARE\Microsoft\Windows NT" $NlsRegLogFolder\WindowsNT.hiv 2>&1 | Out-Null
        reg save "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" $NlsRegLogFolder\WindowsUpdate.hiv 2>&1 | Out-Null
        
        reg save "HKLM\SYSTEM\CurrentControlSet" $NlsRegLogFolder\SYSTEM.hiv 2>&1 | Out-Null
        reg save "HKLM\SYSTEM\DriverDatabase" $NlsRegLogFolder\DriverDatabase.hiv 2>&1 | Out-Null
        reg save HKLM\SYSTEM\CurrentControlSet\Services $NlsRegLogFolder\Services.hiv 2>&1 | Out-Null
    }Catch{
        LogException ("ERROR: Exporting from Registry") $_ $fLogFileOnly
    }

    LogMessage $LogLevel.Info ("[Nls] Collecting command outputs.")
    Try{
      dism /online /get-intl 2>&1| Out-File -Append "$NlsLogFolder\dism-get-intl.txt"
      dism /online /get-features 2>&1| Out-File -Append "$NlsLogFolder\dism-get-features.txt"
      dism /online /get-packages 2>&1| Out-File "$NlsLogFolder\dism-get-package.txt" 
  
      Get-WinUserLanguageList | Out-File "$NlsLogFolder\get-winuserlist.txt"
      Get-Culture | Out-File "$NlsLogFolder\get-culture.txt"
      Get-WinHomeLocation | Out-File "$NlsLogFolder\get-winhomelocation.txt"
      Get-WinSystemLocale | Out-File "$NlsLogFolder\get-winsystemlocale.txt"
      Get-TimeZone | Out-File "$NlsLogFolder\get-timezone.txt"
    }Catch{
        LogException ("ERROR: Execute command") $_ $fLogFileOnly
    }

    LogMessage $LogLevel.Info ("[Nls] Collecting Panther files.")
    $NlsPantherLogFolder = "$NlsLogFolder\Panther"
    Try{
        New-Item $NlsPantherLogFolder -ItemType Directory -ErrorAction Stop | Out-Null
        Copy-Item C:\Windows\Panther\* $NlsPantherLogFolder
    }Catch{
        LogException ("ERROR: Copying files from C:\Windows\Panther") $_ $fLogFileOnly
    }

    LogMessage $LogLevel.Info ("[Nls] Collecting Setupapi files.")
    $NlsSetupApiLogFolder = "$NlsLogFolder\Setupapi"
    Try{
        New-Item $NlsSetupApiLogFolder -ItemType Directory -ErrorAction Stop | Out-Null
        Copy-Item "C:\Windows\inf\Setupapi*" $NlsSetupApiLogFolder
    }Catch{
        LogException ("ERROR: Copying files from C:\Windows\Inf\Setup*") $_ $fLogFileOnly
    }

    EndFunc $MyInvocation.MyCommand.Name
}

Function CollectAppCompatLog{
    EnterFunc $MyInvocation.MyCommand.Name
    $AppCompatLogFolder = "$LogFolder\AppCompatLog$LogSuffix"
    $LogPrefix = 'AppCompat'
    Try{
        CreateLogFolder $AppCompatLogFolder
    }Catch{
        LogException ("Unable to create $AppCompatLogFolder.") $_
        Return
    }

    $AppCompatRegistries = @(
        ('HKLM:Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags', "$AppCompatLogFolder\AppCompatFlags-HKLM-Reg.txt"),
        ('HKCU:Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags', "$AppCompatLogFolder\AppCompatFlags-HKCU-Reg.txt")
    )
    ExportRegistry $LogPrefix $AppCompatRegistries
    REG SAVE 'HKLM\System\CurrentControlSet\Control\Session Manager\AppCompatCache' "$AppCompatLogFolder\AppCompatCache.HIV" 2>&1 | Out-Null

    EndFunc $MyInvocation.MyCommand.Name
}

Function WMIPreStart{
    EnterFunc $MyInvocation.MyCommand.Name
    LogMessage $LogLevel.Debug ('Enabling analytic logs for WMI')
    Try{
        SetEventLog 'Microsoft-Windows-WMI-Activity/Trace'
        SetEventLog 'Microsoft-Windows-WMI-Activity/Debug'
    }Catch{
        $ErrorMessage = 'An exception happened in SetEventLog.'
        LogException $ErrorMessage $_ $fLogFileOnly
        Throw ($ErrorMessage)
    }
    EndFunc $MyInvocation.MyCommand.Name
}

Function WMIPostStop{
    EnterFunc $MyInvocation.MyCommand.Name
    LogMessage $LogLevel.Debug ('Disabling analytic logs for WMI')

    Try{
        ResetEventLog 'Microsoft-Windows-WMI-Activity/Trace'
        ResetEventLog 'Microsoft-Windows-WMI-Activity/Debug'
    }Catch{
        $ErrorMessage = 'An exception happened in ResetEventLog.'
        LogException $ErrorMessage $_ $fLogFileOnly
        Throw ($ErrorMessage)
    }
    EndFunc $MyInvocation.MyCommand.Name
}

$UserDumpCode=@'
using System;
using System.Runtime.InteropServices;

namespace MSDATA
{
    public static class UserDump
    {
        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessID);
        [DllImport("dbghelp.dll", EntryPoint = "MiniDumpWriteDump", CallingConvention = CallingConvention.Winapi, CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        public static extern bool MiniDumpWriteDump(IntPtr hProcess, uint processId, SafeHandle hFile, uint dumpType, IntPtr expParam, IntPtr userStreamParam, IntPtr callbackParam);

        private enum MINIDUMP_TYPE
        {
            MiniDumpNormal = 0x00000000,
            MiniDumpWithDataSegs = 0x00000001,
            MiniDumpWithFullMemory = 0x00000002,
            MiniDumpWithHandleData = 0x00000004,
            MiniDumpFilterMemory = 0x00000008,
            MiniDumpScanMemory = 0x00000010,
            MiniDumpWithUnloadedModules = 0x00000020,
            MiniDumpWithIndirectlyReferencedMemory = 0x00000040,
            MiniDumpFilterModulePaths = 0x00000080,
            MiniDumpWithProcessThreadData = 0x00000100,
            MiniDumpWithPrivateReadWriteMemory = 0x00000200,
            MiniDumpWithoutOptionalData = 0x00000400,
            MiniDumpWithFullMemoryInfo = 0x00000800,
            MiniDumpWithThreadInfo = 0x00001000,
            MiniDumpWithCodeSegs = 0x00002000
        };

        public static bool GenerateUserDump(uint ProcessID, string dumpFileName)
        {
            System.IO.FileStream fileStream = System.IO.File.OpenWrite(dumpFileName);

            if (fileStream == null)
            {
                return false;
            }

            // 0x1F0FFF = PROCESS_ALL_ACCESS
            IntPtr ProcessHandle = OpenProcess(0x1F0FFF, false, ProcessID);

            if(ProcessHandle == null)
            {
                return false;
            }

            MINIDUMP_TYPE Flags =
                MINIDUMP_TYPE.MiniDumpWithFullMemory |
                MINIDUMP_TYPE.MiniDumpWithFullMemoryInfo |
                MINIDUMP_TYPE.MiniDumpWithHandleData |
                MINIDUMP_TYPE.MiniDumpWithUnloadedModules |
                MINIDUMP_TYPE.MiniDumpWithThreadInfo;

            bool Result = MiniDumpWriteDump(ProcessHandle,
                                 ProcessID,
                                 fileStream.SafeFileHandle,
                                 (uint)Flags,
                                 IntPtr.Zero,
                                 IntPtr.Zero,
                                 IntPtr.Zero);

            fileStream.Close();
            return Result;
        }
    }
}
'@
Try{
    add-type -TypeDefinition $UserDumpCode -Language CSharp
}Catch{
    LogMessage $LogLevel.Error ("Unable to add C# code for collecting user dump.")
}

Function ExecWMIQuery {
    [OutputType([Object])]
    param(
        [string] $NameSpace,
        [string] $Query
    )

    LogMessage $Loglevel.info ("[WMI] Executing query " + $Query)
    Try{
        $Obj = Get-CimInstance -Namespace $NameSpace -Query $Query -ErrorAction Stop
        $Obj = Get-WmiObject -Namespace $NameSpace -Query $Query -ErrorAction Stop
    }Catch{
        LogException ("An error happened during running $Query") $_ $fLogFileOnly
    }

    Return $Obj
}

<#
.SYNOPSIS
    Collect WMI log and settings
.DESCRIPTION
    Collect WMI log and settings and save them to WMI log folder
.NOTES
    Author: Gianni Bragante, Luc Talpe, Ryutaro Hayashi
    Date:   June 09, 2020
#>
Function CollectWMILog{
    EnterFunc $MyInvocation.MyCommand.Name
    $WMILogFolder = "$LogFolder\WMILog$LogSuffix"
    $WMISubscriptions = "$WMILogFolder\Subscriptions"
    $WMIProcDumpFolder = "$WMILogFolder\Process dump"
    $LogPrefix = "WMI"

    Try{
        CreateLogFolder $WMILogFolder
        CreateLogFolder $WMISubscriptions
        CreateLogFolder $WMIProcDumpFolder
    }Catch{
        LogMessage ("Unable to create $WMILogFolder.") $_ 
        Return
    }

    $WMIAnalysiticLogs = @(
        'Microsoft-Windows-WMI-Activity/Trace'
        'Microsoft-Windows-WMI-Activity/Debug'
    )

    LogMessage $LogLevel.Info ('[WMI] Exporting WMI analysitic logs.')
    [reflection.assembly]::loadwithpartialname("System.Diagnostics.Eventing.Reader") 
    $Eventlogsession = New-Object System.Diagnostics.Eventing.Reader.EventLogSession

    ForEach($WMIAnalysiticLog in $WMIAnalysiticLogs){
        Try{
            $EventLogConfig = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration -ArgumentList $WMIAnalysiticLog,$Eventlogsession -ErrorAction Stop
        }Catch{
            LogException ("Error happened in creating EventLogConfiguration.") $_ $fLogFileOnly
            Continue
        }

        Try{
            $LogPath = [System.Environment]::ExpandEnvironmentVariables($Eventlogconfig.LogFilePath)
            # This is the case where ResetEventLog did nothing as the log already enabled. In this case, 
            # we need to disable it and copy the etl and then re-enable the log as it was orginally enabled.
            If($EventLogConfig.IsEnabled -eq $True){
                $EventLogConfig.IsEnabled=$False
                $EventLogConfig.SaveChanges()
                LogMessage $LogLevel.Debug "Copying $LogPath to $WMILogFolder"
                Copy-Item $LogPath $WMILogFolder  -ErrorAction Stop
                LogMessage $LogLevel.Debug ('Re-enabling ' + $Eventlogconfig.LogName)
                $EventLogConfig.IsEnabled=$True
                $EventLogConfig.SaveChanges()
            }Else{
                If(Test-path -path $LogPath){
                    LogMessage $LogLevel.Debug ('Copying ' + $Eventlogconfig.LogFilePath + " to $WMILogFolder")
                    Copy-Item $LogPath $WMILogFolder -ErrorAction Stop
                }
            }
        }Catch{
            LogException ('An exception happened in CollectWMILog.') $_ $fLogFileOnly
        }
    }

    # Get subscription info
    ExecWMIQuery -Namespace "root\subscription" -Query "select * from ActiveScriptEventConsumer" | Export-Clixml -Path ("$WMISubscriptions\ActiveScriptEventConsumer.xml")
    ExecWMIQuery -Namespace "root\subscription" -Query "select * from __eventfilter" | Export-Clixml -Path ("$WMISubscriptions\__eventfilter.xml")
    ExecWMIQuery -Namespace "root\subscription" -Query "select * from __IntervalTimerInstruction" | Export-Clixml -Path ("$WMISubscriptions\__IntervalTimerInstruction.xml")
    ExecWMIQuery -Namespace "root\subscription" -Query "select * from __AbsoluteTimerInstruction" | Export-Clixml -Path ("$WMISubscriptions\__AbsoluteTimerInstruction.xml")
    ExecWMIQuery -Namespace "root\subscription" -Query "select * from __FilterToConsumerBinding" | Export-Clixml -Path ("$WMISubscriptions\__FilterToConsumerBinding.xml")

    # MOFs
    LogMessage $LogLevel.Info ('[WMI] Collecting Autorecover MOFs content') 
    $mof = (Get-Itemproperty -ErrorAction SilentlyContinue -literalpath ("HKLM:\SOFTWARE\Microsoft\Wbem\CIMOM")).'Autorecover MOFs'
    If ($mof.length -ne 0) {
        $mof | Out-File ("$WMILogFolder\Autorecover MOFs.txt")
    }

    # COM Security
    LogMessage $LogLevel.Info ("[WMI] Getting COM Security info")
    $Reg = [WMIClass]"\\.\root\default:StdRegProv"
    $DCOMMachineLaunchRestriction = $Reg.GetBinaryValue(2147483650,"software\microsoft\ole","MachineLaunchRestriction").uValue
    $DCOMMachineAccessRestriction = $Reg.GetBinaryValue(2147483650,"software\microsoft\ole","MachineAccessRestriction").uValue
    $DCOMDefaultLaunchPermission = $Reg.GetBinaryValue(2147483650,"software\microsoft\ole","DefaultLaunchPermission").uValue
    $DCOMDefaultAccessPermission = $Reg.GetBinaryValue(2147483650,"software\microsoft\ole","DefaultAccessPermission").uValue
    
    $converter = new-object system.management.ManagementClass Win32_SecurityDescriptorHelper
    "Default Access Permission = " + ($converter.BinarySDToSDDL($DCOMDefaultAccessPermission)).SDDL | Out-File -FilePath ("$WMILogFolder\COMSecurity.txt") -Append
    "Default Launch Permission = " + ($converter.BinarySDToSDDL($DCOMDefaultLaunchPermission)).SDDL | Out-File -FilePath ("$WMILogFolder\COMSecurity.txt") -Append
    "Machine Access Restriction = " + ($converter.BinarySDToSDDL($DCOMMachineAccessRestriction)).SDDL | Out-File -FilePath ("$WMILogFolder\COMSecurity.txt") -Append
    "Machine Launch Restriction = " + ($converter.BinarySDToSDDL($DCOMMachineLaunchRestriction)).SDDL | Out-File -FilePath ("$WMILogFolder\COMSecurity.txt") -Append

    # File version
    LogMessage $LogLevel.Info ("[WMI] Getting file version of WMI modules")
    FileVersion -Filepath ($env:windir + "\system32\wbem\wbemcore.dll") | Out-File -FilePath ("$WMILogFolder\FilesVersion.csv") -Append
    FileVersion -Filepath ($env:windir + "\system32\wbem\repdrvfs.dll") | Out-File -FilePath ("$WMILogFolder\FilesVersion.csv") -Append
    FileVersion -Filepath ($env:windir + "\system32\wbem\WmiPrvSE.exe") | Out-File -FilePath ("$WMILogFolder\FilesVersion.csv") -Append
    FileVersion -Filepath ($env:windir + "\system32\wbem\WmiPerfClass.dll") | Out-File -FilePath ("$WMILogFolder\FilesVersion.csv") -Append
    FileVersion -Filepath ($env:windir + "\system32\wbem\WmiApRpl.dll") | Out-File -FilePath ("$WMILogFolder\FilesVersion.csv") -Append

    $proc = ExecWMIQuery -Namespace "root\cimv2" -Query "select Name, CreationDate, ProcessId, ParentProcessId, WorkingSetSize, UserModeTime, KernelModeTime, ThreadCount, HandleCount, CommandLine, ExecutablePath, ExecutionState from Win32_Process"
    $StartTime= @{e={$_.CreationDate.ToString("yyyyMMdd HH:mm:ss")};n="Start time"}
    $Owner = @{N="User";E={(GetOwnerCim($_))}}
    
    if ($proc) {
        $proc | Sort-Object Name |
        Format-Table -AutoSize -property @{e={$_.ProcessId};Label="PID"}, @{e={$_.ParentProcessId};n="Parent"}, Name,
        @{N="WorkingSet";E={"{0:N0}" -f ($_.WorkingSetSize/1kb)};a="right"},
        @{e={[DateTime]::FromFileTimeUtc($_.UserModeTime).ToString("HH:mm:ss")};n="UserTime"}, @{e={[DateTime]::FromFileTimeUtc($_.KernelModeTime).ToString("HH:mm:ss")};n="KernelTime"},
        @{N="Threads";E={$_.ThreadCount}}, @{N="Handles";E={($_.HandleCount)}}, @{N="State";E={($_.ExecutionState)}}, $StartTime, $Owner, CommandLine |
        Out-String -Width 500 | Out-File -FilePath ("$WMILogFolder\processes.txt")
        
        LogMessage $LogLevel.Info "[WMI] Retrieving file version of running binaries"
        $binlist = $proc | Group-Object -Property ExecutablePath
        ForEach($file in $binlist){
          If($file.Name) {
              FileVersion -Filepath ($file.name) | Out-File -FilePath ("$WMILogFolder\FilesVersion.csv") -Append
          }
        }
    }

    # Quota info
    LogMessage $LogLevel.Info ("[WMI] Collecting quota details")
    $quota = ExecWMIQuery -Namespace "Root" -Query "select * from __ProviderHostQuotaConfiguration"
    if ($quota) {
        ("ThreadsPerHost : " + $quota.ThreadsPerHost + "`r`n") + `
        ("HandlesPerHost : " + $quota.HandlesPerHost + "`r`n") + `
        ("ProcessLimitAllHosts : " + $quota.ProcessLimitAllHosts + "`r`n") + `
        ("MemoryPerHost : " + $quota.MemoryPerHost + "`r`n") + `
        ("MemoryAllHosts : " + $quota.MemoryAllHosts + "`r`n") | Out-File -FilePath ("$WMILogFolder\ProviderHostQuotaConfiguration.txt")
    }

    # Details of decoupled providers
    LogMessage $LogLevel.Info ("[WMI] Collecting details of decoupled providers")
    $list = Get-Process
    $DecoupledProviders = @()
    foreach ($proc in $list) {
        $prov = Get-Process -id $proc.id -Module -ErrorAction SilentlyContinue | Where-Object {$_.ModuleName -eq "wmidcprv.dll"} 
        if (($prov | measure).count -gt 0) {
            $DecoupledProviders += $proc

            if (-not $hdr) {
                "Decoupled providers" | Out-File -FilePath ("$WMILogFolder\ProviderHosts.txt") -Append
                " " | Out-File -FilePath ("$WMILogFolder\ProviderHosts.txt") -Append
                $hdr = $true
            }
            
            $prc = ExecWMIQuery -Namespace "root\cimv2" -Query ("select ProcessId, CreationDate, HandleCount, ThreadCount, PrivatePageCount, ExecutablePath, KernelModeTime, UserModeTime from Win32_Process where ProcessId = " +  $proc.id)
            $ut= New-TimeSpan -Start $prc.ConvertToDateTime($prc.CreationDate)
            
            $uptime = ($ut.Days.ToString() + "d " + $ut.Hours.ToString("00") + ":" + $ut.Minutes.ToString("00") + ":" + $ut.Seconds.ToString("00"))
            
            $ks = $prc.KernelModeTime / 10000000
            $kt = [timespan]::fromseconds($ks)
            $kh = $kt.Hours.ToString("00") + ":" + $kt.Minutes.ToString("00") + ":" + $kt.Seconds.ToString("00")
            
            $us = $prc.UserModeTime / 10000000
            $ut = [timespan]::fromseconds($us)
            $uh = $ut.Hours.ToString("00") + ":" + $ut.Minutes.ToString("00") + ":" + $ut.Seconds.ToString("00")
            
            $svc = ExecWMIQuery -Namespace "root\cimv2" -Query ("select Name from Win32_Service where ProcessId = " +  $prc.ProcessId)
            $svclist = ""
            if ($svc) {
              foreach ($item in $svc) {
                $svclist = $svclist + $item.name + " "
              }
              $svc = " Service: " + $svclist
            } else {
              $svc = ""
            }
            
            ($prc.ExecutablePath + $svc) | Out-File -FilePath ("$WMILogFolder\ProviderHosts.txt") -Append
            "PID " + $prc.ProcessId  + " (" + [String]::Format("{0:x}", $prc.ProcessId) + ")  Handles: " + $prc.HandleCount + " Threads: " + $prc.ThreadCount + " Private KB: " + ($prc.PrivatePageCount/1kb) + " KernelTime:" + $kh + " UserTime:" + $uh + " Uptime:" + $uptime | Out-File -FilePath ("$WMILogFolder\ProviderHosts.txt") -Append
            
            $Keys = Get-ChildItem HKLM:\SOFTWARE\Microsoft\Wbem\Transports\Decoupled\Client
            $Items = $Keys | Foreach-Object {Get-ItemProperty $_.PsPath }
            ForEach ($key in $Items) {
              if ($key.ProcessIdentifier -eq $prc.ProcessId) {
                ($key.Scope + " " + $key.Provider) | Out-File -FilePath ("$WMILogFolder\ProviderHosts.txt") -Append
              }
            }
            " " | Out-File -FilePath ("$WMILogFolder\ProviderHosts.txt") -Append
        }
    }

    # Service configuration
    LogMessage $LogLevel.Info ("[WMI] Exporting service configuration")
    $Commands = @(
        "sc.exe queryex winmgmt | Out-File $WMILogFolder\WinMgmtServiceConfig.txt -Append"
        "sc.exe qc winmgmt | Out-File $WMILogFolder\WinMgmtServiceConfig.txt -Append"
        "sc.exe enumdepend winmgmt 3000  | Out-File $WMILogFolder\WinMgmtServiceConfig.txt -Append"
        "sc.exe sdshow winmgmt | Out-File $WMILogFolder\WinMgmtServiceConfig.txt -Append"
    )
    RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$True

    # WMI class keys
    LogMessage $LogLevel.Info ("[WMI] Exporting WMIPrvSE AppIDs and CLSIDs registration keys")
    $Commands = @(
        "reg query ""HKEY_CLASSES_ROOT\AppID\{73E709EA-5D93-4B2E-BBB0-99B7938DA9E4}"" | Out-File $WMILogFolder\WMIPrvSE.reg.txt -Append"
        "reg query ""HKEY_CLASSES_ROOT\AppID\{1F87137D-0E7C-44d5-8C73-4EFFB68962F2}"" | Out-File $WMILogFolder\WMIPrvSE.reg.txt -Append"
        "reg query ""HKEY_CLASSES_ROOT\Wow6432Node\AppID\{73E709EA-5D93-4B2E-BBB0-99B7938DA9E4}"" | Out-File $WMILogFolder\WMIPrvSE.reg.txt -Append"
        "reg query ""HKEY_CLASSES_ROOT\Wow6432Node\AppID\{1F87137D-0E7C-44d5-8C73-4EFFB68962F2}"" | Out-File $WMILogFolder\WMIPrvSE.reg.txt -Append"
        "reg query ""HKEY_CLASSES_ROOT\CLSID\{4DE225BF-CF59-4CFC-85F7-68B90F185355}"" | Out-File $WMILogFolder\WMIPrvSE.reg.txt -Append"
    )
    RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$True

    # process dump for WMIPrvSE.exe
    $WMIPrvSEProcs = Get-Process -Name "WMIPrvse*"
    ForEach($WMIPrvSE in $WMIPrvSEProcs){
        $DumpFileName = "$WMIProcDumpFolder/" + $WMIPrvSE.Name + ".exe_" + $WMIPrvSE.ID + ".dmp"
        LogMessage $LogLevel.Info ('[WMI] Capturing user dump for ' + $WMIPrvSE.Name + ".exe(" + $WMIPrvSE.ID + ")")
        $Result = [MSDATA.UserDump]::GenerateUserDump($WMIPrvSE.ID, $DumpFileName)
        If(!$Result){
            LogMessage $LogLevel.Error ("Failed to capture process dump for " + $WMIPrvSE.Name + ".exe(" + $WMIPrvSE.ID + ")")
        }
    }

    # process dump for WinMgmt
    $WinMgmt = (Get-WmiObject win32_service | Where-Object -Property Name -Like *winmgmt*)
    $DumpFileName = "$WMIProcDumpFolder/Svchost.exe-WinMgmt.dmp"
    LogMessage $LogLevel.Info ('[WMI] Capturing user dump for Winmgmt service')
    $Result = [MSDATA.UserDump]::GenerateUserDump($WinMgmt.ProcessId, $DumpFileName)
    If(!$Result){
        LogMessage $LogLevel.Error ("Failed to capture process dump for WinMgmt")
    }

    # process dump for decoupled providers
    ForEach($DecoupledProvider in $DecoupledProviders){
        $DumpFileName = "$WMIProcDumpFolder/" + $DecoupledProvider.Name + ".exe_" + $DecoupledProvider.ID + ".dmp"
        LogMessage $LogLevel.Info ('[WMI] Capturing user dump for ' + $DecoupledProvider.Name + ".exe(" + $DecoupledProvider.ID + ")")
        $Result = [MSDATA.UserDump]::GenerateUserDump($DecoupledProvider.ID, $DumpFileName)
        If(!$Result){
            LogMessage $LogLevel.Error ("Failed to capture process dump for " + $DecoupledProvider.Name + ".exe(" + $DecoupledProvider.ID + ")")
        }
    }

    $Commands = @(
        "wevtutil epl Application $WMILogFolder\Application.evtx",
        "wevtutil al $WMILogFolder\Application.evtx /l:en-us",
        "wevtutil epl System $WMILogFolder\System.evtx",
        "wevtutil al $WMILogFolder\System.evtx /l:en-us",
        "wevtutil epl Microsoft-Windows-WMI-Activity/Operational $WMILogFolder\Microsoft-Windows-WMI-Activity-Operational.evtx",
        "wevtutil al $WMILogFolder\Microsoft-Windows-WMI-Activity-Operational.evtx /l:en-us"
    )
    RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$True

    # WMI-Activity log
    LogMessage $LogLevel.Info ('[WMI] Exporting WMI Operational log.')
    $actLog = Get-WinEvent -logname "Microsoft-Windows-WMI-Activity/Operational" -Oldest -ErrorAction SilentlyContinue
    If(($actLog | measure).count -gt 0) {
        $actLog | Out-String -width 1000 | Out-File "$WMILogFolder\Microsoft-Windows-WMI-Activity-Operational.txt"
    }

    LogMessage $LogLevel.Info ('[WMI] Collecting WMI repository and registry.')
    $Commands = @(
        "Get-ChildItem $env:SYSTEMROOT\System32\Wbem -Recurse -ErrorAction SilentlyContinue | Out-File -Append $WMILogFolder\wbemfolder.txt"
        "REG QUERY 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\wbem' /s 2>&1 | Out-File -Append $WMILogFolder\wbem.reg"
    )
    RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$True

    EndFunc $MyInvocation.MyCommand.Name
}

Function RDSPreStart{
    EnterFunc $MyInvocation.MyCommand.Name
    reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RDMS /t REG_DWORD /v EnableDeploymentUILog /d 1 /f | Out-Null
    reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RDMS  /t REG_DWORD /v EnableUILog /d 1 /f | Out-Null
    EndFunc $MyInvocation.MyCommand.Name
}

Function RDSPostStop{
    EnterFunc $MyInvocation.MyCommand.Name
    If(Test-Path -Path "C:\Windows\Logs\RDMSDeploymentUI.txt"){
        LogMessage $LogLevel.Info ('[RDS] Copying RDMS-Deplyment log')
        Copy-Item "C:\Windows\Logs\RDMSDeploymentUI.txt" $LogFolder -Force -ErrorAction SilentlyContinue
    }
    If(Test-Path -Path "$env:temp\RdmsUI-trace.log"){
        LogMessage $LogLevel.Info ('[RDS] Copying RDMS-UI log')
        Copy-Item "$env:temp\RdmsUI-trace.log" $LogFolder -Force -ErrorAction SilentlyContinue
    }
    reg delete HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RDMS /F | Out-Null
    EndFunc $MyInvocation.MyCommand.Name
}

Function ResetProcmonSetting{
    EnterFunc $MyInvocation.MyCommand.Name

    $ProcmonObj = Get-Process -Name "procmon" -ErrorAction SilentlyContinue
    If($ProcmonObj -ne $Null){
        Try{
            LogMessage $LogLevel.Debug ('Waiting for procmon to be completed.')
            Wait-Process -id $ProcmonObj.Id -ErrorAction Stop
        }Catch{
            LogMessage $LogLevel.Error ('An exception happened during waiting for procmon to be terminated.')
        }
    }

    # Now procmon have completed and start resetting LogFile registy.
    $ProcmonReg = Get-ItemProperty "HKCU:Software\Sysinternals\Process Monitor"
    If($ProcmonReg.LogFile -ne $Null -and $ProcmonReg.LogFile -ne ""){
        Try{
            LogMessage $LogLevel.Debug ('Resetting LogFile registry.')
            Set-Itemproperty -path 'HKCU:Software\Sysinternals\Process Monitor' -Name 'LogFile' -value ''
        }Catch{
            $ErrorMessage = 'An exception happened in ResetProcmonSetting.'
            LogException $ErrorMessage $_ $fLogFileOnly
            Throw ($ErrorMessage)
        }
    }
    EndFunc $MyInvocation.MyCommand.Name
}

Function CreateLogFolder{
    Param(
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [string]$LogFolder
    )
    EnterFunc $MyInvocation.MyCommand.Name
    If(!(test-path -Path $LogFolder)){
        LogMessage $LogLevel.info ("Creating log folder $LogFolder") "Cyan"
        New-Item $LogFolder -ItemType Directory -ErrorAction Stop | Out-Null
    }Else{
        LogMessage $LogLevel.Debug ("$LogFolder already exist.")
    }
    EndFunc $MyInvocation.MyCommand.Name
}

Function CompressLogIfNeededAndShow{
    EnterFunc $MyInvocation.MyCommand.Name

    If($Compress.IsPresent){
        $zipSourceFolder = $LogFolder
        $zipDestinationPath = "$LogFolder$LogSuffix.zip"

        Write-Host ""
        LogMessage $LogLevel.Info ("Compressing $zipSourceFolder. This may take a while.")
        Try{
            Add-Type -Assembly 'System.IO.Compression.FileSystem'
            [System.IO.Compression.ZipFile]::CreateFromDirectory($zipSourceFolder, $zipDestinationPath)
        }Catch{
            LogMessage $LogLevel.Warning ('An exception happened during compressing log folder' + "`n" + $_.Exception.Message)
            LogMessage $LogLevel.Info ("Please compress $LogFolder manually and send it to our upload site.")
            LogException $ErrorMessage $_ $fLogFileOnly
            Return # Return here to prevent the deletion of source folder that is performed later.
        }
        LogMessage $LogLevel.Normal ("Please send $zipDestinationPath to our upload site.")

        If($Delete.IsPresent){
            LogMessage $LogLevel.Info ("Deleting $LogFolder")
            Try{
                Remove-Item $LogFolder -Recurse -Force -ErrorAction Stop | Out-Null
            }Catch{
                LogMessage $LogLevel.Warning ('An exception happens in Remove-Item' + "`n" + $_.Exception.Message)
                LogMessage $LogLevel.Info ("Please remove $LogFolder manually")
                LogException $ErrorMessage $_ $fLogFileOnly
            }
        }
        Explorer (Split-Path $LogFolder -parent)
    }Else{
        Explorer $LogFolder 
    }

    EndFunc $MyInvocation.MyCommand.Name
}

Function ShowTraceResult{
    Param(
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [System.Collections.Generic.List[PSObject]]$TraceObjectList,
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('Start','Stop')]
        [String]$FlagString,
        [Parameter(Mandatory=$True)]
        [Bool]$fAutoLogger
    )
    EnterFunc $MyInvocation.MyCommand.Name
    If($FlagString -eq 'Start'){
        $Status = $TraceStatus.Started
        If($fAutLogger){
            $Message = 'Following autologger session(s) were enabled:'
        }Else{
            $Message = 'Following trace(s) are started:'
        }
    }ElseIf($FlagString -eq 'Stop'){
        $Status = $TraceStatus.Stopped
        $Message = 'Following trace(s) are successfully stopped:'
    }

    Write-Host ''
    Write-Host '********** RESULT **********'
    $TraceObjects = $TraceObjectList | Where-Object{$_.Status -eq $Status}
    If($TraceObjects -ne $Null){
        Write-Host($Message)
        ForEach($TraceObject in $TraceObjects){
            If(!$fAutoLogger){
                Write-Host('    - ' + $TraceObject.TraceName)
            }Else{
                Write-Host('    - ' + $TraceObject.AutoLogger.AutoLoggerSessionName)
            }
        }
    }Else{
        If($FlagString -eq 'Start'){
            Write-Host('No traces are started.')
        }ElseIf($FlagString -eq 'Stop'){
            Write-Host('No traces are stoppped.')
        }
    }

    $ErrorTraces = $TraceObjectList | Where-Object{$_.Status -ne $Status -and $_.Status -ne $TraceStatus.NoStopFunction -and $_.Status -ne $TraceStatus.NotSupported}
    If($ErrorTraces -ne $Null){
        Write-Host('The following trace(s) were failed:')
        ForEach($TraceObject in $ErrorTraces){
            $StatusString = ($TraceStatus.GetEnumerator() | Where-Object {$_.Value -eq $TraceObject.Status}).Key
            If(!$fAutoLogger){
                Write-Host('    - ' + $TraceObject.TraceName + "($StatusString)") -ForegroundColor Red
            }Else{
                Write-Host('    - ' + $TraceObject.AutoLogger.AutoLoggerSessionName + "($StatusString)") -ForegroundColor Red
            }
        }
        Write-Host ""
        Write-Host "=> Run '.\UXTrace.ps1 -Stop' to stop all running traces." -ForegroundColor Yellow
    }
    EndFunc $MyInvocation.MyCommand.Name
}

Function PrintPreStart{
    EnterFunc $MyInvocation.MyCommand.Name
    Try{
        SetEventLog 'Microsoft-Windows-PrintService/Admin'
        SetEventLog 'Microsoft-Windows-PrintService/Operational'
        SetEventLog 'Microsoft-Windows-PrintService/Debug'
    }Catch{
        $ErrorMessage = 'An exception happened in SetEventLog'
        LogException $ErrorMessage $_ $fLogFileOnly
        Throw ($ErrorMessage)
    }
    EndFunc $MyInvocation.MyCommand.Name
}

Function PrintPostStop{
    EnterFunc $MyInvocation.MyCommand.Name
    $fResult = $True
    Try{
        ResetEventLog 'Microsoft-Windows-PrintService/Admin'
        ResetEventLog 'Microsoft-Windows-PrintService/Operational'
        ResetEventLog 'Microsoft-Windows-PrintService/Debug'
    }Catch{
        $ErrorMessage = 'An exception happened in ResetEventLog'
        LogException $ErrorMessage $_ $fLogFileOnly
        Throw ($ErrorMessage)
    }
    EndFunc $MyInvocation.MyCommand.Name
}

Function TaskPreStart{
    EnterFunc $MyInvocation.MyCommand.Name
    Try{
        SetEventLog 'Microsoft-Windows-TaskScheduler/Operational'
        SetEventLog 'Microsoft-Windows-TaskScheduler/Maintenance'
    }Catch{
        $ErrorMessage = 'An exception happened in SetEventLog'
        LogException $ErrorMessage $_ $fLogFileOnly
        Throw ($ErrorMessage)
    }
    EndFunc $MyInvocation.MyCommand.Name
}

Function TaskPostStop{
    EnterFunc $MyInvocation.MyCommand.Name
    Try{
        ResetEventLog 'Microsoft-Windows-TaskScheduler/Operational'
        ResetEventLog 'Microsoft-Windows-TaskScheduler/Maintenance'
    }Catch{
        $ErrorMessage = 'An exception happened in ResetEventLog'
        LogException $ErrorMessage $_ $fLogFileOnly
        Throw ($ErrorMessage)
    }
    EndFunc $MyInvocation.MyCommand.Name
}

Function IMEPreStart{
    EnterFunc $MyInvocation.MyCommand.Name
    Try{
        SetEventLog 'Microsoft-Windows-IME-Broker/Analytic'
        SetEventLog 'Microsoft-Windows-IME-CandidateUI/Analytic'
        SetEventLog 'Microsoft-Windows-IME-CustomerFeedbackManager/Debug'
        SetEventLog 'Microsoft-Windows-IME-CustomerFeedbackManagerUI/Analytic'
        SetEventLog 'Microsoft-Windows-IME-JPAPI/Analytic'
        SetEventLog 'Microsoft-Windows-IME-JPLMP/Analytic'
        SetEventLog 'Microsoft-Windows-IME-JPPRED/Analytic'
        SetEventLog 'Microsoft-Windows-IME-JPSetting/Analytic'
        SetEventLog 'Microsoft-Windows-IME-JPTIP/Analytic'
        SetEventLog 'Microsoft-Windows-IME-KRAPI/Analytic'
        SetEventLog 'Microsoft-Windows-IME-KRTIP/Analytic'
        SetEventLog 'Microsoft-Windows-IME-OEDCompiler/Analytic'
        SetEventLog 'Microsoft-Windows-IME-TCCORE/Analytic'
        SetEventLog 'Microsoft-Windows-IME-TCTIP/Analytic'
        SetEventLog 'Microsoft-Windows-IME-TIP/Analytic'
        SetEventLog 'Microsoft-Windows-TaskScheduler/Operational'
    }Catch{
        $ErrorMessage = 'An exception happened in SetEventLog'
        LogException $ErrorMessage $_ $fLogFileOnly
        Throw ($ErrorMessage)
    }
    EndFunc $MyInvocation.MyCommand.Name
}

Function IMEPostStop{
    EnterFunc $MyInvocation.MyCommand.Name
    $fResult = $True
    Try{
        ResetEventLog 'Microsoft-Windows-IME-Broker/Analytic'
        ResetEventLog 'Microsoft-Windows-IME-CandidateUI/Analytic'
        ResetEventLog 'Microsoft-Windows-IME-CustomerFeedbackManager/Debug'
        ResetEventLog 'Microsoft-Windows-IME-CustomerFeedbackManagerUI/Analytic'
        ResetEventLog 'Microsoft-Windows-IME-JPAPI/Analytic'
        ResetEventLog 'Microsoft-Windows-IME-JPLMP/Analytic'
        ResetEventLog 'Microsoft-Windows-IME-JPPRED/Analytic'
        ResetEventLog 'Microsoft-Windows-IME-JPSetting/Analytic'
        ResetEventLog 'Microsoft-Windows-IME-JPTIP/Analytic'
        ResetEventLog 'Microsoft-Windows-IME-KRAPI/Analytic'
        ResetEventLog 'Microsoft-Windows-IME-KRTIP/Analytic'
        ResetEventLog 'Microsoft-Windows-IME-OEDCompiler/Analytic'
        ResetEventLog 'Microsoft-Windows-IME-TCCORE/Analytic'
        ResetEventLog 'Microsoft-Windows-IME-TCTIP/Analytic'
        ResetEventLog 'Microsoft-Windows-IME-TIP/Analytic'
        ResetEventLog 'Microsoft-Windows-TaskScheduler/Operational'
    }Catch{
        $ErrorMessage = 'An exception happened in ResetEventLog'
        LogException $ErrorMessage $_ $fLogFileOnly
        Throw ($ErrorMessage)
    }
    EndFunc $MyInvocation.MyCommand.Name
}

Function CleanUpandExit{
    If($fQuickEditCodeExist){
        [DisableConsoleQuickEdit]::SetQuickEdit($False) | Out-Null
    }

    Try{
        Stop-Transcript -ErrorAction SilentlyContinue
    }Catch{
    }

    Exit
}

Function StartSCM{
    EnterFunc $MyInvocation.MyCommand.Name
    Write-Host("[SCM] Setting HKLM\Software\Microsoft\Windows NT\CurrentVersion\Tracing\SCM\Regular\TracingDisabled to 0") -ForegroundColor Yellow
    reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Tracing\SCM\Regular" /v TracingDisabled /t REG_DWORD /d 0 /f | Out-Null
    If($LASTEXITCODE -ne 0){
        Throw("[SCM] Error during setting TracingDisabled registry to 0. Error=$LASTEXITCODE")
    }
    EndFunc $MyInvocation.MyCommand.Name
}

Function StopSCM{
    EnterFunc $MyInvocation.MyCommand.Name
    $fSCMTraceRunning = $False
    logman SCM -ets 2>&1 | Out-Null
    If($LASTEXITCODE -eq -2144337918){
        Write-Host("[SCM] INFO: SCM is not running.")
        $fSCMTraceRunning = $False
    }ElseIf($LASTEXITCODE -ne 0){
        $ErrorMessage = "[SCM] Unable to retrieve ETW session for SCM. Error=$LASTEXITCODE"
        LogMessage $LogLevel.Error $ErrorMessage
        Throw($ErrorMessage)
    }Else{
        LogMessage $LogLevel.Debug ("SCM trace is running.") Yellow
        $fSCMTraceRunning = $True
    }

    # Stopping SCM tracing
    If($fSCMTraceRunning){
        LogMessage $LogLevel.Info ("[SCM] Running logman stop SCM -ets")
        logman stop SCM -ets | Out-Null
        If($LASTEXITCODE -ne 0){
            $ErrorMessage = "[SCM] Error happened during stopping SCM trace. Error=$LASTEXITCODE"
            LogMessage $LogLevel.Error $ErrorMessage
            Throw($ErrorMessage)
        }
        Write-Host("[SCM] Copying $env:SYSTEMROOT\system32\LogFiles\Scm\SCM* to log folder") -ForegroundColor Yellow
        If(Test-Path -Path "$env:SYSTEMROOT\system32\LogFiles\Scm\SCM*"){
            Copy-Item  "C:\Windows\system32\LogFiles\Scm\SCM*" $LogFolder -Force -ErrorAction SilentlyContinue | Out-Null
        }Else{
            LogMessage $LogLevel.Debug ("[SCM] WARNING: SCM tracing is enabled but $env:SYSTEMROOT\system32\LogFiles\Scm does not exist.")
        }
    }

    # Disabling registry
    Write-Host("[SCM] Setting HKLM\Software\Microsoft\Windows NT\CurrentVersion\Tracing\SCM\Regular\TracingDisabled to 1") -ForegroundColor Yellow
    reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Tracing\SCM\Regular" /v TracingDisabled /t REG_DWORD /d 1 /f | Out-Null
    If($LASTEXITCODE -ne 0){
        Throw("[SCM] Error happens during deleting TracingDisabled. Error=$LASTEXITCODE")
    }
    EndFunc $MyInvocation.MyCommand.Name
}

Function DetectSCMTrace{
    [OutputType([Bool])]
    Param()
    EnterFunc $MyInvocation.MyCommand.Name
    $fSCMTraceRunning = $False

    logman "SCM" -ets 2>&1 | Out-Null
    If($LASTEXITCODE -eq -2144337918){
        LogMessage $LogLevel.Debug ("SCM trace is not running.")
        $fSCMTraceRunning = $False
    }ElseIf($LASTEXITCODE -ne 0){
        $ErrorMessage = "Unable to retrieve ETW session for SCM. Error=$LASTEXITCODE"
        LogMessage $LogLevel.Error $ErrorMessage
        Throw($ErrorMessage)
    }Else{
        LogMessage $LogLevel.Debug ("SCM trace is running.") Yellow
        $fSCMTraceRunning = $True
    }

    Try{
        $RegValue = Get-ItemProperty -Path "HKLM:Software\Microsoft\Windows NT\CurrentVersion\Tracing\SCM\Regular" -Name 'TracingDisabled' -ErrorAction Stop
    }Catch{
        LogMessage $LogLevel.Debug ("[SCM] TracingDisabled does not exist")
    }
    If($RegValue -eq $Null){
        $fRegEnabled = $False
    }Else{
        LogMessage $LogLevel.Debug ("[SCM] TracingDisabled = " + $RegValue.TracingDisabled)
        If($RegValue.TracingDisabled -eq 1){
            $fRegEnabled = $False
        }Else{
            $fRegEnabled = $True
        }
    }

    If($fSCMTraceRunning -eq $True -or $fRegEnabled -eq $True){
        $fResult = $True
    }Else{
        $fResult = $False
    }
    EndFunc $MyInvocation.MyCommand.Name
    Return $fResult
}

Function StartTTD{
    EnterFunc $MyInvocation.MyCommand.Name

    $fInboxTTDMode # This valiable is for future use but implment beforehand.
    # Case with -TTDPath(Internal TTD)
    If($TTDPath -ne $Null -and $TTDPath -ne ""){
        LogMessage $Loglevel.Debug ("Searching tttracer.exe")
        $Script:TTTracerPath = SearchTTTracer
        If($Script:TTTracerPath -eq $Null){
            Throw("Unable to find TTTracer.exe in $TTDPath")
        }
    # Inbox TTD
    }Else{
        Try{
            $TTDCommand = Get-Command 'TTTracer.exe' -ErrorAction Stop
            $Script:TTTracerPath = $TTDCommand.Source
            $fInboxTTDMode = $True
        }Catch{
            $ErrorMessage = 'TTTracer.exe does not exist.'
            LogMessage $Loglevel.Error $ErrorMessage
            LogMessage $Loglevel.Info ("Please run with -Start -TTD <PID|Process Name|Service Name> -TTDPath <location of tttracer.exe>.")
            Throw ($ErrorMessage)
        }
    }

    LogMessage $Loglevel.Info ("[TTD] Using $TTTracerPath")

    # Check passed string for -TTD is PID, exe name or service name.
    # PID
    $fFound = $False
    If(([int]::TryParse($TTD,[ref]$Null))){
        Try{
             $Process = Get-Process -Id $TTD -ErrorAction Stop
        }Catch{
            $ErrorMessage = "Invalid PID $TTD was specified for -TTD. Check the PID."
            LogMessage $Loglevel.Error $ErrorMessage
            Throw ($ErrorMessage)
        }
        $ProcID = $Process.Id
        $fFound = $True
        LogMessage $Loglevel.Debug ("Found target process with PID $ProcID")
    }

    # Process or service name case
    If(!$fFound){
        If($TTD.Contains('.exe')){
            Try{
                $ProcName = $TTD.Replace('.exe','')
                $Processes = Get-Process -IncludeUserName -Name $ProcName -ErrorAction Stop
            }Catch{
                If(!$TTDOnlaunch.IsPresent){
                    $ErrorMessage = "$TTD is not running or invalid process name."
                    LogMessage $Loglevel.Error $ErrorMessage
                    Throw ($ErrorMessage)
                }
            }
            If($Processes.Count -gt 1 -and !$TTDOnlaunch.IsPresent){
                Write-Host("Found mutiple processes below.")
                Write-Host("-----------------------------------------")
                ForEach($Process in $Processes){
                    Write-Host("- " + $Process.Name +"(PID:" + $Process.Id + " User:" + $Process.UserName + ")")
                }
                Write-Host("-----------------------------------------")
                Try{
                    $SpecifiedPID = Read-Host "Enter PID of process you want to attach"
                    $Process = Get-Process -Id $SpecifiedPID -ErrorAction Stop
                }Catch{
                    $ErrorMessage = "Invalid PID `'$SpecifiedPID`' was specified. Check enter correct PID."
                    LogMessage $Loglevel.Error $ErrorMessage
                    Throw ($ErrorMessage)
                }
                $ProcID = $SpecifiedPID
            }Else{
                $Process = $Processes
                $ProcID = $Processes.Id
            }
            $fPID = $True
            $fFound = $True
            LogMessage $Loglevel.Debug ("Convertion of process name to PID was successful and target process was found with PID $ProcID")

        }Else{ # Service name or package name case
            Try{
                $Service = Get-WmiObject -Class win32_service -ErrorAction Stop | Where-Object {$_.Name -eq $TTD}
            }Catch{
                $ErrorMessage = "Error happened during running Get-WmiObject -Class win32_service"
                LogMessage $Loglevel.Error $ErrorMessage
                Throw ($ErrorMessage)
            }

            If ($Service -ne $Null){
                If($Service.ProcessID -eq $Null){
                    $ProcID = $Null
                }Else{
                    $ProcID = $Service.ProcessID
                }
                $fService = $True
                $fFound = $True
                LogMessage $Loglevel.Debug ("Target service " + $Service + " was found.")
            }

            # Search as a package name
            If($TTDOnLaunch.IsPresent -and !$fFound){
                $AppXApps = Get-AppxPackage -Name $TTD
                If ($AppXApps.count -eq 1){
                    $fAppX = $True
                    $fFound = $True
                    LogMessage $Loglevel.Debug ("Found AppX package for " + $AppXApps.Name)
                }ElseIf($AppXApps.count -gt 1){
                    $ErrorMessage = "We see multiple packages that have name of $TTD. Please specify accurate package name for -TTD."
                    LogMessage $Loglevel.Error $ErrorMessage
                    Throw ($ErrorMessage)
                }
            }
        }
    }

    If(!$fFound){
        $ErrorMessage = "We were not able to found target process/service/package"
        LogMessage $Loglevel.Error $ErrorMessage
        Throw ($ErrorMessage)
    }

    # -Onlaunch case
    If($TTDOnlaunch.IsPresent){
        
        If($fService){
            $TTDArg = "/k $TTTracerPath -out `"$LogFolder`" -OnLaunch $TTD"
        }ElseIf($fPID){
            $TTDArg = "/k $TTTracerPath -out `"$LogFolder`" -OnLaunch $TTD -Parent *"
        }ElseIf($fAppX){
            $TTDArg = "/k $TTTracerPath -out `"$LogFolder`" -OnLaunch $TTD -plm"
        }

        $TTDcmd = "cmd.exe $TTDArg"
        LogMessage $Loglevel.info ("[TTD] Starting $TTDcmd")

        Try{
            # TTTracer.exe starts here. We use call operator(&) as TTD shows small window and we also would like to see every outputs as TTD is risky command.
            Start-Process 'cmd.exe' -ArgumentList $TTDArg -ErrorAction Stop
        }Catch{
            $ErrorMessage = "An exception happed during starting `'TTTracer.exe -onLaunch`'. See error in command prompt open with another window."
            LogMessage $Loglevel.Error $ErrorMessage
            Throw ($ErrorMessage)
        }
        EndFunc $MyInvocation.MyCommand.Name
        Return
    }

    # -Attach case
    If($ProcID -eq $Null){
        $ErrorMessage = "Unable to find PID for $TTD"
        LogMessage $Loglevel.Error $ErrorMessage
        Throw ($ErrorMessage)
    }

    If($fService){
        LogMessage $Loglevel.info ("[TTD] Target service is `'" + $Service.Name + "`'(PID:$ProcID)")
    }Else{
        LogMessage $Loglevel.info ("[TTD] Target process is `'" + $Process.Name + ".exe`'(PID:$ProcID)")
    }

    $TTDArg =  "-bg -out `"$LogFolder`" -attach $ProcID"
    $TTDcmd = "$TTTracerPath $TTDArg"
    LogMessage $Loglevel.info ("[TTD] Starting $TTDcmd")

    # TTTracer.exe starts here. We use call operator(&) as TTD shows small window and we also would like to see every outputs as TTD is risky command.
    & $TTTracerPath -bg -out `"$LogFolder`" -attach $ProcID
    If($LASTEXITCODE -ne 0){
        $ErrorMessage = "An exception happed during starting `'$TTDcmd`'. See error in command prompt open with another window."
        LogMessage $Loglevel.Error ($ErrorMessage)
        Throw ($ErrorMessage)
    }

    Start-Sleep 1  # Wait for tttracer to be started.

    Try{
        # See if tttracer.exe is started or not.
        $TTDProc = Get-Process -Name "tttracer" -ErrorAction Stop
        LogMessage $Loglevel.info ("[TTD] TTTracer started successfully with PID:" + $TTDProc.Id)
    }Catch{
        $ErrorMessage = "Failed to start TTD. See above error message for detail."
        LogMessage $Loglevel.Error $ErrorMessage
        Throw ($ErrorMessage)
    }

    EndFunc $MyInvocation.MyCommand.Name
}

Function StopTTD{
    EnterFunc $MyInvocation.MyCommand.Name
    LogMessage $Loglevel.info ("[TTD] Stopping TTD.")

    Try{
        # See if tttracer.exe is started or not.
        $TTDProcs = Get-Process -Name "tttracer" -ErrorAction Stop
        LogMessage $Loglevel.info ("[TTD] Detected running TTTracer")
        $fTTDRunning = $True
    }Catch{
        $ErrorMessage = "[TTD] TTTracer.exe is not running."
        LogMessage $Loglevel.Info $ErrorMessage
        $TTDExePath = $Script:TTTracerPath
        $fTTDRunning = $False
    }

    If($TTDProcs.count -gt 1){
        # This is case for downlevel OS like WS2012R2
        # In this case, there are two tttracers, normal tttracer.exe and 'downlevel/tttracer.exe', are running.
        # If we see tttracer for downlevel, we have to use it to stop running tttracer.
        ForEach($TTDProc in $TTDProcs){
            If(($TTDProc.Path).contains("downlevel\tttracer.exe")){
                LogMessage $Loglevel.info ("[TTD] Detected downlevel TTTracer and will use the tttracer to stop trace.")
                $TTDExePath = $TTDProc.Path
                break
            }Else{
                $TTDExePath = $TTDProc.Path
            }
        }
    }Else{
        $TTDExePath = $TTDProcs.Path
    }

    # This could happen for -Onlaunch case.
    # In case of -Onlaunch, tttracer may not be running need to get ttd path from running TTDService.exe.
    If(!$fTTDRunning){
        Try{
            $TTDService = Get-Process -Name "TTDService" -ErrorAction Stop
        }Catch{
            LogMessage $Loglevel.Info ("[TTD] TTTracer.exe and TTDService.exe are not running.")
            Return
        }
        $TTDExePath = $TTDService.Path -replace "TTDService.exe","TTTracer.exe"
    }

    If($TTDExePath -eq $Null -or $TTDExePath -eq ''){
        LogMessage $Loglevel.Info ("[TTD] TTTracer.exe does not exist on this machine.")
        Return
    }

    LogMessage $Loglevel.Info ("[TTD] Using $TTDExePath")
    LogMessage $Loglevel.info ("[TTD] Running $TTDExePath -stop all")
    & $TTDExePath -stop all

    Start-Sleep 10  # It seems like we have to wait several seconds after issuing '-stop all' for -delete and -cleanup to work properly.
    LogMessage $Loglevel.info ("[TTD] Running $TTTracerPath -delete all")
    & $TTDExePath -delete all

    Start-Sleep 3
    $fTTDRunning = DetectTTD
    If($fTTDRunning){
        # This is the case where -stop all does not work
        # This could happen with downlevel OS like Windows Server 2012 RS. So request manual stop.
        Write-Host "Please uncheck checkbox for `'Tracing on`' in small window on top left of desktop."
        Read-Host -Prompt "Enter any after uncheck the check box"
    }


    Start-Sleep 1
    LogMessage $Loglevel.info ("[TTD] Running $TTTracerPath -cleanup")
    & $TTDExePath -cleanup

    EndFunc $MyInvocation.MyCommand.Name
}

Function DetectTTD{
    [OutputType([Bool])]
    Param()
    EnterFunc $MyInvocation.MyCommand.Name
    $fResult = $False
    Try{
        $ProcObj = Get-Process -Name 'tttracer' -ErrorAction Stop
    }Catch{
        # Do nothing
    }
    If($ProcObj -ne $Null){
        LogMessage $Loglevel.Debug ("DetectTTD: " + $ProcObj.Path + " is running") Yellow
        $fResult = $True
        $fTTDRunning = $True
    }Else{
        $fResult = $False
        $fTTDRunning = $False
    }

    # This is called from -Stop or -Status
    # In this case, we also check if TTDService.exe is running for -Onlaunch scenario
    #If($Stop.IsPresent -or $Status.IsPresent){
    #    Try{
    #        $ProcObj = Get-Process -Name 'TTDService' -ErrorAction Stop
    #    }Catch{
    #        # Do nothing
    #    }
    #    If($ProcObj -ne $Null){
    #        LogMessage $Loglevel.Info ("DetectTTD: " + $ProcObj.Path + " is running") Yellow
    #        $fResult = $True
    #        If(!$fTTDRunning){
    #            $Script:fOnlyTTDService = $True # This will be used when showing status
    #        }
    #    }Else{
    #        $fResult = $False
    #    }
    #}

    EndFunc $MyInvocation.MyCommand.Name
    Return $fResult
}

Function RunSetWer{
    EnterFunc $MyInvocation.MyCommand.Name
    $WERRegKey = "HKLM:Software\Microsoft\Windows\Windows Error Reporting\LocalDumps"
    $DumpFolder = Read-Host -Prompt "Enter dump folder name"
    If(!(Test-Path -Path $DumpFolder -PathType Container)){
        Try{
            LogMessage $Loglevel.Info ("Creating $DumpFolder.")
            New-Item $DumpFolder -ItemType Directory -ErrorAction Stop | Out-Null
        }Catch{
            LogException ("Unable to create $DumpFolder") $_
            CleanUpandExit
        }
    }

    If(!(Test-Path -Path $WERRegKey)){
        Try{
            LogMessage $Loglevel.Info ("Creating $WERRegKey.")
            New-Item $WERRegKey -ErrorAction Stop | Out-Null
        }Catch{
            LogException ("Unable to create $WERRegKey") $_
            CleanUpandExit
        }
    }

    Try{
        LogMessage $Loglevel.Info ("Setting `'DumpType`' to `'2`'.")
        Set-ItemProperty -Path $WERRegKey -Name 'DumpType' -value 2 -Type DWord -ErrorAction Stop | Out-Null
        LogMessage $Loglevel.Info ("Setting `'DumpFolder`' to `'$DumpFolder`'")
        Set-ItemProperty -Path $WERRegKey -Name 'DumpFolder' -value $DumpFolder -Type ExpandString -ErrorAction Stop | Out-Null
    }Catch{
        LogException ("Unable to set DumpType or DumpFolder") $_
        CleanUpandExit
    }
    Write-Host("WER settings are set properly.")
    EndFunc $MyInvocation.MyCommand.Name
    CleanUpandExit
}

Function RunUnSetWer{
    EnterFunc $MyInvocation.MyCommand.Name
    $WERRegKey = "HKLM:Software\Microsoft\Windows\Windows Error Reporting\LocalDumps"
    If(Test-Path -Path $WERRegKey){
        Try{
            LogMessage $Loglevel.Info ("Deleting $WERRegKey.")
            Remove-Item $WERRegKey -ErrorAction Stop | Out-Null
        }Catch{
            LogException ("Unable to delete $WERRegKey") $_
            CleanUpandExit
        }
    }Else{
            LogMessage $Loglevel.Info ("INFO: `'$WERRegKey`' is already deleted.")
    }
    Write-Host("Disabling WER settings is completed.")
    EndFunc $MyInvocation.MyCommand.Name
}

Function ShowSupportedTraceList{
    EnterFunc $MyInvocation.MyCommand.Name
    Write-Host('The following traces are supported:')
    ForEach($Key in $TraceSwitches.Keys){
        Write-Host('    - ' + $Key + ': ' + $TraceSwitches[$Key])
    }
    Write-Host('')
    Write-Host('The following commands are supported:')
    ForEach($Key in $CommandSwitches.Keys){
        Write-Host('    - ' + $Key + ': ' + $CommandSwitches[$Key])
    }
    Write-Host('')
    Write-Host("To see usage, run '.\" + $ScriptName + " -help'")
    Write-Host('')
    EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessList{
    EnterFunc $MyInvocation.MyCommand.Name
    Write-Host('The following traces are supported:')
    ForEach($Key in $TraceSwitches.Keys){
        Write-Host('    - ' + $Key + ': ' + $TraceSwitches[$Key])
    }
    Write-Host('')
    Write-Host('The following commands are supported:')
    ForEach($Key in $CommandSwitches.Keys){
        Write-Host('    - ' + $Key + ': ' + $CommandSwitches[$Key])
    }
    Write-Host('')
    Write-Host("To see usage, run '.\" + $ScriptName + " -help'")
    Write-Host('')
    EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessListSupportedLog{
    EnterFunc $MyInvocation.MyCommand.Name
    $TraceArray = @()
    ForEach($Key in $TraceSwitches.Keys){
        $TraceArray += $Key
    }
    ForEach($Key in $CommandSwitches.Keys){
        $TraceArray += $Key
    }
    $TraceArray += 'Basic'

    Write-Host("The following logs are supported")
    ForEach($Trace in $TraceArray){
        $FuncName = 'Collect' + $Trace + 'Log'
        Try{
            Get-Command $FuncName -ErrorAction Stop | Out-Null
        }Catch{
            Continue
        }
        Write-Host("    - $Trace")
    }
    Write-Host('')
    Write-Host('Usage:')
    Write-Host('  .\UXTrace.ps1 -CollectLog [ComponentName,ComponentName,...]')
    Write-Host('  Example: .\UXTrace.ps1 -CollectLog AppX,Basic')
    Write-Host('')
    EndFunc $MyInvocation.MyCommand.Name
}

Function ShowSupportedNetshScenario{
    EnterFunc $MyInvocation.MyCommand.Name
    $SupportedScenrios = Get-ChildItem 'HKLM:SYSTEM\CurrentControlSet\Control\NetDiagFx\Microsoft\HostDLLs\WPPTrace\HelperClasses'
    Write-Host "Supported scenarios for -NetshScnario are:"
    ForEach($SupportedScenario in $SupportedScenrios){
        Write-Host("  - " + $SupportedScenario.PSChildName)
    }
    Write-Host('')
    EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessCollectLog{
    EnterFunc $MyInvocation.MyCommand.Name
    LogMessage $LogLevel.Debug ("Started with -Collectlog $CollectLog")
    $IsAlreadyGetBasicLog = $False
    $RequestedLogs = $CollectLog -Split '\s+'
    $i=0
    ForEach($RequestedLog in $RequestedLogs){
        $FuncName = 'Collect' + $RequestedLog + 'Log'
        Try{
             Get-Command $FuncName -ErrorAction Stop | Out-Null
        }Catch{
             Write-Host("Log collection for $RequestedLog($FuncName) is not implemented yet.") -ForegroundColor Yellow
             Continue
        }
        If($FuncName.ToLower() -eq "collectbasiclog"){
            $IsAlreadyGetBasicLog = $True
        }
        & $FuncName  # Calling function for log collection.
        $i++
    }

    # We always collect basic log
    if(!$IsAlreadyGetBasicLog -and !$NoBasicLog.IsPresent){
        CollectBasicLog
    }

    If($i -eq 0){
        Write-Host('Usage:')
        Write-Host('  .\UXTrace.ps1 -CollectLog [ComponentName,ComponentName,...]')
        Write-Host('  Example: .\UXTrace.ps1 -CollectLog AppX,Basic')
        Write-Host('')
        Write-Host("Run .\$ScriptName -ListSupportedLog to see supported log name")
    }
    CompressLogIfNeededAndShow
    CleanUpandExit

}

Function CheckParameterCompatibility{
    EnterFunc $MyInvocation.MyCommand.Name
    If($Netsh.IsPresent -and ($NetshScenario -ne $Null)){
        $Message = 'ERROR: Cannot specify -Netsh and -NetshScenario at the same time.'
        Write-Host $Message -ForegroundColor Red
        Throw $Message
    }

    If($SCM.IsPresent -and !$NoWait.IsPresent){
        $Message = 'ERROR: -SCM must be specified with -NoWait.'
        Write-Host $Message -ForegroundColor Red
        Throw $Message
    }

    If($TTDOnlaunch.IsPresent -and $NoWait.IsPresent){
        $Message = 'ERROR: Currently setting both -TTDOnlauch and -NoWait is not supported.'
        Write-Host $Message -ForegroundColor Red
        Throw $Message
    }

    If(![string]::IsNullOrEmpty($LogFolderName) -and $StopAutoLogger.IsPresent){
        $Message = "ERROR: don't set -StopAutoLogger and -LogFolderName at the same time.`n"
        $Message += "-StopAutoLogger detects log folder automatically and you cannot change the log folder when stopping autologger.`n"
        $Message += "If you want to change log folder for autologger, please set it when you set autologger."
        Write-Host $Message -ForegroundColor Red
        Write-Host "ex) .\UXTrace.ps1 -SetAutolloger -[TraceName] -AutologgerFolderName E:\MSDATA" -ForegroundColor Yellow
        Throw $Message
    }

    EndFunc $MyInvocation.MyCommand.Name
}

Function CreateStartCommandforBatch{
    Param(
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [System.Collections.Generic.List[PSObject]]$TraceObjectList
    )
    EnterFunc $MyInvocation.MyCommand.Name

    If($TraceObjectList -eq $Null){
        LogMessage $LogLevel.Error "There is no trace in LogCollector."
        retrun
    }

    If($SetAutoLogger.IsPresent){
        $BatFileName = $SetAutologgerBatFileName
    }

    Try{
        $BatchFolder = Split-Path $BatFileName -Parent
        CreateLogFolder $BatchFolder
    }Catch{
        LogException("Unable to create $BatchFolder") $_
        CleanUpandExit
    }

    If(!$SetAutoLogger.IsPresent){
        If($LogFolderName -eq ""){
            $LogFolder = $LogFolder -replace ".*\Desktop","%USERPROFILE%\Desktop"
        }
        Write-Output("MD $LogFolder") | Out-File $BatFileName -Encoding ascii -Append
    }Else{
        Write-Output("MD $AutoLoggerLogFolder") | Out-File $BatFileName -Encoding ascii -Append
    }

    ForEach($TraceObject in $TraceObjectList){
        Switch($TraceObject.LogType){
            'ETW' {
                If($SetAutoLogger.IsPresent){
                    $TraceName = $TraceObject.AutoLogger.AutoLoggerSessionName
                }Else{    
                    $TraceName = $TraceObject.TraceName
                }
                $LogFileName = $TraceObject.LogFileName -replace "-[0-9]+-[0-9]+-[0-9]+\.[0-9]+\.[0-9]+.","."

                If($LogFolderName -eq ""){
                    $LogFileName = $LogFileName -replace ".*\Desktop","`"%USERPROFILE%\Desktop"
                }

                $Commandline = "logman create trace $TraceName -ow -o $LogFileName -mode Circular -bs 64 -f bincirc -max $MAXLogSize -ft 60 -ets"
                LogMessage $LogLevel.Info ("Adding `'$CommandLine`' to $BatFileName")
                Write-Output($CommandLine) | Out-File $BatFileName -Encoding ascii -Append
                
                ForEach($Provider in $TraceObject.Providers){
                    $Commandline = "logman update trace $TraceName -p $Provider 0xffffffffffffffff 0xff -ets"
                    LogMessage $LogLevel.Info ("Adding `'$CommandLine`' to $BatFileName")
                    Write-Output($CommandLine) | Out-File $BatFileName -Encoding ascii -Append
                }

                If($SetAutoLogger.IsPresent -and $TraceObject.AutoLogger -ne $Null){
                    $Commandline = "logman update trace $TraceName -o $($TraceObject.AutoLogger.AutoLoggerLogFileName)"
                    LogMessage $LogLevel.Info ("Adding `'$CommandLine`' to $BatFileName")
                    Write-Output($CommandLine) | Out-File $BatFileName -Encoding ascii -Append

                    $AutologgerKey = $TraceObject.AutoLogger.AutoLoggerKey -replace ":",""  # Convert "HKLM:" => "HKLM\"
                    $Commandline = "REG ADD $AutologgerKey /V FileMax /T REG_DWORD /D 5 /F"
                    LogMessage $LogLevel.Info ("Adding `'$CommandLine`' to $BatFileName")
                    Write-Output($CommandLine) | Out-File $BatFileName -Encoding ascii -Append
                }
            }
            'Perf' {
               ForEach($PerfCounter in $TraceObject.Providers){
                   $AllCounters += "`"" + $PerfCounter + "`""  + " "
               }
               $LogFileName = $TraceObject.LogFileName -replace "-[0-9]+-[0-9]+-[0-9]+\.[0-9]+\.[0-9]+.","."

               If($LogFolderName -eq ""){
                   $LogFileName = $LogFileName -replace ".*\Desktop","%USERPROFILE%\Desktop"
               }

               $Commandline = "logman create counter " + $TraceObject.Name + " -o `"" + $LogFileName + "`" -si $PerflogInterval -c $AllCounters"
               LogMessage $LogLevel.Info ("Adding `'$CommandLine`' to $BatFileName")
               Write-Output($CommandLine) | Out-File $BatFileName -Encoding ascii -Append

               $Commandline = "logman start $($TraceObject.Name)"
               LogMessage $LogLevel.Info ("Adding `'$CommandLine`' to $BatFileName")
               Write-Output($CommandLine) | Out-File $BatFileName -Encoding ascii -Append
            }
            'Command' {
                If(!$SetAutoLogger.IsPresent){
                    $StartOptionWithoutSuffix = $($TraceObject.Startoption) -replace "-[0-9]+-[0-9]+-[0-9]+\.[0-9]+\.[0-9]+.","."
                }Else{
                    $StartOptionWithoutSuffix = $($TraceObject.AutoLogger.AutoLoggerStartOption) -replace "-[0-9]+-[0-9]+-[0-9]+\.[0-9]+\.[0-9]+.","."
                }
                $CommandLine = "Start $($TraceObject.CommandName) $StartOptionWithoutSuffix"
                LogMessage $LogLevel.Info ("Adding `'$CommandLine`' to $BatFileName")
                Write-Output($CommandLine) | Out-File $BatFileName -Encoding ascii -Append
            }
            Default {
                LogMessage $LogLevel.Warning ("-CreateBatFile does not support command for $($TraceObject.TraceName)")
                Continue
            }
        }
    }
    EndFunc $MyInvocation.MyCommand.Name
}

Function CreateStopCommandforBatch{
    Param(
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [System.Collections.Generic.List[PSObject]]$TraceObjectList
    )
    EnterFunc $MyInvocation.MyCommand.Name

    If($SetAutoLogger.IsPresent){
        $BatFileName = $StopAutologgerBatFileName
    }Else{
        LogMessage $LogLevel.Info ("Adding `'Pause`' to $BatFileName")
        Write-Output("") | Out-File $BatFileName -Encoding ascii -Append
        Write-Output("Pause") | Out-File $BatFileName -Encoding ascii -Append
        Write-Output("") | Out-File $BatFileName -Encoding ascii -Append
    }

    ForEach($TraceObject in $TraceObjectList){
        Switch($TraceObject.LogType){
            'ETW' {
                $CommandLine = "logman stop $($TraceObject.TraceName) -ets"
                LogMessage $LogLevel.Info ("Adding `'$CommandLine`' to $BatFileName")
                Write-Output($CommandLine) | Out-File $BatFileName -Encoding ascii -Append

                If($SetAutoLogger.IsPresent){
                    $CommandLine = "logman delete $($TraceObject.AutoLogger.AutoLoggerSessionName)"
                    LogMessage $LogLevel.Info ("Adding `'$CommandLine`' to $BatFileName")
                    Write-Output($CommandLine) | Out-File $BatFileName -Encoding ascii -Append
                }
            }
            'Perf' {
                $CommandLine = "logman stop $($TraceObject.Name) & logman delete $($TraceObject.Name)"
                LogMessage $LogLevel.Info ("Adding `'$CommandLine`' to $BatFileName")
                Write-Output($CommandLine) | Out-File $BatFileName -Encoding ascii -Append
            }
            'Command' {
                If(!$SetAutoLogger.IsPresent){
                    $StopOptionWithoutSuffix = $($TraceObject.StopOption) -replace "-[0-9]+-[0-9]+-[0-9]+\.[0-9]+\.[0-9]+.","."

                }Else{
                    $StopOptionWithoutSuffix = $($TraceObject.AutoLogger.AutoLoggerStopOption) -replace "-[0-9]+-[0-9]+-[0-9]+\.[0-9]+\.[0-9]+.","."
                }
                $CommandLine = "$($TraceObject.CommandName) $StopOptionWithoutSuffix"
                LogMessage $LogLevel.Info ("Adding `'$CommandLine`' to $BatFileName")
                Write-Output($CommandLine) | Out-File $BatFileName -Encoding ascii -Append
            }
            Default {
                LogMessage $LogLevel.Warning ("-CreateBatFile does not support command for $($TraceObject.TraceName)")
                Continue
            }
        }
    }
    EndFunc $MyInvocation.MyCommand.Name
}


Function RunPreparation{
    EnterFunc $MyInvocation.MyCommand.Name

    # For -NetshScenario
    If($NetshScenario -ne $Null -and $NetshScenario -ne ''){
        $SupportedScenrios = Get-ChildItem 'HKLM:SYSTEM\CurrentControlSet\Control\NetDiagFx\Microsoft\HostDLLs\WPPTrace\HelperClasses'
        $RequestedScenarios = $NetshScenario -Split '\s+'
        $i=0
        ForEach($RequestedScenario in $RequestedScenarios){
            $fFound=$False
            ForEach($SupportedScenario in $SupportedScenrios){
                If($RequestedScenario.ToLower() -eq $SupportedScenario.PSChildName.ToLower()){
                    $fFound=$True
                    If($i -eq 0){
                        $SenarioString = $SupportedScenario.PSChildName
                    }Else{
                        $SenarioString = $SenarioString + ',' + $SupportedScenario.PSChildName
                    }
                }
            }
            If(!$fFound){
                Write-Host "ERROR: Unable to find scenario `"$RequestedScenario`" for -NetshScenario. Supported scenarios for -NetshScnario are:" -ForegroundColor Red
                ForEach($SupportedScenario in $SupportedScenrios){
                    Write-Host("  - " + $SupportedScenario.PSChildName)
                }
                CleanUpandExit
            }
            $i++
        }
        LogMessage $Loglevel.Info ("Scenario string is $SenarioString")
        $SenarioString2 = $SenarioString.Replace(",","-")
        $NetshScenarioLogFile = "$LogFolder\Netsh-$SenarioString2$LogSuffix.etl"
        $NetshProperty.LogFileName = $NetshScenarioLogFile
    
        If($NoPacket.IsPresent){
            $NetshProperty.StartOption = "trace start capture=no report=disabled scenario=$SenarioString traceFile=$NetshScenarioLogFile maxSize=$NetshLogSize"
            $NetshProperty.AutoLogger.AutoLoggerStartOption = "trace start capture=no report=disabled scenario=$SenarioString persistent=yes fileMode=circular traceFile=" + "$AutoLoggerLogFolder\Netsh-$SenarioString2-AutoLogger$LogSuffix.etl" + " maxSize=$NetshLogSize"
        }Else{
            $NetshProperty.StartOption = "trace start capture=yes report=disabled scenario=$SenarioString traceFile=$NetshScenarioLogFile maxSize=$NetshLogSize"
            $NetshProperty.AutoLogger.AutoLoggerStartOption = "trace start capture=yes report=disabled scenario=$SenarioString persistent=yes fileMode=circular traceFile=" + "$AutoLoggerLogFolder\Netsh-$SenarioString2-AutoLogger$LogSuffix.etl" + " maxSize=$NetshLogSize"
        }
        $NetshProperty.AutoLogger.AutoLoggerLogFileName = "`"$AutoLoggerLogFolder\Netsh-$SenarioString2-AutoLogger$LogSuffix.etl`""
    }
    
    # For -WPR
    If($WPR -ne $Null -and $WPR -ne ''){
        $SupportedWPRScenarios = @('general(high CPU, wait analysis, file/registry I/O)', 'network', 'graphic', 'xaml', 'simple')
        $WPRLogFile = "$LogFolder\WPR-$WPR$LogSuffix.etl"
        Switch($WPR.ToLower()) {
            'general' {
                $WPRProperty.StartOption = '-start GeneralProfile -start CPU -start DiskIO -start FileIO -Start Minifilter -Start Registry -FileMode'
                $WPRProperty.AutoLogger.AutoLoggerStartOption = "-boottrace -addboot GeneralProfile -addboot CPU -addboot DiskIO -addboot FileIO -addboot Minifilter -addboot Registry -filemode -recordtempto $AutoLoggerLogFolder"
            }
            'network' {
                $WPRProperty.StartOption = '-start GeneralProfile -start CPU -start FileIO -Start Registry -start Network -start Power -FileMode'
                $WPRProperty.AutoLogger.AutoLoggerStartOption = "-boottrace -addboot GeneralProfile -addboot CPU -addboot FileIO -addboot Registry -addboot Network -addboot Power -filemode -recordtempto $AutoLoggerLogFolder"
            }
            'graphic' {
                $WPRProperty.StartOption = '-start GeneralProfile -start CPU -Start Registry -start Video -start GPU -Start DesktopComposition -start Power -FileMode'
                $WPRProperty.AutoLogger.AutoLoggerStartOption = "-boottrace -addboot GeneralProfile -addboot CPU -addboot Registry -addboot Video -addboot GPU -addboot DesktopComposition -addboot Power -filemode -recordtempto $AutoLoggerLogFolder"
            }
            'xaml' {
                $WPRProperty.StartOption = '-start GeneralProfile -start CPU -start XAMLActivity -start XAMLAppResponsiveness -Start DesktopComposition -start Video -start GPU -FileMode'
                $WPRProperty.AutoLogger.AutoLoggerStartOption = "-boottrace -addboot GeneralProfile -addboot CPU -addboot XAMLActivity -addboot XAMLAppResponsiveness -addboot DesktopComposition -addboot Video -addboot GPU -filemode -recordtempto $AutoLoggerLogFolder"
            }
            'simple' {
                $WPRProperty.StartOption = '-start GeneralProfile -start CPU -FileMode'
                $WPRProperty.AutoLogger.AutoLoggerStartOption = "-boottrace -addboot GeneralProfile -addboot CPU -filemode -recordtempto $AutoLoggerLogFolder"
            }
            Default {
                Write-Host "ERROR: Unable to find scenario `"$WPR`" for -WPR. Supported scenarios for -WRR are:" -ForegroundColor Red
                ForEach($SupportedWPRScenario in $SupportedWPRScenarios){
                    Write-Host("  - " + $SupportedWPRScenario)
                }
                CleanUpandExit
            }
        }
        $WPRProperty.StopOption = "-stop `"$WPRLogFile`""
        $WPRProperty.LogFileName = "`"$WPRLogFile`""
    }

    <# 
    Autual process starts here:
    1. CreateETWTraceProperties creates trace properties for ETW trace automatically based on $ETWTraceList.
    2. Created trace properties are added to $GlobalPropertyList which has all properties including other traces like WRP and Netsh.
    3. Create trace objects based on $GlobalPropertyList 
    4. Created TraceObjects are added to $GlobalTraceCatalog
    5. Check argmuents and pick up TraceObjects specified in command line parameter and add them to $LogCollector(Generic.List)
    6. StartTraces() starts all traces in $LogCollector(not $GlobalTraceCatalog). 
    #>
    
    # Creating properties for ETW trace and add them to ETWPropertyList
    Try{
        LogMessage $LogLevel.Debug ('Creating properties for ETW and adding them to GlobalPropertyList.')
        If($ETWTraceList.Count -ne 0){
            CreateETWTraceProperties $ETWTraceList  # This will add created property to $script:ETWPropertyList
        }
    }Catch{
        LogException ("An exception happened in CreateETWTraceProperties.") $_
        CleanUpandExit # Trace peroperty has invalid value and this is critical. So exits here.
    }

    ForEach($RequestedTraceName in $ParameterArray){
        If($TraceSwitches.Contains($RequestedTraceName)){
            $ETWTrace = $ETWTraceList | Where-Object {$_.Name -eq $RequestedTraceName}
            If($ETWTrace -eq $Null){
                Write-Host($RequestedTraceName + ' is not registered in our trace list.') -ForegroundColor Red
                CleanUpandExit
            }
            $MergedTraceList.add($ETWTrace)
            Continue 
        }
    }

    If($MergedTraceList.Count -ne 0){
        CreateETWTraceProperties $MergedTraceList $True
    }Else{
        If($ETWTraceList.Count -ne 0){
            CreateETWTraceProperties $ETWTraceList $True
        }
    }

    # Create all properties and add them to $GlobalPropertyList
    LogMessage $LogLevel.Debug ('Adding traces and commands to GlobalPropertyList.')
    $AllProperties = $ETWPropertyList + $CommandPropertyList
    ForEach($TraceProperty in $AllProperties){
    
        If($TraceProperty.Name -eq 'Procmon'){
            $FoundProcmonPath = SearchProcmon
            If($FoundProcmonPath -ne $Null){
                $TraceProperty.CommandName = $FoundProcmonPath
            }ElseIf($Procmon.IsPresent){
                ShowProcmonErrorMessage
                CleanUpandExit
            }Else{
                $TraceProperty.CommandName = $ProcmonDefaultPath
                LogMessage $LogLevel.Debug ('INFO: Using default procmon path ' + $ProcmonDefaultPath)
            }
        }
        Try{
            LogMessage $LogLevel.Debug ('Inspecting ' + $TraceProperty.Name)
            InspectProperty $TraceProperty
        }Catch{
            LogMessage $LogLevel.Error ('An error happened druing inspecting property for ' + $TraceProperty.Name)
            LogMessage $LogLevel.Error ($_.Exception.Message)
            Write-Host('---------- Error propery ----------')
            $TraceProperty | ft
            Write-Host('-----------------------------------')
            CleanUpandExit # This is critical and exiting.
        }
        #LogMessage $LogLevel.Debug ('Adding ' + $TraceProperty.Name + ' to GlobalPropertyList.')
        $GlobalPropertyList.Add($TraceProperty) 
    }
    
    # Creating TraceObject from TraceProperty and add it to GlobalTraceCatalog.
    LogMessage $LogLevel.Debug ('Adding all properties to GlobalTraceCatalog.')
    ForEach($Property in $GlobalPropertyList){
        #LogMessage $LogLevel.Debug ('Adding ' + $TraceObject.Name + ' to GlobalTraceCatalog.')
        $TraceObject = New-Object PSObject -Property $Property
        $GlobalTraceCatalog.Add($TraceObject)
    }
    LogMessage $LogLevel.Debug ('Setting $fPreparationCompleted to true.')
    $script:fPreparationCompleted = $True
    EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessStart{
    EnterFunc $MyInvocation.MyCommand.Name
    LogMessage $LogLevel.Debug ("fPreparationCompleted is $script:fPreparationCompleted")
    If(!$script:fPreparationCompleted){
        Try{
            RunPreparation
        }Catch{
            LogMessage $LogLevel.Error ('Error happend while setting trace properties. Exiting...')
            CleanUpandExit
        }
    }

    $TraceSwitcheCount=0
    # Checking trace and command switches and add them to LogCollector.
    ForEach($RequestedTraceName in $ParameterArray){

        If($ControlSwitches.Contains($RequestedTraceName)){
            Continue # This is not switch for trace.
        }ElseIf($TraceSwitches.Contains($RequestedTraceName) -and $AsOneTrace.IsPresent){
            $TraceSwitcheCount++
            Continue # In case of -AsOneTrace, MergedTrace will be added to LogCollector later.
        }

        If($RequestedTraceName -eq 'NetshScenario'){
            $RequestedTraceName = 'Netsh' # NetshScenario uses Netsh object. So replace the name.
        }
        If($SetAutoLogger.IsPresent){
            # Only autologger supported traces are added to LogCollector
            $AllAutoLoggerSupportedTraces =  $GlobalTraceCatalog | Where-Object{$_.AutoLogger -ne $Null}
            If($AllAutoLoggerSupportedTraces -eq $Null){
                Continue
            }
            $AutoLoggerSupportedTrace = $AllAutoLoggerSupportedTraces | Where-Object{$_.Name -eq $RequestedTraceName}
            If($AutoLoggerSupportedTrace -ne $Null){ # This trace has autologger
                AddTraceToLogCollector $RequestedTraceName
            }
        }Else{
            # If not autologger, just add all traces which are specified in option.
            AddTraceToLogCollector $RequestedTraceName
        }
    }

    # In case of -AsOneTrace, no traces are added to LogCollector at this point and add it LogCollector here.
    If($TraceSwitcheCount -gt 0 -and $AsOneTrace.IsPresent){
        AddTraceToLogCollector $MergedTracePrefix
    }

    If($Procmon.IsPresent){
    $ProcmonObject = $LogCollector | Where-Object{$_.Name.ToLower() -eq 'procmon'}
        If($ProcmonObject -ne $Null){
            $Path = SearchProcmon
            If($Path -eq $Null){
                ShowProcmonErrorMessage
                CleanUpandExit
            }
        }
    }

    # Check collection
    If($LogCollector.Count -eq 0){
        Write-Host('Please specify trace name with -Start -or -SetAutoLogger...') -ForegroundColor Red
        CleanUpandExit
    }

    $fResult = ValidateCollection $LogCollector
    If(!$fResult){
        Write-Host('ERROR: Found error in LogCollector. Please check above error.') -ForegroundColor Red
        CleanUpandExit
    }

    Write-Host('Processing below traces:')
    ForEach($TraceObject in $LogCollector){
        If($SetAutoLogger.IsPresent -and $TraceObject.LogType -eq 'ETW'){
            Write-Host('    - ' + $TraceObject.AutoLogger.AutoLoggerSessionName + ' with ' + $TraceObject.Providers.Count + ' providers')
        }ElseIf($TraceObject.LogType -eq 'ETW'){     
            Write-Host('    - ' + $TraceObject.TraceName + ' with ' + $TraceObject.Providers.Count + ' providers')
        }Else{
            Write-Host('    - ' + $TraceObject.TraceName)
        }
    }
    Write-Host('')
    If($DebugMode.IsPresent){
        DumpCollection $LogCollector
    }

    If($SetAutoLogger.IsPresent){
        $Folder = $AutoLoggerLogFolder
    }Else{
        $Folder = $LogFolder
    }

    Try{
        CreateLogFolder $Folder
    }Catch{
        LogException ("Unable to create $Folder.") $_
        CleanUpandExit
    }

    ### 
    ### Finally we can start tracing here. 
    ### 
    Try{
        StartTraces
    }Catch{
        $fInRecovery = $True
        LogException ('An error happened in StartTraces') $_
        LogMessage $LogLevel.Warning ('Starting recovery process...')
        StopTraces $LogCollector
        If($SetAutoLogger.IsPresent){
            Write-Host('Deleting autologger settings if exists...')
            DeleteAutoLogger
        }
        CleanUpandExit
    }

    # -SetAutoLogger
    If($SetAutoLogger.IsPresent){
        ShowTraceResult $LogCollector 'Start' -fAutoLogger:$True
        Write-Host('The trace will be started from next boot.')
        If($ProcmonPath -ne $Null -and $ProcmonPath -ne ''){
            Write-Host("==> Run `'" + ".\$ScriptName -StopAutoLogger -ProcmonPath $ProcmonPath" + "`' to stop autologger after next boot.") -ForegroundColor Yellow
        }
        CleanUpandExit
    # -Start + -NoWait
    }ElseIf($NoWait.IsPresent){
        ShowTraceResult $LogCollector 'Start' -fAutoLogger:$False
        If($SCM.IsPresent){
            Write-Host('Restart your computer. The trace will start from next boot.')
            Write-Host("To stop SCM trace, run `'.\UXTrace.ps1 -Stop`'")
        }Else{
            Write-Host('Reproduce the issue. After that, run below command to stop traces.')
            If($LogFolderName -ne $Null -and $LogFolderName -ne ''){
                Write-Host("==> .\$ScriptName -Stop -LogFolderName $LogFolderName") -ForegroundColor Yellow
            }ElseIf($ProcmonPath -ne $Null -and $ProcmonPath -ne ''){
                Write-Host("==> .\$ScriptName -Stop -ProcmonPath $ProcmonPath") -ForegroundColor Yellow
            }Else{
                Write-Host("==> .\$ScriptName -Stop") -ForegroundColor Yellow
            }
            Write-Host('')
        }
        CleanUpandExit
    # -Start
    }Else{
        Write-Host('')
        Read-Host('Reproduce the issue and enter return key after finishing the repro')
        StopTraces $LogCollector
        ShowTraceResult $LogCollector 'Stop' -fAutoLogger:$False
        CompressLogIfNeededAndShow
        CleanUpandExit
    }
    EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessStopAutologger{
    EnterFunc $MyInvocation.MyCommand.Name
    LogMessage $LogLevel.Debug ("fPreparationCompleted is $script:fPreparationCompleted")
    If(!$script:fPreparationCompleted){
        Try{
            RunPreparation
        }Catch{
            LogMessage $LogLevel.Error ('Error happend while setting trace properties. Exiting...')
            CleanUpandExit
        }
    }
    $EnabledAutoLoggerTraces = GetEnabledAutoLoggerSession
    If($EnabledAutoLoggerTraces -eq $Null){
        Write-Host('No autologer sessions found.')
        CleanUpandExit
    }

    # Update autlogogger log path for all running trace objects. The updated path is used in StopTraces() later.
    # Also UpdateAutologgerPath updates global $CustomAutoLoggerLogFolder used in later.
    UpdateAutologgerPath $EnabledAutoLoggerTraces

    $ProcmonObject = $EnabledAutoLoggerTraces | Where-Object{$_.Name.ToLower() -eq 'procmon'}
    If($ProcmonObject -ne $Null){
        $Path = SearchProcmon
        If($Path -eq $Null){
            ShowProcmonErrorMessage
            CleanUpandExit
        }
    }

    Write-Host('Found following autologger sessions:')
    ForEach($TraceObject in $EnabledAutoLoggerTraces){
        Write-Host('    - ' + $TraceObject.AutoLogger.AutoLoggerSessionName)
    }

    # Create MSLOG folder on destkop if autologger path is default.
    If([string]::IsNullOrEmpty($CustomAutoLoggerLogFolder)){
        CreateLogFolder $LogFolder
    }Else{
        # Update global logfolder path to let CompressLogIfNeededAndShow() compress the autologger folder.
        LogMessage $LogLevel.Debug ("Updating Logfolder to $CustomAutoLoggerLogFolder")
        $Script:LogFolder = $CustomAutoLoggerLogFolder
    }

    Try{
        StopTraces $EnabledAutoLoggerTraces
        DeleteAutoLogger
    }Catch{
        LogException ("An error happened in DeleteAutoLogger") $_
    }

    # This the case where -SetAutologger is performed but -stopautologger is run 
    # without restart system. In this case, we don't show any result and simply exit.
    If($StoppedTraceList.Count -eq 0){
        CleanUpandExit
    }

    ShowTraceResult $EnabledAutoLoggerTraces 'Stop' $True

    # If autologger log folder is not default, will use the customized path and not move to $LogFolder.
    If([string]::IsNullOrEmpty($CustomAutoLoggerLogFolder)){ 
        If(Test-Path -Path $AutoLoggerLogFolder){
            $FolderName = "$LogFolder\AutoLogger$LogSuffix"
            Try{
                Stop-Transcript -ErrorAction SilentlyContinue
                LogMessage $Loglevel.info ("Copying $AutoLoggerLogFolder to $FolderName") "Cyan"
                CreateLogFolder $FolderName
                Move-Item  "$AutoLoggerLogFolder\stdout-*.txt" $LogFolder
                Move-Item  "$AutoLoggerLogFolder\*" $FolderName
                Remove-Item $AutoLoggerLogFolder -ErrorAction SilentlyContinue
            }Catch{
                Write-Host("ERROR: Creating folder $FolderName") -ForegroundColor Red
                Write-Host("Logs for autologger will not be copied and collect logs in $AutoLoggerLogFolder manually.") 
            }
        }
    }Else{
        # Update global logfolder path to let CompressLogIfNeededAndShow() compress the autologger folder.
        LogMessage $LogLevel.Debug ("Updating Logfolder to $CustomAutoLoggerLogFolder")
        $Script:LogFolder = $CustomAutoLoggerLogFolder
        LogMessage $Loglevel.info ("Moving script log(stdout/sdterr) to $Script:LogFolder from $AutoLoggerLogFolder") "Cyan"
        Try{
            Stop-Transcript -ErrorAction SilentlyContinue
            Move-Item "$AutoLoggerLogFolder\stdout-*.txt" $Script:LogFolder -ErrorAction SilentlyContinue
            Remove-Item $AutoLoggerLogFolder -ErrorAction SilentlyContinue
        }Catch{
        }
    }
    CompressLogIfNeededAndShow
    EndFunc $MyInvocation.MyCommand.Name
}

Function UpdateAutologgerPath{
    Param(
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [System.Collections.Generic.List[PSObject]]$TraceObjectList
    )
    EnterFunc $MyInvocation.MyCommand.Name
    
    ForEach($TraceObject in $TraceObjectList){
        LogMessage $LogLevel.Debug ($MyInvocation.MyCommand.Name + ": Updating autologer log path for " + $TraceObject.Name)

        # This object does not support Autologger. So skip it.
        If($TraceObject.Autologger -eq $Null){
            continue
        }

        Try{
            $RegValue = Get-ItemProperty -Path $TraceObject.Autologger.AutoLoggerKey
        }Catch{
            LogMessage $LogLevel.Warning ($MyInvocation.MyCommand.Name + ": Unable to get AutoLoggerKey for " + $TraceObject.Name)
            continue
        }

        # Fix up log path for autologger
        If($RegValue.FileName -ne $Null -and $RegValue.FileName -ne ""){
            LogMessage $LogLevel.Debug ($MyInvocation.MyCommand.Name + ": Updating  AutoLoggerLogFileName to " + $RegValue.FileName)
            If($TraceObject.Name -eq 'WPR'){
                $BoottraceFile = Split-Path $TraceObject.Autologger.AutoLoggerLogFileName -Leaf
                $BoottraceDir = Split-Path $RegValue.FileName -Parent
                $TraceObject.Autologger.AutoLoggerLogFileName = join-path $BoottraceDir $BoottraceFile
            }Else{
                $TraceObject.Autologger.AutoLoggerLogFileName = $RegValue.FileName
            }
        }Else{
            If($TraceObject.Name -ne "Procmon"){ # Procmon always does not have 'FileName' so suppress the message
               LogMessage $LogLevel.Warning ($MyInvocation.MyCommand.Name + ": AutologgerKey for " + $TraceObject.Name + " exists but `'FileName`' does not.")
            }
            continue
        }

        # Fix up start and stop option for autologger
        $AutloggerPath = Split-Path $TraceObject.Autologger.AutoLoggerLogFileName -Parent
        If($TraceObject.Name -eq 'WPR'){
            $TraceObject.Autologger.AutoLoggerStartOption = $TraceObject.Autologger.AutoLoggerStartOption -replace "-recordtempto .*","-recordtempto `"$AutloggerPath`""
            $TraceObject.Autologger.AutoLoggerStopOption = $TraceObject.Autologger.AutoLoggerStopOption -replace "-stopboot .*",("-stopboot `"" + $TraceObject.Autologger.AutoLoggerLogFileName +"`"")
            LogMessage $LogLevel.Debug ($MyInvocation.MyCommand.Name + ": " + $TraceObject.Name + " was updated ")
        }

        If($TraceObject.Name -eq 'Netsh'){
            $TraceObject.Autologger.AutoLoggerStartOption = $TraceObject.Autologger.AutoLoggerStartOption -replace "traceFile=.*etl`"",("traceFile=`"" + $TraceObject.Autologger.AutoLoggerLogFileName +"`"")
            LogMessage $LogLevel.Debug ($MyInvocation.MyCommand.Name + ": " + $TraceObject.Name + " was updated ")
        }
    }

    # lastly, we update stop option for procmon as we don't have any way to know the path from procmon object. So use $AutloggerPath which is autologger path for last object in above ForEach. This is best effort handing.
    $ProcmonObject = $TraceObjectList | Where-Object{$_.Name.ToLower() -eq 'procmon'}
    If($ProcmonObject -ne $Null -and ($AutloggerPath -ne $Null -and $AutloggerPath -ne "")){
        $BootloggingFile = Split-Path $ProcmonObject.Autologger.AutoLoggerLogFileName -Leaf
        $ProcmonObject.Autologger.AutoLoggerLogFileName = "$AutloggerPath\$BootloggingFile"
        $ProcmonObject.Autologger.AutoLoggerStopOption = $ProcmonObject.Autologger.AutoLoggerStopOption -replace "/ConvertBootLog .*",("/ConvertBootLog `"" + $ProcmonObject.Autologger.AutoLoggerLogFileName +"`"")
        LogMessage $LogLevel.Debug ($MyInvocation.MyCommand.Name + ": Procomn path was updated to " + (join-path $AutloggerPath $BootloggingFile))
    }

    # Compare obtained autologger path to default path then if it is not same, we assume default autogger path was changed use the custom path.
    If(!($AutloggerPath -eq $AutoLoggerLogFolder)){
        LogMessage $LogLevel.Debug ($MyInvocation.MyCommand.Name + ": Updating global CustomAutoLoggerLogFolder to $AutloggerPath")
        $Script:CustomAutoLoggerLogFolder = $AutloggerPath # This is used in ProcessStopAutologger.
    }

    EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessStop{
    EnterFunc $MyInvocation.MyCommand.Name
    LogMessage $LogLevel.Debug ("fPreparationCompleted is $script:fPreparationCompleted")
    If(!$script:fPreparationCompleted){
        Try{
            RunPreparation
        }Catch{
            LogMessage $LogLevel.Error ('Error happend while setting trace properties. Exiting...')
            CleanUpandExit
        }
    }

    $EnabledAutoLoggerSessions = GetEnabledAutoLoggerSession  # This updates $fAutoLoggerExist and $GlobalTraceCatalog
    If($EnabledAutoLoggerSessions -ne $Null){
        Write-Host('The following existing autologger session was found:')
        ForEach($TraceObject in $EnabledAutoLoggerSessions){
            Write-Host('    - ' + $TraceObject.AutoLogger.AutoLoggerSessionName)
        }
        Write-Host('')
        Write-Host('You can disable and stop autologger with below command:')
        Write-Host("PS> .\$ScriptName -StopAutoLogger") -ForegroundColor Yellow
        Write-Host('')
        CleanUpandExit
    }

    $RunningTraces = GetExistingTraceSession
    If($RunningTraces -eq $Null){
        Write-Host('No traces are running.')
        CleanUpandExit
    }
    $ProcmonObject = $RunningTraces | Where-Object{$_.Name.ToLower() -eq 'procmon'}
    If($ProcmonObject -ne $Null){
        $Path = SearchProcmon
        If($Path -eq $Null){
            ShowProcmonErrorMessage
            CleanUpandExit
        }
    }

    Try{
        CreateLogFolder $LogFolder
    }Catch{
        Write-Host("Unable to create $Logfolder." + $_.Exception.Message)
        CleanUpandExit
    }

    Try{
        StopTraces $RunningTraces
    }Catch{
        Write-Host('ERROR: An exception happened during stopping traces: ' + $_.Exception.Message)
    }
    ShowTraceResult $RunningTraces 'Stop' $False
    CompressLogIfNeededAndShow
    EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessSet{
    EnterFunc $MyInvocation.MyCommand.Name
    LogMessage $Loglevel.debug ("-Set is specifid with $Set")

    # Check if set function corresponding to the option exists or not
    If(!$SupportedSetOptions.Contains($Set)){
        Write-Host('ERROR: -Set ' + $Set + ' is invalid.') -ForegroundColor Red
        Write-Host('Supported options are:')
        ForEach($Key in $SupportedSetOptions.Keys){
            Write-Host('    o .\UXTrace.ps1 -Set ' + $Key + '   /// ' + $SupportedSetOptions[$Key])
        }
        CleanUpandExit
    }

    Try{
        $SetFuncName = "RunSet" + $Set
        Get-Command $SetFuncName -ErrorAction Stop | Out-Null
    }Catch{
        Write-Host('ERROR: -Set ' + $Set + ' is invalid option. Possible option is:')
        CleanUpandExit
    }
    # Run set function
    LogMessage $Loglevel.debug ("Calling $SetFuncName")
    & $SetFuncName
    EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessUnset{
    EnterFunc $MyInvocation.MyCommand.Name
    LogMessage $Loglevel.debug ("-Unset is specifid with $Unset")

    # Check if set function corresponding to the option exists or not
    If(!$SupportedSetOptions.Contains($Unset)){
        Write-Host('ERROR: -Unset ' + $Unset + ' is invalid.') -ForegroundColor Red
        Write-Host('Supported options are:')
        ForEach($Key in $SupportedSetOptions.Keys){
            Write-Host('    o .\UXTrace.ps1 -Unset ' + $Key)
        }
        CleanUpandExit
    }

    Try{
        $UnsetFuncName = "RunUnset" + $Unset
        Get-Command $UnsetFuncName -ErrorAction Stop | Out-Null
    }Catch{
        Write-Host("ERROR: Unable to find a function for unsetting `'$Unset`'($UnsetFuncName)")
        CleanUpandExit
    }
    # Run set function
    LogMessage $Loglevel.debug ("Calling $UnsetFuncName")
    & $UnsetFuncName
    EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessStatus{
    EnterFunc $MyInvocation.MyCommand.Name
    LogMessage $LogLevel.Debug ("fPreparationCompleted is $script:fPreparationCompleted")
    If(!$script:fPreparationCompleted){
        Try{
            RunPreparation
        }Catch{
            LogMessage $LogLevel.Error ('Error happend while setting trace properties. Exiting...')
            CleanUpandExit
        }
    }

    LogMessage $LogLevel.Info ("Checking running traces.")
    $RunningTraces = GetExistingTraceSession

    # Checking running ETW traces and WPR/Procmon/Netsh/Perf. 
    Write-Host('Running ETW trace session:')
    If($RunningTraces -ne $Null -or $RunningTraces.Count -gt 0){
        Write-Host('Below traces are currently running:')
        ForEach($TraceObject in $RunningTraces){
            If($TraceObject.LogType -eq 'ETW' -and $TraceObject.Name -ne $MergedTracePrefix){
                Write-Host('    - ' + $TraceObject.TraceName + ' with ' + $TraceObject.Providers.Count + ' providers')
            }Else{
                Write-Host('    - ' + $TraceObject.TraceName)
            }
        }
    }Else{
        Write-Host("    There is no running session.")
    }
    Write-Host('')

    # Checking if autologger is enabled or not.
    Write-Host('Autologger session enabled:')
    $EnabledAutoLoggerTraces = GetEnabledAutoLoggerSession # This updates $TraceObject.AutoLogger.AutoLoggerEnabled

    If($EnabledAutoLoggerTraces -ne $Null){
        UpdateAutologgerPath $EnabledAutoLoggerTraces
    }

    $AutoLoggerCount=0
    ForEach($TraceObject in $EnabledAutoLoggerTraces){
        Write-Host('    - ' + $TraceObject.AutoLogger.AutoLoggerSessionName)
        $AutoLoggerCount++
        If($DebugMode.IsPresent){
            DumpCollection $TraceObject
        }
    }

    If($AutoLoggerCount -eq 0){
        Write-Host('    There is no autologger session enabled.')
    }Else{
        Write-Host('Found ' + $AutoLoggerCount.ToString() + ' autologger session(s).')
    }
    Write-Host('')
    EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessCreateBatFile{
    EnterFunc $MyInvocation.MyCommand.Name

    LogMessage $LogLevel.Debug ("fPreparationCompleted is $script:fPreparationCompleted")
    If(!$script:fPreparationCompleted){
        Try{
            RunPreparation
        }Catch{
            LogMessage $LogLevel.Error ('Error happend while setting trace properties. Exiting...')
            CleanUpandExit
        }
    }

    $TraceSwitcheCount=0
    # Checking trace and command switches and add them to LogCollector.
    ForEach($RequestedTraceName in $ParameterArray){
    
        If($ControlSwitches.Contains($RequestedTraceName)){
            Continue # This is not switch for trace.
        }ElseIf($TraceSwitches.Contains($RequestedTraceName) -and $AsOneTrace.IsPresent){
            $TraceSwitcheCount++
            Continue # In case of -AsOneTrace, MergedTrace will be added to LogCollector later.
        }
    
        If($RequestedTraceName -eq 'NetshScenario'){
            $RequestedTraceName = 'Netsh' # NetshScenario uses Netsh object. So replace the name.
        }
        If($SetAutoLogger.IsPresent){
            # Only autologger supported traces are added to LogCollector
            $AllAutoLoggerSupportedTraces =  $GlobalTraceCatalog | Where-Object{$_.AutoLogger -ne $Null}
            If($AllAutoLoggerSupportedTraces -eq $Null){
                Continue
            }
            $AutoLoggerSupportedTrace = $AllAutoLoggerSupportedTraces | Where-Object{$_.Name -eq $RequestedTraceName}
            If($AutoLoggerSupportedTrace -ne $Null){ # This trace has autologger
                AddTraceToLogCollector $RequestedTraceName
            }
        }Else{
            # If not autologger, just add all traces which are specified in option.
            AddTraceToLogCollector $RequestedTraceName
        }
    }
    
    # In case of -AsOneTrace, no traces are added to LogCollector at this point and add it LogCollector here.
    If($TraceSwitcheCount -gt 0 -and $AsOneTrace.IsPresent){
        AddTraceToLogCollector $MergedTracePrefix
    }
    
    If($Procmon.IsPresent){
    $ProcmonObject = $LogCollector | Where-Object{$_.Name.ToLower() -eq 'procmon'}
        If($ProcmonObject -ne $Null){
            $Path = SearchProcmon
            If($Path -eq $Null){
                ShowProcmonErrorMessage
                CleanUpandExit
            }
        }
    }
    
    # Check collection
    If($LogCollector.Count -eq 0){
        LogMessage $LogLevel.Error ('LogCollector is null.')
        CleanUpandExit
    }

    CreateStartCommandforBatch $LogCollector
    CreateStopCommandforBatch $LogCollector
    LogMessage $LogLevel.Info ("Batch file was created on $BatFileName.")
    If(!$SetAutoLogger.IsPresent){
        Explorer.exe $LogFolder
    }Else{
        Explorer.exe $AutoLoggerLogFolder
    }
    EndFunc $MyInvocation.MyCommand.Name
}


<#------------------------------------------------------------------
                                MAIN 
------------------------------------------------------------------#>
# CHECK 1:
# First thing we need to check is 'Constrained Language Mode' as this prevents most .net types from being accessed and it is very critical for this scirpt.
# https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/
$ConstrainedLanguageMode = $ExecutionContext.SessionState.LanguageMode
$LockdownPolicy = $Env:__PSLockdownPolicy
If($ConstrainedLanguageMode -ne 'FullLanguage'){
    If($LockdownPolicy -eq $Null){
        $fIsLockdownByEnvironmentVariable = $False
    }Else{
        $fIsLockdownByEnvironmentVariable = $True
    }

    Write-Host("Current constrained language mode is `'" + $ConstrainedLanguageMode + "`' but this script must be run with `'FullLanguage`' mode.") -ForegroundColor Red
    Write-Host('Please ask administrator why $ExecutionContext.SessionState.LanguageMode is set to ' + $ConstrainedLanguageMode + '.') -ForegroundColor Red
    Write-Host("")
    If($fIsLockdownByEnvironmentVariable){
        Write-Host("To fix this issue, remove `'__PSLockdownPolicy`' environment valuable.")
        Write-Host("")
    }
    CleanUpandExit
}

# CHECK 2:
# Disabling quick edit mode as somethimes this causes the script to stop working until enter key is pressed.
If($fQuickEditCodeExist){
    [DisableConsoleQuickEdit]::SetQuickEdit($True) | Out-Null
}

# CHECK 3:
# Version check
$Version = [environment]::OSVersion.Version
If(($Version.Major -lt 10) -and !($Version.Major -eq 6 -and $Version.Build -eq 9600)){
    Write-Host('This script supported from Windows 8.1 or Windows Server 2012 R2') -ForegroundColor Red
    Write-Host('')
    CleanUpandExit
}

# CHECK 4:
# Admin check
# This script needs to be run with administrative privilege except for -Collectlog.
If($CollectLog -eq $Null){
    If(!(Is-Elevated)){
        Write-Host('This script needs to run from elevated command/powershell prompt.') -ForegroundColor Red
        CleanUpandExit
    }
}

# CHECK 5:
# Parameter compatibility check
Try{
    CheckParameterCompatibility
}Catch{
    Write-Host('Detected parameter compatibility error. Exiting...')
    CleanUpandExit
}

###
### Variables
###
# Collor setting
Try{
    $Host.privatedata.ProgressBackgroundColor = 'Black'
    $Host.privatedata.ProgressForegroundColor = 'Cyan'
}Catch{
    # Do nothing
}

# Globals
$ScriptName = $MyInvocation.MyCommand.Name
$f64bitOS = [System.Environment]::Is64BitOperatingSystem
$fInRecovery = $False
$fPreparationCompleted = $False
$LogSuffix = "-$(Get-Date -f yyyy-MM-dd.HHmm.ss)"
$LogFolder = "$env:userprofile\desktop\MSLOG"
If($LogFolderName -ne "" -and $LogFolderName -ne $Null){
    $LogFolder = $LogFolderName
}Else{
    # What we are doing here is that when the script is run from non administrative user 
    # and PowerShell prompt is launched with 'Run as Administrator', profile path of the administrator
    # is obtained. But desktop path used for log path must be under current user's desktop path.
    # So we will check explorer's owner user to know the actual user name and build log folder path using it.
    Try{
        $CurrentSessionID = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
        $Owner = (Get-WmiObject -Class Win32_Process -Filter "Name=`"explorer.exe`" AND SessionId=$CurrentSessionID" -ErrorAction Stop).GetOwner()
    }Catch{
        Write-Host "WARNING: Unable to retrieve Win32_Process object." -ForegroundColor Magenta
    }
    If($Owner -eq $Null){
        $LogonUser = ""
        $UserDomain = ""
    }ElseIf($Owner.Count -eq $Null){
        $LogonUser = $Owner.User
        $UserDomain = $Owner.Domain
    }Else{
        $LogonUser = $Owner[0].User
        $UserDomain = $Owner[0].Domain
    }

    # There are two possible desktop paths
    $DesktopPath = "C:\users\$LogonUser\Desktop"
    $DesktopPath2 = "C:\users\$LogonUser.$UserDomain\Desktop"

    If(Test-Path -Path $DesktopPath2){ # like C:\Users\ryhayash.FAREAST\desktop
        $tmpLogFolder = "$DesktopPath2\MSLOG"
    }ElseIf(Test-Path -Path $DesktopPath){ 
        $tmpLogFolder = "$DesktopPath\MSLOG"
    }Else{
        $tmpLogFolder = "C:\temp\MSLOG"
    }

    $LogFolder = $tmpLogFolder
}
Write-Debug "Setting log folder to $LogFolder"

# Log files
$SdtoutLogFile = "$LogFolder\stdout.txt"
$ErrorLogFile = "$LogFolder\stderr.txt"

# Autologger
$AutoLoggerLogFolder = 'C:\temp\MSLOG'
$CustomAutoLoggerLogFolder = ""
If(($AutoLoggerFolderName -ne "" -and $AutoLoggerFolderName -ne $Null)){
    $AutoLoggerLogFolder = $AutoLoggerFolderName
    $CustomAutoLoggerLogFolder = $AutoLoggerFolderName
    $SdtoutLogFile = "$AutoLoggerFolderName\stdout-setautologger.txt"
    $ErrorLogFile = "$AutoLoggerFolderName\stderr-setautologger.txt"
}ElseIf($StopAutoLogger.IsPresent){
    $SdtoutLogFile = "$AutoLoggerLogFolder\stdout-stopautologger.txt"
    $ErrorLogFile = "$AutoLoggerLogFolder\stderr-stopautologger.txt"
}ElseIf($SetAutologger.IsPresent){
    $SdtoutLogFile = "$AutoLoggerLogFolder\stdout-setautologger.txt"
    $ErrorLogFile = "$AutoLoggerLogFolder\stderr-setautologger.txt"
}

$AutoLoggerPrefix = 'autosession\'
$AutoLoggerBaseKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\'
$fAutoLoggerExist = $False


# Batch file
$BatFileName = "$LogFolder\UXTrace.cmd"
$SetAutologgerBatFileName = "$AutoLoggerLogFolder\SetAutologger.cmd"
$StopAutologgerBatFileName = "$AutoLoggerLogFolder\StopAutologger.cmd"

# ETW
$MAXLogSize = 2048  # Max log size for each trace(logman) and packet capture => 2 GB by default
$MergedTracePrefix = 'UX'

# TTD
$TTTracerPath = "" # This will be set later.
$fOnlyTTDService = $False

# Read-only valuables
Set-Variable -Name 'fLogFileOnly' -Value $True -Option readonly

# Collections
$ETWPropertyList = New-Object 'System.Collections.Generic.List[Object]'
$CommandPropertyList = New-Object 'System.Collections.Generic.List[Object]'
$GlobalPropertyList = New-Object 'System.Collections.Generic.List[Object]'
$GlobalTraceCatalog = New-Object 'System.Collections.Generic.List[Object]'
$LogCollector = New-Object 'System.Collections.Generic.List[Object]'
$ETWTraceList = New-Object 'System.Collections.Generic.List[Object]'
$MergedTraceList = New-Object 'System.Collections.Generic.List[Object]'
$StoppedTraceList = New-Object 'System.Collections.Generic.List[Object]'
$RequestedTraceList = New-Object 'System.Collections.Generic.List[Object]'

### Start logging
# Closing existing session just in case and then start logging.
Try{
    Stop-Transcript -ErrorAction SilentlyContinue
}Catch{
    # Do nothing
}
# We won't start logging if one of -Status/-List/-ListSupportedLog/-ListSupportedNetshScenario/-DeleteAutologger/-Help is enabled.
If(!$Status.IsPresent -and !$List.IsPresent -and !$ListSupportedLog.IsPresent -and !$ListSupportedNetshScenario.IsPresent -and !$DeleteAutoLogger.IsPresent -and !$Help.IsPresent){
    Start-Transcript -Append -Path $SdtoutLogFile
}

### STEP 1: Get parameters
$ParameterArray = @()
ForEach($Key in $MyInvocation.BoundParameters.Keys){
    $ParameterArray += $Key
}

ForEach($RequestedTraceName in $ParameterArray){
    If($TraceSwitches.Contains($RequestedTraceName)){
        $RequestedTraceList.Add($RequestedTraceName)
    }
}

###
### STEP 2: Build trace list
###
If(!$Start.IsPresent){
    # In case of not -Start, we add all traces to trace list to know what traces are currently running.
    $RequestedTraceList = $TraceSwitches.Keys
}

ForEach($Trace in $TraceSwitches.Keys){
    $TraceName = $Trace
    $ProviderName = $TraceName + "Providers"
    $PreStartFunc = $TraceName + "PreStart"
    $PostStartFunc = $TraceName + "PostStop"

    LogMessage $LogLevel.Debug ("Starting building trace property for $TraceName")
    Try{
        $ProviderGUIDs = Get-Variable -Name $ProviderName -ErrorAction Stop
    }Catch{
        Continue # This is a case for swith that does not have trace provider but has log function
    }

    $Trace = @{
        Name = $TraceName
        Provider = $ProviderGUIDs.Value
        PreStartFunc = $PreStartFunc
        PostStopFunc = $PostStartFunc
    }
    LogMessage $LogLevel.Debug ('Adding ' + $TraceName + ' to ETWTraceList')
    $ETWTraceList.Add($Trace)
}

###
### STEP 3: Build properties for command switch 
###

# WPR
$WPRLogFile = "$LogFolder\WPR$LogSuffix.etl"
$WPRBoottraceSupprotedVersion = @{OS=10;Build=15063} # Boottrace is supported from RS2

$WPRProperty = @{
    Name = 'WPR'
    TraceName = 'WPR'
    LogType = 'Command'
    CommandName = 'wpr.exe'
    Providers = $Null
    LogFileName = "`"$WPRLogFile`""
    StartOption = '-start GeneralProfile -start CPU -start DiskIO -start FileIO -Start Registry -FileMode'
    StopOption = "-stop $WPRLogFile"
    PreStartFunc = $Null
    PostStopFunc = $Null
    AutoLogger = @{
        AutoLoggerEnabled = $Null
        AutoLoggerLogFileName = "$AutoLoggerLogFolder\WPR-boottrace$LogSuffix.etl"
        AutoLoggerSessionName = 'WPR(boottrace)'
        AutoLoggerStartOption = "-boottrace -addboot GeneralProfile -addboot CPU -addboot FileIO -addboot DiskIO -addboot Registry -filemode -recordtempto $AutoLoggerLogFolder"
        AutoLoggerStopOption = "-boottrace -stopboot `"$AutoLoggerLogFolder\WPR-boottrace$LogSuffix.etl`""
        AutoLoggerKey = "$AutoLoggerBaseKey" + "WPR_initiated_WprApp_boottr_WPR Event Collector"
    }
    Wait = $True
    SupprotedOSVersion = @{OS=10;Build=10240}
    Status = $TraceStatus.Success
}

# Netsh(Packet capturing)
$NetshLogSize = 2048
$NetshLogFile = "$LogFolder\Netsh$LogSuffix.etl"
$NetshProperty = @{
    Name = 'Netsh'
    TraceName = 'Netsh'
    LogType = 'Command'
    CommandName = 'netsh.exe'
    Providers = $Null
    LogFileName = "`"$NetshLogFile`""
    StartOption = "trace start capture=yes report=disabled fileMode=circular traceFile=`"$NetshLogFile`" maxSize=$NetshLogSize"
    StopOption = 'trace stop'
    PreStartFunc = $Null
    PostStopFunc = $Null
    AutoLogger = @{
        AutoLoggerEnabled = $Null
        AutoLoggerLogFileName = "$AutoLoggerLogFolder\Netsh-AutoLogger$LogSuffix.etl"
        AutoLoggerSessionName = 'Netsh(persistent=yes)'
        AutoLoggerStartOption = 'trace start capture=yes report=disabled persistent=yes fileMode=circular traceFile=' + "`"$AutoLoggerLogFolder\Netsh-AutoLogger$LogSuffix.etl`"" + " maxSize=$NetshLogSize"
        AutoLoggerStopOption = 'trace stop'
        AutoLoggerKey = "$AutoLoggerBaseKey" + "-NetTrace-$env:UserDomain-$env:username"
    }
    Wait = $True
    SupprotedOSVersion = $Null
    Status = $TraceStatus.Success
}

If($Version.Major -eq 6 -and $Version.Build -eq 9600){
    $NetshProperty.AutoLogger.AutoLoggerKey = "$AutoLoggerBaseKey\NetTrace-$env:UserDomain-$env:username"
}

# Procmon
$ProcmonLogFile = "$LogFolder\Procmon$LogSuffix.pml"
$ProcmonDefaultPath = "$env:userprofile\desktop\procmon.exe" # By default we use procmon on desktop. If not exist, will be searched later. 
$fDonotDeleteProcmonReg = $False
$ProcmonProperty = @{
    Name = 'Procmon'
    TraceName = 'Procmon'
    LogType = 'Command'
    CommandName = $Null  # exe path will be filled later as we need to search it.
    Providers = $Null
    LogFileName = "`"$ProcmonLogFile`""
    StartOption = "/accepteula /quiet /backingfile `"$ProcmonLogFile`""
    StopOption = '/accepteula /Terminate'
    PreStartFunc = $Null
    PostStopFunc = 'ResetProcmonSetting'
    AutoLogger = @{
        AutoLoggerEnabled = $Null
        AutoLoggerLogFileName = "$AutoLoggerLogFolder\Procmon-bootlogging.pml"
        AutoLoggerSessionName = 'Procmon(Bootlogging)'
        AutoLoggerStartOption = '/accepteula /EnableBootLogging'
        AutoLoggerStopOption = "/accepteula /ConvertBootLog `"$AutoLoggerLogFolder\Procmon-bootlogging.pml`""
        AutoLoggerKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\PROCMON24'
    }
    Wait = $False
    SupprotedOSVersion = $Null
    Status = $TraceStatus.Success
}

# PSR
$PSRProperty = @{
    Name = 'PSR'
    TraceName = 'PSR(Problem Steps Recorder)'
    LogType = 'Command'
    CommandName = 'psr.exe'
    Providers = $Null
    LogFileName = "`"$LogFolder\PSR$LogSuffix.zip`""
    StartOption = "/start /output `"$LogFolder\PSR$LogSuffix.zip`" /maxsc 100"
    StopOption = '/stop'
    PreStartFunc = $Null
    PostStopFunc = $Null
    AutoLogger = $Null
    Wait = $False
    SupprotedOSVersion = $Null
    Status = $TraceStatus.Success
}

# Performance log
$PerflogInterval = 10 # default 10 seconds
If($PerfInterval -ne 0){
    $PerflogInterval = $PerfInterval
}

$PerfProperty = @{
    Name = 'Perf'
    TraceName = 'Performance log'
    LogType = 'Perf'
    CommandName = $Null
    Providers = @(
       # '\Remote Desktop Database Counterset(*)\*'
       # '\リモート デスクトップ接続ブローカー カウンターセット(*)\*'
       # '\リモート デスクトップ接続ブローカー リダイレクター カウンターセット(*)\*'
       # '\Terminal Services(*)\*'
        '\Process(*)\*'
        '\Processor(*)\*'
        '\Processor information(*)\*'
        '\memory(*)\*'
        '\System(*)\*'
        '\PhysicalDisk(*)\*'
        '\LogicalDisk(*)\*'
    )
    LogFileName = "$LogFolder\PerfLog$LogSuffix.blg"
    StartOption = $Null
    StopOption = $Null
    PreStartFunc = $Null
    PostStopFunc = $Null
    AutoLogger = $Null
    Wait = $True
    SupprotedOSVersion = $Null
    Status = $TraceStatus.Success
}

# SCM trace
$SCMProperty = @{
    Name = 'SCM'
    TraceName = 'SCM trace'
    LogType = 'Custom'
    CommandName = $Null
    Providers = $Null
    LogFileName = $Null
    StartOption = $Null
    StopOption = $Null
    PreStartFunc = $Null
    StartFunc = 'StartSCM'
    StopFunc = 'StopSCM'
    PostStopFunc = $Null
    DetectionFunc = 'DetectSCMTrace'
    AutoLogger = $Null
    Wait = $True
    SupprotedOSVersion = $Null
    Status = $TraceStatus.Success
}

# TTD trace
$TTDProperty = @{
    Name = 'TTD'
    TraceName = 'TTD trace'
    LogType = 'Custom'
    CommandName = $Null
    Providers = $Null
    LogFileName = $Null
    StartOption = $Null
    StopOption = $Null
    PreStartFunc = $Null
    StartFunc = 'StartTTD'
    StopFunc = 'StopTTD'
    PostStopFunc = $Null
    DetectionFunc = 'DetectTTD'
    AutoLogger = $Null
    Wait = $True
    SupprotedOSVersion = $Null # @{OS=10;Build=17763} # From RS5. Now we support internal TTD and removed version restriction
    Status = $TraceStatus.Success
}

$CommandPropertyList = @(
    $ProcmonProperty
    $WPRProperty
    $PerfProperty
    $NetshProperty
    $PSRProperty
    $SCMProperty
    $TTDProperty
)


Switch($ParameterArray[0].toLower()){
    'start'{
        If($CreateBatFile.IsPresent){
            ProcessCreateBatFile
            CleanUpandExit
        }
        ProcessStart
    }
    'SetAutoLogger'{
        If($CreateBatFile.IsPresent){
            ProcessCreateBatFile
            CleanUpandExit
        }
        ProcessStart
    }
    'stop'{
        ProcessStop
    }
    'stopautologger'{
        ProcessStopAutologger
    }
    'deleteautologger'{
        DeleteAutoLogger
    }
    'set'{
        ProcessSet
    }
    'unset'{
        ProcessUnset
    }
    'help'{
        Get-Help $MyInvocation.InvocationName
    }
    'status'{
        ProcessStatus
    }
    'collectlog'{
        ProcessCollectLog
    }
    'list'{
        ProcessList
    }
    'listsupportedlog'{
        ProcessListSupportedLog
    }
    'listsupportednetshscenario'{
        ShowSupportedNetshScenario
    }
    'default'{
        Write-Host("Unknown option `'" + $ParameterArray[0] +"`' was specifed.")
    }
}

CleanUpandExit