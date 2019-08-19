# TSS
TSS Windows CMD based universal TroubleShooting Script toolset v`2019.08.19.0`

## Difference TSS and TSS ttt toolset
If you don't need TTT/TTD/iDNA tracing, please download the smaller zip **tss_tools.zip**. (just click on the .zip file and then on **[Download]**) 

If you need the package including the TTT/TTD/iDNA tracing, please download the bigger zip **tss_tools_ttt.zip** in TTD subfolder.

### 1.	Quick Overview of Troubleshooting script tss.cmd
Purpose: Multi-purpose Troubleshooting tool to simplify just-in-time rapid data collection for standard and sporadic issues in in complex environments - or is to be considered as a convenient method for submitting and following quick&easy action plans.
Copy the relevant _tss_tools.zip_ file and expand it to local disk, i.e. into _C:\tools_ folder.

Please start the script in the C:\tools folder in **elevated CMD window**.
For help, just run: `TSS`

` C:\tools>  tss [parameter list] `

Please invoke the tss command with necessary/appropriate parameters from here.

If troubleshooting intermittent/long-term issues, please invoke the script and stop it later in elevated CMD with same Admin User account (because parameters are stored in user’s registry hive `[HKCU\Software\Microsoft\tss.cmd-state\*]` )

•	Tss.cmd is built on t.cmd and fully down-level compatible (accepts same parameters as t.cmd), and provides a '`Persistent`' switch to capture debug ETL, network sniff, WPR and ProcMon data at boot time. (Example: `tss.cmd CliOn Trace ProcMon Persistent`)

•	For overview of possible command switches, run tss.cmd without any parameter; for full help, run ‘`tss /help`’

•	The tss*.zip file contains additional binaries (*.exe, *.dll) and helper.cmd scripts needed for correct usage of some parameters, like WPR tracing, Procmon tracing, or purging older trace files.

•	You can use *On paramaters [cliOn][srvOn][rOn] individually or in combination, but at least one of cliOn, srvOn, rOn must be specified. 

•	In typical reproduction scenarios you would start tracing, reproduce the problem, then stop tracing, Example:

o	Start tracing: `Tss rOn Trace Procmon Video`

o	..Now reproduce problem scenario

o	Stop tracing: `Tss off`

o	Predefined -+scenarios don’t require the ‘tss off’, just hit any key when your good/failure scenario is finished. 


Less frequent customizable parameters are read in from configuration file _tss_config.cfg_, and editing this file is the preferred option when you need to change default parameters like _DirWork, which is the default location (`C:\MS_DATA\`) for resulting data set.

•	You can adjust additional scripts to run at start or stop time

I.	Start of repro: tss_extra_repro_steps_AtStart.cmd

II.	Before stopping repro:  tss_extra_repro_steps_AtStop.cmd

III.	As a condition to stop tracing: _tss_stop_condition_script.cmd_ to be leveraged by TSS switch `stop:Cmd`

If you start the script without any parameters, you will see available options in the help menu:
` C:\tools> tss `
```
 Usage example: tss General               - enables general purpose logs, DNScli, Network sniff, PSR, SDP, wait for user input w/ ANY-key
                tss rOn cliOn Trace Video - enables SMB-client ETL-logs, Network sniff, Problem-Step-Recorder, video and SDP report

    Query      - query active tss ms_* Data Collector Sets (LOGMAN QUERY, LOGMAN QUERY -ets)
    REMOVE     - removes/cleans-up all persistent network and ETL component tracing; clean up Registry settings; use after forced crash
    SDP[:spec] - collect SDP report only, default SDP specialty= NET, choose [Net|Apps|CTS|Cluster|Dom|HyperV|Perf|Print|S2D|Setup|SQLbase|Mini|Nano]

 Enabling Tracing:
  usage: tss [cliOn][srvOn][rOn] + see below section Options for predefined scenarios: - and [rOn] Additional options:
   At least one of *on: cliOn, srvOn, rOn (= ReproOn) or any predefined scenario must be specified.
    cliOn      - generate SMB/NFS client component ETL-logs
    srvOn      - generate SMB/NFS/DFS server component ETL-logs
    rOn        - collecting Repro-On data and logs, needed for not predefined Tss scenarios
                 you can choose any combination of available [rOn] options below, i.e [tss rOn DCOM Trace:N:scenario]

  Predefined Tss scenarios: (no 'Tss Off' required, use ANY-key to stop, run: tss ScanarioName), all scenarios contain network trace, PSR and SDP
    802Dot1x[:LAN|WLAN] -+ scenario: 802.1x, AfdTcp, NDIS and RadioMgr ETL, network trace data for wired LAN or WiFi wireless WLAN [default=LAN]
    Auth            -+ scenario: Authentication logs (Kerberos, NTLM, SSL, negoexts, pku2u, Http), WFP, Procmon
    Branchcache     -+ scenario: Branchcache+BITS logs, Perfmon:BC
    Container       -+ scenario: Docker/Containers AfdTcp, WFP, HNS, Vfp, WinNAT
    CSC             -+ scenario: OfflineFiles infos, CSC database dump, Procmon
    DAsrv[:wfp]     -+ scenario: DirectAccess server ETL-log, trace scenario=DirectAcces,WFP-IPsec, get netlogon.log, optional WFP
    DFScli          -+ scenario: DFS client logs, Procmon
    DFSsrv[:dfsR]   -+ scenario: DFS server ETL-log and Eventlog, optional collect DFS-R replication ETL-log
    DHCPsrv         -+ scenario: DHCP server Eventlog ETL-log PsCmdlets 'netsh dhcp server' info
    DNScli          -+ scenario: DNS client logs
    DNSsrv          -+ scenario: DNS server DNScmd PsCmdlets ETL-log and Eventlog
    General         -+ scenario: General purpose logs, DNScli, wait for user input ANY-key
    MBN             -+ scenario: Mobile Broadband network, AfdTcp,DNScli,GPresult,RasMan,RadioManager,WFP ETL-logs, Firewall info, Netsh Ras diag, Trace VpnClient_dbg,wcn_dbg,wwan_dbg,wireless_dbg, Video
    MsCluster       -+ scenario: MsCluster related logs: NetFt, LBFO, Storport, Perfmon:CORE, ClusterLog
    NCSI            -+ scenario: AfdTcp DNScli LDAPcli NLA GPresult WebIO NLM ETL-logs, Video, you may run tss_NCSI_detect script
    NPS[:MFAext]    -+ scenario: NPS ETL-log, Netsh Ras diag, netsh nps tracing, optional: MFA extension
    SQLtrace        -+ scenario: SQL server related logs and TraceChn, Perfmon:SQL
    RAS             -+ scenario: Remote Access Server ETL-log, WFP diag trace, trace scenario=VpnServer
    UNChard         -+ scenario: UNChardening persistent logs, Auth, GPsvc, Procmon:Boot; after Reboot run 'TSS OFF'
    VPN             -+ scenario: Afd,TcpIp,NetIO,VPN ETL-log, WFP diag trace, 1GB network trace VpnClient_dbg, Netsh Ras diag, Video
    WebClient[:Adv|Restart] -+ scenario: WebClient logs, WebIO ETL, Proxy, [def:Basic, Restart= ~ service, Adv= incl. iDNA, requires TTT]
    WLAN            -+ scenario: WLAN ETL data for WiFi wireless WLAN (similar to 802Dot1x)
    - more options for predefined scenarios to control: noSDP,noNetView,noPSR,noProcmon,noGPresult,noSound,noCrash,noAsk,noWait see also tss_config.cfg

  [rOn] Additional options:
    AccessChk          - collect Sysinternals AccessChk logs, may need adjustments in tss_config.cfg
    AdSAM              - collect ActiveDirectory SAM client logs (on Win10)
    AfdTcp[:Basic|Full] - collect Afd, TcpIp, NetIO ETL-log, if :Basic is specified do Basic logging; default:Full
    Bluetooth          - collect Bluetooth logs
    Crash              - to be used at stop, or together with Stop trigger, Caution: this switch will force a memory dump, open files won't save. Run 'tss remove' after reboot, see KB969028
    CSVspace           - collect cluster CSV_space ETL-log
    DAcli              - collect DirectAccess client info, tss_DAclient-collector.ps1 at TSS OFF
    DCOM               - collect DCOM ETL-log, Reg-settings and SecurityDescriptor info
    DHCPcli            - collect DHCP client ETL-log and DHCP Reg info
    ETLmax:N[:NrKeep]  - set limit of ETL file size to N MB, NrKeep will force chained logs, Range N:100-4096, Circ:N has precedence for cliOn/srvOn, [def:N=1024 (MB), NrKeep=10]
    Evt[:Sec|Days:N] - collect Security Eventlog, default is Sys+App Eventlogs; [def. days back for TXT/CSV convert: Days:10]
    Fiddler            - collect Fiddler trace, to decrypt https, see https://fiddlerbook.com/fiddler/help/httpsdecryption.asp
    Firewall           - collect Firewall ETL-log and Firewall REG settings and Eventlog
    GPresult           - collect GPresult, Auditing and Security logs
    GPsvc              - collect client Group Policy GPsvc.log, netlogon.log
    Handle[:start|stop|both] - collect handle.exe output at stage Start or Stop [def:Stop]
    HttpSys            - collect HTTP.SYS ETL logging, i.e. on IIS server
    HypHost            - collect LBFO, HyperV-Host, HyperV-VMbus, Vmms ETL-log
    HypVM              - collect HyperV-VirtualMachine ETL-log
    ICS                - collect ICS SharedAccess ETL-log and SharedAccess Reg key
    iDNA:PID|name[:maxF:Full|ring|onLaunch] - collect iDNA/TTT dump for process ID or service name or unique ProcessName (requires tss_tools_ttt.zip) [defaults: maxF=2048 mode=Full]
    IPAM               - collect IPAM ETL-log and IPAM specific Event-Logs
    IPsec              - collect IPsec ETL-log
    iSCSI              - collect iSCSI ETL-log
    LBFO               - collect LBFO teaming ETL-log (included in HypHost)
    LDAPcli[:ProcName] - collect LDAP client process ETL-log, requires 'REG ADD HKLM\System\CurrentControlSet\Services\ldap\Tracing\processName.exe /f'
    LiveKd[:start|stop|both] - Execute kd/windbg memory dump on a live system at stage Start or Stop [def:Stop]
    Mini               - collect only minimal data, no supporting information data like Sysinfo, Tasklist, Services, Registry hives
    Miracast           - collect Miracast, please also add Video
    NDIS               - collect NDIS ETL-log
    NetIO              - collect Afd, TcpIp, NetIO, WFP ETL-log
    Netlogon           - collect Netlogon debug log
    NetView            - collect Get-NetView infos for diagnosing Microsoft Networking
    NLA                - collect NLA ETL-log
    NLB                - collect Afd, TcpIp, NetIO, WFP, NLB ETL-log, NLB/Diagnostic, WLBS display, msinfo32
    Outlook            - collect Outlook ETL-log, see kb2862843, start tss - restart Outlook - repro - stop tss
    PCI                - collect PCI, setupapi and msinfo32 infos
    Perfmon[:spec:int] - collect Perfmon logs, spec: choose CORE|DISK|SQL|BC|DC [def:CORE], Interval: 1-59 sec [def:30]
    PerfmonLong[:spec:int] - collect Perfmon logs, spec: choose CORE|DISK|SQL|BC|DC [def:CORE], Interval: 1-59 min [def:05]
    persistent         - Boot-scenarios: choosen ETL logs, NETSH traces, ProcMon or WPR will be activated, requires a reboot, then settings will be active
                         after restart, stop tracing using command: TSS OFF
    ProcDump:PID|name[:N:Int:Start|Stop|both] - collect N user dumps with ProcDump.exe for process ID or service name or unique ProcessName [defaults: N=3, Int=10 sec, Stop]
                       to combine multiple processes or service names, use '/' seperator, i.e.  ProcDump:Notepad.exe/dnscache/WinHttpAutoProxySvc:2
    ProcMon[:Boot|Purge:N] - collect ProcMon [Bootlog] trace, [Purge:N]: purge older *.pml files, keep number N [def:5]
    ProcTrack[:module|thread] - collect process tracking ETL, [Module: with Module load activity | Thread: with Thread+Module load activity]
    Profile            - Client Profile, WinLogon, GroupPolicy, DClocator ETL tracing
    Proxy              - collect Proxy settings and related Registry settings
    PSR[:maxsc]        - default: collect Problem Step Recorder (PSR) screenshots, [def: maxsc=99], starting timedate.cpl, to deactivate use noPSR
    Radar:PID|name     - collect RADAR Leak diag for process ID or service name or unique ProcessName.exe
    RasMan             - collect RasMan service ETL-log
    REG[:spec]         - collect Registry hives, spec: choose all|ATP|Auth|Branchcache|CSC|Firewall|Proxy|Rpc|tcp|UNChard|Webclient|VPN [def:all]
    Rpc                - collect RPC, RpcSs and DCOM ETL-log
    SCM                - collect Service Control Manager ETL-log
    SCCM               - collect SCCM System Center Configuration Manager debug ETL-log
    Sddc               - collect HA/Cluster PrivateCloud.DiagnosticInfo infos
    SDP[:spec]         - collect psSDP report, default SDP category= NET, choose [Net|Dom|CTS|Print|HyperV|Setup|Perf|Cluster|S2D|SQLbase|Apps|Mini|Nano|All]
    SignPs1            - used to selfSign PowerShell .ps1 files at first run, so that they run with any ExecutionPolicy requiring script signing
    Stop:Evt:ID[:Sys|App|Sec|Other:EventlogName[:EventData]] - stop data collection on trigger Eventlog: EventID and optional App, Sys, Sec; 'Other' for _EventlogName in tss_config.cfg
    Stop:Log[:pollInt] - stop data collection on trigger Logfile: optional PollIntervall-in-sec (def pollInt=10); edit criteria in tss_config.cfg
    Stop:Cmd[:pollInt] - stop data collection on trigger tss_stop_condition_script: optional PollIntervall-in-sec (def pollInt=8)
      Example: stop:Evt:999:App =Stop on Event ID# 999 in Application Event log
               stop:Evt:40962/40961:Other:Microsoft-Windows-PowerShell/Operational:3221226599 =Stop on Event ID# 40962 or 40961 in Microsoft-Windows-PowerShell/Operational Event log
               stop:Log:5 =Stop on Search-string entry in specific Log file, PollInt: 5-sec, all to be defined within tss_config.cfg
               stop:Cmd   =Stop based on condition given in tss_stop_condition_script.cmd
    StorPort           - collect disk/StorPort ETL-log
    SysInfo            - collect SystemInfo (txt based msinfo32)
    Trace[:N:scenario:fileMode:Byte] - capture circular NETSH trace, N: bufferSize MB, separate multiple scenario names with '/' [def:bufferSize=300, Scenario=InternetClient, fileMode=circular, truncate Byte=1514]
                       for available tracing scenarios, type: 'netsh trace show scenarios', [for SrvCORE def:InternetServer], scenario 'Capture' will only sniff
    TraceChn[:N:scenario:NrKeep] - capture chained NETSH trace, chunk bufferSize MB [def:300, Scenario=InternetClient, NrKeep=10]
    TraceNM[:N]        - capture requires Netmon NMcap.exe, N: bufferSize MB [def:300]
    TraceNMchn[:N:NrKeep] - chained capture requires Netmon NMcap.exe, N: bufferSize MB [def:300, NrKeep=10]
    Video              - collect ScreenRecorder Video ~6 MB/min, plz use max 1920x1080 (requires .NET 3.5, Feature 'Desktop Experience' on server edition; needs DeCoder or VLC for viewing)
    VSS                - collect Volume Shadow Copy Service (VSS) reports
    WorkFolders[:Adv]  - collect WorkFolders infos on Srv and Client, if Adv collect AdvancedMode with restart of service, on WF server you should include Perfmon:CORE:5
    WCM                - collect Windows Connection Manager WCM ETL-log
    WebIO              - collect WinInet, WinHTTP, WebIO ETL-log, i.e. for WebClient or Outlook
    WFP                - collect Afd, TcpIp, NetIO, WFP Windows Filtering Platform, BFE (Base Filtering Engine), netsh wfp capture
    Winsock            - collect Afd, TcpIp, NetIO, NDIS, Winsock ETL-log
    WinUpd             - collect PS Get-WindowsUpdateLog, Merges Windows Update .etl files
    WMI                - collect WMI ETL-log
    WNV[:capML]        - collect Network Virtualization WNV ETL-log, and network trace Virtualization,InternetClient; if capML captureMultilayer=yes
    WPR[:spec]         - collect WPR trace on Win8.0+ , spec: choose Network|Storage|CPU|Wait|General [def:General], TSS will use Xperf for Win2008-R2
    WWAN               - collect WWAN Wireless mobile Broadband MBN ETL-log (see also MBN)
    Xperf[:spec]       - collect Xperf trace, spec: choose General|SMB2|Disk [def:General], alternatively: you may put your Xperf command into tss_extra_repro_steps_AtStart.cmd


 Disabling Tracing:
  usage: tss off [nocab] [nobin] [noSDP]
    off             - turn off tracing
    nocab           - do not compress trace data
    nobin           - do not gather system binaries matching the captured traces on downlevel OS
    noSDP           - do not ask for SDP report, i.e. when using script in scheduled tasks

 TSS v2019.08.19.1. Check for updates on: https://github.com/CSS-Windows/WindowsDiag/tree/master/ALL/TSS
 -> see 'tss /help' for more detailed help info
 -> Looking for help on specific keywords? Try e.g.: tss /help |findstr /i /c:docker
```


Predefined parameters in _tss_config.cfg_ 

```
@rem tss_config.cfg: CONFIGURE below variables for granular controlling TSS behaviour
@rem Disk and folder path of data collection results, i.e. D:\MS_DATA - only use local disk!
_DirWork=!SYSTEMDRIVE!\MS_DATA
@
@rem For using 'Stop:Log' trigger specify path of monitored Logfile, optional PollIntervall-in-sec (def pollInt=8)
_StopSearchString=tss_test123
_LogFilePath="C:\Tools\tss_StopTokenFile_.tmp"
_LogPollIntervalSec=8
@
@rem next 3 variables control the frequency of purging chained Network Traces or Procmon logs
_PurgeNrFilesToKeep=10
_PurgePollIntervalSec=10
_PurgeTraceChn=1
@
_ProcMonSpec=Purge
_EtlCircBuf=1024
_TraceBufferSize=300
_TracefileMode=circular
@
@rem to suppress acoustic sound output at some stages that need attention
_noSound=0  
@
@rem next 3 variables are for 'AccessChk', please verify if disk, folder and file names exist
_ShareNames=C$ D$ E$
_FolderPaths=C:\DFSroots D:\ E:\
_FilePaths=C:\Temp\test.txt
@
@ controlling Branchcache/BITS
_RunPS_BCstatus=1
_BC_RESTART=0
_BITSLOG_RESET=0
_BITSLOG_RESTART=1
@
@rem ex: _EventlogName=Microsoft-Windows-PowerShell/Operational and _Stop_EventID=40962/40961 are used by  'stop:Evt:ID:Other:EvtLogname:EventData' to stop i.e. on multiple eventIDs and strings
_EventlogName=
_Stop_EventID=
_Stop_WaitTimeInSec=0
_Stop_EventData=0
@
@rem write an EventID 999 into remote hosts eventlog to stop TSS at remote host, if started with 'stop:Evt:999'; comma separated list like =host1,host2
_WriteEventToHosts=
@
@rem TSS tasks/parameters that will be skipped on local PC at 'tss OFF' or using 'stop:Evt' when EventID created by source 'TSS' is found; comma separated list
_SkipExecutionList=LiveKd,_Cluster_GetLogs
@
@rem _ClusterLog=0 : don't collect cluster log; _Cluster_GetLogs=1 : collect cluster info via PS script tss_Cluster_GetLogs.ps1
_ClusterLog=0
_Cluster_GetLogs=1
_Cluster_WriteEventToHosts=1
_LiveDmp_analytic=0
@
@rem for Direct Acccess data collection, set _DA_RESTART=1, if you want to restart the automatically the RaMgmtSvc service
_DA_RESTART=0
@
@rem To skip data compression/zip at stop of TSS, set nocab=1 
nocab=0
@
@rem To turn off asking for SDP reports at end of TSS, set _noSDP=1
_noSDP=0
@
@rem To turn off Procmon logging in TS_Scenarios, set _noProcmon=1
_noProcmon=0
@
@rem To turn off PSR logging in TS_Scenarios, set _noPSR=1
_noPSR=0
@
@rem To turn off GPresult logs in TS_Scenarios, set _noGPresult=1
_noGPresult=0
@
@rem  To automatically restart a new run after Stop condition was hit
_Autorestart=0
@
@rem  To check for Get-SpeculationControlSettings, set _SpeculationControl=1
_SpeculationControl=0
@
@rem SCCM enable debug logging when using 'Branchcache' scenario, set _SCCMdebug=1
_SCCMdebug=0
@
```

### 2.	**Examples of frequently helpful built-in TS (troubleshooting) scenarios**
TSS scenarios are predefined data collection sets, which include all necessary data like PSR, ProcMon, Perfmon or ETL tracing logs.
All these predefined scenarios include network tracing/sniffing: 


#1 Collect logs for UNC hardening issues, log on as local Admin, open elevated CMD window and run:
(Scenario includes persistent Client SMB ETL-logs, Network Trace, Gpresult, GPsvc, Auth, Registry, Procmon, SDP)

` C:\tools> tss Clion Ron UNChard `

#2 Collect Branchcache logs
(Scenario includes Network Trace, PSR, Gpresult, Registry, Perfmon, SDP)

` C:\tools> tss Ron Branchcache `

#3 Collect DFS client logs
(Scenario includes Network Trace, PSR, Gpresult, Procmon, SDP)

` C:\tools> tss CliOn Ron DFScli `

#4 Collect DNS client logs
(Scenario includes Network Trace, PSR, SDP)

` C:\tools> tss Ron DNScli `

#5 Collect logs for SQLtracing
(Scenario includes Network Trace, Perfmon)
 `C:\tools> tss Ron SQLtrace `

#6 Collect logs for CSC Offline Files
(Scenario includes Client SMB ETL-logs, Network Trace, Gpresult, Registry, PSR, Procmon, SDP)

` C:\tools> tss CliOn Ron CSC `

#7 Collect logs for Authentication provider
(Scenario includes Client SMB, SSL,HTTPsys ETL-logs, Network Trace, Gpresult, Registry, PSR, Procmon, SDP)

` C:\tools> tss CliOn Ron Auth `

#8 Collect logs for MS-cluster 
(Scenario includes Network Trace, NetFT+LBFO+Cluster ETL, Storport, Perfmon, SDP)

` C:\tools> tss Ron MsCluster `

sample for 1135 issues: 

`TSS srvOn cliOn rOn MsCluster Perfmon:CORE:1 CSVspace Stop:evt:1135:Sys `

#9 Collect logs for WebClient (similar to interactive WebClient SDP)
 (Scenario includes Network Trace, WebIO ETL, Proxy, PSR, Procmon, SDP, Advanced includes TTT/iDNA)
` C:\tools> tss CliOn Ron Webclient[:Adv] `

#10 DiskSpeed tests, for more info see 'tss /help'

` C:\tools> tss Ron DsR:D:1024:300:10G `

Above commands will start the data collection and most will stop on predefined scenarios after hitting ANY-key.
To stop data collection logging for non-predefined scenarios, run: 
 ` C:\tools> tss off` 
( if you use ‘tss off nocab’ the data in C:\MS_DATA\<date-time folder> will not be compressed; using noSDP will not ask for SDP report.)

Most of the scenarios will ask for the SDP report at the end of the data collection; the default SDP report is the Network Diagnostic. 

Note: The SDP tool Portable_Diagnostic.exe from https://home.diagnostics.support.microsoft.com/selfhelp can also be downloaded separately from same GitHub location, but be aware:

For this SDP report, at the end of SDP data collection please uncheck ‘[ ] Send results to Microsoft’ click [Save a copy], then click [Next].
Please upload the saved report manually onto MS workspace.
 

TSS will invoke the already included PowerShell script based psSDP report, which runs on all OS versions, including Server core 2016. 
To start the psSDP report separately, open an elevated PowerShell window and enter for 
EXAMPLE 1:

  ` .\Get-psSDP.ps1 Net -savePath C:\temp` 
  
  for collecting SDP NETworking Diagnostic data, saving data to folder C:\temp
  
  EXAMPLE 2:
  ` .\Get-psSDP.ps1 Mini` 
  
  for SDP Basic minimal data collection, saving data to current folder
  
  EXAMPLE 3:
   ` .\Get-psSDP.ps1 Net NoCab` 
   
   for SDP Net without zipping results


**More Examples:**

A)	You want to stop tracing based on a trigger Eventlog ID (stop:Evt:Id) or some specific error entry in a log file for issues, which occur sporadically: use the Stop feature:

Example:  ` C:\tools> tss Ron traceChn:1 stop:Log `
```stop:Evt:ID:Eventlog - stop data collection on trigger Eventlog: choose either App or Sys, and EventID
stop:Log[:pollInt] - stop data collection on trigger Logfile: optional PollIntervall-in-sec (def pollInt=10)
      Examples: stop:Evt:999:App =Stop on Event in Application Event log with Event ID# 999  (def: App:999 )
                         stop:Log:5 =Stop on Search-string entry in specific Log file, both to be defined within tss_TestLogFile.cfg
```

regarding second example, if you want to stop tracing based on a specific Windows Log entry, you can adjust the first two parameters in the file tss_TestLogFile.cfg, and optionally adjust 3rd parameter LogPollIntervalSec:

```	set StopSearchString=tss_test123
	set LogFilePath=!_MS_ScriptDir!\tss_StopTokenFile._tmp
	set LogPollIntervalSec=8
```
Read the file tss_StopTokenFile._tmp for testing your config.

B)	You want to run extra commands right after the script begins to start running?
No problem, just edit the included batch file tss_extra_repro_steps_AtStart.cmd and modify it for your own needs.
This batch file will be executed at each start of 'tss Ron' =ReproOn.

C)	You want to run extra commands before the script ends repro?
No problem, just edit the included batch file tss_extra_repro_steps_AtStop.cmd and modify it for your own needs.
This batch file will be executed at end of repro and before 'tss OFF' =ReproOFF.

D)	You want to stop tracing based on specific conditions?
No problem, just edit the included batch file tss_stop_condition_script.cmd and modify it for your own needs (i.e. by default: check if File share is available).


When using the **Persistent** switch, the settings will be active after each reboot, and you will stop data collection using 'Tss Off', unless you decide to remove it by running following command, when you are finished with all of your troubleshooting:

` C:\tools> Tss remove `

**Notes/hints:**
-	Some parameters are mutually exclusive: don’t combine [capture], [trace] or [traceChn]

-	If you want to use the SDP switch with a specialty switch, just supply your SDP sceciality: 
default SDP category= NET, choose [Net|Dom|CTS|Print|HyperV|Setup|Perf|Mini|Nano]

-	In case of unforeseen errors, please be sure to stop tracing **“tss off”** before starting a new trace session. Also try **“tss remove”** if you can’t recover (new start of tss .. fails, stop command  tss off also fails)

