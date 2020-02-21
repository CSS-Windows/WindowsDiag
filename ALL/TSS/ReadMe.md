# TSS
TSS Windows CMD based universal TroubleShooting Script toolset v`2020.01.23.2`

## TSS and TSS ttt toolset

To download the zip **tss_tools.zip**. (just click on the .zip file and then on **[Download]**) 

If you need a package including the TTT/TTD/iDNA time travel tracing for a specific support case, please ask your Support Engineer for custom zip **tss_tools_ttt.zip** (redistribution of TTT is not allowed).

### 1.	Quick Overview of Troubleshooting script tss.cmd
Purpose: Multi-purpose Troubleshooting tool to simplify just-in-time rapid data collection for standard and sporadic issues in complex environments - or is to be considered as a convenient method for submitting and following quick&easy action plans.
Copy the relevant _tss_tools.zip_ file and expand it to local disk, i.e. into _C:\tools_ folder.

Please start the script in the C:\tools folder in **elevated CMD window**.
For help, just run: `TSS` or  `TSS help yourKeyword`

` C:\tools>  tss [parameter list] `

Please invoke the tss command with necessary/appropriate parameters from here.

If troubleshooting intermittent/long-term issues, please invoke the script and stop it later in elevated CMD with same Admin User account (because parameters are stored in user’s registry hive `[HKCU\Software\Microsoft\tss.cmd-state\*]` )

•	Tss.cmd is built on t.cmd and fully down-level compatible (accepts same parameters as t.cmd), and provides a '`Persistent`' switch to capture debug ETL, network sniff, WPR and ProcMon data at boot time. (Example: `tss.cmd CliOn Trace ProcMon Persistent`)

•	For overview of possible command switches, run tss.cmd without any parameter `tss`; for full help, run `tss /help`

•	The tss*.zip file contains additional binaries (*.exe, *.dll) and helper.cmd scripts needed for correct usage of some parameters, like WPR tracing, Procmon tracing, or purging older trace files.

•	You can use *On paramaters [cliOn][srvOn][rOn] individually or in combination, but at least one of cliOn, srvOn, rOn or any predefined scenario parameter must be specified. 

•	In typical reproduction scenarios you would start tracing, reproduce the problem, then stop tracing, Example:

o	Start tracing: `Tss General Procmon Video`

o	..Now reproduce problem scenario

o	Stop tracing: `Tss off` - or hit *ANY* key in TSS CMD window for stopping predefined scenarios

o	Predefined -+scenarios don’t require the ‘tss off’, just hit any key when your good case/failure scenario is finished. 


Less frequent customizable parameters are read in from configuration file _tss_config.cfg_, and editing this file is the preferred option when you need to change default parameters like _DirWork, which is the default location (`C:\MS_DATA\`) for resulting data set.

•	You can adjust additional scripts to run at start or stop time

I.	Start of repro: tss_extra_repro_steps_AtStart.cmd

II.	Before stopping repro:  tss_extra_repro_steps_AtStop.cmd

III.	As a condition to stop tracing: _tss_stop_condition_script.cmd_ to be leveraged by TSS switch `stop:Cmd`

If you start the script without any parameters, you will see available options in the help menu:
` C:\tools> tss `
```
 TSS v2020.02.21.0 (c) Microsoft
  Syntax: Tss Param[:argment] argment in [brackets] for Param is optional, defaults will be used if argment is missing, order of sub-args is mandatory, '|' means 'OR', ':' is a delimiter between args, 'def: val' stands for Default value

 Usage example: TSS General               - enables general purpose logs, DNScli, Network sniff, PSR, SDP, wait for user input w/ ANY-key
                TSS rOn cliOn Trace Video - enables SMB-client ETL-logs, Network sniff=Trace, Problem-Step-Recorder, Video and SDP report

    Help [keyword] - or -? /? -help /help = this help screen, + optional keyword to search for
    Query      - query active ETW tss ms_* Data Collector Sets (LOGMAN QUERY, LOGMAN QUERY -ets)
    Update     - update current tss version from latest GitHub release
    Version    - shows current tss version: v2020.02.21.0
    Remove     - removes/cleans-up all persistent network and ETL component tracing; clean up Registry settings; recommended to use after forced crash

 Enabling Tracing:
  usage: TSS [cliOn][srvOn][rOn] + see below sections '[rOn] Additional module options:' -and 'Predefined Tss scenarios:'
   At least one of *on: cliOn, srvOn, rOn (= ReproOn) or any predefined ScanarioName must be specified.
    cliOn      - generate SMB/NFS client component ETL-logs
    srvOn      - generate SMB/NFS/DFS server component ETL-logs
    rOn        - collecting Repro-On data / logs, required for below options unless ScanarioName is present.
      you can choose any combination of available [rOn] options and/or -+scenarios below, i.e: TSS rOn DCOM General Trace:N:scenario

  [rOn / ScanarioName] Additional module options:
    AccessChk       - collect Sysinternals AccessChk logs, may need adjustments in tss_config.cfg
    AdSAM           - collect ActiveDirectory SAM client logs (on Win10)
    AfdTcp[:Basic|Full] - collect Afd,TcpIp,NetIO ETL-logs, if :Basic is specified do Basic logging; default:Full
    BGP             - collect Border Gateway Protocol (BGP) ETL-Logs
    Bluetooth       - collect Bluetooth logs
    Crash           - to be used at stop, or together with Stop trigger, Caution: this switch will force a memory.dump, open files won't save. Run 'tss off noCrash' after reboot, see KB969028
    CSVspace        - collect cluster CSV_space ETL-logs
    customETL:Provider1/Provider2 - collect ETL-logs with list of custom providers, example: customETL:"Microsoft-Windows-DNS-Client"/{1540FF4C-3FD7-4BBA-9938-1D1BF31573A7}
    DAcli           - collect DirectAccess client info, tss_DAclient-collector.ps1 at TSS OFF
    DCOM            - collect DCOM ETL-log, Reg-settings and SecurityDescriptor info
    DfsR            - collect DFS replication ETL-log
    DsR[:Drive:BlockSize:Sec:FS] - DriveLetter [D], BlockSize(K) [1024], Duration(Sec) [300], FileSize [10G] for DiskSpeed Repro
    ETLmax:N[:NrKeep] - set limit of ETL file size to N MB, NrKeep will force chained logs, Range N:100-4096, Circ:N has precedence for cliOn/srvOn, [def: N=1024 (MB), NrKeep=1]
    Evt[:Sec|Days:N] - collect Security Eventlog, default is Sys+App Eventlogs; [def. days back for TXT/CSV convert: Days:10]
    Fiddler         - collect Fiddler trace, to decrypt https, see https://fiddlerbook.com/fiddler/help/httpsdecryption.asp
    FWmgr           - collect Firewall Manager ETL log, consider also collecting WFP
    GPresult        - collect GPresult, Auditing and Security logs
    GPsvc           - collect client Group Policy GPsvc.log, netlogon.log
    Handle[:start|stop|both] - collect handle.exe output at stage Start or Stop [def: Stop]
    HttpSys         - collect HTTP.SYS ETL logging, i.e. on IIS server
    ICS             - collect ICS SharedAccess ETL-log and SharedAccess Reg key
    iDNA:PID|name[:maxF:Full|ring|onLaunch] - collect iDNA/TTD dump for PID, service name or unique ProcessName (requires tss_tools_ttt.zip) [defaults: maxF=2048 mode=Full], separate multiple PIDs/names by '/'
    IPAM            - collect IPAM ETL-log and IPAM specific Event-Logs
    IPsec           - collect IPsec ETL-log
    iSCSI           - collect iSCSI ETL-log
    LBFO            - collect LBFO teaming ETL-log (included in HypHost / WNV)
    LDAPcli[:ProcName] - collect LDAP client process ETL-log, requires 'REG ADD HKLM\System\CurrentControlSet\Services\ldap\Tracing\processName.exe /f' [def: svchost.exe]
    LiveKd[:start|stop|both] - Execute kd/windbg memory dump on a live system at stage Start or Stop [def: Stop]
    Mini            - collect only minimal data, skip ClearCaches, no supporting information data like Sysinfo, Tasklist, Services, Registry hives, no PSR, no SDP
    Miracast        - collect Miracast, please also add Video
    MPIO            - collect MPIO, MsDSM, Storport, ClassPnP ETL-logs
    MsDSM           - collect MsDSM ETL-logs
    MUX             - collect NetworkController MUX Microsoft-Windows-SlbMux ETL-log (in SDN)
    NCHA            - collect NetworkController.HostAgent ETL-log (in SDN / WNV)
    NDIS            - collect NDIS ETL-log
    NdisWan         - collect NdisWan ETL-log
    Netlogon        - collect Netlogon debug log
    NetView         - collect Get-NetView infos for diagnosing Microsoft Networking
    NetworkUX       - collect Network UI User Interface ETL-logs
    NLA             - collect NLA ETL-log
    Outlook         - collect Outlook ETL-log, see kb2862843, start tss - restart Outlook - repro - stop tss
    OLE             - collect OLE32 ETL-log
    PCI             - collect PCI, setupapi and msinfo32 infos
    PktMon          - collect Packet Monitoring data (on RS5+ / Srv2019)
    Perfmon[:spec:int] - collect Perfmon logs, spec: choose CORE|DISK|SQL|BC|DC|Biz [def: CORE], Interval: 1-59 sec [def: 30]
    PerfmonLong[:spec:int] - collect Perfmon logs, spec: choose CORE|DISK|SQL|BC|DC|Biz [def: CORE], Interval: 1-59 min [def: 05]
    persistent      - Boot-scenarios: choosen ETL logs, NETSH traces, ProcMon or WPR will be activated, requires a reboot, then settings will be active
                      after restart, stop tracing using command: TSS OFF
    PNP             - collect PlugAndPlay PnP ETL-log and info
    PortProxy       - collect PortProxy IP Helper Service ETL-Logs, can be used i.e. in combination with Test:psTelnet:Both:IPaddr/TCPportNr
    Print           - collect Print Service ETL- and Event-Logs
    ProcDump:PID|name[:N:Int:Start|Stop|Both] - collect N user dumps with ProcDump.exe for process ID or service name or unique ProcessName [defaults: N=3, Int=10 sec, Stop]
                    to combine multiple processes or service names, use '/' separator, i.e.  ProcDump:Notepad.exe/dnscache/WinHttpAutoProxySvc:2
    ProcMon[:Boot|Purge:N[:Filter]] - collect ProcMon [Bootlog] trace, [Purge:N]: purge older *.pml files, keep number N [def: 9], Filter=name-of-FilterConfig.pmc
    ProcTrack[:module|thread] - collect process tracking ETL, [Module: with Module load activity | Thread: with Thread+Module load activity]
    Profile         - Client Profile, WinLogon, GroupPolicy, DClocator ETL tracing
    PSR[:maxsc]     - default: collect Problem Step Recorder (PSR) screenshots, [def: maxsc=99], starting timedate.cpl, to deactivate use noPSR
    Radar:PID|name - collect RADAR Leak diag for process ID or service name or unique ProcessName.exe
    RasMan          - collect RasMan service ETL-log
    RDMA            - collect RDMA ETL-log
    REG[:spec]      - collect Registry hives, spec: choose all|ATP|Auth|BITS|Branchcache|CSC|Firewall|HyperV|Proxy|Rpc|tcp|UNChard|Webclient|VPN [def: all]
    Rpc             - collect RPC, RpcSs and DCOM ETL-logs
    SCM             - collect Service Control Manager ETL-log
    SCCM            - collect SCCM System Center Configuration Manager debug ETL-log
    Sddc            - collect HA/Cluster PrivateCloud.DiagnosticInfo infos
    SignPs1         - used to selfSign PowerShell .ps1 files at first run, so that they run with any ExecutionPolicy requiring script signing
    SmartCard       - collect SmartCard/Windows Hello for Business (WHfB) ETL-log
    SNMP            - collect Simple Network Management Protocol (SNMP) ETL-log
    Stop:Evt:ID[:Sys|App|Sec|Other:EventlogName[:EventData]] - stop data collection on trigger Eventlog: EventID and optional App, Sys, Sec; 'Other' for _EventlogName in tss_config.cfg
    Stop:Log[:pollInt] - stop data collection on trigger Logfile: optional PollIntervall-in-sec (def pollInt=10); edit criteria in tss_config.cfg
    Stop:Cmd[:DFS|Smb|Svc|custom[:pollInt]] - stop data collection on trigger tss_stop_condition_script.cmd, optional PollIntervall-in-sec [def: Stop:Cmd:custom:8]
    Stop:ps1[:Dfs|HTTP|PortDest|PortLoc|RDP|Smb|Svc|WINRM|custom[:pollInt]] - stop data collection based on trigger condition defined in (adjusted) PoSh tss_stop_condition_script.ps1 [def: Port=135]
      Example: stop:Evt:999:App =Stop on Event ID# 999 in Application Event log
               stop:Evt:40962/40961:Other:Microsoft-Windows-PowerShell/Operational:3221226599 =Stop on Event ID# 40962 or 40961 in Microsoft-Windows-PowerShell/Operational Event log
               stop:Log:5      =Stop on Search-string entry in specific Log file, PollInt: 5-sec, all to be defined within tss_config.cfg
               stop:Cmd:Svc:4  =Stop based on service stop condition given in (adjusted) tss_stop_condition_script.cmd, PollInt: 4-sec
               stop:ps1:PortDest:5 =Stop based on dest. TCP port 135 fail condition given in (adjusted) tss_stop_condition_script.ps1, PollInt: 5-sec
    StorPort        - collect disk/StorPort ETL-log
    SysInfo         - collect SystemInfo (txt based msinfo32)
    TaskSch         - collect Task Scheduler ETL-log
    Test[:psPing|TraceRt|NsLookup|Http|Ldap|Smb|Wmi|publicIP|psTelnet[:Start|Stop|Both[:TestDestName[:Nr:Int] | IPaddr/Port]]] - connectivity info, separate multiple Test-scenarios names with '/', [def: psPing, TestPhase: Stop, TestDestName:www.microsoft.com|UserDomain, Nr=5, Int=2]
    TLS             - collect Schannel TLS/SSL ETL-log
    Trace[:N:scenario:fileMode:Byte] - capture circular NETSH trace, N: bufferSize MB, separate multiple scenario names with '/' [def: bufferSize=300, Scenario=InternetClient, fileMode=circular, truncate Byte=1514]
                    for available tracing scenarios, type: 'netsh trace show scenarios', [for SrvCORE def: InternetServer], scenario 'Capture' will only sniff
    TraceChn[:N:scenario:NrKeep] - capture chained NETSH trace, chunk bufferSize MB [def:300, Scenario=InternetClient, NrKeep=10]
    TraceNM[:N]     - capture requires Netmon NMcap.exe, N: bufferSize MB [def: 300]
    TraceNMchn[:N:NrKeep] - chained capture requires Netmon NMcap.exe, N: bufferSize MB [def: 300, NrKeep=10]
    USB             - collect Universal Serial Bus (USB) ETL-log
    Video           - collect ScreenRecorder Video ~6 MB/min, plz use max 1920x1080 (requires .NET 3.5, Feature 'Desktop Experience' on server edition; needs DeCoder or VLC for viewing)
    VML[:verbose]   - collect Hyper-V host VmlTrace ETL-log [def: Standard, Verbose will restart the Hyper-V service] + FRuti.exe log
    VmSwitch        - collect VmSwitch ETL-log (included in HypHost and SDN)
    VSS             - collect Volume Shadow Copy Service (VSS) reports
    WCM             - collect Windows Connection Manager (WCM) ETL-log
    WebIO           - collect WinInet, WinHTTP, WebIO ETL-logs, i.e. for WebClient or Outlook
    WfpDiag         - collect WFP diag trace: netsh wfp capture
    WinRM           - collect Windows Remote Management (WinRM) ETL-log
    WinUpd          - collect PS Get-WindowsUpdateLog, Merges Windows Update .etl files, (included in psSDP)
    WmbClass        - collect WmbClass,NDISuIO,PnP ETL-logs
    WMI             - collect WMI ETL-log
    WPR[:spec]      - collect WPR trace on Win8.0+ , spec: choose CPU|General|Network|Storage|Wait [def: General], TSS will use Xperf for Win2008-R2
    WWAN            - collect WWAN Wireless mobile Broadband MBN ETL-log (see also MBN)
    Xperf[:spec]    - collect Xperf trace, spec: choose General|SMB2|Disk [def: General], alternatively: you may put your Xperf command into tss_extra_repro_steps_AtStart.cmd

  Predefined Tss scenarios: (no 'Tss Off' required, use ANY-key to stop, run: tss ScanarioName), all scenarios include network trace, PSR and SDP
    802Dot1x[:LAN|WLAN] -+ scenario: 802.1x,Afd,TcpIp,NDIS,RadioMgr,WCM ETL-logs, Video, for wired LAN or WiFi wireless WLAN [def: LAN]
    Auth            -+ scenario: Authentication logs (Kerberos, Kps, Kdc, NTLM, SSL, Lsa, negoexts, pku2u, vault, Http), WFP, Procmon
    BITS            -+ scenario: Background Intelligent Transfer Service (BITS) client logs
    Branchcache     -+ scenario: Branchcache+BITS logs, Perfmon:BC
    Container       -+ scenario: Afd,TcpIp,WFP,HNS,Vfp,WinNAT ETL-Logs, Docker/Containers
    CSC             -+ scenario: OfflineFiles infos, CSC database dump, Procmon
    DAsrv[:Restart] -+ scenario: DirectAccess server ETL-logs, trace scenario=DirectAcces,WFP-IPsec, get netlogon.log, 1-GB network trace, Restart= RaMgmtSvc service, [consider also WfpDiag]
    DFScli          -+ scenario: DFS client logs, Procmon
    DFSsrv          -+ scenario: DFS server ETL-logs and Eventlog, [consider also DfsR]
    DHCPcli         -+ scenario: Boot/persistent DHCP client ETL-log and DHCP Reg info, DNScli, Procmon, persistent; after Reboot run 'TSS OFF'; use noPersistent for instant logging
    DHCPsrv         -+ scenario: DHCP server Eventlog ETL-logs PsCmdlets 'netsh dhcp server' info, includes DNScli
    DNScli          -+ scenario: DNS client ETL-logs, Eventlog
    DNSsrv          -+ scenario: DNS server DNScmd PsCmdlets, ETL-logs and Eventlog
    Firewall        -+ scenario: Firewall ETL-log, Firewall REG settings and Eventlog
    General         -+ scenario: General purpose logs, DNScli, wait for user input ANY-key
    HypHost         -+ scenario: LBFO, HyperV-Host, HyperV-VMbus, Vmms ETL-logs
    HypVM           -+ scenario: HyperV-VirtualMachine ETL-logs
    IIS             -+ scenario: IIS server logs, HttpSys ETL-logs
    MBAM            -+ scenario: Microsoft Bitlocker Administration and Monitoring ETL-logs
    MBN[:verbose]   -+ scenario: Mobile Broadband Network: Afd,TcpIp,DNScli,GPresult,RasMan,RadioManager,VPN,WFP,WCM ETL-logs, Firewall info, Netsh Ras diag, 1-GB Trace wwan_dbg [if verbose: +,wireless_dbg], Video
    MsCluster       -+ scenario: MsCluster related logs: NetFt, LBFO, Storport, Perfmon:CORE, ClusterLog
    NCSI            -+ scenario: Afd,TcpIp,DNScli,LDAPcli,NLA,NLM,WebIO ETL-logs, GPresult, Procmon, Video, you may run tss_NCSI_detect script
    NetIO           -+ scenario: Afd,TcpIp,NetIO,WFP ETL-logs
    NFScli          -+ scenario: NFS client logs, GPresult, Procmon, Video
    NFSsrv[:perm]   -+ scenario: NFS server cmds PsCmdlets, ETL-logs and Eventlogs, 'perm' will ask for NFS Folder/File path
    NLB             -+ scenario: Afd,TcpIp,NetIO,NLB ETL-logs, NLB/Diagnostic Events, WLBS display, msinfo32
    NPS[:MFAext]    -+ scenario: NPS ETL-logs, Netsh Ras diag, netsh nps tracing, 1-GB trace, Securtiy EvtLog, [optional :MFAext]
    Proxy           -+ scenario: NCSI,WebIO,Winsock ETL-logs, Proxy settings and related Registry settings, 1-GB trace, Procmon Video
    SQLtrace        -+ scenario: SQL server related logs and TraceChn, Perfmon:SQL
    RAS             -+ scenario: Remote Access Server ETL-logs, WFP diag trace, trace scenario=VpnServer
    RDScli          -+ scenario: Remote Desktop (RDP) client ETL-logs, QWinSta, REG settings, Env-var, GPresult, event logs, Video; add Evt:Sec to collect Security Eventlog
    RDSsrv          -+ scenario: Remote Desktop server ETL-logs, QWinSta, REG settings, Env-var, GPresult, event logs incl Sec.EvtLog
    SdnNC           -+ scenario: SDN NetworkController,HttpSys,MUX,LBFo,NCHA,TLS,VmSwitch ETL-logs, consider to add WFP for GW
    SBSL            -+ scenario: Slow Boot/Slow Logon: boot/persistent logs, Profile,Netlogon,WinLogon,GroupPolicy,DCLocator,GPresult,GPsvc,Auth,WPR:Wait,Procmon:Boot, 1-GB trace; after Reboot run 'TSS OFF'
    SDP[:spec[:noNetadapters|skipBPA|skipNetview|skipSddc|skipTS]] - collect SDP report, choose SDP specialty Apps|CTS|Cluster|Dom|HyperV|Net|Perf|Print|S2D|Setup|SQLbase|SQLconn|SQLmsdtc|SQLsetup|VSS|Mini|Nano|All [def: Net], to combine more specs, use '/' as separator i.e. SDP:Net/HyperV
    UNChard         -+ scenario: UNC-hardening: boot/persistent logs, Profile,Netlogon,WinLogon,GroupPolicy,DCLocator,GPresult,GPsvc,Auth,Procmon:Boot, 1-GB trace; after Reboot run 'TSS OFF'
    VPN             -+ scenario: Afd,TcpIp,NetIO,VPN ETL-logs, WFP diag trace, 1-GB network trace VpnClient_dbg, Netsh Ras diag, Video
    WebClient[:Adv|Restart] -+ scenario: WebClient logs, WebIO ETL, Proxy, [def: Basic, Restart= ~ service, Adv= incl. iDNA, requires TTD], do *not* combine with Persistent
    WFP             -+ scenario: Afd,TcpIp,NetIO,WFP Windows Filtering Platform, BFE (Base Filtering Engine), includes WfpDiag: netsh wfp capture, Procmon, Video
    Winsock         -+ scenario: Afd,TcpIp,NetIO,NDIS,Winsock ETL-logs
    WIP             -+ scenario: Windows Information Protection diagnostic, Procmon, Video
    WLAN            -+ scenario: WLAN,NetworkUX ETL-logs, Video for WiFi wireless WLAN (similar to 802Dot1x)
    WNV[:capML]     -+ scenario: Network Virtualization (WNV) ETL-log, Afd,TcpIp,LBFo,NCHA,VmSwitch, network trace Virtualization,InternetClient; if capML captureMultilayer=yes
    WorkFolders[:Adv] -+ scenario: WorkFolders infos on Srv and Client, Perfmon, Video, if :Adv collect Advanced-Mode with restart of service
     - more options for controlling predefined scenarios: noSDP,noPSR,noCab,noPersistent,noProcmon,noGPresult,noSound,noCrash,noClearCache,noAsk,noWait,noVideo see also tss_config.cfg

 Disabling Tracing:
  usage: TSS off [nocab] [nobin] [noSDP]

 TSS v2020.02.21.0. Check for updates on: https://github.com/CSS-Windows/WindowsDiag/tree/master/ALL/TSS
      or run 'TSS update'
  -> see 'TSS /help' for more detailed help info
  -> Looking for help on specific keywords? Try e.g.: tss help my_keyword

```


Predefined parameters in _tss_config.cfg_ 

```
@rem tss_config.cfg: CONFIGURE below variables for granular controlling TSS behaviour - be sure that modified lines have no trailing space character
@rem Disk and folder path of data collection results, i.e. D:\MS_DATA - only use local disk!
_DirWork=!SYSTEMDRIVE!\MS_DATA
@
@rem For using 'Stop:Log' trigger specify path of monitored Logfile, optional PollIntervall-in-sec (def: pollInt=8 sec), be sure the error string is not already found in curent logFile at start of TSS
_StopSearchString=tss_test123
_LogFilePath="C:\tss_Tools\tss_StopLog_EntryFound.tmp"
_LogPollIntervalSec=8
@
@rem next 3 variables control the frequency of purging chained Network Traces or Procmon logs
_PurgeNrFilesToKeep=10
_PurgePollIntervalSec=10
_PurgeTraceChn=1
@
_ProcMonSpec=Purge
_EtlBuf=1024
_TraceBufferSize=300
_TracefileMode=circular
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
@rem ex: _EventlogName=Microsoft-Windows-PowerShell/Operational and _Stop_EventID=40962/40961 are used by  'stop:Evt:ID:Other:EvtLogname:EventData' to stop i.e. on multiple eventIDs and strings. Note:Eventlog names with space/blank character need to be specified in this config file with quotes, ex: "DNS Server"; 
@        _Stop_EventData must match a complete string within XMLview <Data> </Data>
_EventlogName=
_Stop_EventID=
_Stop_WaitTimeInSec=0
_Stop_EventData=0
@
@rem write an EventID 999 into remote hosts eventlog to stop TSS at remote host, if started with 'stop:Evt:999' or any other ID; comma separated list like =host1,host2
_WriteEventToHosts=
@
@rem TSS tasks/parameters that will be skipped on local PC at 'tss OFF' or using 'stop:Evt' when EventID created by source 'TSS' is found; comma separated list
_SkipExecutionList=LiveKd,_Cluster_GetLogs
@
@rem set _ClusterLog=0 to skip collect cluster log; per default we collect already cluster info via PS script tss_Cluster_GetLogs.ps1
_ClusterLog=0
_Cluster_WriteEventToHosts=1
_LiveDmp_analytic=0
@
@rem to suppress acoustic sound output at some stages that need attention
_noSound=0  
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
@rem To turn off waiting for ANY/key in TS_Scenarios, set _noWait=1
_noWait=0
@
@rem To turn off Video recording in TS_Scenarios, set _noVideo=1
_noVideo=0
@
@rem To turn off Persistent switch in scenarios, set __noPersistent=1
_noPersistent=0
@
@rem  To automatically restart a new run after Stop condition was hit
_Autorestart=0
@
@rem  To check for Get-SpeculationControlSettings, set _SpeculationControl=1
_SpeculationControl=0
@
@rem SCCM enable debug logging when using 'Branchcache' scenario, set _SCCMdebug=1, alternate method: use TSS switch SCCM
_SCCMdebug=0
@
@rem VmlTrace start parameters, i.e. for VmlTrace.exe /m a /f all all /i
_VmlTraceCmd=/m all /f all all /u /z 600 /i
@
@rem custom ETL tracing. Add a '/' separated list of Providernames or GUIDs, i.e. _customETL="Microsoft-Windows-DNS-Client"/{1540FF4C-3FD7-4BBA-9938-1D1BF31573A7}
_customETL=
@
@rem Connectivity Test:[:psPing|TraceRt|NsLookup|Http|Ldap|Smb|Wmi|publicIP|psTelnet[:Start|Stop|Both[:TestDestName[:Nr:Int]
_TestPhase=Stop
_TestURL=www.microsoft.com
_TestDestName=
_psPingNr=5
_psPingInt=2
@
@rem define NetLogon DbgFlag, i.e. less verbose: 2080FFFF
_NetLogonFlag=2FFFFFFF
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

` C:\tools> tss Branchcache `

#3 Collect DFS client logs
(Scenario includes Network Trace, PSR, Gpresult, Procmon, SDP)

` C:\tools> tss DFScli `

#4 Collect DNS client logs
(Scenario includes Network Trace, PSR, SDP)

` C:\tools> tss DNScli `

#5 Collect logs for SQLtracing
(Scenario includes Network Trace, Perfmon)
 `C:\tools> tss SQLtrace `

#6 Collect logs for CSC Offline Files
(Scenario includes Client SMB ETL-logs, Network Trace, Gpresult, Registry, PSR, Procmon, SDP)

` C:\tools> tss CSC `

#7 Collect logs for Authentication provider
(Scenario includes Client SMB, SSL,HTTPsys ETL-logs, Network Trace, Gpresult, Registry, PSR, Procmon, SDP)

` C:\tools> tss Auth `

#8 Collect logs for MS-cluster 
(Scenario includes Network Trace, NetFT+LBFO+Cluster ETL, Storport, Perfmon, SDP)

` C:\tools> tss MsCluster `

sample for 1135 issues: 

`TSS srvOn cliOn MsCluster Perfmon:CORE:1 CSVspace Stop:evt:1135:Sys `

#9 Collect logs for WebClient (similar to interactive WebClient SDP)
 (Scenario includes Network Trace, WebIO ETL, Proxy, PSR, Procmon, SDP, Advanced includes TTT/iDNA)
` C:\tools> tss CliOn Ron Webclient[:Adv] `

#10 DiskSpeed tests, for more info see 'tss /help'

` C:\tools> tss Ron DsR:D:1024:300:10G `

Above commands will start the data collection and most will stop on predefined scenarios after hitting ANY-key.
To stop data collection logging for non-predefined scenarios, run: 
 ` C:\tools> tss off` 
( if you use ‘tss off nocab’ the data in C:\MS_DATA\<date-time folder> will not be compressed; using noSDP will not ask for SDP report.)

Most of the scenarios will automatically collect the SDP report at the end of the data collection; the default SDP report is the Network Diagnostic. 

Note: The SDP tool Portable_Diagnostic.exe from https://home.diagnostics.support.microsoft.com/selfhelp can also be downloaded separately from same GitHub location, but be aware:

For this SDP report, at the end of SDP data collection please uncheck ‘[ ] Send results to Microsoft’ click [Save a copy], then click [Next].
Please upload the saved report manually onto MS workspace.
 

TSS will invoke the already included PowerShell script based psSDP report, which runs on all OS versions, including Server core 2016/2019. 
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


When using the **Persistent** switch, the settings will be active after each reboot, and you will stop data collection using 'Tss Off', unless you decide to Stop and Remove it by running following command, when you are finished with all of your troubleshooting:

` C:\tools> Tss Remove `

**Notes/hints:**
-	Some parameters are mutually exclusive: don’t combine [capture], [trace] or [traceChn]

-	If you want to use the SDP switch with a specialty switch, just supply your SDP sceciality: 
default SDP category= NET, choose [Apps|Cluster|S2D|CTS|Dom|HyperV|Net|Perf|Print|Setup|SQLbase|SQLconn|SQLmsdtc|SQLsetup|VSS|Mini|Nano|Remote|RFL|All]

-	In case of unforeseen errors, please be sure to stop tracing **“tss off”** before starting a new trace session. Also try **“tss remove”** if you can’t recover (new start of tss .. fails, stop command  tss off also fails)

**Revision History**

See https://github.com/CSS-Windows/WindowsDiag/blob/master/ALL/TSS/revision-history.txt 

**Additional Infos**

For customers: To download files from MS workspace, see KB article 4012140: 

  How to use Secure File Exchange to exchange files with Microsoft Support 
  https://support.microsoft.com/en-US/help/4012140 

