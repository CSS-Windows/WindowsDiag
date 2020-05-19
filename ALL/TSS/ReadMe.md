## DISCLAIMER:
` TSS is a collection of cmd/powershell scripts that mainly utilize the built-in Windows OS logging mechanisms or other Microsoft tools (like process monitor, procdump, ...) to collect static (like event logs, registry outputs, configuration outputs and similar) or dynamic repro logs (like network traces, user/kernel mode memory dumps, perfmon logs, Process monitor logs, ETL traces from various Windows OS components and similar) to troubleshoot various Windows OS or other Microsoft product related problems dispatched to Microsoft Support. TSS has been developed and maintained by Microsoft Support Platform Escalation Team. For more details on TSS please visit https://aka.ms/TssTools `

# TSS
TSS Windows CMD based universal TroubleShooting Script toolset v`2020.04.27.2`

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
 TSS v2020.05.09.0 (c) Microsoft CSS
  Syntax: Tss Param[:<argument>] argument in [brackets] for Param is optional, defaults will be used if argument is missing, the order of sub-args is mandatory, '|' means 'OR', ':' is a delimiter between params and/or args, 'def: val' stands for Default value, '<name>' is placeholder

 Usage example: TSS General               - enables general purpose logs, DNScli, Network sniff, PSR, SDP, wait for user input w/ ANY-key
                TSS rOn cliOn Trace Video - enables SMB-client ETL-logs, Network sniff=Trace, Problem-Step-Recorder, Video and SDP report

    Help [<keyword>] - or -? /? -help /help = this help screen, + optional <keyword> to search for
    Query      - query active ETW tss ms_* Data Collector Sets (LOGMAN QUERY, LOGMAN QUERY -ets)
    Update     - update current tss version from latest GitHub release
    Version    - shows current tss version: v2020.05.09.0
    Remove     - removes/cleans-up all persistent network and ETL component tracing; clean up Registry settings; stop running PSR,ProcMon,Trace,Video; recommended to use after forced crash

 Enabling Tracing:
  usage: TSS [<ScanarioName>|cliOn|srvOn|rOn] + see below sections '[rOn] Additional module options:' -and 'Predefined Tss scenarios:'
   At least one of *on: cliOn, srvOn, rOn (= ReproOn) or any predefined <ScanarioName> must be specified. 
    cliOn      - generate SMB/NFS client component ETL-logs
    srvOn      - generate SMB/NFS/DFS server component ETL-logs
    rOn        - collecting Repro-On data / logs, required for below options unless -+<ScanarioName> is present.
      you can choose any combination of available [rOn] options and/or -+scenarios below, i.e: TSS rOn DCOM General Trace:N:scenario

  [rOn / <ScanarioName>] Additional module options:
    AccessChk       - collect Sysinternals AccessChk logs, may need adjustments in tss_config.cfg
    AdSAM           - collect ActiveDirectory SAM client logs (on Win10)
    AfdTcp[:Basic|Full] - collect Afd,TcpIp,NetIO ETL-log, if :Basic is specified do Basic logging; default:Full
    ATA             - collect ATAPort ETL-log
    BadPwd          - collect User's bad password attempts info from all DCs
    BGP             - collect Border Gateway Protocol (BGP) ETL-log
    Bluetooth       - collect Bluetooth logs
    CDROM           - collect CD/DVD ETL-log
    Coreinfo        - collect Sysinternals Coreinfo log
    Crash           - to be used at stop, or together with Stop trigger, Caution: this switch will force a memory.dump, open files won't save. Run 'tss off noCrash' after reboot, see KB969028
    CSVspace        - collect cluster CSV_space ETL-log
    customETL:<Provider1>/<Provider2> - collect ETL-log with list of custom providers, example: customETL:"Microsoft-Windows-DNS-Client"/{1540FF4C-3FD7-4BBA-9938-1D1BF31573A7}
    DataDisk:<letter> - to specify Disk drive letter for resulting data, default is disk C; example: DataDisk:E
    DCOM            - collect COM,COM+,COMSVCS,COMADMIN,DCOM,DCOMSCM ETL-log, Reg-settings and SecurityDescriptor info, consider also OLE32
    Dedup           - collect Data Deduplication and Filter ETL-log
    Defender        - collect Defender/Operational Eventlogs and ATP Reg.keys
    DfsR            - collect DFS replication ETL-log, Eventlog, DFSR logs
    DsR[:<Drive>:<BlockSize>:<Sec>:<FS>] - DriveLetter [D], BlockSize(K) [1024], Duration(Sec) [300], FileSize [10G] for DiskSpeed Repro
    EFS             - collect encryped FS ETL-log
    ETLmax:<N>[:<NrKeep>] - set limit of ETL file size to <N> MB, <NrKeep> will force chained logs, Range <N>:100-4096, Circ:<N> has precedence for cliOn/srvOn, [def: N=1024 (MB), NrKeep=1]
    Evt[:Sec|Days:<N>] - collect Security Eventlog, default is Sys+App Eventlogs; [def. days back for TXT/CSV convert: Days:10]
    Fiddler         - collect Fiddler trace, to decrypt https, see https://fiddlerbook.com/fiddler/help/httpsdecryption.asp
    FSRM            - collect FSRM drivers ETL-log
    FWmgr           - collect Firewall Manager ETL log, consider also collecting WFP
    GPresult        - collect GPresult, Auditing and Security logs
    GPsvc           - collect client Group Policy GPsvc.log, netlogon.log
    Handle[:start|stop|both] - collect handle.exe output at stage Start or Stop [def: Stop]
    HttpSys         - collect HTTP.SYS ETL logging, i.e. on IIS server
    ICS             - collect ICS SharedAccess ETL-log and SharedAccess Reg key
    iDNA:<PID>|name[:<maxF>:Full|ring|onLaunch] - collect iDNA/TTD dump for PID, service name or unique ProcessName (requires tss_tools_ttt.zip) [defaults: maxF=2048 mode=Full], separate multiple PIDs/names by '/'
    IPsec           - collect IPsec ETL-log
    iSCSI           - collect iSCSI ETL-log
    LBFO            - collect LBFO teaming ETL-log (included in HypHost / WNV) 
    LDAPcli[:<ProcName>] - collect LDAP client process ETL-log, requires 'REG ADD HKLM\System\CurrentControlSet\Services\ldap\Tracing\processName.exe /f' [def: svchost.exe]
    LiveKd[:start|stop|both] - Execute kd/windbg memory dump on a live system at stage Start or Stop [def: Stop]
    LockOut         - find User Account Lockout info from all DCs (EventIDs 4625,4771,4776), requires Domain Admin account
    Mini            - collect only minimal data, no supporting information data like Sysinfo, Tasklist, Services, Registry hives/files, Evt-logs, skip ClearCaches, noPSR,noSDP,noVideo,noVerCheck
    MPIO            - collect MPIO, MsDSM, Storport, ClassPnP ETL-logs
    MsDSM           - collect MsDSM ETL-log
    MUX             - collect NetworkController MUX Microsoft-Windows-SlbMux ETL-log (in SDN)
    NCHA            - collect NetworkController.HostAgent ETL-log (in SDN / WNV)
    NDIS            - collect NDIS ETL-log
    NdisWan         - collect NdisWan ETL-log
    Netlogon        - collect Netlogon debug log 
    NetView         - collect Get-NetView infos for diagnosing Microsoft Networking
    NFC             - collect Near-field communication ETL-log
    NetworkUX       - collect Network UI User Interface ETL-log
    NLA             - collect NLA ETL-log
    NTFS            - collect NTFS driver ETL-log
    Outlook         - collect Outlook ETL-log, see kb2862843, start tss - restart Outlook - repro - stop tss
    OpsMgr          - collect OpsMgr ETL and Eventlogs
    OLE             - collect OLE32 ETL-log, consider also DCOM
    PCI             - collect PCI, setupapi and msinfo32 infos
    PktMon[:Drop]   - collect Packet Monitoring data (on RS5+ / Srv2019), PktMon:Drop will collect only dropped packets
    Perfmon[:<spec>:<int>] - collect Perfmon logs, <spec>: choose CORE|DISK|SQL|BC|DC|Biz [def: CORE], Interval: 1-59 sec [def: 30]
    PerfmonLong[:<spec>:<int>] - collect Perfmon logs, <spec>: choose CORE|DISK|SQL|BC|DC|Biz [def: CORE], Interval: 1-59 min [def: 05]
    persistent      - Boot-scenarios: choosen ETL logs, NETSH traces, ProcMon or WPR will be activated, requires a reboot, then settings will be active
                      after restart, stop tracing using command: TSS OFF; Note: persistent will not work in combi with Stop:*, PSR, Video 
    PNP             - collect PlugAndPlay PnP ETL-log and info
    PortProxy       - collect PortProxy IP Helper Service ETL-log, can be used i.e. in combination with Test:psTelnet:Both:IPaddr/TCPportNr
    Print           - collect Print Service ETL- and Event-Logs
    ProcDump:<PID>|<name>[:<N>:<Int>:Start|Stop|Both] - collect N user dumps with ProcDump.exe for process ID or service name or unique ProcessName [defaults: N=3, Int=10 sec, Stop]
                    to combine multiple processes or service names, use '/' separator, i.e.  ProcDump:Notepad.exe/dnscache/WinHttpAutoProxySvc:2
    ProcMon[:Boot|Purge:<N>[:<Filter>]] - collect ProcMon [Bootlog] trace, [Purge:N]: purge older *.pml files, keep number N [def: 9], Filter=name-of-FilterConfig.pmc
    ProcTrack[:module|thread] - collect process tracking ETL, [Module: with Module load activity | Thread: with Thread+Module load activity]
    Profile         - Client Profile, WinLogon, GroupPolicy, DClocator ETL tracing
    PSR[:<maxsc>]   - default: collect Problem Step Recorder (PSR) screenshots, [def: maxsc=99], starting timedate.cpl, to deactivate use noPSR
    Radar:<PID>|<name> - collect heap RADAR Leak diag for process ID or service name or unique ProcessName.exe
    RAmgmt          - collect RemoteAccess Management ETL-log
    RasMan          - collect RasMan service ETL-log
    REG[:<spec>]    - collect Registry output, <spec>: choose Hives|802Dot1x|ATP|Auth|BITS|Bluetooth|Branchcache|Cluster|CSC|DAcli|DAsrv|DFS|DCOM|DHCP|DNS|Firewall|GPsvc|Http|HyperV|ICS|LBFO|LDAPcli|MBN|MFAext|NLA|NPS|NTDS|PCI|Proxy|RAS|Rpc|SNMP|Tcp|TLS|UNChard|USB|Webclient|VPN|webClient|WLBS [def: Hives]
    Rpc             - collect RPC, RpcSs services and DCOM ETL-logs
    SCM             - collect Service Control Manager ETL-log of process services.exe
    SCCM            - collect SCCM System Center Configuration Manager debug ETL-log
    Sddc            - collect HA/Cluster PrivateCloud.DiagnosticInfo infos
    SignPs1         - used to selfSign PowerShell .ps1 files at first run, so that they run with any ExecutionPolicy requiring script signing
    SmartCard       - collect SmartCard/Windows Hello for Business (WHfB) ETL-log
    SNMP            - collect Simple Network Management Protocol (SNMP) ETL-log
    Stop:Evt:<ID>[:Sys|App|Sec|Other:<EventlogName>[:<EventData>]] - stop data collection on trigger Eventlog: EventID and optional App, Sys, Sec; 'Other' for _EventlogName in tss_config.cfg
    Stop:Log[:<pollInt>] - stop data collection on trigger Logfile: optional PollIntervall-in-sec (def pollInt=10); edit criteria in tss_config.cfg
    Stop:Cmd[:DFS|Smb|Svc|custom[:<pollInt>]] - stop data collection on trigger tss_stop_condition_script.cmd, optional PollIntervall-in-sec [def: Stop:Cmd:custom:8]
    Stop:ps1[:Dfs|HTTP|PortDest|PortLoc|RDP|Smb|Svc|WINRM|custom[:<pollInt>]] - stop data collection based on trigger condition defined in (adjusted) PoSh tss_stop_condition_script.ps1 [def: Port=135]
    Stop:Time[:<min>] - stop data collection after <min> minutes, [def: Stop:Time:10]
      Example: stop:Evt:999:App =Stop on Event ID# 999 in Application Event log
               stop:Evt:40962/40961:Other:Microsoft-Windows-PowerShell/Operational:3221226599 =Stop on Event ID# 40962 or 40961 in Microsoft-Windows-PowerShell/Operational Event log
               stop:Log:5      =Stop on Search-string entry in specific Log file, PollInt: 5-sec, all to be defined within tss_config.cfg
               stop:Cmd:Svc:4  =Stop based on service stop condition given in (adjusted) tss_stop_condition_script.cmd, PollInt: 4-sec 
               stop:ps1:PortDest:5 =Stop based on dest. TCP port 135 fail condition given in (adjusted) tss_stop_condition_script.ps1, PollInt: 5-sec 
               stop:Time:3     =Stop after 3 minutes
    Storage         - collect Storage drivers ETL-log
    StorageReplica  - collect Storage Replica ETL-log
    StorageSpace    - collect Storage Space ETL-log
    StorPort        - collect disk/StorPort ETL-log
    SysInfo         - collect SystemInfo (txt based msinfo32)
    TaskSch         - collect Task Scheduler ETL-log
    Test[:psPing|TraceRt|NsLookup|Http|Ldap|Smb|Wmi|publicIP|psTelnet[:Start|Stop|Both[:<TestDestName>[:<Nr>:<Int>] | <IPaddr>/<Port>]]] - connectivity info, separate multiple Test-scenarios names with '/', [def: psPing, TestPhase: Stop, TestDestName:www.microsoft.com|UserDomain, Nr=5, Int=2]
    TLS             - collect Schannel TLS/SSL ETL-log, CAPI2 Evt-Log
    Trace[:<N>[:<scenario>[:<fileMode>:<Byte>]]] - capture circular NETSH trace, N: bufferSize MB, separate multiple scenario names with '/' [defaults: bufferSize=500, Scenario=InternetClient, fileMode=circular, truncate Byte=1514 for Ethernet]
                    for available tracing scenarios, type: 'netsh trace show scenarios', [for SrvCORE def: InternetServer], scenario 'Capture' will only sniff
      i.e.: Trace:2048 -or-  Trace:1024:NetConnection -or- Trace:4096:Capture -or- Trace:1024:InternetClient:Circular:128
    TraceChn[:<N>:<scenario>:<NrKeep>] - capture chained NETSH trace, chunk bufferSize MB [def: 500, Scenario=InternetClient, NrKeep=10]
    TraceNM[:<N>:<Byte>] - capture requires Netmon NMcap.exe, N: bufferSize MB [def: 500, truncate Byte=1514]
    TraceNMchn[:<N>:<NrKeep>:<Byte>] - chained capture requires Netmon NMcap.exe, N: bufferSize MB [def: 500, NrKeep=10, truncate Byte=1514]
    USB             - collect Universal Serial Bus (USB) ETL-log
    VDS             - collect VDS services ETL-log
    Video           - collect ScreenRecorder Video ~6 MB/min, plz use max 1920x1080 (requires .NET 3.5, Feature 'Desktop Experience' on server edition; needs DeCoder or VLC for viewing)
    VirtualFC       - collect Virtual FC info logs
    VML[:verbose]   - collect Hyper-V host VmlTrace ETL-log [def: Standard, Verbose will restart the Hyper-V service] + FRuti.exe log
    VMQ             - validate Hyper-V VMQ and RSS settings (USB)
    VmSwitch        - collect VmSwitch ETL-log (included in HypHost and SDN)
    VSS             - collect VolSnap, Volume Shadow Copy Service (VSS) reports
    WCM             - collect Windows Connection Manager (WCM) ETL-log
    WebIO           - collect WinInet, WinHTTP, WebIO ETL-logs, i.e. for WebClient or Outlook
    WfpDiag         - collect WFP diag trace: netsh wfp capture
    WinNAT          - collect WindowsNAT ETL-log
    WinRM           - collect Windows Remote Management (WinRM) ETL-log
    WinUpd          - collect PS Get-WindowsUpdateLog, Merges Windows Update .etl files, (included in psSDP)
    WmbClass        - collect WmbClass,NDISuIO,PnP ETL-logs
    WMI             - collect WMI services ETL-log
    WPR[:<spec>]   - collect WPR trace on Win8.0+ , <spec>: choose CPU|General|Network|Storage|Wait [def: General], TSS will use Xperf for Win2008-R2
    WSB             - collect Windows Server Backup modules ETL-log
    WWAN            - collect WWAN Wireless mobile Broadband MBN ETL-log (see also MBN)
    Xperf[:<spec>] - collect circular Xperf trace, <spec>: choose CPU|General|SMB2|Disk|Memory [def: General / Delay], alternatively: you may put your specific Xperf command into tss_extra_repro_steps_AtStart.cmd

  [for cliOn/srvOn  -only] Collection options:
  usage on original t.cmd: T [cliOn|srvOn] [persistent][capture][core][verbose] [csv][cluster][hyperv] [circ:N] [driver:flags:level]
    capture         - [downlevel t.cmd] in combination with cliOn, srvOn: enable packet capture (Windows 7 / 2008 R2 or newer)
    circ:N          - generate circular logs of size N megabytes (default circular buffer size is 250 MB per log)
    cluster         - collect Cluster event logs
    csv             - generate cluster CSV component traces
    hyperv          - collect Hyper-V event logs
    verbose         - verbose mode tracing flags (defined for fskm/mup srv)
    driver:flags:level - specify trace flags and level for this driver (support rdbss, mrxsmb, smb20 only)
                         flags and level must be in hex
        rdbss:  0x0001 error     0x0002 misc     0x0004 io        0x0008 openclose
                0x0010 readwrite 0x0020 fileinfo 0x0040 oplock    0x0080 connectionobject
                0x0100 fcb       0x0200 caching  0x0400 migration 0x0800 namecache
                0x1000 security
        mrxsmb: 0x0001 error     0x0002 misc        0x0004 network          0x0008 security
                0x0010 exchange  0x0020 compounding 0x0040 connectionobject 0x0080 midwindow
                0x0100 multichannel
        smb20:  0x0001 error    0x0002 misc   0x0004 network 0x0008 security
                0x0010 exchange 0x0020 io     0x0040 handle  0x0080 infocache
                0x0100 dircache 0x0200 oplock
        level:  0x1 error 0x2 brief 0x4 verbose

 Disabling and ReEnabling Tracing:
  usage: TSS snapshot [nocab] [nobin]

	[rOn] more No* options:
    noAsk           - do not ask about good/failing scenario text input before compressing data
    noClearCache    - do not clear DNS,NetBios,Kerberos,DFS chaches at start
    noCluster_GetLogs - don't collect cluster infos / validation reports
    noCrash         - do not run Crash after reboot again when using 'tss off noCrash'
    noGPresult      - do not run GPresult, used to override setting in preconfigured TS scenarios
    noSDP           - do not gather SDP report, i.e. when using script in scheduled tasks
    noPersistent    - do not use predefined Persistent in scenarios
    noProcMon       - do not run ProcMon, used to override setting in preconfigured TS scenarios
    noPSR           - do not run PSR, used to override setting in preconfigured TS scenarios
    noRestart       - do not restart associated service
    noSound         - do not play attention sound
    noVerCheck      - do not check online for latest TSS version on Github, no AutoUpdate
    noWait          - do not wait at stage: Press ANY-Key to stop, use 'TSS OFF'
    noVideo         - do not run Video, used to override setting in preconfigured TS scenarios
    noXray          - do not start Xray troubleshooter

  You can lookup netsh trace scenarios here: dbg/wpp : HKLM\System\CurrentControlSet\Control\NetDiagFx\Microsoft\HostDLLs\WPPTrace\HelperClasses
 	 - and normal scenarios here: HKLM\System\CurrentControlSet\Control\NetTrace\Scenarios	
  All network traces *packetcapture|NetTrace|capture|sniff*.etl files can be converted into the corresponding .pcap files using RFLcheck Etl2Pcap
  Short link to tss download: https://aka.ms/getTSS
 
  Predefined Tss scenarios: (no 'Tss Off' is required, use ANY-key to stop, run: tss <ScanarioName>), all scenarios include network trace, PSR and SDP
    802Dot1x[:LAN|WLAN] -+ scenario: 802.1x,Afd,TcpIp,NDIS,RadioMgr,TLS,WCM ETL-logs, Video, for wired LAN or WiFi wireless WLAN [def: LAN]
    Auth            -+ scenario: Authentication logs (Kerberos, Kps, Kdc, NTLM, SSL, Lsa, negoexts, pku2u, vault, Http), WFP, TLS, Procmon 
    BITS            -+ scenario: Background Intelligent Transfer Service (BITS) client logs
    Branchcache     -+ scenario: Branchcache+BITS logs, Perfmon:BC
    Container       -+ scenario: Afd,TcpIp,WFP,HNS,Vfp,WinNAT ETL-Logs, Docker/Containers 
    CSC             -+ scenario: OfflineFiles infos, CSC database dump, Procmon
    DAcli           -+ scenario: DirectAccess client info, scenario=DirectAccess,Netconnection, DA client config, WFPdiag, TLS, tss_DAclient-collector.ps1 at TSS OFF
    DAsrv[:Restart] -+ scenario: DirectAccess server ETL-logs, trace scenario=DirectAcces,WFP-IPsec, get netlogon.log, TLS, 1-GB network trace, RAmgmt, Restart= RaMgmtSvc service, WfpDiag
    DFScli          -+ scenario: DFS client logs, RDR, GPresult, Procmon
    DFSsrv          -+ scenario: DFS server ETL-logs and Eventlog, [consider also DfsR]
    DHCPcli         -+ scenario: Boot/persistent DHCP client ETL-log and DHCP Reg info, DNScli, Procmon, persistent; after Reboot run 'TSS OFF'; add noPersistent for instant logging
    DHCPsrv         -+ scenario: DHCP server Eventlog ETL-logs PsCmdlets 'netsh dhcp server' info, includes DNScli
    DNScli          -+ scenario: DNS client ETL-logs, Eventlog
    DNSsrv          -+ scenario: DNS server DNScmd PsCmdlets, ETL-logs and Eventlog
    Firewall        -+ scenario: Firewall ETL-log, Firewall REG settings and Eventlog
    General         -+ scenario: General purpose logs, DNScli, wait for user input ANY-key
    HypHost         -+ scenario: LBFO, HyperV-Host, HyperV-VMbus, Vmms ETL-logs, VmWp,VmConfig, VMM-debug, 1-GB network trace
    HypVM           -+ scenario: HyperV-VirtualMachine ETL-logs
    IIS             -+ scenario: IIS server logs, HttpSys ETL-logs
    IPAM            -+ scenario: IPAM ETL-log and IPAM specific Event-Logs
    MBAM            -+ scenario: Microsoft Bitlocker Administration and Monitoring ETL-logs
    MBN[:verbose]   -+ scenario: Mobile Broadband Network/LTE: Afd,TcpIp,DNScli,GPresult,RasMan,RadioManager,VPN,WFP,WCM ETL-logs, Firewall info, Netsh Ras diag, 1-GB Trace wwan_dbg [if verbose: +,wireless_dbg], Video
    Miracast        -+ scenario: Miracast, Video
    MsCluster       -+ scenario: MsCluster related logs: CSV,NetFt,LBFO,Storport, Perfmon:CORE, ClusterLog, SDP:cluster
    NCSI            -+ scenario: Afd,TcpIp,DNScli,LDAPcli,NLA,NLM,WebIO ETL-logs, GPresult, Procmon, Video, you may run tss_NCSI_detect script
    NetIO           -+ scenario: Afd,TcpIp,NetIO,WFP ETL-logs
    NFScli          -+ scenario: NFS client logs, GPresult, Procmon, Video
    NFSsrv[:perm]   -+ scenario: NFS server cmds PsCmdlets, ETL-logs and Eventlogs, 'perm' will ask for NFS Folder/File path
    NLB             -+ scenario: Afd,TcpIp,NetIO,NLB ETL-logs, NLB/Diagnostic Events, WLBS display, msinfo32
    NPS[:MFAext]    -+ scenario: NPS ETL-logs, Netsh Ras diag, netsh nps tracing, TLS, 1-GB network trace, Securtiy EvtLog, [optional :MFAext]
    Proxy           -+ scenario: NCSI,WebIO,Winsock ETL-logs, Proxy settings and related Registry settings, 1-GB trace, Procmon Video
    RAS[:Hang]      -+ scenario: Remote Access Server ETL-logs, TLS, WFP diag trace, trace scenario=VpnServer; [:Hang will collect at stop Procdumps of Rasman/RemoteAccess/RaMgmtSvc/IKEEXT/RaMgmtui.exe]
    RDScli          -+ scenario: Remote Desktop (RDP) client ETL-logs, QWinSta, REG settings, Env-var, GPresult, event logs, Video; add Evt:Sec to collect Security Eventlog
    RDMA[:Basic|Full] -+ scenario: RDMA ETL-log, Event-Logs, SMB client [default=Basic]
    RDSsrv          -+ scenario: Remote Desktop (RDP) server ETL-logs, QWinSta, REG settings, Env-var, GPresult, event logs incl Sec.EvtLog
    SBSL            -+ scenario: Slow Boot/Slow Logon: boot/persistent logs, Profile,Netlogon,WinLogon,GroupPolicy,DCLocator,GPresult,GPsvc,Auth,WPR:Wait,Procmon:Boot, 1-GB trace; after Reboot run 'TSS OFF'
    SDN             -+ scenario: SDN Infra Logs, see SDN\SDNLogCollect.ps1, Specify one of the NC VM and collect Logs from NC, MUX and Gateway VMs
    SdnNC           -+ scenario: SDN NetworkController,HttpSys,MUX,LBFo,NCHA,TLS,VmSwitch ETL-logs, consider to add WFP for GW
    SDP[:<spec>[:noNetadapters|skipBPA|skipHang|skipNetview|skipSddc|skipTS|skipHVreplica]] - collect SDP report, choose SDP <spec>ialty Apps|CTS|Cluster|DA|Dom|HyperV|Net|Perf|Print|S2D|Setup|SQLbase|SQLconn|SQLmsdtc|SQLsetup|VSS|Mini|Nano|All [def: Net]; to combine more specs or skip-parameters, use '/' as separator i.e.: SDP:Net/HyperV:skipBPA
    SMBcli          -+ scenario: SMB,DFS client logs, RDR, GPresult, Procmon
    SQLtrace        -+ scenario: SQL server related logs and TraceChn, Perfmon:SQL, SDP:SQLbase
    UNChard         -+ scenario: UNC-hardening: boot/persistent logs, Profile,Netlogon,WinLogon,GroupPolicy,DCLocator,GPresult,GPsvc,Auth,Procmon:Boot, 1-GB trace; after Reboot run 'TSS OFF'
    VPN             -+ scenario: Afd,TcpIp,NetIO,VPN ETL-logs, WFP diag trace, 1-GB network trace VpnClient_dbg, Netsh Ras diag, Video
    WebClient[:Adv|Restart] -+ scenario: WebClient logs, WebIO ETL, Proxy, TLS, [def: Basic, Restart= ~ service, Adv= incl. iDNA, requires TTD], do *not* combine with Persistent
    WFP             -+ scenario: Afd,TcpIp,NetIO,WFP Windows Filtering Platform, BFE (Base Filtering Engine), includes WfpDiag: netsh wfp capture, Procmon, Video
    Winsock         -+ scenario: Afd,TcpIp,NetIO,NDIS,Winsock ETL-logs
    WIP             -+ scenario: Windows Information Protection diagnostic, Procmon, Video
    WLAN            -+ scenario: 802.1x,Afd,TcpIp,NDIS,NetworkUX,RadioMgr,TLS,WCM ETL-logs, Video for WiFi wireless WLAN
    WNV[:capML]     -+ scenario: Network Virtualization (WNV) ETL-log, Afd,TcpIp,LBFo,NCHA,VmSwitch, network trace Virtualization,InternetClient; if capML captureMultilayer=yes
    WorkFolders[:Adv] -+ scenario: WorkFolders infos on Srv and Client, Perfmon, Video, if :Adv collect Advanced-Mode with restart of service
     - more options for controlling predefined scenarios: noSDP,noPSR,noCab,noPersistent,noProcmon,noGPresult,noRestart,noSound,noCrash,noClearCache,noAsk,noWait,noVideo,noVerCheck see also tss_config.cfg

 Disabling Tracing:
  usage: TSS off [nocab] [nobin] [noSDP]
    off          - turn off tracing
    noCab        - do not compress/zip trace data
    nobin        - do not gather system binaries matching the captured traces on downlevel OS
    noSDP        - do not gather SDP report, i.e. when using script in scheduled tasks

 TSS v2020.05.09.0. Check for updates on: http://aka.ms/TssTools - Download: http://aka.ms/getTss
      or run 'TSS update'
  -> see 'TSS /help' for more detailed help info
  -> Looking for help on specific keywords? Try e.g.: tss help <my_keyword>

```


Predefined parameters in _tss_config.cfg_ 

```
@rem tss_config.cfg: CONFIGURE below variables for granular controlling TSS behaviour - be sure that modified lines have no trailing space character
@rem Disk and folder path of data collection results, i.e. D:\MS_DATA - only use local disk, NOT a Onedrive or redirected Folder!
_DataDisk=C
@_DirWork=!_DataDisk!:\MS_DATA
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
_TraceBufferSize=500
_TracefileMode=circular
@
@rem next 3 variables are for 'AccessChk', please verify if disk, folder and file names exist
_ShareNames=C$ D$ E$
_FolderPaths=C:\DFSroots D:\ E:\
_FilePaths=C:\Temp\test.txt
@
@rem ex: _EventlogName=Microsoft-Windows-PowerShell/Operational and _Stop_EventID=40962/40961 are used by  'stop:Evt:ID:Other:EvtLogname:EventData' to stop i.e. on multiple eventIDs and strings. Note:Eventlog names with space/blank character need to be specified in this config file with quotes, ex: "DNS Server"; 
@        _Stop_EventData must match a complete string within XMLview <Data> </Data>, put whole multi-word string within quotes
_EventlogName=
_Stop_EventID=
_Stop_WaitTimeInSec=0
_Stop_EventData=0
@
@rem write an EventID 999 into remote hosts eventlog to stop TSS at remote host, if started with 'stop:Evt:999' or any other ID; comma separated list like =host1,host2
_WriteEventToHosts=
_Remote_Stop_EventID=999
@
@rem TSS tasks/parameters that will be skipped on local PC at 'tss OFF' or using 'stop:Evt' when EventID created by source 'TSS' is found; comma separated list
_SkipExecutionList=LiveKd,_Cluster_GetLogs
@
@rem set _ClusterLog=0 to skip collect cluster log; per default we collect already cluster info via PS script tss_Cluster_GetLogs.ps1
_ClusterLog=0
_Cluster_WriteEventToHosts=1
_LiveDmp_analytic=0
@
@rem to suppress acoustic sound output at some stages that need attention, set _noSound=1
_noSound=0  
@
@rem To turn off waiting for ANY/key in TS_Scenarios, set _noWait=1
_noWait=0
@
@rem To turn off TSS version check, set _noVerCheck=1
_noVerCheck=0
@
@rem To turn off SDP,Procmon,PSR,GPresult,Video,Persistent logging in TS_Scenarios, set _no<Variable>=1
_noSDP=0
_noProcmon=0
_noPSR=0
_noGPresult=0
_noVideo=0
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
@ controlling Branchcache/BITS
_RunPS_BCstatus=1
_BC_RESTART=0
_BITSLOG_RESET=0
_BITSLOG_RESTART=1
@
@rem  To perform no RunDown in AfdTcpIp ( netsh int TCP rundown ), set _RunDown=0
_RunDown=1
@
```

### 2.	**Examples of frequently helpful built-in TS (troubleshooting) scenarios**
TSS scenarios are predefined data collection sets, which include all necessary data like PSR, ProcMon, Perfmon or ETL tracing logs.
All these predefined scenarios include network tracing/sniffing, PSR and SDP report: 


#1 Collect logs for UNC hardening issues, log on as local Admin, open elevated CMD window and run:
(Scenario includes persistent Client SMB ETL-logs, Network Trace, Gpresult, GPsvc, Auth, Registry, Procmon, SDP)

` C:\tools> tss UNChard `

#2 Collect Branchcache logs
(Scenario includes Network Trace, PSR, Gpresult, Registry, Perfmon, SDP)

` C:\tools> tss Branchcache `

#3 Collect DFS client or SMB client logs
(Scenario includes Network Trace, PSR, Gpresult, Procmon, SDP)

` C:\tools> tss DFScli `
` C:\tools> tss SMBcli `

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
` C:\tools> tss Webclient[:Adv] `

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

regarding second example, if you want to stop tracing based on a specific Windows Log entry, you can adjust the two parameters _StopSearchString and _LogFilePath in the configuration file tss_config.cfg, and optionally adjust 3rd parameter _LogPollIntervalSec:

```
_StopSearchString=tss_test123
_LogFilePath="C:\tss_Tools\tss_StopLog_EntryFound.tmp"
_LogPollIntervalSec=8
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

