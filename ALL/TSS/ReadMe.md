## DISCLAIMER:
` TSS is a collection of cmd/powershell scripts that mainly utilize the built-in Windows OS logging mechanisms or other Microsoft tools (like Process Monitor, procdump, ...) to collect static (like event logs, registry outputs, configuration outputs and similar) or dynamic repro logs (like network traces, user/kernel mode memory dumps, Perfmon logs, Process Monitor logs, ETL traces from various Windows OS components and similar) to troubleshoot various Windows OS or other Microsoft product related problems dispatched to Microsoft Support. TSS has been developed and maintained by Microsoft Support Platform Escalation Team. For more details on TSS please visit https://aka.ms/TssTools `

# TSS
TSS All-in-1 Windows CMD based universal TroubleShooting Script toolset v`2020.12.23.2`

## TSS and TSS ttt toolset

To download the zip **tss_tools.zip**. (just click on the .zip file and then on **[Download]**) or simply run https://aka.ms/getTSS

If you need a package including the TTT/TTD/iDNA time travel tracing for a specific support case, please ask your Support Engineer for custom zip **tss_tools_ttt.zip** (redistribution of TTT is not allowed) to be uploaded to your MS workspace. Please login to workspace with your workspace credentials. 

### 1.	Quick Overview of Troubleshooting script tss.cmd
Purpose: Multi-purpose **All-in-1** Troubleshooting tool to simplify just-in-time rapid data collection for standard and sporadic issues in complex environments - or is to be considered as a convenient method for submitting and following quick&easy action plans.
Copy the relevant _tss_tools.zip_ file and expand it to local disk, i.e. into _C:\tools_ folder.

Please start the script in the C:\tools folder in **elevated CMD window**.
For help, just run: `TSS` or more specific `TSS help <yourKeyword>`

` C:\tools>  tss [parameter list] `

Please invoke the tss command with necessary/appropriate parameters from here.
For additional help/FAQ info, engineers can leverage: 

` C:\tools>  tss HelpMe `

If troubleshooting intermittent/long-term issues, please invoke the script and stop it later in elevated CMD with same Admin User account (because parameters are stored in user’s registry hive `[HKCU\Software\Microsoft\tss.cmd-state\*]` )

•	Tss.cmd is built on t.cmd and fully down-level compatible (accepts same parameters as t.cmd), and provides a '`Persistent`' switch to capture debug ETL, network sniff, WPR and ProcMon data at next boot time. (Example: `tss.cmd CliOn Trace ProcMon Persistent`)

•	For overview of possible command switches, run tss.cmd without any parameter `tss`; for full help, run `tss /help`; for specific help `TSS help <yourKeyword>`

•	The tss*.zip file contains additional binaries (*.exe, *.dll) and helper.cmd scripts needed for correct usage of some parameters, like WPR tracing, Procmon tracing, or purging older trace files.

•	You can use *On paramaters [cliOn][srvOn][rOn] individually or in combination, but at least one of cliOn, srvOn, rOn or any predefined scenario name must be specified. 

•	In typical reproduction scenarios you would start tracing, reproduce the problem, then stop tracing, Example:

o	Start tracing: `Tss General Procmon Video`

o	..Now reproduce problem scenario

o	Stop tracing: hit *ANY* key in TSS CMD window for stopping predefined scenarios - or `Tss OFF` 

o	Predefined -+scenarios don’t require the ‘tss off’, just hit any key when your good case/failure scenario is finished. 


Less frequent customizable parameters are read in from configuration file _tss_config.cfg_, and editing this file is the preferred option when you need to change default parameters like _DirWork, which is the default location (`C:\MS_DATA\`) for resulting data set.

•	You can adjust additional scripts to run at start or stop time:

I.	Start of repro: tss_extra_repro_steps_AtStart.cmd

II.	Before stopping repro:  tss_extra_repro_steps_AtStop.cmd

III.	As a condition to stop tracing: _tss_stop_condition_script.cmd_ or  _tss_stop_condition_script.ps1_ to be leveraged by TSS switch `stop:Cmd` or `stop:Ps1`

If you start the script without any parameters, you will see available options in the help menu:
` C:\tools> tss `
```
 TSS v2020.12.23.2 (c) Microsoft CSS
 DISCLAIMER:
 TSS is a collection of cmd/powershell scripts that mainly utilize the built-in Windows OS logging mechanisms or other Microsoft tools (like process monitor, procdump, ...) to collect static (like Event Logs, registry outputs, configuration outputs and similar) or dynamic repro logs (like network traces, user/kernel mode memory dumps, perfmon logs, Process monitor logs, ETL traces from various Windows OS components and similar) to troubleshoot various Windows OS or other Microsoft product related problems dispatched to Microsoft Support. TSS has been developed and maintained by Microsoft Support Platform Escalation Team. For more details on TSS please visit https://aka.ms/TssTools

 Syntax: Tss Param[:<argument>] argument in [square brackets] for Param is optional, defaults will be used if argument is missing, the order of sub-args is mandatory, '|' means 'OR', ':' is a delimiter between params and/or args, 'def: val' stands for Default value, '<name>'  in angle brackets is placeholder.

 Usage examples: TSS General               - enables general purpose log(s), DNScli, Network sniff, PSR, SDP, wait for user input w/ ANY-key
                 TSS rOn cliOn Trace Video - enables SMB-client ETL log(s), Network sniff=Trace, Problem-Step-Recorder, Video and SDP report

 Enabling Tracing:
  usage: TSS [<ScenarioName>|cliOn|srvOn|rOn] + see below sections '[rOn] Additional module options:' -and 'Predefined Tss scenarios:'
   At least one of *on: cliOn, srvOn, rOn (= ReproOn) or any predefined <ScenarioName> must be specified. 
    cliOn      - generate SMB/NFS client component ETL log(s), network trace
    srvOn      - generate SMB/NFS/DFS server component ETL log(s), network trace
    rOn        - collecting Repro-On data / log(s), required for below options unless -+<ScenarioName> is present.
      you can choose any combination of available [rOn] options (modules) and/or -+scenarios below, i.e: TSS rOn DCOM General Trace:N:scenario

  CONTROLS
    AcceptEula      - do not ask at first run to accept Disclaimer 
    CLUE[:on|off]   - CLUE=Collection of Logs and the User Experience - Tool for performance problems (Xperf, PALPerfMon), see .\CLUE\Clue Usage Guide.docx [def = install, :off = un-install]
    DataDisk:<letter> - to specify Disk drive letter for resulting data, default is disk C; example: DataDisk:E
    Debug           - invoke current command with Debug facility - it will set Env variable _DbgOut=1
    DumpType        - set the memory dump option using x64\kdbgctrl.exe <options>, -sd <dump type> - active|automatic|full|kernel|mini
    Discard         - can be used at OFF, to dismiss and delete all data collected in current Tss run
    Downgrade       - downgrade to last-known-good (stable) TSS version, please use noUpdate on next TSS command
    ETLmax:<N>[:<NrKeep>] - set limit of ETL file size to <N> MB, <NrKeep> will force chained log(s), Range <N>:100-4096, Circ:<N> has precedence for cliOn/srvOn, [def: N=1024 (MB), NrKeep=1]
    Help [<keyword>] - or -? /? -help /help = this help screen, + optional <keyword> to search for
    Mini            - collect only minimal data, no supporting information data like Sysinfo, Tasklist, Services, Registry hives/files, Evt log(s), skip ClearCaches, noPSR,noSDP,noVideo,noUpdate
    moveResult:<server>:<share>[:<folder>] - move resulting tss zip file to central location \\<server>\<share>\<folder> [def: <folder> = tssResults]
    Msg[:<username>[:<servername>[:<message>[:<WaitTime>]]]] - using Msg.exe to send a short <message> (string without spaces) to <username> on <servername>, waiting max <WaitTime> seconds [def:waltere, WALTERE-VDI, '[Info]_TSS_stopped', 2 sec]
    persistent      - Boot-scenarios: choosen ETL log(s), NETSH traces, ProcMon, WPR or Xperf will be activated, requires a reboot, then settings will be active
                      after restart, stop tracing using command: TSS OFF; Note: persistent will not work in combi with Stop:*, PSR, Video 
    Query           - query active ETW tss ms_* Data Collector Sets (LOGMAN QUERY, LOGMAN QUERY -ets)
    Remote          - used for remote execution i.e. using psExec
    Remove          - removes/cleans-up all persistent network and ETL component tracing; clean up Registry settings; stop running PSR,ProcMon,Trace,Video; recommended to use after forced crash
    SignPs1         - used to selfSign PowerShell .ps1 files at first run, so that they run with any ExecutionPolicy requiring script signing
    Stop:Evt:<ID>[:Sys|App|Sec|Other:<EventlogName>[:<EventData>[:Partial[:AND|OR]]]]] - stop data collection on trigger classic (Sys, App, Sec) Eventlogs <EventID> and/or 'Other' for non-classic EventlogNames (or _EventlogName in tss_config.cfg)
    Stop:Log[:<pollInt>] - stop data collection on trigger Logfile: optional PollInterval-in-sec (def pollInt=10); edit criteria in tss_config.cfg
    Stop:Cmd[:DFS|Smb|Svc|custom[:<pollInt>]] - stop data collection on trigger tss_stop_condition_script.cmd, optional PollInterval-in-sec [def: Stop:Cmd:custom:8]
    Stop:ps1[:BC|Branchcache|Dfs|HTTP|LDAP|PortDest|PortLoc|Process|RDP|Smb|Svc|WinRM|Share|custom[:<pollInt>]] - stop data collection based on trigger condition defined in (adjusted) PoSh tss_stop_condition_script.ps1 [def: Port=135] and/or tss_config.cfg
    Stop:Time[:<min>] - stop data collection after <min> minutes, [def: Stop:Time:10]
      Example: stop:Evt:999:App    =Stop on Event ID# 999 in Application Event log
               stop:Evt:40962/40961:Other:Microsoft-Windows-PowerShell/Operational:3221226599 =Stop on Event ID# 40962 or 40961 in Microsoft-Windows-PowerShell/Operational EventLog with STATUS_FILE_NOT_AVAILABLE
               Stop:Evt:31010:Other:Microsoft-Windows-SMBClient/Security:Access/Denied:Partial =Stop on Event ID# 31010 in Microsoft-Windows-SMBClient/Security EventLog with Partial Message 'Access' or 'Denied'
               Stop:Evt:4624:Other:Security:Contoso.com/User1:Partial:AND =Stop on Event ID# 4624 in Security EventLog with Partial Message 'Contoso.com' AND 'User1', both criteria must match
               stop:Log:5          =Stop on Search-string entry in specific Log file, PollInt: 5-sec, all to be defined within tss_config.cfg
               stop:Cmd:Svc:4      =Stop based on service stop condition given in (adjusted) tss_stop_condition_script.cmd, PollInt: 4-sec 
               stop:ps1:LDAP:10    =Stop based on failing LDAP test 'nltest /DSGETDC:$DomainName /LDAPONLY', PollInt: 10-sec
               stop:ps1:PortDest:5 =Stop based on dest. TCP port < default =135> fail condition given in tss_config.cfg or (adjusted) tss_stop_condition_script.ps1, PollInt: 5-sec
               stop:ps1:Share:3    =Stop based on \\<server>\<share> availability condition; adjust server+share name in tss_config.cfg, see also tss_stop_condition_script.ps1, PollInt: 3-sec 
               stop:ps1:Svc:5:<SvcName> =Stop based on <SvcName> is not 'Running', PollInt: 5-sec 
               stop:ps1:Branchcache:300 =Stop when CurrentActiveCacheSize exceeds <percent> % of configured BC size limit [default 120%]
               stop:Time:3         =Stop data-collection after 3 minutes elapsed
    Update[:Full|Quick|Force] - update current tss version from latest GitHub release (will not refresh iDNA part in TTT package) [def: Full; Quick will only update differential script changes; Force will force a full update regardless of installed version]
    Version         - shows current tss version: v2020.12.23.2
    WhatIf          - validate TSS command input parameters, check for sufficient free diskspace and free ETL sessions

  TOOLS
    AccessChk       - collect Sysinternals AccessChk log(s), may need adjustments in tss_config.cfg
    Coreinfo        - collect Sysinternals Coreinfo log
    Crash           - to be used at stop, or together with Stop trigger, Caution: this switch will force a memory.dump, open files won't save. Run 'tss off noCrash' after reboot, see KB969028
    DFSmgmt         - enable DFSmgmt console (DfsMgmt.msc) tracing in DfsMgmt.current.log
    Fiddler         - collect Fiddler trace, by default it will NOT decrypt the traffic, ask cx to enable 'Decrypt HTTPS traffic' option, see https://fiddlerbook.com/fiddler/help/httpsdecryption.asp
    GPmgmt          - enable Group Policy Management Console (GPmc.msc/GPmgmt.msc) tracing
    GPresult        - collect GPresult, Auditing and Security log(s)
    Handle[:start|stop|both] - collect handle.exe output at stage Start or Stop [def: Stop]
    iDNA:<PID>|name[:<maxF>:Full|ring|onLaunch] - collect iDNA/TTD dump for PID, service name or unique ProcessName (requires tss_tools_ttt.zip) [defaults: maxF=2048 mode=Full], separate multiple PIDs/names by '/'
    LiveKd[:start|stop|both] - Execute kd/windbg memory dump on a live system at stage Start or Stop [def: Stop], only for Win8.1+
    NetView         - collect Get-NetView infos for diagnosing Microsoft Networking
    Perfmon[:<spec>:<int>] - collect Perfmon -max 1024 log(s), <spec>: choose CORE|BC|Biz|DC|DISK|NC|NET|SQL [def: CORE], Interval: 1-59 sec [def: 30]
    PerfmonLong[:<spec>:<int>] - collect Perfmon -max 1024 log(s), <spec>: choose CORE|BC|Biz|DC|DISK|NC|NET|SQL [def: CORE], Interval: 1-59 min [def: 05]
    PktMon[:Drop]   - collect Packet Monitoring data (on RS5+ / Srv2019), PktMon:Drop will collect only dropped packets
    PoolMon         - collect PoolMon snap at start and stop
    ProcDump:<PID>|<name>[:<N>:<Int>:Start|Stop|Both] - collect N user dumps with ProcDump.exe for process ID or service name or unique ProcessName [defaults: N=3, Int=10 sec, Stop]
                    to combine multiple processes or service names, use '/' separator, i.e.  ProcDump:Notepad.exe/dnscache/WinHttpAutoProxySvc:2
    ProcMon[:Boot|Purge:<N>[:<Filter>]] - collect ProcMon [Bootlog] trace, [Purge:N]: purge older *.pml files, keep number N [def: 9], Filter=name-of-FilterConfig.pmc
    PSR[:<maxsc>]   - default: collect Problem Step Recorder (PSR) screenshots, [def: maxsc=99], starting timedate.cpl, to deactivate use noPSR
    Radar:<PID>|<name> - collect heap RADAR Leak diag (rdrleakdiag) for <process ID> or <service name> or unique <ProcessName>.exe
    RASdiag         - collect trace: Netsh Ras diagnostics set trace enable
    REG[:<spec>]    - collect Registry output, <spec>: choose Hives|802Dot1x|ATP|Auth|BITS|Bluetooth|Branchcache|Cluster|CSC|DAcli|DAsrv|DFS|DCOM|DHCP|DNS|Firewall|GPsvc|Http|HyperV|ICS|LBFO|LDAPcli|MBN|MFAext|NLA|NPS|NTDS|PCI|Proxy|RAS|Rpc|SNMP|Tcp|TLS|UNChard|USB|Webclient|VPN|webClient|WLBS [def: Hives]
    Sddc            - collect HA/Cluster PrivateCloud.DiagnosticInfo infos
    SDP[:<spec>[:noNetadapters|skipBPA|skipHang|skipNetview|skipSddc|skipTS|skipHVreplica|skipCsvSMB]] - collect SDP report, choose SDP <spec>ialty Apps|CTS|Cluster|DA|Dom|DPM|HyperV|Net|Perf|Print|S2D|Setup|SQLbase|SQLconn|SQLmsdtc|SQLsetup|VSS|Mini|Nano|All [def: Net]; to combine more specs or skip-parameters, use '/' as separator i.e.: SDP:Net/HyperV:skipBPA
    SysInfo         - collect SystemInfo (txt based msinfo32)
    SysMon[:<config.xml>] - collect System Monitor (Sysmon) log [def: sysmonConfig.xml]
    Test[:psPing|TraceRt|NsLookup|Http|Ldap|Smb|Wmi|publicIP|psTelnet[:Start|Stop|Both[:<TestDestName>[:<Nr>:<Int>] | <IPaddr>/<Port>]]] - connectivity info, separate multiple Test-scenarios names with '/', [def: psPing, TestPhase: Stop, TestDestName:www.microsoft.com|UserDomain, Nr=5, Int=2]
    Trace[:<N>[:<scenario>[:<fileMode>[:<Byte>]]]] - capture circular NETSH trace, N: bufferSize MB, separate multiple scenario names with '/' [defaults: bufferSize=1024, Scenario=InternetClient, fileMode=circular, truncate Byte=1514 for Ethernet]
                    for available tracing scenarios, type: 'netsh trace show scenarios', [for SrvCORE def: InternetServer], scenario 'Capture' will only sniff
      i.e.: Trace:2048 -or-  Trace:1024:NetConnection -or- Trace:4096:Capture -or- Trace:1024:InternetClient:Circular:128
    TraceChn[:<N>[:<NrKeep>]] - capture chained network sniff, chunk bufferSize MB [def: N=1024, NrKeep=10]
    TraceNM[:<N>[:<Byte>]] - capture requires Netmon NMcap.exe, N: bufferSize MB [def: N=1024, truncate Byte=1514]
    TraceNMchn[:<N>[:<NrKeep>[:<Byte>]]] - chained capture requires Netmon NMcap.exe, N: bufferSize MB [def: 1024, NrKeep=10, truncate Byte=1514]
    TraceWS[:<ifNr>[:<N>[:<NrKeep>[:<Byte>]]]] - WireShark capture, ifNr=interfaceNr, [N: bufferSize MB, def: N=1024, NrKeep=10, truncate Byte=262144]; WS_Filter in tss_config.cfg
       TraceWS requires WireShark dumpcap.exe installed, ifNr to be found with command: "C:\Program Files\Wireshark\dumpcap.exe" -D -M
    Video           - collect ScreenRecorder Video ~6 MB/min, plz use max 1920x1080 (requires .NET 3.5, Feature 'Desktop Experience' on server edition; needs DeCoder or VLC for viewing)
    VMQ             - validate Hyper-V VMQ and RSS settings (USB)
    WFPdiag         - collect trace: netsh wfp capture
    WhoAmI          - collect WhoAmI -all info
    WinUpd          - collect PS Get-WindowsUpdateLog, Merges Windows Update .etl files, (included in psSDP)
    WPR[:<spec>[:skip]] - collect WPR trace on Win8.0+ , <spec>: choose CPU|General|Network|Registry|Storage|Wait [def: General], [:skip] will use -skipPdbGen on w10 2004+; TSS will use Xperf for downlevel Win2008-R2
    Xperf[:<spec>[:<maxF>]] - collect circular Xperf trace, <spec>: choose CPU|Disk|General|Memory|Network|Pool|PoolNPP|Registry|SMB2|SBSL [def: General / Delay, maxF=2048],  alternatively: you may put your specific Xperf command into tss_extra_repro_steps_AtStart.cmd

  MODULES options: [with rOn or <ScenarioName>]
    ADcore          - collect Active Directory Domain Services: Core ETL log(s) (kb2826734)
    ADdiag          - collect Active Directory Diagnostics on DC, running for max 5 minutes, \ADDS\report.html
    ADsam           - collect ActiveDirectory SAM client ETL log(s) (on Win10)
    AfdTcp[:Basic|Full] - collect Afd,TcpIp,NetIO ETL log(s), if :Basic is specified do Basic logging; default:Full
    AppLocker       - collect application control (AppLocker) ETL log(s)
    AppV            - collect Application Virtualization (App-V) ETL log(s) and Registry settings
    ATA             - collect ATAPort ETL log(s)
    BadPwd          - collect User's bad password attempts info from all DCs
    BGP             - collect Border Gateway Protocol (BGP) ETL log(s)
    Bluetooth       - collect Bluetooth ETL log(s)
    CDROM           - collect CD/DVD ETL log(s)
    certCA          - Certification Authority Service Tracing
    certEnroll      - Client Certificate Enrollment Tracing
    CSVspace        - collect cluster CSV_space ETL log(s)
    customETL:<Provider1>/<Provider2> - collect ETL log(s) with list of custom providers, example: customETL:"Microsoft-Windows-DNS-Client"/{1540FF4C-3FD7-4BBA-9938-1D1BF31573A7}
    DCOM            - collect COM,COM+,COMSVCS,COMADMIN,DCOM,DCOMSCM ETL log(s), Reg-settings and SecurityDescriptor info, consider also OLE32
    Dedup           - collect Data Deduplication and Filter ETL log(s)
    DfsR            - collect DFS replication ETL log(s), Eventlog, DFSR log(s)
    EFS             - collect encryped FS ETL log(s)
    Evt[:Sec|Days:<N>] - collect Security Eventlog, default is Sys+App EventLogs; [def. days back for TXT/CSV convert: Days:10]
    FSLogix         - collect FSLogix log and registry outputs
    FSRM            - collect FSRM drivers ETL log(s)
    FWmgr           - collect Firewall Manager ETL log(s), consider also collecting WFP
    GPsvc           - collect client Group Policy GPsvc.log, netlogon.log
    HttpSys         - collect HTTP.SYS ETL log(s), i.e. on IIS server
    ICS             - collect ICS SharedAccess ETL log(s) and SharedAccess Reg key
    IPsec           - collect IPsec ETL log(s)
    iSCSI           - collect iSCSI ETL log(s)
    LBFO            - collect LBFO teaming ETL log(s) (included in HypHost / WNV) 
    LDAPcli[:<ProcName>.exe] - collect LDAP client process ETL log(s), [def: <ProcName>.exe = svchost.exe]
    LDAPsrv         - collect LDAP server NTDSA ETL log(s)
    LockOut         - find User Account Lockout info from all DCs (EventIDs 4625,4771,4776), requires Domain Admin account
    MDM             - collect DeviceManagement EventLogs and reg.keys
    MPIO            - collect MPIO, MsDSM, Storport, ClassPnP ETL log(s)
    MiSpace         - collect MiSpace ETL log(s) and MountMgr reg.keys
    MsDSM           - collect MsDSM ETL log(s)
    MUX             - collect NetworkController MUX Microsoft-Windows-SlbMux ETL log(s) (in SDN)
    NCHA            - collect NetworkController.HostAgent ETL log(s) (in SDN / WNV)
    NDIS            - collect NDIS ETL log(s)
    NdisWan         - collect NdisWan ETL log(s)
    Netlogon        - collect Netlogon debug log 
    NFC             - collect Near-field communication ETL log(s)
    NetworkUX       - collect Network UI User Interface ETL log(s)
    NLA             - obsolete, -> plz use NCSI scenario
    NTFS            - collect NTFS driver ETL log(s)
    OLE             - collect OLE32 ETL log(s), consider also DCOM
    OpsMgr          - collect OpsMgr ETL and EventLogs
    Outlook         - collect Outlook ETL log(s), see kb2862843, start tss - restart Outlook - repro - stop tss
    PCI             - collect PCI, setupapi and msinfo32 infos
    PNP             - collect PlugAndPlay PnP ETL log(s) and info
    PortProxy       - collect PortProxy IP Helper Service ETL log(s), can be used i.e. in combination with Test:psTelnet:Both:IPaddr/TCPportNr
    PowerShell      - collect PowerShell ETL log(s) and EventLogs, incl. WinRM
    Print           - collect Print Service ETL- and EventLogs
    ProcTrack[:module|thread] - collect process tracking ETL, [Module: with Module load activity | Thread: with Thread+Module load activity]
    Profile         - Client Profile, WinLogon, GroupPolicy, DClocator ETL log(s) 
    RAmgmt          - collect RemoteAccess Management ETL log(s)
    RasMan          - collect RasMan service ETL log(s)
    Rpc             - collect RPC, RpcSs services and DCOM ETL log(s)
    SCM             - collect Service Control Manager ETL log(s) of process services.exe
    SCCM            - collect SCCM System Center Configuration Manager debug ETL log(s)
    SmartCard       - collect SmartCard/Windows Hello for Business (WHfB) ETL log(s), this is only a subset of Auth; prefer using Auth switch for authentiction issues
    SNMP            - collect Simple Network Management Protocol (SNMP) ETL log(s) and registry output
    Storage         - collect Storage drivers ETL log(s)
    StorageMig      - collect Storage Migration Service and SM Proxy Service ETL log(s)
    StorageReplica  - collect Storage Replica ETL log(s)
    StorageSpace    - collect Storage Space ETL log(s)
    StorPort        - collect disk/StorPort ETL log(s)
    Tapi            - collect Tapi (Print FaxSrv) ETL log(s) and C:\Windows\tracing data
    TaskSch         - collect Task Scheduler ETL log(s)
    TLS             - collect Schannel TLS/SSL ETL log(s), CAPI2 Evt-Log
    UEV             - collect User Experience Virtualization ETL log(s)
    USB             - collect Universal Serial Bus (USB) ETL log(s)
    VDS             - collect VDS services ETL log(s)
    VirtualFC       - collect Virtual FC info ETL log(s)
    VML[:verbose]   - collect Hyper-V host VmlTrace ETL log(s) [def: Standard, Verbose will restart the Hyper-V service] + FRuti.exe log
    VmSwitch        - collect VmSwitch ETL log(s) (included in HypHost and SDN)
    VSS             - collect VolSnap and Volume Shadow Copy Service (VSS) ETL log(s)
    WCM             - collect Windows Connection Manager (WCM) ETL log(s)
    WebIO           - collect WinInet, WinHTTP, WebIO ETL log(s), i.e. for WebClient or Outlook
    WinNAT          - collect WindowsNAT ETL log(s)
    WinRM           - collect Windows Remote Management (WinRM) ETL log(s)
    WmbClass        - collect WmbClass,NDISuIO,PnP ETL log(s)
    WMI             - collect WMI services ETL log(s)
    WSB             - collect Windows Server Backup modules ETL log(s)
    WWAN            - collect WWAN Wireless mobile Broadband MBN ETL log(s) (see also MBN)

  [for cliOn/srvOn  -only] Collection options:
  usage on original t.cmd: T [cliOn|srvOn] [persistent][capture][core][verbose] [csv][cluster][hyperv] [circ:N] [driver:flags:level]
    capture         - [downlevel t.cmd] in combination with cliOn, srvOn: enable packet capture (Windows 7 / 2008 R2 or newer)
    circ:N          - generate circular log(s) of size N megabytes (default circular buffer size is 250 MB per log)
    cluster         - collect Cluster EventLogs
    csv             - generate cluster CSV component traces
    hyperv          - collect Hyper-V EventLogs
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
  usage: TSS snapshot [noCab] [noBin]

  No* OPTIONS:
    noAsk           - do not ask about good/failing scenario text input before compressing data
    noClearCache    - do not clear DNS,NetBios,Kerberos,DFS chaches at start
    noCluster_GetLogs - don't collect cluster infos / validation reports
    noCab           - do not compress/zip trace data
    noCrash         - do not run Crash after reboot again when using 'tss off noCrash'
    noGPresult      - do not run GPresult, used to override setting in preconfigured TS scenarios
    noSDP           - do not gather SDP report, i.e. when using script in scheduled tasks
    noPersistent    - do not use predefined Persistent in scenarios
    noPoolMon       - do not run PoolMon at start and stop
    noProcMon       - do not run ProcMon, used to override setting in preconfigured TS scenarios
    noPSR           - do not run PSR, used to override setting in preconfigured TS scenarios
    noRestart       - do not restart associated service
    noSound         - do not play attention sound
    noUpdate        - do not check online for latest TSS version on Github, no AutoUpdate
    noWait          - do not wait at stage: Press ANY-Key to stop, use 'TSS OFF'
    noVideo         - do not run Video, used to override setting in preconfigured TS scenarios
    noXray          - do not start Xray troubleshooter

  You can lookup netsh trace scenarios here: dbg/wpp : HKLM\System\CurrentControlSet\Control\NetDiagFx\Microsoft\HostDLLs\WPPTrace\HelperClasses
 	 - and normal scenarios here: HKLM\System\CurrentControlSet\Control\NetTrace\Scenarios	
  All network traces *packetcapture|NetTrace|capture|sniff*.etl files can be converted into the corresponding .pcap files using RFLcheck Etl2Pcap
  Short link to tss download: https://aka.ms/getTSS
 
  Tss SCENARIOS predefined : (no 'Tss Off' is required, use ANY-key to stop, run: tss <ScenarioName>), all scenarios include 1-GB network trace, PSR and SDP
    802Dot1x        -+ scenario: wired LAN 802.1x,Afd,TcpIp,NDIS,RadioManager,RASdiag,TLS,WCM ETL log(s), Procmon Video; for WiFi wireless please choose WLAN
    Auth[:Basic|Full] -+ scenario: Authentication ETL log(s) (:Basic= LSA Ntlm_CredSSP Kerberos Kdc ; Full= + NGC BIO Sam Ssl CryptNcryptDpapi WebAuth Smartcard CredprovAuthui), Security.evt, WFPdiag TLS GPresult DCLocator NetLogon WinLogon Procmon Video [default=Full]
    BITS            -+ scenario: Background Intelligent Transfer Service (BITS) client logs
    Branchcache[:<percent>] -+ scenario: Branchcache+BITS ETL log(s), Perfmon:BC, <percent> used with Stop trigger means actual size is <percent> % over configured limit [default 120%]
    Container       -+ scenario: Afd,TcpIp,WFP,HNS,Vfp,WinNAT ETL log(s), collect PowerShell based Docker/Containers info
    CSC             -+ scenario: OfflineFiles infos, CSC database dump, Procmon
    DAcli           -+ scenario: DirectAccess client info, scenario=DirectAccess,Netconnection, DA client config, WFPdiag, TLS, tss_DAclient-collector.ps1 at TSS OFF
    DAsrv[:Restart] -+ scenario: DirectAccess server RASdiag,WfpDiag ETL log(s), trace scenario=DirectAcces,WFP-IPsec, get netlogon.log, TLS, RAmgmt, Restart= RaMgmtSvc service
    Defender[:ana[:v|h|l|c|i|b|a|v|t|d|z|k[:<Min>]]] -+ scenario: collect MDATPClientAnalyzer.ps1, MpCmdRun.exe -getfiles, Defender/Operational EventLogs and ATP Reg.keys; [:ana= run MDATP analyzer with option -v = def, <Min> = minutes to run]
    DFScli          -+ scenario: DFS client logs, RDR ETL log(s), GPresult, Procmon
    DFSsrv[:Basic|Full] -+ scenario: DFS server ETL log(s) and Eventlog, Perfmon:NET, :Basic will skip DFSdiag results [default=Full], (for DFS replication issues, consider also DfsR switch)
    DHCPcli         -+ scenario: Boot/persistent DHCP client ETL log(s) and DHCP Reg info, DNScli, Procmon, persistent; after Reboot run 'TSS OFF'; add noPersistent for instant logging
    DHCPsrv         -+ scenario: DHCP server Eventlog, ETL log(s) PsCmdlets 'netsh dhcp server' info, includes DNScli, Perfmon:NET
    DNScli          -+ scenario: DNS client ETL log(s), Eventlog
    DNSsrv[:verbose] -+ scenario: DNS server DNScmd PsCmdlets, ETL log(s) and Eventlog, Perfmon:NET, [if verbose: Flags=FFFFFFFF]
    Docker          -+ scenario: Afd,TcpIp,WFP,HNS,Vfp,WinNAT ETL log(s), collect PowerShell based Docker/Containers info
    Firewall        -+ scenario: Firewall ETL log(s), Firewall REG settings and Eventlog
    General         -+ scenario: General purpose logs, Procmon, Video, wait for user input ANY-key
    HypHost         -+ scenario: LBFO, HyperV-Host, HyperV-VMbus, Vmms ETL log(s), VmWp,VmConfig, VMM-debug
    HypVM           -+ scenario: HyperV-VirtualMachine ETL log(s)
    IIS             -+ scenario: IIS server logs, HttpSys ETL log(s)
    IPAM            -+ scenario: IPAM ETL log(s) and IPAM specific EventLogs
    MBAM            -+ scenario: Microsoft Bitlocker Administration and Monitoring ETL log(s)
    MBN[:verbose]   -+ scenario: Mobile Broadband Network/LTE: Afd,TcpIp,DNScli,GPresult,NetworkUX,RasMan,RadioManager,RASdiag,VPN,WFP,WfpDiag,WCM ETL log(s), Firewall info, Netsh Ras diag, Trace wwan_dbg [if verbose: +,wireless_dbg], Video
    Miracast        -+ scenario: Miracast or 'Wi-Fi Direct', Video
    MsCluster       -+ scenario: MsCluster related logs: CSV,NetFt,LBFO,Storport ETL log(s), Perfmon:CORE, ClusterLog, SDP:cluster
    NCSI            -+ scenario: includes wireless_dbg,internetclient_dbg with NLA logging, Microsoft-Windows-PrimaryNetworkIcon, WFPdiag, GPresult, Procmon, Video, you may run tss_NCSI_detect script
    NetIO           -+ scenario: Afd,TcpIp,NDIS,NetIO,WFP ETL log(s)
    NFScli          -+ scenario: NFS client ETL log(s), GPresult, Procmon, Video
    NFSsrv[:perm]   -+ scenario: NFS server cmds PsCmdlets, ETL log(s) and EventLogs, Perfmon:NET, 'perm' will ask for NFS Folder/File path
    NLB             -+ scenario: Afd,TcpIp,NetIO,NLB ETL log(s), NLB/Diagnostic Events, WLBS display, msinfo32
    NPS[:MFAext]    -+ scenario: NPS RASdiag ETL log(s), netsh nps tracing, TLS, Securtiy EvtLog, [optional :MFAext]
    PerfDisk[:<Drive>:<BlockSize>:<Sec>:<FS>] -+ scenario: DriveLetter [D], BlockSize(K) [1024], Duration(Sec) [300], FileSize [10G] for DiskSpeed tests using diskspd.exe
    PerfSMB:Server[:<Drive>]|Client:<remoteServer>[:<FileSize>:<FileNr>] -+ scenario: run Robocopy Performance; 1. first start it on FileServer PerfSMB:Server def: <Drive>=C, then 2. start it on Client, def: <FileSize>=10MB, <FileNr>=2
    PerfTCP:Receiver|Sender:<rec-IP>[:<BuLength>:<Duration>] -+ scenario: run TCP Performance tests using NTttcp; 1. first start it on remote Receiver PerfTCP:Receiver:<rec-IP>, then 2. start it on Sender PerfTCP:Sender:<rec-IP>, def: <BuLength>=128 kB, <Duration>=60 sec, plz use same values on Receiver and Sender
    Proxy           -+ scenario: WebIO,WinInet,WinHTTP,Winsock ETL log(s), NCSI, Proxy settings and related Registry settings, Procmon, Video
    RAS[:Hang]      -+ scenario: Remote Access Server RASdiag,WFPdiag ETL log(s), TLS, Perfmon:NET, trace scenario=VpnServer; [:Hang will collect at stop Procdumps of Rasman/RemoteAccess/RaMgmtSvc/IKEEXT/BFE/RaMgmtui.exe]
    RDMA[:Basic|Full] -+ scenario: RDMA ETL log(s), EventLogs, SMB client [default=Basic]
    RDScli          -+ scenario: Remote Desktop (RDP) client ETL log(s), QWinSta, REG settings, Env-var, GPresult, EventLogs, Video; add Evt:Sec to collect Security Eventlog
    RDSsrv          -+ scenario: Remote Desktop (RDP) server ETL log(s), QWinSta, REG settings, Env-var, GPresult, EventLogs incl Sec.EvtLog
    SBSL            -+ scenario: Slow Boot/Slow Logon: Profile,Netlogon,WinLogon,GroupPolicy,DCLocator,GPresult,GPsvc,Auth,WPR:Wait ETL log(s); if persistent: after Reboot run 'TSS OFF'
    SDN             -+ scenario: SDN Infra Logs, see SDN\SDNLogCollect.ps1, Specify one of the NC VM and collect Logs from NC, MUX and Gateway VMs
    SdnNC           -+ scenario: SDN NetworkController,HttpSys,MUX,LBFo,NCHA,TLS,VmSwitch ETL log(s), consider to add WFP for GW
    SMBcli          -+ scenario: SMB, DFS client ETL log(s), CliOn/RDR, GPresult, Procmon
    SMBsrv          -+ scenario: SMB server ETL log(s), SrvOn, Procmon, Perfmon:NET
    SQLtrace        -+ scenario: SQL server related logs and TraceChn, Perfmon:SQL, SDP:SQLbase
    UNChard         -+ scenario: UNC-hardening: boot/persistent logs, Profile,Netlogon,WinLogon,GroupPolicy,DCLocator,GPresult,GPsvc,Auth ETL log(s) Procmon:Boot; after Reboot run 'TSS OFF'
    VPN[:dbg]       -+ scenario: Afd,TcpIp,NetIO,RASdiag,VPN,WFP,WFPdiag ETL log(s), VpnClient, Procmon, Video; [:dbg will collect scenario=VpnClient_dbg]
    WebClient[:Adv|Restart] -+ scenario: WebClient logs, WebIO, Proxy, TLS ETL log(s), GPresult, Procmon, Video [def: Basic, Restart= ~ service, Adv= incl. iDNA, which requires tss_tools_ttt.zip]
    WFP             -+ scenario: Afd,TcpIp,NetIO,WFP Windows Filtering Platform,BFE (Base Filtering Engine), includes WfpDiag: netsh wfp capture, Procmon, Video
    Winsock         -+ scenario: Afd,TcpIp,NDIS,NetIO,Winsock ETL log(s)
    WIP             -+ scenario: Windows Information Protection diagnostic, AfdTcp, AppLocker, Firewall, WFP, WhoAmI, Procmon, Video
    WLAN            -+ scenario: wireless 802.1x,Afd,TcpIp,NDIS,NetworkUX,RadioManager,RASdiag,TLS,WCM ETL log(s), Procmon Video for WiFi wireless connection
    WNV[:capML]     -+ scenario: Network Virtualization (WNV) ETL log(s), Afd,TcpIp,LBFo,NCHA,VmSwitch, network trace Virtualization,InternetClient; if capML captureMultilayer=yes
    WorkFolders[:Adv] -+ scenario: WorkFolders ETL log(s) on Srv and Client, Perfmon, Video, if :Adv collect Advanced-Mode with restart of service
     - more options for controlling predefined scenarios: noSDP,noPSR,noCab,noPersistent,noProcmon,noPoolMon,noGPresult,noRestart,noSound,noCrash,noClearCache,noAsk,noUpdate,noWait,noVideo see also tss_config.cfg

 Disabling Tracing:
  usage: TSS off [noCab] [noBin] [noSDP] [Discard] [Debug]
    off          - turn off tracing
    noCab        - do not compress/zip trace data
    nobin        - do not gather system binaries matching the captured traces on downlevel OS

 TSS v2020.12.23.2. Check for updates on: http://aka.ms/TssTools - Download: http://aka.ms/getTss
      or run 'TSS update'
  -> see 'TSS /help' for more detailed help info
  -> Looking for help on specific keywords? Try e.g.: tss help <my_keyword>
```


Predefined parameters in _tss_config.cfg_ 

```
@ tss_config.cfg v2020.12.23.2: CONFIGURE below variables for granular controlling TSS behaviour - be sure that modified lines have no *trailing space* characters
@ Disk and folder path of data collection results, i.e. D:\MS_DATA - only use local disk drive letter, NOT a Onedrive or redirected Folder!
_DataDisk=C
@ this results in DirWork=C:\MS_DATA
@
@ Setting defaults: all ETL files will be limited to max size of _EtlBuf (MB), circular network trace is limited to _TraceBufferSize (def: 1GB), Procmon will purge older files
_EtlBuf=1024
_TraceBufferSize=1024
_TracefileMode=circular
_ProcMonSpec=Purge
@
@ For using 'Stop:Log' trigger specify path of monitored Logfile, optional Pollinterval-in-sec (def: Log-pollInt=8 sec), be sure the SearchString is not already found in current logFile at start of TSS
_StopSearchString=Access Denied
_LogFilePath="C:\tss_Tools\tss_StopLog_EntryFound.tmp"
_PollIntervalInSec=8
@
@ For using 'Stop:PS1' trigger in tss_stop_condition_script.ps1
_PortLoc=135
_PortDest="135/445"
_SvcName="LanmanWorkstation"
_ServerName="LocalHost"
_ShareName="Contoso-Share"
_DomainName="Contoso"
_ProcessName="Notepad"
_BCpercent=180
_BCdatFilesLimit=1024
_ErrorLimit=1
@
@ next 3 variables control the frequency of purging chained Network Traces or Procmon logs
_PurgeNrFilesToKeep=10
_PurgePollIntervalSec=10
_PurgeTraceChn=1
@ for Wireshark, specify a network interface number, to be found with '"C:\Program Files\Wireshark\dumpcap.exe" -D -M' command, example: _WS_IF=1
_WS_IF=
@ for Wireshark, specify a dumpcap filter condition, see https://wiki.wireshark.org/CaptureFilters , i.e. _WS_Filter=-f "^^(tcp dst port 135 or tcp port 445 or udp dst port 69^^) and host 10.190.1.12"
_WS_Filter=
@
@ next 3 variables are for 'AccessChk', please add a) your missing 'ShareNames', b) local folder paths on this server for 'Share root folders', and c) one or more existing full path 'FilePaths' to relevant folders or files plz DO NOT append *.*
_ShareNames=C$ D$ E$ F$ DATA USERS
_FolderPaths=C:\ C:\DFSroots D:\ E:\ F:\ D:\Shares\DATA D:\Shares\USERS
_FilePaths=C:\DFSroots\ D:\Shares\DATA\folder1\testfile.xlsx
@
@ ex: _EventlogName=Microsoft-Windows-PowerShell/Operational and _Stop_EventID=40962/40961 are used by  'stop:Evt:ID:Other:<EvtLogname>:<EventData>[:Partial]' to stop i.e. on multiple eventIDs and EventData strings. Note: Eventlog names with space/blank character need to be specified in this config file with quotes, ex: "DNS Server"; 
@     _Stop_EventData must match a complete string within XMLview <Data> </Data>, put whole multi-word string within quotes - or append :Partial
@     _CheckIntInSec defines how often the Eventlog will be scanned
_EventlogName=
_Stop_EventID=
_Stop_WaitTimeInSec=0
_Stop_EventData=0
_CheckIntInSec=2
@
@ write an EventID 999 into remote hosts eventlog to stop TSS at remote host, if started with 'stop:Evt:999' or any other ID(s); comma separated list like =host1,host2
_WriteEventToHosts=
_Remote_Stop_EventID=999
@
@ TSS tasks/parameters that will be skipped on local PC at 'tss OFF' or using 'stop:Evt' when EventID created by source 'TSS' is found; comma separated list
_SkipExecutionList=LiveKd,_Cluster_GetLogs
@
@ set _ClusterLog=0 to skip collect cluster log; per default we collect already cluster info via PS script tss_Cluster_GetLogs.ps1
_ClusterLog=0
_Cluster_WriteEventToHosts=1
_LiveDmp_analytic=0
@
@ to suppress acoustic sound output at some stages that need attention, set _noSound=1
_noSound=0  
@
@ To turn off waiting for ANY/key in TS_Scenarios, set _noWait=1
_noWait=0
@
@ To turn off TSS version check, set _noVerCheck=1
_noVerCheck=0
@
@ To turn off SDP,Procmon,PSR,GPresult,Video,Persistent logging in TS_Scenarios, set _no<Variable>=1
_noSDP=0
_noProcmon=0
_noPSR=0
_noGPresult=0
_noVideo=0
_noPersistent=0
@
@  To check for Get-SpeculationControlSettings, set _SpeculationControl=1
_SpeculationControl=0
@
@ SCCM enable debug logging when using 'Branchcache' scenario, set _SCCMdebug=1, alternate method: use TSS switch SCCM
_SCCMdebug=0
@
@ VmlTrace start parameters, i.e. for VmlTrace.exe /m a /f all all /i
_VmlTraceCmd=/m all /f all all /u /z 600 /i
@
@ custom ETL tracing. Add a '/' separated list of Providernames or GUIDs, i.e. _customETL="Microsoft-Windows-DNS-Client"/{1540FF4C-3FD7-4BBA-9938-1D1BF31573A7}
_customETL=
@
@ Connectivity Test[:psPing|TraceRt|NsLookup|Http|Ldap|Smb|Wmi|publicIP|psTelnet[:Start|Stop|Both[:TestDestName[:Nr:Int]]]]
_TestPhase=Stop
_TestURL=www.microsoft.com
_TestDestName=
_psPingNr=5
_psPingInt=2
@
@ define NetLogon DbgFlag, i.e. less verbose: 2080FFFF
_NetLogonFlag=2FFFFFFF
@
@ controlling Branchcache/BITS
_RunPS_BCstatus=1
_BITSLOG_RESET=0
_BITSLOG_RESTART=1
@
@  To perform no RunDown in AfdTcpIp ( netsh int TCP rundown ) on Win10-RS5+, set _RunDown=0
_RunDown=1
@
@  Specify Xperf Pool Tag
_XperfTag=NDnd
@
@ to define one save location in C:\MS_DATA\0000 and overwrite data at each new run / or 'tss off discard'
_OverWrite=
@
@  To automatically restart a new run after Stop condition was hit
_Autorestart=0
@
@ To enable Full Auth on servers (ServerNT) or DC's (LanmanNT), set _EnableSrvAuth=1
_EnableSrvAuth=0
@
@ Xperf, define up to 4 PoolTags like NDnd or TcpE+AleE+AfdE+AfdX or AfdB+AfdC+Afdl+AfdP
_XperfTag=TcpE+AleE+AfdE+AfdX
@
@ Eventlog size, 104857600 is 100MB for setting in wevtutil sl /ms:
_EvtxLogSize=104857600
@
@ for sending a message
_MsgUser=%username%
_MsgServer=%computername%
_MsgMessage="[Info]_TSS_stopped_on %computername%"
_MsgWait=2
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
_StopSearchString=Access Denied
_LogFilePath="C:\tss_Tools\tss_StopLog_EntryFound.tmp"
_PollIntervalInSec=8
```
Read the file tss_StopTokenFile._tmp for testing your config.

B)	You want to run extra commands right after the script begins to start running?
No problem, just edit the included batch file tss_extra_repro_steps_AtStart.cmd and modify it for your own needs.
This batch file will be executed at each start of 'tss Ron' =ReproOn.

C)	You want to run extra commands before the script ends repro?
No problem, just edit the included batch file tss_extra_repro_steps_AtStop.cmd and modify it for your own needs.
This batch file will be executed at end of repro and before 'tss OFF' =ReproOFF, or in combination with any predefined tss scenario.

D)	You want to stop tracing based on specific conditions?
No problem, just run TSS with STOP:PS1:<condition> or edit the included batch file tss_stop_condition_script.ps1 and modify the custom module for your own needs (i.e. by default: check if File share is available) and invoke tss with stop trigger STOP:PS1:custom.


When using the **Persistent** switch, the settings will be active after each reboot, and you will stop data collection using 'Tss OFF', unless you decide to Stop and then Remove it by running following command, when you are finished with all of your troubleshooting:

` C:\tools> Tss Remove `

**Notes/hints:**
-	Some parameters are mutually exclusive: don’t combine [capture], [trace] or [traceChn]

-	If you want to use the SDP switch with a specialty switch, just supply your SDP speciality: 
default SDP category= NET, choose [Apps|Cluster|S2D|CTS|Dom|HyperV|Net|Perf|Print|Setup|SQLbase|SQLconn|SQLmsdtc|SQLsetup|VSS|Mini|Nano|Remote|RFL|All]

-	In case of unforeseen errors, please be sure to stop tracing **“tss off”** before starting a new trace session. Also try opening a new CMD window and running **“tss remove”** if you can’t recover (new start of tss .. fails, stop command  "tss off" also fails)

**TSS FAQ**

Q1: Does TSS change any setup/configuration of my/customer system?

A1: NO, but in some scenarios a REGISTRY setting is required for enabling debug logging, so it sets the necessary key at start and reverts it to default at end of TSS data-collection.
 
Q2: Does it put additionally load on the server?

A2: No, but to some degree, yes, certainly it may take about ~1% more CPU time, so if  the CPU is maxxed already to 99.5%, there is a chance to reach 99.9% - but does it make a real difference? No.
 
Q3: We cannot reproduce our issue when we have TSS running, any explanation why?

A3: perhaps Yes, because TSS clears/deletes all cached information at start. TSS also starts network capture in promiscuous mode, which changes the NIC default behavior; another factor might be different timing of involved modules.
 
Q4: Script seems to hang, no progress for a long time

A4: make sure you did not click inside the script window. Hit any key to continue script processing
 
Q5: How does "persistent" functionality works in various TSS scenarios?

A5: If a scenario includes the persistent functionality by default, or "persistent" switch is specified in TSS command, TSS will activate the given ETLs that are a part of the given scenario in the next reboot along with Procmon, NETSH traces, WPR or Xperf. So after running TSS command in that fashion, it won't ask you to reproduce the issue even though you specify scenario names. After rebooting and reproducing the problem, the TSS OFF command should be run manually.
 
Q6: Xperf doesn't start with an error "Xperf: error: NT Kernel Logger: Cannot create a file when that file already exists. (0xb7)."

A6: Xperf and Procmon (and ADdiag) use the same logger session "NT Kernel Logger" and that prevents Xperf to start properly. Please add noProcmon switch in the TSS command if you intend to collect Xperf or ADdiag traces.

Q7: SBSL scenario: Xperf WPA analysis doesn't show 'CPU Usage Precise' graph in Xperf_SBSL.etl if Xperf is started together with ProcMon.

A7: Avoid running two "NT Kernel Logger" instances together , see Q6.
 
Q8: In some cases, network trace collected by TSS may not include network packets or misses a good amount of them.

A8: This might happen especially on busy servers. In such cases please consider using the TraceWS switch. That switch will collect network traffic by using Wireshark if it's already installed on the client/server:
 
   TraceWS[:<ifNr>[:<N>[:<NrKeep>[:<Byte>]]]] - WireShark capture, ifNr=interfaceNr, [N: bufferSize MB, def: N=1024, NrKeep=10, truncate Byte=262144]; WS_Filter in tss_config.cfg
       TraceWS requires WireShark dumpcap.exe installed, ifNr to be found with command: "C:\Program Files\Wireshark\dumpcap.exe" -D -M
 
Q9: In some cases, TSS may hang at stage psSDP Best Practice Analyzer BPA

A9: You can skip this stage with parameter TSS SDP:Net:skipBPA; Please zip and upload C:\MS_DATA (including SDP log file stdout.log in root folder, or with .\get-psSDP in folder of tss_tools)

Q10: Do I need to worry about diskspace or anything else when running tss for a longer time?

A10: All tss output is captured in ring-buffers, so you can run it for a very long time if needed.
 
Q11: Sometimes network trace collected by TSS ( _packetcapture_ ) may not include network packets.

A11: This could happen at the very first run of TSS (including  Netsh trace); running it the second time seems to take care.


**Revision History**

See https://github.com/CSS-Windows/WindowsDiag/blob/master/ALL/TSS/revision-history.txt 

**Additional Infos**

For customers: To download files from MS workspace, login with your MS workspace credentials, or see KB article 4012140: 

  4012140 How to use Secure File Exchange to exchange files with Microsoft Support 
  https://support.microsoft.com/en-US/help/4012140 

