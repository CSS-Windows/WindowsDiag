# UXTrace

UXTrace is a uniformed tool to collect traces and logs in customer environment. You can collect all diagnostic traces below at the same time and flexibly.

# Supported Tools

- Logman(WPP/ETW/TraceLogging(Telemetry) traces)
- WPR(Windows Performance Recorder)
- Procmon(Sysinternal tool)
- Perfmon(Performance log)
- Netsh(Packet capturing and scneraio trace)
- PSR(Problem Step Recorder)
- TTD(Time Travel Debugging)

# Requirements
- Windows 8.1/Windows Server 2012 R2 or later
    - Note1: WPR is not supported on Win8.1/WS2012R2(you cannot use -wpr)
    - Note2: WPR with boottrace is supported form Windows 10 RS3(you cannot use '-SetAutoLogger -WPR' on Win10RS2 or earlier version)
    - Note3: -TTD is supported from Windows10 RS5


#What UXTrace can do
- Capture ETW trace(-Start -<TraceName>)
- Capture WPR(-Start -WPR <ProfileName>)
- Capture Procmon(-Start -Procmon)
- Capture packet with netsh and also scenario trace netsh is support (-Start -Netsh / -Start -NetshScenario <ScenarioName>)
- Capture TTD(-TTD [PID|<ProcessName>|<ServiceName>]
- Capture multiple traces(ETW/WPR/Procmon/Netsh/PSR/Perfmon) at the same time
- Set autologger for ETW/WPR(boottorace)/Procmon(bootlogging)/Netsh(persistent)
- Delete autologger setting(-DeleteAutologger)
- Start performance log(-Start -Perf)
- Start PSR(Problem Steps Recorder)(-Start -PSR)
- Collect component specific log(-CollectLog <ComponentName>,<ComponentName>,...)
- Set WER setting(-Set WER)
- Set SCM Trace(-Start -SCM -NoWait)
- Create a bat file for the traces to run traces on earlier version like Windows Server 2012 and Win7(-CreateBatFile)
	
#Others
- UXTrace can run with nowait mode(-NoWait)
=> command prompt returns immediately
- You can change log folder(-LogFolderName)
=> By default, logs are saved in 'MSLOG' folder on desktop
- You can specify exe path for Procmon.exe(-ProcmonPath)
- Compress log folder after stopping traces(-Compress)
- Delete log folder after compressing(-Delete)
=> This option is supposed to use with -Compress
- To capture multiple traces and save the data to one etl file, not multiple log files, you can use '-AsOneTrace' switch(-AsOneTrace)
- List supported traces in UXTrace(-List)
- List supported component log(-ListSupportedLog)
- Show current trace status(-Status)

#Usage

##Start traces
1. You can start trace with '-Start'. This option is used for scenario where you can reproduce the issue immediately.(start trace -> repro -> stop trace)
```
.\UXTrace.ps1 -Start -AppX -StartMenu -COM
```
	
2. If you want to start traces but let the prompt returned, you can use -Nowait. This option is intended for a scenario where you cannot repro the issue intentionally and need to wait for next occurrence with trace enabled.(Start trace -> wait for repro -> Stop trace after repro)

```
.\UXTrace.ps1 -Start -AppX -StartMenu -COM -NoWait
// Prompt returns immediately then wait for repro
.\UXTrace.ps1 -Stop
```

##Start WPR 
1. You can start WPR from UXTrace with '-WPR <ProfileName>'.
```
.\UXTrace.ps1 -Start -WPR General
```
Currently below profile is supported
```
.\UXTrace.ps1 -Start -WPR Network
.\UXTrace.ps1 -Start -WPR Graphic
.\UXTrace.ps1 -Start -WPR XAML
```

2. You can set Boottrace for WPR by setting '-Autologger' in case need to start log from system boot
```
.\UXTrace.ps1 -SetAutoLogger -WPR General
```

##Start Procmon
1. Start capturing procmon log
```
.\UXTrace.ps1 -Start -Procmon
```
2. By default, uxtrace searches desktop and under 'c:\program files' for location of procmon.exe. In case customer don't want to place the procmon.exe to desktop, you can use this option to set procmon path.
```
.\UXTrace.ps1 -Start -Procmon -ProcmonPath C:\temp
```
3. In case you use -ProcmonPath with -SetAutologger, also need to specify -ProcmonPath when you stop autologger.
```
.\UXTrace.ps1 -SetAutologger -Procmon -ProcmonPath C:\temp
Restart-Computer
.\UXTrace.ps1 -StopAutologger -ProcmonPath C:\temp
```
##Capture packet
1. You can start capturing packet with '-Netsh' option
```
.\UXTrace.ps1 -Start -Netsh
```
##Start multiple traces at the same time
This would be most common usage in actual field operation. UXTrace exists to provide this scenario. You can start multiple diagnostic traces and tools at the same time.

1. To start multiple traces at the same time, you can just set all options you want to capture. This example shows how to start appx, startmenu and com traces and also wpr with general profile, procmon, packet capture(-netsh), and PSR(problem steps recorder). In addition to this, you can get OS basic log with -Basiclog.
```
.\UXTrace.ps1 -Start -AppX -StartMenu -COM -WPR General -Procmon -Netsh -PSR -Basiclog
```

##Start network scenario trace
1. The scenario trace can be started with -NetshScenario <ScenarioName>. The supported 'ScenarioName' is listed with -ListSupoortedNetshScenario.
```
.\UXTrace.ps1 -Start -NetshScenario <ScenarioName>

Ex: .\UXTrace.ps1 -Start -NetshScenario InternetClient_dbg
```
Supported 'ScenarioName' can be listed with -ListSupoortedNetshScenario
```
.\UXTrace.ps1 -ListSupoortedNetshScenario

Supported scenarios for -NetshScnario are:
	  - dhcp_wpp
	  - dns_wpp
	  - dot3_wpp
	  - InternetClient_dbg
	  - InternetClient_wpp
	  - InternetServer_dbg
	  - InternetServer_wpp
	  - ipsec_dbg
	  - nat
	  - nat_dbg
	  - ndis_wpp
	  - netsec
	  - netsec_dbg
	  - nid_wpp
	  - provisioning
	  - SmbClient_wpp
	  - SmbServer_wpp
	  - VpnClient
	  - VpnClient_dbg
	  - VpnClient_dbgEx
	  - wcn_dbg
	  - wcn_wpp
	  - WirelessDisplay
	  - wireless_dbg
	  - wlan_dbg
	  - wlan_wpp
	  - wns_client
	  - wns_dbg
	  - wwan_dbg
	  - wwan_wpp
```

2. You can also start multiple scenario trace by specifying comma-separated scenario name.
```
.\UXTrace.ps1 -Start -NetshScenario <ScenarioName,ScenarioName,...>
Ex: .\UXTrace.ps1 -Start -NetshScenario wlan_wpp,wlan_dbg,wireless_dbg
```
3. Start scenario trace without capturing packet(-NoPacket)
```
.\UXTrace.ps1 -Start -NetshScenario <SenarioName> -NoPacket

Ex: .\UXTrace.ps1 -Start -NetshScenario InternetClient_dbg -NoPacket
```
4. List supported scenario trace(-ListSupportedNeshScenario)
```
.\UXTrace.ps1 -ListSupoortedNetshScenario
Supported scenarios for -NetshScnario are:
  - dhcp_wpp
  - DirectAccess_DBG
  - dns_wpp
```
##Capture TTD(-TTD)

**Requirements**
- This option is supported from Windows 10 RS5 or later
- -TTD issues 'tttracer.exe -attach PID' internally. So -attach is supported currently but -onLauch/-Launch is not supported yet.
- You cannot use -TTD with -SetAutologger as we don't support TTTracer.exe -persistent yet.

1. Start capturing TTD
```
.\UXTrace.ps1 -Start -TTD [PID|<ProcessName>|<ServiceName>]
```	

2. Start TTD by specifying PID
```
.\UXTrace.ps1 -Start -TTD <PID>
Ex: .\UXTrace.ps1 -Start -TTD 3364
```	
	
3. Start TTD by specifying process name
```
.\UXTrace.ps1 -Start -TTD <ProcessName>

Ex: .\UXTrace.ps1 -Start -TTD Explorer.exe
```
If there are multiple instances of the process, you will see below message and need to specify PID of the process you want to attach.

```
PS C:\Users\test\Desktop> .\UXTrace.ps1 -Start -TTD explorer.exe
Processing below traces:
    - TTD trace
	
Found multiple processes below.
-----------------------------------------
- explorer(PID:3004 User:DOMAIN-C\test)
- explorer(PID:4760 User:DOMAIN-C\test)
-----------------------------------------
Enter PID of process you want to attach: 3004 <---- Enter PID for the process you want to attach
```	
4. Start TTD by specifying service name
```
.\UXTrace.ps1 -Start -TTD <ServiceName>

Ex: .\UXTrace.ps1 -Start -WMI -TTD winmgmt
```
##Set autologger for traces(-SetAutoLogger)
We support autologger setting for ETW, WPR(boottrace), Procmon(bootlogging), netsh(Persistent). To set autolloger, you can use '-SetAutologger' option. If you specify option other than trace(ex -AppX), -WPR, -Procmon and -Netsh with -SetAutolloger, you will get an error.

1. Set autologger(-SetAutoLogger) 
```
.\UXTrace.ps1 -SetAutoLogger -AppX -StartMenu -WPR -Netsh -Procmon
```
2. Set autologger -> restart computer -> Stop traces and delete autologger.(-StopAutoLogger)
```
.\UXTrace.ps1 -SetAutoLogger -AppX -Photo -WPR -Netsh -Procmon
.\Restart-Computer
.\UXTrace.ps1 -StopAutoLogger   /// This will stop all traces and delete autologger settings
```

##Delete autologger settings(-DeleteAutologger)
1. To delete autolloger settings, run UXTrace with -DeleteAutologger. You don't need restart of the system for the change to take effect.
```
.\UXTrace.ps1 -DeleteAutoLogger
```
##Start performance log(-Start -Perf)
1. You can also start perfmon with -Perf option.
```
.\UXTrace.ps1 -Start -Perf
```
Note: If you want to add/change performance object, please change 'Providers' field in $PerfProperty manually which defines perf object to be collected.

2. If you want to change interval for the performance log, use '-PerfInterval'. The unit is second.
```
.\UXTrace.ps1 -Start -Perf -PerfInterval 1   // 1 sec interval
```

##Start PSR(Problem Steps Recorder)(-Start -PSR)
1. You can start PSR with '-PSR' option.
```
.\UXTrace.ps1 -Start -Shel -PSR
```

##Collect component specific log and OS basic log(-CollectLog <ComponentName>)
In case you don't need trace and just need logs for basic OS log or component logs/settings, you can use '-Collectlog' option.

1. To collect OS basic log like OS version or IP address and so on, you can specify '-Collectlog Basic'
```
.\UXTrace.ps1 -CollectLog Basic
```
2. To collect OS basic log and component log/settings, please specify component name with comma separated.
```
.\UXTrace.ps1 -CollectLog Basic,AppX,Shell,Logon
```
3. To collect OS basic log and also start traces, you can use -Basiclog option to get OS logs. Other component log/settings are collected automatically when you specify trace option. In this example, component log for Appx and Shell are collected automatically when traces are stopped and also -Basiclog option starts collecting OS basic log also after stopping the traces.
```
.\UXTrace.ps1 -Start -AppX -Shell -Basiclog
```

##List supported component log
To list supported component logs, use -ListSupportedLog.
```
PS> .\UXTrace.ps1 -ListSupportedLog
The following logs are supported
    - AppCompat
    - AppX
    - IME
    - Logon
    - Print
    - Shell
    - Task
    - UEV
    - WinRM
    - WMI
    - Basic
	
Usage:
  .\UXTrace.ps1 -CollectLog [ComponentName,ComponentName,...]
  Exmaple: .\UXTrace.ps1 -CollectLog AppX,Basic
```

##Enable WER setting(-Set / -Unset)
Currently we only support WER setting. You enable WER with '-Set WER'.
1. Enable WER setting
```
.\UXTrace.ps1 -Set WER
```

2. Disable WER setting
```
.\UXTrace.ps1 -Unset WER
```

##Enable SCM Trace
Enabling SCM trace is a bit not normal and need to set registry to enable debug log. To enable the trace, follow below step.

1. Enable SCM Trace
```
.\UXTrace.ps1 -Start -SCM -NoWait

/// Restart computer
	
.\UXTrace.ps1 -Stop -BasicLog -Compress -Delete  /// Stop trace after reboot and repro
```
##Create bat file that starts and stops traces(-CreateBatFile)
In case of Windows Server 2012 or earlier, UXTrace does not work as it supports from PowerShell v4. In this case, you can export commands that are issued from UXTrace to bat files. Two bat files for start and stop traces is created if you use CreateBatFile option.

1. Create bat file(Create bat file that contains commands issued from UXTrace)
```
.\UXTrace.ps1 -Start -CreateBatFile -Auth -WMI -WPR General -Procmon -Netsh -Perf -PSR
```
After you run above command, bat file named "UXTrace.cmd" is created in 'MSLOG' folder on your desktop
	
2. If you want to create a bat file for autologger, use '-CreateBatFile' with '-SetAutologger'
```
.\UXTrace.ps1 -SetAutologger -CreateBatFile -Auth -WMI -WPR General -Procmon -Netsh
```
After you run above command, two bat files below are created in 'MSLOG' folder on your desktop
- SetAutologger.cmd
- StopAutologger.cmd

##Start traces with nowait mode(-NoWait)
In case you want command prompt to return immediately and stop trace after repro, you can use '-NoWait'. In this case, the powershell prompt returns right after starting the trace.

1. Start trace with nowait mode. In this case, you need to run 'uxtrace.ps1 -stop' to stop the trace
```
.\UXTrace.ps1 -Start -AppX -StartMenu -COM -NoWait

// Reproduce issue

.\UXTrace.ps1 -Stop
```

##Set log folder(-LogFolderName)
You can change log folder(-LogFolderName). By default, UXTrace saves logs to 'MSLOG' folder on desktop which means under profile. In case customer don't want to save large size of date to profile, please use this option.

1. This example shows save traces to C:\temp.
```
.\UXTrace.ps1 -Start -Shell -LogFolderName C:\temp

// Reproduce issue

.\UXTrace.ps1 -Stop
```
2. In autologger scenario, use -LogFolderName when you stop autologger. In case of autologger, UXTrace saves all data to c:\temp. And the data is moved to 'MSLOG' folder on desktop when -StopAutologger is performed. If -LogFolderName is specified when autologger is stopped like below example, all data is saved to C:\temp temporary and moved to D:\MSLOG in this case.
```
.\UXTrace.ps1 -SetAutoLogger -Shell -WPR General
Restart-Computer
.\UXTrace.ps1 -StopAutoLogger -LogFolderName D:\MSLOG
```

##Compress and delete log folder(-Compress / -Delete)

1. Compress log folder after stopping traces(-Compress)
```
.\UXTrace.ps1 -start -Photo -Compress
    or 
.\UXTrace.ps1 -Stop -Compress
    or
.\UXTrace.ps1 -StopAutoLogger -Compress
```        
2. If you want to delete log folder after compressing log folder and creating .zip file, you can delete original log folder using -Delete.
```
.\UXTrace.ps1 -start -Photo -Compress -Delete
```

##Save multiple trace data to one etl file(-AsOneTrace)
To capture multiple traces and save the data to one etl file, not multiple etl files, you can use '-AsOneTrace' option. Sometimes you may want to merge etl files to one etl file to see log sequentially, this option is intended for such scenario.

1. Start traces and save traces to one etl file(-AsOneTrace)
```
.\UXTrace.ps1 -Start -AppX -StartMenu -COM -AsOneTrace
.\UXTrace.ps1 -Stop
```
Note: After running above command, all traces are saved to one etl file named 'UXTrace.etl'

##List supported traces(-List)
```
.\UXTrace.ps1 -List
The following traces are supported:
    - Alarm: Alarm app tracing
    - AppCompat: AppCompat and UAC tracing
    - AppV: App-V tracing
    - AppX: AppX tracing
        :

The following commands are supported:
    - Perf: Performance monitor
    - Procmon: Process monitor(procmon.exe)
    - PSR: Problem Steps Recorder
    - Netsh: Netsh(Packet capture)
    - NetshScenario: Netsh client scenario trace + Packet capture
    - SCM: Setting SCM trace
    - WPR: Windows Performance Recoder(wpr.exe)
```
##List supported component log(-ListSupportedLog)
```
.\UXTrace.ps1 -ListSupportedLog

Ex:
PS C:\Users\test\Desktop> .\UXTrace.ps1 -ListSupportedLog
The following logs are supported
    - AppCompat
    - AppX
    - IME
    - Logon
    - Print
    - Shell
    - Task
    - UEV
    - WinRM
    - WMI
    - Basic
	
Usage:
  .\UXTrace.ps1 -CollectLog [ComponentName,ComponentName,...]
  Exmaple: .\UXTrace.ps1 -CollectLog AppX,Basic
```
##Show current trace status(-Status)
If you want to see what traces are currently running or if autologger traces are set or not, '-Status' shows you current trace status. This command is also helpful when you encounter an error during starting trace or setting autologger. In such case, you may want to see if trace is started and if is, should want to stop it. To do this, run with -Status and if you see the running traces in output of -status, run 'UXTrace.ps1 -stop' to stop them. 
```
.\UXTrace.ps1 -Status
	
Running ETW trace session:
Below traces are currently running:
    - COMTrace with 16 providers
    - AppXTrace with 61 providers
    - StartMenuTrace with 19 providers
    - Procmon
    - WPR
    - Netsh(packet capture)
    - PSR(Problem Steps Recorder)
	
Autologger session enabled:
    There is no autologger session enabled.

Show help message(-Help)
.\UXTrace.ps1 -Help or Get-Help .\UXTrace.ps1
```