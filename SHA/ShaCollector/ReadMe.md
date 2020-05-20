# SYNOPSIS shacollector
    Script Name: shacollector.bat
    Purpose:     collect support information logs related to SHA Area. 
    Version:     5.4
    Last Update: 18th May 2020
    Author:      Koji Ishida
    Email-Alias: kojii

## DESCRIPTION
shacollector is a tool that makes it easy to collect data for problem solving which is included in trace logs (ETW), 
performance logs (perfmon or xperf), event logs and a lot of status information related to SHA area (Storage, Cluster and Hyper-V).

## Whats New in this Version 5.4
  - implement to avoid double execution of trace option 

## How to use it
First, specify main options (trace, perf and support) and select sub option that specifies the information to collect. 
Then, 'trace' and 'perf' can be specified with 'start' to start and 'stop' to stop log collection. 
The 'support' option collects various status information and logs without specifying 'start' and 'stop'. 
By default, logs are saved in 'c:\mslog', but you can specify the output destination.

## EXAMPLE
* To collect trace log related I/O drivers (storport.sys, classpnp ...). 
  And change the output folder to 'd:\logs'.
 
      shacollector.bat trace storage start d:\logs
      shacollector.bat trace storage stop

* To collect multiple trace logs (ex. storport and vss). The log files are saved in 'c:\mslog' as the default.

      shacollector.bat trace storport start
      shacollector.bat trace vss start
      shacollector.bat trace storport stop
      shacollector.bat trace vss stop

* To collect trace log (ex. storport) at OS startup.

      shacollector.bat trace storport boot
      <restart OS>
      shacollector.bat trace storport stop
      shacollector.bat trace storport delete

* To collect performance monitor log. The sample interval is 15sec as the default but it can be change.

      shacollector.bat perf perfmon start
      shacollector.bat perf perfmon stop

* To collect performance monitor log at 1 sec as sample interval. And change the output folder to 'd:\logs'.

      shacollector.bat perf perfmon start d:\logs interval 0:0:1
      shacollector.bat perf perfmon stop

* To collect xperf log for investigating the cpu load. And change the output folder to 'd:\logs'.

      shacollector.bat perf cpu start d:\logs
      shacollector.bat perf cpu stop

* To collect xperf log for investigating the memory exhausion. The log files are saved in 'c:\mslog' as the default.

      shacollector.bat perf memory start
      shacollector.bat perf memory stop

* To collect xperf log for investigating the I/O load. The log files are saved in 'c:\mslog' as the default.

      shacollector.bat perf disk start
      shacollector.bat perf disk stop

* To collect all relevant support information logs such as event logs, registory, dik and network configuration and so on. And change the output folder to 'd:\logs'.

      shacollector.bat support all d:\logs

* To collect specific support information logs (disk, network and event logs). 

      shacollector.bat support disk
      shacollector.bat support network
      shacollector.bat support eventlog

## Usage
    shacollector.bat trace [trace option] start [output folder (default c:\mslog)]
    shacollector.bat trace [trace option] stop
    shacollector.bat trace [trace option] boot [output folder (default c:\mslog)]
    shacollector.bat trace [trace option] delete
    
    shacollector.bat perf perfmon start [output folder (default c:\mslog)] interval [sample interval [hh:mm:ss] (ex. 00:00:15) default 15sec]
    shacollector.bat perf cpu start [output folder (default c:\mslog)]
    shacollector.bat perf cpu stop
    shacollector.bat perf memory start [output folder (default c:\mslog)] tag "POOL TAG (ex. FMfn)"
    shacollector.bat perf memory stop
    shacollector.bat perf disk start [output folder (default c:\mslog)]
    shacollector.bat perf disk stop
    shacollector.bat perf delay start [output folder (default c:\mslog)]
    shacollector.bat perf delay stop
    shacollector.bat perf heap start pid "Process ID (ex. 1234)" enable
    shacollector.bat perf heap start [output folder (default c:\mslog)] pid "Process ID (ex. 1234)" snap
    
    shacollector.bat support all [output folder (default c:\mslog)]
    shacollector.bat support basic [output folder (default c:\mslog)]
    shacollector.bat support [supportlog option] [output folder (default c:\mslog)]

### available trace option:
      storage   collecting storage drivers trace. (ex storport.sys, classpnp.sys ...)
      storport  collecting storport driver trace.
      ntfs      collecting NTFS driver trace.
      usb       collecting USB drivers trace.
      pnp       collecting Plug and Play drivers trace.
      com       collecting COM/COM+ services trace.
      vds       collecting VDS services trace. (Windows Server 2012 or later)
      vss       collecting VSS services trace. (Windows Server 2008 R2 or later)
      wsb       collecting Windows Server Backup modules trace. (Windows Server 2008 R2 or later)
      cdrom     collecting CD/DVD modules trace.
      ata       collecting ATAPort drivers trace.
      fsrm      collecting FSRM drivers trace.
      dedup     collecting Dedup drivers trace. (Windows Server 2012 or later)
      nfs       collecting NFS services trace.
      network   collecting Network driver trace.
      iscsi     collecting iSCSI driver trace.
      csv       collecting CSV drivers trace.
      wmi       collecting WMI services trace.
      rpc       collecting RPC services trace.
      hyper-v   collecting Hyper-V modules trace.
      cluster   collecting Failover Clustering trace (included netft trace).
      space     collecting Storage Space trace.
      storagereplica     collecting Storage Replica trace.
      packet    collecting Network Packet Capture. (Windows Server 2008 R2 or later)
      procmon   collecting Process Monitor log of Sysinternals.
      psr       collecting Problems Steps Recorder log.

### available performance option:
      perfmon   collecting Performance Monitor log. default sample interval is 15sec.
      cpu       collecting CPU perf logs with Xperf.
      memory    collecting Memory perf logs with Xperf.
      disk      collecting Disk perf logs with Xperf.
      delay     collecting Delay perf logs with Xperf.
      heap      collectiong Heap performance log with rdrleakdiag.

### available support option:
      all             collecting all support logs.
         included cluster, disk, diskshadow, driverinfo, eventlog, fltmc, fsrm, handle, hyper-v, iscsi, network, nfs, registry, storagereplica, system, setup, taskscheduler, vss
      basic           collecting basic support logs.
         included disk, driverinfo, eventlog, fltmc, network, system, vss
      cluster         collecting cluster information logs.
      disk            collecting disk information logs.
      diskshadow      collecting diskshadow information logs.
      driverinfo      collecting driver information logs.
      drive-space     collecting drive space information logs.
      eventlog        collecting eventlog information logs.
      fltmc           collecting filter driver information logs.
      fsrm            collecting fsrm information logs.
      handle          collecting file handle information.
      hyper-v         collecting hyper-v information logs.
      iscsi           collecting iscsi information logs.
      network         collecting network information logs.
      nfs             collecting nfs information logs.
      registry        collecting registry information logs.
      storagereplica  collecting Storage Replica information logs.
      system          collecting system information logs.
      taskscheduler   collecting task scheduler information logs.
      virtualfc       collecting virtual fc information.
      vss             collecting vss information logs.
      setup           collecting setup information logs.
      fsi             collecting file system information logs.
      crash           generate blue screen of death (BSOD).