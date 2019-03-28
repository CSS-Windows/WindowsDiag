<#
.SYNOPSIS
This is a Powershell script to collect Hyper-V traces when the scenario time is too long for a VMLTrace

.DESCRIPTION

Script to collect Hyper-V Channels and include Procmon
- Sets registry keys for verbose tracing and restart VMMS
- Enables the channels according to the OS version (RS1, RS5) and sets their size to 50 MB each
- Waits for key pressed
- Stops & Exports the channels
- Evenutally adds the Hyper-V configuration, ClusDB & Cluster logs
- Resets the registry keys to default and restart VMMS

Arguments:
  -Path          : Path to collect the events. If ommitted, the script current path will be used
  -Size          : The size of the channels. If ommitted 52428800 (50 MB)
  -NoRestart     : To prevent the vmms service from restarting when the registry key is set. 
                   If ommitted, the service is restarted. It is recommended not to use this switch 
                   because some settings need the vmms service to be restarted to be effective.
  -NoSysApp      : To prevent from including System and Application event logs in the report. Not recomended
  -HVConfig      : Dumps the Hyper-V settings in a XML file
  -FCConfig      : Dumps the Failover Cluster registry hive
  -GetFCLogs     : Dumps the Cluster log

NOTES:
- As you the script restarts the VMMS service and modifies the Event logs, it must be run under administrator.
- The default behavior of the script is to create an "ExportedEvents" subfolder in the provided Path as a repository
and it will compress its content into a .ZIP file

.EXAMPLE
.\Hyper-V_Tracing_Using_Channels.ps1 
This script will just do the standard steps:
- Change the registry key to have verbose tracing and restart the VMMS service
- Change the channel size to 50MB and enable the analytic, debug & verbose ones
- Wait for a key pressed
- Disable the events that are disabled by default and export all in a .\ExportedEvents subfolder
- Compress the content of the .\ExportedEvents subfolder into a .ZIP file
- Reset the registry keys to default and restart the VMMS service

.EXAMPLE
.\Hyper-V_Tracing_Using_Channels.ps1 -Path C:\Temp\
This script will do:
- Change the registry key to have verbose tracing and restart the VMMS service
- Change the channel size to 50MB and enable the analytic, debug & verbose ones
- Wait for a key pressed
- Disable the events that are disabled by default and export all in a C:\temp\ExportedEvents subfolder
- Compress the content of the C:\temp\ExportedEvents subfolder into a .ZIP file into C:\Temp
- Reset the registry keys to default and restart the VMMS service

.EXAMPLE
.\Hyper-V_Tracing_Using_Channels.ps1 -HVConfig -FCConfig
This script will do:
- Change the registry key to have verbose tracing and restart the VMMS service
- Change the channel size to 50MB and enable the analytic, debug & verbose ones
- Wait for a key pressed
- Disable the events that are disabled by default and export all in a .\ExportedEvents subfolder
- It will export the Hyper-V configuration into an XML file and put it in .\ExportedEvents
- It will export the Cluster database into a .hiv file and put it in .\ExportedEvents
- Compress the content of the \ExportedEvents subfolder into a .ZIP file
- Reset the registry keys to default and restart the VMMS service

.EXAMPLE
.\Hyper-V_Tracing_Using_Channels.ps1 -GetFCLogs
This script will do:
- Change the registry key to have verbose tracing and restart the VMMS service
- Change the channel size to 50MB and enable the analytic, debug & verbose ones
- Wait for a key pressed
- Disable the events that are disabled by default and export all in a .\ExportedEvents subfolder
- It will collect the cluster log from the current node into a .log file and put it in .\ExportedEvents
- Compress the content of the \ExportedEvents subfolder into a .ZIP file
- Reset the registry keys to default and restart the VMMS service

.EXAMPLE
.\Hyper-V_Tracing_Using_Channels.ps1 -NoSysApp
This script will do the same as .\Hyper-V_Tracing_Using_Channels.ps1 but won't include the application and system event logs

.EXAMPLE
.\Hyper-V_Tracing_Using_Channels.ps1 -Size 104857600
This script will do the same as .\Hyper-V_Tracing_Using_Channels.ps1 but will set the events channels size to 100 MB
If not set, we'll give 50 MB

.NOTES
[TBD]

.LINK
http://www.bing.com
#>

Param([string]$Path,
      [int32]$Size=52428800,
      [switch]$NoRestart,
      [switch]$NoSysApp,
      [switch]$HVConfig,
      [switch]$FCConfig,
      [switch]$GetFCLogs
)


#region [::::: FUNCTIONS :::::]

    function Compress_Data([string]$Path,[string]$ExportPath)
    {
        $ServerName = $ENV:ComputerName
        $TodayDate = Get-Date
        $ZipSuffix = '_{0}{1:00}{2:00}-{3:00}{4:00}' -f $TodayDate.Year,$TodayDate.Month,$TodayDate.Day,$TodayDate.Hour,$TodayDate.Minute
        $ZipSuffix = $ServerName + $ZipSuffix
        $ZipPath = $Path+$ZipSuffix+".ZIP"
        Write-Host "Compressing data to "$ZipPath

        [Reflection.Assembly]::LoadWithPartialName("System.IO.Compression.FileSystem") | Out-Null
        $ZipLevel = [System.IO.Compression.CompressionLevel]::Optimal
        [System.IO.Compression.ZipFile]::CreateFromDirectory($ExportPath, $ZipPath, $ZipLevel, $false)
    }

    #region Registry functions
    function Registry_Set([ValidateSet("Standard","Verbose")][string]$Level,[ValidateSet("Yes","No")][string]$RestartService)  {
        if ($Level -eq "Standard"){
            Registry_SetStandard -RestartService $RestartService
        }
        else {
            Registry_SetVerbose -RestartService $RestartService
        }

    }
    function Registry_SetVerbose([ValidateSet("Yes","No")][string]$RestartService){
        write-host "Setting verbose tracing"
        try
        {
            if(-not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\VML"))
            {
                New-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\VML" | Out-Null
            }
            New-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\VML" -name "TraceLevel" -propertytype DWord -value 3 -Force | Out-Null

            if(-not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\VML\TraceLevelsEnabled"))
            {
                New-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\VML\TraceLevelsEnabled" | Out-Null
            }
            New-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\VML\TraceLevelsEnabled" -name "Trace6" -propertytype QWord -value 0x0000000000000000 -Force  | Out-Null
            New-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\VML\TraceLevelsEnabled" -name "Trace0" -propertytype QWord -value 0xFFFFFFFFFFFFFF17 -Force  | Out-Null
            New-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\VML\TraceLevelsEnabled" -name "Trace3" -propertytype QWord -value 0xFFFFFFFFFFFFFFF7 -Force | Out-Null

            if(-not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\PerformanceTracing"))
            {
                New-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\PerformanceTracing" | Out-Null
            }
            New-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\PerformanceTracing" -name "EnableMigrationTrace" -propertytype DWord -value 1 -Force | Out-Null
            New-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\PerformanceTracing" -name "EnableVmbTrace" -propertytype DWord -value 1 -Force | Out-Null
            New-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\PerformanceTracing" -name "EnablePvmTrace" -propertytype DWord -value 1 -Force | Out-Null
            New-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\PerformanceTracing" -name "EnableFrTrace" -propertytype DWord -value 1 -Force | Out-Null
            New-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\PerformanceTracing" -name "EnableVmNicTrace" -propertytype DWord -value 1 -Force | Out-Null
            New-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\PerformanceTracing" -name "EnableStorageMigrationTrace" -propertytype DWord -value 1 -Force | Out-Null
            New-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\PerformanceTracing" -name "EnableWorkerTrace" -propertytype DWord -value 1 -Force | Out-Null
        }
        catch
        {
            throw "Error: couldn't enable performance tracing.`n"+$Error[0].Exception
        }
        if ($RestartService -eq "Yes"){
            Try
            {
                Write-Output "Restarting the Hyper-V service..."
                # Restart the Hyper-V service
                # Because VMMS can be auto-restarted by the cluster, the "Stop-Service" cmdlet
                # may sometimes hit a race with the cluster service. Hence, we always ignore Stop-Service/Wait-Process
                # failures and rely on a change of the start time to determine that restart was successful
                # Start-Service never fails if the service is already running.
                $vmmsStartTime = (Get-Process vmms -ErrorAction:SilentlyContinue).StartTime
                Stop-Service vmms -Force -ErrorAction SilentlyContinue
                Wait-Process vmms -ErrorAction:SilentlyContinue -Timeout:30
                $newVmmsStartTime = (Get-Process vmms -ErrorAction:SilentlyContinue).StartTime
                if(($null -ne $vmmsStartTime) -and ($null -ne $newVmmsStartTime) -and ($newVmmsStartTime -eq $vmmsStartTime))
                {
                    throw "The VMMS process failed to stop and is still running"
                }
                Start-Service vmms

                while((Get-Service vmms).Status -eq "Started")
                {
                    Write-Output "Waiting for the vmms service to restart..."
                    Start-Sleep 1
                }
            }
            catch
            {
                throw "Error: couldn't restart Hyper-V services.`n"+$Error[0].Exception
            }
        }
    }
    function Registry_SetStandard([ValidateSet("Yes","No")][string]$RestartService){
        write-host "Resetting tracing to standard"
        if ((Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\VML")){
            Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\VML" -Force -Recurse
        }
        if ((Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\PerformanceTracing")){
            Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\PerformanceTracing" -Force -Recurse
        }
        if ($RestartService -eq "Yes"){
            Try
            {
                Write-Output "Restarting the Hyper-V service..."
                # Restart the Hyper-V service
                # Because VMMS can be auto-restarted by the cluster, the "Stop-Service" cmdlet
                # may sometimes hit a race with the cluster service. Hence, we always ignore Stop-Service/Wait-Process
                # failures and rely on a change of the start time to determine that restart was successful
                # Start-Service never fails if the service is already running.
                $vmmsStartTime = (Get-Process vmms -ErrorAction:SilentlyContinue).StartTime
                Stop-Service vmms -Force -ErrorAction SilentlyContinue
                Wait-Process vmms -ErrorAction:SilentlyContinue -Timeout:30
                $newVmmsStartTime = (Get-Process vmms -ErrorAction:SilentlyContinue).StartTime
                if(($null -ne $vmmsStartTime) -and ($null -ne $newVmmsStartTime) -and ($newVmmsStartTime -eq $vmmsStartTime))
                {
                    throw "The VMMS process failed to stop and is still running"
                }
                Start-Service vmms

                while((Get-Service vmms).Status -eq "Started")
                {
                    Write-Output "Waiting for the vmms service to restart..."
                    Start-Sleep 1
                }
            }
            catch
            {
                throw "Error: couldn't restart Hyper-V services.`n"+$Error[0].Exception
            }
        }
    }

    #endregion

    #region Channels functions
        #region Channels Enable Functions
            function Channels_Enable([int32]$Size){
                Write-Host "Enable Channels"
                if ([System.Environment]::OSVersion.Version.Major -eq 10){
                    if ([System.Environment]::OSVersion.Version.Build -ge 17763){
                        Channels_Enable_RS -Size $Size -RSVersion "RS5"
                    }
                    else {
                        Channels_Enable_RS -Size $Size -RSVersion "RS1"
                    }
                    # This is not enough to check the builds.
                    #   RS1 : Build = 14393
                    #   RS2 : Build = 15063
                    #   RS3 : Build = 16299
                    #   RS4 : Build = 17134
                    #   RS5 : Build = 17763
                }
            }
            function Channels_Enable_RS([int32]$Size,[ValidateSet("RS1","RS5")][string]$RSVersion)
            {
                Channels_Enable_Compute -Size $Size
                Channels_Enable_Config -Size $Size
                Channels_Enable_GuestDrivers -Size $Size
                Channels_Enable_Hypervisor -Size $Size
                Channels_Enable_Netvsc -Size $Size
                Channels_Enable_StorageVSP -Size $Size -RSVersion $RSVersion
                if ($RSVersion -eq "RS1"){
                    Channels_Enable_VfpExt -Size $Size
                }
                Channels_Enable_VID -Size $Size
                Channels_Enable_VMMS -Size $Size
                Channels_Enable_VMSP -Size $Size -RSVersion $RSVersion
                Channels_Enable_VmSwitch -Size $Size -RSVersion $RSVersion
                Channels_Enable_Worker -Size $Size -RSVersion $RSVersion
                if ((get-service -Name ClusSvc -ErrorAction SilentlyContinue) -ne $null)
                {
                    Channels_Enable_HighAvailability -Size $Size
                    Channels_Enable_SharedVHDX -Size $Size
                }
            }
            
            function Channels_Enable_Compute([int32]$Size){
                wevtutil sl "Microsoft-Windows-Hyper-V-Compute-Analytic" /enabled:false /retention:false /maxsize:$Size /quiet:true
                wevtutil sl "Microsoft-Windows-Hyper-V-Compute-Analytic" /enabled:true /quiet:true
            }
            function Channels_Enable_Config([int32]$Size){
                wevtutil sl "Microsoft-Windows-Hyper-V-Config-Analytic" /enabled:false /retention:false /maxsize:$Size /quiet:true
                wevtutil sl "Microsoft-Windows-Hyper-V-Config-Analytic" /enabled:true /quiet:true
            }
            function Channels_Enable_GuestDrivers([int32]$Size){
                wevtutil sl "Microsoft-Windows-Hyper-V-Guest-Drivers/Analytic" /enabled:false /retention:false /maxsize:$Size /quiet:true
                wevtutil sl "Microsoft-Windows-Hyper-V-Guest-Drivers/Analytic" /enabled:true /quiet:true
                wevtutil sl "Microsoft-Windows-Hyper-V-Guest-Drivers/Debug" /enabled:false /retention:false /maxsize:$Size /quiet:true
                wevtutil sl "Microsoft-Windows-Hyper-V-Guest-Drivers/Debug" /enabled:true /quiet:true
                wevtutil sl "Microsoft-Windows-Hyper-V-Guest-Drivers/Diagnose" /enabled:false /retention:false /maxsize:$Size /quiet:true
                wevtutil sl "Microsoft-Windows-Hyper-V-Guest-Drivers/Diagnose" /enabled:true /quiet:true
            }
            function Channels_Enable_HighAvailability([int32]$Size){
                wevtutil sl "Microsoft-Windows-Hyper-V-High-Availability-Analytic" /enabled:false /retention:false /maxsize:$Size /quiet:true
                wevtutil sl "Microsoft-Windows-Hyper-V-High-Availability-Analytic" /enabled:true /quiet:true
            }
            function Channels_Enable_Hypervisor([int32]$Size){
                wevtutil sl "Microsoft-Windows-Hyper-V-Hypervisor-Analytic" /enabled:false /retention:false /maxsize:$Size /quiet:true
                wevtutil sl "Microsoft-Windows-Hyper-V-Hypervisor-Analytic" /enabled:true /quiet:true
            }
            function Channels_Enable_Netvsc([int32]$Size){
                wevtutil sl "Microsoft-Windows-Hyper-V-Netvsc/Diagnostic" /enabled:false /retention:false /maxsize:$Size /quiet:true
                wevtutil sl "Microsoft-Windows-Hyper-V-Netvsc/Diagnostic" /enabled:true /quiet:true
            }
            function Channels_Enable_SharedVHDX([int32]$Size){
                wevtutil sl "Microsoft-Windows-Hyper-V-Shared-VHDX/Diagnostic" /enabled:false /retention:false /maxsize:$Size /quiet:true
                wevtutil sl "Microsoft-Windows-Hyper-V-Shared-VHDX/Diagnostic" /enabled:true /quiet:true
            }
            function Channels_Enable_StorageVSP([int32]$Size,[ValidateSet("RS1","RS5")][string]$RSVersion){
                if ($RSVersion -eq "RS"){
                    wevtutil sl "Microsoft-Windows-Hyper-V-StorageVSP-Analytic" /enabled:false /retention:false /maxsize:$Size /quiet:true
                    wevtutil sl "Microsoft-Windows-Hyper-V-StorageVSP-Analytic" /enabled:true /quiet:true
                }
            }
            function Channels_Enable_VfpExt([int32]$Size){
                wevtutil sl "Microsoft-Windows-Hyper-V-VfpExt-Analytic" /enabled:false /retention:false /maxsize:$Size /quiet:true
                wevtutil sl "Microsoft-Windows-Hyper-V-VfpExt-Analytic" /enabled:true /quiet:true
            }
            function Channels_Enable_VID([int32]$Size){
                wevtutil sl "Microsoft-Windows-Hyper-V-VID-Analytic" /enabled:false /retention:false /maxsize:$Size /quiet:true
                wevtutil sl "Microsoft-Windows-Hyper-V-VID-Analytic" /enabled:true /quiet:true
            }
            function Channels_Enable_VMMS([int32]$Size){
                wevtutil sl "Microsoft-Windows-Hyper-V-VMMS-Analytic" /enabled:false /retention:false /maxsize:$Size /quiet:true
                wevtutil sl "Microsoft-Windows-Hyper-V-VMMS-Analytic" /enabled:true /quiet:true
            }
            function Channels_Enable_VMSP([int32]$Size,[ValidateSet("RS1","RS5")][string]$RSVersion){
                wevtutil sl "Microsoft-Windows-Hyper-V-VMSP-Debug" /enabled:false /retention:false /maxsize:$Size /quiet:true
                wevtutil sl "Microsoft-Windows-Hyper-V-VMSP-Debug" /enabled:true /quiet:true
                if ($RSVersion -eq "RS5"){
                    wevtutil sl "Microsoft-Windows-Hyper-V-VMSP-Admin" /enabled:false /retention:false /maxsize:$Size /quiet:true
                    wevtutil sl "Microsoft-Windows-Hyper-V-VMSP-Admin" /enabled:true /quiet:true
                }
            }
            function Channels_Enable_VmSwitch([int32]$Size,[ValidateSet("RS1","RS5")][string]$RSVersion){
                wevtutil sl "Microsoft-Windows-Hyper-V-VmSwitch-Diagnostic" /enabled:false /retention:false /maxsize:$Size /quiet:true
                wevtutil sl "Microsoft-Windows-Hyper-V-VmSwitch-Diagnostic" /enabled:true /quiet:true
                if ($RSVersion -eq "RS5"){
                    wevtutil sl "Microsoft-Windows-Hyper-V-VmSwitch-Diagnostic-Traffic" /enabled:false /retention:false /maxsize:$Size /quiet:true
                    wevtutil sl "Microsoft-Windows-Hyper-V-VmSwitch-Diagnostic-Traffic" /enabled:true /quiet:true
                }
            }
            function Channels_Enable_Worker([int32]$Size,[ValidateSet("RS1","RS5")][string]$RSVersion){
                wevtutil sl "Microsoft-Windows-Hyper-V-Worker-Admin" /enabled:false /retention:false /maxsize:$Size /quiet:true
                wevtutil sl "Microsoft-Windows-Hyper-V-Worker-Admin" /enabled:true /quiet:true
                wevtutil sl "Microsoft-Windows-Hyper-V-Worker-Analytic" /enabled:false /retention:false /maxsize:$Size /quiet:true
                wevtutil sl "Microsoft-Windows-Hyper-V-Worker-Analytic" /enabled:true /quiet:true
                wevtutil sl "Microsoft-Windows-Hyper-V-Worker-VDev-Analytic" /enabled:false /retention:false /maxsize:$Size /quiet:true
                wevtutil sl "Microsoft-Windows-Hyper-V-Worker-VDev-Analytic" /enabled:true /quiet:true
            }
            
            
           
        #endregion
        #region Channels Disable Functions
            function Channels_DisableAndExport([string]$Path,[bool]$AddSysAppEvtx,[switch]$NoSysApp){
                Write-Host "Disable and export Channels"
                $SystemVersion = [System.Environment]::OSVersion.Version
                if ($SystemVersion.Major -eq 10){
                    if ($SystemVersion.Major.Build -ge 17763)
                    {
                        Channels_DisableAndExport_RS -Size $Size -RSVersion "RS5" -Path $Path
                    }
                    else {
                        Channels_DisableAndExport_RS -Size $Size -RSVersion "RS1" -Path $Path
                    }
                }
                if (!$NoSysApp){
                    Export_System_And_Application_Events -Path $Path
                }
            }
            function Channels_DisableAndExport_RS([string]$Path,[ValidateSet("RS1","RS5")][string]$RSVersion){
                $FileSuffix = $ENV:ComputerName
                $OutputPath = $Path+$FileSuffix+"_"
                Channels_DisableExport_Compute -OutputPath $OutputPath
                Channels_DisableExport_Config -OutputPath $OutputPath
                Channels_DisableExport_GuestDrivers -OutputPath $OutputPath
                Channels_DisableExport_Hypervisor -OutputPath $OutputPath
                Channels_DisableExport_Netvsc -OutputPath $OutputPath
                Channels_DisableExport_StorageVSP -OutputPath $OutputPath
                if ($RSVersion -eq "RS1")
                {
                    Channels_DisableExport_VfpExt -OutputPath $OutputPath
                }
                Channels_DisableExport_VID -OutputPath $OutputPath
                Channels_DisableExport_VMMS -OutputPath $OutputPath
                Channels_DisableExport_VMSP -OutputPath $OutputPath -RSVersion $RSVersion
                Channels_DisableExport_VmSwitch -OutputPath $OutputPath -RSVersion $RSVersion
                Channels_DisableExport_Worker -OutputPath $OutputPath -RSVersion $RSVersion
                if ((get-service -Name ClusSvc -ErrorAction SilentlyContinue) -ne $null)
                {
                    Channels_DisableExport_HighAvailability -OutputPath $OutputPath
                    Channels_DisableExport_SharedVHDX -OutputPath $OutputPath
                }
            }

            function Export_System_And_Application_Events([string]$Path){
                $FileSuffix = $ENV:ComputerName
                $OutputPath = $Path+$FileSuffix+"_"
                wevtutil epl "Application" $OutputPath"Application.evtx" /ow:true
                wevtutil epl "System" $OutputPath"System.evtx" /ow:true
            }

            function Channels_DisableExport_Compute([string]$OutputPath){
                wevtutil epl "Microsoft-Windows-Hyper-V-Compute-Admin" $OutputPath"Compute_Admin.evtx" /ow:true
                wevtutil sl "Microsoft-Windows-Hyper-V-Compute-Analytic" /enabled:false /quiet:true
                wevtutil epl "Microsoft-Windows-Hyper-V-Compute-Analytic" $OutputPath"Compute_Analytic.evtx" /ow:true
                wevtutil epl "Microsoft-Windows-Hyper-V-Compute-Operational" $OutputPath"Compute_Operational.evtx" /ow:true
            }
            function Channels_DisableExport_Config([string]$OutputPath){
                wevtutil epl "Microsoft-Windows-Hyper-V-Config-Admin" $OutputPath"Config_Admin.evtx" /ow:true
                wevtutil sl "Microsoft-Windows-Hyper-V-Config-Analytic" /enabled:false /quiet:true
                wevtutil epl "Microsoft-Windows-Hyper-V-Config-Analytic" $OutputPath"Config_Analytic.evtx" /ow:true
                wevtutil epl "Microsoft-Windows-Hyper-V-Config-Operational" $OutputPath"Config_Operational.evtx" /ow:true
            }
            function Channels_DisableExport_GuestDrivers([string]$OutputPath){
                wevtutil epl "Microsoft-Windows-Hyper-V-Guest-Drivers/Admin" $OutputPath"Guest-Drivers_Admin.evtx" /ow:true
                wevtutil sl "Microsoft-Windows-Hyper-V-Guest-Drivers/Analytic" /enabled:false /quiet:true
                wevtutil epl "Microsoft-Windows-Hyper-V-Guest-Drivers/Analytic" $OutputPath"Guest-Drivers_Analytic.evtx" /ow:true
                wevtutil sl "Microsoft-Windows-Hyper-V-Guest-Drivers/Debug" /enabled:false /quiet:true
                wevtutil epl "Microsoft-Windows-Hyper-V-Guest-Drivers/Debug" $OutputPath"Guest-Drivers_Vdev_Debug.evtx" /ow:true
                wevtutil sl "Microsoft-Windows-Hyper-V-Guest-Drivers/Diagnose" /enabled:false /quiet:true
                wevtutil epl "Microsoft-Windows-Hyper-V-Guest-Drivers/Diagnose" $OutputPath"Guest-Drivers_Diagnose.evtx" /ow:true
                wevtutil epl "Microsoft-Windows-Hyper-V-Guest-Drivers/Operational" $OutputPath"Guest-Drivers_Operational.evtx" /ow:true
            }
            function Channels_DisableExport_HighAvailability([string]$OutputPath){
                wevtutil epl "Microsoft-Windows-Hyper-V-High-Availability-Admin" $OutputPath"High-Availability_Admin.evtx" /ow:true
                wevtutil sl "Microsoft-Windows-Hyper-V-High-Availability-Analytic" /enabled:false /quiet:true
                wevtutil epl "Microsoft-Windows-Hyper-V-High-Availability-Analytic" $OutputPath"High-Availability_Analytic.evtx" /ow:true
            }
            function Channels_DisableExport_Hypervisor([string]$OutputPath){
                wevtutil epl "Microsoft-Windows-Hyper-V-Hypervisor-Admin" $OutputPath"Hypervizor_Admin.evtx" /ow:true
                wevtutil sl "Microsoft-Windows-Hyper-V-Hypervisor-Analytic" /enabled:false /quiet:true
                wevtutil epl "Microsoft-Windows-Hyper-V-Hypervisor-Analytic" $OutputPath"Hypervizor_Analytic.evtx" /ow:true
                wevtutil epl "Microsoft-Windows-Hyper-V-Hypervisor-Operational" $OutputPath"Hypervizor_Operational.evtx" /ow:true
            }
            function Channels_DisableExport_Netvsc([string]$OutputPath){
                wevtutil sl "Microsoft-Windows-Hyper-V-Netvsc/Diagnostic" /enabled:false /quiet:true
                wevtutil epl "Microsoft-Windows-Hyper-V-Netvsc/Diagnostic" $OutputPath"Netvsc-Diagnostic.evtx" /ow:true
            }
            function Channels_DisableExport_SharedVHDX([string]$OutputPath){
                wevtutil sl "Microsoft-Windows-Hyper-V-Shared-VHDX/Diagnostic" /enabled:false /quiet:true
                wevtutil epl "Microsoft-Windows-Hyper-V-Shared-VHDX/Diagnostic" $OutputPath"Shared-VHDX-Diagnostic.evtx" /ow:true
                wevtutil epl "Microsoft-Windows-Hyper-V-Shared-VHDX/Operational" $OutputPath"Shared-VHDX-Operational.evtx" /ow:true
                wevtutil epl "Microsoft-Windows-Hyper-V-Shared-VHDX/Reservation" $OutputPath"Shared-VHDX-Reservation.evtx" /ow:true
            }
            function Channels_DisableExport_StorageVSP([string]$OutputPath,[ValidateSet("RS1","RS5")][string]$RSVersion){
                wevtutil epl "Microsoft-Windows-Hyper-V-StorageVSP-Admin" $OutputPath"StorageVSP-Admin.evtx" /ow:true
                if ($RSVersion -eq "RS5"){
                    wevtutil sl "Microsoft-Windows-Hyper-V-StorageVSP-Analytic" /enabled:false /quiet:true
                    wevtutil epl "Microsoft-Windows-Hyper-V-StorageVSP-Analytic" $OutputPath"StorageVSP-Analytic.evtx" /ow:true
                }
            }
            function Channels_DisableExport_VfpExt([string]$OutputPath){
                wevtutil sl "Microsoft-Windows-Hyper-V-VfpExt-Analytic" /enabled:false /quiet:true
                wevtutil epl "Microsoft-Windows-Hyper-V-VfpExt-Analytic" $OutputPath"VfpExt-Analytic.evtx" /ow:true
            }
            function Channels_DisableExport_VID([string]$OutputPath){
                wevtutil epl "Microsoft-Windows-Hyper-V-VID-Admin" $OutputPath"VID-Admin.evtx" /ow:true
                wevtutil sl "Microsoft-Windows-Hyper-V-VID-Analytic" /enabled:false /quiet:true
                wevtutil epl "Microsoft-Windows-Hyper-V-VID-Analytic" $OutputPath"VID-Analytic.evtx" /ow:true
            }
            function Channels_DisableExport_VMMS([string]$OutputPath){
                wevtutil epl "Microsoft-Windows-Hyper-V-VMMS-Admin" $OutputPath"VMMS_Admin.evtx" /ow:true
                wevtutil epl "Microsoft-Windows-Hyper-V-VMMS-Networking" $OutputPath"VMMS_Networking.evtx" /ow:true
                wevtutil epl "Microsoft-Windows-Hyper-V-VMMS-Operational" $OutputPath"VMMS_Operational.evtx" /ow:true
                wevtutil epl "Microsoft-Windows-Hyper-V-VMMS-Storage" $OutputPath"VMMS_Storage.evtx" /ow:true
                wevtutil sl "Microsoft-Windows-Hyper-V-VMMS-Analytic" /enabled:false /quiet:true
                wevtutil epl "Microsoft-Windows-Hyper-V-VMMS-Analytic" $OutputPath"VMMS_Analytic.evtx" /ow:true
            }
            function Channels_DisableExport_VMSP([string]$OutputPath,[ValidateSet("RS1","RS5")][string]$RSVersion){
                wevtutil sl "Microsoft-Windows-Hyper-V-VMSP-Debug" /enabled:false /quiet:true
                wevtutil epl "Microsoft-Windows-Hyper-V-VMSP-Debug" $OutputPath"VMSP_Debug.evtx" /ow:true
                if ($RSVersion -eq "RS5"){
                    wevtutil epl "Microsoft-Windows-Hyper-V-VMSP-Admin" $OutputPath"VMSP_Admin.evtx" /ow:true
                }
            }
            function Channels_DisableExport_VmSwitch([string]$OutputPath,[ValidateSet("RS1","RS5")][string]$RSVersion){
                wevtutil sl "Microsoft-Windows-Hyper-V-VmSwitch-Diagnostic" /enabled:false /quiet:true
                wevtutil epl "Microsoft-Windows-Hyper-V-VmSwitch-Diagnostic" $OutputPath"VmSwitch-Diagnostic.evtx" /ow:true
                wevtutil epl "Microsoft-Windows-Hyper-V-VmSwitch-Operational" $OutputPath"VmSwitch-Operational.evtx" /ow:true
                if ($RSVersion -eq "RS5"){
                    wevtutil sl "Microsoft-Windows-Hyper-V-VmSwitch-Diagnostic-Traffic" /enabled:false /quiet:true
                    wevtutil epl "Microsoft-Windows-Hyper-V-VmSwitch-Diagnostic-Traffic" $OutputPath"VmSwitch-Diagnostic-Traffic.evtx" /ow:true
                }
            }
            function Channels_DisableExport_Worker([string]$OutputPath,[ValidateSet("RS1","RS5")][string]$RSVersion){
                wevtutil epl "Microsoft-Windows-Hyper-V-Worker-Admin" $OutputPath"Worker_Admin.evtx" /ow:true
                wevtutil sl "Microsoft-Windows-Hyper-V-Worker-Analytic" /enabled:false /quiet:true
                wevtutil epl "Microsoft-Windows-Hyper-V-Worker-Analytic" $OutputPath"Worker_Analytic.evtx" /ow:true
                wevtutil sl "Microsoft-Windows-Hyper-V-Worker-VDev-Analytic" /enabled:false /quiet:true
                wevtutil epl "Microsoft-Windows-Hyper-V-Worker-VDev-Analytic" $OutputPath"Worker_Vdev_Analytic.evtx" /ow:true
                if ($RSVersion -eq "RS5"){
                    wevtutil epl "Microsoft-Windows-Hyper-V-Worker-Operational" $OutputPath"Worker_Operational.evtx" /ow:true
                }
            }
           
        #endregion
    #endregion

    #region Data collection functions

    function Export_HyperV_Configuration([string]$Path)
    {
        Write-Host "Exporting the Hyper-V configuration"
        $FileSuffix = $ENV:ComputerName
        $OutputPath = $Path+$FileSuffix+"_HyperV_Config.xml"
        Get-VMHost | Export-Clixml -LiteralPath $OutputPath
    }

    function Export_FailoverCluster_Configuration([string]$Path)
    {
        Write-Host "Exporting the Cluster hive"
        $FileSuffix = $ENV:ComputerName
        $OutputPath = $Path+$FileSuffix+"_ClusDB.hiv"
        if ((Test-Path -Path HKLM:\Cluster) -eq $true){
            reg save HKLM\cluster $OutputPath
        }
    }

    function Export_ClusterLog([string]$Path)
    {
        Write-Host "Collection the cluster log"
        if ((get-service -Name ClusSvc -ErrorAction SilentlyContinue) -ne $null){
            $NodeName = $ENV:ComputerName
            Get-ClusterLog -Node $NodeName -Destination $Path
        }
    }
    #endregion
#endregion


#region ::::: MAIN :::::]

#region Path Management

    $ScriptPath = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition

    if (-not $Path){
        $Path = $ScriptPath+"\"
        write-host "Export path is"$Path
    }
    else {
        if ($Path[-1] -ne "\") {
            $Path+="\"
        }
    }
    $ExportPath = $Path+"ExportedEvents\"

    if ((Test-Path -Path $ExportPath)){
        Remove-Item -Path $ExportPath -Force -Recurse | Out-Null
    }

    new-item -Path $ExportPath -ItemType Directory -Force | Out-Null
    
#endregion

# ----- Set Verbose Tracing
    Registry_Set -Level "Verbose" -RestartService "Yes"

# ----- Start tracing
    Channels_Enable -Size 52428800

# ----- Wait for prompt
    write-host "Reproduce the problem then press any key to continue ..." -ForegroundColor Green
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

# ----- Stop tracing and export the events
    if ($NoSysApp){
        Channels_DisableAndExport -Path $ExportPath -NoSysApp
    }
    else{
        Channels_DisableAndExport -Path $ExportPath
    }
    
# ----- Export Additional Configs

    if ($HVConfig){
        Export_HyperV_Configuration -Path $ExportPath
    }

    if ($FCConfig){
        Export_FailoverCluster_Configuration -Path $ExportPath
    }

    if ($GetFCLogs){
        Export_ClusterLog -Path $ExportPath
    }

# ----- Compress the data
    Compress_Data -Path $Path -ExportPath $ExportPath

# ----- Set Tracing to standard back
    Registry_Set -Level "Standard" -RestartService "Yes"
    
#endregion
