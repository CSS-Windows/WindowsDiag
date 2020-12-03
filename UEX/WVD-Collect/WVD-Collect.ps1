# =====================================================
#
# DISCLAIMER:
#
# THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
#
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
# =====================================================
# 
# IMPORTANT NOTICE: 
# 
# This script is designed to collect information that will help Microsoft Customer Support Services (CSS) troubleshoot an issue you may be experiencing with Windows Virtual Desktop.
# 
# The collected data may contain Personally Identifiable Information (PII) and/or sensitive data, such as (but not limited to) IP addresses, PC names and user names.
# 
# The script will save the collected data in a subfolder and also compress the results into a ZIP file. The folder or ZIP file are not automatically sent to Microsoft. 
# 
# You can send the ZIP file to Microsoft CSS using a secure file transfer tool - Please discuss this with your support professional and also any concerns you may have.
# 
# Find our privacy statement here: https://privacy.microsoft.com/en-us/privacy 
# 
# =====================================================


param (
    [switch]$Profile = $false,
    [switch]$ClientAutoTrace = $false,
    [switch]$MonTables = $false,
    [switch]$Certificate = $false,
    [switch]$MSRA = $false,    
    [switch]$Teams = $false,    
    [switch]$Verbose = $false,
    [switch]$DiagOnly = $false
)

$version = "201110.3"
# Author: Robert Klemencz @ Microsoft Customer Service and Support


$myWindowsID = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal = new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
$adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
if (-not $myWindowsPrincipal.IsInRole($adminRole)) {
  Write-Host "This script needs to be run as Administrator" -ForegroundColor Yellow
  exit
}

$Root = Split-Path (Get-Variable MyInvocation).Value.MyCommand.Path

$resName = "WVD-Results-" + $env:computername +"-" + $(get-date -f yyyyMMdd_HHmmss)
$resDir = $Root + "\" + $resName
$resFile = $resDir + "\" + $env:computername +"_"

$outfile = $resFile + "WVD-Collect-Output.txt"
$errfile = $resFile + "WVD-Collect-Errors.txt"
$RdrOut =  " >>""" + $outfile + """"
$RdrErr =  " 2>>""" + $errfile + """"
$fqdn = [System.Net.Dns]::GetHostByName(($env:computerName)).HostName

$OSVer = ([environment]::OSVersion.Version.Major) + ([environment]::OSVersion.Version.Minor) /10

$ver = (Get-WmiObject Win32_OperatingSystem).Caption

New-Item -itemtype directory -path $resDir | Out-Null


# Functions

Function Write-Log {
  param( [string] $msg, [string] $fcolor = "White")
  $msg = (get-date).ToString("yyyyMMdd HH:mm:ss.fff") + " " + $msg
  Write-Host $msg -ForegroundColor $fcolor
  $msg | Out-File -FilePath $outfile -Append
}


Function Write-LogDetails {
    param( [string] $msg)
    if ($verbose) {$status = 1}
    else {$status = 0}

if ($status -eq 1) {  
  $msg = (get-date).ToString("yyyyMMdd HH:mm:ss.fff") + " " + $msg
  Write-Host $msg -ForegroundColor Gray
  $msg | Out-File -FilePath $outfile -Append
  }
}


Function Write-LogError {
  param( [string] $msg )
  $msg = (get-date).ToString("yyyyMMdd HH:mm:ss.fff") + " [INFO] " + $msg
  $msg | Out-File -FilePath $outfile -Append
}


Function Write-LogTitle {
  param( [string] $msg)
  $msg = (get-date).ToString("yyyyMMdd HH:mm:ss.fff") + " " + $msg
  Write-Host $msg -ForegroundColor White -BackgroundColor DarkCyan
  $msg | Out-File -FilePath $outfile -Append
}


Function Write-Diag {
  param( [string] $msg )

  if ($verbose) {$status = 1}
  else {$status = 0}

if ($status -eq 1) {  
  $msg = (get-date).ToString("yyyyMMdd HH:mm:ss.fff") + " " + $msg
  $msg | Out-File -FilePath $diagfile -Append
  Write-Host $msg -ForegroundColor Gray
  } else {
  $msg = (get-date).ToString("yyyyMMdd HH:mm:ss.fff") + " " + $msg
  $msg | Out-File -FilePath $diagfile -Append
  }
}


Function ExecQuery {
  param(
    [string] $NameSpace,
    [string] $Query
  )
  # Write-Log ("Executing query " + $Query)
  if ($PSVersionTable.psversion.ToString() -ge "3.0") {
    $ret = Get-CimInstance -Namespace $NameSpace -Query $Query -ErrorAction Continue 2>>$errfile
  } else {
    $ret = Get-WmiObject -Namespace $NameSpace -Query $Query -ErrorAction Continue 2>>$errfile
  }
  # Write-Log (($ret | measure).count.ToString() + " results")
  return $ret
}


Function ArchiveLog {
  param( [string] $LogName )
  $cmd = "wevtutil al """+ $resFile + "EventLogs\" + $env:computername + "_evt_" + $LogName + ".evtx"" /l:en-us >>""" + $outfile + """ 2>>""" + $errfile + """"
  Write-LogDetails $cmd
  Invoke-Expression $cmd
}


Add-Type -MemberDefinition @"
[DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern uint NetApiBufferFree(IntPtr Buffer);
[DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern int NetGetJoinInformation(
  string server,
  out IntPtr NameBuffer,
  out int BufferType);
"@ -Namespace Win32Api -Name NetApi32


Function GetNBDomainName {
  $pNameBuffer = [IntPtr]::Zero
  $joinStatus = 0
  $apiResult = [Win32Api.NetApi32]::NetGetJoinInformation(
    $null,               # lpServer
    [Ref] $pNameBuffer,  # lpNameBuffer
    [Ref] $joinStatus    # BufferType
  )
  if ( $apiResult -eq 0 ) {
    [Runtime.InteropServices.Marshal]::PtrToStringAuto($pNameBuffer)
    [Void] [Win32Api.NetApi32]::NetApiBufferFree($pNameBuffer)
  }
}


Function GetStore($store) {
  $certlist = Get-ChildItem ("Cert:\LocalMachine\" + $store)

  foreach ($cert in $certlist) {
    $EKU = ""
    foreach ($item in $cert.EnhancedKeyUsageList) {
      if ($item.FriendlyName) {
        $EKU += $item.FriendlyName + " / "
      } else {
        $EKU += $item.ObjectId + " / "
      }
    }

    $row = $tbcert.NewRow()

    foreach ($ext in $cert.Extensions) {
      if ($ext.oid.value -eq "2.5.29.14") {
        $row.SubjectKeyIdentifier = $ext.SubjectKeyIdentifier.ToLower()
      }
      if (($ext.oid.value -eq "2.5.29.35") -or ($ext.oid.value -eq "2.5.29.1")) { 
        $asn = New-Object Security.Cryptography.AsnEncodedData ($ext.oid,$ext.RawData)
        $aki = $asn.Format($true).ToString().Replace(" ","")
        $aki = (($aki -split '\n')[0]).Replace("KeyID=","").Trim()
        $row.AuthorityKeyIdentifier = $aki
      }
    }
    if ($EKU) {$EKU = $eku.Substring(0, $eku.Length-3)} 
    $row.Store = $store
    $row.Thumbprint = $cert.Thumbprint.ToLower()
    $row.Subject = $cert.Subject
    $row.Issuer = $cert.Issuer
    $row.NotAfter = $cert.NotAfter
    $row.EnhancedKeyUsage = $EKU
    $row.SerialNumber = $cert.SerialNumber.ToLower()
    $tbcert.Rows.Add($row)
  } 
}


Function FileVersion {
  param(
    [string] $FilePath,
    [bool] $Log = $false
  )
  if (Test-Path -Path $FilePath) {
    $fileobj = Get-item $FilePath
    $filever = $fileobj.VersionInfo.FileMajorPart.ToString() + "." + $fileobj.VersionInfo.FileMinorPart.ToString() + "." + $fileobj.VersionInfo.FileBuildPart.ToString() + "." + $fileobj.VersionInfo.FilePrivatepart.ToString()

    if ($log) {
      ($FilePath + "," + $filever + "," + $fileobj.CreationTime.ToString("yyyyMMdd HH:mm:ss")) | Out-File -FilePath ($resFile + "ver_KeyFileVersions.csv") -Append
    }
    return $filever | Out-Null
  } else {
    return ""
  }
}


# =============================================================================

Write-Host
Write-LogTitle "Starting WVD-Collect (v$version)" "White" "DarkCyan"

##### Disclaimer

Write-Host "
=====================================================

IMPORTANT NOTICE: 

This script is designed to collect information that will help Microsoft Customer Support Services (CSS) troubleshoot an issue you may be experiencing with Windows Virtual Desktop.

The collected data may contain Personally Identifiable Information (PII) and/or sensitive data, such as (but not limited to) IP addresses, PC names and user names.

The script will save the collected data in a subfolder and also compress the results into a ZIP file. The folder or ZIP file are not automatically sent to Microsoft. 

You can send the ZIP file to Microsoft CSS using a secure file transfer tool - Please discuss this with your support professional and also any concerns you may have.

Find our privacy statement here: https://privacy.microsoft.com/en-us/privacy

=====================================================
"

$confirm = Read-Host ("Do you agree to continue? [Y/N]")
if ($confirm.ToLower() -ne "y") {exit}


$StopWatchDC = [system.diagnostics.stopwatch]::startNew()


if (!$DiagOnly) {


if($Teams) {

# checking if diagnostic logs are present (user has pressed Ctrl+Alt+Shift+1 in Teams prior to running the script)

        $TeamsDiagFolder = "C:\Users\" + $realprofile + "\Downloads"
        
        if (Test-path -path $TeamsDiagFolder) {         
            
            Switch(Get-ChildItem -Path $TeamsDiagFolder) {
                {$_.Name -match "MSTeams Diagnostics Log"} {
                    echo "Teams diag log files are present"
                    }
                }            
        } else {
            Write-LogError "Teams Diagnostics logs are not present"
        }


Write-host
Write-host
Write-Host "You are running the script with the '-Teams' command line parameter. This will collect Teams specific logs for troubleshooting Teams WVD optimization issues with the Teams desktop app or calls/meetings.

Please make sure that the script is running under the affected user's WVD session and that the affected user has pressed Ctrl+Alt+Shift+1 within the open Teams application before starting this script, so that additional Teams diagnostics logs have been generated.
"
$confirm = Read-Host ("Do you confirm that these requirements are met? [Y/N]")
if ($confirm.ToLower() -ne "y") {exit}
}

Write-host
Write-LogTitle "Starting data collection (... please wait ...)" "White" "DarkCyan"
Write-host




##### Collecting files

        Write-Log "Collecting log files"
        New-Item -Path ($resFile + 'LogFiles\') -ItemType Directory | Out-Null
                     
        # Collecting DSC Logs

            if (Test-path -path 'c:\packages\plugins\microsoft.powershell.dsc') {

                $verfolder = get-ChildItem c:\packages\plugins\microsoft.powershell.dsc -recurse | foreach {If ($_.psiscontainer) {$_.fullname}} | select -first 1  
                $filepath = $verfolder + "\Status\"

                if (Test-path -path $filepath) {
                  Copy-Item $filepath ($resFile + "LogFiles\Microsoft.PowerShell.DSC\") -Recurse -ErrorAction Continue 2>>$errfile
                  Write-LogDetails "Copy-Item $filepath ($resFile + ""LogFiles\Microsoft.PowerShell.DSC\"") -ErrorAction Continue 2>>$errfile"
                } else {
                  Write-LogError "The DSC Provisioning log is not present"
                }

            } else {
              Write-LogError "The 'c:\packages\plugins\microsoft.powershell.dsc' folder is not present"
            }


        # Collecting Monitoring Agent Log

            if (Test-path -path 'C:\Packages\Plugins\Microsoft.EnterpriseCloud.Monitoring.MicrosoftMonitoringAgent') {

                $verfolder = get-ChildItem C:\Packages\Plugins\Microsoft.EnterpriseCloud.Monitoring.MicrosoftMonitoringAgent -recurse | foreach {If ($_.psiscontainer) {$_.fullname}} | select -first 1  
                $filepath = $verfolder + "\Status\"

                if (Test-path -path $filepath) {
                  Copy-Item $filepath ($resFile + "LogFiles\Microsoft.EnterpriseCloud.Monitoring.MicrosoftMonitoringAgent\") -Recurse -ErrorAction Continue 2>>$errfile
                  Write-LogDetails "Copy-Item $filepath ($resFile + ""LogFiles\Microsoft.EnterpriseCloud.Monitoring.MicrosoftMonitoringAgent\"") -ErrorAction Continue 2>>$errfile"
                } else {
                  Write-LogError "The Monitoring Agent log is not present"
                }

            } else {
              Write-LogError "The 'C:\Packages\Plugins\Microsoft.EnterpriseCloud.Monitoring.MicrosoftMonitoringAgent' folder is not present"
            }

            
        # Collecting Azure VM Agent Log

            if (Test-path -path 'C:\WindowsAzure\Logs\WaAppAgent.log') {  
              Copy-Item 'C:\WindowsAzure\Logs\WaAppAgent.log' ($resFile + "LogFiles\" + $env:computername + "_log_WaAppAgent.txt") -ErrorAction Continue 2>>$errfile
              Write-LogDetails "Copy-Item 'C:\WindowsAzure\Logs\WaAppAgent.log' ($resFile + ""LogFiles\"" + $env:computername + ""_log_WaAppAgent.txt"") -ErrorAction Continue 2>>$errfile"              
            } else {
              Write-LogError "The Azure VM Agent log is not present"
            }
            
        # Collecting Azure VM MonitoringAgent Log

            if (Test-path -path 'C:\WindowsAzure\Logs\MonitoringAgent.log') {  
              Copy-Item 'C:\WindowsAzure\Logs\MonitoringAgent.log' ($resFile + "LogFiles\" + $env:computername + "_log_MonitoringAgent.txt") -ErrorAction Continue 2>>$errfile
              Write-LogDetails "Copy-Item 'C:\WindowsAzure\Logs\MonitoringAgent.log' ($resFile + ""LogFiles\"" + $env:computername + ""_log_MonitoringAgent.txt"") -ErrorAction Continue 2>>$errfile"              
            } else {
              Write-LogError "The Azure VM MonitoringAgent log is not present"
            }

            
        # Collecting Domain Join Logs

            if (Test-path -path 'c:\packages\plugins\Microsoft.Compute.JsonADDomainExtension') {

                $verfolder = get-ChildItem c:\packages\plugins\Microsoft.Compute.JsonADDomainExtension -recurse | foreach {If ($_.psiscontainer) {$_.fullname}} | select -first 1  
                $filepath = $verfolder + "\Status\"

                if (Test-path -path $filepath) {
                  Copy-Item $filepath ($resFile + "LogFiles\Microsoft.Compute.JsonADDomainExtension\") -Recurse -ErrorAction Continue 2>>$errfile
                  Write-LogDetails "Copy-Item $filepath ($resFile + ""LogFiles\Microsoft.Compute.JsonADDomainExtension\"") -ErrorAction Continue 2>>$errfile"
                } else {
                  Write-LogError "The Domain Join log is not present"
                }

            } else {
              Write-LogError "The 'c:\packages\plugins\Microsoft.Compute.JsonADDomainExtension' folder is not present"
            }
                              

            if (Test-path -path 'C:\Windows\debug\NetSetup.LOG') {
              Copy-Item 'C:\Windows\debug\NetSetup.LOG' ($resFile + "LogFiles\" + $env:computername + "_log_NetSetup.txt") -ErrorAction Continue 2>>$errfile
              Write-LogDetails "Copy-Item 'C:\Windows\debug\NetSetup.LOG' ($resFile + ""LogFiles\"" + $env:computername + ""_log_NetSetup.txt"") -ErrorAction Continue 2>>$errfile"
            } else {
              Write-LogError "The NetSetup file is not present"
            }
            

        # Collecting Windows Azure Plugin Logs
        
            if (Test-path -path 'C:\WindowsAzure\Logs\Plugins') {
              Copy-Item 'C:\WindowsAzure\Logs\Plugins\*' ($resFile + "LogFiles\") -Recurse -ErrorAction Continue 2>>$errfile
              Write-LogDetails "Copy-Item 'C:\WindowsAzure\Logs\Plugins\*' ($resFile + ""LogFiles\"") -Recurse -ErrorAction Continue 2>>$errfile"
            } else {
              Write-LogError "The Windows Azure Plugins logs are not present"
            }

                
        # Collecting RDInfra Agent Log

            if (Test-path -path 'C:\Program Files\Microsoft RDInfra\AgentInstall.txt') {  
              Copy-Item 'C:\Program Files\Microsoft RDInfra\AgentInstall.txt' ($resFile + "LogFiles\" + $env:computername + "_log_AgentInstall.txt") -ErrorAction Continue 2>>$errfile
              Write-LogDetails "Copy-Item 'C:\Program Files\Microsoft RDInfra\AgentInstall.txt' ($resFile + ""LogFiles\"" + $env:computername + ""_log_AgentInstall.txt"") -ErrorAction Continue 2>>$errfile"              
            } else {
              Write-LogError "The RDInfra Agent log is not present"
            }


        # Collecting WVDAgent Log (from Windows 7 hosts)

        if ($ver -like "*Windows 7*") {
            if (Test-path -path 'C:\Program Files\Microsoft RDInfra\WVDAgentManagerInstall.txt') {  
              Copy-Item 'C:\Program Files\Microsoft RDInfra\WVDAgentManagerInstall.txt' ($resFile + "LogFiles\" + $env:computername + "_log_WVDAgentManagerInstall.txt") -ErrorAction Continue 2>>$errfile
              Write-LogDetails "Copy-Item 'C:\Program Files\Microsoft RDInfra\WVDAgentManagerInstall.txt' ($resFile + ""LogFiles\"" + $env:computername + ""_log_WVDAgentManagerInstall.txt"") -ErrorAction Continue 2>>$errfile"              
            } else {
              Write-LogError "The WVDAgent log is not present"
            }
        }


        # Collecting RDInfra Geneva Log

            if (Test-path -path 'C:\Program Files\Microsoft RDInfra\GenevaInstall.txt') {
              Copy-Item 'C:\Program Files\Microsoft RDInfra\GenevaInstall.txt' ($resFile + "LogFiles\" + $env:computername + "_log_GenevaInstall.txt") -ErrorAction Continue 2>>$errfile
              Write-LogDetails "Copy-Item 'C:\Program Files\Microsoft RDInfra\GenevaInstall.txt' ($resFile + ""LogFiles\"" + $env:computername + ""_log_GenevaInstall.txt"") -ErrorAction Continue 2>>$errfile"
            } else {
              Write-LogError "The RDInfra Geneva Agent log is not present"
            }


        # Collecting RDInfra SXS Log

            if (Test-path -path 'C:\Program Files\Microsoft RDInfra\SXSStackInstall.txt') {
              Copy-Item 'C:\Program Files\Microsoft RDInfra\SXSStackInstall.txt' ($resFile + "LogFiles\" + $env:computername + "_log_SXSStackInstall.txt") -ErrorAction Continue 2>>$errfile
              Write-LogDetails "Copy-Item 'C:\Program Files\Microsoft RDInfra\SXSStackInstall.txt' ($resFile + ""LogFiles\"" + $env:computername + ""_log_SXSStackInstall.txt"") -ErrorAction Continue 2>>$errfile"
            } else {
              Write-LogError "The RDInfra SXSStack log is not present"
            }


        # Collecting Scriptlog

            if (Test-path -path 'C:\Windows\Temp\ScriptLog.log') {
              Copy-Item 'C:\Windows\Temp\ScriptLog.log' ($resFile + "LogFiles\" + $env:computername + "_log_ScriptLog.txt") -ErrorAction Continue 2>>$errfile
              Write-LogDetails "Copy-Item 'C:\Windows\Temp\ScriptLog.log' ($resFile + ""LogFiles\"" + $env:computername + ""_log_ScriptLog.txt"") -ErrorAction Continue 2>>$errfile"
            } else {
              Write-LogError "The ScriptLog file is not present"
            }

                    
        # Collecting FSLogix related Logs

            if ($Profile) {
                if (Test-path -path 'C:\ProgramData\FSLogix\Logs') {
                  Copy-Item 'C:\ProgramData\FSLogix\Logs\' ($resFile + "FSLogix\") -Recurse -ErrorAction Continue 2>>$errfile
                  Write-LogDetails "Copy-Item 'C:\ProgramData\FSLogix\Logs\' ($resFile + ""FSLogix\"") -Recurse -ErrorAction Continue 2>>$errfile"
                } else {
                  Write-LogError "The FSLogix logs are not present"
                }               
                
                                
                if (Test-path -path 'C:\Program Files\FSLogix\apps') {
                    $cmd = "c:\program files\fslogix\apps\frx.exe" 
                    "FSLogix: 'frx list-redirects' output:" | Out-File -FilePath ($resFile + "FSLogix\" + $env:computername + "_Frx-list.txt") -Append
                    " " | Out-File -FilePath ($resFile + "FSLogix\" + $env:computername + "_Frx-list.txt") -Append
                    Invoke-Expression "& '$cmd' + 'list-redirects'" | Out-File -FilePath ($resFile + "FSLogix\" + $env:computername + "_Frx-list.txt") -Append

                    " " | Out-File -FilePath ($resFile + "FSLogix\" + $env:computername + "_Frx-list.txt") -Append
                    "==========================================" | Out-File -FilePath ($resFile + "FSLogix\" + $env:computername + "_Frx-list.txt") -Append
                    " " | Out-File -FilePath ($resFile + "FSLogix\" + $env:computername + "_Frx-list.txt") -Append

                    "FSLogix: 'frx list-rules' output:" | Out-File -FilePath ($resFile + "FSLogix\" + $env:computername + "_Frx-list.txt") -Append
                    " " | Out-File -FilePath ($resFile + "FSLogix\" + $env:computername + "_Frx-list.txt") -Append
                    Invoke-Expression "& '$cmd' + 'list-rules'" | Out-File -FilePath ($resFile + "FSLogix\" + $env:computername + "_Frx-list.txt") -Append
                }
            }
            



##### Collecting DSC configuration information

    Write-Log "Collecting DSC configuration information"

    Write-LogDetails "Get-DscConfiguration output"
    Get-DscConfiguration 2>>$errfile | Out-File -FilePath ($resFile + "Get-DscConfiguration.txt") -Append

    " " | Out-File -FilePath ($resFile + "Get-DscConfiguration.txt") -Append
    "==========================================" | Out-File -FilePath ($resFile + "Get-DscConfiguration.txt") -Append
    " " | Out-File -FilePath ($resFile + "Get-DscConfiguration.txt") -Append

    Write-LogDetails "Get-DscConfigurationStatus output"
    Get-DscConfigurationStatus -all 2>>$errfile | Out-File -FilePath ($resFile + "Get-DscConfiguration.txt") -Append



##### Collecting Geneva scheduled task information from non-Win7 machines

if (!($ver -like "*Windows 7*")) {
            Write-Log "Collecting Geneva scheduled task information"        
            if (Get-ScheduledTask GenevaTask* -ErrorAction Ignore) { 
                (Get-ScheduledTask GenevaTask*).TaskName | ForEach-Object -Process {
                    $cmd = "Export-ScheduledTask -TaskName $_ >>""" + $resFile + "schtasks_" + $_ + ".xml""" + $RdrErr
                    Write-LogDetails $cmd
                    Invoke-Expression $cmd

                    $cmd = "Get-ScheduledTaskInfo -TaskName $_ >>""" + $resFile + "schtasks_" + $_ + "_Info.txt""" + $RdrErr
                    Write-LogDetails $cmd
                    Invoke-Expression $cmd
                }
            } else { 
                Write-LogError "The Geneva Scheduled Task is not present"
            }
}


##### Collecting RDP and networking information

        Write-Log "Collecting RDP and networking information"


        # Get-NetConnectionProfile output
        if (!($ver -like "*Windows 7*")) {
            Get-NetConnectionProfile | Out-File -FilePath ($resFile + "NetConnectionProfile.txt") -Append
            Write-LogDetails "Get-NetConnectionProfile | Out-File -FilePath ($resFile + ""NetConnectionProfile.txt"") -Append"
        }

        # Collecting firewall rules

            $cmd = "netsh advfirewall firewall show rule name=all >""" + $resFile + "FirewallRules.txt""" + $RdrErr
            Write-LogDetails $cmd
            Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append


        # Collecting netstat output

            $cmd = "netstat -anob >""" + $resFile + "Netstat.txt""" + $RdrErr
            Write-LogDetails $cmd
            Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append


        # Collecting ipconfig /all output

            $cmd = "ipconfig /all >""" + $resFile + "Ipconfig.txt""" + $RdrErr
            Write-LogDetails $cmd
            Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append


        # Collecting proxy settings

            $cmd = "netsh winhttp show proxy >""" + $resFile + "WinHTTP-Proxy.txt""" + $RdrErr
            Write-LogDetails $cmd
            Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append


            "------------------" | Out-File -FilePath ($resFile + "WinHTTP-Proxy.txt") -Append
            "NSLookup WPAD" | Out-File -FilePath ($resFile + "WinHTTP-Proxy.txt") -Append
            "" | Out-File -FilePath ($resFile + "WinHTTP-Proxy.txt") -Append
            $cmd = "nslookup wpad >>""" + $resFile + "WinHTTP-Proxy.txt""" + $RdrErr
            Write-LogDetails $cmd
            Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append


        # Collecting qwinsta information

            $cmd = "qwinsta /counter >>""" + $resFile + "Qwinsta.txt""" + $RdrErr
            Write-LogDetails $cmd
            Invoke-Expression $cmd



##### Collecting policy information

        Write-Log "Collecting group policy information (gpresult)"

        $cmd = "gpresult /h """ + $resFile + "Gpresult.html""" + $RdrErr
        write-LogDetails $cmd
        Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

        $cmd = "gpresult /r /v >""" + $resFile + "Gpresult.txt""" + $RdrErr
        write-LogDetails $cmd
        Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append


##### Collecting group memberships

        Write-Log "Collecting group membership information"


        # Exporting members of Remote Desktop Users group

            if ([ADSI]::Exists("WinNT://localhost/Remote Desktop Users")) {
                $cmd = "net localgroup ""Remote Desktop Users"" >>""" + $resFile + "LocalGroupsMembership.txt""" + $RdrErr
                Write-LogDetails $cmd
                Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append
            } else {
                Write-LogError "The 'Remote Desktop Users' group is not present"
            }
              
                                      
        # Exporting members of Offer Remote Assistance Helpers group

            if ($MSRA) {
                if ([ADSI]::Exists("WinNT://localhost/Offer Remote Assistance Helpers")) {
                    $cmd = "net localgroup ""Offer Remote Assistance Helpers"" >>""" + $resFile + "LocalGroupsMembership.txt""" + $RdrErr
                    Write-LogDetails $cmd
                    Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append
                } else {
                    Write-LogError "The 'Offer Remote Assistance Helpers' group is not present"
                }

                if ([ADSI]::Exists("WinNT://localhost/Distributed COM Users")) {
                    $cmd = "net localgroup ""Distributed COM Users"" >>""" + $resFile + "LocalGroupsMembership.txt""" + $RdrErr
                    Write-LogDetails $cmd
                    Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append
                } else {
                    Write-LogError "The 'Distributed COM Users' group is not present"
                }
            }



##### Collecting registry keys

        Write-Log "Collecting registry key information"
        New-Item -Path ($resFile + 'RegistryKeys\') -ItemType Directory | Out-Null


        # Collecting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RDInfraAgent

            if (Test-Path HKLM:\SOFTWARE\Microsoft\RDInfraAgent) {        
            $cmd = "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RDInfraAgent """ + $resFile + "RegistryKeys\" + $env:computername + "_reg_SW-MS-RDInfraAgent.txt"" /y " + $RdrOut + $RdrErr
            Write-LogDetails $cmd
            Invoke-Expression $cmd
            } else {
              Write-LogError "The registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RDInfraAgent is not present"
            }


        # Collecting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RDAgentBootLoader
            if (!($ver -like "*Windows 7*")) {
                if (Test-Path HKLM:\SOFTWARE\Microsoft\RDAgentBootLoader) {        
                $cmd = "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RDAgentBootLoader """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_SW-MS-RDAgentBootLoader.txt"" /y" + $RdrOut + $RdrErr
                Write-LogDetails $cmd
                Invoke-Expression $cmd
                } else {
                  Write-LogError "The registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RDAgentBootLoader is not present"
                }
            } else {
                if (Test-Path HKLM:\SOFTWARE\Microsoft\WVDAgentManager) {        
                $cmd = "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WVDAgentManager """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_SW-MS-WVDAgentManager.txt"" /y" + $RdrOut + $RdrErr
                Write-LogDetails $cmd
                Invoke-Expression $cmd
                } else {
                  Write-LogError "The registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WVDAgentManager is not present"
                }
            }

        # Collecting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RDMonitoringAgent

            if (Test-Path HKLM:\SOFTWARE\Microsoft\RDMonitoringAgent) {        
            $cmd = "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RDMonitoringAgent """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_SW-MS-RDMonitoringAgent.txt"" /y" + $RdrOut + $RdrErr
            Write-LogDetails $cmd
            Invoke-Expression $cmd
            } else {
              Write-LogError "The registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RDMonitoringAgent is not present"
            }


        # Collecting registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server

            if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server') {        
            $cmd = "reg export 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server' """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_System-CCS-Control-TerminalServer.txt"" /y" + $RdrOut + $RdrErr
            Write-LogDetails $cmd
            Invoke-Expression $cmd
            } else {
              Write-LogError "The registry key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server' is not present"
            }

        
        # Collecting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server

            if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server') {        
            $cmd = "reg export 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server' """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_SW-MS-WinNT-CV-TerminalServer.txt"" /y" + $RdrOut + $RdrErr
            Write-LogDetails $cmd
            Invoke-Expression $cmd
            } else {
              Write-LogError "The registry key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server' is not present"
            }


        # Collecting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Terminal Server Client

            if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Terminal Server Client') {        
            $cmd = "reg export 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Terminal Server Client' """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_SW-MS-TerminalServerClient.txt"" /y" + $RdrOut + $RdrErr
            Write-LogDetails $cmd
            Invoke-Expression $cmd
            } else {
              Write-LogError "The registry key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Terminal Server Client' is not present"
            }


        # Collecting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies

            if (Test-Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies) {        
            $cmd = "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_SW-MS-Win-CV-Policies.txt"" /y" + $RdrOut + $RdrErr
            Write-LogDetails $cmd
            Invoke-Expression $cmd
            } else {
              Write-LogError "The registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies is not present"
            }


        # Collecting registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders

            if (Test-Path HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders) {        
            $cmd = "reg export HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_System-CCS-Control-SecurityProviders.txt"" /y" + $RdrOut + $RdrErr
            Write-LogDetails $cmd
            Invoke-Expression $cmd
            } else {
              Write-LogError "The registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders is not present"
            }


        # Collecting registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography

            if (Test-Path HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography) {        
            $cmd = "reg export HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_System-CCS-Control-Cryptography.txt"" /y" + $RdrOut + $RdrErr
            Write-LogDetails $cmd
            Invoke-Expression $cmd
            } else {
              Write-LogError "The registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography is not present"
            }


        # Collecting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography

            if (Test-Path HKLM:\SOFTWARE\Policies\Microsoft\Cryptography) {        
            $cmd = "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_SW-Policies-MS-Cryptography.txt"" /y" + $RdrOut + $RdrErr
            Write-LogDetails $cmd
            Invoke-Expression $cmd
            } else {
              Write-LogError "The registry key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography is not present"
            }


        # Collecting registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa

            if (Test-Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa) {        
            $cmd = "reg export HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_System-CCS-Control-LSA.txt"" /y" + $RdrOut + $RdrErr
            Write-LogDetails $cmd
            Invoke-Expression $cmd
            } else {
              Write-LogError "The registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa is not present"
            }


        # Collecting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation

            if (Test-Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation) {          
              $cmd = "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_SW-Policies-MS-Win-CredentialsDelegation.txt"" /y" + $RdrOut + $RdrErr
              Write-LogDetails $cmd
              Invoke-Expression $cmd
            } else {
              Write-LogError "The registry key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation is not present"
            }


        # Collecting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services

            if (Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services') {          
              $cmd = "reg export 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_SW-Policies-MS-WinNT-TerminalServices.txt"" /y" + $RdrOut + $RdrErr
              Write-LogDetails $cmd
              Invoke-Expression $cmd
            } else {
              Write-LogError "The registry key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' is not present"
            }
        

        # Collecting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Azure\DSC

            if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Azure\DSC') {          
              $cmd = "reg export 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Azure\DSC' """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_SW-MS-Azure-DSC.txt"" /y" + $RdrOut + $RdrErr
              Write-LogDetails $cmd
              Invoke-Expression $cmd
            } else {
              Write-LogError "The registry key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Azure\DSC' is not present"
            }


        # Collecting registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinRM

            if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\WinRM') {          
              $cmd = "reg export 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinRM' """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_System-CCS-Svc-WinRM.txt"" /y" + $RdrOut + $RdrErr
              Write-LogDetails $cmd
              Invoke-Expression $cmd
            } else {
              Write-LogError "The registry key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinRM' is not present"
            }


        # Collecting registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TermService

            if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\TermService') {          
              $cmd = "reg export 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TermService' """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_System-CCS-Svc-TermService.txt"" /y" + $RdrOut + $RdrErr
              Write-LogDetails $cmd
              Invoke-Expression $cmd
            } else {
              Write-LogError "The registry key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TermService' is not present"
            }


        # Collecting registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UmRdpService

            if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\UmRdpService') {          
              $cmd = "reg export 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UmRdpService' """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_System-CCS-Svc-UmRdpService.txt"" /y" + $RdrOut + $RdrErr
              Write-LogDetails $cmd
              Invoke-Expression $cmd
            } else {
              Write-LogError "The registry key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UmRdpService' is not present"
            }


        # Collecting registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RdAgent

            if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\RdAgent') {          
              $cmd = "reg export 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RdAgent' """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_System-CCS-Svc-RdAgent.txt"" /y" + $RdrOut + $RdrErr
              Write-LogDetails $cmd
              Invoke-Expression $cmd
            } else {
              Write-LogError "The registry key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RdAgent' is not present"
            }


        # Collecting registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RDAgentBootLoader

        if (!($ver -like "*Windows 7*")) {
            if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\RDAgentBootLoader') {          
              $cmd = "reg export 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RDAgentBootLoader' """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_System-CCS-Svc-RDAgentBootLoader.txt"" /y" + $RdrOut + $RdrErr
              Write-LogDetails $cmd
              Invoke-Expression $cmd
            } else {
              Write-LogError "The registry key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RDAgentBootLoader' is not present"
            }
        } else {
            if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\WVDAgentManager') {          
              $cmd = "reg export 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WVDAgentManager' """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_System-CCS-Svc-WVDAgentManager.txt"" /y" + $RdrOut + $RdrErr
              Write-LogDetails $cmd
              Invoke-Expression $cmd
            } else {
              Write-LogError "The registry key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WVDAgentManager' is not present"
            }

            if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\WVDAgent') {          
              $cmd = "reg export 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WVDAgent' """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_System-CCS-Svc-WVDAgent.txt"" /y" + $RdrOut + $RdrErr
              Write-LogDetails $cmd
              Invoke-Expression $cmd
            } else {
              Write-LogError "The registry key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WVDAgent' is not present"
            }
        }    


        # Collecting registry key HKEY_LOCAL_MACHINE\SOFTWARE\FSLogix

            if ($Profile) {
                if (Test-Path HKLM:\SOFTWARE\FSLogix) {          
                  $cmd = "reg export HKEY_LOCAL_MACHINE\SOFTWARE\FSLogix """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_SW-FSLogix.txt"" /y" + $RdrOut + $RdrErr
                  Write-LogDetails $cmd
                  Invoke-Expression $cmd
                } else {
                  Write-LogError "The registry key HKEY_LOCAL_MACHINE\SOFTWARE\FSLogix is not present"
                }
        

        # Collecting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\FSLogix

                if (Test-Path HKLM:\SOFTWARE\FSLogix) {          
                  $cmd = "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Policies\FSLogix """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_SW-Policies-FSLogix.txt"" /y" + $RdrOut + $RdrErr
                  Write-LogDetails $cmd
                  Invoke-Expression $cmd
                } else {
                  Write-LogError "The registry key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\FSLogix is not present"
                }
            
            
        # Collecting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions + Paths + Processes

                if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions') {          
                  $cmd = "reg export 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions' """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_SW-MS-WinDef-Excl-Extensions.txt"" /y" + $RdrOut + $RdrErr
                  Write-LogDetails $cmd
                  Invoke-Expression $cmd
                } else {
                  Write-LogError "The registry key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions' is not present"
                }          
                      
                if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths') {          
                  $cmd = "reg export 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths' """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_SW-MS-WinDef-Excl-Paths.txt"" /y" + $RdrOut + $RdrErr
                  Write-LogDetails $cmd
                  Invoke-Expression $cmd
                } else {
                  Write-LogError "The registry key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths' is not present"
                }          
            
                if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes') {          
                  $cmd = "reg export 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes' """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_SW-MS-WinDef-Excl-Processes.txt"" /y" + $RdrOut + $RdrErr
                  Write-LogDetails $cmd
                  Invoke-Expression $cmd
                } else {
                  Write-LogError "The registry key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes' is not present"
                }   
            
            }


        # Collecting registry key HKEY_CURRENT_USER\SOFTWARE\Microsoft\RdClientRadc

           if (Test-Path HKCU:\SOFTWARE\Microsoft\RdClientRadc) {          
              $cmd = "reg export HKEY_CURRENT_USER\SOFTWARE\Microsoft\RdClientRadc """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_SW-MS-RdClientRadc.txt"" /y" + $RdrOut + $RdrErr
              Write-LogDetails $cmd
              Invoke-Expression $cmd
            } else {
              Write-LogError "The registry key HKEY_CURRENT_USER\SOFTWARE\Microsoft\RdClientRadc is not present"
            } 


       # Collecting registry key HKEY_CURRENT_USER\SOFTWARE\Microsoft\Remote Desktop

           if (Test-Path 'HKCU:\SOFTWARE\Microsoft\Remote Desktop') {          
              $cmd = "reg export 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Remote Desktop' """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_SW-MS-RemoteDesktop.txt"" /y" + $RdrOut + $RdrErr
              Write-LogDetails $cmd
              Invoke-Expression $cmd
            } else {
              Write-LogError "The registry key 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Remote Desktop' is not present"
            }
       

       # Collecting registry key HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office

           if ($Profile) {
               if (Test-Path HKCU:\Software\Microsoft\Office) {          
                  $cmd = "reg export 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office' """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_FSLogix-SW-MS-Office.txt"" /y" + $RdrOut + $RdrErr
                  Write-LogDetails $cmd
                  Invoke-Expression $cmd
                } else {
                  Write-LogError "The registry key 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office' is not present"
                }


       # Collecting registry key HKEY_CURRENT_USER\Software\Policies\Microsoft\office

               if (Test-Path HKCU:\Software\Policies\Microsoft\office) {          
                  $cmd = "reg export 'HKEY_CURRENT_USER\Software\Policies\Microsoft\office' """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_FSLogix-SW-Policies-MS-Office.txt"" /y" + $RdrOut + $RdrErr
                  Write-LogDetails $cmd
                  Invoke-Expression $cmd
                } else {
                  Write-LogError "The registry key 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office' is not present"
                }
                
       # Collecting registry key HKEY_CURRENT_USER\SOFTWARE\Microsoft\OneDrive

               if (Test-Path HKCU:\SOFTWARE\Microsoft\OneDrive) {          
                  $cmd = "reg export 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\OneDrive' """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_FSLogix-SW-MS-OneDrive.txt"" /y" + $RdrOut + $RdrErr
                  Write-LogDetails $cmd
                  Invoke-Expression $cmd
                } else {
                  Write-LogError "The registry key 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\OneDrive' is not present"
                }
       

       # Collecting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Search

               if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows Search') {          
                  $cmd = "reg export 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Search' """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_FSLogix-SW-MS-WindowsSearch.txt"" /y" + $RdrOut + $RdrErr
                  Write-LogDetails $cmd
                  Invoke-Expression $cmd
                } else {
                  Write-LogError "The registry key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Search' is not present"
                }
 
      
       # Collecting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList

               if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList') {          
                  $cmd = "reg export 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_SW-MS-WinNT-CV-ProfileList.txt"" /y" + $RdrOut + $RdrErr
                  Write-LogDetails $cmd
                  Invoke-Expression $cmd
                } else {
                  Write-LogError "The registry key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' is not present"
                }
            }
          
        

##### Collecting event logs

        Write-Log "Collecting event log information"
        New-Item -Path ($resFile + 'EventLogs\') -ItemType Directory | Out-Null


        # Collecting System event log

            $cmd = "wevtutil epl System """+ $resFile + "EventLogs\" + $env:computername + "_evt_System.evtx""" + $RdrOut + $RdrErr
            Write-LogDetails $cmd
            Invoke-Expression $cmd
            ArchiveLog "System"
                

        # Collecting Application event log

            $cmd = "wevtutil epl Application """+ $resFile + "EventLogs\" + $env:computername + "_evt_Application.evtx""" + $RdrOut + $RdrErr
            Write-LogDetails $cmd
            Invoke-Expression $cmd
            ArchiveLog "Application"


        # Collecting Security event log

            $cmd = "wevtutil epl Security """+ $resFile + "EventLogs\" + $env:computername + "_evt_Security.evtx""" + $RdrOut + $RdrErr
            Write-LogDetails $cmd
            Invoke-Expression $cmd
            ArchiveLog "Security"
        
        
        # Collecting RemoteDesktopServices event log

            if (Get-WinEvent -ListLog RemoteDesktopServices -ErrorAction SilentlyContinue) {
                $cmd = "wevtutil epl RemoteDesktopServices """+ $resFile + "EventLogs\" + $env:computername + "_evt_RemoteDesktopServices.evtx""" + $RdrOut + $RdrErr
                Write-LogDetails $cmd
                Invoke-Expression $cmd
                ArchiveLog "RemoteDesktopServices"
            } else {
                Write-LogError "The event log 'RemoteDesktopServices' is not present"
            }


        # Collecting WindowsAzure Diagnostics and Status event logs
        
            if (Get-WinEvent -ListLog Microsoft-WindowsAzure-Diagnostics/Bootstrapper -ErrorAction SilentlyContinue) {
                $cmd = "wevtutil epl Microsoft-WindowsAzure-Diagnostics/Bootstrapper """+ $resFile + "EventLogs\" + $env:computername + "_evt_WindowsAzure-Diag-Bootstrapper.evtx""" + $RdrOut + $RdrErr
                Write-LogDetails $cmd
                Invoke-Expression $cmd
                ArchiveLog "WindowsAzure-Diag-Bootstrapper"
            } else {
                Write-LogError "The event log 'Microsoft-WindowsAzure-Diagnostics/Bootstrapper' is not present"
            }

            if (Get-WinEvent -ListLog Microsoft-WindowsAzure-Diagnostics/GuestAgent -ErrorAction SilentlyContinue) {
                $cmd = "wevtutil epl Microsoft-WindowsAzure-Diagnostics/GuestAgent """+ $resFile + "EventLogs\" + $env:computername + "_evt_WindowsAzure-Diag-GuestAgent.evtx""" + $RdrOut + $RdrErr
                Write-LogDetails $cmd
                Invoke-Expression $cmd
                ArchiveLog "WindowsAzure-Diag-GuestAgent"
            } else {
                Write-LogError "The event log 'Microsoft-WindowsAzure-Diagnostics/GuestAgent' is not present"
            }

            if (Get-WinEvent -ListLog Microsoft-WindowsAzure-Diagnostics/Heartbeat -ErrorAction SilentlyContinue) {
                $cmd = "wevtutil epl Microsoft-WindowsAzure-Diagnostics/Heartbeat """+ $resFile + "EventLogs\" + $env:computername + "_evt_WindowsAzure-Diag-Heartbeat.evtx""" + $RdrOut + $RdrErr
                Write-LogDetails $cmd
                Invoke-Expression $cmd
                ArchiveLog "WindowsAzure-Diag-Heartbeat"
            } else {
                Write-LogError "The event log 'Microsoft-WindowsAzure-Diagnostics/Heartbeat' is not present"
            }

            if (Get-WinEvent -ListLog Microsoft-WindowsAzure-Diagnostics/Runtime -ErrorAction SilentlyContinue) {
                $cmd = "wevtutil epl Microsoft-WindowsAzure-Diagnostics/Runtime """+ $resFile + "EventLogs\" + $env:computername + "_evt_WindowsAzure-Diag-Runtime.evtx""" + $RdrOut + $RdrErr
                Write-LogDetails $cmd
                Invoke-Expression $cmd
                ArchiveLog "WindowsAzure-Diag-Runtime"
            } else {
                Write-LogError "The event log 'Microsoft-WindowsAzure-Diagnostics/Runtime' is not present"
            }

            if (Get-WinEvent -ListLog Microsoft-WindowsAzure-Status/GuestAgent -ErrorAction SilentlyContinue) {
                $cmd = "wevtutil epl Microsoft-WindowsAzure-Status/GuestAgent """+ $resFile + "EventLogs\" + $env:computername + "_evt_WindowsAzure-Status-GuestAgent.evtx""" + $RdrOut + $RdrErr
                Write-LogDetails $cmd
                Invoke-Expression $cmd
                ArchiveLog "WindowsAzure-Status-GuestAgent"
            } else {
                Write-LogError "The event log 'Microsoft-WindowsAzure-Status/GuestAgent' is not present"
            }

            if (Get-WinEvent -ListLog Microsoft-WindowsAzure-Status/Plugins -ErrorAction SilentlyContinue) {
                $cmd = "wevtutil epl Microsoft-WindowsAzure-Status/Plugins """+ $resFile + "EventLogs\" + $env:computername + "_evt_WindowsAzure-Status-Plugins.evtx""" + $RdrOut + $RdrErr
                Write-LogDetails $cmd
                Invoke-Expression $cmd
                ArchiveLog "WindowsAzure-Status-Plugins"
            } else {
                Write-LogError "The event log 'Microsoft-WindowsAzure-Status/Plugins' is not present"
            }


        # Collecting CAPI2 event log

            if ($Certificate) {
                if (Get-WinEvent -ListLog Microsoft-Windows-CAPI2/Operational -ErrorAction SilentlyContinue) {
                    $cmd = "wevtutil epl Microsoft-Windows-CAPI2/Operational """+ $resFile + "EventLogs\" + $env:computername + "_evt_CAPI2.evtx""" + $RdrOut + $RdrErr
                    Write-LogDetails $cmd
                    Invoke-Expression $cmd
                    ArchiveLog "capi2"
                } else {
                    Write-LogError "The event log 'Microsoft-Windows-CAPI2/Operational' is not present"
                }
            }


        # Collecting DSC event log

            if (Get-WinEvent -ListLog Microsoft-Windows-DSC/Operational -ErrorAction SilentlyContinue) {
                $cmd = "wevtutil epl Microsoft-Windows-DSC/Operational """+ $resFile + "EventLogs\" + $env:computername + "_evt_DSC-Operational.evtx""" + $RdrOut + $RdrErr
                Write-LogDetails $cmd
                Invoke-Expression $cmd
                ArchiveLog "DSC-Operational"
            } else {
                Write-LogError "The event log 'Microsoft-Windows-DSC/Operational' is not present"
            }


        # Collecting WinRM event log

            if (Get-WinEvent -ListLog Microsoft-Windows-WinRM/Operational -ErrorAction SilentlyContinue) {
                $cmd = "wevtutil epl Microsoft-Windows-WinRM/Operational """+ $resFile + "EventLogs\" + $env:computername + "_evt_WinRM-Operational.evtx""" + $RdrOut + $RdrErr
                Write-LogDetails $cmd
                Invoke-Expression $cmd
                ArchiveLog "WinRM-Operational"
            } else {
                Write-LogError "The event log 'Microsoft-Windows-WinRM/Operational' is not present"
            }


        # Collecting PowerShell event log

            if (Get-WinEvent -ListLog Microsoft-Windows-PowerShell/Operational -ErrorAction SilentlyContinue) {
                $cmd = "wevtutil epl Microsoft-Windows-PowerShell/Operational """+ $resFile + "EventLogs\" + $env:computername + "_evt_PowerShell-Operational.evtx""" + $RdrOut + $RdrErr
                Write-LogDetails $cmd
                Invoke-Expression $cmd
                ArchiveLog "PowerShell-Operational"
            } else {
                Write-LogError "The event log 'Microsoft-Windows-PowerShell/Operational' is not present"
            }
            

        # Collecting Remote Desktop Services RdpCoreTS event logs
            
            if (Get-WinEvent -ListLog Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational -ErrorAction SilentlyContinue) {
                $cmd = "wevtutil epl Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational """+ $resFile + "EventLogs\" + $env:computername + "_evt_RemoteDesktopServicesRdpCoreTS-Operational.evtx""" + $RdrOut + $RdrErr
                Write-LogDetails $cmd
                Invoke-Expression $cmd
                ArchiveLog "RemoteDesktopServicesRdpCoreTS-Operational"
            } else {
                Write-LogError "The event log 'Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational' is not present"
            }

            if (Get-WinEvent -ListLog Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Admin -ErrorAction SilentlyContinue) {
                $cmd = "wevtutil epl Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Admin """+ $resFile + "EventLogs\" + $env:computername + "_evt_RemoteDesktopServicesRdpCoreTS-Admin.evtx""" + $RdrOut + $RdrErr
                Write-LogDetails $cmd
                Invoke-Expression $cmd
                ArchiveLog "RemoteDesktopServicesRdpCoreTS-Admin"
            } else {
                Write-LogError "The event log 'Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Admin' is not present"
            }


        # Collecting Remote Desktop Services RdpCoreCDV event log

            if (Get-WinEvent -ListLog Microsoft-Windows-RemoteDesktopServices-RdpCoreCDV/Operational -ErrorAction SilentlyContinue) {
                $cmd = "wevtutil epl Microsoft-Windows-RemoteDesktopServices-RdpCoreCDV/Operational """+ $resFile + "EventLogs\" + $env:computername + "_evt_RemoteDesktopServicesRdpCoreCDV-Operational.evtx""" + $RdrOut + $RdrErr
                Write-LogDetails $cmd
                Invoke-Expression $cmd
                ArchiveLog "RemoteDesktopServicesRdpCoreCDV-Operational"
            } else {
                Write-LogError "The event log 'Microsoft-Windows-RemoteDesktopServices-RdpCoreCDV/Operational' is not present"
            }


        # Collecting Terminal Services LocalSessionManager event logs

            if (Get-WinEvent -ListLog Microsoft-Windows-TerminalServices-LocalSessionManager/Operational -ErrorAction SilentlyContinue) {
                $cmd = "wevtutil epl Microsoft-Windows-TerminalServices-LocalSessionManager/Operational """+ $resFile + "EventLogs\" + $env:computername + "_evt_TerminalServicesLocalSessionManager-Operational.evtx""" + $RdrOut + $RdrErr
                Write-LogDetails $cmd
                Invoke-Expression $cmd
                ArchiveLog "TerminalServicesLocalSessionManager-Operational"
            } else {
                Write-LogError "The event log 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' is not present"
            }

            if (Get-WinEvent -ListLog Microsoft-Windows-TerminalServices-LocalSessionManager/Admin -ErrorAction SilentlyContinue) {
                $cmd = "wevtutil epl Microsoft-Windows-TerminalServices-LocalSessionManager/Admin """+ $resFile + "EventLogs\" + $env:computername + "_evt_TerminalServicesLocalSessionManager-Admin.evtx""" + $RdrOut + $RdrErr
                Write-LogDetails $cmd
                Invoke-Expression $cmd
                ArchiveLog "TerminalServicesLocalSessionManager-Admin"
            } else {
                Write-LogError "The event log 'Microsoft-Windows-TerminalServices-LocalSessionManager/Admin' is not present"
            }


        # Collecting Terminal Services RemoteConnectionManager event logs

            if (Get-WinEvent -ListLog Microsoft-Windows-TerminalServices-RemoteConnectionManager/Admin -ErrorAction SilentlyContinue) {
                $cmd = "wevtutil epl Microsoft-Windows-TerminalServices-RemoteConnectionManager/Admin """+ $resFile + "EventLogs\" + $env:computername + "_evt_TerminalServicesRemoteConnectionManager-Admin.evtx""" + $RdrOut + $RdrErr
                Write-LogDetails $cmd
                Invoke-Expression $cmd
                ArchiveLog "TerminalServicesRemoteConnectionManager-Admin"
            } else {
                Write-LogError "The event log 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Admin' is not present"
            }
            
            if (Get-WinEvent -ListLog Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational -ErrorAction SilentlyContinue) {
                $cmd = "wevtutil epl Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational """+ $resFile + "EventLogs\" + $env:computername + "_evt_TerminalServicesRemoteConnectionManager-Operational.evtx""" + $RdrOut + $RdrErr
                Write-LogDetails $cmd
                Invoke-Expression $cmd
                ArchiveLog "TerminalServicesRemoteConnectionManager-Operational"
            } else {
                Write-LogError "The event log 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' is not present"
            }


        # Collecting Terminal Services PnP Devices event logs

            if (Get-WinEvent -ListLog Microsoft-Windows-TerminalServices-PnPDevices/Admin -ErrorAction SilentlyContinue) {
                $cmd = "wevtutil epl Microsoft-Windows-TerminalServices-PnPDevices/Admin """+ $resFile + "EventLogs\" + $env:computername + "_evt_TerminalServicesPnPDevices-Admin.evtx""" + $RdrOut + $RdrErr
                Write-LogDetails $cmd
                Invoke-Expression $cmd
                ArchiveLog "TerminalServicesPnPDevices-Admin"
            } else {
                Write-LogError "The event log 'Microsoft-Windows-TerminalServices-PnPDevices/Admin' is not present"
            }

            if (Get-WinEvent -ListLog Microsoft-Windows-TerminalServices-PnPDevices/Operational -ErrorAction SilentlyContinue) {
                $cmd = "wevtutil epl Microsoft-Windows-TerminalServices-PnPDevices/Operational """+ $resFile + "EventLogs\" + $env:computername + "_evt_TerminalServicesPnPDevices-Operational.evtx""" + $RdrOut + $RdrErr
                Write-LogDetails $cmd
                Invoke-Expression $cmd
                ArchiveLog "TerminalServicesPnPDevices-Operational"
            } else {
                Write-LogError "The event log 'Microsoft-Windows-TerminalServices-PnPDevices/Operational' is not present"
            }


        # Collecting User Profile Service event log

            if ($Profile) {
                if (Get-WinEvent -ListLog 'Microsoft-Windows-User Profile Service/Operational' -ErrorAction SilentlyContinue) {
                    $cmd = "wevtutil epl 'Microsoft-Windows-User Profile Service/Operational' """+ $resFile + "EventLogs\" + $env:computername + "_evt_UserProfileService-Operational.evtx""" + $RdrOut + $RdrErr
                    Write-LogDetails $cmd
                    Invoke-Expression $cmd
                    ArchiveLog "UserProfileService-Operational"
                } else {
                    Write-LogError "The event log 'Microsoft-Windows-User Profile Service/Operational' is not present"
                }
            }

        # Collecting Remote Assistance event logs

            if ($MSRA) {
                if (Get-WinEvent -ListLog Microsoft-Windows-RemoteAssistance/Operational -ErrorAction SilentlyContinue) {
                    $cmd = "wevtutil epl 'Microsoft-Windows-RemoteAssistance/Operational' """+ $resFile + "EventLogs\" + $env:computername + "_evt_RemoteAssistance-Operational.evtx""" + $RdrOut + $RdrErr
                    Write-LogDetails $cmd
                    Invoke-Expression $cmd
                    ArchiveLog "RemoteAssistance-Operational"
                } else {
                    Write-LogError "The event log 'Microsoft-Windows-RemoteAssistance/Operational' is not present"
                }

                if (Get-WinEvent -ListLog Microsoft-Windows-RemoteAssistance/Admin -ErrorAction SilentlyContinue) {
                    $cmd = "wevtutil epl 'Microsoft-Windows-RemoteAssistance/Admin' """+ $resFile + "EventLogs\" + $env:computername + "_evt_RemoteAssistance-Admin.evtx""" + $RdrOut + $RdrErr
                    Write-LogDetails $cmd
                    Invoke-Expression $cmd
                    ArchiveLog "RemoteAssistance-Admin"
                } else {
                    Write-LogError "The event log 'Microsoft-Windows-RemoteAssistance/Admin' is not present"
                }
            }


        # Collecting VHDMP event logs

            if ($Profile) {
                if (Get-WinEvent -ListLog Microsoft-Windows-VHDMP-Operational -ErrorAction SilentlyContinue) {
                    $cmd = "wevtutil epl 'Microsoft-Windows-VHDMP-Operational' """+ $resFile + "EventLogs\" + $env:computername + "_evt_VHDMP-Operational.evtx""" + $RdrOut + $RdrErr
                    Write-LogDetails $cmd
                    Invoke-Expression $cmd
                    ArchiveLog "VHDMP-Operational"
                } else {
                    Write-LogError "The event log 'Microsoft-Windows-VHDMP-Operational' is not present"
                }


        # Collecting SMBclient and SMBserver event logs

                if (Get-WinEvent -ListLog Microsoft-Windows-SMBClient/Operational -ErrorAction SilentlyContinue) {
                    $cmd = "wevtutil epl 'Microsoft-Windows-SMBClient/Operational' """+ $resFile + "EventLogs\" + $env:computername + "_evt_SMBClient-Operational.evtx""" + $RdrOut + $RdrErr
                    Write-LogDetails $cmd
                    Invoke-Expression $cmd
                    ArchiveLog "SMBClient-Operational"
                } else {
                    Write-LogError "The event log 'Microsoft-Windows-SMBClient/Operational' is not present"
                }

                if (Get-WinEvent -ListLog Microsoft-Windows-SMBClient/Connectivity -ErrorAction SilentlyContinue) {
                    $cmd = "wevtutil epl 'Microsoft-Windows-SMBClient/Connectivity' """+ $resFile + "EventLogs\" + $env:computername + "_evt_SMBClient-Connectivity.evtx""" + $RdrOut + $RdrErr
                    Write-LogDetails $cmd
                    Invoke-Expression $cmd
                    ArchiveLog "SMBClient-Connectivity"
                } else {
                    Write-LogError "The event log 'Microsoft-Windows-SMBClient/Connectivity' is not present"
                }

                if (Get-WinEvent -ListLog Microsoft-Windows-SMBClient/Security -ErrorAction SilentlyContinue) {
                    $cmd = "wevtutil epl 'Microsoft-Windows-SMBClient/Security' """+ $resFile + "EventLogs\" + $env:computername + "_evt_SMBClient-Security.evtx""" + $RdrOut + $RdrErr
                    Write-LogDetails $cmd
                    Invoke-Expression $cmd
                    ArchiveLog "SMBClient-Security"
                } else {
                    Write-LogError "The event log 'Microsoft-Windows-SMBClient/Security' is not present"
                }

                if (Get-WinEvent -ListLog Microsoft-Windows-SMBServer/Operational -ErrorAction SilentlyContinue) {
                    $cmd = "wevtutil epl 'Microsoft-Windows-SMBServer/Operational' """+ $resFile + "EventLogs\" + $env:computername + "_evt_SMBServer-Operational.evtx""" + $RdrOut + $RdrErr
                    Write-LogDetails $cmd
                    Invoke-Expression $cmd
                    ArchiveLog "SMBServer-Operational"
                } else {
                    Write-LogError "The event log 'Microsoft-Windows-SMBServer/Operational' is not present"
                }

                if (Get-WinEvent -ListLog Microsoft-Windows-SMBServer/Connectivity -ErrorAction SilentlyContinue) {
                    $cmd = "wevtutil epl 'Microsoft-Windows-SMBServer/Connectivity' """+ $resFile + "EventLogs\" + $env:computername + "_evt_SMBServer-Connectivity.evtx""" + $RdrOut + $RdrErr
                    Write-LogDetails $cmd
                    Invoke-Expression $cmd
                    ArchiveLog "SMBServer-Connectivity"
                } else {
                    Write-LogError "The event log 'Microsoft-Windows-SMBServer/Connectivity' is not present"
                }

                if (Get-WinEvent -ListLog Microsoft-Windows-SMBServer/Security -ErrorAction SilentlyContinue) {
                    $cmd = "wevtutil epl 'Microsoft-Windows-SMBServer/Security' """+ $resFile + "EventLogs\" + $env:computername + "_evt_SMBServer-Security.evtx""" + $RdrOut + $RdrErr
                    Write-LogDetails $cmd
                    Invoke-Expression $cmd
                    ArchiveLog "SMBServer-Security"
                } else {
                    Write-LogError "The event log 'Microsoft-Windows-SMBServer/Security' is not present"
                }
            }



##### Collecting certificate information

    if ($Certificate) {
        Write-Log "Collecting certificate information"


        # Collecting certificates details

            $cmd = "Certutil -verifystore -v MY > """ + $resFile + "Certificates-My.txt""" + $RdrErr
            Write-LogDetails $cmd
            Invoke-Expression $cmd

            $tbCert = New-Object system.Data.DataTable
            $col = New-Object system.Data.DataColumn Store,([string]); $tbCert.Columns.Add($col)
            $col = New-Object system.Data.DataColumn Thumbprint,([string]); $tbCert.Columns.Add($col)
            $col = New-Object system.Data.DataColumn Subject,([string]); $tbCert.Columns.Add($col)
            $col = New-Object system.Data.DataColumn Issuer,([string]); $tbCert.Columns.Add($col)
            $col = New-Object system.Data.DataColumn NotAfter,([DateTime]); $tbCert.Columns.Add($col)
            $col = New-Object system.Data.DataColumn IssuerThumbprint,([string]); $tbCert.Columns.Add($col)
            $col = New-Object system.Data.DataColumn EnhancedKeyUsage,([string]); $tbCert.Columns.Add($col)
            $col = New-Object system.Data.DataColumn SerialNumber,([string]); $tbCert.Columns.Add($col)
            $col = New-Object system.Data.DataColumn SubjectKeyIdentifier,([string]); $tbCert.Columns.Add($col)
            $col = New-Object system.Data.DataColumn AuthorityKeyIdentifier,([string]); $tbCert.Columns.Add($col)
        
            GetStore "My"


        # Matching issuer thumbprints

            $aCert = $tbCert.Select("Store = 'My' ")
            foreach ($cert in $aCert) {
              $aIssuer = $tbCert.Select("SubjectKeyIdentifier = '" + ($cert.AuthorityKeyIdentifier).tostring() + "'")
              if ($aIssuer.Count -gt 0) {
                $cert.IssuerThumbprint = ($aIssuer[0].Thumbprint).ToString()
              }
            }
            $tbcert | Export-Csv ($resFile + "Certificates.tsv") -noType -Delimiter "`t"
    }



##### Collecting installed Windows updates

        Write-Log "Collecting list of installed Windows updates"
        Get-HotFix -ErrorAction SilentlyContinue 2>>$errfile | Sort-Object -Property InstalledOn -Descending -ErrorAction SilentlyContinue | Out-File ($resFile + "Hotfixes.txt")
        Write-LogDetails "Get-HotFix -ErrorAction SilentlyContinue 2>>$errfile | Sort-Object -Property InstalledOn -ErrorAction SilentlyContinue | Out-File ($resFile + ""Hotfixes.txt"")"
      


##### Collecting file versions and system information
        
        Write-Log "Collecting details about currently running processes"
        $proc = ExecQuery -Namespace "root\cimv2" -Query "select Name, CreationDate, ProcessId, ParentProcessId, WorkingSetSize, UserModeTime, KernelModeTime, ThreadCount, HandleCount, CommandLine, ExecutablePath from Win32_Process"
        if ($PSVersionTable.psversion.ToString() -ge "3.0") {
          $StartTime= @{e={$_.CreationDate.ToString("yyyyMMdd HH:mm:ss")};n="Start time"}
        } else {
          $StartTime= @{n='StartTime';e={$_.ConvertToDateTime($_.CreationDate)}}
        }

        if ($proc) {
          $proc | Sort-Object Name | Format-Table -AutoSize -property @{e={$_.ProcessId};Label="PID"}, @{e={$_.ParentProcessId};n="Parent"}, Name,
          @{N="WorkingSet";E={"{0:N0}" -f ($_.WorkingSetSize/1kb)};a="right"},
          @{e={[DateTime]::FromFileTimeUtc($_.UserModeTime).ToString("HH:mm:ss")};n="UserTime"}, @{e={[DateTime]::FromFileTimeUtc($_.KernelModeTime).ToString("HH:mm:ss")};n="KernelTime"},
          @{N="Threads";E={$_.ThreadCount}}, @{N="Handles";E={($_.HandleCount)}}, $StartTime, CommandLine | Out-String -Width 500 | Out-File -FilePath ($resFile + "RunningProcesses.txt")
        

          Write-Log "Collecting file version of running and key system binaries"
          $binlist = $proc | Group-Object -Property ExecutablePath
          foreach ($file in $binlist) {
            if ($file.Name) {
              FileVersion -Filepath ($file.name) -Log $true
            }
          }

          (get-item -Path 'C:\Windows\System32\*.dll').VersionInfo | Format-List -Force | Out-File ($resFile + "ver_System32_DLL.txt")
          (get-item -Path 'C:\Windows\System32\*.exe').VersionInfo | Format-List -Force | Out-File ($resFile + "ver_System32_EXE.txt")
          (get-item -Path 'C:\Windows\System32\*.sys').VersionInfo | Format-List -Force | Out-File ($resFile + "ver_System32_SYS.txt")
          (get-item -Path 'C:\Windows\System32\drivers\*.sys').VersionInfo | Format-List -Force | Out-File ($resFile + "ver_Drivers.txt")
          (get-item -Path 'C:\Windows\SysWOW64\*.dll').VersionInfo | Format-List -Force | Out-File ($resFile + "ver_SysWOW64_DLL.txt")
          (get-item -Path 'C:\Windows\SysWOW64\*.exe').VersionInfo | Format-List -Force | Out-File ($resFile + "ver_SysWOW64_EXE.txt")
        
        
        # Collecting MSRDC binary information (when installed in "per machine" mode)
                
          if (Test-Path 'C:\Program Files\Remote Desktop\msrdc.exe') {
              FileVersion -Filepath ("C:\Program Files\Remote Desktop\msrdc.exe") -Log $true
          } else {
              Write-LogError "The file 'C:\Program Files\Remote Desktop\msrdc.exe' is not present"
          }
        
          if (Test-Path 'C:\Program Files\Remote Desktop\msrdcw.exe') {
              FileVersion -Filepath ("C:\Program Files\Remote Desktop\msrdcw.exe") -Log $true
          } else {
              Write-LogError "The file 'C:\Program Files\Remote Desktop\msrdcw.exe' is not present"
          }
        

        # Collecting MSRDC binary information (when installed in "per user" mode - only from the current user)

        $msrdcpath = 'C:\Users\' + $env:USERNAME + '\AppData\Local\Apps\Remote Desktop\msrdc.exe'
        $msrdcwpath = 'C:\Users\' + $env:USERNAME + '\AppData\Local\Apps\Remote Desktop\msrdcw.exe'

          if (Test-Path $msrdcpath) {
              FileVersion -Filepath $msrdcpath -Log $true
          } else {
              Write-LogError "The file '$msrdcpath' is not present"
          }
        
          if (Test-Path $msrdcwpath) {
              FileVersion -Filepath $msrdcwpath -Log $true
          } else {
              Write-LogError "The file '$msrdcwpath' is not present"
          }
        
 

        # Collecting service details

          Write-Log "Collecting services details"
          $svc = ExecQuery -NameSpace "root\cimv2" -Query "select  ProcessId, DisplayName, StartMode,State, Name, PathName, StartName from Win32_Service"

          if ($svc) {
            $svc | Sort-Object DisplayName | Format-Table -AutoSize -Property ProcessId, DisplayName, StartMode,State, Name, PathName, StartName | Out-String -Width 400 | Out-File -FilePath ($resFile + "Services.txt")
          }
          


        # Collecting system information

          Write-Log "Collecting system information"

          $pad = 27
          $OS = ExecQuery -Namespace "root\cimv2" -Query "select Caption, CSName, OSArchitecture, BuildNumber, InstallDate, LastBootUpTime, LocalDateTime, TotalVisibleMemorySize, FreePhysicalMemory, SizeStoredInPagingFiles, FreeSpaceInPagingFiles from Win32_OperatingSystem"
          $CS = ExecQuery -Namespace "root\cimv2" -Query "select Model, Manufacturer, SystemType, NumberOfProcessors, NumberOfLogicalProcessors, TotalPhysicalMemory, DNSHostName, Domain, DomainRole from Win32_ComputerSystem"
          $BIOS = ExecQuery -Namespace "root\cimv2" -query "select BIOSVersion, Manufacturer, ReleaseDate, SMBIOSBIOSVersion from Win32_BIOS"
          $TZ = ExecQuery -Namespace "root\cimv2" -Query "select Description from Win32_TimeZone"
          $PR = ExecQuery -Namespace "root\cimv2" -Query "select Name, Caption from Win32_Processor"

          $ctr = Get-Counter -Counter "\Memory\Pool Paged Bytes" -ErrorAction Continue 2>>$errfile
          $PoolPaged = $ctr.CounterSamples[0].CookedValue 
          $ctr = Get-Counter -Counter "\Memory\Pool Nonpaged Bytes" -ErrorAction Continue 2>>$errfile
          $PoolNonPaged = $ctr.CounterSamples[0].CookedValue 

          "Computer name".PadRight($pad) + " : " + $OS.CSName | Out-File -FilePath ($resFile + "SystemInfo.txt") -Append
          "Model".PadRight($pad) + " : " + $CS.Model | Out-File -FilePath ($resFile + "SystemInfo.txt") -Append
          "Manufacturer".PadRight($pad) + " : " + $CS.Manufacturer | Out-File -FilePath ($resFile + "SystemInfo.txt") -Append
          "BIOS Version".PadRight($pad) + " : " + $BIOS.BIOSVersion | Out-File -FilePath ($resFile + "SystemInfo.txt") -Append
          "BIOS Manufacturer".PadRight($pad) + " : " + $BIOS.Manufacturer | Out-File -FilePath ($resFile + "SystemInfo.txt") -Append
          "BIOS Release date".PadRight($pad) + " : " + $BIOS.ReleaseDate | Out-File -FilePath ($resFile + "SystemInfo.txt") -Append
          "SMBIOS Version".PadRight($pad) + " : " + $BIOS.SMBIOSBIOSVersion | Out-File -FilePath ($resFile + "SystemInfo.txt") -Append
          "SystemType".PadRight($pad) + " : " + $CS.SystemType | Out-File -FilePath ($resFile + "SystemInfo.txt") -Append
          "Processor".PadRight($pad) + " : " + $PR.Name + " / " + $PR.Caption | Out-File -FilePath ($resFile + "SystemInfo.txt") -Append
          "Processors physical/logical".PadRight($pad) + " : " + $CS.NumberOfProcessors + " / " + $CS.NumberOfLogicalProcessors | Out-File -FilePath ($resFile + "SystemInfo.txt") -Append
          "Memory physical/visible".PadRight($pad) + " : " + ("{0:N0}" -f ($CS.TotalPhysicalMemory/1mb)) + " MB / " + ("{0:N0}" -f ($OS.TotalVisibleMemorySize/1kb)) + " MB" | Out-File -FilePath ($resFile + "SystemInfo.txt") -Append
          "Pool Paged / NonPaged".PadRight($pad) + " : " + ("{0:N0}" -f ($PoolPaged/1mb)) + " MB / " + ("{0:N0}" -f ($PoolNonPaged/1mb)) + " MB" | Out-File -FilePath ($resFile + "SystemInfo.txt") -Append
          "Free physical memory".PadRight($pad) + " : " + ("{0:N0}" -f ($OS.FreePhysicalMemory/1kb)) + " MB" | Out-File -FilePath ($resFile + "SystemInfo.txt") -Append
          "Paging files size / free".PadRight($pad) + " : " + ("{0:N0}" -f ($OS.SizeStoredInPagingFiles/1kb)) + " MB / " + ("{0:N0}" -f ($OS.FreeSpaceInPagingFiles/1kb)) + " MB" | Out-File -FilePath ($resFile + "SystemInfo.txt") -Append
          "Operating System".PadRight($pad) + " : " + $OS.Caption + " " + $OS.OSArchitecture | Out-File -FilePath ($resFile + "SystemInfo.txt") -Append


            [string]$WinVerBuild = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion' CurrentBuild).CurrentBuild
            [string]$WinVerRevision = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion' UBR).UBR

if (!($ver -like "*Windows 7*")) {                              
            [string]$WinVerMajor = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion' CurrentMajorVersionNumber).CurrentMajorVersionNumber
            [string]$WiNVerMinor = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion' CurrentMinorVersionNumber).CurrentMinorVersionNumber
            $WinVer = "Build Number".PadRight($pad) + " : " + $WinVerMajor + "." + $WiNVerMinor + "." + $WinVerBuild + "." + $WinVerRevision | Out-File -FilePath ($resFile + "SystemInfo.txt") -Append
} else {
            $WinVer = "Build Number".PadRight($pad) + " : " + $WinVerBuild + "." + $WinVerRevision | Out-File -FilePath ($resFile + "SystemInfo.txt") -Append
}
                      
          "Installation type".PadRight($pad) + " : " + (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").InstallationType | Out-File -FilePath ($resFile + "SystemInfo.txt") -Append
          "Time zone".PadRight($pad) + " : " + $TZ.Description | Out-File -FilePath ($resFile + "SystemInfo.txt") -Append
          "Install date".PadRight($pad) + " : " + $OS.InstallDate | Out-File -FilePath ($resFile + "SystemInfo.txt") -Append
          "Last boot time".PadRight($pad) + " : " + $OS.LastBootUpTime | Out-File -FilePath ($resFile + "SystemInfo.txt") -Append
          "Local time".PadRight($pad) + " : " + $OS.LocalDateTime | Out-File -FilePath ($resFile + "SystemInfo.txt") -Append
          "DNS Hostname".PadRight($pad) + " : " + $CS.DNSHostName | Out-File -FilePath ($resFile + "SystemInfo.txt") -Append
          "DNS Domain name".PadRight($pad) + " : " + $CS.Domain | Out-File -FilePath ($resFile + "SystemInfo.txt") -Append
          "NetBIOS Domain name".PadRight($pad) + " : " + (GetNBDomainName) | Out-File -FilePath ($resFile + "SystemInfo.txt") -Append
          $roles = "Standalone Workstation", "Member Workstation", "Standalone Server", "Member Server", "Backup Domain Controller", "Primary Domain Controller"
          "Domain role".PadRight($pad) + " : " + $roles[$CS.DomainRole] | Out-File -FilePath ($resFile + "SystemInfo.txt") -Append

          " " | Out-File -FilePath ($resfile + "SystemInfo.txt") -Append

          $drives = @()
          $drvtype = "Unknown", "No Root Directory", "Removable Disk", "Local Disk", "Network Drive", "Compact Disc", "RAM Disk"
          $Vol = ExecQuery -NameSpace "root\cimv2" -Query "select * from Win32_LogicalDisk"
          foreach ($disk in $vol) {
            $drv = New-Object PSCustomObject
            $drv | Add-Member -type NoteProperty -name Letter -value $disk.DeviceID 
            $drv | Add-Member -type NoteProperty -name DriveType -value $drvtype[$disk.DriveType]
            $drv | Add-Member -type NoteProperty -name VolumeName -value $disk.VolumeName 
            $drv | Add-Member -type NoteProperty -Name TotalMB -Value ($disk.size)
            $drv | Add-Member -type NoteProperty -Name FreeMB -value ($disk.FreeSpace)
            $drives += $drv
          }
          $drives | 
          Format-Table -AutoSize -property Letter, DriveType, VolumeName, @{N="TotalMB";E={"{0:N0}" -f ($_.TotalMB/1MB)};a="right"}, @{N="FreeMB";E={"{0:N0}" -f ($_.FreeMB/1MB)};a="right"} |
          Out-File -FilePath ($resFile + "SystemInfo.txt") -Append
       } else {
          $proc = Get-Process | Where-Object {$_.Name -ne "Idle"}
          $proc | Format-Table -AutoSize -property id, name, @{N="WorkingSet";E={"{0:N0}" -f ($_.workingset/1kb)};a="right"},
          @{N="VM Size";E={"{0:N0}" -f ($_.VirtualMemorySize/1kb)};a="right"},
          @{N="Proc time";E={($_.TotalProcessorTime.ToString().substring(0,8))}}, @{N="Threads";E={$_.threads.count}},
          @{N="Handles";E={($_.HandleCount)}}, StartTime, Path | 
          Out-String -Width 300 | Out-File -FilePath ($resFile + "RunningProcesses.txt")
        }


        ### Collecting PowerShell version
        $PSVersionTable | ft Name, Value | Out-File -FilePath ($resfile + "SystemInfo.txt") -Append

        
        $cmd = "msinfo32 /nfo """ + $resFile + "msinfo32.nfo""" + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression $cmd

        while (!(Test-Path ($resFile + "msinfo32.nfo"))) { Start-Sleep 30 }


        ### Collecting MiniFilter driver information
        
        $cmd = "fltmc filters >""" + $resFile + "Fltmc.txt""" + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append



##### Collecting RDClient AutoTraces

    if ($ClientAutoTrace) {
        
        Write-Log "Collecting RDClient AutoTraces"

        $ETLfolder = 'C:\Users\' + $env:USERNAME + '\AppData\Local\Temp\DiagOutputDir\RdClientAutoTrace\'
        
        if (Test-path -path $ETLfolder) {
                        
            Copy-Item $ETLfolder ($resFile + 'RdClientAutoTrace\') -Recurse -ErrorAction Continue 2>>$errfile            
            Write-LogDetails "Copy-Item $ETLfolder ($resFile + ""RdClientAutoTrace\"") -Recurse -ErrorAction Continue 2>>$errfile"
        } else {
            Write-LogError "The RD Client AutoTrace folder is not present"
        }
}



##### Collecting Monitoring\Tables traces

    if ($MonTables) {
        
        Write-Log "Collecting Monitoring\Tables traces"

        $ETLfolder = 'C:\Windows\System32\config\systemprofile\AppData\Roaming\Microsoft\Monitoring\Tables'
        
        if (Test-path -path $ETLfolder) {
                        
            New-Item -Path ($resFile + 'MonitoringTables\') -ItemType Directory | Out-Null     
            
            Switch(Get-ChildItem -Path "C:\Program Files\Microsoft RDInfra\") {
                {$_.Name -match "RDMonitoringAgent"} {
                    $convertpath = "C:\Program Files\Microsoft RDInfra\" + $_.Name + "\Agent\table2csv.exe"
                }
            }

            Switch(Get-ChildItem -Path $ETLfolder) {
                {($_.Name -notmatch "00000") -and ($_.Name -match ".tsf")} {
                    $monfile = $ETLfolder + "\" + $_.name
                    $targetpath = $resFile + "MonitoringTables\"
                    $cmd = "cmd /c ""$convertpath""" + " -path ""$targetpath"" ""$monfile""" + $RdrOut + $RdrErr
                    Write-LogDetails $cmd
                    Invoke-Expression $cmd
                }
            }
        } else {
            Write-LogError "The Monitoring\Tables folder is not present"
        }
}



##### Collecting WinRM configuration

    Write-Log "Collecting WinRM configuration"
    
    $diagfile = $resFile + "WinRM-Config.txt"

    if ((get-service -name WinRM).status -eq "Running") {
        $config = Get-ChildItem WSMan:\localhost\ -Recurse -ErrorAction Continue 2>>$errfile
        if (!$config) {
          Write-Diag ("Cannot connect to localhost, trying with FQDN " + $fqdn)
          Connect-WSMan -ComputerName $fqdn -ErrorAction Continue 2>>$errfile
          $config = Get-ChildItem WSMan:\$fqdn -Recurse -ErrorAction Continue 2>>$errfile
          Disconnect-WSMan -ComputerName $fqdn -ErrorAction Continue 2>>$errfile
        }

        $config | out-file -FilePath $diagfile -Append
    
        Write-LogDetails "winrm get winrm/config"
        $cmd = "winrm get winrm/config >>""" + $resFile + "WinRM-Config.txt""" + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

        Write-LogDetails "winrm e winrm/config/listener"
        $cmd = "winrm e winrm/config/listener >>""" + $resFile + "WinRM-Config.txt""" + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append
    } else {
        Write-Diag ("WinRM service is not running. Skipping collection of WinRM configuration data.")
    }
       

##### Collecting Teams diagnostics data

if($Teams) {

    Write-Log "Collecting Teams diagnostics data"
    New-Item -Path ($resFile + 'LogFiles\Teams\') -ItemType Directory | Out-Null

    $realprofile = query user | Select-String '^>(\w+)' | ForEach-Object { $_.Matches[0].Groups[1].Value }  
    # this 'realprofile' is required as the script runs elevated with potentially different admin credentials and we need the logs from the actual logged in user's profile who has the issue and who may not be the same as the admin

    $TeamsLogPath = "C:\users\" + $realprofile + "\AppData\Roaming\Microsoft\Teams\logs.txt"
    if(Test-Path $TeamsLogPath) {
        Copy-Item $TeamsLogPath ($resFile + "LogFiles\Teams\" + $env:computername + "_Teams_logs.txt") -ErrorAction Continue 2>>$errfile
        Write-LogDetails "Copy-Item $TeamsLogPath ($resFile + ""LogFiles\Teams\"" + $env:computername + ""_Teams_logs.txt"") -ErrorAction Continue 2>>$errfile"
    } else {
        Write-LogError "The Teams logs are not present"
    }


    # Collecting dxdiag Log
        
        $dxtarget = $resFile + "LogFiles\Teams\" + $env:computername + "_DxDiag.txt"
        $cmd = "dxdiag /whql:off /t $dxtarget" 
        Write-LogDetails $cmd
        Invoke-Expression $cmd


    # Collecting diagnostics logs

        $TeamsDiagFolder = "C:\Users\" + $realprofile + "\Downloads"
        
        if (Test-path -path $TeamsDiagFolder) {         
            
            Switch(Get-ChildItem -Path $TeamsDiagFolder) {
                {$_.Name -match "MSTeams Diagnostics Log"} {
                    $diagfile = $TeamsDiagFolder + "\" + $_.Name
                    Copy-Item $diagfile ($resFile + "LogFiles\Teams\" + $env:computername + "_" + $_.Name) -ErrorAction Continue 2>>$errfile
                    Write-LogDetails "Copy-Item $diagfile ($resFile + ""LogFiles\Teams\"" + $env:computername + $_.Name) -ErrorAction Continue 2>>$errfile"
                    }
                }            
        } else {
            Write-LogError "The Teams Diagnostics logs are not present"
        }
 
 
    # Collecting HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Teams
            
        if (Test-Path HKLM:\SOFTWARE\Microsoft\Teams) {          
            $cmd = "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Teams """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_SW-MS-Teams.txt"" /y" + $RdrOut + $RdrErr
            Write-LogDetails $cmd
            Invoke-Expression $cmd
        } else {
            Write-LogError "The registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Teams is not present"
        }     


    # Collecting HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RDWebRTCSvc

        if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\RDWebRTCSvc') {          
            $cmd = "reg export 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RDWebRTCSvc' """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_System-CCS-Svc-RDWebRTCSvc.txt"" /y" + $RdrOut + $RdrErr
            Write-LogDetails $cmd
            Invoke-Expression $cmd
        } else {
            Write-LogError "The registry key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RDWebRTCSvc' is not present"
        }

}


} #end of !$DiagOnly





# Running Basic Diagnostics

Write-host
if (!$DiagOnly) { 
    Write-LogTitle "Data collection complete - starting diagnostics (... please wait ...)" "White" "DarkCyan" 
} else {
    Write-LogTitle "Starting diagnostics (... please wait ...)" "White" "DarkCyan"
}

Write-host
Write-Log "Running Basic Diagnostics (see the 'WVD-Diag.txt' file in the output folder for details)"

function Test-RegistryValue {

param (
[parameter(Mandatory=$true)]
[ValidateNotNullOrEmpty()]$Path,

[parameter(Mandatory=$true)]
[ValidateNotNullOrEmpty()]$Value
)

try {
    $trv = Get-ItemProperty -Path $Path | Select-Object -ExpandProperty $Value -ErrorAction SilentlyContinue
    if (($trv) -or ($trv -eq 0)) { 
        return $true 
    } else { 
        return $false
    }
}

catch {
return $false
}
}

$diagfile = $resFile + "WVD-Diag.txt"


"Basic WVD Diagnostics" | Out-File -FilePath $diagfile -Append
"=====================" | Out-File -FilePath $diagfile -Append
" " | Out-File -FilePath $diagfile -Append



# Checking status of key services

write-diag "Checking status of key services"

if (!($ver -like "*Windows 7*")) {
    $servlist = "RdAgent", "RDAgentBootLoader", "TermService", "SessionEnv", "UmRdpService", "WinRM", "AppXSvc"
} else {
    $servlist = "WVDAgent", "WVDAgentManager", "TermService", "SessionEnv", "UmRdpService", "WinRM"
}

$servlist | ForEach-Object -Process {

    $service = Get-Service -Name $_ -ErrorAction SilentlyContinue
    if ($service.Length -gt 0) {

        $servstatus = (Get-Service $_).Status
        $servdispname = (Get-Service $_).DisplayName
        $servstart = (Get-Service $_).StartType
            if ($servstatus -eq "Running") { 
                $msg = "... " + $_ + " (" + $servdispname + ") is Running (StartType: " + $servstart + ")."
                write-diag $msg
            } 
            else { 
                $msg = "... [WARNING] " + $_ + " (" + $servdispname + ") is in '" + $servstatus + "' state (StartType: " + $servstart + ")."
                write-diag $msg
            }
    }
    else {
        $msg = "... [WARNING] " + $_ + " is missing!"
        write-diag $msg
    }
}


if (!($ver -like "*Windows 7*")) {
    "AppReadiness" | ForEach-Object -Process {

        $service = Get-Service -Name $_ -ErrorAction SilentlyContinue
        if ($service.Length -gt 0) {

            $servstatus = (Get-Service $_).Status
            $servdispname = (Get-Service $_).DisplayName
                if ($servstatus -eq "Stopped") { 
                    $msg = "... " + $_ + " (" + $servdispname + ") is Stopped (StartType: " + $servstart + ")."
                    write-diag $msg
                } 
                else { 
                    $msg = "... [WARNING] " + $_ + " (" + $servdispname + ") is in '" + $servstatus + "' state (StartType: " + $servstart + ")."
                    write-diag $msg
                }
        }
        else {
            $msg = "... [WARNING] " + $_ + " is missing!"
            write-diag $msg
        }
    }
}


if ($Profile) {
    "frxsvc", "frxdrv", "frxccds", "OneDrive Updater Service" | ForEach-Object -Process {

        $service = Get-Service -Name $_ -ErrorAction SilentlyContinue
        if ($service.Length -gt 0) {

            $servstatus = (Get-Service $_).Status
            $servdispname = (Get-Service $_).DisplayName
                if ($servstatus -eq "Running") { 
                    $msg = "... " + $_ + " (" + $servdispname + ") is Running (StartType: " + $servstart + ")."
                    write-diag $msg
                } 
                else {
                    $msg = "... " + $_ + " (" + $servdispname + ") is in '" + $servstatus + "' state (StartType: " + $servstart + ")."
                    write-diag $msg
                }
        }
        else {
            $msg = "... [WARNING] " + $_ + " is missing!"
            write-diag $msg
        }
    }
}



" " | Out-File -FilePath $diagfile -Append
"==========================================" | Out-File -FilePath $diagfile -Append
" " | Out-File -FilePath $diagfile -Append




# Checking if the Remote Desktop Session Host role is installed (for server OS hosts that do not show up in the host pool and agent doesn't install properly)

Write-Diag "Checking for Session Host role presence (Scenario: VM running Server OS not showing up in the host pool after agent installation)"

    if ($ver -like "*Windows Server*") {
        
        # Windows Server OS found. Checking for the RDSH role.
        
        if (Get-WindowsFeature -Name RDS-RD-Server) {
            Write-Diag "... Remote Desktop Session Host role is installed on this VM."
        }
        else {
            Write-Diag "... [WARNING] Remote Desktop Session Host role is not installed on this VM. The VM is running server OS and the RDSH role is required for proper host pool registration."
        }
    } 
    else {
        Write-Diag "... Windows Server OS not found. Skipping this check (not applicable)."
    }
    

" " | Out-File -FilePath $diagfile -Append
"==========================================" | Out-File -FilePath $diagfile -Append
" " | Out-File -FilePath $diagfile -Append




# Checking for "fEnableWinStation" (host not available scenario)

write-diag "Checking for 'fEnableWinStation' (Scenario: host not available)"

if (Test-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\' -Value 'fEnableWinStation') {

    $rdpkeyvalue = Get-ItemPropertyValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -name "fEnableWinStation"
    $msg = "... Registry key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\fEnableWinStation' exists and has a value of: " + $rdpkeyvalue 
    Write-Diag $msg
}
else {
    Write-Diag "... [WARNING] Registry key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\fEnableWinStation' is missing!"
}



#checking if multiple WVD listener reg keys are present

if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\rdp-sxs*') {

    (Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\rdp-sxs*').PSChildName | foreach-object -process {  
    
        $wvdlistener = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\" + $_
        
        if (Test-RegistryValue -Path $wvdlistener -Value 'fEnableWinStation') {

            $wvdkeyvalue = Get-ItemPropertyValue -Path $wvdlistener -name "fEnableWinStation"
            $msg = "... Registry key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\" + $_ + "\fEnableWinStation' exists and has a value of: " + $wvdkeyvalue
            Write-Diag $msg            

        }
        else {

            $msg = "... [WARNING] WVD Listener registry keys found, but the registry key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\" + $_ + "\fEnableWinStation' is missing!"
            Write-Diag $msg

        }
    }
}
else {
    $msg = "... [WARNING] No WVD listener (HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\rdp-sxs*) registry keys are present. This machine is either not a WVD VM or the WVD listener is not configured properly."
    Write-Diag $msg
}



#checking for the current WVD listener version

if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\ClusterSettings') {

    if (Test-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\ClusterSettings\' -Value 'SessionDirectoryListener') {

        $listenervalue = Get-ItemPropertyValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\ClusterSettings' -name "SessionDirectoryListener"
        $msg = "... 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\ClusterSettings\SessionDirectoryListener' registry key found. The WVD listener currently in use is: " + $listenervalue
        Write-Diag $msg
    } else {
        Write-Diag "... [WARNING] Registry key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\ClusterSettings\SessionDirectoryListener' is missing! This machine is either not a WVD VM or the WVD listener is not configured properly."
    }
} else {
    Write-Diag "... [WARNING] Registry key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\ClusterSettings' is missing! This machine is either not a WVD VM or the WVD listener is not configured properly."
}


" " | Out-File -FilePath $diagfile -Append
"==========================================" | Out-File -FilePath $diagfile -Append
" " | Out-File -FilePath $diagfile -Append




# Checking for "SSL Cipher Suite Order" configuration (Scenario: cannot connect with message: 'security package error' or 'no available resources')

write-diag "Checking for 'SSL Cipher Suite Order' configuration (Scenario: cannot connect with message: 'security package error' or 'no available resources')"

if (Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002') {

    if (Test-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -Value 'Functions') {

        $rdpkeyvalue = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -name "Functions"
        $msg = "... [WARNING] Registry key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002\Functions' exists and has a value of: " + $rdpkeyvalue 
        Write-Diag $msg
        Write-Diag "... [WARNING] Make sure that the configured SSL cipher suites contain also the ones required by Azure Front Door: https://docs.microsoft.com/en-us/azure/frontdoor/front-door-faq#what-are-the-current-cipher-suites-supported-by-azure-front-door"
    }
    else {
        Write-Diag "... Registry key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002\Functions' is not present. 'SSL Cipher Suite Order' is not configured."
    }
} else {
    Write-Diag "... Registry key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002\Functions' is not present. 'SSL Cipher Suite Order' is not configured."
}


" " | Out-File -FilePath $diagfile -Append
"==========================================" | Out-File -FilePath $diagfile -Append
" " | Out-File -FilePath $diagfile -Append




# Checking for "DeleteUserAppContainersOnLogoff" (FW rules bloating scenario)

write-diag "Checking for 'DeleteUserAppContainersOnLogoff' (Scenario: firewall rules bloating)"

if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy') {
    if (Test-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy' -Value 'DeleteUserAppContainersOnLogoff') {

        $keyvalue = Get-ItemPropertyValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\' -name "DeleteUserAppContainersOnLogoff"
        $msg = "... Registry key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DeleteUserAppContainersOnLogoff' exists and has a value of: " + $keyvalue 
        Write-Diag $msg
    }
    else {
        Write-Diag "... Registry key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DeleteUserAppContainersOnLogoff' is missing or has an empty value."
        Write-Diag "... You could eventually run into host performance/hang issues if this key is not configured. See: https://support.microsoft.com/en-us/help/4490481"
    }
} else {
    Write-Diag "... Registry key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DeleteUserAppContainersOnLogoff' is missing."
    Write-Diag "... You could eventually run into host performance/hang issues if this key is not configured. See: https://support.microsoft.com/en-us/help/4490481"
}


" " | Out-File -FilePath $diagfile -Append
"==========================================" | Out-File -FilePath $diagfile -Append
" " | Out-File -FilePath $diagfile -Append




# Checking WinRM listener

write-diag "Checking WinRM configuration"

    if ((get-service -name WinRM).status -eq "Running") {
        $ipfilter = Get-Item WSMan:\localhost\Service\IPv4Filter
        if ($ipfilter.Value) {
            if ($ipfilter.Value -eq "*") {
            Write-Diag "... IPv4Filter = *"
            } else {
            Write-Diag ("... [WARNING] IPv4Filter = " + $ipfilter.Value)
            }
        } else {
            Write-Diag ("... [WARNING] IPv4Filter is empty, WinRM will not listen on IPv4.")
        }


        $ipfilter = Get-Item WSMan:\localhost\Service\IPv6Filter
        if ($ipfilter.Value) {
            if ($ipfilter.Value -eq "*") {
            Write-Diag "... IPv6Filter = *"
            } else {
            Write-Diag ("... [WARNING] IPv6Filter = " + $ipfilter.Value)
            }
        } else {
            Write-Diag ("... [WARNING] IPv6Filter is empty, WinRM will not listen on IPv6.")
        }
    } else {
        Write-Diag ("... [WARNING] The WinRM service is not running.")
    }

if (!($ver -like "*Windows 7*")) {
    $fwrules = (Get-NetFirewallPortFilter –Protocol TCP | Where { $_.localport –eq ‘5985’ } | Get-NetFirewallRule)
    if ($fwrules.count -eq 0) {
      Write-Diag "... No firewall rule for port 5985."
    } else {
      Write-Diag "... Found firewall rule for port 5985. Check the 'FirewallRules.txt' file for more details."
    }


    $fwrules = (Get-NetFirewallPortFilter –Protocol TCP | Where { $_.localport –eq ‘5986’ } | Get-NetFirewallRule)
    if ($fwrules.count -eq 0) {
      Write-Diag "... No firewall rule for port 5986."
    } else {
      Write-Diag "... Found firewall rule for port 5986. Check the 'FirewallRules.txt' file for more details."
    }
}


# Checking the WinRMRemoteWMIUsers__ group"

    if ((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain) {
  
      Write-Diag "... Checking the WinRMRemoteWMIUsers__ group"
      $search = New-Object DirectoryServices.DirectorySearcher([ADSI]"")  # This is a Domain local group, therefore we need to collect to a non-global catalog
      $search.filter = "(samaccountname=WinRMRemoteWMIUsers__)"
      try 
        { $results = $search.Findall() } 
      catch {
        $_ | Out-File -FilePath $errfile
        } 

      if ($results.count -gt 0) {
        Write-Diag ("... Found " + $results.Properties.distinguishedname)
        if ($results.Properties.grouptype -eq  -2147483644) {
          Write-Diag "... WinRMRemoteWMIUsers__ is a Domain local group."
        } elseif ($results.Properties.grouptype -eq -2147483646) {
          Write-Diag "... [WARNING] WinRMRemoteWMIUsers__ is a Global group."
        } elseif ($results.Properties.grouptype -eq -2147483640) {
          Write-Diag "... [WARNING] WinRMRemoteWMIUsers__ is a Universal group."
        }
        if (Get-WmiObject -query "select * from Win32_Group where Name = 'WinRMRemoteWMIUsers__' and Domain = '$env:computername'") {
          Write-Diag "... The group WinRMRemoteWMIUsers__ is also present as machine local group."
        }
      } else {
        Write-Diag "... [WARNING] The WinRMRemoteWMIUsers__ was not found in the domain." 
        if (Get-WmiObject -query "select * from Win32_Group where Name = 'WinRMRemoteWMIUsers__' and Domain = '$env:computername'") {
          Write-Diag "... The group WinRMRemoteWMIUsers__ is present as machine local group."
        } else {
          Write-Diag "... [WARNING] The group WinRMRemoteWMIUsers__ is not present as machine local group!"
        }
      }
    } else {
      Write-Diag "... [WARNING] The machine is not joined to a domain."
      if (Get-WmiObject -query "select * from Win32_Group where Name = 'WinRMRemoteWMIUsers__' and Domain = '$env:computername'") {
        Write-Diag "... The group WinRMRemoteWMIUsers__ is present as machine local group."
      } else {
        Write-Diag "... [WARNING] The group WinRMRemoteWMIUsers__ is not present as machine local group!"
      }
    }



##### Archive results

        $StopWatchDC.Stop()
        $tsDC =  [timespan]::fromseconds(($StopWatchDC.Elapsed).TotalSeconds)
        $elapsedDC = ("{0:hh\:mm\:ss\.fff}" -f $tsDC)

        Write-Host
        Write-LogTitle "Diagnostics complete - archiving files!"
        Write-Host

        Write-LogError "Data collection/diagnostics took (hh:mm:ss.fff): $elapsedDC"
                
        $destination = $Root + "\" + $resName + ".zip"
        $cmd = "Compress-Archive -Path $resDir -DestinationPath $destination -CompressionLevel Optimal -Force"
        Write-LogDetails $cmd     
        Invoke-Expression $cmd

        if (Test-path -path $destination) {  
              Write-Log "Zip file ready. Location of the collected data and zip file: $Root\" "Green"
            } else {
              Write-Log "Zip file could not be created. Please manually archive the subfolder containing the collected data. Location of the collected data: $Root\" "Yellow"
            }

        explorer $root
# SIG # Begin signature block
# MIIjwAYJKoZIhvcNAQcCoIIjsTCCI60CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD2k51r1oOQ9eMB
# x63F5arjFfGTi7VQHM/fFXFJkkyxEKCCDYEwggX/MIID56ADAgECAhMzAAABh3IX
# chVZQMcJAAAAAAGHMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjAwMzA0MTgzOTQ3WhcNMjEwMzAzMTgzOTQ3WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDOt8kLc7P3T7MKIhouYHewMFmnq8Ayu7FOhZCQabVwBp2VS4WyB2Qe4TQBT8aB
# znANDEPjHKNdPT8Xz5cNali6XHefS8i/WXtF0vSsP8NEv6mBHuA2p1fw2wB/F0dH
# sJ3GfZ5c0sPJjklsiYqPw59xJ54kM91IOgiO2OUzjNAljPibjCWfH7UzQ1TPHc4d
# weils8GEIrbBRb7IWwiObL12jWT4Yh71NQgvJ9Fn6+UhD9x2uk3dLj84vwt1NuFQ
# itKJxIV0fVsRNR3abQVOLqpDugbr0SzNL6o8xzOHL5OXiGGwg6ekiXA1/2XXY7yV
# Fc39tledDtZjSjNbex1zzwSXAgMBAAGjggF+MIIBejAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUhov4ZyO96axkJdMjpzu2zVXOJcsw
# UAYDVR0RBEkwR6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMRYwFAYDVQQFEw0yMzAwMTIrNDU4Mzg1MB8GA1UdIwQYMBaAFEhu
# ZOVQBdOCqhc3NyK1bajKdQKVMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0w
# Ny0wOC5jcmwwYQYIKwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY0NvZFNpZ1BDQTIwMTFfMjAx
# MS0wNy0wOC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAixmy
# S6E6vprWD9KFNIB9G5zyMuIjZAOuUJ1EK/Vlg6Fb3ZHXjjUwATKIcXbFuFC6Wr4K
# NrU4DY/sBVqmab5AC/je3bpUpjtxpEyqUqtPc30wEg/rO9vmKmqKoLPT37svc2NV
# BmGNl+85qO4fV/w7Cx7J0Bbqk19KcRNdjt6eKoTnTPHBHlVHQIHZpMxacbFOAkJr
# qAVkYZdz7ikNXTxV+GRb36tC4ByMNxE2DF7vFdvaiZP0CVZ5ByJ2gAhXMdK9+usx
# zVk913qKde1OAuWdv+rndqkAIm8fUlRnr4saSCg7cIbUwCCf116wUJ7EuJDg0vHe
# yhnCeHnBbyH3RZkHEi2ofmfgnFISJZDdMAeVZGVOh20Jp50XBzqokpPzeZ6zc1/g
# yILNyiVgE+RPkjnUQshd1f1PMgn3tns2Cz7bJiVUaqEO3n9qRFgy5JuLae6UweGf
# AeOo3dgLZxikKzYs3hDMaEtJq8IP71cX7QXe6lnMmXU/Hdfz2p897Zd+kU+vZvKI
# 3cwLfuVQgK2RZ2z+Kc3K3dRPz2rXycK5XCuRZmvGab/WbrZiC7wJQapgBodltMI5
# GMdFrBg9IeF7/rP4EqVQXeKtevTlZXjpuNhhjuR+2DMt/dWufjXpiW91bo3aH6Ea
# jOALXmoxgltCp1K7hrS6gmsvj94cLRf50QQ4U8Qwggd6MIIFYqADAgECAgphDpDS
# AAAAAAADMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0
# ZSBBdXRob3JpdHkgMjAxMTAeFw0xMTA3MDgyMDU5MDlaFw0yNjA3MDgyMTA5MDla
# MH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMT
# H01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTEwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCr8PpyEBwurdhuqoIQTTS68rZYIZ9CGypr6VpQqrgG
# OBoESbp/wwwe3TdrxhLYC/A4wpkGsMg51QEUMULTiQ15ZId+lGAkbK+eSZzpaF7S
# 35tTsgosw6/ZqSuuegmv15ZZymAaBelmdugyUiYSL+erCFDPs0S3XdjELgN1q2jz
# y23zOlyhFvRGuuA4ZKxuZDV4pqBjDy3TQJP4494HDdVceaVJKecNvqATd76UPe/7
# 4ytaEB9NViiienLgEjq3SV7Y7e1DkYPZe7J7hhvZPrGMXeiJT4Qa8qEvWeSQOy2u
# M1jFtz7+MtOzAz2xsq+SOH7SnYAs9U5WkSE1JcM5bmR/U7qcD60ZI4TL9LoDho33
# X/DQUr+MlIe8wCF0JV8YKLbMJyg4JZg5SjbPfLGSrhwjp6lm7GEfauEoSZ1fiOIl
# XdMhSz5SxLVXPyQD8NF6Wy/VI+NwXQ9RRnez+ADhvKwCgl/bwBWzvRvUVUvnOaEP
# 6SNJvBi4RHxF5MHDcnrgcuck379GmcXvwhxX24ON7E1JMKerjt/sW5+v/N2wZuLB
# l4F77dbtS+dJKacTKKanfWeA5opieF+yL4TXV5xcv3coKPHtbcMojyyPQDdPweGF
# RInECUzF1KVDL3SV9274eCBYLBNdYJWaPk8zhNqwiBfenk70lrC8RqBsmNLg1oiM
# CwIDAQABo4IB7TCCAekwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFEhuZOVQ
# BdOCqhc3NyK1bajKdQKVMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1Ud
# DwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFHItOgIxkEO5FAVO
# 4eqnxzHRI4k0MFoGA1UdHwRTMFEwT6BNoEuGSWh0dHA6Ly9jcmwubWljcm9zb2Z0
# LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcmwwXgYIKwYBBQUHAQEEUjBQME4GCCsGAQUFBzAChkJodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcnQwgZ8GA1UdIASBlzCBlDCBkQYJKwYBBAGCNy4DMIGDMD8GCCsGAQUFBwIB
# FjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2RvY3MvcHJpbWFyeWNw
# cy5odG0wQAYIKwYBBQUHAgIwNB4yIB0ATABlAGcAYQBsAF8AcABvAGwAaQBjAHkA
# XwBzAHQAYQB0AGUAbQBlAG4AdAAuIB0wDQYJKoZIhvcNAQELBQADggIBAGfyhqWY
# 4FR5Gi7T2HRnIpsLlhHhY5KZQpZ90nkMkMFlXy4sPvjDctFtg/6+P+gKyju/R6mj
# 82nbY78iNaWXXWWEkH2LRlBV2AySfNIaSxzzPEKLUtCw/WvjPgcuKZvmPRul1LUd
# d5Q54ulkyUQ9eHoj8xN9ppB0g430yyYCRirCihC7pKkFDJvtaPpoLpWgKj8qa1hJ
# Yx8JaW5amJbkg/TAj/NGK978O9C9Ne9uJa7lryft0N3zDq+ZKJeYTQ49C/IIidYf
# wzIY4vDFLc5bnrRJOQrGCsLGra7lstnbFYhRRVg4MnEnGn+x9Cf43iw6IGmYslmJ
# aG5vp7d0w0AFBqYBKig+gj8TTWYLwLNN9eGPfxxvFX1Fp3blQCplo8NdUmKGwx1j
# NpeG39rz+PIWoZon4c2ll9DuXWNB41sHnIc+BncG0QaxdR8UvmFhtfDcxhsEvt9B
# xw4o7t5lL+yX9qFcltgA1qFGvVnzl6UJS0gQmYAf0AApxbGbpT9Fdx41xtKiop96
# eiL6SJUfq/tHI4D1nvi/a7dLl+LrdXga7Oo3mXkYS//WsyNodeav+vyL6wuA6mk7
# r/ww7QRMjt/fdW1jkT3RnVZOT7+AVyKheBEyIXrvQQqxP/uozKRdwaGIm1dxVk5I
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIVlTCCFZECAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAYdyF3IVWUDHCQAAAAABhzAN
# BglghkgBZQMEAgEFAKCB3DAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQg+yPfRLEa
# wF9jiVMhrqfOULhAsmDejdyak1455Q/d+8wwcAYKKwYBBAGCNwIBDDFiMGCgQIA+
# AFcAVgBEACAAQwBvAGwAbABlAGMAdAAgAGYAbwByACAAVAByAG8AdQBiAGwAZQBz
# AGgAbwBvAHQAaQBuAGehHIAaaHR0cHM6Ly9ha2EubXMvd3ZkLWNvbGxlY3QwDQYJ
# KoZIhvcNAQEBBQAEggEArDH09qkVOpWalZdFfD9w2pplJx+/tRgZcMHvexFPGnyQ
# hjH9dYHmbBaUW1IgTxK+pxN6PpHY002wMNhANKxEhVIRWZoMsZwF9OmIhhh7n7yj
# 8RVjHMbqEw4sqPNv5vCea6YVnTO3ktXqKhnBo9s/0JTSC8sPw9oUSsPIr3Wp5/lu
# Sc+xPhc/4ce+/4BltWjfKhVpyEb5w5LeCmTV7YJEVLBgrlcCMmyX/FsDs9w2TSCf
# 6B2r7U4qUu5X+8ImdN+s1EFKwDeDMdxjMMxbopQ0byMkkhlTG09PDhDL/yLQ7wCG
# wdTHdPl8CEL74XBt5dYsyRxlBDeKgIwW/6dyuV7muaGCEvEwghLtBgorBgEEAYI3
# AwMBMYIS3TCCEtkGCSqGSIb3DQEHAqCCEsowghLGAgEDMQ8wDQYJYIZIAWUDBAIB
# BQAwggFVBgsqhkiG9w0BCRABBKCCAUQEggFAMIIBPAIBAQYKKwYBBAGEWQoDATAx
# MA0GCWCGSAFlAwQCAQUABCAIRSYxUgqM17+T3jNbDJksMJoBKyw8TV/ASTr97nEw
# 4QIGX4h2TTsiGBMyMDIwMTExMjEzNDcxMi4wNzdaMASAAgH0oIHUpIHRMIHOMQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSkwJwYDVQQLEyBNaWNy
# b3NvZnQgT3BlcmF0aW9ucyBQdWVydG8gUmljbzEmMCQGA1UECxMdVGhhbGVzIFRT
# UyBFU046RDlERS1FMzlBLTQzRkUxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0
# YW1wIFNlcnZpY2Wggg5EMIIE9TCCA92gAwIBAgITMwAAAS0uTUHKY2UzoAAAAAAB
# LTANBgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAe
# Fw0xOTEyMTkwMTE1MDRaFw0yMTAzMTcwMTE1MDRaMIHOMQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMSkwJwYDVQQLEyBNaWNyb3NvZnQgT3BlcmF0
# aW9ucyBQdWVydG8gUmljbzEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046RDlERS1F
# MzlBLTQzRkUxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2Uw
# ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCpYY30dUk6mEU0t7NIuIyH
# EjFfhuDdKGIMJUCvqZeA1TBZq9Yk2RxS4907e1ehfjPwV8dIfYtLrtcgZ6gqjTpL
# iREU21ZzOLtyb0cc7EHwowX6g/wjcKDDXpKMpSAc8T+dEpI6daT7J0ASh2gj/LYL
# r2Fc6E0OeKtlaWBD//jmE0HhD6lhYvFoIL7HJLnq3FBpIWFjPA1f+CVOzf62w67W
# pmG3vC7ZFYk0GG4oFEggKK/Q4bQGb6vANAO91xR9nX9sA5S7QJygnLFb10pmd+Ww
# Kp3jeLhEFcvDUHUXhiNbSOlMaAu154xryuDHA3SoWrzSewwJ0j+fhvw05HVg/pTf
# AgMBAAGjggEbMIIBFzAdBgNVHQ4EFgQU2WxkfEIBIfhODor/L0O+NPKdhs0wHwYD
# VR0jBBgwFoAU1WM6XIoxkPNDe3xGG8UzaFqFbVUwVgYDVR0fBE8wTTBLoEmgR4ZF
# aHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljVGlt
# U3RhUENBXzIwMTAtMDctMDEuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcw
# AoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNUaW1TdGFQ
# Q0FfMjAxMC0wNy0wMS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEF
# BQcDCDANBgkqhkiG9w0BAQsFAAOCAQEAfWsDZPdOq3nAbqDuxM6uwfFBrvRKBV4i
# /GnNG27GQwWPc/96fGrVWUQsRzeN2t1hmwjGaCmMUgR+lApHA3MFyHzShG1TM5xd
# Zo6UBBm6oUfqzzah12aLUlfr5/OQMZnnwDN23C7fljQaRLjmWeJD2VXBbTKOGMkI
# 8aDUT4sJqfgdB5IULP5f1SINFyWOpORUShPyRRHFWONuejXalGft46Lt2+DgJLRN
# rq6+FelUcNX33zpcWW/DMrxOZqr01STkrVcQrobqoNayHvJWtYGeYoriMlnn7TjX
# zMNJ0mXIRi4oA3iJ8Ol38MIBZwuUJfD239ozsQlJbgGG88pCPjJwYjCCBnEwggRZ
# oAMCAQICCmEJgSoAAAAAAAIwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBSb290
# IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTEwMDcwMTIxMzY1NVoXDTI1
# MDcwMTIxNDY1NVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwggEiMA0G
# CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCpHQ28dxGKOiDs/BOX9fp/aZRrdFQQ
# 1aUKAIKF++18aEssX8XD5WHCdrc+Zitb8BVTJwQxH0EbGpUdzgkTjnxhMFmxMEQP
# 8WCIhFRDDNdNuDgIs0Ldk6zWczBXJoKjRQ3Q6vVHgc2/JGAyWGBG8lhHhjKEHnRh
# Z5FfgVSxz5NMksHEpl3RYRNuKMYa+YaAu99h/EbBJx0kZxJyGiGKr0tkiVBisV39
# dx898Fd1rL2KQk1AUdEPnAY+Z3/1ZsADlkR+79BL/W7lmsqxqPJ6Kgox8NpOBpG2
# iAg16HgcsOmZzTznL0S6p/TcZL2kAcEgCZN4zfy8wMlEXV4WnAEFTyJNAgMBAAGj
# ggHmMIIB4jAQBgkrBgEEAYI3FQEEAwIBADAdBgNVHQ4EFgQU1WM6XIoxkPNDe3xG
# G8UzaFqFbVUwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGG
# MA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb186a
# GMQwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3Br
# aS9jcmwvcHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoGCCsG
# AQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraS9jZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcnQwgaAGA1UdIAEB
# /wSBlTCBkjCBjwYJKwYBBAGCNy4DMIGBMD0GCCsGAQUFBwIBFjFodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vUEtJL2RvY3MvQ1BTL2RlZmF1bHQuaHRtMEAGCCsGAQUF
# BwICMDQeMiAdAEwAZQBnAGEAbABfAFAAbwBsAGkAYwB5AF8AUwB0AGEAdABlAG0A
# ZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQAH5ohRDeLG4Jg/gXEDPZ2joSFv
# s+umzPUxvs8F4qn++ldtGTCzwsVmyWrf9efweL3HqJ4l4/m87WtUVwgrUYJEEvu5
# U4zM9GASinbMQEBBm9xcF/9c+V4XNZgkVkt070IQyK+/f8Z/8jd9Wj8c8pl5SpFS
# AK84Dxf1L3mBZdmptWvkx872ynoAb0swRCQiPM/tA6WWj1kpvLb9BOFwnzJKJ/1V
# ry/+tuWOM7tiX5rbV0Dp8c6ZZpCM/2pif93FSguRJuI57BlKcWOdeyFtw5yjojz6
# f32WapB4pm3S4Zz5Hfw42JT0xqUKloakvZ4argRCg7i1gJsiOCC1JeVk7Pf0v35j
# WSUPei45V3aicaoGig+JFrphpxHLmtgOR5qAxdDNp9DvfYPw4TtxCd9ddJgiCGHa
# sFAeb73x4QDf5zEHpJM692VHeOj4qEir995yfmFrb3epgcunCaw5u+zGy9iCtHLN
# HfS4hQEegPsbiSpUObJb2sgNVZl6h3M7COaYLeqN4DMuEin1wC9UJyH3yKxO2ii4
# sanblrKnQqLJzxlBTeCG+SqaoxFmMNO7dDJL32N79ZmKLxvHIa9Zta7cRDyXUHHX
# odLFVeNp3lfB0d4wwP3M5k37Db9dT+mdHhk4L7zPWAUu7w2gUDXa7wknHNWzfjUe
# CLraNtvTX4/edIhJEqGCAtIwggI7AgEBMIH8oYHUpIHRMIHOMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSkwJwYDVQQLEyBNaWNyb3NvZnQgT3Bl
# cmF0aW9ucyBQdWVydG8gUmljbzEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046RDlE
# RS1FMzlBLTQzRkUxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZp
# Y2WiIwoBATAHBgUrDgMCGgMVAJ/OX8d+h3uxdL4JslJc9sPNpdCxoIGDMIGApH4w
# fDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMd
# TWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEFBQACBQDj
# VzQ4MCIYDzIwMjAxMTEyMDgxMDMyWhgPMjAyMDExMTMwODEwMzJaMHcwPQYKKwYB
# BAGEWQoEATEvMC0wCgIFAONXNDgCAQAwCgIBAAICDS0CAf8wBwIBAAICESowCgIF
# AONYhbgCAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQAC
# AwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUFAAOBgQA+XS2OQcA2Ovbh4etm
# UiI5xfZRn3rH5lxKc1voihDuO7VCLIbWkWIIimdNVlK6RNEuuXjZ5pHhchSeX93v
# 0v/v+3/P81tvGakTGDGdlRo49YoVJq7Cly3XR/4DxqotAZAqXgueq7GsbOC8OqS7
# Frqderlg4FQmYM9DF2hRkqOrAjGCAw0wggMJAgEBMIGTMHwxCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1l
# LVN0YW1wIFBDQSAyMDEwAhMzAAABLS5NQcpjZTOgAAAAAAEtMA0GCWCGSAFlAwQC
# AQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkE
# MSIEIF/Z3FnDx9JbQ7jk43og4U9Bc+i+nNCIk3LviBuExSnAMIH6BgsqhkiG9w0B
# CRACLzGB6jCB5zCB5DCBvQQgjvFacnJ9IAeP4pUQDzw20vgpm6o/7gtNdZqHOaHh
# g8EwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQ
# MA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
# MSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAS0u
# TUHKY2UzoAAAAAABLTAiBCClJsmrLDeE9jNTiZK7xVBKudhxeAEU8DsUpOZe/6U2
# 5DANBgkqhkiG9w0BAQsFAASCAQBustynzXL2232bDXsnQ/t7SwPEFm8feCkPX/U4
# e2rVpJEw6B9Ews1MUWD4op/p+T1QIc7Gpn8BiuMYqxotqfqydgZLwfD6E9CxPpyN
# Z7unBervlciJnRtG+bsFW4HVNE/2mCNBUf8VqBYHYBytQAQRsq+SpRpTFN6AjM9i
# 9RGDLnyHjb1DYdKZgVIky8M7yKDPsr0AbiIzK0SWCBYYqbfVqLmGt/oSQuCRfbKB
# FaEhe65p3mJCey2BMrBLmFww7UrahXVCB1oSh0ruHMa5mDLx55M5MkUKh6Jqg7NA
# AIYA0afzHktVSuRL9dc1gVQY4vw0++OdJmOWUhoSoYgwmvKB
# SIG # End signature block
