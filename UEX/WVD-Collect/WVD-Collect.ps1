# =====================================================
#
# DISCLAIMER:
#
# THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
# =====================================================


<#
        .SYNOPSIS
        Simplify data collection for troubleshooting Windows Virtual Desktop issues and a convenient method for submitting and following quick & easy action plans.
        
        .DESCRIPTION
        This script is designed to collect information that will help Microsoft Customer Support Services (CSS) troubleshoot an issue you may be experiencing with Windows Virtual Desktop.
        The collected data may contain Personally Identifiable Information (PII) and/or sensitive data, such as (but not limited to) IP addresses; PC names; and user names.
        The script will save the collected data in a folder and also compress the results into a ZIP file, both in the same location from where the script has been launched.
        This folder and its contents or the ZIP file are not automatically sent to Microsoft.
        You can send the ZIP file to Microsoft CSS using a secure file transfer tool - Please discuss this with your support professional and also any concerns you may have.
        Find our privacy statement here: https://privacy.microsoft.com/en-us/privacy
        
        Run 'Get-Help WVD-Collect.ps1 -Full' for more details.

        USAGE SUMMARY:

        The script must be run with elevated permissions in order to collect all required data. It works on any Windows client and Windows server OS supporting at least PowerShell 5.1.

        Run the script on WVD host VMs and/or on Windows based devices from where you connect to the WVD hosts, as needed.

        The script will collect a set of "default data" regardless of parameters. 
        By adding one or more parameters, you can collect additional data, useful for specific troubleshooting scenarios.

        The script will archive the collected data into a .zip file located in the same folder as the script itself.

        .PARAMETER Certificate
        Collects Certificates related data.

        .PARAMETER Client
        Collects existing RD client ETL traces and RD client upgrade log from devices running the WVD Desktop Client (the content of the "C:\Users\%username%\AppData\Local\Temp\DiagOutputDir\RdClientAutoTrace" folder).

    	Important note: This "-Client" parameter is useful for collecting the automatic client ETL traces, when troubleshooting WVD client connectivity or WVD client issues. 
	    Please note that the RdClientAutoTrace folder might get quite large over time. 
	    When such data is needed for troubleshooting, recommended is to first clear the content of the folder (eventually create a backup of the old content if you want), then reproduce the issue and close the client afterwards so that new traces are generated and after that run the WVD-Collect script so that only the latest, relevant traces are collected.

        .PARAMETER MonTables
        Collects existing converted monitoring traces from WVD hosts (.csv files converted from existing .tsf files from under "C:\Windows\System32\config\systemprofile\AppData\Roaming\Microsoft\Monitoring\Tables").

	    Important note: This "-MonTables" parameter is useful for investigating issues with WVD hosts not communicating with the WVD services (Broker or Diagnostics).
	    In these scenarios Kusto/Log Analytics may not receive any data, but some traces are still available on the hosts themselves and may help identify the underlying cause.

        .PARAMETER MSRA
        Collects Remote Assistance related data.

        .PARAMETER Profiles
        Collects User Profile related data (incl. FSLogix).

        .PARAMETER Teams
        Collects Teams WVD optimization related data.

	    Important note: To collect the proper data when having issues with Teams optimized for WVD, reproduce the issue with an affected user, press Ctrl+Alt+Shift+1 within the affected user's session while Teams is open to generate additional Teams diagnostics data and after that run the script with the "-Teams" parameter (WVD-Collect.ps1 -Teams) within this affected user's WVD session.
	    The script itself will not force generating these diagnostics files, it will only collect them if they are already available.
	    There is also an additional confirmation prompt when launching the script with the "-Teams" parameter to get the user's confirmation that these prerequisites have been met before continuing.

        .PARAMETER DiagOnly
        When executed with this parameter (even if other parameters are also included) the script will skip ALL data collection and will ONLY run the diagnostics part. 
	
	    This is useful when you want to run only a quick Diag without collecting additional data.
	    Important note: To run diagnostics also for a specific scenario (like Profile troubleshooting), the corresponding command line parameter needs to be present too.
	    E.g.: 
		    ".\WVD-Collect.ps1 -DiagOnly" will run only the default diagnostics
		    ".\WVD-Collect.ps1 -Profiles -DiagOnly" will run the default diagnostics + "Profiles"-specific diagnostics

        .PARAMETER Verbose
        Displays more verbose information about the steps performed during data collection
        
        .OUTPUTS
        By default, all collected data are stored in a subfolder in the same location from where the tool was launched.

        .EXAMPLE
        .\WVD-Collect.ps1 
        Example without parameters (collects only default data).
                   
        .EXAMPLE
        .\WVD-Collect.ps1 -Profiles -Teams -Verbose
        Usage example with parameters (collects default data + profile related information + Teams WVD optimization related data + displays more information on the performed steps).

        .EXAMPLE
        .\WVD-Collect.ps1 -Profiles -DiagOnly
        Runs only the WVD diagnostics + profile related diagnostics, without collecting any of the additional data.
    
        .LINK
        Online version: http://aka.ms/WVD-Collect
    #>



param (
    [switch]$Profiles = $false,
    [switch]$Client = $false,
    [switch]$MonTables = $false,
    [switch]$Certificate = $false,
    [switch]$MSRA = $false,    
    [switch]$Teams = $false,    
    [switch]$DiagOnly = $false,
    [switch]$Verbose = $false
    
)

$version = "201219.7"
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

$ver = (Get-CimInstance Win32_OperatingSystem).Caption

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
    $ret = get-ciminstance -Namespace $NameSpace -Query $Query -ErrorAction Continue 2>>$errfile
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
      ($FilePath + "," + $filever + "," + $fileobj.CreationTime.ToString("yyyyMMdd HH:mm:ss")) | Out-File -FilePath ($resFile + "SystemInfo\" + $env:computername + "_ver_KeyFileVersions.csv") -Append
    }
    return $filever | Out-Null
  } else {
    return ""
  }
}


# This function disable quick edit mode. If the mode is enabled, console output will hang when key input or strings are selected. 
# So disable the quick edit mode druing running script and re-enable it after script is finished.
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


Function CleanUpandExit{
    If($fQuickEditCodeExist){
        [DisableConsoleQuickEdit]::SetQuickEdit($False) | Out-Null
    }
    Exit
}


# Disabling quick edit mode as somethimes this causes the script stop working until enter key is pressed.
If($fQuickEditCodeExist){
    [DisableConsoleQuickEdit]::SetQuickEdit($True) | Out-Null
}

"WVD-Collect error file. This file contains potential error messages returned by the script during execution." | Out-File -FilePath $errfile -Append
"====================================================================================" | Out-File -FilePath $errfile -Append
" " | Out-File -FilePath $errfile -Append

"WVD-Collect output file. This file logs the tool's output shown on the screen during execution of the tool and some additional information from the data collection process." | Out-File -FilePath $outfile -Append
"====================================================================================" | Out-File -FilePath $outfile -Append
" " | Out-File -FilePath $outfile -Append


# =============================================================================

Write-Host
Write-LogTitle "Starting WVD-Collect (v$version)" "White" "DarkCyan"

##### Disclaimer

Write-Host "`n=============== Microsoft CSS Diagnostics Script ===============`n"
Write-Host "This Data Collection is for troubleshooting reported issues for the given scenarios."
Write-Host "Once you have started this script please wait until all data has been collected.`n`n"
Write-Host "======================= IMPORTANT NOTICE =======================`n"
Write-Host "This script is designed to collect information that will help Microsoft Customer Support Services (CSS) troubleshoot an issue you may be experiencing with Windows Virtual Desktop."
Write-Host "The collected data may contain Personally Identifiable Information (PII) and/or sensitive data, such as (but not limited to) IP addresses; PC names; and user names."
Write-Host "The script will save the collected data in a folder and also compress the results into a ZIP file, both in the same location from where the script has been launched."
Write-Host "This folder and its contents or the ZIP file are not automatically sent to Microsoft."
Write-Host "You can send the ZIP file to Microsoft CSS using a secure file transfer tool - Please discuss this with your support professional and also any concerns you may have."
Write-Host "Find our privacy statement here: https://privacy.microsoft.com/en-us/privacy`n`n"

$confirm = Read-Host ("Do you agree to continue? [Y/N]")

if ($confirm.ToLower() -ne "y") {
    Write-Host("Script execution not approved by the admin user, exiting.")
    Remove-Item -path $resDir -Recurse | Out-Null
    CleanUpandExit
}


$StopWatchDC = [system.diagnostics.stopwatch]::startNew()


if (!$DiagOnly) {


if($Teams) {

# checking if diagnostic logs are present (user has pressed Ctrl+Alt+Shift+1 in Teams prior to running the script)

        $TeamsDiagFolder = "C:\Users\" + $realprofile + "\Downloads"
        
        if (Test-path -path $TeamsDiagFolder) {         
            
            Switch(Get-ChildItem -Path $TeamsDiagFolder) {
                {$_.Name -match "MSTeams Diagnostics Log"} {
                    Write-LogDetails "Teams diag log files are present"
                    }
                }            
        } else {
            Write-LogError "Teams Diagnostics logs are not present"
        }


    Write-host
    Write-host
    Write-Host "You are running the script with the '-Teams' command line parameter. This will collect Teams specific logs for troubleshooting Teams WVD optimization issues with the Teams desktop app or calls/meetings.
    "
    Write-host "Please make sure that the script is running under the affected user's WVD session and that the affected user has pressed Ctrl+Alt+Shift+1 within the open Teams application before starting this script, so that additional Teams diagnostics logs have been generated.
    "
    $confirm = Read-Host ("Do you confirm that these requirements are met? [Y/N]")
    if ($confirm.ToLower() -ne "y") {exit}

}

if($Client) {

  $msrdc = Get-Process msrdc -ErrorAction SilentlyContinue

  If ($msrdc) {
    Write-host
    Write-host
    Write-host "You are running the script with the '-Client' command line parameter and MSRDC.exe is still running."
    Write-host "To collect the most recent WVD Desktop Client specific ETL traces, MSRDC.exe must not be running.
    "
    $confirm = Read-Host ("Do you want to close the MSRDC.exe now? This will disconnect all active WVD connections on this client! [Y/N]")
    
    if ($confirm.ToLower() -ne "y") {
        Write-host
        Write-Log "[NOTE] MSRDC.exe has not been closed. The most recent ETL traces will NOT be available for troubleshooting! Continuing data collection."
    } else {
      Write-Host
      Write-Log "Closing MSRDC.exe ..."
      $msrdc.CloseMainWindow() | Out-Null
      Start-Sleep 5
      if (!$msrdc.HasExited) {
        $msrdc | Stop-Process -Force
      }
      Write-Log "MSRDC.exe has been closed. Waiting 10 seconds for the latest trace file(s) to get saved before continuing with the data collection."
      Start-Sleep 10
    }

  }
}

Write-host
Write-LogTitle "Starting data collection (... please wait ...)" "White" "DarkCyan"
Write-host


New-Item -Path ($resFile + 'SystemInfo\') -ItemType Directory | Out-Null

##### Collecting files

        Write-Log "Collecting log files"
        New-Item -Path ($resFile + 'LogFiles\') -ItemType Directory | Out-Null
                     
        # Collecting DSC Logs

            if (Test-path -path 'c:\packages\plugins\microsoft.powershell.dsc') {

                $verfolder = get-ChildItem c:\packages\plugins\microsoft.powershell.dsc -recurse | Foreach-Object {If ($_.psiscontainer) {$_.fullname}} | Select-Object -first 1  
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

                $verfolder = get-ChildItem C:\Packages\Plugins\Microsoft.EnterpriseCloud.Monitoring.MicrosoftMonitoringAgent -recurse | Foreach-Object {If ($_.psiscontainer) {$_.fullname}} | Select-Object -first 1  
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

                $verfolder = get-ChildItem c:\packages\plugins\Microsoft.Compute.JsonADDomainExtension -recurse | Foreach-Object {If ($_.psiscontainer) {$_.fullname}} | Select-Object -first 1  
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

            if ($Profiles) {
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
    Get-DscConfiguration 2>>$errfile | Out-File -FilePath ($resFile + "SystemInfo\" + $env:computername + "_Get-DscConfiguration.txt") -Append

    " " | Out-File -FilePath ($resFile + "SystemInfo\" + $env:computername + "_Get-DscConfiguration.txt") -Append
    "==========================================" | Out-File -FilePath ($resFile + "SystemInfo\" + $env:computername + "_Get-DscConfiguration.txt") -Append
    " " | Out-File -FilePath ($resFile + "SystemInfo\" + $env:computername + "_Get-DscConfiguration.txt") -Append

    Write-LogDetails "Get-DscConfigurationStatus output"
    Get-DscConfigurationStatus -all 2>>$errfile | Out-File -FilePath ($resFile + "SystemInfo\" + $env:computername + "_Get-DscConfiguration.txt") -Append



##### Collecting Geneva scheduled task information from non-Win7 machines

if (!($ver -like "*Windows 7*")) {
            Write-Log "Collecting Geneva scheduled task information"        
            New-Item -Path ($resFile + 'ScheduledTasks\') -ItemType Directory | Out-Null

            if (Get-ScheduledTask GenevaTask* -ErrorAction Ignore) { 
                (Get-ScheduledTask GenevaTask*).TaskName | ForEach-Object -Process {
                    $cmd = "Export-ScheduledTask -TaskName $_ >>""" + $resFile + "ScheduledTasks\" + $env:computername + "_schtasks_" + $_ + ".xml""" + $RdrErr
                    Write-LogDetails $cmd
                    Invoke-Expression $cmd

                    $cmd = "Get-ScheduledTaskInfo -TaskName $_ >>""" + $resFile + "ScheduledTasks\" + $env:computername + "_schtasks_" + $_ + "_Info.txt""" + $RdrErr
                    Write-LogDetails $cmd
                    Invoke-Expression $cmd
                }
            } else { 
                Write-LogError "The Geneva Scheduled Task is not present"
            }
}


##### Collecting RDP and networking information

        Write-Log "Collecting RDP and networking information"

        New-Item -Path ($resFile + 'Networking\') -ItemType Directory | Out-Null

        # Get-NetConnectionProfile output
        if (!($ver -like "*Windows 7*")) {
            Get-NetConnectionProfile | Out-File -FilePath ($resFile + "Networking\" + $env:computername + "_NetConnectionProfile.txt") -Append
            Write-LogDetails "Get-NetConnectionProfile | Out-File -FilePath ($resFile + ""Networking\"" + $env:computername + ""_NetConnectionProfile.txt"") -Append"
        }

        # Collecting firewall rules

            $cmd = "netsh advfirewall firewall show rule name=all >""" + $resFile + "Networking\" + $env:computername + "_FirewallRules.txt""" + $RdrErr
            Write-LogDetails $cmd
            Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append


        # Collecting netstat output

            $cmd = "netstat -anob >""" + $resFile + "Networking\" + $env:computername + "_Netstat.txt""" + $RdrErr
            Write-LogDetails $cmd
            Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append


        # Collecting ipconfig /all output

            $cmd = "ipconfig /all >""" + $resFile + "Networking\" + $env:computername + "_Ipconfig.txt""" + $RdrErr
            Write-LogDetails $cmd
            Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append


        # Collecting proxy settings

            $cmd = "netsh winhttp show proxy >""" + $resFile + "Networking\" + $env:computername + "_WinHTTP-Proxy.txt""" + $RdrErr
            Write-LogDetails $cmd
            Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append


            "------------------" | Out-File -FilePath ($resFile + "Networking\" + $env:computername + "_WinHTTP-Proxy.txt") -Append
            "NSLookup WPAD" | Out-File -FilePath ($resFile + "Networking\" + $env:computername + "_WinHTTP-Proxy.txt") -Append
            "" | Out-File -FilePath ($resFile + "Networking\" + $env:computername + "_WinHTTP-Proxy.txt") -Append
            $cmd = "nslookup wpad >>""" + $resFile + "Networking\" + $env:computername + "_WinHTTP-Proxy.txt""" + $RdrErr
            Write-LogDetails $cmd
            Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append


        # Collecting qwinsta information

            $cmd = "qwinsta /counter >>""" + $resFile + "SystemInfo\" + $env:computername + "_Qwinsta.txt""" + $RdrErr
            Write-LogDetails $cmd
            Invoke-Expression $cmd



##### Collecting policy information

        Write-Log "Collecting group policy information (gpresult)"

        $cmd = "gpresult /h """ + $resFile + "SystemInfo\" + $env:computername + "_Gpresult.html""" + $RdrErr
        write-LogDetails $cmd
        Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

        $cmd = "gpresult /r /v >""" + $resFile + "SystemInfo\" + $env:computername + "_Gpresult.txt""" + $RdrErr
        write-LogDetails $cmd
        Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append


##### Collecting group memberships

        Write-Log "Collecting group membership information"


        # Exporting members of Remote Desktop Users group

            if ([ADSI]::Exists("WinNT://localhost/Remote Desktop Users")) {
                $cmd = "net localgroup ""Remote Desktop Users"" >>""" + $resFile + "SystemInfo\" + $env:computername + "_LocalGroupsMembership.txt""" + $RdrErr
                Write-LogDetails $cmd
                Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append
            } else {
                Write-LogError "The 'Remote Desktop Users' group is not present"
            }
              
                                      
        # Exporting members of Offer Remote Assistance Helpers group

            if ($MSRA) {
                if ([ADSI]::Exists("WinNT://localhost/Offer Remote Assistance Helpers")) {
                    $cmd = "net localgroup ""Offer Remote Assistance Helpers"" >>""" + $resFile + "SystemInfo\" + $env:computername + "_LocalGroupsMembership.txt""" + $RdrErr
                    Write-LogDetails $cmd
                    Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append
                } else {
                    Write-LogError "The 'Offer Remote Assistance Helpers' group is not present"
                }

                if ([ADSI]::Exists("WinNT://localhost/Distributed COM Users")) {
                    $cmd = "net localgroup ""Distributed COM Users"" >>""" + $resFile + "SystemInfo\" + $env:computername + "_LocalGroupsMembership.txt""" + $RdrErr
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
        


        # Collecting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP

            if (Test-Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP') {          
              $cmd = "reg export 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP' """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_SW-MS-NetFS-NDP.txt"" /y" + $RdrOut + $RdrErr
              Write-LogDetails $cmd
              Invoke-Expression $cmd
            } else {
              Write-LogError "The registry key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP' is not present"
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

            if ($Profiles) {
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

           if ($Profiles) {
               if (Test-Path HKCU:\Software\Microsoft\Office) {          
                  $cmd = "reg export 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office' """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_SW-MS-Office.txt"" /y" + $RdrOut + $RdrErr
                  Write-LogDetails $cmd
                  Invoke-Expression $cmd
                } else {
                  Write-LogError "The registry key 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office' is not present"
                }


       # Collecting registry key HKEY_CURRENT_USER\Software\Policies\Microsoft\office

               if (Test-Path HKCU:\Software\Policies\Microsoft\office) {          
                  $cmd = "reg export 'HKEY_CURRENT_USER\Software\Policies\Microsoft\office' """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_SW-Policies-MS-Office.txt"" /y" + $RdrOut + $RdrErr
                  Write-LogDetails $cmd
                  Invoke-Expression $cmd
                } else {
                  Write-LogError "The registry key 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office' is not present"
                }
                
       # Collecting registry key HKEY_CURRENT_USER\SOFTWARE\Microsoft\OneDrive

               if (Test-Path HKCU:\SOFTWARE\Microsoft\OneDrive) {          
                  $cmd = "reg export 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\OneDrive' """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_SW-MS-OneDrive.txt"" /y" + $RdrOut + $RdrErr
                  Write-LogDetails $cmd
                  Invoke-Expression $cmd
                } else {
                  Write-LogError "The registry key 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\OneDrive' is not present"
                }
       

       # Collecting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Search

               if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows Search') {          
                  $cmd = "reg export 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Search' """+ $resFile + "RegistryKeys\" + $env:computername + "_reg_SW-MS-WindowsSearch.txt"" /y" + $RdrOut + $RdrErr
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

            if ($Profiles) {
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

            if ($Profiles) {
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


        # Collecting FSLogix event logs

                if (Get-WinEvent -ListLog FSLogix-Apps/Admin -ErrorAction SilentlyContinue) {
                  $cmd = "wevtutil epl 'FSLogix-Apps/Admin' """+ $resFile + "EventLogs\" + $env:computername + "_evt_FSLogix-Apps-Admin.evtx""" + $RdrOut + $RdrErr
                  Write-LogDetails $cmd
                  Invoke-Expression $cmd
                  ArchiveLog "FSLogix-Apps-Admin"
                } else {
                  Write-LogError "The event log 'FSLogix-Apps/Admin' is not present"
                }

                if (Get-WinEvent -ListLog FSLogix-Apps/Operational -ErrorAction SilentlyContinue) {
                  $cmd = "wevtutil epl 'FSLogix-Apps/Operational' """+ $resFile + "EventLogs\" + $env:computername + "_evt_FSLogix-Apps-Operational.evtx""" + $RdrOut + $RdrErr
                  Write-LogDetails $cmd
                  Invoke-Expression $cmd
                  ArchiveLog "FSLogix-Apps-Operational"
                } else {
                  Write-LogError "The event log 'FSLogix-Apps/Operational' is not present"
                }
            }



##### Collecting certificate information

    if ($Certificate) {
        Write-Log "Collecting certificate information"


        # Collecting certificates details
        New-Item -Path ($resFile + 'Certificates\') -ItemType Directory | Out-Null

            $cmd = "Certutil -verifystore -v MY > """ + $resFile + "Certificates\" + $env:computername + "_Certificates-My.txt""" + $RdrErr
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
            $tbcert | Export-Csv ($resFile + "Certificates\" + $env:computername + "_Certificates.csv") -noType -Delimiter "`t"
    }



##### Collecting installed Windows updates

        Write-Log "Collecting list of installed Windows updates"
        Get-HotFix -ErrorAction SilentlyContinue 2>>$errfile | Sort-Object -Property InstalledOn -Descending -ErrorAction SilentlyContinue | Out-File ($resFile + "SystemInfo\" + $env:computername + "_Hotfixes.txt")
        Write-LogDetails "Get-HotFix -ErrorAction SilentlyContinue 2>>$errfile | Sort-Object -Property InstalledOn -ErrorAction SilentlyContinue | Out-File ($resFile + ""SystemInfo\"" + $env:computername + ""_Hotfixes.txt"")"
      


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
          @{N="Threads";E={$_.ThreadCount}}, @{N="Handles";E={($_.HandleCount)}}, $StartTime, CommandLine | Out-String -Width 500 | Out-File -FilePath ($resFile + "SystemInfo\" + $env:computername + "_RunningProcesses.txt")
        

          Write-Log "Collecting file version of running and key system binaries"
          $binlist = $proc | Group-Object -Property ExecutablePath
          foreach ($file in $binlist) {
            if ($file.Name) {
              FileVersion -Filepath ($file.name) -Log $true
            }
          }

          (get-item -Path 'C:\Windows\System32\*.dll').VersionInfo | Format-List -Force | Out-File ($resFile + "SystemInfo\" + $env:computername + "_ver_System32_DLL.txt")
          (get-item -Path 'C:\Windows\System32\*.exe').VersionInfo | Format-List -Force | Out-File ($resFile + "SystemInfo\" + $env:computername + "_ver_System32_EXE.txt")
          (get-item -Path 'C:\Windows\System32\*.sys').VersionInfo | Format-List -Force | Out-File ($resFile + "SystemInfo\" + $env:computername + "_ver_System32_SYS.txt")
          (get-item -Path 'C:\Windows\System32\drivers\*.sys').VersionInfo | Format-List -Force | Out-File ($resFile + "SystemInfo\" + $env:computername + "_ver_Drivers.txt")
          (get-item -Path 'C:\Windows\SysWOW64\*.dll').VersionInfo | Format-List -Force | Out-File ($resFile + "SystemInfo\" + $env:computername + "_ver_SysWOW64_DLL.txt")
          (get-item -Path 'C:\Windows\SysWOW64\*.exe').VersionInfo | Format-List -Force | Out-File ($resFile + "SystemInfo\" + $env:computername + "_ver_SysWOW64_EXE.txt")
          (get-item -Path 'C:\Windows\SysWOW64\*.sys').VersionInfo | Format-List -Force | Out-File ($resFile + "SystemInfo\" + $env:computername + "_ver_SysWOW64_SYS.txt")
        
        
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
            $svc | Sort-Object DisplayName | Format-Table -AutoSize -Property ProcessId, DisplayName, StartMode,State, Name, PathName, StartName | Out-String -Width 400 | Out-File -FilePath ($resFile + "SystemInfo\" + $env:computername + "_Services.txt")
          }
          


        # Collecting system information

          Write-Log "Collecting system information (this might take a bit longer)"

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

          "Computer name".PadRight($pad) + " : " + $OS.CSName | Out-File -FilePath ($resFile + "SystemInfo\" + $env:computername + "_SystemInfo.txt") -Append
          "Model".PadRight($pad) + " : " + $CS.Model | Out-File -FilePath ($resFile + "SystemInfo\" + $env:computername + "_SystemInfo.txt") -Append
          "Manufacturer".PadRight($pad) + " : " + $CS.Manufacturer | Out-File -FilePath ($resFile + "SystemInfo\" + $env:computername + "_SystemInfo.txt") -Append
          "BIOS Version".PadRight($pad) + " : " + $BIOS.BIOSVersion | Out-File -FilePath ($resFile + "SystemInfo\" + $env:computername + "_SystemInfo.txt") -Append
          "BIOS Manufacturer".PadRight($pad) + " : " + $BIOS.Manufacturer | Out-File -FilePath ($resFile + "SystemInfo\" + $env:computername + "_SystemInfo.txt") -Append
          "BIOS Release date".PadRight($pad) + " : " + $BIOS.ReleaseDate | Out-File -FilePath ($resFile + "SystemInfo\" + $env:computername + "_SystemInfo.txt") -Append
          "SMBIOS Version".PadRight($pad) + " : " + $BIOS.SMBIOSBIOSVersion | Out-File -FilePath ($resFile + "SystemInfo\" + $env:computername + "_SystemInfo.txt") -Append
          "SystemType".PadRight($pad) + " : " + $CS.SystemType | Out-File -FilePath ($resFile + "SystemInfo\" + $env:computername + "_SystemInfo.txt") -Append
          "Processor".PadRight($pad) + " : " + $PR.Name + " / " + $PR.Caption | Out-File -FilePath ($resFile + "SystemInfo\" + $env:computername + "_SystemInfo.txt") -Append
          "Processors physical/logical".PadRight($pad) + " : " + $CS.NumberOfProcessors + " / " + $CS.NumberOfLogicalProcessors | Out-File -FilePath ($resFile + "SystemInfo\" + $env:computername + "_SystemInfo.txt") -Append
          "Memory physical/visible".PadRight($pad) + " : " + ("{0:N0}" -f ($CS.TotalPhysicalMemory/1mb)) + " MB / " + ("{0:N0}" -f ($OS.TotalVisibleMemorySize/1kb)) + " MB" | Out-File -FilePath ($resFile + "SystemInfo\" + $env:computername + "_SystemInfo.txt") -Append
          "Pool Paged / NonPaged".PadRight($pad) + " : " + ("{0:N0}" -f ($PoolPaged/1mb)) + " MB / " + ("{0:N0}" -f ($PoolNonPaged/1mb)) + " MB" | Out-File -FilePath ($resFile + "SystemInfo\" + $env:computername + "_SystemInfo.txt") -Append
          "Free physical memory".PadRight($pad) + " : " + ("{0:N0}" -f ($OS.FreePhysicalMemory/1kb)) + " MB" | Out-File -FilePath ($resFile + "SystemInfo\" + $env:computername + "_SystemInfo.txt") -Append
          "Paging files size / free".PadRight($pad) + " : " + ("{0:N0}" -f ($OS.SizeStoredInPagingFiles/1kb)) + " MB / " + ("{0:N0}" -f ($OS.FreeSpaceInPagingFiles/1kb)) + " MB" | Out-File -FilePath ($resFile + "SystemInfo\" + $env:computername + "_SystemInfo.txt") -Append
          "Operating System".PadRight($pad) + " : " + $OS.Caption + " " + $OS.OSArchitecture | Out-File -FilePath ($resFile + "SystemInfo\" + $env:computername + "_SystemInfo.txt") -Append


            [string]$WinVerBuild = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion' CurrentBuild).CurrentBuild
            [string]$WinVerRevision = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion' UBR).UBR

if (!($ver -like "*Windows 7*")) {                              
            [string]$WinVerMajor = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion' CurrentMajorVersionNumber).CurrentMajorVersionNumber
            [string]$WiNVerMinor = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion' CurrentMinorVersionNumber).CurrentMinorVersionNumber
            $WinVer = "Build Number".PadRight($pad) + " : " + $WinVerMajor + "." + $WiNVerMinor + "." + $WinVerBuild + "." + $WinVerRevision | Out-File -FilePath ($resFile + "SystemInfo\" + $env:computername + "_SystemInfo.txt") -Append
} else {
            $WinVer = "Build Number".PadRight($pad) + " : " + $WinVerBuild + "." + $WinVerRevision | Out-File -FilePath ($resFile + "SystemInfo\" + $env:computername + "_SystemInfo.txt") -Append
}
                      
          "Installation type".PadRight($pad) + " : " + (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").InstallationType | Out-File -FilePath ($resFile + "SystemInfo\" + $env:computername + "_SystemInfo.txt") -Append
          "Time zone".PadRight($pad) + " : " + $TZ.Description | Out-File -FilePath ($resFile + "SystemInfo\" + $env:computername + "_SystemInfo.txt") -Append
          "Install date".PadRight($pad) + " : " + $OS.InstallDate | Out-File -FilePath ($resFile + "SystemInfo\" + $env:computername + "_SystemInfo.txt") -Append
          "Last boot time".PadRight($pad) + " : " + $OS.LastBootUpTime | Out-File -FilePath ($resFile + "SystemInfo\" + $env:computername + "_SystemInfo.txt") -Append
          "Local time".PadRight($pad) + " : " + $OS.LocalDateTime | Out-File -FilePath ($resFile + "SystemInfo\" + $env:computername + "_SystemInfo.txt") -Append
          "DNS Hostname".PadRight($pad) + " : " + $CS.DNSHostName | Out-File -FilePath ($resFile + "SystemInfo\" + $env:computername + "_SystemInfo.txt") -Append
          "DNS Domain name".PadRight($pad) + " : " + $CS.Domain | Out-File -FilePath ($resFile + "SystemInfo\" + $env:computername + "_SystemInfo.txt") -Append
          "NetBIOS Domain name".PadRight($pad) + " : " + (GetNBDomainName) | Out-File -FilePath ($resFile + "SystemInfo\" + $env:computername + "_SystemInfo.txt") -Append
          $roles = "Standalone Workstation", "Member Workstation", "Standalone Server", "Member Server", "Backup Domain Controller", "Primary Domain Controller"
          "Domain role".PadRight($pad) + " : " + $roles[$CS.DomainRole] | Out-File -FilePath ($resFile + "SystemInfo\" + $env:computername + "_SystemInfo.txt") -Append

          " " | Out-File -FilePath ($resFile + "SystemInfo\" + $env:computername + "_SystemInfo.txt") -Append

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
          Out-File -FilePath ($resFile + "SystemInfo\" + $env:computername + "_SystemInfo.txt") -Append
       } else {
          $proc = Get-Process | Where-Object {$_.Name -ne "Idle"}
          $proc | Format-Table -AutoSize -property id, name, @{N="WorkingSet";E={"{0:N0}" -f ($_.workingset/1kb)};a="right"},
          @{N="VM Size";E={"{0:N0}" -f ($_.VirtualMemorySize/1kb)};a="right"},
          @{N="Proc time";E={($_.TotalProcessorTime.ToString().substring(0,8))}}, @{N="Threads";E={$_.threads.count}},
          @{N="Handles";E={($_.HandleCount)}}, StartTime, Path | 
          Out-String -Width 300 | Out-File -FilePath ($resFile + "SystemInfo\" + $env:computername + "_RunningProcesses.txt")
        }


        ### Collecting PowerShell version
        "PowerShell Information:" | Out-File -FilePath ($resFile + "SystemInfo\" + $env:computername + "_SystemInfo.txt") -Append
        $PSVersionTable | Format-Table Name, Value | Out-File -FilePath ($resFile + "SystemInfo\" + $env:computername + "_SystemInfo.txt") -Append


        ### Collecting .Net version
        ".Net Framework Information:" | Out-File -FilePath ($resFile + "SystemInfo\" + $env:computername + "_SystemInfo.txt") -Append
        Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse | Get-ItemProperty -Name version -EA 0 | Where-Object { $_.PSChildName -Match '^(?!S)\p{L}'} | Select-Object PSChildName, version | Out-File -FilePath ($resFile + "SystemInfo\" + $env:computername + "_SystemInfo.txt") -Append



        ### Collecting msinfo32 information
        $cmd = "msinfo32 /nfo """ + $resFile + "SystemInfo\" + $env:computername + "_msinfo32.nfo""" + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression $cmd

        while (!(Test-Path ($resFile + "SystemInfo\" + $env:computername + "_msinfo32.nfo"))) { Start-Sleep 30 }



        ### Collecting MiniFilter driver information        
        $cmd = "fltmc filters >""" + $resFile + "SystemInfo\" + $env:computername + "_Fltmc.txt""" + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append



##### Collecting RDClient AutoTraces

    if ($Client) {
        
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
    
    $diagfile = $resFile + "SystemInfo\" + $env:computername + "_WinRM-Config.txt"

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
        $cmd = "winrm get winrm/config >>""" + $resFile + "SystemInfo\" + $env:computername + "_WinRM-Config.txt""" + $RdrErr
        Write-LogDetails $cmd
        Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

        Write-LogDetails "winrm e winrm/config/listener"
        $cmd = "winrm e winrm/config/listener >>""" + $resFile + "SystemInfo\" + $env:computername + "_WinRM-Config.txt""" + $RdrErr
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





# Running WVD Diagnostics

Write-host
if (!$DiagOnly) { 
    Write-LogTitle "Data collection complete - starting diagnostics (... please wait ...)" "White" "DarkCyan" 
} else {
    Write-LogTitle "Starting diagnostics (... please wait ...)" "White" "DarkCyan"
}

Write-host
Write-Log "Running WVD Diagnostics (see the 'WVD-Diag.txt' file in the output folder for details)"

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


"WVD Diagnostics" | Out-File -FilePath $diagfile -Append
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
            $servstart = (Get-Service $_).StartType
                if ($servstatus -eq "Stopped") { 
                    $msg = "... " + $_ + " (" + $servdispname + ") is Stopped (StartType: " + $servstart + ")."
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


if ($Profiles) {
    "frxsvc", "frxdrv", "frxccds", "OneDrive Updater Service" | ForEach-Object -Process {

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


#checking start type of Windows Installer (if disabled, it prevents agent upgrades)
$service = Get-Service -Name msiserver -ErrorAction SilentlyContinue
    if ($service.Length -gt 0) {
            if ($service.StartType -eq "Disabled") { 
                $msg = "... [WARNING] " + $service.Name + " (" + $service.DisplayName + ") has StartType: " + $service.StartType + ". If you disable Windows Installer, the service won't be able to install agent updates on your session hosts, and your session hosts won't function properly."
                write-diag $msg
            } 
            else { 
                $msg = "... " + $service.Name + " (" + $service.DisplayName + ") is in '" + $service.Status + "' state (StartType: " + $service.StartType + ")."
                write-diag $msg
            }
    }
    else {
        $msg = "... [WARNING] " + $service.Name + " is missing!"
        write-diag $msg
    }



if (!($ver -like "*Windows 7*")) {

" " | Out-File -FilePath $diagfile -Append
"==========================================" | Out-File -FilePath $diagfile -Append
" " | Out-File -FilePath $diagfile -Append


# Checking for WVD Agent and Stack information
    Write-Diag "Checking for WVD Agent and Stack information"

    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\RDAgentBootLoader') {

        if (Test-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\RDAgentBootLoader\' -Value 'DefaultAgent') {

            $wvdagent = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\RDAgentBootLoader\' -name "DefaultAgent"
            $wvdagentver = $wvdagent.split("_")[1]

            $sxsstack = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\RDInfraAgent\SxsStack' -name "CurrentVersion"
            $sxsstackpath = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\RDInfraAgent\SxsStack' -name $sxsstack
            $sxsstackver = $sxsstackpath.split("-")[1].trimend(".msi")

            $wvdagentdate = (Get-ItemProperty  hklm:\software\microsoft\windows\currentversion\uninstall\* | Where-Object {($_.DisplayName -eq "Remote Desktop Services Infrastructure Agent" -and $_.DisplayVersion -eq $wvdagentver)}).InstallDate

            $msg = "... Current WVD Agent version: " + $wvdagentver + " (Installed on: " + $wvdagentdate + ")"
            Write-Diag $msg

            $sxsstackdate = (Get-ItemProperty  hklm:\software\microsoft\windows\currentversion\uninstall\* | Where-Object {($_.DisplayName -eq "Remote Desktop Services SxS Network Stack" -and $_.DisplayVersion -eq $sxsstackver)}).InstallDate
            $msg = "... Current SxS Stack version: " + $sxsstackver + " (Installed on: " + $sxsstackdate + ")"
            Write-Diag $msg
            
            if (Test-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\RDAgentBootLoader\' -Value 'PreviousAgent') {

                $wvdagentpre = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\RDAgentBootLoader\' -name "PreviousAgent"
                $wvdagentverpre = $wvdagentpre.split("_")[1]

                $sxsstackpre = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\RDInfraAgent\SxsStack' -name "PreviousVersion"
                $sxsstackpathpre = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\RDInfraAgent\SxsStack' -name $sxsstackpre
                $sxsstackverpre = $sxsstackpathpre.split("-")[1].trimend(".msi")

                $wvdagentdatepre = (Get-ItemProperty  hklm:\software\microsoft\windows\currentversion\uninstall\* | Where-Object {($_.DisplayName -eq "Remote Desktop Services Infrastructure Agent" -and $_.DisplayVersion -eq $wvdagentverpre)}).InstallDate

                $msg = "... Previous WVD Agent version: " + $wvdagentverpre + " (Installed on: " + $wvdagentdatepre + ")"
                Write-Diag $msg

                $sxsstackdatepre = (Get-ItemProperty  hklm:\software\microsoft\windows\currentversion\uninstall\* | Where-Object {($_.DisplayName -eq "Remote Desktop Services SxS Network Stack" -and $_.DisplayVersion -eq $sxsstackverpre)}).InstallDate
                $msg = "... Previous SxS Stack version: " + $sxsstackverpre + " (Installed on: " + $sxsstackdatepre + ")"
                Write-Diag $msg

            }
        
            $msg = "... For more details check the agent and stack installation log files collected under the '" + $env:computername + "_LogFiles' subfolder (not available when the tool run with '-DiagOnly')."
            Write-Diag $msg

        } else {
            Write-Diag "... Registry key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RDAgentBootLoader\DefaultAgent' is missing! This machine is either not a WVD VM or the WVD agent is not installed or configured properly."
        }
    } else {
        Write-Diag "... Registry key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RDAgentBootLoader' is missing! This machine is either not a WVD VM or the WVD agent is not installed or configured properly."
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

        $msg = "... The WVD listener currently in use is: " + $listenervalue
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


if (!($ver -like "*Windows 7*")) {
    " " | Out-File -FilePath $diagfile -Append
    "==========================================" | Out-File -FilePath $diagfile -Append
    " " | Out-File -FilePath $diagfile -Append

    # Checking the UDP listener
    Write-Diag "Checking UDP ShortPath configuration"

        # Checking for UDP ShortPath registry keys

        if (test-registryvalue -path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations' -value 'fUseUdpPortRedirector') {

            $keyvalue = Get-ItemPropertyValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations' -name "fUseUdpPortRedirector"
    
            if ($keyvalue = "1") {    
                $msg = "... Registry key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\fUseUdpPortRedirector' exists and has the expected value of: " + $keyvalue 
                Write-Diag $msg
            } 
            else {
                $msg = "... Registry key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\fUseUdpPortRedirector' exists and has a value of: " + $keyvalue + " but this is not the expected value for UDP ShortPath. UDP ShortPath is not configured properly."
                Write-Diag $msg
            }
        }
        else {
            Write-Diag "... Registry key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\fUseUdpPortRedirector' is missing. UDP ShortPath is either not configured at all or not configured properly."
        }


        if (test-registryvalue -path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations' -value 'UdpPortNumber') {

            $keyvalue = Get-ItemPropertyValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations' -name "UdpPortNumber"
    
            if ($keyvalue = "3390") {    
                $msg = "... Registry key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\UdpPortNumber' exists and has the expected value of: " + $keyvalue
                Write-Diag $msg
            } 
            else {
                $msg = "... Registry key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\UdpPortNumber' exists and has a value of: " + $keyvalue + " but this is not the expected value for UDP ShortPath. UDP ShortPath is not configured properly."
                Write-Diag $msg
            }
        }
        else {
            Write-Diag "... Registry key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\UdpPortNumber' is missing. UDP ShortPath is either not configured at all or not configured properly."
        }


        # Checking if TermService is listening for UDP

        $udplistener = Get-NetUDPEndpoint -OwningProcess ((get-ciminstance win32_service -Filter "name = 'TermService'").ProcessId) -LocalPort 3390 -ErrorAction SilentlyContinue
        if ($udplistener) {
            Write-Diag "... TermService is listening on UDP port 3390."
        }
        else {
            # Checking the process occupying UDP port 3390

            $procpid = (Get-NetUDPEndpoint -LocalPort 3390 -LocalAddress 0.0.0.0 -ErrorAction SilentlyContinue).OwningProcess

            if ($procpid) {
                Write-Diag "... TermService is NOT listening on UDP port 3390. UDP ShortPath is either not configured at all or not configured properly. The UDP port 3390 is being used by:"
                tasklist /svc /fi "PID eq $procpid" | Out-File -FilePath $diagfile -Append    
            }
            else {
                Write-Diag "... No process is using UDP port 3390. UDP ShortPath is either not configured at all or not configured properly."
            }
        }


        # Checking if there are Firewall rules for UDP 3390

        $fwrules = (Get-NetFirewallPortFilter –Protocol UDP | Where-Object { $_.localport –eq ‘3390’ } | Get-NetFirewallRule)
        if ($fwrules.count -eq 0) {
            Write-Diag "... No firewall rule for UDP port 3390."
        } else {
            Write-Diag "... Found firewall rule for UDP port 3390. Check the 'FirewallRules.txt' file for more details."
        }
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
    $fwrules = (Get-NetFirewallPortFilter –Protocol TCP | Where-Object { $_.localport –eq ‘5985’ } | Get-NetFirewallRule)
    if ($fwrules.count -eq 0) {
      Write-Diag "... No firewall rule for port 5985."
    } else {
      Write-Diag "... Found firewall rule for port 5985. Check the 'FirewallRules.txt' file for more details."
    }


    $fwrules = (Get-NetFirewallPortFilter –Protocol TCP | Where-Object { $_.localport –eq ‘5986’ } | Get-NetFirewallRule)
    if ($fwrules.count -eq 0) {
      Write-Diag "... No firewall rule for port 5986."
    } else {
      Write-Diag "... Found firewall rule for port 5986. Check the 'FirewallRules.txt' file for more details."
    }
}


# Checking the WinRMRemoteWMIUsers__ group"

    if ((get-ciminstance -Class Win32_ComputerSystem).PartOfDomain) {
  
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
        if (get-ciminstance -query "select * from Win32_Group where Name = 'WinRMRemoteWMIUsers__' and Domain = '$env:computername'") {
          Write-Diag "... The group WinRMRemoteWMIUsers__ is also present as machine local group."
        }
      } else {
        Write-Diag "... [WARNING] The WinRMRemoteWMIUsers__ was not found in the domain." 
        if (get-ciminstance -query "select * from Win32_Group where Name = 'WinRMRemoteWMIUsers__' and Domain = '$env:computername'") {
          Write-Diag "... The group WinRMRemoteWMIUsers__ is present as machine local group."
        } else {
          Write-Diag "... [WARNING] The group WinRMRemoteWMIUsers__ is not present as machine local group!"
        }
      }
    } else {
      Write-Diag "... [WARNING] The machine is not joined to a domain."
      if (get-ciminstance -query "select * from Win32_Group where Name = 'WinRMRemoteWMIUsers__' and Domain = '$env:computername'") {
        Write-Diag "... The group WinRMRemoteWMIUsers__ is present as machine local group."
      } else {
        Write-Diag "... [WARNING] The group WinRMRemoteWMIUsers__ is not present as machine local group!"
      }
    }



    # Checking for proper Defender Exclusions for FSLogix
    if ($Profiles -and (Test-path -path 'C:\Program Files\FSLogix\apps')) {

      " " | Out-File -FilePath $diagfile -Append
      "==========================================" | Out-File -FilePath $diagfile -Append
      " " | Out-File -FilePath $diagfile -Append
  
      Write-Diag "FSLogix detected - Checking for currently configured Windows Defender Antivirus exclusions"
      Write-Diag "... The tool is comparing the local settings with the recommended settings from https://docs.microsoft.com/en-us/azure/architecture/example-scenario/wvd/windows-virtual-desktop-fslogix#antivirus-exclusions (as of the date of this tool's release)."
      Write-Diag "... The below information is only for Windows Defender. If you are using any other Antivirus software, you should configure the recommended exclusions similarly, based on the above article."
      if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions') {          
        Write-Diag "... Windows Defender Extensions exclusions"
        if ((Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions').Property) {
            #(Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions').Property | ForEach-Object -process {
            #  Write-Diag "... ... $_"
            #}
            
            $recextensions = @("%ProgramFiles%\FSLogix\Apps\frxdrv.sys","%ProgramFiles%\FSLogix\Apps\frxdrvvt.sys","%ProgramFiles%\FSLogix\Apps\frxccd.sys","%TEMP%\*.VHD","%TEMP%\*.VHDX","%Windir%\TEMP\*.VHD","%Windir%\TEMP\*.VHDX","\\storageaccount.file.core.windows.net\share*\*.VHD","\\storageaccount.file.core.windows.net\share*\*.VHDX")
            $foundextensions = @((Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths').Property)
            $msgext = Compare-Object -ReferenceObject($foundextensions) -DifferenceObject($recextensions)
            
            Write-Diag "... Comparing local values found with recommended values. False positives may occur if you use full paths instead of environment variables."
            if ($msgext) {              
              Write-Diag "... => means a recommended value that is not configured on this VM."
              Write-Diag "... <= means a local value that is not part of the default list of recommended values."
                          
              $msgext | Out-File -FilePath $diagfile -Append
            } else {
              Write-Diag "... No differences found."
            }

        } else {
          Write-Diag "... [WARNING] No Extensions exclusions have been found. Follow the above article to configure the recommended exclusions."
        }   
      }
            
      if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths') {          
        Write-Diag "... Windows Defender Paths exclusions"
        if ((Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths').Property) {
            #(Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths').Property | ForEach-Object -process {
            #  Write-Diag "... ... $_"
            #}

            $recpaths = @("%ProgramFiles%\FSLogix\Apps\frxdrv.sys","%ProgramFiles%\FSLogix\Apps\frxdrvvt.sys","%ProgramFiles%\FSLogix\Apps\frxccd.sys","%TEMP%\*.VHD","%TEMP%\*.VHDX","%Windir%\TEMP\*.VHD","%Windir%\TEMP\*.VHDX","\\storageaccount.file.core.windows.net\share*\*.VHD","\\storageaccount.file.core.windows.net\share*\*.VHDX")
            $foundpaths = @((Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths').Property)
            $msgpath = Compare-Object -ReferenceObject($foundpaths) -DifferenceObject($recpaths)
          
            Write-Diag "... Comparing local values found with recommended values. False positives may occur if you use full paths instead of environment variables."
            if ($msgpath) {              
              Write-Diag "... => means a recommended value that is not configured on this VM."
              Write-Diag "... <= means a local value that is not part of the default list of recommended values."
              
              $msgpath | Out-File -FilePath $diagfile -Append
            } else {
              Write-Diag "... No differences found."
            }

        } else {
            Write-Diag "... [WARNING] No Paths exclusions have been found. Follow the above article to configure the recommended exclusions."
        }         
      }

      if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes') {          
        Write-Diag "... Windows Defender Processes exclusions"
        if ((Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes').Property) {
            #(Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes').Property | ForEach-Object -process {
            #  Write-Diag "... ... $_"
            #}

            $recprocesses = @("%ProgramFiles%\FSLogix\Apps\frxccd.exe","%ProgramFiles%\FSLogix\Apps\frxccds.exe","%ProgramFiles%\FSLogix\Apps\frxsvc.exe")
            $foundprocesses = @((Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes').Property)
            $msgproc = Compare-Object -ReferenceObject($foundprocesses) -DifferenceObject($recprocesses)

            Write-Diag "... Comparing local values found with recommended values. False positives may occur if you use full paths instead of environment variables."
            if ($msgproc) {
              Write-Diag "... => means a recommended value that is not configured on this VM."
              Write-Diag "... <= means a local value that is not part of the default list of recommended values."
              
              $msgproc | Out-File -FilePath $diagfile -Append
            } else {
              Write-Diag "... No differences found."
            }

        } else {
            Write-Diag "... [WARNING] No Processes exclusions have been found. Follow the above article to configure the recommended exclusions."
        }    
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


If($fQuickEditCodeExist){
    [DisableConsoleQuickEdit]::SetQuickEdit($False) | Out-Null
}

# SIG # Begin signature block
# MIIjwAYJKoZIhvcNAQcCoIIjsTCCI60CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAfmf6QyXf7xPvh
# Ko8aUSahBZ01Jnc5sc7o5jgTdBApUaCCDYEwggX/MIID56ADAgECAhMzAAABh3IX
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
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgKP82h+wE
# zI+3OBak6wkyIqXJJ8ZYpSg4RXpfuByMA+QwcAYKKwYBBAGCNwIBDDFiMGCgQIA+
# AFcAVgBEACAAQwBvAGwAbABlAGMAdAAgAGYAbwByACAAVAByAG8AdQBiAGwAZQBz
# AGgAbwBvAHQAaQBuAGehHIAaaHR0cHM6Ly9ha2EubXMvd3ZkLWNvbGxlY3QwDQYJ
# KoZIhvcNAQEBBQAEggEAeo82kckYaNGSu7vwEUTy0KFVuXji8dtpn0C9rqSxTo1Q
# vgq5Bje8seJAdW/q6I+SgKmWmMr3Xbl863r1NA8/4nQAmU53T8EGVzpis4pf6P0o
# W9+086B0wEvJ2LU2JZHpzZqTtHXC80+kpNpcmUdEXLRS8qJh7AW1qwmlqeL7qD0N
# qFOKCzHpVZ4XKupTLkJyND0sTONhAOgNfRDT0Ayho+qvk9Jqetn0JsfCkRbX2TNI
# sk8qMiS5uXMYQW7LKfCdFN90weW0KBZVDHlGOszqvOafYBS2wL1IN2SHGTkh6oIt
# 0sd07+janjb5jj3P/vzTtzROCVxJ1iRHkrOsdqrI4qGCEvEwghLtBgorBgEEAYI3
# AwMBMYIS3TCCEtkGCSqGSIb3DQEHAqCCEsowghLGAgEDMQ8wDQYJYIZIAWUDBAIB
# BQAwggFVBgsqhkiG9w0BCRABBKCCAUQEggFAMIIBPAIBAQYKKwYBBAGEWQoDATAx
# MA0GCWCGSAFlAwQCAQUABCC3NxfIjcjZuNNC8xtsy80j1pR5wxZ00ONH/Buw3QJt
# EgIGX9uJq6szGBMyMDIwMTIyMjA2NDgzNi4xNDNaMASAAgH0oIHUpIHRMIHOMQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSkwJwYDVQQLEyBNaWNy
# b3NvZnQgT3BlcmF0aW9ucyBQdWVydG8gUmljbzEmMCQGA1UECxMdVGhhbGVzIFRT
# UyBFU046MEE1Ni1FMzI5LTRENEQxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0
# YW1wIFNlcnZpY2Wggg5EMIIE9TCCA92gAwIBAgITMwAAAScvbqPvkagZqAAAAAAB
# JzANBgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAe
# Fw0xOTEyMTkwMTE0NTlaFw0yMTAzMTcwMTE0NTlaMIHOMQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMSkwJwYDVQQLEyBNaWNyb3NvZnQgT3BlcmF0
# aW9ucyBQdWVydG8gUmljbzEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046MEE1Ni1F
# MzI5LTRENEQxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2Uw
# ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQD4Ad5xEZ5On0uNL71ng9xw
# oDPRKeMUyEIj5yVxPRPh5GVbU7D3pqDsoXzQMhfeRP61L1zlU1HCRS+129eo0yj1
# zjbAlmPAwosUgyIonesWt9E4hFlXCGUcIg5XMdvQ+Ouzk2r+awNRuk8ABGOa0I4V
# By6zqCYHyX2pGauiB43frJSNP6pcrO0CBmpBZNjgepof5Z/50vBuJDUSug6OIMQ7
# ZwUhSzX4bEmZUUjAycBb62dhQpGqHsXe6ypVDTgAEnGONdSBKkHiNT8H0Zt2lm0v
# CLwHyTwtgIdi67T/LCp+X2mlPHqXsY3u72X3GYn/3G8YFCkrSc6m3b0wTXPd5/2f
# AgMBAAGjggEbMIIBFzAdBgNVHQ4EFgQU5fSWVYBfOTEkW2JTiV24WNNtlfIwHwYD
# VR0jBBgwFoAU1WM6XIoxkPNDe3xGG8UzaFqFbVUwVgYDVR0fBE8wTTBLoEmgR4ZF
# aHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljVGlt
# U3RhUENBXzIwMTAtMDctMDEuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcw
# AoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNUaW1TdGFQ
# Q0FfMjAxMC0wNy0wMS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEF
# BQcDCDANBgkqhkiG9w0BAQsFAAOCAQEACsqNfNFVxwalZ42cEMuzZc126Nvluanx
# 8UewDVeUQZEZHRmppMFHAzS/g6RzmxTyR2tKE3mChNGW5dTL730vEbRhnYRmBgiX
# /gT3f4AQrOPnZGXY7zszcrlbgzxpakOX+x0u4rkP3Ashh3B2CdJ11XsBdi5PiZa1
# spB6U5S8D15gqTUfoIniLT4v1DBdkWExsKI1vsiFcDcjGJ4xRlMRF+fw7SY0WZoO
# zwRzKxDTdg4DusAXpaeKbch9iithLFk/vIxQrqCr/niW8tEA+eSzeX/Eq1D0ZyvO
# n4e2lTnwoJUKH6OQAWSBogyK4OCbFeJOqdKAUiBTgHKkQIYh/tbKQjCCBnEwggRZ
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
# cmF0aW9ucyBQdWVydG8gUmljbzEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046MEE1
# Ni1FMzI5LTRENEQxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZp
# Y2WiIwoBATAHBgUrDgMCGgMVALOVuE5sgxzETO4s+poBqI6r1x8zoIGDMIGApH4w
# fDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMd
# TWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEFBQACBQDj
# i/arMCIYDzIwMjAxMjIyMDgzODAzWhgPMjAyMDEyMjMwODM4MDNaMHcwPQYKKwYB
# BAGEWQoEATEvMC0wCgIFAOOL9qsCAQAwCgIBAAICFyICAf8wBwIBAAICEcUwCgIF
# AOONSCsCAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQAC
# AwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUFAAOBgQBWgTVCqLlE7S+S3Wc9
# OE4y9Wac6Jn6W9qgOQPb5HA+OscvFPie8xij8Y0KwrH2cQdHjUXEH7w556GRFNcS
# rYcUSc9BNRix9HKq8k7xkTk9SnwX7FWugTZmkAQ5GSffyS2842iS2MnM3rT6p0kY
# M9kabaFDe4tOOCUndzu2cOfldDGCAw0wggMJAgEBMIGTMHwxCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1l
# LVN0YW1wIFBDQSAyMDEwAhMzAAABJy9uo++RqBmoAAAAAAEnMA0GCWCGSAFlAwQC
# AQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkE
# MSIEIOaaQ2g7wyUQfhZ4bCR1FW/YmHFyL328dvaEOk6em3XGMIH6BgsqhkiG9w0B
# CRACLzGB6jCB5zCB5DCBvQQgG5LoSxKGHWoW/wVMlbMztlQ4upAdzEmqH//vLu0j
# PiIwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQ
# MA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
# MSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAScv
# bqPvkagZqAAAAAABJzAiBCDQWwIT7tKQuodLmBd7u7/xUwp3g8qsXGuSj60QVYWS
# nTANBgkqhkiG9w0BAQsFAASCAQAx5mlDicPtfV72bFtv9x5BYwaNDWpM6U7u/40N
# sr1R0pi0aDTpJwC/fudhhPmE8mz4TgFoStychY6WTNNPIYe7kswPVOIWLYx3nooT
# j82g+/WcBzKc2brBRvlftJZzk3a71hCzFxthlBkDv0mxKl3YlASivnbwqOPSin60
# UjP5wI34TLP3HjdH0Ku2l++jkxrkxJFFv4hGYhtR0tNZtMR2NIyULDWhHdXt6T20
# az5WKlCb4PKSNNqRf7qBEs0Gov3DCBGaVPH2TUToqvUlKtsKKWSotd4cjhkWN5PK
# pqjH2M0Ql4DahQ77hY3pWB2dBJI/9vVhinlpht51avpaEkpt
# SIG # End signature block
