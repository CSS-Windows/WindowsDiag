## WMI-Collect

Version: v201110.3

Description: ​​​​​​​​​​​​​​​​​​​​​​​This script is designed to collect information that will help Microsoft Customer Support Services (CSS) troubleshoot an issue you may be experiencing with Windows Virtual Desktop.
The collected data may contain Personally Identifiable Information (PII) and/or sensitive data, such as (but not limited to) IP addresses, PC names and user names.
The script will save the collected data in a subfolder and also compress the results into a ZIP file. The folder or ZIP file are not automatically sent to Microsoft. 
You can send the ZIP file to Microsoft CSS using a secure file transfer tool - Please discuss this with your support professional and also any concerns you may have. 
Find our privacy statement here: https://privacy.microsoft.com/en-us/privacy 


### How to use WVD-Collect (v201110.3)

The script must be run with elevated permissions in order to collect all required data. It works on any Windows client and Windows server OS supporting at least PowerShell 5.1.
Run the script on WVD host VMs and/or on Windows based devices from where you connect to the WVD hosts, as needed.
The script will collect a set of "default data" regardless of parameters. 
By adding one or more parameters, you can collect additional data, useful for specific troubleshooting scenarios.
The script will archive the collected data into a .zip file located in the same folder as the script itself.

### Available command line parameters:

-Certificate = Collects Certificates related data

-ClientAutoTrace = Collects existing RD client ETL traces and RD client upgrade log from devices running the WVD Desktop Client (the content of the "C:\Users\%username%\AppData\Local\Temp\DiagOutputDir\RdClientAutoTrace" folder)

	Important note: This "-ClientAutoTrace" parameter is useful for collecting the automatic client ETL traces, when troubleshooting WVD client connectivity or WVD client issues. 
	Please note that the RdClientAutoTrace folder might get quite large over time. 
	When such data is needed for troubleshooting, recommended is to first clear the content of the folder (eventually create a backup of the old content if you want), then reproduce the issue and close the client afterwards so that new traces are generated and after that run the WVD-Collect script so that only the latest, relevant traces are collected.

-MonTables = Collects existing converted monitoring traces from WVD hosts (.csv files converted from existing .tsf files from under "C:\Windows\System32\config\systemprofile\AppData\Roaming\Microsoft\Monitoring\Tables")

	Important note: This "-MonTables" parameter is useful for investigating issues with WVD hosts not communicating with the WVD services (Broker or Diagnostics).
	In these scenarios Kusto/Log Analytics may not receive any data, but some traces are still available on the hosts themselves and may help identify the underlying cause.

-MSRA = Collects Remote Assistance related data

-Profile = Collects User Profile related data (incl. FSLogix)

-Teams = Collects Teams WVD optimization related data
	
	Important note: To collect the proper data when having issues with Teams optimized for WVD, reproduce the issue with an affected user, press Ctrl+Alt+Shift+1 within the affected user's session while Teams isopen to generate additional Teams diagnostics data and after that run the script with the "-Teams" parameter (WVD-Collect.ps1 -Teams) within this affected user's WVD session.
	The script itself will not force generating these diagnostics files, it will only collect them if they are already available.
	There is also an additional confirmation prompt when launching the script with the "-Teams" parameter to get the user's confirmation that these prerequisites have been met before continuing.

-DiagOnly = When executed with this parameter (even if other parameters are also included) the script will skip ALL data collection and will ONLY run the diagnostics part. This is useful when you want to run only a quick Diag without collecting additional data.

	Important note: To run diagnostics also for a specific scenario (like Profile troubleshooting), the corresponding command line parameter needs to be present too.
	E.g.: 
		".\WVD-Collect.ps1 -DiagOnly" will run only the default diagnostics
		".\WVD-Collect.ps1 -Profile -DiagOnly" will run the default diagnostics + "Profile"-specific diagnostics

-Verbose = Displays more verbose information about the steps performed during data collection

Usage example without parameters (collects only default data):
	.\WVD-Collect.ps1 

Usage example with parameters (collects default data + profile related information + Teams WVD optimization related data + displays more information on the performed steps):
	.\WVD-Collect.ps1 -Profile -Teams -Verbose

### PowerShell ExecutionPolicy
If the script does not start, complaining about execution restrictions, then in an elevated PowerShell console run:
	Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Force -Scope Process
and verify with "Get-ExecutionPolicy -List" that no ExecutionPolicy with higher precedence is blocking execution of this script.
The script is digitally signed with a Microsoft Code Signing certificate.
After that run the WVD-Collect script again.
If you cannot change the ExecutionPolicy settings or a higher restriction applies that blocks execution of the script, please ask your domain admin (or the responsible team) for a temporary exemption.
Once the script has started, p​​​lease read the "IMPORTANT NOTICE" message and confirm if you agree to continue with the data collection.
Depending on the amount of data that needs to be collected, the script may need run for several minutes. Please wait until the script finishes collecting all the data.
If you are missing any of the data that the tool should normally collect, check the content of "*_WVD-Collect-Output.txt" and "*_WVD-Collect-Errors.txt" for more information. Some data may not be present during data collection and thus not picked up by the script. This should be visible in one of the two text files.


### Data being collected

The collected data is stored in a subfolder under the same folder where the script is located and at the end of the data collection, the results are archived into a .zip file. No data is automatically uploaded to Microsoft.

The script collects the following set of "default data" (if present) regardless if command line parameters have been specified (in brackets is the folder or file that contains the collected data, with * = computer name):

1. Log files:__
C:\Packages\Plugins\Microsoft.Powershell.DSC\<version>\Status\__
C:\Packages\Plugins\Microsoft.Compute.JsonADDomainExtension\<version>\Status\__
C:\Packages\Plugins\Microsoft.EnterpriseCloud.Monitoring.MicrosoftMonitoringAgent\<version>\Status\__
C:\Program Files\Microsoft RDInfra\AgentInstall.txt__
C:\Program Files\Microsoft RDInfra\GenevaInstall.txt__
C:\Program Files\Microsoft RDInfra\SXSStackInstall.txt__
C:\Program Files\Microsoft RDInfra\WVDAgentManagerInstall.txt (when executed on Windows 7 hosts)__
C:\Windows\debug\NetSetup.log__
C:\Windows\Temp\ScriptLog.log__
C:\WindowsAzure\Logs\WaAppAgent.log__
C:\WindowsAzure\Logs\MonitoringAgent.log__
C:\WindowsAzure\Logs\Plugins\ folder with all subfolders__

2. Geneva Scheduled Task information

3. Local group membership information:
Remote Desktop Users

4. Registry keys:
HKEY_CURRENT_USER\SOFTWARE\Microsoft\RdClientRadc
HKEY_CURRENT_USER\SOFTWARE\Microsoft\Remote Desktop
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Azure\DSC
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RDAgentBootLoader
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RDInfraAgent
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RDMonitoringAgent
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WVDAgentManager (when executed on Windows 7 hosts)
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Terminal Server Client
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RdAgent
​​​​​​​HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RDAgentBootLoader
​​​​​​​HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WVDAgent (when executed on Windows 7 hosts)
​​​​​​​HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WVDAgentManager (when executed on Windows 7 hosts)
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TermService
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UmRdpService
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinRM​​

5. Event Logs:
Application
Microsoft-Windows-DSC/Operational
Microsoft-Windows-PowerShell/Operational
Microsoft-Windows-RemoteDesktopServices
Microsoft-Windows-RemoteDesktopServices-RdpCoreCDV/Admin
Microsoft-Windows-RemoteDesktopServices-RdpCoreCDV/Operational
Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Admin
Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational
Microsoft-Windows-TerminalServices-LocalSessionManager/Admin
Microsoft-Windows-TerminalServices-LocalSessionManager/Operational
Microsoft-Windows-TerminalServices-PnPDevices/Admin
Microsoft-Windows-TerminalServices-PnPDevices/Operational
Microsoft-Windows-TerminalServices-RemoteConnectionManager/Admin
Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational
Microsoft-Windows-WinRM/Operational
Microsoft-WindowsAzure-Diagnostics/Bootstrapper
Microsoft-WindowsAzure-Diagnostics/GuestAgent
Microsoft-WindowsAzure-Diagnostics/Heartbeat
Microsoft-WindowsAzure-Diagnostics/Runtime
Microsoft-WindowsAzure-Status/GuestAgent
Microsoft-WindowsAzure-Status/Plugins
Security
System

6. "gpresult /h" and "gpresult /r /v" output

7. "fltmc filters" output

8. Details of the running processes and services

9. Networking information (firewall rules, ipconfig /all, profiles, netstat -anob, proxy settings)

10. Qwinsta output

11. PowerShell version

12. Get-Hotfix output

13. Get-DscConfiguration and Get-DscConfigurationStatus output

14. File versions of the currently running binaries

15. File information about the WVD desktop client binaries ("msrdc.exe" and "msrdcw.exe")

16. File versions of key binaries:
Windows\System32\*.dll
Windows\System32\*.exe
Windows\System32\*.sys
Windows\SysWOW64\*.dll
Windows\SysWOW64\*.exe
Windows\System32\drivers\*.sys

17. Basic system information

18. Msinfo32 output

19. WinRM configuration information

20. Basic Diagnostics information (see below for more details)

21. When used together with the "-Certificate" command line parameter, the following data are also collected (if present):
Certificate My store information
Certificate thumbprint information
Event Logs:
Microsoft-Windows-CAPI2/Operational

22. When used together with the "-ClientAutoTrace" command line parameter, the following data are also collected (if present):
The content of the "C:\Users\%username%\AppData\Local\Temp\DiagOutputDir\RdClientAutoTrace" folder (available on devices used as source clients to connect to WVD hosts), containing:
WVD remote desktop client connection ETL traces
WVD remote desktop client application ETL traces
WVD remote desktop client upgrade log (MSI.log)

23. When used together with the "-MonTables" command line parameter, the following steps are also performed:
Convert existing .tsf files on WVD hosts from under "C:\Windows\System32\config\systemprofile\AppData\Roaming\Microsoft\Monitoring\Tables" into .csv files
Collect the resulting .csv files

24. When used together with the "-MSRA" command line parameter, the following data are also collected (if present):
Membership information for the following groups:
- Distributed COM Users
- Offer Remote Assistance Helpers
Event Logs:
Microsoft-Windows-RemoteAssistance/Admin
Microsoft-Windows-RemoteAssistance/Operational

25. When used together with the "-Profile" command line parameter, the following data are also collected (if present):
- FSLogix log files:
C:\ProgramData\FSLogix\Logs
- Registry keys:
HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office
HKEY_CURRENT_USER\SOFTWARE\Microsoft\OneDrive
HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Office
HKEY_LOCAL_MACHINE\SOFTWARE\FSLogix
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Search
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\FSLogix
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes
- Event Logs:
Microsoft-Windows-SMBClient/Connectivity
Microsoft-Windows-SMBClient/Operational
Microsoft-Windows-SMBClient/Security
Microsoft-Windows-SMBServer/Connectivity
Microsoft-Windows-SMBServer/Operational
Microsoft-Windows-SMBServer/Security
Microsoft-Windows-User Profile Service/Operational
Microsoft-Windows-VHDMP/Operational
- FSLogix tool output:
frx list-redirects
frx list-rules

26. When used together with the "-Teams" command line parameter and ran within the session of an affected user that has already pressed Ctrl+Alt+Shift+1 within Teams to generate additioanl diagnostics logs, the following data are also collected:
- Teams Logs:
%appdata%\Microsoft\Teams\logs.txt
%userprofile%\Downloads\MSTeams Diagnostics Log DATE_TIME.txt
%userprofile%\Downloads\MSTeams Diagnostics Log DATE_TIME_calling.txt
%userprofile%\Downloads\MSTeams Diagnostics Log DATE_TIME_cdl.txt
%userprofile%\Downloads\MSTeams Diagnostics Log DATE_TIME_cdlWorker.txt
%userprofile%\Downloads\MSTeams Diagnostics Log DATE_TIME_chatListData.txt
%userprofile%\Downloads\MSTeams Diagnostics Log DATE_TIME_sync.txt
%userprofile%\Downloads\MSTeams Diagnostics Log DATE_TIME_vdi_partner.txt
- Registry keys:
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Teams
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RDWebRTCSvc
- DxDiag output in .txt format with no WHQL check



### WVD-Diag

WVD-Collect also performs basic diagnostics for some common known issues. You can run the script also in DiagOnly mode, by specifying the "-DiagOnly" command line parameter.
With this parameter, the script will skip all data collection and run only the basic diagnostics steps.
Important: To run diagnostics also for a specific scenario (like Profile troubleshooting), the corresponding command line parameter needs to be present too.
E.g.: 
	"WVD-Collect -DiagOnly" will run only the default diagnostics
	"WVD-Collect -Profile -DiagOnly" will run the default diagnostics + "Profile"-specific diagnostics

Currently the following checks are performed:

Default diagnostics:
- Check the status of key services (RdAgent, RDAgentBootLoader, WVDAgent (Win7), WVDAgentManager (Win7), TermService, SessionEnv, UmRdpService, AppReadiness, AppXSvc, WinRM)
- Check the availability and value of the reg key: 'fEnableWinStation' for host not available scenarios
- Check the availability and value of the reg key: 'DeleteUserAppContainersOnLogoff' for firewall rules bloating scenarios
- Check the availability and value of the reg key: 'SessionDirectoryListener' to better identify the WVD listener currently in use
- Check the availability and value of the reg key responsible for the 'SSL Cipher Suite Order' policy for scenarios where users cannot connect with a message containing 'security package error' or 'no available resources'
- Check WinRM configuration / requirements
​​​​​​​- Presence of "WinRMRemoteWMIUsers__" group
- IPv4Filter and IPv6Filter values
- Presence of firewall rules for ports 5985 and 5986

Profile specific diagnostics (when ran together with the "-Profile" command line paramenter):
- Check the status of key services (frxsvc, frxdrv, frxccds, OneDrive Updater Service)

The script generates a *_WVD-Diag.txt output file with the results of the above checks.


### Tool Owner: 
Robert Klemencz @ Microsoft Customer Service and Support
If you have any feedback or bugs to report, please, reach out to me (Robert Klemencz) at robert.klemencz@microsoft.com


## DISCLAIMER:
THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


