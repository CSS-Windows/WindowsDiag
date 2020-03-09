## DSC-Collect

Description:
​​​​​​​​​​​PowerShell script to simplify the collection of DSC troubleshooting data.

The script collects the following:

The Get-DscLocalConfigurationManager output\
The details of the installed PowerShell version\
The list of installed certificates in the Personal store of the Local Machine\
The output of ipconfig /all
The content of the folder C:\Windows\System32\Configuration
The Get-Module output
The Get-DscResource output
The Get-DscConfiguration output
The Get-DscConfigurationStatus output
The content of the folder C:\WindowsAzure\Logs\Plugins\Microsoft.Powershell.DSC (Azure VMs only)
The content of the folder C:\Packages\Plugins\Microsoft.Powershell.DSC (Azure VMs only)
The Windows Virtual Desktop log C:\Windows\Temp\ScriptLog.log​
The export of the registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Azure\DSC (Azure VMs only)
The Windows Azure Guest Agent log C:\WindowsAzure\Logs\WaAppAgent.log (Azure VMs only)​
The content of the folder C:\Program Files\WindowsPowerShell\DscService\Configuration (Pull Server only)
The version of the file Microsoft.Powershell.DesiredStateConfiguration.Service.dll
A copy of the file C:\Program Files\WindowsPowerShell\DscService\RegistrationKeys.txt (Pull Server only)
A copy of the file C:\inetpub\PSDSCPullServer\web.config (Pull Server only)
A copy of the file C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config​
A copy of the file C:\Windows\System32\inetsrv\Config\ApplicationHost.config (Pull Server only)
A copy of the file C:\Program Files\WindowsPowerShell\DscService\Devices.edb (Pull Server only)
The list of the IIS worker processes
The web.config and the last log for each website
The last HTTPERR.LOG file
The export of the registry key HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\HTTP
The export of the Application, System, WMI-Activity, DSC, DSC PullServer, DSC FileDownloadManager, ManagementOdataService, PowerShell, Windows Remote Management
The output of the command netsh winhttp show proxy​ and nslookup wpad​
The details of the running processes
The details of the services
The list of the installed hotfixes

Customer-friendly action plan:
Save the attached file DSC-Collect.ps1.txt on a folder on the C: driver as DSC-Collect.ps1
Open an administrative PowerShell prompt and go to that folder
Execute .\DSC-Collect.ps1
The script will create a subfolder with the results, please compress the folder and upload it into the workspace
If the script does not start, complaining about execution policy, then use Set-ExecutionPolicy -ExecutionPolicy RemoteSigned to change it.​


### Tool Owner: Gianni Bragante