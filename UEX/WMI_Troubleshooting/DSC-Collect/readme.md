## DSC-Collect

Description:
​​​​​​​​​​​PowerShell script to simplify the collection of DSC troubleshooting data.__

The script collects the following:__

The Get-DscLocalConfigurationManager output__
The details of the installed PowerShell version__
The list of installed certificates in the Personal store of the Local Machine__
The output of ipconfig /all__
The content of the folder C:\Windows\System32\Configuration__
The Get-Module output__
The Get-DscResource output__
The Get-DscConfiguration output__
The Get-DscConfigurationStatus output__
The content of the folder C:\WindowsAzure\Logs\Plugins\Microsoft.Powershell.DSC (Azure VMs only)__
The content of the folder C:\Packages\Plugins\Microsoft.Powershell.DSC (Azure VMs only)__
The Windows Virtual Desktop log C:\Windows\Temp\ScriptLog.log​__
The export of the registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Azure\DSC (Azure VMs only)__
The Windows Azure Guest Agent log C:\WindowsAzure\Logs\WaAppAgent.log (Azure VMs only)​__
The content of the folder C:\Program Files\WindowsPowerShell\DscService\Configuration (Pull Server only)__
The version of the file Microsoft.Powershell.DesiredStateConfiguration.Service.dll__
A copy of the file C:\Program Files\WindowsPowerShell\DscService\RegistrationKeys.txt (Pull Server only)__
A copy of the file C:\inetpub\PSDSCPullServer\web.config (Pull Server only)__
A copy of the file C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config​__
A copy of the file C:\Windows\System32\inetsrv\Config\ApplicationHost.config (Pull Server only)__
A copy of the file C:\Program Files\WindowsPowerShell\DscService\Devices.edb (Pull Server only)__
The list of the IIS worker processes__
The web.config and the last log for each website__
The last HTTPERR.LOG file__
The export of the registry key HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\HTTP__
The export of the Application, System, WMI-Activity, DSC, DSC PullServer, DSC FileDownloadManager, ManagementOdataService, PowerShell, Windows Remote Management__
The output of the command netsh winhttp show proxy​ and nslookup wpad​__
The details of the running processes__
The details of the services__
The list of the installed hotfixes__

Customer-friendly action plan:
Save the attached file DSC-Collect.ps1.txt on a folder on the C: driver as DSC-Collect.ps1__
Open an administrative PowerShell prompt and go to that folder__
Execute .\DSC-Collect.ps1__
The script will create a subfolder with the results, please compress the folder and upload it into the workspace__
If the script does not start, complaining about execution policy, then use Set-ExecutionPolicy -ExecutionPolicy RemoteSigned to change it.​__


### Tool Owner: Gianni Bragante