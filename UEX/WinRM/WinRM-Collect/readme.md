## WinRM-Collect

Description:
​​​​​​​​​​​​​​​​​​​​​​​​​​PowerShell script to simplify the collection of WinRM and EventLog Forwarding troubleshooting data and make our action plans easier. 

The script collects:\
The configuration of WinRM and all the plugins\
The dump of the svchost.exe process hosting the WinRM service\
The dump of the svchost.exe process hosting the WecSvc service, if it is not the same as WinRM\
The dump of all wsmprovhost.exe processes\
The dump of sme.exe (Windows Admin Center service)\
The configuration and the runtime status of the configured subscriptions\
The details of the groups Event Log Readers and WinRMRemoteWMIUsers__\
The output of the Get-NetConnectionProfile​ command\
The firewall rules\
The netstat -anob output\
The output of ipconfig /all\
The files hosts and lmhosts\
The output of the command netsh winhttp show proxy and nslookup wpad\
The results of the SPN lookups for HTTP and WSMAN, in the domain and in the forest\
The IIS configuration\
The latest httperr.log file\
The output of Get-Hotifx\
The output of Get-WSManCredSSP​​\
The gpresult output in text and html format\
The export of the registry keys HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinRM and HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\
The export of the registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\
The export of the registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\EventCollector\
The export of the registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\EventForwarding\
The export of the registry key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog​\
The export of the registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\
The export of the registry keys HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography and HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography\
The export of the registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\
The export of the registry key HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\HTTP\
The export of the registry key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentials\
The export of the registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\
The export of the registry key ​HKEY_USERS\S-1-5-20\Control Panel\International (Network Service international settings)\
The export of the registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ServerManager\ServicingStorage\ServerComponentCache\
The export of the event logs CAPI2, Windows Remote Management, EventCollector, EventForwarding-Plugin, PowerShell/Operational, Group Policy/Operational, Windows PowerShell, ServerManagementExperience, Kernel-EventTracing, Application and System\
The channel configuration, the first and the last EventRecordID for the logs System, Security, Application and FordwardedEvents\
The output of the commands netsh http settings, netsh http urlacl, netsh http servicestate and netsh http show iplisten\
The output of Certutil -verifystore -v for MY, CA and ROOT and the list of installed certificate in .tsv format\
The details of the running processes and services\
The ServerManager configuration file\
The system information\
The WinRM-Diag​ output

Customer-friendly action plan:\
Retrieve the file WinRM-Collect.zip from the workspace\
Extract the archive WinRM-Collect.zip in a folder, such as c:\WinRM-Collect\
Open an administrative PowerShell prompt and go to that folder\
Execute .\WinRM-Collect.ps1\
The script will create a subfolder with the results, please compress the folder and upload it into the workspace\
If the script does not start, complaining about execution policy, then use Set-ExecutionPolicy -ExecutionPolicy RemoteSigned to change it.


### Tool Owner: Gianni Bragante