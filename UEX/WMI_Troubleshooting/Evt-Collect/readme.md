## Evt-Collect

Description:
​​​​​​​​​​​​​​​​​​​​PowerShell script to simplify the collection of data related to EventLog troubleshooting and make our action plans easier.​

The script collects the following:

The output of IPCONFIG /all
The GPRESULT output
The list of WMI performance classes
The export of the registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger
The export of the registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels
The export of the registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers
The export of the registry key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog
The export of the registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog
The export of the Application, EventTracing and System logs
The details of the Application, System and Security logs
The permissions on the folder C:\Windows\System32\winevt\Logs
The permissions and the content of the folder C:\Windows\System32\LogFiles\WMI\RtBackup​
The list of the files in %windir%\System32\winevt\Logs
The output of the command logman -ets query "EventLog-Application"
The output of the command logman -ets query "EventLog-System"
The output of the command logman query providers
The output of the command logman query -ets
The output of the command wevtutil el
The output of the command auditpol /get /category:*
The list of the installed hotfixes​
The system information
Customer-friendly action plan:

Save the attached file Evt-Collect.ps1.txt on a folder on the C: driver as Evt-Collect.ps1
Open an administrative PowerShell prompt and go to that folder
Execute .\Evt-Collect.ps1
The script will create a subfolder with the results, please compress the folder and upload it into the workspace
If the script does not start, complaining about execution policy, then use Set-ExecutionPolicy -ExecutionPolicy RemoteSigned to change it.​


### Tool Owner: Gianni Bragante