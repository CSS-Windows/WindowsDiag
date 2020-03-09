## Perf-Collect

Description:
​​​​​​​​​​​​​​​​​​​​PowerShell script to simplify the collection of Performance Counters data and make our action plans easier.​

The script collects the following:

A csv file with the summary of all V1 counters on the system
The files perf*.dat from c::\windows\system32
The list of WMI performance classes
The value HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib\CurrentLanguage\Counter in Counter.txt
The value HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib\CurrentLanguage\Help in Help.txt
The export of the registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services
The export of the registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib
The export of the registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup
The output of typeperf.exe -qx for 32 and 64 bits counters
The export of the Application and System logs
The systsem information
Customer-friendly action plan:

Save the attached file Perf-Collect.ps1.txt on a folder on the C: driver as Perf-Collect.ps1
Open an administrative PowerShell prompt and go to that folder
Execute ./Perf-Collect.ps1
The script will create a subfolder with the results, please compress the folder and upload it into the workspace
If the script does not start, complaining about execution policy, then use Set-ExecutionPolicy -ExecutionPolicy RemoteSigned to change it.​


### Tool Owner: Gianni Bragante