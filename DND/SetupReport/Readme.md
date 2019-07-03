# Readme SetupReport

This package contains 3 cmd/txt files. Please review the instructions below for next steps.

## Instructions
1.	Save ALL 3 files to the SAME folder on the Windows drive. 
2.	Obsolete/done: Change the name of the setupreport.cmd.txt to setupreport.cmd (may need to enable show extensions to see file extensions). DO NOT change the names of the other files. 
3.	Double click on the setupreport.cmd file to run. It will ask for elevation (unless UAC is disabled and then it will auto elevate). 
4.	A standard End User License Agreement will be displayed which you have to agree to before continuing. 
5.	It will take 10 - 20 minutes to run. 
6.	Note that it is normal for some errors to be displayed as some files or registry entries will not exist on some systems. 
7.	All files will be saved in 'C:\setup_report_computername' folder. 
8.	When the batch completes it will return you to a C prompt. You can zip up (right click and send to compressed folder) the 'C:\setup_report_computername' folder and upload to the workspace provided below. You will need to manually remove the setup_report_computername folder after providing the data.

Workspace Info: This is a hyper-link and you need to be logged in with any account to upload and with specific account for the case to download.

Workspace:


## About this Script
It is composed of 3 files:
1.	SetupReport.cmd - Batch file that does most of the work. It calls the included VBScript files, Windows built in commands and runs some simple PowerShell commands to gather additional information. 
2.	GetEvents.txt - VBScript file that saves specific event logs as txt and csv files. 
3.	SummaryRep.txt - VBScript file that generates a single text file summary of the system much like MSInfo32.

## What’s gathered?
A wide variety of data is gathered including the following broad categories (when available on the system):

•	Windows Setup Information including contents of ~Windows.~BT folder and the Windows Panther logs. 

•	Windows Update Information including Windows Update history, logs and SCCM logs. 

•	Windows servicing information including CBS logs, setupapi logs, servicing registry hives and WinSxS info. 

•	Info on Windows files including dll and exe files and listing of files in temp folders. 

•	Various keys from the registry including services, network info (including AD and IP address info), activation and drive info.

•	No data files are copied, and no changes are made to the configuration of the system.


If there are any questions or concerns about the data collected please let us know. You can also review the contents of the report folder before zipping it and uploading it.
