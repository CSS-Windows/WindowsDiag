# SYNOPSIS GetLogs.ps1
    Script Name:  GetLogs.ps1	
    Purpose:      gather data from Windows Failover Cluster Nodes (default 3 Month back)
    Version:      1.3
    Last Update:  20th April 2020
    Author:       Josef Holzer 
    Email-Alias:  josefh


## DESCRIPTION
	This script collects data from one or more computers
	If the script runs on a cluster node with cluster service running, it collects data from all cluster nodes


## USAGE
	Simply copy paste GetLogs.ps1 to one of the Failover Cluster Nodes and run as admin.
	No Parameters are necessary. If you want you could change parameters see script for details.


## DOWNLOAD
	Click on GetLogs.zip - on the right side of the webpage a Download button shows up


## KNOWN-ISSUES
	- Script can not be run, when you use RemoteSigned as ExecutionPolicy # Get-ExecutionPolicy #reports your current ExecutionPolicy
		You get the following error message:
		PS C:\temp> .\GetLogs.ps1
		.\GetLogs.ps1 : File C:\temp\GetLogs.ps1 cannot be loaded. The file C:\temp\GetLogs.ps1 is not digitally signed.
		You cannot run this script on the current system. For more information about running scripts and setting execution policy, 
		see about_Execution_Policies at https:/go.microsoft.com/fwlink/?LinkID=135170.
		At line:1 char:1
		+ .\GetLogs.ps1
		+ ~~~~~~~~~~~~~
		    + CategoryInfo          : SecurityError: (:) [], PSSecurityException
		    + FullyQualifiedErrorId : UnauthorizedAccess

	  Solution:
		- Open a Powershell Window and run 
		Unblock-File .\GetLogs.ps1

	
## Whats New in this Version 1.3
  - Added function CopyFilesInReportsFoldersToLocalComputer -ComputerNames $ComputerNames 
    From each Node additionally collecting all files in "$Env:SystemRoot\Cluster\Reports" (e.g. c:\windows\cluster\reports) to Local MS_DATA Folder 

  - By default collect more "Event Logs"
    - *CSVFS*, *Hyper-V*, "*Smb*", "*spaces*"

    
## PARAMETER 

PARAMETER ComputerNames
	Define on which computers you want to run the script. Default is local host

PARAMETER LogPathLocal
	Path where we store the data. Default is SystemDrive\MS_DATA\DataTime; e.g. C:\MS_DATA\180925-101214

PARAMETER HoursBack
	How much hours should we look back in the event data and collect them. Test Default =1 
	
PARAMETER EventLogNames
	Define the Eventlogs you want to gather; wildcard * is allowed
	Sample: -EventLogNames "System", "Application", "*CSVFS*", "*Smb*", "*winrm*", "*wmi*", "*spaces*" 
    Alternatively define this in the parameter section on top of this script


## EXAMPLE

EXAMPLE
	GetLogs.ps1  # simply run it without any parameter to collect all data with defaults

EXAMPLE 
	GetLogs.ps1 -ComputerName H16N4 # run the script data collection on specific computer

EXAMPLE
    To access the Info´s stored in xml files, do what is done in the following sample
    $Inf= Import-CliXml -path "C:\MS_DATA\190221-121553\H16N1-GeneralInfoPerHost.xml"
    $Inf # lists all Members
    $Inf.Hotfix # Lists installed Hotfixes for example