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