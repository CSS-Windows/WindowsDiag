# GetLogs
PowerShell based script set for collecting basic diag data - like SDP - from a Windows based computer

## Purpose
This script collects data from one or more computers, local or remote

EXAMPLE data collection local

	`GetLogs.ps1`  # simply run it without any parameter to collect all data with defaults

EXAMPLE data collection remote

	`GetLogs.ps1 -ComputerName` # run the script data collection on specific computer

EXAMPLE data analysis

    To access the infos stored in xml files run in PowerShell window the following sample
    `$Inf= Import-CliXml -path "C:\MS_DATA\190221-121553\H16N1-GeneralInfoPerHost.xml"`
    `$Inf # lists all Members`
    `$Inf.Hotfix # Lists installed Hotfixes for example`
