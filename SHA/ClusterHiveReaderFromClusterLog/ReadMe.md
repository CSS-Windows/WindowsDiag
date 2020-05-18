# SYNOPSIS ClusterHiveReaderFromClusterLog.ps1
    Script Name:  ClusterHiveReaderFromClusterLog.ps1    	
    Version:      1.3
    Last Update:  12 March 2020
    Author:       Josef Holzer 

## DESCRIPTION
    In 2016 and later we store all Configuration Info on top of the Cluster Log in csv format
    The script reads the header of the cluster.log file and creates the following files:    
    ClusterLogName-ClusConfig-All.txt             # Contains all Info Exported as AllObjects  fl *
    ClusterLogName-ClusConfig-All.xml             # Contains all Info as Powershell Objects
    ClusterLogName-ClusConfig-All-Overview.txt    # Contains most important info as | ft Prop1, Prop2...
    ClusterLogName-ClusConfig-ProcessIDs.txt      # All PIDs of Processes that wrote to cluster log (only if -FindPIDs was passed)

    
    HowTo Use it the simple way: 
    - Copy ClusterHiveReaderFromClusterLog.ps1 to your path where you have one or multiple Cluster Logs (2016 or later)
    - Run it without any parameters


## PARAMETER

PARAMETER FindPIDs
    - switch parameter (default is $False) so by default we don´t search for PIDs in Cluster Logs    
    - If you called the script with -FindPIDs it will find ProcessID´s that wrote into ClusterLog
    - it will save the results in ClusterLogName-ClusConfig-ProcessIDs.txt     
    - if we have a valid path to Parameter: FileWithProcessInfoPathFull it will resolve PIDs to Process Names
      this works on all cluster logs
    - It can take a couple of mins 

	
PARAMETER  Path
    - $PDW (default)  # $PWD is the current path of the Powershell window
    - enter the full name (Path\Filename) to a Cluster.Log file or 
    - enter the path to a couple of Cluster.log files
      the script will take the first one which contains config Info (2016 or later)    	


PARAMETER FileWithProcessInfoPathFull
    enter the full name (Path\Filename) to the file that contains Process Information
    if you collected the data with GetLogs.ps1 this would be NodeName-GeneralInfoPerHost.xml
    or you collected simply with Get-Process | Export-CliXml -path c:\temp\NodeName-ProcessInfo.xml
    The script will take both formats


## EXAMPLE
    
EXAMPLE     
    ClusterHiveReaderFromClusterLog.ps1    
    - if you have several cluster logs in c:\logs and copy the script to this folder you simply run the script with no parameters
    - it will then take the first (2016 or later ) cluster.log that contains config data and process it

EXAMPLE    
    ClusterHiveReaderFromClusterLog.ps1 -FindPIDs -Path "C:\ClusterLog\H19N1.H19Corp.com_cluster.log" -FileWithProcessInfoPathFull "C:\ClusterLog\H19N1-GeneralInfoPerHost.xml" 
    - it will read cluster configuration and write it down into file names mentioned above including *ProcessIDs
