# SYNOPSIS ClusterHiveReaderFromClusterLog.ps1
    The script Reads the Header Lines from a Server 2016 or later cluster.log and creates config files
    Script Name:  ClusterHiveReaderFromClusterLog.ps1    	
    Version:      1.1
    Last Update:  12 Feb 2020
    Author:       Josef Holzer 

## DESCRIPTION
    In 2016 and later we store all Configuration Info on top of the Cluster Log in csv format
    The script reads the header of the cluster.log file and creates the following files:    
    ClusterLogName-ClusConfig-All.txt             # Contains all Info Exported as AllObjects  fl *
    ClusterLogName-ClusConfig-All.xml             # Contains all Info as Powershell Objects
    ClusterLogName-ClusConfig-All-Overview.txt    # Contains most important info as | ft Prop1, Prop2...
    ClusterLogName-ClusConfig-ProcessIDs.txt      # All PIDs of Processes that wrote to cluster log

EXAMPLE 1
     ClusterHiveReaderFromClusterLog.ps1    
    - if you have several cluster logs in c:\logs and copy the script to this folder
       you simply run the script with no parameters
    - it will then take the first (2016 or later ) 
      cluster.log that contains config data and processes it

EXAMPLE 2
    ClusterHiveReaderFromClusterLog.ps1 -Path "C:\ClusterLog\H19N1.H19Corp.com_cluster.log" `
    -FileWithProcessInfoPathFull "C:\ClusterLog\H19N1-GeneralInfoPerHost.xml" -FindPIDs $True
    
    ...it will read cluster configuration and write it down into file names mentioned above including *ProcessIDs

