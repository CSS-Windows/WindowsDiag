# SYNOPSIS DNS_SUFFIX_RESET.exe
    Tool Name:   DNS_SUFFIX_RESET.exe
    Purpose:     Fix local DNS Suffix List
    Version:     
    Last Update: 27th of Feb 2020
    Author:       
    Contact:     Josef Holzer 
    Email-Alias:  


## DOWNLOAD
	Currently we don´t have a public download - will come soon


## DESCRIPTION	
	When connected to MSFTVPN, I cannot access internal resources like HRWeb, RAMWeb, or others. What should I do?

​​	To be able to reach internal resources like those mentioned above, follow the steps below.
	- To resolve this issue, you'll need to run a script on the device. To get started, double-click on DNS_SUFFIX_RESET.EXE. 
	- You will be prompted to run the script. Select Run.
	- You will be asked for confirmation to proceed. Select Yes.
	- The script will then run to completion. Once the script is complete, press any key to close the window.
	- If you are still unable to access internal resources, please contact the Helpdesk and inform them that you have followed the steps above. 
	  Ask them to escalate this issue. Please DO NOT complete the steps above f​or a second time.


## EXAMPLE
	=============================================================================
	DNS_SUFFIX_RESET.EXE
	=============================================================================
	If you run it a cmd window pops up with the following message
	
	Your current global DNS settings are:
	UseSuffixSearchList : True
	SuffixSearchList    : {corp.microsoft.com}
	UseDevolution       : True
	DevolutionLevel     : 0
	
	This will clear the non-microsoft global DNS suffix list. Are you Sure You Want To Proceed? (y / n): y
	
	Clearing Suffix Search List
	
	Your new global DNS settings are:
	
	UseSuffixSearchList : True
	SuffixSearchList    : {europe.corp.microsoft.com, fritz.box, corp.microsoft.com, windeploy.ntdev.microsoft.com...}
	UseDevolution       : True
	DevolutionLevel     : 0
	
	Press any key to continue...
