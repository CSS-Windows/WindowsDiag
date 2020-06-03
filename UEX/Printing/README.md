## Printing related tools


# Print-Collect(A).ps1
Print-collect  tool will help gather all the necessary dumps, events and logs needed to investigate a printing issue.

There are two versions of the tool, a light one print-CollectA (all the logs and events except the dumps) and the complete one.
Print-Collect​ that collect the following :
- The dump of the spooler process
- The dumps of all Printisolationhost processes
- The dump of the splwow64 process
- The list of running processes
- The export of the Application, System event logs
- The export of the PrintService and DeviceSetupmanager (Admin and Operational) event logs
- The export of the Print and CSR registry keys
- The export of the remote printers in the user context
- The export of the setupapi.dev.log
- The spooler service configuration
- The DeviceSetupmanager configuration
- The ipconfig /all and netstat -anob​ output
- The list of installed hotfixes
- The version Print subsystem DLLs​
- The export of the Gpo(s) applied​​​​​
The tool will generate a folder with all these files. 


# Print-trace(-local).bat
The print-Trace​ is sample bat file to run simultaneos traces while reproducing the issue.
It will help get a procmon trace, network trace, ETL trace along with a PSR output with the snapshots of the actions that leads to the error.​

Run the script as admin  (use the Print-trace-local.bat to exclude the network trace). 

Reproduce the issue when it is requested by the script

Press any key when it is done

Wait for the logs to be generated​ in c:\traces 

