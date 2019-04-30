# ESR - Scripts for collecting data when investigating Enterprise State Roaming (ESR) scenarios

Provided are Enterprise State Roaming (ESR) scripts that enable tracing, debug logging and collect data that can be used to investigate Enterprise State Roaming scenarios (aka ESR) and related component scenarios.

Tips for data collection:
Try to collect data using this script from 2 client machines at the same time when attempting to sync changes using ESR from 1 machine to another.
Please note down the time of attempt (along with the time zone) and the change (adding favorite to edge or moving taskbar location) for a more efficient analysis of the data.
 
Steps for enabling tracing and data collection:
1.     Create a directory on the machine where the tracing is going to run - example c:\ms
2.     Copy start-ESR-tracing.txt and stop-ESR-tracing.txt to target and rename the files with .bat extensions - example start-ESR.bat and stop-ESR-script.bat
3.     From an elevated admin command prompt, navigate to the c:\ms directory and run Start-ESR-Tracing.bat to start the tracing.
4.     The customer will be presented with a legal disclaimer and requested to select Y to allow the script to run.
5.     Create the issue that you are investigating.
 
Steps for stopping tracing and data collection:
1.     From an elevated admin command prompt, navigate to the c:\ms directory and run Stop-ESR-Tracing.bat to stop the tracing.
2.     The customer will be presented with a legal disclaimer and requested to select Y to allow the scripts to run.
3.     The data will be saved to a subdirectory called "ESRlogs"
4.     Ask the customer to collect and share the ESRlogs folder from all the machines involved in the issue.


## Important "General Data Protection Regulation and Legal" Notes:
The collected data may contain Personally Identifiable Information (PII) and/or sensitive data, such as (but not limited to) IP addresses, PC names, and user names.
Once the tracing and data collection has completed, the data will be saved in a folder on the local hard drive.
This folder is NOT automatically sent to Microsoft.
You can send this folder to Microsoft CSS using a secure file transfer tool - Please discuss this with your support professional and also any concerns you may have.
This tool is provided as it is and neither Microsoft nor the author have any legal responsibility over it.
