# xray 
*tdimli, March 2020*

#### Script to identify and help resolve known issues

We have known issues documented in multiple places, xray aims to automate the detection of these known issues and reduce down time

*Please contact tdimli if you can help create scripts to identify and resolve even more issues.  
Or just report known issues and how to identify them to us and we can create the script.*

#### Usage:
```
.\xray.ps1 [-Area: <area(s)>] | [-Component: <component(s)>] [-DataPath <path to save files created>]
        Specify either Area or Component to check for (they are mutually exclusive).
                Area:all or Area:* checks all areas
                When area(s) specified, all components within the specified area(s) are checked
                Example: .\xray.ps1 -Component dhcpsrv dnssrv
```

#### Guidance for diagnostic function developers:
 
xray will only show messages when it's useful and actionable for the end-user.
Diagnostic functions should not write anything to console, should not show any pop-ups etc.
 
Use try/catch block(s) where necessary to avoid exceptions and unwanted error messages to console.  
Note: The diagnostic functions are called with "$ErrorActionPreference set to "Stop"

There are functions which are provided by the main script block for use by diagnostic functions:

1. `MakeFileName`
When creating any files, name should be prefixed with `"xray_<hostname>_"` and suffixed with timestamp.
MakeFileName can wrap your chosen filename with these and also prepends it with current data path being used.  
Syntax: `MakeFileName "<name>" "<extension>"`  
Example: `MakeFileName "log" "txt"` will return a string that contains "xray_mycomputer_log_20200330143000.txt" if run
on 30th March 2020 at 14:30:00 on a computer with name "mycomputer"  
The timestamp suffix stays the same for the duration of xray execution.  
This ensures that all files created during the same run of xray have the same timestamp suffix

2. `LogToFile`
Use LogToFile function to log internal diagnostic info pertaining to execution details  
Absolutely no data/no PII should be logged here  
Syntax: `LogToFile <string>`  
Do not write anything to console, do not show any pop-ups etc.  

3. `ReportFailure`
Use to report a failure when a diagnostic function has failed to run  
Syntax: `ReportFailure`
Diagnostic functions can use this for managed/handled failures  
When a diagnostic function throws an unhandled exception/error, then a failure is automatically caught and logged by main script block  
 
Diagnostic functions should:  
Return `$null` if no issue is found  
Return a message containing details of the issue and how to resolve it if an issue is found. They should also provide links to public KB articles/documents etc. where available. This message will be shown to end-user and logged by main script-block  
 
Skeleton diagnostic function:
```
# Component: 
# 
# Checks for: Details of the issue this function checks for 
# 
# Returns $null if no issue found or detailed error message string to be shown to end user (issue details and
# instructions on how to resolve, link to public KBs etc.)
function component_issue
{
    $returnMsg = $null

    # Look for the issue
    try {
        # your code here
    }
    catch {
        ReportFailure
        LogToFile $Error[0].Exception
        continue
    }

    return $returnMsg
}
```
