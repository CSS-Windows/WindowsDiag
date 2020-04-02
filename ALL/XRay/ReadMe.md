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
Syntax: `LogToFile <info>`  
Do not write anything to console, do not show any pop-ups etc.  

3. `ReportIssue`
Diagnostic functions can use this to report the issue they  have identified  
Syntax: `ReportIssue <issue details>`  
Provide a message containing details of the issue and how to resolve it. If possible, also provide links to public KB articles/documents etc. This message will be reported to end-user.  
 
Skeleton diagnostic function:
```
# Component: 
# 
# Checks for: Details of the issue this function checks for 
#
# If diagnostic function identifies an issue, it should call ReportIssue and provide detailed error message (issue details and
# instructions on how to resolve, link to public KBs etc.)
# Returns $null if no issue found or detailed error message string to be shown to end user (issue details and
# instructions on how to resolve, link to public KBs etc.)
# 
# Parameter(s)
# $online Boolean, Input
# $true if running on the actual computer
# $false not running on the actual computer, diagnostics needs to run against offline data 
# 
# Returns 
# $ReturnCode_Success if diagnostic function ran successfully
# $ReturnCode_Failed  if diagnostic function failed to run successfully
# $ReturnCode_Skipped if diagnostic function chose not to run (for example if it cannot run offline)
function component_issue
{
    param(
        [Parameter(Mandatory=$true,
        Position=0)]
        [Boolean]
        $online
    )
    
    # Look for the issue
    try {
        if($online) {
            # your online diagnostic code here
            ReportIssue $issue
        }
        else {
            # your offline diagnostic code here
            # or 
            # return [ReturnCode]::Skipped
        }
    }
    catch {
        LogToFile $Error[0].Exception
        continue
    }

    return [ReturnCode]::Success
}
```
