# xray 
*tdimli, March 2020*

#### Guidance for diagnostic function developers:
 
xray aims to resolve known issues with minimal delay and effort.
xray relies on diagnostic functions to achieve this. 

*Please contact tdimli if you can help create diagnostic functions to identify and resolve even more issues.  
You can write it yourself or you can just share issue details and how to identify it with us and we can code it for you.*

##### When writing a diagnostic function...

Target a single issue (the issue should have a corresponding internal or public KB). And target issues that are known to cause incoming critsits and support cases.
name of the function is in format: <tech area>_<component>_KB<issue id>

Try and use (no pun intended) try/catch block(s) where necessary to avoid exceptions and unwanted error messages to console.  
`Note:` xray calls the diagnostic functions with "$ErrorActionPreference set to "Stop" to catch/handle any unhandled exceptions.

Creating data files is fine when it's required for the diagnostic being run.
Filename should be generated using API provided (MakeFileName) which will include a full path. 
This will also ensure that all files are created in the same directory (provided by end user when xray is run).
If the targeted issue is not found, then any file created should be deleted (we have TSS for data collection).

Your diagnostic function can have helper function(s) if it's necessary. 
Helper function(s) can be defined in your #region after diagnostic function. They are for use by your diagnostic function only. 
Using helper functions from other diagnostics is prohibited (here today, gone tomorrow as xray is dynamic!)

Diagnostic functions take one input parameter: bool $offline 
$False if running on the actual computer being examined
$True  if not running on the actual computer, diagnostics needs to run against offline TSS data 

Do not write anything to console, do not show any pop-ups etc. Instead, use provided APIs (listed below) to report issues and log to logfile (execution details, not data).

Diagnostic functions should return a status code:
$ReturnCode_Success if diagnostic function ran successfully
$ReturnCode_Failed  if diagnostic function failed to run successfully
$ReturnCode_Skipped if diagnostic function chose not to run (for example if it cannot run offline and offline parameter was specified)

A starter skeleton diagnostic function is provided below. 
You might also find that reviewing existing diagnostic functions can be inspirational.

##### Functions (APIs) provided by xray for use by diagnostic functions:

1. `MakeFileName`
When creating any files, name should be prefixed with `"xray_<datetime>_"` and suffixed with <hostname>.
MakeFileName wraps your chosen filename with these and also prepends it with current data path being used.  
Syntax: `MakeFileName "<name>" "<extension>"`  
Example: `MakeFileName "dhcpexport" "xml"` returns "C:\MS_DATA\xray_dhcpexport_200421-211747_tdimli-tp.xml"
The timestamp suffix stays the same for the duration of xray execution.  
This ensures that all files created during the same run of xray have the same timestamp suffix

2. `LogToFile`
Use LogToFile function to log internal diagnostic info pertaining to execution details  
Absolutely no data/no PII should be logged here  
Syntax: `LogToFile <info>`  

3. `ReportIssue`
Diagnostic functions can use this to report the issue they  have identified  
Syntax: `ReportIssue <issue details> <diagnostic details> <issue type>`
Issue details: Provide a message containing details of the issue and how to resolve it. If possible, also provide links to public KB articles/documents etc. This message will be reported to end-user.
Issue details parameter is normally multiline string and contains a token: <xray!diag>
diagnostic details: This token will be replaced with the contents of <diagnostic details> parameter before being presented user. This allows us to point the faulty component/config etc. to user, like providing the name of the problem network card.
issue type: This is for future use, diagnostic functions should only report errors: $IssueType_Error

##### Skeleton diagnostic function:
```
#region area_component_KB123456
<#
Wrapped in a region same name as function name
 
Checks for: Details of the issue this function checks for 

If diagnostic function identifies an issue, it should call ReportIssue and provide detailed error message (issue details and
instructions on how to resolve, link to public KBs etc.)
 
Parameter(s)
$offline Boolean, Input
$False if running on the actual computer
$True  if not running on the actual computer, diagnostics needs to run against offline data 

Returns 
$ReturnCode_Success if diagnostic function ran successfully
$ReturnCode_Failed  if diagnostic function failed to run successfully
$ReturnCode_Skipped if diagnostic function chose not to run (for example if it cannot run offline)
#>
function area_component_KB123456
{
    param(
        [Parameter(Mandatory=$true,
        Position=0)]
        [Boolean]
        $offline
    )
    
    # example issue message with <xray!diag> token
    $issueMsg = "
Following network adapter has no connectivity:

<xray!diag>

You might be hitting an issue affecting wired network adapters when network
cable is unplugged.

Resolution:
Please reconnect network cable.
"

    # Look for the issue
    try {
        if($offline) {
            # your offline diagnostic code here
            ReportIssue $issueMsg $diagInfo $IssueType_Error
            # or 
            # return $ReturnCode_Skipped
        }
        else {
            # your online diagnostic code here
            ReportIssue $issueMsg $diagInfo $IssueType_Error
        }
    }
    catch {
        LogToFile $Error[0].Exception
        return $ReturnCode_Failed
    }

    return $ReturnCode_Success
}
# Helper function(s) can be defined here if you must, for use by this diagnostic function only
# Using helper functions from other diagnostics is prohibited (here today, gone tomorrow as xray is dynamic!)
#endregion area_component_KB123456
```
