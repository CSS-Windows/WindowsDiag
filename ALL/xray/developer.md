# xray 
*tdimli, March 2020*

### Guidance for diagnostic function developers:
 
xray aims to resolve known issues with minimal delay and effort.
xray relies on diagnostic functions to achieve this. 

*Please contact tdimli if you can help create diagnostic functions to identify and resolve even more issues.  
You can write it yourself or you can just share issue details and how to identify it with us and we can code it for you.*

#### What is a diagnostic function?
A diagnostic function is a PowerShell function, that looks for a specific known issue and if detected, reports it to main script using reporting API provided.

#### How to write a diagnostic function
(in no particular order)

1. Target a single issue and ideally target type of issues that are known to cause incoming critsits and support cases. 

2. The targeted issue should have a corresponding KB article. Name your diagnostic function in this format: <tech area>_<component>_KB<id>

3. Try and use (no pun intended) try/catch block(s) where necessary to avoid exceptions and unwanted error messages to console.  
`Note:` xray calls the diagnostic functions with "$ErrorActionPreference set to "Stop" to catch/handle any unhandled exceptions.

4. Please be mindful that xray can be run on various versions of OS and PowerShell versions. Try to acommodate widest variety where you can, by using commands/syntax supported also by older systems where possible. As a suggestion, a diagnostic should ideally be able to run on Windows 8/PowerShell 4.0 would be good (xray can run on Win7SP1/PowerShell 2.0). We can work around this if we must.

5. 3 API calls are provided by main xray script for use by diagnostic functions (MakeFilename, LogWrite and ReportIssue) which are detailed further down below. 

6. If you neeed a WMI object (Win32_OperatingSystem etc.) let us know, we'll rather have them retrieved centrally once rather than multiple diagnostics retrieving the same data. Anything else (function or variable) is off limits (just you can see something doesn't mean you should use it), as they may appear/disappear without notice.

7. Creating data files is fine when it's required for the diagnostic being run.
Filename should be generated using API provided (MakeFilename) which will include a full path. 
This will also ensure that all files are created in the same directory (provided by end user/TSS when xray is run).
If the targeted issue is not found, then any file(s) created should be deleted (we have TSS for data collection).

8. Your diagnostic function can have helper function(s) if it's necessary. 
Helper function(s) can be defined in your #region after diagnostic function. They are for use by your diagnostic function only. 
Using helper functions from other diagnostics (even from your other diagnostics) is prohibited (here today, gone tomorrow as xray is dynamic!)

9. All diagnostic functions define $issueMsg variable at the very beginning, which takes the form of a multi-line formatted string and serves as readme/help as well as defining the message that will be shown to end user and saved in the report if the issue is found. No run-time changes should be made to this variable other than replacing tokens using `[string]::Format()`. 

10. All diagnostic functions also define two further variables -when needed- which are string arrays:
$effectingUpdates: List of updates, which when installed, may lead to this issue
$resolvingUpdates: List of updates, which when installed, resolve this issue
Both arrays have the updates listed in release order, oldest first, i.e. item[0] will contain earliest released update.
Either or both arrays can be omitted (not defined) if the issue is not specific to an update or is not resolved by an update, just pass $null for the corresponding parameter when calling ReportIssue.

11. Diagnostic functions take one input parameter: bool $offline 
$False if running on the actual computer being examined
$True  if not running on the actual computer, diagnostics needs to run against offline TSS data 

12. Diagnostic functions do not write anything to console, do not show any pop-ups etc. Instead, they use provided APIs to report issues and write to logfile (logfile is for execution details, not data).

13. Diagnostic functions should return a status code:
$RETURNCODE_SUCCESS if diagnostic function ran successfully
$RETURNCODE_FAILED  if diagnostic function failed to run successfully
$RETURNCODE_SKIPPED if diagnostic function chose not to run (for example if it cannot run offline and offline parameter was specified)

`Note:` A starter sample diagnostic function is at the end of this document below. You might also find that reviewing existing diagnostic functions can be inspirational.

#### Functions (APIs) provided by xray for use by diagnostic functions:

1. `ReportIssue`
`[void] ReportIssue [String] $issueMsg [Int] $issueType [string[]] $effectingUpdates [string[]] $resolvingUpdates`
Diagnostic functions can use this to report the issue they have identified. 
$issueMsg: This is the message that will be shown to end-user and saved to the report. Provide a message containing details of the issue and how to resolve it. If possible, also try and provide links to public KB articles/documents etc. 
Issue details parameter is normally a multiline/formatted string and may contain one or more tokens ({0}, {1} etc.) to be replaced with machine/issue specific info -like the name of the problem network card- before being passed to ReportIssue`
Please see sample diagnostic function below for more details on how $issueMsg and  specific Info can be merged together.
$issueType: Diagnostic functions should only report errors: `$ISSUETYPE_ERROR`
$effectingUpdates: Array of updates (oldest update first), which when installed, may lead to this issue. Empty if issue is not specific to any updates.
$resolvingUpdates: Array of updates (oldest update first), which when installed, resolve this issue. Empty if issue is not resolved by an update

2. `LogWrite`
`[void] LogWrite [String] $msg`
Use LogWrite function to log internal diagnostic info pertaining to execution details 
$msg: Message to be written to log file
No data or PII should be logged here.

3. `MakeFilename`
`[String] MakeFilename [String] $name [String] $extension` 
If creating files needed for the diagnostic function, call this to generate a filename. 
MakeFilename wraps your chosen filename with "xray", timestamp and hostname, it also prepends it with current data path being used.
Example: `MakeFilename "dhcpexport" "xml"` returns `C:\MS_DATA\xray_dhcpexport_200421-211747_tdimli-pcx.xml`
The timestamp suffix stays the same for the duration of xray execution. This ensures that all files created during the same run of xray have the same timestamp suffix

#### Sample diagnostic function:
```
#region area_component_KB123456
<#
Wrapped in a region same name as function name
 
Checks for: Details of the issue this function checks for 

If diagnostic function identifies an issue, it should call ReportIssue and provide detailed information:
Issue details and instructions on how to resolve, link to public KBs etc.
 
Parameter(s)
 $offline Boolean, Input
  $False if running on the actual computer
  $True  if not running on the actual computer, diagnostics needs to run against offline data 

Returns 
 $RETURNCODE_SUCCESS if diagnostic function ran successfully
 $RETURNCODE_FAILED  if diagnostic function failed to run successfully
 $RETURNCODE_SKIPPED if diagnostic function chose not to run (for example if it cannot run offline)
#>
function area_component_KB123456
{
    param(
        [Parameter(Mandatory=$true,
        Position=0)]
        [Boolean]
        $offline
    )
    
    # example issue message as formatted string
    # it is always the first item as it also serves as readme/help
    $issueMsg = "
Following network adapter has no connectivity:

{0}

You might be hitting an issue affecting wired network adapters when network
cable is unplugged.

Resolution:
Please reconnect network cable.

Just to demonstrate use of multiple tokens, this is the last update installed:
{1}
"
    # updates (oldest update first), which when installed, may lead to this issue
    $effectingUpdates = @()  # this issue is not specific to an update
    # updates (oldest update first), which when installed, resolve this issue
    $resolvingUpdates = @() # this issue is not resolved by an update

    # Look for the issue
    try {
        if($offline) {
            # your offline diagnostic code here, or skip
            return $RETURNCODE_SKIPPED
        }
        else {
            # your online diagnostic code here
            $AdapterName = (Get-NetAdapter -Name Eth*).Name
            $LastInstalledHotfix = ((Get-HotFix | Sort-Object -Property InstalledOn)[-1]).HotFixID
            [string]::Format($issueMsg, $AdapterName, $LastInstalledHotfix)
            ReportIssue $issueMsg $ISSUETYPE_ERROR $effectingUpdates $resolvingUpdates
        }
    }
    catch {
        LogWrite "Failed - exiting! (Error: $_)"
        return $RETURNCODE_FAILED
    }

    return $RETURNCODE_SUCCESS
}
# Helper function(s) can be defined here if you must, for use by this diagnostic function only
# Using helper functions from other diagnostics is prohibited (here today, gone tomorrow as xray is dynamic!)
#endregion area_component_KB123456
```

The message that will be shown to user and saved in a report:
```
**
** Issue 1      Found a potential issue (area_component_KB123456):
**

Following network adapter has no connectivity:

Ethernet

You might be hitting an issue affecting wired network adapters when network
cable is unplugged.

Resolution:
Please reconnect network cable.

Just to demonstrate use of multiple tokens, this is the most recent hotfix installed:
KB654321
```
