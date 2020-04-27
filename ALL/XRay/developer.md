# xray 
*tdimli, March 2020*

### Guidance for diagnostic function developers:
 
xray aims to resolve known issues with minimal delay and effort.
xray relies on diagnostic functions to achieve this. 

*Please contact tdimli if you can help create diagnostic functions to identify and resolve even more issues.  
You can write it yourself or you can just share issue details and how to identify it with us and we can code it for you.*

#### When writing a diagnostic function...

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

All diagnostic functions define $issueMsg variable at the very beginning, which takes the form of a multiline formatted string and serves as readme/help as well as defining the message that will be shown to end user and saved in the report if the issue is found. No changes should be made to this variable other than formatting/replacing tokens using `[string]::Format()`. 

All diagnostic functions also define two further variables which are string arrays:
$effectingUpdates: List of updates, which when installed, may lead to this issue
$resolvingUpdates: List of updates, which when installed, resolve this issue
Both arrays have the updates listed in release order, oldest first, i.e. item[0] will contain earliest released update.
Either or both arrays can be empty if the issue is not specific to an update or is not resolved by an update.

Diagnostic functions take one input parameter: bool $offline 
$False if running on the actual computer being examined
$True  if not running on the actual computer, diagnostics needs to run against offline TSS data 

Diagnostic functions do not write anything to console, do not show any pop-ups etc. Instead, they use provided APIs (listed below) to report issues and log to logfile (execution details, not data).

Diagnostic functions should return a status code:
$xrayDiag::ReturnCode_Success if diagnostic function ran successfully
$xrayDiag::ReturnCode_Failed  if diagnostic function failed to run successfully
$xrayDiag::ReturnCode_Skipped if diagnostic function chose not to run (for example if it cannot run offline and offline parameter was specified)

A starter sample diagnostic function is provided below. 
You might also find that reviewing existing diagnostic functions can be inspirational.

#### Functions (APIs) provided by xray for use by diagnostic functions:

1. `ReportIssue`
`[void] ReportIssue([String] $issueMsg, [Int] $issueType, [string[]] $effectingUpdates, [string[]] $resolvingUpdates)`
Diagnostic functions can use this to report the issue they have identified. 
$issueMsg: This is the message that will be shown to end-user and saved to the report. Provide a message containing details of the issue and how to resolve it. If possible, also try and provide links to public KB articles/documents etc. 
Issue details parameter is normally a multiline/formatted string and may contain one or more tokens ({0}, {1} etc.) to be replaced with machine/issue specific info -like the name of the problem network card- before being passed to ReportIssue`
Please see sample diagnostic function below for more details on how $issueMsg and  specific Info can be merged together.
$issueType: Diagnostic functions should only report errors: `$xrayDiag::IssueType_Error`
$effectingUpdates: Array of updates (oldest update first), which when installed, may lead to this issue. Empty if issue is not specific to any updates.
$resolvingUpdates: Array of updates (oldest update first), which when installed, resolve this issue. Empty if issue is not resolved by an update

2. `LogToFile`
`[void] xrayDiag.LogToFile([String] $msg)`
Use LogToFile function to log internal diagnostic info pertaining to execution details 
$msg: Message to be written to log file
No data or PII should be logged here.

3. `MakeFileName`
`[String] xrayDiag.MakeFileName([String] $name, [String] $extension)` 
If creating files needed for the diagnostic function, call this to receive a name prefixed with `"xray_<datetime>_"` and suffixed with <hostname>. 
MakeFileName wraps your chosen filename with these and also prepends it with current data path being used.  
Example: `xrayDiag.MakeFileName("dhcpexport", "xml")` returns `C:\MS_DATA\xray_dhcpexport_200421-211747_tdimli-pcx.xml`
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
 $xrayDiag::ReturnCode_Success if diagnostic function ran successfully
 $xrayDiag::ReturnCode_Failed  if diagnostic function failed to run successfully
 $xrayDiag::ReturnCode_Skipped if diagnostic function chose not to run (for example if it cannot run offline)
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
            return $xrayDiag::ReturnCode_Skipped
        }
        else {
            # your online diagnostic code here
            $AdapterName = (Get-NetAdapter -Name Eth*).Name
            $LastInstalledHotfix = ((Get-HotFix | Sort-Object -Property InstalledOn)[-1]).HotFixID
            [string]::Format($issueMsg, $AdapterName, $LastInstalledHotfix)
            xrayDiag.ReportIssue($issueMsg, $xrayDiag::IssueType_Error, $effectingUpdates, $resolvingUpdates)
        }
    }
    catch {
        xrayDiag.LogToFile($Error[0].Exception)
        return $xrayDiag::ReturnCode_Failed
    }

    return $xrayDiag::ReturnCode_Success
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
