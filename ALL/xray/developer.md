# xray 
*tdimli, March 2020*

### Guidance for diagnostic function developers:
 
xray aims to resolve known issues with minimal delay and effort.
xray relies on diagnostic functions to achieve this. 

*Please contact tdimli if you can help create diagnostic functions to identify and resolve even more issues.  
You can write it yourself or you can just share issue details and how to identify it with us and we can code it for you.*

#### What is a diagnostic function?
A diagnostic function is a PowerShell function, that looks for a specific known issue and if detected, reports it to main script using reporting API provided.

#### How to add a diagnostic function
Contact tdimli and share the diagnostic function you have created and we will help get it added.

#### How to write a diagnostic function
(in no particular order)

1. Target a single issue and ideally target type of issues that are known to cause incoming critsits and support cases. 

2. The targeted issue should have a corresponding KB article. Name your diagnostic function in this format: <tech area>_<component>_KB<id>

3. Try and use (no pun intended) try/catch block(s) where necessary to avoid exceptions and unwanted error messages to console.  
`Note:` xray calls the diagnostic functions with "$ErrorActionPreference set to "Stop" to catch/handle any unhandled exceptions.

4. Please be mindful that xray can be run on various versions of OS and PowerShell versions. Try to acommodate widest variety where you can, by using commands/syntax supported also by older systems where possible (xray framework code can run on Win7SP1/PowerShell 2.0). As a suggestion, a diagnostic should ideally be able to run on Windows 8/PowerShell 4.0, if this is not possible, please add code to check OS version/build and skip running (see example diagnostic function below).

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

10. Diagnostic functions take one input parameter: bool $offline 
$False if running on the actual computer being examined
$True  if not running on the actual computer, diagnostics needs to run against offline TSS data 

11. Diagnostic functions do not write anything to console, do not show any pop-ups etc. Instead, they use provided APIs to report issues and write to logfile (logfile is for execution details, not data).

12. Diagnostic functions should return a status code:
$RETURNCODE_SUCCESS if diagnostic function ran successfully
$RETURNCODE_FAILED  if diagnostic function failed to run successfully
$RETURNCODE_SKIPPED if diagnostic function chose not to run (for example if it cannot run offline and offline parameter was specified)

13. Diagnostic functions should run in the shortest time possible (there are many diagnostic functions and it all adds up!). As a rough guideline, if your diagnostic takes more than a second to run without detecting an issue, then there is room for improvement. Naturally, time taken becomes less of a concern if it actually resolves the issue.

`Note:` A simple diagnostic function is provided for reference and as a starting point at the end of this document below. You might also find that reviewing existing diagnostic functions can be inspirational.

#### Functions (APIs) provided by xray for use by diagnostic functions:

1. `ReportIssue`  
`[void] ReportIssue [String] $issueMsg [Int] $issueType`  
Diagnostic functions can use this to report the issue they have identified.  
$issueMsg: This is the message that will be shown to end-user and saved to the report. Provide a message containing details of the issue and how to resolve it. If possible, also try and provide links to public KB articles/documents etc.  
Issue details parameter is normally a multiline/formatted string and may contain one or more tokens ({0}, {1} etc.) to be replaced with machine/issue specific info -like the name of the problem network card- before being passed to `ReportIssue`  
Please see sample diagnostic function below for more details on how $issueMsg and  specific Info can be merged together.  
$issueType: Diagnostic functions should only report errors: `$ISSUETYPE_ERROR`  

2. `LogWrite`  
`[void] LogWrite [String] $msg`  
Use LogWrite function to log internal diagnostic info pertaining to execution details  
$msg: Message to be written to log file  
No data or PII should be logged here.  

3. `MakeFilename`  
`[String] MakeFilename [String] $name [String] $extension`  
If creating files needed for the diagnostic function, call this to generate a filename.  
`MakeFilename` wraps your chosen filename with "xray", timestamp and hostname, it also prepends it with current data path being used.  
Example: `MakeFilename "dhcpexport" "xml"` returns `C:\MS_DATA\xray_dhcpexport_200421-211747_tdimli-pcx.xml`  
The timestamp suffix stays the same for the duration of xray execution. This ensures that all files created during the same run of xray have the same timestamp suffix  

4. `HasRequiredUpdate`  
`[Boolean] HasRequiredUpdate [string[]] $reqUpdates`  
Checks if one of the required updates ($reqUpdates) or a later update is installed.  
Returns true if a required update or a later one is installed, false if a required update is not present.  
If none of the updates in $reqUpdates apply to current OS version, if for example all required updates are for for RS5 but the OS is RS4, then it also returns true as the specified update(s) are not relevant/not needed.  
 $reqUpdates array contains a list of update(s) that specifies the minimum required update for each OS version affected/to be checked  
Example: `HasRequiredUpdate $requiredUpdates`  
`    # list of updates (for various OS versions) that first fixed this issue`  
`    $requiredUpdates = @(`  
`        "KB4565503", # 2004`  
`        "KB4565483", # 1903 & 1909`  
`        "KB4558998", # 2019`  
`        "KB4565511", # 2016`  
`        "KB4565541", # 2012 R2`  
`        "KB4565537", # 2012`  
`        "KB4565524", # 2008 R2 SP1`  
`        "KB4565536"  # 2008 SP2`  

5. `GetPoolUsageSummary`  
`[System.Collections.Generic.List[string[]]] GetPoolUsageSummary`  
Returns summary data from poolmon. If multiple poolmon data sets are available one set for each will be returned. This can be used to check general memory usage.  
Each returned set will contain two list items with a string[7] in following format:  
` Summary1,22/05/2020 22:35:55.53,33356024,19399488,400263915,12672,935188`  
` Summary2,22/05/2020 22:35:55.53,15680004,40433912,15917968,629240,1004712`  
Example:  
 For sample summary:  
`  Memory:33356024K Avail:19399488K  PageFlts:400263915   InRam Krnl:12672K P:935188K`  
`  Commit:15680004K Limit:40433912K Peak:15917968K            Pool N:629240K P:1004712K`  
 it will return string array(s) containing:  
`  Summary1,22/05/2020 22:35:55.53,33356024,19399488,400263915,12672,935188`  
`  Summary2,22/05/2020 22:35:55.53,15680004,40433912,15917968,629240,1004712`  

6. `GetPoolUsageByTag`  
`[System.Collections.Generic.List[Int64[]]] GetPoolUsageByTag [string] $poolTag [string] $poolType`  
Returns pool usage info from poolmon for specified pool tag and type, $null if no entry for specified item.  
This API can be used to check memory usage for a specific tag and/or to identify specific memory leaks.  
Pooltag has to be 4 characters (case-sensitive), pooltype can be "Nonp" or "Paged" (case-sensitive)  
If multiple poolmon data sets are available all matching entries will be returned.  
Return data type is list of Int64 arrays  
Example:  
 For sample entry:  
`  Ntfx Nonp    1127072   1037111     89961 26955808        299        `  
 it will return an Int64 array containing:  
`  1127072, 1037111, 89961, 26955808, 299`  

#### Sample diagnostic function:
```
# Wrapped in a region same name as function name

#region net_dnscli_KB4562541
<# 
Component: dnscli, vpn, da, ras
Checks for:
 The issue where multiple NRPT policies are configured and are in conflict.
 This will result in none of configured NRPT policies being applied.
Created by: tdimli 
#>
function net_dnscli_KB4562541
{
    param(
        [Parameter(Mandatory=$true,
        Position=0)]
        [Boolean]
        $offline
    )
$issueMsg = "
This computer has local NRPT rules configured when there are also domain 
group policy NRPT rules present. This can cause unexpected name resolution 
behaviour. 
When domain group policy NRPT rules are configured, local NRPT rules are 
ignored and not applied:
`tIf any NRPT settings are configured in domain Group Policy, 
`tthen all local Group Policy NRPT settings are ignored.

More Information:
https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn593632(v=ws.11)

Resolution:
Inspect configured NRPT rules and decide which ones to keep, local or domain 
Group Policy NRPT rules. 

Registry key where local group policy NRPT rules are stored:
  {0}

Registry key where domain group policy NRPT rules are stored:
  {1}

Note: Even if domain group policy registry key is empty, local group policy 
NRPT rules will still be ignored. Please delete the domain group policy 
registry key if it is not being used.
If it is being re-created, identify the policy re-creating it and remove the 
corresponding policy configuration.
"

    if($offline) {
        LogWrite "Cannot run offline, skipping"
        return $RETURNCODE_SKIPPED
    }

    # Look for the issue
    $localNRPTpath = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"
    $domainNRPTpath = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\DnsClient"
    $DnsPolicyConfig = "DnsPolicyConfig"

    try {
        # NRPT available in WS2012 (9200) and later
        $curBuild = [Convert]::ToUInt32($wmi_Win32_OperatingSystem.BuildNumber)
        $minBuild = 9200
        if ($curBuild -lt $minBuild ) {
            LogWrite "OS version $($wmi_Win32_OperatingSystem.Version) not affected, skipping"
            return $RETURNCODE_SKIPPED
        }

        # are there any local NRPTs configured which risk being ignored?
        if ((Get-ChildItem -Path "Registry::$localNRPTpath\$DnsPolicyConfig" -ErrorAction SilentlyContinue).Count -gt 0) {
            # does domain policy NRPT key exist (empty or not)?
            $domainNRPT = (Get-ChildItem -Path "Registry::$domainNRPTpath" -ErrorAction SilentlyContinue)
            if ($domainNRPT -ne $null) {
                if ($domainNRPT.Name.Contains("$domainNRPTpath\$DnsPolicyConfig")) {
                    # issue present: domain Group Policy NRPT key present, local Group Policy NRPT settings are ignored
                    $issueMsg = [string]::Format($issueMsg, "$localNRPTpath\$DnsPolicyConfig", "$domainNRPTpath\$DnsPolicyConfig")
                    ReportIssue $issueMsg $ISSUETYPE_ERROR $null $null
                }
            }
        }
    }
    catch {
        LogWrite "Failed - exiting! (Error: $_)"
        return $RETURNCODE_FAILED
    }

    return $RETURNCODE_SUCCESS
}

# Helper function(s) can be defined here if you must, strictly for use by this diagnostic function only
# Using helper functions from other diagnostics is prohibited (here today, gone tomorrow as xray is dynamic!)

#endregion net_dnscli_KB4562541
```

The message that will be shown to user and saved in a report:
```
**
** Issue 1	Found a potential issue (reported by net_dnscli_KB4562541):
**

This computer has local NRPT rules configured when there are also domain 
group policy NRPT rules present. This can cause unexpected name resolution 
behaviour. 
When domain group policy NRPT rules are configured, local NRPT rules are 
ignored and not applied:
	If any NRPT settings are configured in domain Group Policy, 
	then all local Group Policy NRPT settings are ignored.

More Information:
https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn593632(v=ws.11)

Resolution:
Inspect configured NRPT rules and decide which ones to keep, local or domain 
Group Policy NRPT rules. 

Registry key where local group policy NRPT rules are stored:
  HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig

Registry key where domain group policy NRPT rules are stored:
  HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\DnsClient\DnsPolicyConfig

Note: Even if domain group policy registry key is empty, local group policy 
NRPT rules will still be ignored. Please delete the domain group policy 
registry key if it is not being used.
If it is being re-created, identify the policy re-creating it and remove the 
corresponding policy configuration.
```