# xray.ps1
# by tdimli
# March 2020
# Detects known issues and helps resolve them

# parameters
# Specify either one or more area(s) or component(s), not both
Param(
    [Parameter(Mandatory=$true,
    ParameterSetName="Areas")]
    [String[]]
    $Area,

    [Parameter(Mandatory=$true,
    ParameterSetName="Components")]
    [String[]]
    $Component,

    [Parameter(Mandatory=$true,
    ParameterSetName="Diagnostics")]
    [String[]]
    $Diagnostic,

    [Parameter(Mandatory=$false,
    ParameterSetName="Areas")]
    [Parameter(Mandatory=$false,
    ParameterSetName="Components")]
    [Parameter(Mandatory=$false,
    ParameterSetName="Diagnostics")]
    [String]
    $DataPath,

    [Parameter(Mandatory=$false,
    ParameterSetName="Areas")]
    [Parameter(Mandatory=$false,
    ParameterSetName="Components")]
    [Parameter(Mandatory=$false,
    ParameterSetName="Diagnostics")]
    [switch]
    $Offline,

    [Parameter(Mandatory=$false,
    ParameterSetName="Areas")]
    [Parameter(Mandatory=$false,
    ParameterSetName="Components")]
    [Parameter(Mandatory=$false,
    ParameterSetName="Diagnostics")]
    [switch]
    $WaitBeforeClose,

    [Parameter(Position=0, Mandatory=$false,
    ParameterSetName="Help")]
    [AllowEmptyString()]
    [AllowNull()]
    [String]
    $Help
)

#region modules
Import-Module -Name .\diag_ads.psm1 -Force
Import-Module -Name .\diag_dnd.psm1 -Force
Import-Module -Name .\diag_net.psm1 -Force
Import-Module -Name .\diag_prf.psm1 -Force
Import-Module -Name .\diag_sha.psm1 -Force
Import-Module -Name .\diag_uex.psm1 -Force
#endregion modules

#region globals
# version
$version = "1.0.200427.0"

# Area and Area/Component arrays
$TechAreas = @("ADS", "DND", "NET", "PRF", "SHA", "UEX")
#endregion globals

#region classes
class diagHelper 
{
    # constants
    # return codes
    static [Int] $ReturnCode_Success = 0
    static [Int] $ReturnCode_Skipped = 1
    static [Int] $ReturnCode_Failed = 2
    static [Int] hidden $ReturnCode_Exception = 3

    # issue types
    static [Int] $IssueType_Info = 0
    static [Int] $IssueType_Warning = 1
    static [Int] $IssueType_Error = 2
    #static [string[]] $IssueTypes = @("Information", "Warning", "Error")

    # value could not be retrieved
    static [string] hidden $valueNA = "<error!>"

    # globals
    [string] $version
    [DateTime] $startTime
    [string] $timestamp
    [string] $datapath
    [string] hidden $logfile
    [string] hidden $reportfile
    [string] hidden $xmlRptfile
    [xmlReport] hidden $xmlRpt

    # counters
    [int] hidden $DiagnosticsRun = 0
    [int] hidden $DiagnosticsSuccess = 0
    [int] hidden $DiagnosticsSkipped = 0
    [int] hidden $DiagnosticsFailed = 0
    [int] hidden $IssuesFound = 0

    diagHelper([string] $version, [string] $datapath, [xmlReport] $xmlreport)
    {
        $this.version = $version
        $this.datapath = $datapath
        # create xmlReport
        $this.xmlRpt = $xmlreport
        # create activity log
        $this.startTime = (Get-Date).ToUniversalTime()
        #$timestampSuffix = (Get-Date).ToUniversalTime().ToString("yyMMdd-HHmmss")
        $this.timestamp = $this.startTime.ToString("yyMMdd-HHmmss")
        $this.logfile = $this.MakeFileName("log", "txt")
        $this.reportfile = $this.MakeFileName( "ISSUES-FOUND", "txt")
    } 

    # To report an issue if one was identified by a diagnostic function
    # Diagnostic functions use this function to report the issue they have identified 
    # $issueType: 0 (Info), 1 (Warning) or 2 (Error)
    [void] ReportIssue([String] $issueMsg, [Int] $issueType, [string[]] $effectingUpdates, [string[]] $resolvingUpdates)
    {
        [string] $eUpd, $rUpd = ""
        $this.IssuesFound++

        # get caller/diagnostic details
        $callStack = Get-PSCallStack
        if ($callStack.Count -gt 1) {
            $issueId = $callStack[1].FunctionName
        }
        else {
            # this shouldn't happen
            $issueId = $this.valueNA
            $this.LogToFile("Could not retrieve issueId!")
        }

        if ($effectingUpdates.Count -gt 0) {
            # issue maybe affected by certain update(s)
            $this.LogToFile("Affected updates: $effectingUpdates")
        }

        if ($resolvingUpdates.Count -gt 0) {
            # issue is resolved by update(s)
            $this.LogToFile("Resolving updates: $resolvingUpdates")
        }

        $this.xmlRpt.AddIssue($issueId, $IssueType, $effectingUpdates, $resolvingUpdates)
        $this.LogToFile([string]::Format("Issue reported by diagnostic [{0}], type:{1}", $issueId, $issueType))

        # ignore showing/reporting anything but errors for now
        if ($issueType -lt $this::IssueType_Error) {
            $this.LogToFile("Issue type is not error: Not displaying on screen and not creating ISSUES-FOUND report, saving to xml report only")
            return
        }

        if($this.IssuesFound -eq 1) {
            # first issue, create report file, add header
            [string]::Format("xray by tdimli, v{0}",$this.version)>$this.reportfile
            [string]::Format("Diagnostic check run on {0} UTC`n", $this.startTime.ToString("yyyy-MM-dd HH:mm:ss"))>>$this.reportfile
        }
        else {
            # add separator
            "`n* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *`n">>$this.reportfile
        }
        
        "**">>$this.reportfile
        [string]::Format("** Issue {0}`tFound a potential issue ({1}):", $this.IssuesFound, $issueId)>>$this.reportfile
        "**">>$this.reportfile
        $issueMsg>>$this.reportfile
    
        # show message on screen
        if ($issueType -eq $this::IssueType_Error) {
            Write-Host ([string]::Format("
**
** Issue {0}`tFound a potential issue ({1}):
**", $this.IssuesFound, $issueId)) -ForegroundColor red
            IndentMsg $issueMsg
        }
    }

    # Wraps a filename with "xray_" prefix and timestamp & computername suffix "" for consistency
    # Ensures all files created have the same name format, same run of xray script uses the same timestamp-suffix
    # Also prepends $DataPath to ensure all files are created in the designated folder
    [String] MakeFileName([String] $name, [String] $extension)
    {
        $computer = hostname
        $filename = "xray_" + $name + "_" + $this.timestamp + "_" + $computer + "." + $extension
        return Join-Path -Path $this.datapath -ChildPath $filename
    }

    # Logs to activity log with timestamp
    [void] LogToFile([String] $msg)
    {
        $callStack = Get-PSCallStack
        $caller = $this.valueNA
        if ($callStack.Count -gt 1) {
            $caller = $callStack[1].FunctionName + " " + (Split-Path -Path $callStack[1].ScriptName -Leaf).ToString() + ":" +  $callStack[1].ScriptLineNumber
        }
        $time = (Get-Date).ToUniversalTime().ToString("yyyy/MM/dd HH:mm:ss.fffffff")
        [string]::Format("{0} [{1}] {2}", $time, $caller, $msg) >> $this.logfile
    }
}

class xmlReport 
{
    [System.XML.XMLDocument] $xmlReport
    [System.XML.XMLElement] $nodeXray
    [System.XML.XMLElement] $xmlTechAreas
    [System.XML.XMLElement] $xmlParameters
    [System.XML.XMLElement] $xmlSystemInfo
    [System.XML.XMLElement] $xmlIssues
    [System.XML.XMLElement] $xmlDiagnostics
    [DateTime] $startTime
    [DateTime] $finishTime
    [string] $timeFormat

    xmlReport([string] $version)
    {
        $this.xmlReport = New-Object System.XML.XMLDocument
        # add root node: nodeXray
        $this.nodeXray = $this.xmlReport.CreateElement("xray")
        $this.xmlReport.appendChild($this.nodeXray)
        $this.nodeXray.SetAttribute("Version", $version)

        # time stamp
        $this.timeFormat = "dd/MM/yy-HH:mm:ss"
        $this.startTime = (Get-Date).ToUniversalTime()
        $this.nodeXray.SetAttribute("StartTime", $this.startTime.ToString($this.timeFormat))
        
        # add TechAreas
        $this.xmlTechAreas = $this.nodeXray.AppendChild($this.xmlReport.CreateElement("TechAreas"))
        # add Parameters
        $this.xmlParameters = $this.nodeXray.AppendChild($this.xmlReport.CreateElement("Parameters"))
        # add SystemInfo
        $this.xmlSystemInfo = $this.nodeXray.AppendChild($this.xmlReport.CreateElement("SystemInfo"))
        # add Issues
        $this.xmlIssues = $this.nodeXray.AppendChild($this.xmlReport.CreateElement("Issues"))
        # add Diagnostics
        $this.xmlDiagnostics = $this.nodeXray.AppendChild($this.xmlReport.CreateElement("Diagnostics"))
    }

    [void] AddTechArea([string] $name, [string] $version){
        [System.XML.XMLElement]$xmlTechArea = $this.xmlTechAreas.AppendChild($this.xmlReport.CreateElement("TechArea"))
        $xmlTechArea.SetAttribute("Name", $name)
        $xmlTechArea.SetAttribute("Version", $version)
    }

    [void] AddParameters([string[]] $areas, [string[]] $components, [string[]] $diagnostics, [bool] $offline, [bool] $waitBeforeClose){
        foreach ($area in $areas) {
            [System.XML.XMLElement] $xmlArea = $this.xmlParameters.AppendChild($this.xmlReport.CreateElement("Area"))
            $xmlArea.SetAttribute("Name", $area)
        }
        foreach ($component in $components) {
            [System.XML.XMLElement] $xmlComponent = $this.xmlParameters.AppendChild($this.xmlReport.CreateElement("Component"))
            $xmlComponent.SetAttribute("Name", $component)
        }
        foreach ($diagnostic in $diagnostics) {
            [System.XML.XMLElement] $xmlComponent = $this.xmlParameters.AppendChild($this.xmlReport.CreateElement("Diagnostic"))
            $xmlComponent.SetAttribute("Name", $diagnostic)
        }
        [System.XML.XMLElement] $xmlOffline = $this.xmlParameters.AppendChild($this.xmlReport.CreateElement("Offline"))
        $xmlOffline.SetAttribute("Value", $offline)
        [System.XML.XMLElement] $xmlOffline = $this.xmlParameters.AppendChild($this.xmlReport.CreateElement("WaitBeforeClose"))
        $xmlOffline.SetAttribute("Value", $waitBeforeClose)
    }

    [void] AddSystemInfo([string] $name, [string] $value){
        [System.XML.XMLElement] $xmlSysInfo = $this.xmlSystemInfo.AppendChild($this.xmlReport.CreateElement($name))
        [System.XML.XMLElement] $xmlDetail = $xmlSysInfo.AppendChild($this.xmlReport.CreateElement("Value"))
        $xmlDetail.InnerText = $value
    }

    [void] AddIssue([string] $id, [Int] $type, [string] $effUpd, [string] $resUpd){
        [System.XML.XMLElement] $xmlIssue = $this.xmlIssues.AppendChild($this.xmlReport.CreateElement("Issue"))
        [System.XML.XMLElement] $xmlDetail = $xmlIssue.AppendChild($this.xmlReport.CreateElement("Id"))
        $xmlDetail.InnerText = $id
        $xmlDetail = $xmlIssue.AppendChild($this.xmlReport.CreateElement("Type"))
        $xmlDetail.InnerText = $type
        $xmlDetail = $xmlIssue.AppendChild($this.xmlReport.CreateElement("effUpd"))
        if ($effUpd.Length -gt 0) {
            $xmlDetail.InnerText = $effUpd
        }
        $xmlDetail = $xmlIssue.AppendChild($this.xmlReport.CreateElement("resUpd"))
        if ($resUpd.Length -gt 0) {
            $xmlDetail.InnerText = $resUpd
        }
    }

    [void] AddDiagnostic([string] $name, [Int] $result, [UInt64] $duration){
        [System.XML.XMLElement] $xmlDiagnostic = $this.xmlDiagnostics.AppendChild($this.xmlReport.CreateElement("Diagnostic"))
        $xmlDiagnostic.SetAttribute("Name", $name)
        $xmlDiagnostic.SetAttribute("Result", $result)
        $xmlDiagnostic.SetAttribute("Duration", $duration)
    }

    [void] Save([string] $filename){
        $this.finishTime = (Get-Date).ToUniversalTime()
        $this.nodeXray.SetAttribute("EndTime", $this.finishTime.ToString($this.timeFormat))
        [UInt64] $timeTaken = ($this.finishTime - $this.startTime).TotalMilliseconds
        $this.nodeXray.SetAttribute("Duration", $timeTaken)
        $this.xmlReport.Save($filename)
    }
}
#endregion classes

#region helpers
# For use by main script functions
# Not for use by diagnostic functions

# Processes provided area(s) with all its components & checks
function RunDiagForArea($areas)
{
    foreach ($area in $areas) {
        $xrayDiag.LogToFile("Processing area:$area")
        $ErrorActionPreference = "Stop"
        try {
            $components = (Get-Variable -Name $area).Value
        }
        catch {
            $xrayDiag.LogToFile($Error[0].Exception)
            #continue
        }
        finally {
            $ErrorActionPreference = "Continue"
        }
        RunDiagForComponent $components
    }
}

# Processes provided components and runs corresponding checks
function RunDiagForComponent($components)
{
    if($components.Count -eq 0){
        $xrayDiag.LogToFile("No components!")
        return
    }
    foreach ($component in $components) {
        $xrayDiag.LogToFile("Processing component: $component")
        $ErrorActionPreference = "Stop"
        try {
            $diags = (Get-Variable -Name $component -ErrorVariable ErrorMsg -ErrorAction SilentlyContinue).Value
        }
        catch {
            $xrayDiag.LogToFile($Error[0].Exception)
            #continue
        }
        finally {
            $ErrorActionPreference = "Continue"
            if($ErrorMsg) {
                $xrayDiag.LogToFile($ErrorMsg)
            }
        }
        RunDiag $diags
    }
}

# Runs specified diagnostics
function RunDiag($diagnostics)
{
    # to prevent failure messages from diag functions
    $ErrorActionPreference = "Stop"

    foreach ($diag in $diagnostics) {
        $xrayDiag.LogToFile([string]::Format("Running diagnostic: {0}", $diag))
        Write-Host "." -NoNewline
        $startTime = (Get-Date).ToUniversalTime()
        try {
            $xrayDiag.DiagnosticsRun++
            $result = & $diag $Offline
        }
        catch {
            $result = $xrayDiag::ReturnCode_Exception
            $xrayDiag.LogToFile($Error[0].Exception)
        }
        finally {
            $xrayDiag.LogToFile([string]::Format("{0} returned: {1}", $diag, $result))
            $finishTime = (Get-Date).ToUniversalTime()
            [UInt64] $timeTaken = ($finishTime - $startTime).TotalMilliseconds
            $xmlRpt.AddDiagnostic($diag, $result, $timeTaken)
        }

        if($result -eq $xrayDiag::ReturnCode_Success){
            $xrayDiag.DiagnosticsSuccess++
        }
        elseif($result -eq $xrayDiag::ReturnCode_Skipped){
            $xrayDiag.DiagnosticsSkipped++
        }
        else {
            $xrayDiag.DiagnosticsFailed++
        }
    }

    # this was to prevent failure messages from diag functions, now revert to normal error handling 
    $ErrorActionPreference = "Continue"
}

# Shows message on screen indented for readability
function IndentMsg($msg)
{
    $newMsg = $msg -split "`n"
    foreach ($line in $newMsg) {
        Write-Host "   $line"
    }
}

# 'Translates' TSS scenarios to xray components 
function ValidateTssComponents
{
    param(
        [Parameter(Mandatory=$true)]
        [String[]]
        $TssComponents
    )

    $tssComps  = @("802Dot1x", "WLAN",     "Auth", "BITS", "BranchCache", "Container", "CSC", "DAcli", "DAsrv", "DFScli", "DFSsrv", "DHCPcli", "DhcpSrv", "DNScli", "DNSsrv", "Firewall", "General", "HypHost", "HypVM", "IIS", "IPAM", "MsCluster", "MBAM", "MBN", "Miracast", "NCSI", "NetIO", "NFScli", "NFSsrv", "NLB", "NPS", "Proxy", "RAS", "RDMA", "RDScli", "RDSsrv", "SDN", "SdnNC", "SQLtrace", "SBSL", "UNChard", "VPN", "WFP", "Winsock", "WIP", "WNV", "Workfolders")
    $xrayComps = @("802Dot1x", "802Dot1x", "Auth", "BITS", "BranchCache", "Container", "CSC", "DAcli", "DAsrv", "DFScli", "DFSsrv", "DHCPcli", "DhcpSrv", "DNScli", "DNSsrv", "Firewall", "General", "HypHost", "HypVM", "IIS", "IPAM", "MsCluster", "MBAM", "MBN", "Miracast", "NCSI", "NetIO", "NFScli", "NFSsrv", "NLB", "NPS", "Proxy", "RAS", "RDMA", "RDScli", "RDSsrv", "SDN", "SdnNC", "SQLtrace", "SBSL", "UNChard", "VPN", "WFP", "Winsock", "WIP", "WNV", "Workfolders")

    $tssComps = $tssComps.ToLower()
    $xrayComps = $xrayComps.ToLower()
    $TssComponents = $TssComponents.ToLower()
    [System.Collections.Generic.List[String]] $newComps = $TssComponents

    for (($i = 0); $i -lt $TssComponents.Count; $i++) {
        $tcomp = $TssComponents.GetValue($i)
        $index = $tssComps.IndexOf($tcomp)
        if($index -lt 0) {
            continue
        }
        $xcomp = $xrayComps.GetValue($index)
        if($tcomp -ne $xcomp) {
            if($newComps.Contains($xcomp)) {
                # remove
                $newComps.RemoveAt($i)
            }
            else {
                # replace
                $newComps = $newComps.Replace($tcomp, $xcomp)
            }
        }
    }
    return [String[]] $newComps
}

# Displays help/usage info
function ShowHelp
{
    "
xray by tdimli, v$version

Checks for known issues

Usage:
xray.ps1 -Area <string[]> [-DataPath <string>] [-Offline] [-WaitBeforeClose] [<CommonParameters>]
xray.ps1 -Component <string[]> [-DataPath <string>] [-Offline] [-WaitBeforeClose] [<CommonParameters>]
xray.ps1 -Diagnostic <string[]> [-DataPath <string>] [-Offline] [-WaitBeforeClose] [<CommonParameters>]

xray.ps1 Shows help

    Parameters:
    Specify either Area or Component to check or Diagnostic to run (they are mutually exclusive), multiple items can be specified (comma-separated).
        When area(s) specified, all components within the specified area(s) are checked
        When component(s) specified, all diagnostics within the specified component(s) are run
        When diagnostic(s) specified, only the specified diagnostics are run
        ""-Area all"" or ""-Area *"" checks all areas
    -DataPath: Path for input/output files
    -Offline: Not running on the actual machine being examined (some -not all- diagnostics can use data files to search for issues)
    -WaitBeforeClose: If any known issues are detected, pauses just before script terminates/window closes
        Use to ensure detected issues are not missed

    Example: .\xray.ps1 -Component dhcpsrv,dnssrv -DataPath c:\xray

List of available diagnostic areas/components to scan for issues:
Area (version):  `tComponents:
=================`t===========
    "
    foreach ($techarea in $TechAreas) {
        $version_name = $techarea + "_version"
        $techarea_version = (Get-Variable -Name $version_name).Value
        $components = (Get-Variable -Name $techarea).Value
        "$techarea ($techarea_version)`t$components"
    }
    ""
}
#endregion helpers

#region main
# main script

if (($Area -eq $null) -and ($Component -eq $null) -and ($Diagnostic -eq $null)) {
    # show help if no area or component specified
    ShowHelp
}
else {
    # validate DataPath, do it here before any file operations
    $origDataPath = $DataPath
    if(($DataPath.Length -eq 0) -or -not(Test-Path -Path $DataPath)) {
        $DataPath = (Get-Location).Path
    }
    else {
        $DataPath = Convert-Path $DataPath
    }

    # create xmlReport
    $xmlRpt = [xmlReport]::new($version)
    # create diagHelper
    $Global:xrayDiag  = [diagHelper]::new($version, $DataPath, $xmlRpt)
    $xmlRptfile = $xrayDiag.MakeFileName("report", "xml")

    $xrayDiag.LogToFile("xray by tdimli, v$version")
    Write-Host "xray by tdimli, v$version`nStarting diagnostics, checking for known issues..."
    foreach ($techarea in $TechAreas) {
        $version_name = $techarea + "_version"
        $techarea_version = (Get-Variable -Name $version_name).Value
        $xrayDiag.LogToFile(" $techarea $techarea_version")
        $xmlRpt.AddTechArea($techarea, $techarea_version)
    }
    # log parameters
    $xmlRpt.AddParameters($Area, $Component, $Diagnostic, $Offline, $WaitBeforeClose)
    $xrayDiag.LogToFile("Parameters:")
    $xrayDiag.LogToFile(" Area(s): $Area")
    $xrayDiag.LogToFile(" Component(s): $Component")
    if(($Component -ne $null) -and ($Component.Count -gt 0)) {
        $ConvertedComponent = ValidateTssComponents $Component
        $xrayDiag.LogToFile("  after conversion: $ConvertedComponent")
        $Component = $ConvertedComponent
    }
    $xrayDiag.LogToFile(" Diagnostic(s): $Diagnostic")
    $xrayDiag.LogToFile(" Datapath: $DataPath")
    if (!$DataPath.Equals($origDataPath)) {
        $xrayDiag.LogToFile("  Original Datapath: $origDataPath")
    }
    $xrayDiag.LogToFile(" Offline: $Offline")
    $xrayDiag.LogToFile(" WaitBeforeClose: $WaitBeforeClose")
    $xrayDiag.LogToFile([string]::Format("Log file: {0}", $xrayDiag.logfile))

    # add OS info
    if (!$Offline) {
        # if not offline
        $os = Get-WmiObject -class Win32_OperatingSystem -ErrorAction SilentlyContinue
        if ($os -ne $null) {
            $xmlRpt.AddSystemInfo("Win32_OperatingSystem.Caption", $os.Caption)
            $xmlRpt.AddSystemInfo("Win32_OperatingSystem.Version", $os.Version)
        }
    }
    else {
        # if offline retrieve from data
    }
    $xrayDiag.LogToFile("Starting diagnostics, checking for known issues...")

    if ($Area) {
        # do we need to run checks for all areas?
        if (($Area -eq  "all") -or ($Area -eq  "*")) {
            # run checks for all areas
            RunDiagForArea $TechAreas
        } else {
            # run checks for the area(s) specified
            RunDiagForArea $Area
        }
    } elseif ($Component) {
        # run checks for the component(s) specified
        RunDiagForComponent $Component
    } elseif ($Diagnostic) {
        # run checks for the component(s) specified
        RunDiag $Diagnostic
    }
    $xrayDiag.LogToFile("Saving xml report $xmlRptfile...")
    $xmlRpt.Save($xmlRptfile)
    $stats1 = [string]::Format("{0} diagnostic check(s) run (R:{1} S:{2} F:{3})", $xrayDiag.DiagnosticsRun, $xrayDiag.DiagnosticsSuccess, $xrayDiag.DiagnosticsSkipped, $xrayDiag.DiagnosticsFailed)
    $stats2 = [string]::Format("{0} issue(s) found", $xrayDiag.IssuesFound)
    if ($xrayDiag.IssuesFound -gt 0) {
        $stats2 += [string]::Format(", details saved to {0}", $xrayDiag.reportfile)
    }
    $xrayDiag.LogToFile($stats1)
    $xrayDiag.LogToFile($stats2)
    $xrayDiag.LogToFile("Diagnostics completed.")

    # show summary
    Write-Host
    Write-Host $stats1
    Write-Host $stats2
    Write-Host "Diagnostics completed.`n"
}

if($WaitBeforeClose -and ($IssuesFound -gt 0)) {
    # wait for user
    pause
}
#endregion main
