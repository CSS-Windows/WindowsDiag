# file: Validate-HypvRssVMQ.ps1 v1.0

<#
.SYNOPSIS
    Collect and Validate Hypv RSS and Config 
.DESCRIPTION
    Collect and Validate Hypv RSS and Config 
.PARAMETER CollectOnly
    Only Collect infos to validate offline
.EXAMPLE
    .\Validate-HypvRssVMQ.ps1 -scriptmode -DataPath "c:\ms_data"
	This example saves the results in C:\ms_data\HypvRssVMQ, 
.NOTES
    Script developped by Vincent Douhet <vidou@microsoft.com> - Escalation Engineer / Microsoft Support CSS
        Please report him any issue using this script or regarding a ask in term of improvement and contribution

    DISCLAIMER:
    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

.LINK
	https://github.com/ViDou83/WinDiag/blob/master/Validate-HypvRssVMQ.ps1
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)] [bool]$CollectOnly,
    [Parameter(Mandatory = $false)] [String]$OfflineData,
	[String]$DataPath = "$env:TMP\HypvRssVMQ",
	[switch]$HostMode  = $true,  # This tells the logging functions to show logging on the screen
	[switch]$ScriptMode = $false # This tells the logging functions to show logging in log file __Result_HypvRssVMQ.txt
)

#########
####    GLOBALS
########
$VerDate = "2020.03.31.0"
$PROGRAMNAME = "Validate-HypvRssVMQ"
$NbrVmSwitch = 0
#$outputDir = "$env:TMP\HypvRssVMQ"
$outputDir = "$DataPath\HypvRssVMQ"
Test-path $outputDir
if ( -not $(Test-Path $outputDir) ) {write-host "not exists";(new-item -path $outputDir -type directory | Out-Null)}
$LogPath = $outputDir + "\_Result_HypvRssVMQ.txt"
 Write-host "LogPath $LogPath"

$LogLevel = 0

Enum NetLbfoTeamTeamingMode {
    Static = 0
    SwitchIndependent = 1
    Lacp = 2
}

Enum NetLbfoTeamLoadBalancingAlgorithm {
    TransportPorts = 0
    IPAddresses = 2
    MacAddresses = 3
    HyperVPort = 4
    Dynamic = 5
}

Enum RssProfile {
    ClosestProcessor = 1
    ClosestProcessorStatic = 2
    NUMAScaling = 3
    NUMAScalingStatic = 4
    ConservativeScaling = 5
}

$g_VMHost = @{ }

#region: Logging Functions
	function WriteLine ([string]$line,[string]$ForegroundColor, [switch]$NoNewLine){
		# SYNOPSIS: writes the actual output - used by other Logging Functions
    if($Script:ScriptMode){
      if($NoNewLine) {
        $Script:Trace += "$line"
      }
      else {
        $Script:Trace += "$line`r`n"
      }
      Set-Content -Path $script:LogPath -Value $Script:Trace
    }
    if($Script:HostMode){
      $Params = @{
        NoNewLine    = $NoNewLine -eq $true
        ForegroundColor = if($ForegroundColor) {$ForegroundColor} else {"White"}
      }
      Write-Host $line @Params
    }
  }

  function WriteInfo([string]$message,[switch]$WaitForResult,[string[]]$AdditionalStringArray,[string]$AdditionalMultilineString){
		# SYNOPSIS: handles informational logs
    if($WaitForResult){
      WriteLine "[$(Get-Date -Format hh:mm:ss)] INFO:  $("`t" * $script:LogLevel)$message" -NoNewline
    }
    else{
      WriteLine "[$(Get-Date -Format hh:mm:ss)] INFO:  $("`t" * $script:LogLevel)$message"
    }
    if($AdditionalStringArray){
      foreach ($String in $AdditionalStringArray){
        WriteLine "          $("`t" * $script:LogLevel)`t$String"
      }
    }
    if($AdditionalMultilineString){
      foreach ($String in ($AdditionalMultilineString -split "`r`n" | Where-Object {$_ -ne ""})){
        WriteLine "          $("`t" * $script:LogLevel)`t$String"
      }
    }
  }

  function WriteResult([string]$message,[switch]$Pass,[switch]$Success){
		# SYNOPSIS: writes results - should be used after -WaitForResult in WriteInfo
    if($Pass){
      WriteLine " - Pass" -ForegroundColor Cyan
      if($message){
        WriteLine "[$(Get-Date -Format hh:mm:ss)] INFO:  $("`t" * $script:LogLevel)`t$message" -ForegroundColor Cyan
      }
    }
    if($Success){
      WriteLine " - Success" -ForegroundColor Green
      if($message){
        WriteLine "[$(Get-Date -Format hh:mm:ss)] INFO:  $("`t" * $script:LogLevel)`t$message" -ForegroundColor Green
      }
    }
  }

  function WriteInfoHighlighted([string]$message,[string[]]$AdditionalStringArray,[string]$AdditionalMultilineString){
		# SYNOPSIS: write highlighted info
    WriteLine "[$(Get-Date -Format hh:mm:ss)] INFO:  $("`t" * $script:LogLevel)$message" -ForegroundColor Cyan
    if($AdditionalStringArray){
      foreach ($String in $AdditionalStringArray){
        WriteLine "[$(Get-Date -Format hh:mm:ss)]     $("`t" * $script:LogLevel)`t$String" -ForegroundColor Cyan
      }
    }
    if($AdditionalMultilineString){
      foreach ($String in ($AdditionalMultilineString -split "`r`n" | Where-Object {$_ -ne ""})){
        WriteLine "[$(Get-Date -Format hh:mm:ss)]     $("`t" * $script:LogLevel)`t$String" -ForegroundColor Cyan
      }
    }
  }

  function WriteWarning([string]$message,[string[]]$AdditionalStringArray,[string]$AdditionalMultilineString){
		# SYNOPSIS: write warning logs
    WriteLine "[$(Get-Date -Format hh:mm:ss)] WARNING: $("`t" * $script:LogLevel)$message" -ForegroundColor Yellow
    if($AdditionalStringArray){
      foreach ($String in $AdditionalStringArray){
        WriteLine "[$(Get-Date -Format hh:mm:ss)]     $("`t" * $script:LogLevel)`t$String" -ForegroundColor Yellow
      }
    }
    if($AdditionalMultilineString){
      foreach ($String in ($AdditionalMultilineString -split "`r`n" | Where-Object {$_ -ne ""})){
        WriteLine "[$(Get-Date -Format hh:mm:ss)]     $("`t" * $script:LogLevel)`t$String" -ForegroundColor Yellow
      }
    }
  }

  function WriteError([string]$message){
		# SYNOPSIS: logs errors
			WriteLine ""
			WriteLine "[$(Get-Date -Format hh:mm:ss)] ERROR:  $("`t`t" * $script:LogLevel)$message" -ForegroundColor Red
  }

  function WriteErrorAndExit($message){
		# SYNOPSIS: logs errors and terminates script
			WriteLine "[$(Get-Date -Format hh:mm:ss)] ERROR:  $("`t" * $script:LogLevel)$message" -ForegroundColor Red
			Write-Host "Press any key to continue ..."
			$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | OUT-NULL
			$HOST.UI.RawUI.Flushinputbuffer()
			Throw "Terminating Error"
	}

	#endregion: Logging Functions
#region: Script Functions
function IsHypvInstalled() {
	#if( (Get-WindowsFeature Hyper-V  )Installed -eq "True" ) { $res=$true }
	<#
	# Windows 10: Get the Hyper-V feature and store it in $hyperv
		$hyperv = Get-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V-All -Online
	# Check if Hyper-V is already enabled.
	if ($hyperv.State -eq "Enabled") {
		WriteInfo -message "Hyper-V is enabled."
		$res = $true
	} else {
		WriteWarning -message "Hyper-V is disabled."
		$res = $false
	}
    return $res
	#>
	$TestPath = Test-Path "C:\Windows\System32\vmms.exe"
	return $TestPath 
    
    
}

function Get-NetAdapterNumaNode {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [String] $NicName
    )

    return $(Get-NetAdapterHardwareInfo -Name $NicName).NumaNode
}

function CollectEnvInfo() {
    WriteInfo -message "--------------------------------------------"
    WriteInfo -message "`tCollecting machine state on $env:COMPUTERNAME"
    WriteInfo -message "--------------------------------------------"

    $RegWinNTCurrVer = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\"

    $RegWinNTCurrVer | ConvertTo-Json | Set-Content -Path $outputDir\WinNTVersion.json

}


function CollectCPUAndNumaTopology() {
    #    $res = $false

    [String []] $cmdlets = @( "Get-VMHost", "Get-VMHostNumaNode" )

    $cmdlets | ForEach-Object { 
        $cmd = $_
        "Collecting $cmd"
        & $cmd | ConvertTo-Json | Set-Content -Path $outputDir\$_.json    
    }

    Get-WmiObject -Class win32_processor -Property * | ConvertTo-JSON  | Set-Content -Path $outputDir\CpuInfo.json 
}


function CollectVMNetworkInfo() {

    WriteInfo -message "--------------------------------------------"
    WriteInfo -message "`tCollecting Network info on $env:COMPUTERNAME"
    WriteInfo -message "--------------------------------------------"


    [String []] $cmdlets = @( "Get-NetAdapter", "Get-NetAdapterHardwareInfo", "Get-NetAdapterRSS", "Get-NetAdapterVMQ", "Get-NetAdapterVmqQueue",
        "Get-VMHost", "Get-VMSwitch", "Get-NetLbfoTeam", "Get-NetLbfoTeamMember", "Get-NetLbfoTeamNic", "Get-VMNetworkAdapter", "Get-NetIPAddress"
    )

    $cmdlets | ForEach-Object { 
        $cmd = $_
        "Collecting $cmd"
        if ( $cmd -eq "Get-VMNetworkAdapter") {
            & $cmd -All | ConvertTo-Json | Set-Content -Path $outputDir\$_.json    
        }
        else {
            & $cmd | ConvertTo-Json -Depth 10 | Set-Content -Path $outputDir\$_.json    
        }
    }


    if ( Test-Path $outputDir\Get-VMSwitch.json ) {
        $VMSwitchobj = Get-Content $outputDir\Get-VMSwitch.json | ConvertFrom-Json 
        $VMSwitchobj | ForEach-Object {
            $VMSwitch = $_
            $VMSwitchName = $_.Name
            $VMSwitchType = $_.SwitchType

            #            WriteResult -Success -message "VMSWITH NAME=$VMSwitchName TYPE=$VMSwitchType detected"
            if ( $VMSwitchType -eq 2) {   
                if ( $VMSwitch.EmbeddedTeamingEnabled -eq "True") {
                    #"SET Team enabled"
                    $cmd = "Get-VMSwitchTeam"
                    Invoke-Command -ScriptBlock { & $cmd $VMSwitchName } | ConvertTo-Json | Set-Content -Path $outputDir\$cmd-$VMSwitchName.json 
                }
                elseif ( $VMSwitch.NetAdapterInterfaceDescription -match "Multiplexor" ) {
                    #"LBFO Team found"
                }

                #
                if ( $VMSwitch.AllowManagementOS -eq "True") {
                    $cmd = "Get-VMNetworkAdapter"
                    Invoke-Command -ScriptBlock { & $cmd -ManagementOS -SwitchName $VMSwitchName } | ConvertTo-Json | Set-Content -Path $outputDir\$cmd-$VMSwitchName.json 
                }
            }
		}
    }
    else {
        WriteError "SCRIPT ERROR: No external VMSwitch configured. Cannot check RSS/VMQ stuff"
    }

    $res = $true

    return $res

}

function GetAndInsertVmqTopology() {
    param(
        [String] $VMSwitchName,
        [PSobject] $NetAdapter
    )

    $NetAdapterVmq = Get-Content $outputDir\Get-NetAdapterVmq.json | ConvertFrom-Json 

    $hashtable = @{ 
        Enabled               = "False";
        NumaNode              = 0;
        BaseProcessorGroup    = 0;
        BaseProcessorNumber   = 0;
        MaxProcessorNumber    = 0;
        MaxProcessors         = 0;
        NumberOfReceiveQueues = 0;
    }    
                              
    $NetAdapterVmq | ForEach-Object { 
        if ($NetAdapter.Name -eq $_.IfAlias) {

            $hashtable.Enabled = $_.Enabled
            $hashtable.NumaNode = $_.NumaNode
            $hashtable.BaseProcessorGroup = $_.BaseProcessorGroup
            $hashtable.BaseProcessorNumber = $_.BaseProcessorNumber
            $hashtable.MaxProcessorNumber = $_.MaxProcessorNumber
            $hashtable.NumberOfReceiveQueues = $_.NumberOfReceiveQueues
            $g_VMHost.$VMSwitchName."VMQ".Add($NetAdapter.Name, $hashtable)
        }    
    }
}

###
## Checking VMQ Status on each Team NIC
#
function IsVmqEnabledOnNIC() {
    param(
        [string] $VMSwitchName,
        [string] $NetAdapterKey
    )

    if ( $g_VMHost.$VMSwitchName."VMQ".$NetAdapterKey.Enabled -eq "True") {
        WriteResult -Success -message "VMQ Enabled on NIC $NetAdapterKey"
        if ( $g_VMHost.$VMSwitchName."VMQ".$NetAdapterKey.BaseProcessorNumber -eq 0) {
            WriteWarning "VMQ BaseProc=0 NIC=$NetAdapterKey - You should consider changing VMQ BaseProcNumber"
        }
    }
    else {
        WriteError "VMQ Disabled on NIC $NetAdapterKey"
        WriteWarning "Don't use VMQ on vmSwitch leads to poor performance"

    }
}

function CheckTeamNicCompliancy() {
    param(
        $hashtable
    )
    WriteInfo -message "- TeamNics compliancy check => Team=$($hashtable.TeamNics) TeamingType=$($hashtable.TeamingType) "
        
    if ( $hashtable.TeamingType -eq "LBFO") {
        $NetLbfoTeamNic = Get-Content $outputDir\Get-NetLbfoTeamNic.json | ConvertFrom-Json 
        $NetLbfoTeamMember = Get-Content $outputDir\Get-NetLbfoTeamMember.json | ConvertFrom-Json 
    }

    $members = $hashtable.members

    # Check how many NICs the teaming has 
    if ( $members.count -eq 1 ) {
        WriteWarning "Team=$($hashtable.TeamNics) TeamingType=$($hashtable.TeamingType) : Teaming with one NIC cannot offer failover"        
    }

    # SET teamin should have between 1 and 8 NICs
    if ( $hashtable.TeamingType -eq "LBFO" ) {
        if ( -Not ( $members.count -ge 1 -and $members.count -le 32 ) ) {
            WriteError "Team=$($hashtable.TeamNics) TeamingType=$($hashtable.TeamingType) : TeamNICs is composed of $($members.count) NICs"
        }
    }
    # LBFO teamin should have between 1 and 32 NICs
    elseif ($hashtable.TeamingType -eq "SET" ) {
        if ( -Not ( $members.count -ge 1 -and $members.count -le 8 ) ) {
            WriteError "Team=$($hashtable.TeamNics) TeamingType=$($hashtable.TeamingType) : TeamNICs is composed of $($members.count) NICs"
        }  
    }

    #Checking Speed
    if ( $NetLbfoTeamNic.ReceiveLinkSpeed -match "Gbps" -and $NetLbfoTeamNic.TransmitLinkSpeed -match "Gbps"  ) {
        $pow = 9
        $unit = "Gpbs"  
    }
    if ( $NetLbfoTeamNic.ReceiveLinkSpeed -match "Mpbs" -and $NetLbfoTeamNic.TransmitLinkSpeed -match "Mpbs"  ) {
        $pow = 6
        $unit = "Mpbs" 
    }

    $TotalSpeedExpected = $members[0].Speed * $members.count 

    if ( $hashtable.TeamingType -eq "LBFO") {
        $TotalSpeedExpected /= [Math]::pow(10, $pow )
        if ( $NetLbfoTeamNic.TransmitLinkSpeed.Split()[0] -ne $TotalSpeedExpected ) {
            WriteError "Team=$($hashtable.TeamNics) TeamingType=$($hashtable.TeamingType) : TeamNICs must have same speed. Teaming of NICs with different speed connections is not supported."
        }
    }
    else {
        $MgmtOsNic = (  Get-Content $outputDir\Get-NetAdapter.json | ConvertFrom-Json ) | Where-Object { $_.Name -match $hashtable.TeamNics } 
        if ( $MgmtOsNic ) { 
            if ( $MgmtOsNic.TransmitLinkSpeed -ne $TotalSpeedExpected ) {
                WriteError "Team=$($hashtable.TeamNics) TeamingType=$($hashtable.TeamingType) : TeamNICs must have same speed. Teaming of NICs with different speed connections is not supported."
            }
        }
    }
    
    #Driver
    $Driver = @{ }

    $Driver.Add($members[0].DriverName, 0)
    $Driver.Add($members[0].DriverVersionString, 0)
    $Driver.Add($members[0].DriverProvider, 0)
    $Driver.Add($members[0].DriverFileName, 0)
    $Driver.Add($members[0].DriverDescription, 0)

    for ($i = 0; $i -lt $members.count; $i++) {
        $Driver[$members[$i].DriverName]++
        $Driver[$members[$i].DriverVersionString]++
        $Driver[$members[$i].DriverProvider]++
        $Driver[$members[$i].DriverFileName]++
        $Driver[$members[$i].DriverDescription]++

    }

    foreach ($key in $Driver.Keys) {
        if ( $Driver[$key] -ne $members.count ) {
            if ( $hashtable.TeamingType -eq "SET") {
                WriteError "Team=$($hashtable.TeamNics) TeamingType=$($hashtable.TeamingType) : TeamNICs must have same driver. TeamNICs with different driver/manufacter is not supported."
            }
            else {
                WriteWarning "Team=$($hashtable.TeamNics) TeamingType=$($hashtable.TeamingType) : TeamNICs with different driver/manufacter might be supported even if this is not recommended"                
            }
            break
        }
    }

}

function ComputeVMSwitchTeamingInfo() {
    param(
        [PSobject]$VMSwitch
    )

    $hashtable = @{ 
        TeamNics               = "";
        TeamingType            = "";
        LoadBalancingAlgorithm = 0;
        TeamingMode            = 0;
        Id                     = "{00000000-0000-0000-0000-000000000000}";
        Members                = [PSobject]@();
        LacpTimers             = 0
    }    
    
    #If SET Teaming
    if ($VMSwitch.EmbeddedTeamingEnabled -eq "True") {
        $NetTeam = Get-Content $outputDir\Get-VMSwitchTeam-$VMSwitchName.json | ConvertFrom-Json 
        $hashtable.TeamNics = $NetTeam.Name
        $hashtable.Id = $NetTeam.Id
        $hashtable.TeamingType = "SET"
        $NetTeam.NetAdapterInterfaceDescription |
        ForEach-Object {
            $NetAdapterInterfaceDescription = $_
            $member = (Get-Content $outputDir\Get-NetAdapter.json | ConvertFrom-Json) | Where-Object { $_.ifDesc -eq $NetAdapterInterfaceDescription }
            $hashtable.Members += $member
        }
    } # Otherwise LBFO 
    elseif ( $VMSwitch.NetAdapterInterfaceDescription -match "Multiplexor" ) {

        $NetTeamNic = ( Get-Content $outputDir\Get-NetLbfoTeamNic.json | ConvertFrom-Json ) | Where-Object { $VMSwitch.NetAdapterInterfaceDescription -eq $_.InterfaceDescription } 
        $NetTeam = ( Get-Content $outputDir\Get-NetLbfoTeam.json | ConvertFrom-Json ) | Where-Object { $_.Name -eq $NetTeamNic.Name    } 
        
        $hashtable.TeamNics = $NetTeamNic.Name
        $hashtable.Id = $NetTeam.InstanceID
        $hashtable.TeamingType = "LBFO"
        $NetTeam.Members.Value |
        ForEach-Object {
            $NetAdapterInterfaceDescription = $_
            $member = (Get-Content $outputDir\Get-NetAdapter.json | ConvertFrom-Json) | Where-Object { $_.Name -eq $NetAdapterInterfaceDescription }            
            $hashtable.Members += $member
        }
    }
    else {
        WriteError -message "SCRIPT ERROR: Wrong Switch type provided"
    }

    $hashtable.TeamingMode = $NetTeam.TeamingMode
    $hashtable.LoadBalancingAlgorithm = $NetTeam.LoadBalancingAlgorithm

    $g_VMHost.$VMSwitchName.Add("TEAM", $hashtable)        

    WriteInfo -message "+ TeamingMode"
    WriteInfo -message "- VMSwithName=$($VMSwitch.name) TeamingType=$($g_VMHost.$VMSwitchName."TEAM".TeamingType)"
    
    #Checking if NIC are same speed / same brand / type and so on
    CheckTeamNicCompliancy $hashtable  

}


function ComputeVMQPlan() {
    param(
        [PSobject] $VMSwitchName
    )
    
    $members = $g_VMHost.$VMSwitchName."TEAM".members.name
    $g_VMHost.$VMSwitchName.Add("VMQ", @{ })

    $members | 
    ForEach-Object {
        $NetAdapterDescription = $_
        $NetAdapter = (Get-Content $outputDir\Get-NetAdapter.json | ConvertFrom-Json) | Where-Object { $_.Name -eq $NetAdapterDescription }
        GetAndInsertVmqTopology $VMSwitchName $NetAdapter
    }  

    WriteInfo -message "+ VMQ status"

    #Checking if VMQ is Enabled on NIC
    foreach ( $NetAdapterKey in $g_VMHost.$VMSwitchName.VMQ.Keys) {        
        IsVmqEnabledOnNIC $VMSwitchName $NetAdapterKey
    }
}

function CheckVMQSumMinQ() { 
    param(
        [PSobject] $VMSwitchName
    )
    
    $QueueModeExpect = ""
    $QueueModeCurrent = ""
    $VMQCpuOverlap = $false

    if ( $g_VMHost.$VMSwitchName."TEAM".TeamingType -eq "SET") {
        $QueueModeExpect = "SUM"
    }
    elseif ( $g_VMHost.$VMSwitchName."TEAM".TeamingType -eq "LBFO") { 
        switch ( $g_VMHost.$VMSwitchName."TEAM".TeamingMode ) {
            ([NetLbfoTeamTeamingMode]::SwitchIndependent.value__) {
                if (  $g_VMHost.$VMSwitchName."TEAM".LoadBalancingAlgorithm -ne [NetLbfoTeamLoadBalancingAlgorithm]::HyperVPort.value__ -or
                    $g_VMHost.$VMSwitchName."TEAM".LoadBalancingAlgorithm -ne [NetLbfoTeamLoadBalancingAlgorithm]::Dynamic.value__ 
                ) {
                    $QueueModeExpect = "MIN"
                }
                else {
                    $QueueModeExpect = "SUM"
                }
            }
            (   [NetLbfoTeamTeamingMode]::Lacp.value__ -or 
                [NetLbfoTeamTeamingMode]::Static.value__
            ) {
                $QueueModeExpect = "MIN"
            }
        }
    }

    WriteInfo -message "- VMQ check if CPU set overlaps"

    #Checking if there is CPU overlaps
    foreach ( $L_member in $g_VMHost.$VMSwitchName."VMQ".Keys  ) {
        foreach ( $R_member in $g_VMHost.$VMSwitchName."VMQ".Keys  ) {
            if ( $L_member -ne $R_member) {
                if ( 
                    $g_VMHost.$VMSwitchName."VMQ".$L_member.BaseProcessorNumber -eq $g_VMHost.$VMSwitchName."VMQ".$R_member.BaseProcessorNumber -and 
                    $g_VMHost.$VMSwitchName."VMQ".$L_member.MaxProcessorNumber -eq $g_VMHost.$VMSwitchName."VMQ".$R_member.MaxProcessorNumber
                ) {
                    $QueueModeCurrent = "MIN"
                }
                else {
                    $QueueModeCurrent = "SUM"
                }

                if ( 
                    (
                        $g_VMHost.$VMSwitchName."VMQ".$R_member.BaseProcessorNumber -ge $g_VMHost.$VMSwitchName."VMQ".$L_member.BaseProcessorNumber -and
                        $g_VMHost.$VMSwitchName."VMQ".$R_member.BaseProcessorNumber -le $g_VMHost.$VMSwitchName."VMQ".$L_member.MaxProcessorNumber
                    ) -or
                    (
                        $g_VMHost.$VMSwitchName."VMQ".$R_member.MaxProcessorNumber -ge $g_VMHost.$VMSwitchName."VMQ".$L_member.BaseProcessorNumber -and
                        $g_VMHost.$VMSwitchName."VMQ".$R_member.MaxProcessorNumber -le $g_VMHost.$VMSwitchName."VMQ".$L_member.MaxProcessorNumber 
                    )        
                ) {
                    WriteError "VMQ CPU set overlaps between $L_member and $R_member NIC"      
                    $VMQCpuOverlap = $true  
                }

            }
        }            
    }

    if ($QueueModeCurrent -eq $QueueModeExpect) {
        WriteResult -Success -message "QueueModeExpect=$QueueModeExpect QueueModeCurrent=$QueueModeCurrent"
    }
    else {
        WriteError "QueueModeExpect=$QueueModeExpect QueueModeCurrent=$QueueModeCurrent"
        if ( $g_VMHost.$VMSwitchName."TEAM".TeamingType -eq "SET") {
            WriteWarning "VMswitch configured with SET teaming must be configured in VMQ Sum-of-Queues mode"
        }
    }

    if ( $VMQCpuOverlap -eq $true ) {
        WriteError "VMQ CPU set overlaps"
    }

}


function Get-RssProfile() {

    param(
        [PSobject] $VMNetworkAdapterRss
    )
    
    switch ( $VMNetworkAdapterRss.Profile) {
        ([RssProfile]::ClosestProcessor.Value__) {
            [RssProfile]::ClosestProcessor   
        }
                        
        ([RssProfile]::ClosestProcessorStatic.Value__) {
            [RssProfile]::ClosestProcessorStatic   
        }

        ([RssProfile]::NUMAScaling.Value__) {
            [RssProfile]::NUMAScaling  
        }
                        
        ([RssProfile]::NUMAScalingStatic.Value__) {
            [RssProfile]::NUMAScalingStatic
        }
                        
        ([RssProfile]::ConservativeScaling.Value__) {
            [RssProfile]::ConservativeScaling                         
        }
    }
}


function CheckVrssStatus() {
    param(
        [PSobject] $VMSwitchName
    )
    
    WriteInfo -message "+ VRSS Status VmSwitch=$VMSwitchName"

    if ( -Not $( Test-Path $outputDir\Get-VMNetworkAdapter.json ) ) { 
        WriteError "Cannot checkt VRSS Status as Get-VMNetworkAdapter.json file is missing"
        return 1
    }
    $VMNetworkAdapter = (Get-Content $outputDir\Get-VMNetworkAdapter.json | ConvertFrom-Json) | Where-Object { $_.SwitchName -eq $VMSwitchName }

    $VMNetworkAdapter | ForEach-Object {
        $VMNetworkAdapterCurrent = $_
        if ( $_.VrssEnabled) {
            #Check Indirection table and NUMA distance
            $VMNetworkAdapterRss = (Get-Content $outputDir\Get-NetAdapterRSS.json | ConvertFrom-Json) | Where-Object { $_.Name -match $VMNetworkAdapterCurrent.name }
            
            $RssPreviousCPU = 0
            $VMNetworkAdapterRss.IndirectionTable.CimInstanceProperties | ForEach-Object {
                $RssCurrentCPU = $_.Value
                if ( $RssPreviousCPU -eq $RssCurrentCPU) {
                    $RssAllZeroes = $true
                }
                else {
                    $RssAllZeroes = $false                    
                }
                $RssPreviousCPU = $RssCurrentCPU
            }
            
            #
            if ($VMNetworkAdapterCurrent.IsManagementOs) { 
                WriteResult -Success -message "VRSS enabled on MgmtOS vNIC=$($VMNetworkAdapterCurrent.name)"
            }
            else {
                WriteResult -Success -message "VRSS enabled on VM=$($VMNetworkAdapterCurrent.VMName) vNIC=$($VMNetworkAdapterCurrent.name) "                
            }

            #
            if ( $VMNetworkAdapterRss.BaseProcessorNumber -eq 0) {
                WriteWarning "RSS BaseProc=0 vNIC=$($VMNetworkAdapterCurrent.name) - you should consider to exlude CPU=0"
            }

            #Indirection table EMPTY
            if ( $RssAllZeroes ) {
                WriteWarning "RSS Indirection table empty for vNIC=$($VMNetworkAdapterCurrent.name) RssProfile=$(Get-RssProfile $VMNetworkAdapterRss)"
                WriteWarning "--------- Please try to reset RSS on $($VMNetworkAdapterRss.name)"   
            }
        }
        else {
            if ($VMNetworkAdapterCurrent.IsManagementOs) { 
                WriteError "VRSS disabled on MgmtOS vNIC=$($VMNetworkAdapterCurrent.name)"
            }
            else {
                WriteError "VRSS disabled on VM=$($VMNetworkAdapterCurrent.VMName) vNIC=$($VMNetworkAdapterCurrent.name) "                
            }
        }
    }
} 


function CheckVMQNumaNode() {
    param(
        [PSobject] $VMSwitchName
    )

    WriteInfo -message "+ VMQ check spreading from NUMA node topology"


    $VMHost = (Get-Content $outputDir\Get-VMHost.json | ConvertFrom-Json)
    $VMHostNumaNode = (Get-Content $outputDir\Get-VMHostNumaNode.json | ConvertFrom-Json)
    #$cpuInfo = @(Get-WmiObject -Class win32_processor -Property "NumberOfCores", "NumberOfLogicalProcessors")

    $NbrNUMA = $VMHostNumaNode.NodeId.Count

    if ( Test-Path $outputDir\CpuInfo.json) {
        $g_VMHost.add("CpuInfo", $( Get-Content $outputDir\CpuInfo.json | ConvertFrom-Json ))
    
        $g_VMHost.CpuInfo[0].NumberOfCores
        for ( $i = 0; $i -lt $g_VMHost.cpuInfo.count ; $i++) {
            $NbrCores += $g_VMHost.cpuInfo[$i].NumberOfCores
            $NbrLPs += $g_VMHost.cpuInfo[$i].NumberOfLogicalProcessors
        }
    }
    else {
        $NbrNUMA = $VMHostNumaNode.NumaNodEId.count
        $NbrCores = $NbrNUMA
        $NbrLPs = $VMHostNumaNode.ProcessorsAvailability.count
    }

    $NbrLPsPerNuma = $NbrLPs / $VMHostNumaNode.NumaNodEId.count

    # Hyper-Threading is enabled if NumberOfCores is less than NumberOfLogicalProcessors
    $htEnabled = $NbrCores -lt $NbrLPs

    $out = if ($htEnabled) { "HyperThreading=Enabled " }else { "HyperThreading=Disabled " } 
    $out += "NbrNUMA=$NbrNUMA NumberOfCores=$NbrCores NbrLPsPerNuma=$NbrLPsPerNuma NumberOfTotalLogicalProcessors=$NbrLPs"    
    WriteInfo -message $out
 
    #Checking if there is CPU overlaps
    foreach ( $NetAdapterName in $g_VMHost.$VMSwitchName."VMQ".Keys  ) {
        $NetAdapterHardwareInfo = (Get-Content $outputDir\Get-NetAdapterHardwareInfo.json | ConvertFrom-Json) | Where-Object { $_.Name -eq $NetAdapterName }

        $VMQNumaNode = if ( $g_VMHost.$VMSwitchName."VMQ".$NetAdapterName.NumaNode -ne 65535) { $g_VMHost.$VMSwitchName."VMQ".$NetAdapterName.NumaNode }else { $NetAdapterHardwareInfo.NumaNode }
  

        $NumaBaseProcNumber = $VMQNumaNode * $NbrLPsPerNuma
        $NumaMaxProcNumber = if ( $htEnabled) { ( $NbrLPsPerNuma * ( $VMQNumaNode + 1 ) ) - 2 }else { ( $NbrLPsPerNuma * ( $VMQNumaNode + 1 ) ) - 1 }

        $PhysicalNumaPin = $NetAdapterHardwareInfo.NumaNode

        if ( $PhysicalNumaPin -ne $VMQNumaNode) { WriteWarning "VMSwitchName=$VMSwitchName NetAdapterName=$NetAdapterName NetHardwareInfoNumaNode=$PhysicalNumaPin != VMQNumaNode=$VMQNumaNode" } 

        #"NetAdapterName=$NetAdapterName NumaNodEId=$($g_VMHost.$VMSwitchName."VMQ".$NetAdapterName.NumaNode) NumaBaseProcNumber=$NumaBaseProcNumber NumaMaxProcNumber=$NumaMaxProcNumber"
        if ( $g_VMHost.$VMSwitchName."VMQ".$NetAdapterName.BaseProcessorNumber -ge $NumaBaseProcNumber -and
            $g_VMHost.$VMSwitchName."VMQ".$NetAdapterName.MaxProcessorNumber -le $NumaMaxProcNumber 
        ) {
            WriteResult -Success -message "VMSwitchName=$VMSwitchName NetAdapterName=$NetAdapterName NumaNode=$VMQNumaNode CPU set is configured properly between $NumaBaseProcNumber and $NumaMaxProcNumber"    
        }
        else {
            WriteError "VMSwitchName=$VMSwitchName NetAdapterName=$NetAdapterName NumaNode=$VMQNumaNode CPU set is not configured properly | not between $NumaBaseProcNumber and $NumaMaxProcNumber"    
        } 
    }
}


###### 
####   ComputeVMSwitchConfig
##
###
### 1/ Check VMSwitch
### 2/ Check teaming 
### 3/ Check CPU & Numa Node topo
### 4/ Check VMQ & vRSS spreading
###
function CheckVMQandRSS() {
		$VMSwitchobj = Get-Content $outputDir\Get-VMSwitch.json | ConvertFrom-Json 
		# Iterating each VMSwitch found
		$VMSwitchobj | 
		ForEach-Object {
			$VMSwitch = $_
			$VMSwitchName = $VMSwitch.Name
			#Only interested by external vmswtich 
			if ( $VMSwitch.SwitchType -eq 2) {
				WriteInfo -message "##"
				WriteInfo -message "### External VMSwitch  Name=$VMSwitchName" 
				WriteInfo -message "##"
				
				#Add it to the hashtable
				$g_VMHost.Add($VMSwitchName, @{ })    
				
				### 2/ Check teaming             
				ComputeVMSwitchTeamingInfo $VMSwitch
				ComputeVMQPlan $VMSwitchName
				CheckVMQSumMinQ $VMSwitchName
				CheckVMQNumaNode $VMSwitchName
				CheckVrssStatus $VMSwitchName
			}
		}
}


function CheckNetworkTopology() {
    
    WriteInfo -message "-----------------------------------------------------"
    WriteInfo -message "`tChecking Hyper-V HOST Network topology"
    WriteInfo -message "-----------------------------------------------------"

    if ( -Not ( Test-Path $outputDir\Get-VMNetworkAdapter.json) ) {
        WriteWarning "HypvHost is not having MgmtOS vNIC means that this is not a converged NIC deployment" 
        WriteWarning "Additionnally it appears that neighter MgmtOS and VM vNICs exist" 
    }
    else {
        $VMNetworkAdapterMgmtOs = $( Get-Content $outputDir\Get-VMNetworkAdapter.json | ConvertFrom-Json ) | Where-Object { $_.IsManagementOs }

        if ( -Not $VMNetworkAdapterMgmtOs) {
            WriteWarning "HypvHost is not having MgmtOS vNIC means that this is not a converged NIC deployment" 
            #
        }
        else {

            $NetLbfoTeam = Get-Content $outputDir\Get-NetLbfoTeam.json | ConvertFrom-Json 
            $NetLbfoTeamNic = Get-Content $outputDir\Get-NetLbfoTeamNic.json | ConvertFrom-Json 
            $NetLbfoTeamMember = Get-Content $outputDir\Get-NetLbfoTeamMember.json | ConvertFrom-Json

            $NetIPAddress = Get-Content $outputDir\Get-NetIPAddress.json | ConvertFrom-Json 
        }
    }
}
#endregion: Script Functions

###### 
####   Main
##
WriteInfo -message "...Starting '$PROGRAMNAME' on $ENV:COMPUTERNAME by $ENV$USERNAME at $(Get-Date) "
#if ( Test-Path $outputDir) { Remove-Item $outputDir -Recurse -Force }

if ( IsHypvInstalled ) {
    if ( $OfflineData ) {
        if ( Test-Path $OfflineData ) {
            $outputDir = $OfflineData
        }
    }
    else {
        if ( -not $(Test-Path $outputDir) ) {
			mkdir $outputDir | Out-Null
			CollectEnvInfo
			CollectCPUAndNumaTopology
			CollectVMNetworkInfo
        }
    }
    if ( -Not $CollectOnly) {
        WriteInfo -message "-----------------------------------------------------"
        WriteInfo -message "`tChecking VirtualNetwork optimization "
        WriteInfo -message "-----------------------------------------------------"
        #
        if (Test-Path $outputDir\Get-VMSwitch.json ) { 
			CheckVMQandRSS } else {WriteWarning "This is not a Hyper-V Host"}
        #
        CheckNetworkTopology
    }
    else {
        Write-Host "Please zip and upload collected informations located in $outputDir to Microsoft Support using DTM workspace." -ForegroundColor Green
    }
}
else {
    WriteError -message "Hyper-V role appears to be not installed"
}

#rmdir $outputDir -Force 
Write-Host -BackgroundColor Gray -ForegroundColor Black -Object "$(Get-Date -UFormat "%R:%S") Done $PROGRAMNAME"