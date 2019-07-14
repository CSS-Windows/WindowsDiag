# file: Validate-HypvRssVMQ.ps1

<#
.SYNOPSIS
    Collect and Validate Hypv RSS and Config 
.DESCRIPTION
    Collect and Validate Hypv RSS and Config 
.PARAMETER CollectOnly
    Only Collect infos to validate offline
.EXAMPLE
    test
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
    [Parameter(Mandatory = $false)] [String] $OfflineData
)

#########
####    GLOBALS
########
$PROGRAMNAME = "Validate-HypvRssVMQ"
$NbrVmSwitch = 0
$outputDir = "$env:TMP\HypvRssVMQ"

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

function IsHypvInstalled() {
    $res = $true
    
    #if( (Get-WindowsFeature Hyper-V  )Installed -eq "True" ) { $res=$true }

    return $res
}

function Get-NetAdapterNumaNode {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [String] $NicName
    )

    return $(Get-NetAdapterHardwareInfo -Name $NicName).NumaNode
}

function CollectEnvInfo() {
    Write-Host "--------------------------------------------"
    Write-Host "`tCollecting machine state on $env:COMPUTERNAME"
    Write-Host "--------------------------------------------"

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

    Write-Host "--------------------------------------------"
    Write-Host "`tCollecting Network info on $env:COMPUTERNAME"
    Write-Host "--------------------------------------------"


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

            #            Write-Host "OK: VMSWITH NAME=$VMSwitchName TYPE=$VMSwitchType detected" -ForegroundColor Green
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
        Write-Host "SCRIPT ERROR: No external VMSwitch configured. Cannot check RSS/VMQ stuff"
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
        Write-Host "OK: VMQ Enabled on NIC $NetAdapterKey" -ForegroundColor Green
        if ( $g_VMHost.$VMSwitchName."VMQ".$NetAdapterKey.BaseProcessorNumber -eq 0) {
            Write-Host "WARNING: VMQ BaseProc=0 NIC=$NetAdapterKey - You should consider changing VMQ BaseProcNumber" -ForegroundColor yellow
        }
    }
    else {
        Write-Host "ERROR: VMQ Disabled on NIC $NetAdapterKey" -ForegroundColor Red
        Write-Host "WARNING: Don't use VMQ on vmSwitch leads to poor performance" -ForegroundColor yellow

    }
}

function CheckTeamNicCompliancy() {
    param(
        $hashtable
    )
    Write-Host "- TeamNics compliancy check => Team=$($hashtable.TeamNics) TeamingType=$($hashtable.TeamingType) "
        
    if ( $hashtable.TeamingType -eq "LBFO") {
        $NetLbfoTeamNic = Get-Content $outputDir\Get-NetLbfoTeamNic.json | ConvertFrom-Json 
        $NetLbfoTeamMember = Get-Content $outputDir\Get-NetLbfoTeamMember.json | ConvertFrom-Json 
    }

    $members = $hashtable.members

    # Check how many NICs the teaming has 
    if ( $members.count -eq 1 ) {
        Write-Host "WARNING: Team=$($hashtable.TeamNics) TeamingType=$($hashtable.TeamingType) : Teaming with one NIC cannot offer failover" -ForegroundColor Yellow        
    }

    # SET teamin should have between 1 and 8 NICs
    if ( $hashtable.TeamingType -eq "LBFO" ) {
        if ( -Not ( $members.count -ge 1 -and $members.count -le 32 ) ) {
            Write-Host "ERROR: Team=$($hashtable.TeamNics) TeamingType=$($hashtable.TeamingType) : TeamNICs is composed of $($members.count) NICs" -ForegroundColor Red
        }
    }
    # LBFO teamin should have between 1 and 32 NICs
    elseif ($hashtable.TeamingType -eq "SET" ) {
        if ( -Not ( $members.count -ge 1 -and $members.count -le 8 ) ) {
            Write-Host "ERROR: Team=$($hashtable.TeamNics) TeamingType=$($hashtable.TeamingType) : TeamNICs is composed of $($members.count) NICs" -ForegroundColor Red
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
            Write-Host "ERROR: Team=$($hashtable.TeamNics) TeamingType=$($hashtable.TeamingType) : TeamNICs must have same speed. Teaming of NICs with different speed connections is not supported." -ForegroundColor Red
        }
    }
    else {
        $MgmtOsNic = (  Get-Content $outputDir\Get-NetAdapter.json | ConvertFrom-Json ) | Where-Object { $_.Name -match $hashtable.TeamNics } 
        if ( $MgmtOsNic ) { 
            if ( $MgmtOsNic.TransmitLinkSpeed -ne $TotalSpeedExpected ) {
                Write-Host "ERROR: Team=$($hashtable.TeamNics) TeamingType=$($hashtable.TeamingType) : TeamNICs must have same speed. Teaming of NICs with different speed connections is not supported." -ForegroundColor Red
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
                Write-Host "ERROR: Team=$($hashtable.TeamNics) TeamingType=$($hashtable.TeamingType) : TeamNICs must have same driver. TeamNICs with different driver/manufacter is not supported." -ForegroundColor Red
            }
            else {
                Write-Host "WARNING: Team=$($hashtable.TeamNics) TeamingType=$($hashtable.TeamingType) : TeamNICs with different driver/manufacter might be supported even if this is not recommended" -ForegroundColor Yellow                
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
        Write-Host "SCRIPT ERROR: Wrong Switch type provided"
    }

    $hashtable.TeamingMode = $NetTeam.TeamingMode
    $hashtable.LoadBalancingAlgorithm = $NetTeam.LoadBalancingAlgorithm

    $g_VMHost.$VMSwitchName.Add("TEAM", $hashtable)        

    Write-Host "+ TeamingMode"
    Write-Host "- VMSwithNAme=$($VMSwitch.name) TeamingType=$($g_VMHost.$VMSwitchName."TEAM".TeamingType)"
    
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

    Write-Host "+ VMQ status"

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

    Write-Host "- VMQ check if CPU set overlaps"

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
                    Write-Host "ERROR: VMQ CPU set overlaps between $L_member and $R_member NIC" -ForegroundColor Red      
                    $VMQCpuOverlap = $true  
                }

            }
        }            
    }

    if ($QueueModeCurrent -eq $QueueModeExpect) {
        Write-Host "OK: QueueModeExpect=$QueueModeExpect QueueModeCurrent=$QueueModeCurrent" -ForegroundColor Green
    }
    else {
        Write-Host "ERROR: QueueModeExpect=$QueueModeExpect QueueModeCurrent=$QueueModeCurrent" -ForegroundColor Red
        if ( $g_VMHost.$VMSwitchName."TEAM".TeamingType -eq "SET") {
            Write-Host "WARNING: VMswitch configured with SET teaming must be configured in VMQ Sum-of-Queues mode" -ForegroundColor yellow
        }
    }

    if ( $VMQCpuOverlap -eq $true ) {
        Write-Host "ERROR: VMQ CPU set overlaps" -ForegroundColor Red
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
    
    Write-Host "+ VRSS Status VmSwitch=$VMSwitchName"

    if ( -Not $( Test-Path $outputDir\Get-VMNetworkAdapter.json ) ) { 
        Write-Host "ERROR: Cannot checkt VRSS Status as Get-VMNetworkAdapter.json file is missing" -ForegroundColor Red
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
                Write-Host "OK: VRSS enabled on MgmtOS vNIC=$($VMNetworkAdapterCurrent.name)" -ForegroundColor Green
            }
            else {
                Write-Host "OK: VRSS enabled on VM=$($VMNetworkAdapterCurrent.VMName) vNIC=$($VMNetworkAdapterCurrent.name) " -ForegroundColor Green                
            }

            #
            if ( $VMNetworkAdapterRss.BaseProcessorNumber -eq 0) {
                Write-Host "WARNING: RSS BaseProc=0 vNIC=$($VMNetworkAdapterCurrent.name) - you should consided to exlude CPU=0" -ForegroundColor yellow
            }

            #Indirection table EMPTY
            if ( $RssAllZeroes ) {
                Write-Host "WARNING: RSS Indirection table empty for vNIC=$($VMNetworkAdapterCurrent.name) RssProfile=$(Get-RssProfile $VMNetworkAdapterRss)" -ForegroundColor yellow
                Write-Host "--------- Please try to reset RSS on $($VMNetworkAdapterRss.name)" -ForegroundColor yellow   
            }
        }
        else {
            if ($VMNetworkAdapterCurrent.IsManagementOs) { 
                Write-Host "ERROR: VRSS disabled on MgmtOS vNIC=$($VMNetworkAdapterCurrent.name)" -ForegroundColor Red
            }
            else {
                Write-Host "ERROR: VRSS disabled on VM=$($VMNetworkAdapterCurrent.VMName) vNIC=$($VMNetworkAdapterCurrent.name) " -ForegroundColor Red                
            }
        }
    }
} 


function CheckVMQNumaNode() {
    param(
        [PSobject] $VMSwitchName
    )

    Write-Host "+ VMQ check spreading from NUMA node topology"


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
    Write-Host $out
 
    #Checking if there is CPU overlaps
    foreach ( $NetAdapterName in $g_VMHost.$VMSwitchName."VMQ".Keys  ) {
        $NetAdapterHardwareInfo = (Get-Content $outputDir\Get-NetAdapterHardwareInfo.json | ConvertFrom-Json) | Where-Object { $_.Name -eq $NetAdapterName }

        $VMQNumaNode = if ( $g_VMHost.$VMSwitchName."VMQ".$NetAdapterName.NumaNode -ne 65535) { $g_VMHost.$VMSwitchName."VMQ".$NetAdapterName.NumaNode }else { $NetAdapterHardwareInfo.NumaNode }
  

        $NumaBaseProcNumber = $VMQNumaNode * $NbrLPsPerNuma
        $NumaMaxProcNumber = if ( $htEnabled) { ( $NbrLPsPerNuma * ( $VMQNumaNode + 1 ) ) - 2 }else { ( $NbrLPsPerNuma * ( $VMQNumaNode + 1 ) ) - 1 }

        $PhysicalNumaPin = $NetAdapterHardwareInfo.NumaNode

        if ( $PhysicalNumaPin -ne $VMQNumaNode) { Write-Host "WARNING: VMSwitchName=$VMSwitchName NetAdapterName=$NetAdapterName NetHardwareInfoNumaNode=$PhysicalNumaPin != VMQNumaNode=$VMQNumaNode" -ForegroundColor yellow } 

        #"NetAdapterName=$NetAdapterName NumaNodEId=$($g_VMHost.$VMSwitchName."VMQ".$NetAdapterName.NumaNode) NumaBaseProcNumber=$NumaBaseProcNumber NumaMaxProcNumber=$NumaMaxProcNumber"
        if ( $g_VMHost.$VMSwitchName."VMQ".$NetAdapterName.BaseProcessorNumber -ge $NumaBaseProcNumber -and
            $g_VMHost.$VMSwitchName."VMQ".$NetAdapterName.MaxProcessorNumber -le $NumaMaxProcNumber 
        ) {
            Write-Host "OK: VMSwitchName=$VMSwitchName NetAdapterName=$NetAdapterName NumaNode=$VMQNumaNode CPU set is configured properly between $NumaBaseProcNumber and $NumaMaxProcNumber" -ForegroundColor Green    
        }
        else {
            Write-Host "ERROR: VMSwitchName=$VMSwitchName NetAdapterName=$NetAdapterName NumaNode=$VMQNumaNode CPU set is not configured properly | not between $NumaBaseProcNumber and $NumaMaxProcNumber" -ForegroundColor Red    
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
            Write-Host "##"
            Write-Host "### External VMSwitch  Name=$VMSwitchName" 
            Write-Host "##"
            
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
    
    Write-Host "-----------------------------------------------------"
    Write-Host "`tChecking HYPV HOST Netwokr topology"
    Write-Host "------------- ----------------------------------------"

    if ( -Not ( Test-Path $outputDir\Get-VMNetworkAdapter.json) ) {
        Write-Host "WARNING: HypvHost is not having MgmtOS vNIC means that this is not a converged NIC deployment" -ForegroundColor yellow 
        Write-Host "WARNING: Additionnally it appears that neighter MgmtOS and VM vNICs exist" -ForegroundColor yellow 
    }
    else {
        $VMNetworkAdapterMgmtOs = $( Get-Content $outputDir\Get-VMNetworkAdapter.json | ConvertFrom-Json ) | Where-Object { $_.IsManagementOs }

        if ( -Not $VMNetworkAdapterMgmtOs) {
            Write-Host "WARNING: HypvHost is not having MgmtOS vNIC means that this is not a converged NIC deployment" -ForegroundColor yellow 
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

###### 
####   Main
##

if ( Test-Path $outputDir) { Remove-Item $outputDir -Recurse -Force }

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

        Write-Host "-----------------------------------------------------"
        Write-Host "`tChecking VirtualNetwork optimization "
        Write-Host "-------------   ----------------------------------------"
        #
        CheckVMQandRSS
        #
        CheckNetworkTopology
    }
    else {
        Write-Host "Please zip and upload collected informations located in $outputDir to Microsoft Support using DTM workspace." -ForegroundColor Green
    }
}
else {
    MyError "ERROR: Hyper-V role appears to be not installed"
}

Write-Host "EOP : $PROGRAMNAME"

#rmdir $outputDir -Force 