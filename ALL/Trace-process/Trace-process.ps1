<#
.SYNOPSIS
    Collects IDNA aka Time Travel Traces for one or several running processes + run RADAR tools that helps reporting heap leaks or high heap memory
.DESCRIPTION
    Collects IDNA traces of processes provided in input with -IdnaProcessToTrace + plus ability to detect heap leak and high usage of one process.
    Combining both capabilities allow investigating potential memomry leak by identifying the memory allocation "unfreed" callstack. With the IDNA/TTD
    trace(s) of the process (and for involded processes for instance those doing memalloc from API). The tool is also dump the process list running on the 
    system before and after the execution.
.PARAMETER RadarLeakProcess
Optional parameter. Enable RADAR leak detection. Type the first letter of the service/process and then hit <TAB> for completion. Name is case sensitive.
    When RADAR attaches to a process, it starts collecting callstacks from all heap allocation calls. 
    When RADAR takes a snapshot, it produces a list of all unfreed heap allocations and their allocation callstacks. It reports every callstack once, with counts/sizes of the allocations.
.PARAMETER RadarLeakPath
    Path to rdrleakdiag.exe binary. Since RS5 rdrleakdiag is now an embedded tools.
.PARAMETER IdnaProcessToTrace
    Optional list of process to iDNA/TTD trace. Can be one or several process/service. Type the first letter of the service/process and then hit <TAB> for completion. Name is case sensitive. Separate each by a comma
.PARAMETER IdnaTimer
    Optional time in seconds the iDNA/TTD trace will run on. By default, if this option is not provided, collection will run during 30sec.
.PARAMETER IdnaPath
    Path to TTTracer.exe binary. Since RS5 TTTracer is now an embedded tools.
.PARAMETER LogPath
    Folder where all traces will be flushed on disk.
.PARAMETER ExtraCommands
    List of extra commands listed under a .txt file passed as an argument
.EXAMPLE
    .\Trace-Process.ps1 -RadarLeakProcess BFE -IdnaProcessToTrace BFE,IKEEXT -IdnaTimer 300 -LogPath C:\MS_DATA 
    Will collect iDNA trace of BFE and IKEEXT services for a duration of 300secs / 5 min. Then will generate a snap radar report to identify which memory allocation has not been freed during that time.
    Note that here -RadarExecutable and -IdnaExecutable has not been provided as those diag tools are embedded in latest Win10 RS5 versions 
.EXAMPLE
    .\Trace-Process.ps1 -RadarLeakProcess BFE -RadarLeakPath C:\temp\ -IdnaProcessToTrace BFE,IKEEXT -IdnaTimer 300 -IdnaPath C:\temp\TTT_x86_x64_external\x64\TTTracer.exe -LogPath C:\MS_DATA 
    Will collect iDNA trace of BFE and IKEEXT services for a duration of 300secs / 5 min. Then will generate a snap radar report to identify which memory allocation has not been freed during that time.
.NOTES
    Script developped by Vincent Douhet <vidou@microsoft.com> - Escalation Engineer / Microsoft Support CSS
        Please report him any issue using this script or regarding a ask in term of improvement and contribution

    DISCLAIMER:
    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

.LINK
    FAST ring : https://github.com/ViDou83/WinDiag/blob/master/Trace-Process.ps1
    SLOW ring : https://github.com/CSS-Windows/WindowsDiag/blob/master/ALL/Trace-process/Trace-process.ps1
#>

[CmdletBinding()]
Param (
    [Parameter(Mandatory = $false)] [String] $RadarLeakPath,
    [Parameter(Mandatory = $false)] [String]  $IdnaPath,
    [Parameter(Mandatory = $false)] $IdnaTimer,
    [Parameter(Mandatory = $false)] [String]  $LogPath,
    [Parameter(Mandatory = $false)] [String]  $CmdStartScript,
    [Parameter(Mandatory = $false)] [String]  $CmdStopScript
)
DynamicParam {
    # Set up the Run-Time Parameter Dictionary
    $RuntimeParameterDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary

    # Begin dynamic parameter definition
    $ParamName_IdnaProcessToTrace = 'IdnaProcessToTrace'
    $AttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
    $ParameterAttribute = New-Object System.Management.Automation.ParameterAttribute
    $ParameterAttribute.Mandatory = $true
    $ParameterAttribute.Position = 0
    $AttributeCollection.Add($ParameterAttribute)

    $ValidationValues += $(Get-Process).Name
    $ValidationValues += $(Get-Service).Name

    $ValidateSetAttribute = New-Object System.Management.Automation.ValidateSetAttribute([string[]]$ValidationValues)
    $AttributeCollection.Add($ValidateSetAttribute)
    $runtimeparameter = New-Object System.Management.Automation.RuntimeDefinedParameter($ParamName_IdnaProcessToTrace, [string[]], $AttributeCollection)
    $RuntimeParameterDictionary.Add($ParamName_IdnaProcessToTrace, $runtimeparameter)

    # Begin dynamic parameter definition
    $ParamName_RadarLeakProcess = 'RadarLeakProcess'
    $AttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
    $ParameterAttribute = New-Object System.Management.Automation.ParameterAttribute
    $ParameterAttribute.Mandatory = $true
    $ParameterAttribute.Position = 0
    $AttributeCollection.Add($ParameterAttribute)

    $ValidationValues += $(Get-Process).Name
    $ValidationValues += $(Get-Service).Name

    $ValidateSetAttribute = New-Object System.Management.Automation.ValidateSetAttribute($ValidationValues)
    $AttributeCollection.Add($ValidateSetAttribute)
    $runtimeparameter = New-Object System.Management.Automation.RuntimeDefinedParameter($ParamName_RadarLeakProcess, [string[]], $AttributeCollection)
    $RuntimeParameterDictionary.Add($ParamName_RadarLeakProcess, $runtimeparameter )
    
    # End Dynamic parameter definition

    # When done building dynamic parameters, return
    return $RuntimeParameterDictionary
}

Process {
    
    $RuntimeParameterDictionary.Values | ForEach-Object {
        if ( $_.Name -eq $ParamName_IdnaProcessToTrace ) {
            $IdnaProcessToTrace = $_.Value
        }
        elseif ( $_.Name -eq $ParamName_RadarLeakProcess ) {
            $RadarLeakProcess = $_.Value
        }
    } 

    $PROGRAMNAME = "Trace-Process"

    $Disclaimer = 
    '*****************************************************************************************************************************
    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE 
    WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN 
    AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
    DEALINGS IN THE SOFTWARE. 
*****************************************************************************************************************************
'

    Write-Host $Disclaimer -ForegroundColor Yellow

    # press a key to stop

    do {
        Write-Host "`n`n Please type y/Y if you want to execute this script or n/N if you don't !" -ForegroundColor Green
        $x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    } until ($x.Character -eq 'y' -or $x.Character -eq 'Y' -or $x.Character -eq 'n' -or $x.Character -eq 'N')

    if ( $x.Character -eq 'n' -or $x.Character -eq 'N') {
        Write-Host "INFO: Exiting $PROGRAMNAME as user requested" -ForegroundColor Yellow
        exit 1
    }

    Write-Host "$PROGRAMNAME is starting" 

    #TTD EULA
    if ( -Not ( Test-Path 'HKCU:\.DEFAULT\Software\Microsoft\TTD' ) ) {
        New-Item -PAth 'HKCU:\.DEFAULT\Software\Microsoft\TTD' -Force | Out-Null
    }

    if ( -Not ( Test-Path 'HKCU:\.DEFAULT\Software\Microsoft\TTT' ) ) {
        New-Item -PAth 'HKCU:\.DEFAULT\Software\Microsoft\TTT' -Force | Out-Null
    }
    
    if ( Test-Path 'HKCU:\.DEFAULT\Software\Microsoft\TTD' ) {
        New-ItemProperty -PAth 'HKCU:\.DEFAULT\Software\Microsoft\TTD' -Name EULASigned -Value 1 -PropertyType DWORD -Force | Out-Null   
    }

    if ( Test-Path 'HKCU:\.DEFAULT\Software\Microsoft\TTT' ) {
        New-ItemProperty -PAth 'HKCU:\.DEFAULT\Software\Microsoft\TTT' -Name EULASigned -Value 1 -PropertyType DWORD -Force | Out-Null    
    }

        #TTD inbox recorder is only available on Win10 RS5 devices with x86 or x64 architecture for OneCoreUAP and higher editions.
        if ( [System.Environment]::OSVersion.Version.Major -eq 10 -and [System.Environment]::OSVersion.Version.Build -ge 17763 ) {
            if ( $IdnaPath ) {
                Write-Host "INFO: native TTTracer will be used instead of the located one under $IdnaPath " -ForegroundColor Yellow
            } 
            $IdnaExe = "C:\Windows\system32\tttracer.exe"
        }
        else {
            if ( -Not $IdnaPath) { 
                Write-Host "ERROR: Please provide full path to tttracer.exe like this : C:\Users\vidou\Downloads\TTD_x86_x64_external\x64\TTTracer.exe " -ForegroundColor Red
                Write-Host "INFO: Ask Microsoft's support contact to provide the appropriate TTD version"
                exit 1     
            }
            #check if tttracer.exe well exist
            if (  Test-Path $IdnaPath ) {
                if ( Test-Path "$IdnaPath\TTTracer.exe" ) {
                    $IdnaExe = "$IdnaPath\TTTracer.exe" 
                    $null = $( "$IdnaExe -Initialize" | cmd ) 
                }
                else {
                    Write-Host "ERROR: TTTracer.exe is not located in : $LogPath" -ForegroundColor Red
                    exit 1     
                }
            }
            else { 
                Write-Host "ERROR: IdnaPath=$IdnaPath does not exist"  -ForegroundColor Red
                exit 1
            }
        }

        #Log into C:\temp by default
        if ( -Not $LogPath) { 
            $LogPath = "C:\temp" 
            Write-Host "INFO: option -LogDir has not been set hence the default location will be used: $LogPath"
        }

        $LogDir = "$LogPath\$($PROGRAMNAME)_$(Get-Date -Format "%H%m%y%s")"
        Write-Host "INFO: Data collection will be located under $LogDir" 

        #Default Idna will run for 30 seconds
        if ( -not $IdnaTimer) { 
            $IdnaTimer = 30 
            Write-Host "INFO: option -IdnaTimer was not set hence default time of 30Seconds will be used"
        }

        #Cleanup prior radar snaps
        $null = Remove-item $env:tmp\rdr* -Force -Confirm:$False -Recurse

        #Create LogDir if not exist
        if ( -Not $( Test-Path $LogDir) ) {
            if ( -Not $( Test-Path $LogPath ) ) { $null = mkdir $LogPath; $null = mkdir $LogDir }else { $null = mkdir $LogDir }
        }

        #Dump PRocess List prior execution
        tasklist /svc | Out-File $LogDir\$($env:COMPUTERNAME)_tasklist_before.txt

        #If extra commands, run those 1st
        if ( $CmdStartScript -and $CmdStopScript) {
            Write-Host "INFO: Run $CmdStartScript bunch of cmds"
            if ( ( Test-Path $CmdStartScript ) -and ( Test-Path $CmdStopScript ) ) {
                cmd /c $CmdStartScript $LogDir
            }
            else {
                Write-Host "ERROR: Does $CmdStartScript or $CmdStopScript is real file or filepath is the good one ?" -ForegroundColor Red
            } 
        }

        #RADAR leak detection wanted ?
        if ( $RadarLeakProcess) {
            $res = tasklist /Svc /FO CSV | findstr $RadarLeakProcess

            if ( -Not $res ) { 
                Write-Host "RADAR: Cannot find the processs/svc=$RadarLeakProcess as it doesn't exist. Please verify tasklist output as the ProcessName is case sensitive." -ForegroundColor Red
                Write-Host "RADAR: no RADAR leak detection enabled." -ForegroundColor Red
                $RadarLeakProcess = 0
            }
            else {
                $PidToTraceLeak = $res.split(",")[1].replace('"', '')

                Write-Host "RADAR: Starting reflection mode for process/service=$RadarLeakProcess PID=$PidToTraceLeak" -ForegroundColor Green

                if ( Test-Path "C:\Windows\System32\rdrleakdiag.exe" ) { 
                    if ( $RadarLeakPath ) {
                        Write-Host "INFO: native rdrleakdiag will be used instead of the located one under $RadarLeakPath " -ForegroundColor Yellow
                    } 
                    $RadarLeakExe = "C:\windows\system32\rdrleakdiag.exe"
                }
                else {
                    if ( Test-Path $RadarLeakPath ) {
                        if ( Test-Path "$RadarLeakPath\rdrleakdiag.exe" ) { $RadarLeakExe = "$RadarLeakPath\rdrleakdiag.exe" }
                        else { 
                            Write-Host "INFO: Please provide full path to rdrleakdiag.exe like this : C:\Users\vidou\Downloads\rdrleakdiag.exe as it is not apparently located under  " -ForegroundColor Yellow
                            Write-Host "INFO: Ask Microsoft's support contact to provide the appropriate rdrleakdiag.exe binary" 
                        }
                    }
                    else {
                        Write-Host "ERROR: RadarLeakPath=$RadarLeakPath does not exist"  -ForegroundColor Red
                    }
                    return 1;   
                }
                $null = $( "$RadarLeakExe -p $PidToTraceLeak -enable" | cmd )
            }
        }

        #Run one IDNA trace by svc/process provided
        $IdnaProcessToTrace | ForEach-Object {
            $svc = $_
            $res = tasklist /Svc /FO CSV | findstr $svc
            if ( $res ) { 
                $PidToIdna = $res.split(",")[1].replace('"', '')
                Write-Host "IDNA: Starting trace for processs/svc=$svc PID=$PidToIdna in background" -ForegroundColor Green
                $null = start-job -ScriptBlock { param($IdnaExe, $PidToIdna, $IdnaTimer, $svc, $LogDir) "$IdnaExe -attach $PidToIdna -timer $IdnaTimer -noUI -out $LogDir\$svc%.run" | cmd } -Arg $IdnaExe, $PidToIdna, $IdnaTimer, $svc, $LogDir
            }
            else {
                Write-Host "IDNA: Cannot trace processs/svc=$svc as it doesn't exist. Please verify tasklist output as the ProcessName is case sensitive." -ForegroundColor Red
            }
        }

        #Wait that all IDNA are stoped 
        Write-Host "IDNA: IDNA collection is running please wait - Traces will be collected during $IdnaTimer seconds / Don't close this window or don't press CTRL+C" -ForegroundColor Yellow
        Start-Sleep -Seconds $($IdnaTimer + 1)

        $IdnaTraces = $(Get-ChildItem $LogDir\*.run*).name
        if ( $IdnaTraces ) { 
            $IdnaTraces | ForEach-Object { 
                if ( $_ -match "err") {
                    Write-Host "IDNA: trace for is $_" -ForegroundColor Red
                }
                else {
                    Write-Host "IDNA: trace for is $_" -ForegroundColor Green 
                }
            }
        }
        else { 
            Write-Host "IDNA: Verify that trace has been properly collected" -ForegroundColor Yellow
        }


        #Dump PRocess List after execution
        tasklist /svc | Out-File $LogDir\$($env:COMPUTERNAME)_tasklist_after.txt

        #Radar snap
        if ( $RadarLeakProcess -ne 0) {
            Write-Host "RADAR: snap process=$RadarLeakProcess PID=$PidToTraceLeak" 
            Start-Sleep -Seconds 5
            $null = $( "$RadarLeakExe -p $PidToTraceLeak -snap -nowatson -nocleanup" | cmd )

            Start-Sleep -Seconds 1
            #Copy RADAR report to LogDir
            $null = Get-ChildItem  $env:tmp\rdr*.tmp | ForEach-Object { Copy-Item -Force -Recurse $_.FullName $LogDir }

            $RadarReport = $(Get-ChildItem $LogDir\rdr*).name
            if ($RadarReport) {
                Write-Host "RADAR: Report Name is $RadarReport" -ForegroundColor Green
                Write-Host "RADAR: Please refer to the following process to decode it https://osgwiki.com/wiki/Running_RADAR_locally" 
            }
            else {
                Write-Host "RADAR: Report Name is missing" -ForegroundColor Yellow
            }
        }

        #If extra commands, run those 1st
        if ( $CmdStartScript -and $CmdStopScript) {
            Write-Host "INFO: Run $CmdStopScript bunch of cmds"
            if ( ( Test-Path $CmdStartScript ) -and ( Test-Path $CmdStopScript ) ) {
                cmd /c $CmdStopScript
            }
            else {
                Write-Host "ERROR: Does $CmdStartScript or $CmdStopScript is real file or filepath is the good one ?" -ForegroundColor Red
            } 
        }

        Write-Host "INFO:  Please Zip and upload $LogDir content to MS support using DTM workspace" -ForegroundColor Yell
    
    }