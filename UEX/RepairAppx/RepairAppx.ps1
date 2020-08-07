# RepairAppx.ps1 - by nicolas.dietrich@microsoft.com
# Microsoft Customer Support and Services Modern Apps troubleshooting tool
# This tool is provided AS IS, no support nor warranty of any kind is provided for its usage.
# https://github.com/CSS-Windows/WindowsDiag/tree/master/UEX/RepairAppx

param (
  [string]$package, 
  [string]$action = "repair",
  [switch]$force = $false,
  [switch]$verbose = $false,
  [switch]$no_download = $false,
  [switch]$no_change = $false,
  [switch]$no_deps = $false
)

$VERSION =  "v1.9"
$SLEEP_DELAY =  1000
$CONFIG_COLUMN_PAD = 60
$global:mainPFNs = @()
$global:userRights = $false
$global:canInstallForAllUsers = $false
$global:allUsersSwitch = "-AllUsers"
$global:repairSucceeded = $false


Add-Type -AssemblyName System.ServiceModel
$BindingFlags = [System.Reflection.BindingFlags]::NonPublic -bor [System.Reflection.BindingFlags]::Static
[Windows.Management.Deployment.PackageManager,Windows.Management.Deployment,ContentType=WindowsRuntime] | Out-Null
[Windows.ApplicationModel.Store.Preview.InstallControl.AppInstallManager,Windows.ApplicationModel.Store.Preview.InstallControl,ContentType=WindowsRuntime] | Out-Null

# Credits for using IAsyncOperation from PS go to https://fleexlab.blogspot.com/2018/02/using-winrts-iasyncoperation-in.html
Add-Type -AssemblyName System.Runtime.WindowsRuntime
$asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]
Function Await($WinRtTask, $ResultType) {
  try {
    $asTask = $asTaskGeneric.MakeGenericMethod($ResultType)
    $netTask = $asTask.Invoke($null, @($WinRtTask))
    $netTask.Wait(-1) | Out-Null
    $netTask.Result
  }
  catch {
    $savedForegroundColor = $host.ui.RawUI.ForegroundColor
    $savedBackgroundColor = $host.ui.RawUI.BackgroundColor
    $host.ui.RawUI.ForegroundColor = "Red"
    $host.ui.RawUI.BackgroundColor = "Black"

    "Async call failed with:"    
    "  Exception Type: $($_.Exception.GetType().FullName)"
    "    Exception Message: $($_.Exception.Message)"

    ""
    $host.ui.RawUI.ForegroundColor = $savedForegroundColor
    $host.ui.RawUI.BackgroundColor = $savedBackgroundColor
  }
}

function ShowUsage()
{
  "USAGE:"
  "------"
  "  .\RepairAppx.ps1 -action <Action> <PACKAGE_NAME>"
  ""
  ""
  "EXAMPLE:"
  "--------"
  "  Repair Microsoft Photo app:"
  "    .\RepairAppx.ps1 *Photo*"
  ""
  "  Look for packages binaries corruption:"
  "    .\RepairAppx.ps1 -action verify *ExperiencePack*"
  ""
  "  Set Calc and its dependencies to modified appmodel state"
  "    .\RepairAppx.ps1 -action setstate *Calc*"
  ""
  "  List packages that depepnd on .NET Native framework 2.2"
  "    .\RepairAppx.ps1 -action depends *NET.Native.Runtime.2.2"
  ""
  "PARAMETERS:"
  "-----------"
  "  -action <Action>"
  "      repair     - [Default] Try to repair app package(s) and their dependencies by downloading them again"
  "      register   - Registers app package(s) and dependencies for the current user but doesn't repair files"
  "      verify     - Verify package(s) consistency by comparing the on-disk files with package declaration"
  ""
  "      setstate   - Sets package(s) and dependencies to modified state, to prepare downloaing them again"
  "      resetstate - Clears the modified state of package(s) and dependencies to get back to normal state"
  ""
  "      config     - Shows config settings related to AppStore, GPO and Windows Update"
  "      depends    - List dependees and dependencies of specified main package(s) or framework(s)"
  ""
  "      queue      - List active items in the download queue"
  "      cancel     - Cancels the Store active download queue"
  "      update     - Scan for all Store updates available (requires admin rights)"
  ""
  "  <PACKAGE_NAME>"
  "      Package(s) name(s) to work on."
  "      This switch can only be omited for a verify action, where it run on all packages for all users."
  "      Note: Wildcards are permitted, but should be used with caution to avoid repairing many packages at one time"
  ""
  "  [optional settings]"
  "    -verbose     - Used in conjonction to -verify, to output verbose about files being verified"
  "    -no_deps     - Do not try to repair frameworks / package dependencies"
  "    -no_change   - Only search for available package updates, do not modify any package"
  "    -no_check    - Do not show configuration settings"
  "    -no_cancel   - Do not cancel the current download queue items"
  "    -no_download - Avoid trying to to download package files from Windows Update"
  "    -no_clear    - Do not reset package status at the end of a repair operation"
  ""
  ""
  "DISCLAIMER:"
  "-----------"
  "  This tool is provided AS IS, no support nor warranty of any kind is provided for its usage."
  ""
}

function CheckConfig()
{
  "Checking Store and Windows Update configuration:"
  "------------------------------------------------"

  $privatestore = $false
  $nostoreaccess = $false

  " Current context:"
  $winVer = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion")
  "   - OS".PadRight($CONFIG_COLUMN_PAD," ") + $winVer.ProductName + " " + $winVer.ReleaseId + " (build " + $winVer.CurrentBuildNumber + ")"
  "   - UserName".PadRight($CONFIG_COLUMN_PAD," ") + [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
  "   - ComputerName".PadRight($CONFIG_COLUMN_PAD," ") + $env:ComputerName
  "   - Security".PadRight($CONFIG_COLUMN_PAD," ") + $global:userRights
  
  ""
   
  " AppManager properties:"
  if ($global:canInstallForAllUsers -eq $true) { $val = "Yes" } elseif ($global:canInstallForAllUsers -eq $false) { $val = "No" } else { $val = $global:canInstallForAllUsers }
  if ($global:allUsersSwitch -ne '') { $val += " (will use '$allUsersSwitch')"}
  "   - CanInstallForAllUsers".PadRight($CONFIG_COLUMN_PAD," ") + $val

  try {
    $val = $appInstallManager.AutoUpdateSetting 
    }
  catch {
    $val = "N/A"    
  }
  "   - AutoUpdateSetting".PadRight($CONFIG_COLUMN_PAD," ") + $val
   
  try {
    if (Await ($appInstallManager.IsStoreBlockedByPolicyAsync("Microsoft.WindowsStore", "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US")) ([bool]))
    {
      $nostoreaccess = $true
      $val = "blocked"
    }
    else {
      $val = "NOT blocked"
    }
  }
  catch {
    $val = "N/A"    
  }
  "   - IsStoreBlockedByPolicy".PadRight($CONFIG_COLUMN_PAD," ") + $val

  ""
  " Services:"
  $service = Get-Service -Name "AppxSvc"
  "   - $($service.Name) ($($service.DisplayName))".PadRight($CONFIG_COLUMN_PAD," ") + $($service.Status)

  $service = Get-Service -Name "AppReadiness"
  "   - $($service.Name) ($($service.DisplayName))".PadRight($CONFIG_COLUMN_PAD," ") + $($service.Status)

  $service = Get-Service -Name "StorSvc"
  "   - $($service.Name) ($($service.DisplayName))".PadRight($CONFIG_COLUMN_PAD," ") + $($service.Status)

  ""
  " User Profile:"
  $key = "AllowDeploymentInSpecialProfiles"
  $val = (Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\Appx -Name $key -ErrorAction SilentlyContinue).$key
  if ($val) {$msg = "   - $key".PadRight($CONFIG_COLUMN_PAD," ") + "is set to $($val)"; $nostoreaccess = $true} else {$msg = "   - $key".PadRight($CONFIG_COLUMN_PAD," ") + "is not set"}
  "$msg"

  $key = "SpecialRoamingOverrideAllowed"
  $val = (Get-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name $key -ErrorAction SilentlyContinue).$key
  if ($val) {$msg = "   - $key".PadRight($CONFIG_COLUMN_PAD," ") + "is set to $($val)"; $nostoreaccess = $true} else {$msg = "   - $key".PadRight($CONFIG_COLUMN_PAD," ") + "is not set"}
  "$msg"

  ""
  " Group Policies:"
  $key = "RemoveWindowsStore"
  $val = (Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\WindowsStore\ -Name $key -ErrorAction SilentlyContinue).$key
  if ($val) {$msg = "   - $key".PadRight($CONFIG_COLUMN_PAD," ") + "is set to $($val) in HKLM"} else {$msg = "   - $key".PadRight($CONFIG_COLUMN_PAD," ") + "is not set in HKLM"}
  $msg = $msg.PadRight($CONFIG_COLUMN_PAD+19," ")
  $val = (Get-ItemProperty -Path HKCU:\Software\Policies\Microsoft\WindowsStore\ -Name $key -ErrorAction SilentlyContinue).$key
  if ($val) {$msg += "and is set to $($val) in HKCU"} else {$msg += "and is not set in HKCU"}
  "$msg"
  
  $key = "RequirePrivateStoreOnly"
  $val = (Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\WindowsStore\ -Name $key -ErrorAction SilentlyContinue).$key
  if ($val) {$msg = "   - $key".PadRight($CONFIG_COLUMN_PAD," ") + "is set to $($val) in HKLM"} else {$msg = "   - $key".PadRight($CONFIG_COLUMN_PAD," ") + "is not set in HKLM"}
  $msg = $msg.PadRight($CONFIG_COLUMN_PAD+19," ")
  $val = (Get-ItemProperty -Path HKCU:\Software\Policies\Microsoft\WindowsStore\ -Name $key -ErrorAction SilentlyContinue).$key
  if ($val) {$msg += "and is set to $($val) in HKCU"; $privatestore = $true} else {$msg += "and is not set in HKCU"}
  "$msg"

  $key = "DisableStoreApps"
  $val = (Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\WindowsStore\ -Name $key -ErrorAction SilentlyContinue).$key
  if ($val) {$msg = "   - $key".PadRight($CONFIG_COLUMN_PAD," ") + "is set to $($val) in HKLM"} else {$msg = "   - $key".PadRight($CONFIG_COLUMN_PAD," ") + "is not set in HKLM"}
  $msg = $msg.PadRight($CONFIG_COLUMN_PAD+19," ")
  $val = (Get-ItemProperty -Path HKCU:\Software\Policies\Microsoft\WindowsStore\ -Name $key -ErrorAction SilentlyContinue).$key
  if ($val) {$msg += "and is set to $($val) in HKCU"} else {$msg += "and is not set in HKCU"}
  "$msg" 
  
  $key = "NoUseStoreOpenWith"
  $val = (Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\ -Name $key -ErrorAction SilentlyContinue).$key
  if ($val) {$msg = "   - $key".PadRight($CONFIG_COLUMN_PAD," ") + "is set to $($val) in HKLM"} else {$msg = "   - $key".PadRight($CONFIG_COLUMN_PAD," ") + "is not set in HKLM"}
  $msg = $msg.PadRight($CONFIG_COLUMN_PAD+19," ")
  $val = (Get-ItemProperty -Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer\ -Name $key -ErrorAction SilentlyContinue).$key
  if ($val) {$msg += "and is set to $($val) in HKCU"} else {$msg += "and is not set in HKCU"}
  "$msg"
  
  $key = "AutoDownload"
  $val = (Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\WindowsStore\ -Name $key -ErrorAction SilentlyContinue).$key
  if ($val) {$msg = "   - $key".PadRight($CONFIG_COLUMN_PAD," ") + "is set to $($val) in HKLM"} else {$msg = "   - $key".PadRight($CONFIG_COLUMN_PAD," ") + "is not set in HKLM"}
  $msg = $msg.PadRight($CONFIG_COLUMN_PAD+19," ")
  $val = (Get-ItemProperty -Path HKCU:\Software\Policies\Microsoft\WindowsStore\ -Name $key -ErrorAction SilentlyContinue).$key
  if ($val) {$msg += "and is set to $($val) in HKCU"} else {$msg += "and is not set in HKCU"}
  "$msg"
  
  $key = "SetDisableUXWUAccess"
  $val = (Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\WindowsStore\ -Name $key -ErrorAction SilentlyContinue).$key
  if ($val) {$msg = "   - $key".PadRight($CONFIG_COLUMN_PAD," ") + "is set to $($val) in HKLM"} else {$msg = "   - $key".PadRight($CONFIG_COLUMN_PAD," ") + "is not set in HKLM"}
  $msg = $msg.PadRight($CONFIG_COLUMN_PAD+19," ")
  $val = (Get-ItemProperty -Path HKCU:\Software\Policies\Microsoft\WindowsStore\ -Name $key -ErrorAction SilentlyContinue).$key
  if ($val) {$msg += "and is set to $($val) in HKCU"} else {$msg += "and is not set in HKCU"}
  "$msg"
  
  $key = "DoNotConnectToWindowsUpdateInternetLocations"
  $val = (Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name $key -ErrorAction SilentlyContinue).$key
  if ($val) {$msg = "   - $key".PadRight($CONFIG_COLUMN_PAD," ") + "is set to $($val) in HKLM"} else {$msg = "   - $key".PadRight($CONFIG_COLUMN_PAD," ") + "is not set in HKLM"}
  $msg = $msg.PadRight($CONFIG_COLUMN_PAD+19," ")
  $val = (Get-ItemProperty -Path HKCU:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name $key -ErrorAction SilentlyContinue).$key
  if ($val) {$msg += "and is set to $($val) in HKCU"; $nostoreaccess = $true} else {$msg += "and is not set in HKCU"}
  "$msg"

  ""
  " Windows Update:"
  $MUSM = New-Object -ComObject "Microsoft.Update.ServiceManager"
  $val = ($MUSM.Services | Where-Object IsDefaultAUService | Select-Object Name).Name
  "   - Default Update Service".PadRight($CONFIG_COLUMN_PAD," ") + $val

  $val = ($MUSM.Services | Where-Object ServiceId -Match "855e8a7c-ecb4-4ca3-b045-1dfa50104289").ServiceUrl
  $response = try { (Invoke-WebRequest -UseDefaultCredentials -URI $val -ErrorAction Stop).BaseRequest } catch { $_.Exception.Response }
  "   - WU Test ($val)".PadRight($CONFIG_COLUMN_PAD," ") + "$(if (!@(200, 403) -contains ([int]$response.StatusCode)) {'DOES NOT '; $nostoreaccess = $true})looks reachable"

  ""
  if ($privatestore)  { "WARNING: You use the private store, please ensure you have added the apps there for the repair to work."; "" }
  if ($nostoreaccess) { "WARNING: Your settings block Windows Update from accessing internet, the script will likely not be able to re-download apps and fix file corruptions."; "" }
}

function CleanupUpdateQueue()
{
  $queuedApps = $appInstallManager.AppInstallItems

  "Cancelling any active update:"
  "-----------------------------"
  if (!$queuedApps.length) { "  No installation or update is in the active queue."}
  foreach($queuedApp in $queuedApps)
  {
    # Do not cancel Store app update to avoid leaving it in an unconsistent state
    if ($queuedApp.PackageFamilyName -like '*Microsoft.WindowsStore*') {
      "WARNING: The store app is currently being updated. You may have to run again the script once it will be completed."
    }
    else {
      "  - Cancelling update for $($queuedApp.PackageFamilyName)"
      $queuedApp.Cancel()
    }
  }
  ""
}

function ListUpdateQueue()
{
  $queuedApps = $appInstallManager.AppInstallItems

  "Active update queue:"
  "--------------------"
  if (!$queuedApps.length) { "  No installation or update is in the active queue."}
  foreach($queuedApp in $queuedApps)
  {
    $status = $queuedApp.GetCurrentStatus()
    $currentstate = [Windows.ApplicationModel.Store.Preview.InstallControl.AppInstallState]$status.InstallState
    "  - $($queuedApp.PackageFamilyName) is in state $currentstate"
  }
  ""
}

function SetPackageToModifiedState()
{
  $packages = Invoke-Expression "Get-AppXPackage $global:allUsersSwitch $package"
  $packageManager = New-Object Windows.Management.Deployment.PackageManager

  "Setting following packages to modified state:"
  "---------------------------------------------"

  foreach ($p in $packages)
  {
    "  - $($p.PackageFullName)"
    $global:mainPFNs += $p.PackageFamilyName
    $packageManager.SetPackageStatus($p.PackageFullName, [Windows.Management.Deployment.PackageStatus]::Modified)
    
    if ($no_deps)
    {
      "  - [No dependencies processing was requested]"
    }
    else
    {
      ForEach ($dependencies in (Get-AppxPackageManifest $p.PackageFullName).package.dependencies.packagedependency.name) 
      {
        $dep = Invoke-Expression "Get-AppXPackage $global:allUsersSwitch -PackageTypeFilter Framework $dependencies"
        ForEach ($d in $dep) 
        {
          "  - " + $d.PackageFullName
          $packageManager.SetPackageStatus($d.PackageFullName, [Windows.Management.Deployment.PackageStatus]::Modified)
        }
      }
    }
  }
  ""
}

function ClearPackageFromModifiedState()
{
  $packages = Invoke-Expression "Get-AppXPackage $global:allUsersSwitch -PackageTypeFilter Main $package"
  $packageManager = New-Object Windows.Management.Deployment.PackageManager

  "Resetting state of following packages:"
  "--------------------------------------"

  foreach ($p in $packages)
  {
    "  - $($p.PackageFullName)"
    $packageManager.ClearPackageStatus($p.PackageFullName, [Windows.Management.Deployment.PackageStatus]::Modified)
    
    if ($no_deps)
    {
      "  - [No dependencies processing was requested]"
    }
    else
    {
      ForEach ($dependencies in (Get-AppxPackageManifest $p.PackageFullName).package.dependencies.packagedependency.name) 
      {
        $dep = Invoke-Expression "Get-AppXPackage $global:allUsersSwitch -PackageTypeFilter Framework $dependencies"
        ForEach ($d in $dep) 
        {
          "  - " + $d.PackageFullName
          $packageManager.ClearPackageStatus($d.PackageFullName, [Windows.Management.Deployment.PackageStatus]::Modified)
        }
      }
    }
  }
  ""
}

function RegisterPackageAndDeps()
{
  $packages = Invoke-Expression "Get-AppXPackage $global:allUsersSwitch $package"

  "Force registering following packages:"
  "-------------------------------------"

  foreach ($p in $packages)
  {
    if ($no_deps)
    {
      "  - [No dependencies processing was requested]"
    }
    else
    {
      ForEach ($dependencies in (Get-AppxPackageManifest $p.PackageFullName).package.dependencies.packagedependency.name) 
      {
        $dep = Invoke-Expression "Get-AppXPackage $global:allUsersSwitch -PackageTypeFilter Framework $dependencies"
        ForEach ($d in $dep) 
        {
          "  - " + $d.PackageFullName
          $manifestPath = Join-Path -Path $d.InstallLocation -ChildPath "AppxManifest.xml"
          if (Test-Path($manifestPath))
          {
            # Masking errors especially for frequent "Deployment failed with HRESULT: 0x80073D06, The package could not be installed because a higher version of this package is already installed."
            Add-AppxPackage -DisableDevelopmentMode -ForceApplicationShutdown -register  $manifestPath -ErrorAction SilentlyContinue
          }
          else {
            "    -> Can't find Manifest to register: " + $manifestPath
          }
        }
      }
    }
    $manifestPath = Join-Path -Path $p.InstallLocation -ChildPath "AppxManifest.xml"
    if (Test-Path($manifestPath))
    {
      Add-AppxPackage -DisableDevelopmentMode -ForceApplicationShutdown -register  $manifestPath
    }
    else {
      "    -> Can't find Manifest to register: " + $manifestPath
    }
  }
  ""
}

function SearchForPFNUpdates()
{
  $global:ProgressPreference = 'Continue'
  $finished = $true

  foreach($packageFamilyName in $global:mainPFNs)
  {
    "Looking for available Apps Store updates:"
    "-----------------------------------------"

    try
    {
      $finished = $true
      $appinstalls = Await ($appInstallManager.UpdateAppByPackageFamilyNameAsync($packageFamilyName)) ([Windows.ApplicationModel.Store.Preview.InstallControl.AppInstallItem])
      if ($appinstalls.Length -eq 0) 
      { 
        "Package Manager didn't return any package to download for this family name!"
        ""
        SearchForAllUpdates
      }
      else
      {
        foreach($appinstall in $appinstalls)
        {
          if ($appinstall.PackageFamilyName)
          {
            try { $appstoreaction = "to " + ([Windows.ApplicationModel.Store.Preview.InstallControl.AppInstallType]$appinstall.InstallType) } catch { $appstoreaction = "" }
            "  - Requesting $($appinstall.PackageFamilyName) $appstoreaction"
            Start-Sleep -Milliseconds $SLEEP_DELAY
            $finished = $false
          }
        }
        
        ""
        "Running the update process:"
        "---------------------------"
        while (!$finished)
        {
          $finished = $true        
          for ($index=0; $index -lt $appinstalls.Length; $index++)
          {
            $appUpdate = $appinstalls[$index]
            $packageFamilyName = $appUpdate.PackageFamilyName
            $status = $appUpdate.GetCurrentStatus()
            $currentstate = [Windows.ApplicationModel.Store.Preview.InstallControl.AppInstallState]$status.InstallState

            if (!($status.PercentComplete -eq 100) -and !($status.ErrorCode))
            {
              Write-Progress -Id $index -Activity $packageFamilyName -status ("$currentstate $([Math]::Round($status.BytesDownloaded/1024).ToString('N0'))kb ($($status.PercentComplete)%)") -percentComplete $status.PercentComplete
    
              if ($finished)
              {
                $finished = $false
              }
            }
          }
          Start-Sleep -Milliseconds $SLEEP_DELAY
        }
        for ($index=0; $index -lt $appinstalls.Length; $index++)
        {
          $appUpdate = $appinstalls[$index]
          $packageFamilyName = $appUpdate.PackageFamilyName
          $status = $appUpdate.GetCurrentStatus()
          $currentstate = [Windows.ApplicationModel.Store.Preview.InstallControl.AppInstallState]$status.InstallState
    
          if ($status.PercentComplete -eq 100)
          {
            Write-Progress -Id $index -Activity $packageFamilyName -Status "Completed" -Completed
            "  -> $packageFamilyName ended as $currentstate $(if ($status.ReadyForLaunch) {"and reports now to be READY FOR LAUNCH!"} Else {"and is NOT ready for launch"})"
            $global:repairSucceeded = $true
          }
          elseif ($status.ErrorCode)
          {
            "  -> $packageFamilyName failed with Error $status.ErrorCode / $currentstate"
            Write-Progress -Id $index -Activity $packageFamilyName -Status $msg -Completed
          }
        }
        ""
        "The store apps update process ended for $($appinstalls.Length) packages"
        ""
      }
    }
    catch
    {
        $savedForegroundColor = $host.ui.RawUI.ForegroundColor
        $savedBackgroundColor = $host.ui.RawUI.BackgroundColor
        $host.ui.RawUI.ForegroundColor = "Red"
        $host.ui.RawUI.BackgroundColor = "Black"

        "Exception Type: $($_.Exception.GetType().FullName)"
        "    Exception Message: $($_.Exception.Message)"
 
  #      "Trying to open the Microsoft Store, please check the ongoing downloads and try to update it there."
  #      Invoke-Expression "ms-windows-store://pdp/?PFN=$($global:mainPFN)"

        ""
        "Going to reset package status to get back to a normal state"
        $host.ui.RawUI.ForegroundColor = $savedForegroundColor
        $host.ui.RawUI.BackgroundColor = $savedBackgroundColor
        ""
      }
    }
}
function SearchForAllUpdates()
{
  $global:ProgressPreference = 'Continue'
  $finished = $true

  "Looking for all available Apps Store updates:"
  "---------------------------------------------"

  try
  {
    $appinstalls = Await ($appInstallManager.SearchForAllUpdatesAsync()) ([System.Collections.Generic.IReadOnlyList[Windows.ApplicationModel.Store.Preview.InstallControl.AppInstallItem]])

    if ($appinstalls.Length -eq 0) 
    { 
      "Package Manager didn't return any package to download for the machine!"
    }
    else
    {
      foreach($appinstall in $appinstalls)
      {
        if ($appinstall.PackageFamilyName)
        {
          try { $appstoreaction = "to " + ([Windows.ApplicationModel.Store.Preview.InstallControl.AppInstallType]$appinstall.InstallType) } catch { $appstoreaction = "" }
          "  - Requesting $($appinstall.PackageFamilyName) $appstoreaction"
          Start-Sleep -Milliseconds $SLEEP_DELAY
          $finished = $false
        }
      }

    ""
    "Running the update process:"
    "---------------------------"
    while (!$finished)
    {
      $finished = $true
      for ($index=0; $index -lt $appinstalls.Length; $index++)
      {
        $appUpdate = $appinstalls[$index]
        $packageFamilyName = $appUpdate.PackageFamilyName
        $status = $appUpdate.GetCurrentStatus()
        $currentstate = [Windows.ApplicationModel.Store.Preview.InstallControl.AppInstallState]$status.InstallState

        if (!($status.PercentComplete -eq 100) -and !($status.ErrorCode))
        {
          Write-Progress -Id $index -Activity $packageFamilyName -status ("$currentstate $([Math]::Round($status.BytesDownloaded/1024).ToString('N0'))kb ($($status.PercentComplete)%)") -percentComplete $status.PercentComplete

          if ($finished)
          {
            $finished = $false
          }
        }
      }
      Start-Sleep -Milliseconds $SLEEP_DELAY
    }
    for ($index=0; $index -lt $appinstalls.Length; $index++)
    {
      $appUpdate = $appinstalls[$index]
      $packageFamilyName = $appUpdate.PackageFamilyName
      $status = $appUpdate.GetCurrentStatus()
      $currentstate = [Windows.ApplicationModel.Store.Preview.InstallControl.AppInstallState]$status.InstallState

      if ($status.PercentComplete -eq 100)
      {
        Write-Progress -Id $index -Activity $packageFamilyName -Status "Completed" -Completed
        "  -> $packageFamilyName ended as $currentstate $(if ($status.ReadyForLaunch) {"and reports now to be READY FOR LAUNCH!"} Else {"and is NOT ready for launch"})"
        $global:repairSucceeded = $true
      }
      elseif ($status.ErrorCode)
      {
        "  -> $packageFamilyName failed with Error $status.ErrorCode / $currentstate"
        Write-Progress -Id $index -Activity $packageFamilyName -Status $msg -Completed
      }
    }
    ""
    "The store apps update process ended for $($appinstalls.Length) packages"
    ""
  }
}
catch
{
    $savedForegroundColor = $host.ui.RawUI.ForegroundColor
    $savedBackgroundColor = $host.ui.RawUI.BackgroundColor
    $host.ui.RawUI.ForegroundColor = "Red"
    $host.ui.RawUI.BackgroundColor = "Black"

    "Exception Type: $($_.Exception.GetType().FullName)"
    "    Exception Message: $($_.Exception.Message)"

#      "Trying to open the Microsoft Store, please check the ongoing downloads and try to update it there."
#      Invoke-Expression "ms-windows-store://pdp/?PFN=$($global:mainPFN)"

    ""
    "Going to reset package status to get back to a normal state"
    $host.ui.RawUI.ForegroundColor = $savedForegroundColor
    $host.ui.RawUI.BackgroundColor = $savedBackgroundColor
    ""
  }
}

function ReinstallStore()
{
  try {
    $appinstalls = Await ($appInstallManager.StartAppInstallAsync("9WZDNCRFJBMP", "", $true, $true)) ([Windows.ApplicationModel.Store.Preview.InstallControl.AppInstallItem])
    if ($appinstalls.Length -eq 0) 
    { 
      "Package Manager didn't return any package to download for this reinstall"
      ""
    }
    else
    {
      foreach($appinstall in $appinstalls)
      {
        if ($appinstall.PackageFamilyName)
        {
          try { $appstoreaction = "to " + ([Windows.ApplicationModel.Store.Preview.InstallControl.AppInstallType]$appinstall.InstallType) } catch { $appstoreaction = "" }
          "  - Requesting $($appinstall.PackageFamilyName) $appstoreaction"
          Start-Sleep -Milliseconds $SLEEP_DELAY
          $finished = $false
        }
      }
      
      ""
      "Running the update process:"
      "---------------------------"
      while (!$finished)
      {
        $finished = $true        
        for ($index=0; $index -lt $appinstalls.Length; $index++)
        {
          $appUpdate = $appinstalls[$index]
          $packageFamilyName = $appUpdate.PackageFamilyName
          $status = $appUpdate.GetCurrentStatus()
          $currentstate = [Windows.ApplicationModel.Store.Preview.InstallControl.AppInstallState]$status.InstallState

          if (!($status.PercentComplete -eq 100) -and !($status.ErrorCode))
          {
            Write-Progress -Id $index -Activity $packageFamilyName -status ("$currentstate $([Math]::Round($status.BytesDownloaded/1024).ToString('N0'))kb ($($status.PercentComplete)%)") -percentComplete $status.PercentComplete

            if ($finished)
            {
              $finished = $false
            }
          }
        }
        Start-Sleep -Milliseconds $SLEEP_DELAY
      }
      for ($index=0; $index -lt $appinstalls.Length; $index++)
      {
        $appUpdate = $appinstalls[$index]
        $packageFamilyName = $appUpdate.PackageFamilyName
        $status = $appUpdate.GetCurrentStatus()
        $currentstate = [Windows.ApplicationModel.Store.Preview.InstallControl.AppInstallState]$status.InstallState

        if ($status.PercentComplete -eq 100)
        {
          Write-Progress -Id $index -Activity $packageFamilyName -Status "Completed" -Completed
          "  -> $packageFamilyName ended as $currentstate $(if ($status.ReadyForLaunch) {"and reports now to be READY FOR LAUNCH!"} Else {"and is NOT ready for launch"})"
          $global:repairSucceeded = $true
        }
        elseif ($status.ErrorCode)
        {
          "  -> $packageFamilyName failed with Error $status.ErrorCode / $currentstate"
          Write-Progress -Id $index -Activity $packageFamilyName -Status $msg -Completed
        }
      }
      ""
      "The store apps update process ended for $($appinstalls.Length) packages"
      ""
    }
  }
  catch
  {
      $savedForegroundColor = $host.ui.RawUI.ForegroundColor
      $savedBackgroundColor = $host.ui.RawUI.BackgroundColor
      $host.ui.RawUI.ForegroundColor = "Red"
      $host.ui.RawUI.BackgroundColor = "Black"

      "Exception Type: $($_.Exception.GetType().FullName)"
      "    Exception Message: $($_.Exception.Message)"

  #      "Trying to open the Microsoft Store, please check the ongoing downloads and try to update it there."
  #      Invoke-Expression "ms-windows-store://pdp/?PFN=$($global:mainPFN)"

      ""
      "Going to reset package status to get back to a normal state"
      $host.ui.RawUI.ForegroundColor = $savedForegroundColor
      $host.ui.RawUI.BackgroundColor = $savedBackgroundColor
      ""
    }
}

function VerifyPackagesConsistency()
{
  "Checking packages consistency:"
  "------------------------------"
  if (!$package)
  {
    $package = "*"
  }

  $packages = Invoke-Expression "Get-AppXPackage $global:allUsersSwitch $package" | Where-Object {$_.InstallLocation}
  $invalidPackages = 0
  $packagesIndex = 0

  Foreach ($pack in $packages)
  { 
    $packagesIndex++
    "Checking package $($packagesIndex.ToString("000")) / $($packages.Count.ToString("000")) - $($pack.Name)"
    if ($verbose)
    {
      "  Installed in $($pack.InstallLocation)"
    }

    # Reading the AppxBlockMap file and compare each of the expected file with size on-disk 
    $appxBlockMap = $pack.InstallLocation + "\AppxBlockMap.xml"
    if (!(Test-Path $appxBlockMap))
    {
      "  WARNING - No .appxBlockMap file found inside package $($pack.Name)"
      $expectedPackageSize = -1
    }
    else
    {
      $expectedPackageSize = 0
      $realPackageSize = 0
      $missingFiles = 0

      Foreach ($expectedFile in (Select-Xml "/" -Path $appxBlockMap).node.BlockMap.File)
      {
        $realFilePath = $pack.InstallLocation + "\" + $expectedFile.Name
        $expectedFileSize = $expectedFile.Size -as [int]
        $expectedPackageSize = $expectedPackageSize + $expectedFileSize
        if (!(Test-Path $realFilePath))
        {  
            "  WARNING - File not found : $($expectedFile.Name)"
            $missingFiles++
        }
        else
        {
          $realFileSize = (Get-Item $realFilePath).length
          $realPackageSize += $realFileSize
          if ($realFileSize -ne $expectedFileSize)
          {
            "  WARNING - Unexpected size: $($expectedFile.Name) should be $expectedFileSize bytes but is $realFileSize bytes"
          }
          elseif ($verbose)
          {
            "  - $($expectedFile.Name) is as expected $expectedFileSize bytes"
          }
        }
      }
    }

    if ($expectedPackageSize -ne $realPackageSize)
    {
      "=> PACKAGE INVALID $($pack.Name) expected to sum $expectedPackageSize bytes, but is $realPackageSize bytes $(if ($missingFiles -ne 0) {"with $missingFiles files missing"} else {"with no file missing"})"
      ""
      $invalidPackages++
    }
    elseif ($verbose)
    {
      "-> PACKAGE VALID $($pack.Name) sums as expected $expectedPackageSize bytes"
      ""
    }
  }

  if ($packagesIndex -eq 0)
  {
    "==> NO PACKAGE FOUND TO CHECK <=="
    "Please review your package name and rerun with -verbose"
  }
  elseif ($invalidPackages -eq 0)
  {
    "==> NO ERROR FOUND IN " + $packagesIndex + " PACKAGES CHECKED <=="
  }
  else
  {
    ""
    "!!! $invalidPackages INVALID PACKAGES WERE FOUND IN $packagesIndex PACKAGES CHECKED !!!"
  }
  ""
}

function LookForDependencies()
{
  $dependees = Invoke-Expression "Get-AppXPackage $global:allUsersSwitch $package"

  ForEach ($dependee in $dependees)
  { 
    "Listing dependencies of $($dependee.PackageFullName)"
    ForEach ($d in (Get-AppxPackageManifest $dependee).package.dependencies.packagedependency.name) 
    { 
      "  - $d"
    }
    ""
  }
}

function LookForDependees()
{
  $dependencies = Invoke-Expression "Get-AppXPackage $global:allUsersSwitch $package"

  ForEach ($dependency in $dependencies) 
  { 
    "Listing packages depending on $dependency"
    ForEach ($p in $(Invoke-Expression "Get-AppxPackage $global:allUsersSwitch")) 
    { 
      ForEach ($d in (Get-AppxPackageManifest $p).package.dependencies.packagedependency.name) 
      { 
        if ($d -eq $dependency.Name) 
        {
          "  - $p"
        }
      }
    }
    ""
  }
}

function CheckAdminRights()
{
  $isAdmin = $false

  try {
    $bytes = New-Object -TypeName byte[](4)
    $hToken = ([System.ServiceModel.PeerNode].Assembly.GetType('System.ServiceModel.Channels.AppContainerInfo')).GetMethod('GetCurrentProcessToken', $BindingFlags).Invoke($null, @())
    ([System.ServiceModel.PeerNode].Assembly.GetType('System.ServiceModel.Activation.Utility')).GetMethod('GetTokenInformation', $BindingFlags).Invoke($null, @($hToken, 18, [byte[]]$bytes))
    if ($bytes[0] -eq 1)
    {
        $GetTokenInformation.Invoke($null, @($hToken, 20, [byte[]]$bytes)) # TokenElevation
        if ($bytes[0])   { $global:userRights = "UAC disabled but token elevated (Build-in Admin)"; $isAdmin = $true} 
        else             { $global:userRights = "UAC is disabled and not elevated" }
    }
    if ($bytes[0] -eq 2) { $global:userRights = "UAC enabled and token elevated (Run As Admin)"; $isAdmin = $true }
    if ($bytes[0] -eq 3) { $global:userRights = "UAC enabled and token NOT elevated" }
  }
  catch {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
      $global:userRights = "Administrator"
      $isAdmin = $true
    }
    else {
      $global:userRights = "NOT Administrator"
    }
  }

  try {
    $global:canInstallForAllUsers = $appInstallManager.CanInstallForAllUsers
  }
  catch {
    $global:canInstallForAllUsers = "N/A"    
  }
  finally {
    if (($global:canInstallForAllUsers -ne $true) -and (!$isAdmin)) { $global:allUsersSwitch = ""} 
  }
}


""
"RepairAppx $VERSION - Repair & troubleshooting tool for AppX packages"
"This tool is provided AS IS, no support nor warranty of any kind is provided for its usage."
""
"Command line run: " + $MyInvocation.Line
""
$appInstallManager = New-Object Windows.ApplicationModel.Store.Preview.InstallControl.AppInstallManager
CheckAdminRights

switch ( $action )
{
  "config"      { CheckConfig; exit }
  "verify"      { VerifyPackagesConsistency; exit }
  "setstate"    { SetPackageToModifiedState; exit }
  "resetstate"  { ClearPackageFromModifiedState; exit }
  "depends"     { LookForDependencies; LookForDependees; exit }
  "queue"       { ListUpdateQueue; exit }
  "cancel"      { CleanupUpdateQueue; exit }
  "update"      { CheckConfig; SearchForAllUpdates; exit }
  "register"    { RegisterPackageAndDeps; exit }
  "repair"      {
    if (!$package)      { ShowUsage; exit } 
    if (!$no_check)     { CheckConfig                   } else { "No config check was requested." }
    if (!$no_cancel)    { CleanupUpdateQueue            } else { "No active queue cleanup was requested." }
    if (!$no_change)    { SetPackageToModifiedState     } else { "No package state change was requested." }
    if (!$no_download)  { SearchForPFNUpdates           } else { "No package download was requested." }
    if ($force -and !$global:repairSucceeded)
    {
      $savedForegroundColor = $host.ui.RawUI.ForegroundColor
      $savedBackgroundColor = $host.ui.RawUI.BackgroundColor
      $host.ui.RawUI.ForegroundColor = "Red"
#      $host.ui.RawUI.BackgroundColor = "Black"

      "Couldn't automate Windows Update, running its scheduled task as a fallback:"

      New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\InstallService\State" -Name "AutoUpdateLastSuccessTime" -Value "2010-01-01 00:00:00" -PropertyType STRING -Force | Out-Null
      New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\InstallService\State" -Name "AutoUpdateLastSuccessTime" -Value "2010-01-01 00:00:00" -PropertyType STRING -Force | Out-Null
      New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\InstallService\State" -Name "HasFrameworkUpdates" -Value 1 -PropertyType DWORD -Force | Out-Null

      schtasks.exe /run /tn "\Microsoft\Windows\InstallService\ScanForUpdates" /I
      ""
      "==> Please now give time for Windows Update to run..."
      ""
      $host.ui.RawUI.ForegroundColor = $savedForegroundColor
      $host.ui.RawUI.BackgroundColor = $savedBackgroundColor
    }
    if (!$no_clear)     { ClearPackageFromModifiedState } else { "No package state reset was requested."    }
    if (!$no_register)  { RegisterPackageAndDeps        } else { "No package registration requested." }
  }
  default { ShowUsage; exit }
}
