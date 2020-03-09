# WMI-Report (20200309)
# by Gianni Bragante gbrag@microsoft.com

Function Get-WMINamespace($ns) {
  Write-Host $ns
  Get-WMIProviders $ns
  Get-Classes $ns
  Get-WmiNamespaceSecurity $ns
  Get-WmiObject -namespace $ns -class "__Namespace" | sort-object Name  |
  foreach {
    if ((($_.name.Length -le 2) -or ($_.name.Substring(0,3).ToLower() -ne "ms_")) -and (-not($_.name -match "LDAP"))) {
      Get-WMINamespace ($ns + "\" + $_.name)
    }
  }
}

Function Get-WMIProviders ($ns) {
  Get-WmiObject -NameSpace $ns -Class __Win32Provider | sort-object Name  |
  foreach {
    Get-ProvDetails $ns $_.name $_.CLSID $_.HostingModel $_.UnloadTimeout
  }
}

Function Get-Classes ($ns) {
  Get-WmiObject -Namespace $ns -Query "select * from meta_class" | sort-object Name  |
  foreach {
    $dynamic = $_.Qualifiers["dynamic"].Value
    $static = $_.Qualifiers["static"].Value

    if( $abstract -eq $true  -or $dynamic -eq $true ) {
      if ($dynamic -eq $true) { # Dynamic class
        $row = $tbDyn.NewRow()
        $row.NameSpace = $ns
        $row.Name = $_.name
        $row.Provider = $_.qualifiers["Provider"].value
        $tbDyn.Rows.Add($row)
      }
    } else {
      if (-not $_.name.Startswith("__")) {
        if ($static -eq $true) { # Static class = Repository
          $row = $tbStatic.NewRow()
          $row.NameSpace = $ns
          $row.Name = $_.name
          $row.Inst = $_.GetInstances().Count
          $tbStatic.Rows.Add($row)
        } else {
          $inst = $_.GetInstances().Count # Class with instances, repository as well
          #if ($inst  -gt 0) {
            $row = $tbStatic.NewRow()
            $row.NameSpace = $ns
            $row.Name = $_.name
            $row.Inst = $Inst
            $tbStatic.Rows.Add($row)
          #}
        }
      }
    }
  }
}

Function Get-ProvDetails($ns, $name, $clsid, $HostingModel, $UnloadTimeout) {
  $row = $tbProv.NewRow()
  $row.NameSpace = $ns
  $row.Name = $name
  $row.HostingModel = $HostingModel
  $row.CLSID= $clsid
  $row.UnloadTimeout = $UnloadTimeout
  $dll = " "

  if ($clsid -ne $null) {
    if ($HostingModel -match "decoupled") {
      $Keys = Get-ChildItem HKLM:\SOFTWARE\Microsoft\Wbem\Transports\Decoupled\Client
      $Items = $Keys | Foreach-Object {Get-ItemProperty $_.PsPath }
      ForEach ($key in $Items) {
        if ($key.Provider -eq $name) {
          $key.ProcessIdentifier
          $proc = Get-WmiObject -Query ("select ExecutablePath from Win32_Process where ProcessId = " +  $key.ProcessIdentifier)
          $exe = get-item ($proc.ExecutablePath)
          $row.DLL = $proc.ExecutablePath
          $row.dtDLL = $exe.CreationTime
          $row.verDLL = $exe.VersionInfo.FileVersion
          $svc = Get-WmiObject -Query ("select Name from Win32_Service where ProcessId = " +  $key.ProcessIdentifier)
          if ($svc) {
            $row.ThreadingModel = ("Service: " + $svc.Name)
          }
        }
      }
    } elseif ($HostingModel -ne "SelfHost") {
      $name = (get-itemproperty -ErrorAction SilentlyContinue -literalpath ("HKCR:\CLSID\" + $clsid)).'(default)'
      $dll = (get-itemproperty -ErrorAction SilentlyContinue -literalpath ("HKCR:\CLSID\" + $clsid + "\InprocServer32")).'(default)'
      $row.DLL= $dll
      if ($dll) {
        $dll = $dll.Replace("""","")
        $file = Get-Item ($dll)
        $row.dtDLL = $file.CreationTime
        $row.verDLL = $file.VersionInfo.FileVersion
      }
      $row.ThreadingModel = (get-itemproperty -ErrorAction SilentlyContinue -literalpath ("HKCR:\CLSID\" + $clsid + "\InprocServer32")).'ThreadingModel'
    }
  }
  $tbProv.Rows.Add($row)
}

Function Get-WmiNamespaceSecurity {
    # This function comes from https://github.com/KurtDeGreeff/PlayPowershell/blob/master/Get-WmiNamespaceSecurity.ps1
    Param ( [parameter(Mandatory=$true,Position=0)][string] $namespace,
        [string] $computer = ".",
        [System.Management.Automation.PSCredential] $credential = $null)
 
    Process {
        $ErrorActionPreference = "Stop"
 
        Function Get-PermissionFromAccessMask($accessMask) {
            $WBEM_ENABLE            = 1
            $WBEM_METHOD_EXECUTE         = 2
            $WBEM_FULL_WRITE_REP           = 4
            $WBEM_PARTIAL_WRITE_REP     = 8
            $WBEM_WRITE_PROVIDER          = 0x10
            $WBEM_REMOTE_ACCESS            = 0x20
            $READ_CONTROL = 0x20000
            $WRITE_DAC = 0x40000
       
            $WBEM_RIGHTS_FLAGS = $WBEM_ENABLE,$WBEM_METHOD_EXECUTE,$WBEM_FULL_WRITE_REP,`
                $WBEM_PARTIAL_WRITE_REP,$WBEM_WRITE_PROVIDER,$WBEM_REMOTE_ACCESS,`
                $WBEM_RIGHT_SUBSCRIBE,$WBEM_RIGHT_PUBLISH,$READ_CONTROL,$WRITE_DAC
            $WBEM_RIGHTS_STRINGS = "EnableAccount","ExecuteMethod","FullWrite","PartialWrite",`
                "ProviderWrite","RemoteEnable","Subscribe","Publish","ReadSecurity","WriteSecurity"
 
            $permission = @()
            for ($i = 0; $i -lt $WBEM_RIGHTS_FLAGS.Length; $i++) {
                if (($accessMask -band $WBEM_RIGHTS_FLAGS[$i]) -gt 0) {
                    $permission += $WBEM_RIGHTS_STRINGS[$i]
                }
            }
       
            $permission
        }

        $res = "" 
        $INHERITED_ACE_FLAG = 0x10
 
        $invokeparams = @{Namespace=$namespace;Path="__systemsecurity=@";Name="GetSecurityDescriptor";ComputerName=$computer}
 
        if ($credential -eq $null) {
            $credparams = @{}
        } else {
            $credparams = @{Credential=$credential}
        }
 
        $output = Invoke-WmiMethod @invokeparams @credparams -ErrorAction SilentlyContinue
        if ($output.ReturnValue -ne 0) {
            $res = "GetSecurityDescriptor failed:" + $output.ReturnValue + "   "
        }
   
        $acl = $output.Descriptor
        foreach ($ace in $acl.DACL) {
            $user = New-Object System.Management.Automation.PSObject
            $user | Add-Member -MemberType NoteProperty -Name "Name" -Value "$($ace.Trustee.Domain)\$($ace.Trustee.Name)"
            $user | Add-Member -MemberType NoteProperty -Name "Permission" -Value (Get-PermissionFromAccessMask($ace.AccessMask))
            $user | Add-Member -MemberType NoteProperty -Name "Inherited" -Value (($ace.AceFlags -band $INHERITED_ACE_FLAG) -gt 0)
            $res = $res + ($user.Name + " (" + ($user.permission -join " ") + ")") + " / "
        }
        $row = $tbSec.NewRow()
        $row.NameSpace = $namespace
        $row.Security = $res.Substring(0, $res.Length -3)
        $tbSec.Rows.Add($row)
    }
}

$myWindowsID = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal = new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
$adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
if (-not $myWindowsPrincipal.IsInRole($adminRole)) {
  Write-Output "This script needs to be run as Administrator"
  exit
}

Write-Host "This script is designed to collect information that will help Microsoft Customer Support Services (CSS) troubleshoot an issue you may be experiencing with Windows."
Write-Host "The collected data may contain Personally Identifiable Information (PII) and/or sensitive data, such as (but not limited to) IP addresses, PC names, and user names."
Write-Host "Once the tracing and data collection has completed, the script will save the data in a subfolder. This folder is not automatically sent to Microsoft."
Write-Host "You can send this folder to Microsoft CSS using a secure file transfer tool - Please discuss this with your support professional and also any concerns you may have."
Write-Host "Find our privacy statement here: https://privacy.microsoft.com/en-us/privacy"
$confirm = Read-Host ("Are you sure you want to continue[Y/N]?")
if ($confirm.ToLower() -ne "y") {exit}

$Root = Split-Path (Get-Variable MyInvocation).Value.MyCommand.Path

$resName = "WMI-Report-" + $env:computername +"-" + $(get-date -f yyyyMMdd_HHmmss)
$resDir = $Root + "\" + $resName

New-Item -itemtype directory -path $resDir | Out-Null

New-PSDrive -PSProvider registry -Root HKEY_CLASSES_ROOT -Name HKCR | Out-Null

$tbProv = New-Object system.Data.DataTable “WmiProv”
$col = New-Object system.Data.DataColumn NameSpace,([string])
$tbProv.Columns.Add($col)
$col = New-Object system.Data.DataColumn Name,([string])
$tbProv.Columns.Add($col)
$col = New-Object system.Data.DataColumn HostingModel,([string])
$tbProv.Columns.Add($col)
$col = New-Object system.Data.DataColumn ThreadingModel,([string])
$tbProv.Columns.Add($col)
$col = New-Object system.Data.DataColumn DLL,([string])
$tbProv.Columns.Add($col)
$col = New-Object system.Data.DataColumn dtDLL,([string])
$tbProv.Columns.Add($col)
$col = New-Object system.Data.DataColumn verDLL,([string])
$tbProv.Columns.Add($col)
$col = New-Object system.Data.DataColumn UnloadTimeout,([string])
$tbProv.Columns.Add($col)
$col = New-Object system.Data.DataColumn CLSID,([string])
$tbProv.Columns.Add($col)

$tbDyn = New-Object system.Data.DataTable “Classes”
$col = New-Object system.Data.DataColumn NameSpace,([string])
$tbDyn.Columns.Add($col)
$col = New-Object system.Data.DataColumn Name,([string])
$tbDyn.Columns.Add($col)
$col = New-Object system.Data.DataColumn Provider,([string])
$tbDyn.Columns.Add($col)

$tbStatic = New-Object system.Data.DataTable “Repository”
$col = New-Object system.Data.DataColumn NameSpace,([string])
$tbStatic.Columns.Add($col)
$col = New-Object system.Data.DataColumn Name,([string])
$tbStatic.Columns.Add($col)
$col = New-Object system.Data.DataColumn Inst,([string])
$tbStatic.Columns.Add($col)

$tbSec = New-Object system.Data.DataTable “Security”
$col = New-Object system.Data.DataColumn NameSpace,([string])
$tbSec.Columns.Add($col)
$col = New-Object system.Data.DataColumn Security,([string])
$tbSec.Columns.Add($col)


Get-WMINamespace "Root"

Write-Host "Writing Providers.csv"
$tbProv | Export-Csv $resDir"\Providers.csv" -noType
Write-Host "Writing Classes.csv"
$tbDyn | Export-Csv $resDir"\Dynamic.csv" -noType
Write-Host "Writing Repository.csv"
$tbStatic | Export-Csv $resDir"\Static.csv" -noType
Write-Host "Writing Security.csv"
$tbSec | Export-Csv $resDir"\Security.csv" -noType
