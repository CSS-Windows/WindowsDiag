$DiagVersion = "WinRM-Diag (20200309)"
# by Gianni Bragante gbrag@microsoft.com

Function FindSep {
  param( [string]$FindIn, [string]$Left,[string]$Right )

  if ($left -eq "") {
    $Start = 0
  } else {
    $Start = $FindIn.IndexOf($Left) 
    if ($Start -gt 0 ) {
      $Start = $Start + $Left.Length
    } else {
       return ""
    }
  }

  if ($Right -eq "") {
    $End = $FindIn.Substring($Start).Length
  } else {
    $End = $FindIn.Substring($Start).IndexOf($Right)
    if ($end -le 0) {
      return ""
    }
  }
  $Found = $FindIn.Substring($Start, $End)
  return $Found
}

Function Write-Diag {
  param( [string] $msg )
  $msg = (get-date).ToString("yyyyMMdd HH:mm:ss.fff") + " " + $msg
  Write-Host $msg
  $msg | Out-File -FilePath $diagfile -Append
}

Function GetStore($store) {
  $certlist = Get-ChildItem ("Cert:\LocalMachine\" + $store)

  foreach ($cert in $certlist) {
    $EKU = ""
    foreach ($item in $cert.EnhancedKeyUsageList) {
      if ($item.FriendlyName) {
        $EKU += $item.FriendlyName + " / "
      } else {
        $EKU += $item.ObjectId + " / "
      }
    }

    $row = $tbcert.NewRow()

    foreach ($ext in $cert.Extensions) {
      if ($ext.oid.value -eq "2.5.29.14") {
        $row.SubjectKeyIdentifier = $ext.SubjectKeyIdentifier.ToLower()
      }
      if (($ext.oid.value -eq "2.5.29.35") -or ($ext.oid.value -eq "2.5.29.1")) { 
        $asn = New-Object Security.Cryptography.AsnEncodedData ($ext.oid,$ext.RawData)
        $aki = $asn.Format($true).ToString().Replace(" ","")
        $aki = (($aki -split '\n')[0]).Replace("KeyID=","").Trim()
        $row.AuthorityKeyIdentifier = $aki
      }
    }
    if ($EKU) {$EKU = $eku.Substring(0, $eku.Length-3)} 
    $row.Store = $store
    $row.Thumbprint = $cert.Thumbprint.ToLower()
    $row.Subject = $cert.Subject
    $row.Issuer = $cert.Issuer
    $row.NotAfter = $cert.NotAfter
    $row.EnhancedKeyUsage = $EKU
    $row.SerialNumber = $cert.SerialNumber.ToLower()
    $tbcert.Rows.Add($row)
  } 
}

Function ChkCert($cert, $store, $descr) {
  $cert = $cert.ToLower()
  if ($cert) {
    if ("0123456789abcdef".Contains($cert[0])) {
      $aCert = $tbCert.Select("Thumbprint = '" + $cert + "' and $store")
      if ($aCert.Count -gt 0) {
        Write-Diag ("[INFO] The $descr certificate was found, the subject is " + $aCert[0].Subject)
        if (($aCert[0].NotAfter) -gt (Get-Date)) {
          Write-Diag ("[INFO] The $descr certificate will expire on " + $aCert[0].NotAfter.ToString("yyyyMMdd HH:mm:ss.fff") )
        } else {
          Write-Diag ("[ERROR] The $descr certificate expired on " + $aCert[0].NotAfter.ToString("yyyyMMdd HH:mm:ss.fff") )
        }
      }  else {
        Write-Diag "[ERROR] The certificate with thumbprint $cert was not found in $store"
      }
    } else {
      Write-Diag "[ERROR] Invalid character in the $cert certificate thumbprint $cert"
    }
  } else {
    Write-Diag "[ERROR] The thumbprint of $descr certificate is empty"
  }
}

Function GetSubVal {
  param( [string]$SubName, [string]$SubValue)
  $SubProp = (Get-Item -Path ("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\EventCollector\Subscriptions\" + $SubName) | Get-ItemProperty)
  if ($SubProp.($SubValue)) {
    return $SubProp.($SubValue)
  } else {
    $cm = $SubProp.ConfigurationMode
    $subVal = (Get-Item -Path ("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\EventCollector\ConfigurationModes\" + $cm) | Get-ItemProperty)
    return $SubVal.($SubValue)
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
$resName = "WinRM-Diag-" + $env:computername +"-" + $(get-date -f yyyyMMdd_HHmmss)
$resDir = $Root + "\" + $resName
$diagfile = $resDir + "\WinRM-Diag.txt"
New-Item -itemtype directory -path $resDir | Out-Null

$tbCert = New-Object system.Data.DataTable
$col = New-Object system.Data.DataColumn Store,([string]); $tbCert.Columns.Add($col)
$col = New-Object system.Data.DataColumn Thumbprint,([string]); $tbCert.Columns.Add($col)
$col = New-Object system.Data.DataColumn Subject,([string]); $tbCert.Columns.Add($col)
$col = New-Object system.Data.DataColumn Issuer,([string]); $tbCert.Columns.Add($col)
$col = New-Object system.Data.DataColumn NotAfter,([DateTime]); $tbCert.Columns.Add($col)
$col = New-Object system.Data.DataColumn IssuerThumbprint,([string]); $tbCert.Columns.Add($col)
$col = New-Object system.Data.DataColumn EnhancedKeyUsage,([string]); $tbCert.Columns.Add($col)
$col = New-Object system.Data.DataColumn SerialNumber,([string]); $tbCert.Columns.Add($col)
$col = New-Object system.Data.DataColumn SubjectKeyIdentifier,([string]); $tbCert.Columns.Add($col)
$col = New-Object system.Data.DataColumn AuthorityKeyIdentifier,([string]); $tbCert.Columns.Add($col)

Write-Diag ("[INFO] " + $DiagVersion)
Write-Diag "[INFO] Retrieving certificates from LocalMachine\My store"
GetStore "My"
Write-Diag "[INFO] Retrieving certificates from LocalMachine\CA store"
GetStore "CA"
Write-Diag "[INFO] Retrieving certificates from LocalMachine\Root store"
GetStore "Root"

Write-Diag "[INFO] Matching issuer thumbprints"
$aCert = $tbCert.Select("Store = 'My' or Store = 'CA'")
foreach ($cert in $aCert) {
  $aIssuer = $tbCert.Select("SubjectKeyIdentifier = '" + ($cert.AuthorityKeyIdentifier).tostring() + "'")
  if ($aIssuer.Count -gt 0) {
    $cert.IssuerThumbprint = ($aIssuer[0].Thumbprint).ToString()
  }
}
Write-Diag "[INFO] Exporting certificates.tsv"
$tbcert | Export-Csv ($resDir + "\certificates.tsv") -noType -Delimiter "`t"

# Diag start

$OSVer = [environment]::OSVersion.Version.Major + [environment]::OSVersion.Version.Minor * 0.1

$subDom = $false
$subWG = $false
$Subscriptions = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\EventCollector\Subscriptions
foreach ($sub in $Subscriptions) {
  Write-Diag ("[INFO] Found subscription " + $sub.PSChildname)
  $SubProp = ($sub | Get-ItemProperty)
  Write-Diag ("[INFO]   SubscriptionType = " + $SubProp.SubscriptionType + ", ConfigurationMode = " + $SubProp.ConfigurationMode)
  Write-Diag ("[INFO]   MaxLatencyTime = " + (GetSubVal $sub.PSChildname "MaxLatencyTime") + ", HeartBeatInterval = " + (GetSubVal $sub.PSChildname "HeartBeatInterval"))

  if ($SubProp.Locale) {
    if ($SubProp.Locale -eq "en-US") {
      Write-Diag "[INFO]   The subscription's locale is set to en-US"
    } else {
      Write-Diag ("[WARNING] The subscription's locale is set to " + $SubProp.Locale)
    }
  } else {
   Write-Diag "[INFO]   The subscription's locale is not set, the default locale will be used."    
  }

  if ($SubProp.AllowedSubjects) {
    $subWG = $true
    Write-Diag "[INFO]   Listed non-domain computers:"
    $list = $SubProp.AllowedSubjects -split ","
    foreach ($item in $list) {
      Write-Diag ("[INFO]   " + $item)
    }
  } else {
    Write-Diag "[INFO]   No non-domain computers listed, that's ok if this is not a collector in workgroup environment"
  }

  if ($SubProp.AllowedIssuerCAs) {
    $subWG = $true
    Write-Diag "[INFO]   Listed Issuer CAs:"
    $list = $SubProp.AllowedIssuerCAs -split ","
    foreach ($item in $list) {
      Write-Diag ("[INFO]   " + $item)
      ChkCert -cert $item -store "(Store = 'CA' or Store = 'Root')" -descr "Issuer CA"
    }
  } else {
    Write-Diag "[INFO]   No Issuer CAs listed, that's ok if this is not a collector in workgroup environment"
  }

  $RegKey = (($sub.Name).replace("HKEY_LOCAL_MACHINE\","HKLM:\") + "\EventSources")
  if (Test-Path -Path $RegKey) {
    $sources = Get-ChildItem -Path $RegKey
    if ($sources.Count -gt 4000) {
      Write-Diag ("[WARNING] There are " + $sources.Count + " sources for this subscription")
    } else {
      Write-Diag ("[INFO]   There are " + $sources.Count + " sources for this subscription")
    }
  } else {
    Write-Diag ("[INFO]   No sources found for the subscription " + $sub.Name)
  }
}

if ($OSVer -gt 6.1) {
  Write-Diag "[INFO] Retrieving machine's IP addresses"
  $iplist = Get-NetIPAddress
}

Write-Diag "[INFO] Browsing listeners"
$listeners = Get-ChildItem WSMan:\localhost\Listener
foreach ($listener in $listeners) {
  Write-Diag ("[INFO] Inspecting listener " + $listener.Name)
  $prop = Get-ChildItem $listener.PSPath
  foreach ($value in $prop) {
    if ($value.Name -eq "CertificateThumbprint") {
      if ($listener.keys[0].Contains("HTTPS")) {
        Write-Diag "[INFO] Found HTTPS listener"
        $listenerThumbprint = $value.Value.ToLower()
        Write-Diag "[INFO] Found listener certificate $listenerThumbprint"
        if ($listenerThumbprint) {
          ChkCert -cert $listenerThumbprint -descr "listener" -store "Store = 'My'"
        }
      }
    }
    if ($value.Name.Contains("ListeningOn")) {
      $ip = ($value.value).ToString()
      Write-Diag "[INFO] Listening on $ip"
      if ($OSVer -gt 6.1) {
        if (($iplist | Where-Object {$_.IPAddress -eq $ip } | measure-object).Count -eq 0 ) {
          Write-Diag "[ERROR] IP address $ip not found"
        }
      }
    }
  } 
} 

$svccert = Get-Item WSMan:\localhost\Service\CertificateThumbprint
if ($svccert.value ) {
  Write-Diag ("[INFO] The Service Certificate thumbprint is " + $svccert.value)
  ChkCert -cert $svccert.value -descr "Service" -store "Store = 'My'"
}

$ipfilter = Get-Item WSMan:\localhost\Service\IPv4Filter
if ($ipfilter.Value) {
  if ($ipfilter.Value -eq "*") {
    Write-Diag "[INFO] IPv4Filter = *"
  } else {
    Write-Diag ("[WARNING] IPv4Filter = " + $ipfilter.Value)
  }
} else {
  Write-Diag ("[WARNING] IPv4Filter is empty, WinRM will not listen on IPv4")
}

$ipfilter = Get-Item WSMan:\localhost\Service\IPv6Filter
if ($ipfilter.Value) {
  if ($ipfilter.Value -eq "*") {
    Write-Diag "[INFO] IPv6Filter = *"
  } else {
    Write-Diag ("[WARNING] IPv6Filter = " + $ipfilter.Value)
  }
} else {
  Write-Diag ("[WARNING] IPv6Filter is empty, WinRM will not listen on IPv6")
}

if (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager") {
  $isForwarder = $True
  $RegKey = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager')

  Write-Diag "[INFO] Enumerating SubscriptionManager URLs at HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager"
  $RegKey.PSObject.Properties | ForEach-Object {
    If($_.Name -notlike '*PS*'){
      Write-Diag ("[INFO] " + $_.Name + " " + $_.Value)
      $IssuerCA = (FindSep -FindIn $_.Value -Left "IssuerCA=" -Right ",").ToLower()
      if (-not $IssuerCA) {
        $IssuerCA = (FindSep -FindIn $_.Value -Left "IssuerCA=" -Right "").ToLower()
      }
      if ($IssuerCA) {
        if ("0123456789abcdef".Contains($IssuerCA[0])) {
          Write-Diag ("[INFO] Found issuer CA certificate thumbprint " + $IssuerCA)
          $aCert = $tbCert.Select("Thumbprint = '" + $IssuerCA + "' and (Store = 'CA' or Store = 'Root')")
          if ($aCert.Count -eq 0) {
            Write-Diag "[ERROR] The Issuer CA certificate was not found in CA or Root stores"
          } else {
            Write-Diag ("[INFO] Issuer CA certificate found in store " + $aCert[0].Store + ", subject = " + $aCert[0].Subject)
            if (($aCert[0].NotAfter) -gt (Get-Date)) {
              Write-Diag ("[INFO] The Issuer CA certificate will expire on " + $aCert[0].NotAfter.ToString("yyyyMMdd HH:mm:ss.fff") )
            } else {
              Write-Diag ("[ERROR] The Issuer CA certificate expired on " + $aCert[0].NotAfter.ToString("yyyyMMdd HH:mm:ss.fff") )
            }
          }

          $aCliCert = $tbCert.Select("IssuerThumbprint = '" + $IssuerCA + "' and Store = 'My'")
          if ($aCliCert.Count -eq 0) {
            Write-Diag "[ERROR] Cannot find any certificate issued by this Issuer CA"
          } else {
            if ($PSVersionTable.psversion.ToString() -ge "3.0") {
              Write-Diag "[INFO] Listing available client certificates from this IssuerCA"
              $num = 0
              foreach ($cert in $aCliCert) {
                if ($cert.EnhancedKeyUsage.Contains("Client Authentication")) {
                  Write-Diag ("[INFO]   Found client certificate " + $cert.Thumbprint + " " + $cert.Subject)
                  if (($Cert.NotAfter) -gt (Get-Date)) {
                    Write-Diag ("[INFO]   The client certificate will expire on " + $cert.NotAfter.ToString("yyyyMMdd HH:mm:ss.fff") )
                  } else {
                    Write-Diag ("[ERROR]   The client certificate expired on " + $cert.NotAfter.ToString("yyyyMMdd HH:mm:ss.fff") )
                  }
                  $certobj = Get-Item ("CERT:\Localmachine\My\" + $cert.Thumbprint)
                  $keypath = [io.path]::combine("$env:ProgramData\microsoft\crypto\rsa\machinekeys", $certobj.privatekey.cspkeycontainerinfo.uniquekeycontainername)
                  if ([io.file]::exists($keypath)) {
                    $acl = ((get-acl -path $keypath).Access | Where-Object {$_.IdentityReference -eq "NT AUTHORITY\NETWORK SERVICE"})
                    if ($acl) {
                      $rights = $acl.FileSystemRights.ToString()
                      if ($rights.contains("Read") -or $rights.contains("FullControl") ) {
                        Write-Diag ("[INFO]   The NETWORK SERVICE account has permissions on the private key of this certificate: " + $rights)
                      } else {
                        Write-Diag ("[ERROR]  Incorrect permissions for the NETWORK SERVICE on the private key of this certificate: " + $rights)
                      }
                    } else {
                      Write-Diag "[ERROR]  Missing permissions for the NETWORK SERVICE account on the private key of this certificate"
                    }
                  } else {
                    Write-Diag "[ERROR]  Cannot find the private key"
                  } 
                  $num++
                }
              }
              if ($num -eq 0) {
                Write-Diag "[ERROR] Cannot find any client certificate issued by this Issuer CA"
              } elseif ($num -gt 1) {
                Write-Diag "[WARNING] More than one client certificate issued by this Issuer CA, the first certificate will be used by WinRM"
              }
            }
          }
        } else {
         Write-Diag "[ERROR] Invalid character for the IssuerCA certificate in the SubscriptionManager URL"
        }
      }
    } 
  }
} else {
  $isForwarder = $false
  Write-Diag "[INFO] No SubscriptionManager URL configured. It's ok if this machine is not supposed to forward events."
}

if ((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain) {
  $search = New-Object DirectoryServices.DirectorySearcher([ADSI]"GC://$env:USERDNSDOMAIN") # The SPN is searched in the forest connecting to a Global catalog

  $SPNReg = ""
  $SPN = "HTTP/" + $env:COMPUTERNAME
  Write-Diag ("[INFO] Searching for the SPN $SPN")
  $search.filter = "(servicePrincipalName=$SPN)"
  $results = $search.Findall()
  if ($results.count -gt 0) {
    foreach ($result in $results) {
      Write-Diag ("[INFO] The SPN HTTP/$env:COMPUTERNAME is registered for DNS name = " + $result.properties.dnshostname + ", DN = " + $result.properties.distinguishedname + ", Category = " + $result.properties.objectcategory)
      if ($result.properties.objectcategory[0].Contains("Computer")) {
        if (-not $result.properties.dnshostname[0].Contains($env:COMPUTERNAME)) {
          Write-Diag ("[ERROR] The The SPN $SPN is registered for different DNS host name: " + $result.properties.dnshostname[0])
          $SPNReg = "OTHER"
        }
      } else {
        Write-Diag "[ERROR] The The SPN $SPN is NOT registered for a computer account"
        $SPNReg = "OTHER"
      }
    }
    if ($results.count -gt 1) {
      Write-Diag "[ERROR] The The SPN $SPN is duplicate"
    }
  } else {
    Write-Diag "[INFO] The The SPN $SPN was not found. That's ok, the SPN HOST/$env:COMPUTERNAME will be used"
  }

  $SPN = "HTTP/" + $env:COMPUTERNAME + ":5985"
  Write-Diag ("[INFO] Searching for the SPN $SPN")
  $search.filter = "(servicePrincipalName=$SPN)"
  $results = $search.Findall()
  if ($results.count -gt 0) {
    foreach ($result in $results) {
      Write-Diag ("[INFO] The SPN HTTP/$env:COMPUTERNAME is registered for DNS name = " + $result.properties.dnshostname + ", DN = " + $result.properties.distinguishedname + ", Category = " + $result.properties.objectcategory)
      if ($result.properties.objectcategory[0].Contains("Computer")) {
        if (-not $result.properties.dnshostname[0].Contains($env:COMPUTERNAME)) {
          Write-Diag ("[ERROR] The The SPN $SPN is registered for different DNS host name: " + $result.properties.dnshostname[0])
        }
      } else {
        Write-Diag "[ERROR] The The SPN $SPN is NOT registered for a computer account"
      }
    }
    if ($results.count -gt 1) {
      Write-Diag "[ERROR] The The SPN $SPN is duplicate"
    }
  } else {
    if ($SPNReg -eq "OTHER") {
      Write-Diag "[WARNING] The The SPN $SPN was not found. It is required to accept WinRM connections since the HTTP/$env:COMPUTERNAME is reqistered to another name"
    }
  }

  Write-Diag "[INFO] Checking the WinRMRemoteWMIUsers__ group"
  $search = New-Object DirectoryServices.DirectorySearcher([ADSI]"")  # This is a Domain local group, therefore we need to collect to a non-global catalog
  $search.filter = "(samaccountname=WinRMRemoteWMIUsers__)"
  $results = $search.Findall()
  if ($results.count -gt 0) {
    Write-Diag ("[INFO] Found " + $results.Properties.distinguishedname)
    if ($results.Properties.grouptype -eq  -2147483644) {
      Write-Diag "[INFO] WinRMRemoteWMIUsers__ is a Domain local group"
    } elseif ($results.Properties.grouptype -eq -2147483646) {
      Write-Diag "[WARNING] WinRMRemoteWMIUsers__ is a Global group"
    } elseif ($results.Properties.grouptype -eq -2147483640) {
      Write-Diag "[WARNING] WinRMRemoteWMIUsers__ is a Universal group"
    }
    if (Get-WmiObject -query "select * from Win32_Group where Name = 'WinRMRemoteWMIUsers__' and Domain = '$env:computername'") {
      Write-Diag "[INFO] The group WinRMRemoteWMIUsers__ is also present as machine local group"
    }
  } else {
    Write-Diag "[ERROR] The WinRMRemoteWMIUsers__ was not found in the domain" 
    if (Get-WmiObject -query "select * from Win32_Group where Name = 'WinRMRemoteWMIUsers__' and Domain = '$env:computername'") {
      Write-Diag "[INFO] The group WinRMRemoteWMIUsers__ is present as machine local group"
    } else {
      Write-Diag "[ERROR] The group WinRMRemoteWMIUsers__ is not even present as machine local group"
    }
  }
  if ((Get-ChildItem WSMan:\localhost\Service\Auth\Kerberos).value -eq "true") {
    Write-Diag "[INFO] Kerberos authentication is enabled for the service"
  }  else {
    Write-Diag "[WARNING] Kerberos authentication is disabled for the service"
  }
} else {
  Write-Diag "[INFO] The machine is not joined to a domain"
  if (Get-WmiObject -query "select * from Win32_Group where Name = 'WinRMRemoteWMIUsers__' and Domain = '$env:computername'") {
    Write-Diag "[INFO] The group WinRMRemoteWMIUsers__ is present as machine local group"
  } else {
    Write-Diag "[ERROR] The group WinRMRemoteWMIUsers__ is not present as machine local group"
  }
  if ((Get-ChildItem WSMan:\localhost\Service\Auth\Certificate).value -eq "false") {
    Write-Diag "[WARNING] Certificate authentication is disabled for the service"
  }  else {
    Write-Diag "[INFO] Certificate authentication is enabled for the service"
  }
}

$iplisten = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters" | Select-Object -ExpandProperty "ListenOnlyList" -ErrorAction SilentlyContinue)
if ($iplisten) {
  Write-Diag ("[WARNING] The IPLISTEN list is not empty, the listed addresses are " + $iplisten)
} else {
  Write-Diag "[INFO] The IPLISTEN list is empty. That's ok: WinRM will listen on all IP addresses"
}

$binval = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" -Name WinHttpSettings).WinHttPSettings            
$proxylength = $binval[12]            
if ($proxylength -gt 0) {
  $proxy = -join ($binval[(12+3+1)..(12+3+1+$proxylength-1)] | % {([char]$_)})            
  Write-Diag ("[WARNING] A NETSH WINHTTP proxy is configured: " + $proxy)
  $bypasslength = $binval[(12+3+1+$proxylength)]            
  if ($bypasslength -gt 0) {            
    $bypasslist = -join ($binval[(12+3+1+$proxylength+3+1)..(12+3+1+$proxylength+3+1+$bypasslength)] | % {([char]$_)})            
    Write-Diag ("[WARNING] Bypass list: " + $bypasslist)
   } else {            
    Write-Diag "[WARNING] No bypass list is configured"
  }            
  Write-Diag "[WARNING] WinRM does not work very well through proxies, make sure that the target machine is in the bypass list or remove the proxy"
} else {
  Write-Diag "[INFO] No NETSH WINHTTP proxy is configured"
}

$th = (get-item WSMan:\localhost\Client\TrustedHosts).value
if ($th) {
  Write-Diag ("[INFO] TrustedHosts contains: $th")
} else {
  Write-Diag ("[INFO] TrustedHosts is not configured, it's ok it this machine is not supposed to connect to other machines using NTLM")
}

$psver = $PSVersionTable.PSVersion.Major.ToString() + $PSVersionTable.PSVersion.Minor.ToString()
if ($psver -eq "50") {
  Write-Diag ("[WARNING] Windows Management Framework version " + $PSVersionTable.PSVersion.ToString() + " is no longer supported")
} else { 
  Write-Diag ("[INFO] Windows Management Framework version is " + $PSVersionTable.PSVersion.ToString() )
}

$clientcert = Get-ChildItem WSMan:\localhost\ClientCertificate
if ($clientcert.Count -gt 0) {
  Write-Diag "[INFO] Client certificate mappings"
  foreach ($certmap in $clientcert) {
    Write-Diag ("[INFO] Certificate mapping " + $certmap.Name)
    $prop = Get-ChildItem $certmap.PSPath
    foreach ($value in $prop) {
      Write-Diag ("[INFO]   " + $value.Name + " " + $value.Value)
      if ($value.Name -eq "Issuer") {
        ChkCert -cert $value.Value -descr "mapping" -store "(Store = 'Root' or Store = 'CA')"
      } elseif ($value.Name -eq "UserName") {
        $usr = Get-WmiObject -class Win32_UserAccount | Where {$_.Name -eq $value.value}
        if ($usr) {
          if ($usr.Disabled) {
            Write-Diag ("[ERROR]    The local user account " + $value.value + " is disabled")
          } else {
            Write-Diag ("[INFO]     The local user account " + $value.value + " is enabled")
          }
        } else {
          Write-Diag ("[ERROR]    The local user account " + $value.value + " does not exist")
        }
      } elseif ($value.Name -eq "Subject") {
        if ($value.Value[0] -eq '"') {
          Write-Diag "[ERROR]    The subject does not have to be included in double quotes"
        }
      }
    }
  }
} else {
  if ($subWG) {
    Write-Diag "[ERROR] No client certificate mapping configured"
  }
}

$aCert = $tbCert.Select("Store = 'Root' and Subject <> Issuer")
if ($aCert.Count -gt 0) {
  Write-Diag "[ERROR] Found for non-Root certificates in the Root store"
  foreach ($cert in $acert) {
    Write-Diag ("[ERROR]  Misplaced certificate " + $cert.Subject)
  }
}

if ($isForwarder) {
  $evtLogReaders = (Get-WmiObject -Query ("Associators of {Win32_Group.Domain='" + $env:COMPUTERNAME + "',Name='Event Log Readers'} where Role=GroupComponent") | Where {$_.Name -eq "NETWORK SERVICE"} | Measure-Object)
  if ($evtLogReaders.Count -gt 0) {
    Write-Diag "[INFO] The NETWORK SERVICE account is member of the Event Log Readers group"
  } else {
    Write-Diag "[WARNING] The NETWORK SERVICE account is NOT member of the Event Log Readers group, the events in the Security log cannot be forwarded"
  }
}

$fwrules = (Get-NetFirewallPortFilter –Protocol TCP | Where { $_.localport –eq ‘5986’ } | Get-NetFirewallRule)
if ($fwrules.count -eq 0) {
  Write-Diag "[INFO] No firewall rule for port 5986"
} else {
  Write-Diag "[INFO] Found firewall rule for port 5986"
}

$dir = $env:windir + "\system32\logfiles\HTTPERR"
if (Test-Path -path $dir) {
  $httperrfiles = Get-ChildItem -path ($dir)
  if ($httperrfiles.Count -gt 100) {
    Write-Diag ("[WARNING] There are " + $httperrfiles.Count + " files in the folder " + $dir)
  } else {
   Write-Diag ("[INFO] There are " + $httperrfiles.Count + " files in the folder " + $dir)
  }
  $size = 0 
  foreach ($file in $httperrfiles) {
    $size += $file.Length
  }
  $size = [System.Math]::Ceiling($size / 1024 / 1024) # Convert to MB
  if ($size -gt 100) {
    Write-Diag ("[WARNING] The folder " + $dir + " is using " + $size.ToString() + " MB of disk space")
  } else {
    Write-Diag ("[INFO] The folder " + $dir + " is using " + $size.ToString() + " MB of disk space")
  }
}