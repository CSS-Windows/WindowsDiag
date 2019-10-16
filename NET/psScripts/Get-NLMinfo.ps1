param(
    [Parameter(Mandatory = $false)] [ValidateSet("CONNECTED", "DISCONNECTED", "ALL")] [String]$NlmEnumNetwork = "Connected"
)

$NLM_GUID = New-Object Guid 'DCB00C01-570F-4A9B-8D69-199FDBA5723B'
$nlm_type = [Type]::GetTypeFromCLSID($NLM_GUID)
$NetworkListManager = [Activator]::CreateInstance($nlm_type)

# Set enums for GetNetworks
$NLM_ENUM_NETWORK_CONNECTED=1
$NLM_ENUM_NETWORK_DISCONNECTED=2
$NLM_ENUM_NETWORK_ALL=3

if ( $NlmEnumNetwork -eq "CONNECTED") {
    [int]$NlmEnumNetwork = $NLM_ENUM_NETWORK_CONNECTED
}
elseif ( $NlmEnumNetwork -eq "DISCONNECTED") {
    [int]$NlmEnumNetwork = $NLM_ENUM_NETWORK_DISCONNECTED
}
elseif ( $NlmEnumNetwork -eq "ALL") {
    [int]$NlmEnumNetwork = $NLM_ENUM_NETWORK_ALL
}

$Networks = $NetworkListManager.GetNetworks($NlmEnumNetwork)

foreach ($Network in $Networks) {
    # Network name
    if ( $Network.isConnected() ) {
        $color = "green"
    }
    else {
        $color = "white"
    }
    "####################################################"
    Write-Host -ForegroundColor $color  "Network name : $($Network.GetName())"  
    Write-Host -ForegroundColor $color  "Network description : $($Network.GetDescription())"  

    "####################################################"
    if ( $Network.isConnected()) { 
        Get-NetConnectionProfile -Name $Network.GetName() 
        "----------------------------------------------------"
    }
    # Values from INetworkListManager interface https://msdn.microsoft.com/en-us/library/windows/desktop/aa370769(v=vs.85).aspx

    # Network category
    $NetCategories = New-Object -TypeName System.Collections.Hashtable
    $NetCategories.Add(0x00, "NLM_NETWORK_CATEGORY_PUBLIC")
    $NetCategories.Add(0x01, "NLM_NETWORK_CATEGORY_PRIVATE")
    $NetCategories.Add(0x02, "NLM_NETWORK_CATEGORY_DOMAIN_AUTHENTICATED")
    $NetCategories.Get_Item($Network.GetCategory())
    "+"

    # Domain type
    $DomainTypes = New-Object -TypeName System.Collections.Hashtable
    $DomainTypes.Add(0x00, "NLM_DOMAIN_TYPE_NON_DOMAIN_NETWORK")
    $DomainTypes.Add(0x01, "NLM_DOMAIN_TYPE_DOMAIN_NETWORK")
    $DomainTypes.Add(0x02, "NLM_DOMAIN_TYPE_DOMAIN_AUTHENTICATED")
    $DomainTypes.Get_Item($Network.GetDomainType())

    # Several methods for working with the connectivity flags

    # Display all active connectivity types (method a)
    foreach ($Key in $NLMConnectivity.Keys) {
        $KeyBand = $Key -band $Network.GetConnectivity()
        if ($KeyBand -gt 0) {
            $NLMConnectivity.Get_Item($KeyBand)
        }
    }
    "+"

    # Display all active connectivity types (method b)
    #$NLMConnectivity.Keys | Where-Object { $_ -band $Network.GetConnectivity() } | ForEach-Object { $NLMConnectivity.Get_Item($_) }

    # Display all active connectivity types (method c)
    switch ($Network.GetConnectivity()) {
        { $_ -band 0x0000 } { "NLM_CONNECTIVITY_DISCONNECTED" }
        { $_ -band 0x0001 } { "NLM_CONNECTIVITY_IPV4_NOTRAFFIC" }
        { $_ -band 0x0002 } { "NLM_CONNECTIVITY_IPV6_NOTRAFFIC" }
        { $_ -band 0x0010 } { "NLM_CONNECTIVITY_IPV4_SUBNET" }
        { $_ -band 0x0020 } { "NLM_CONNECTIVITY_IPV4_LOCALNETWORK" }
        { $_ -band 0x0040 } { "NLM_CONNECTIVITY_IPV4_INTERNET" }
        { $_ -band 0x0100 } { "NLM_CONNECTIVITY_IPV6_SUBNET" }
        { $_ -band 0x0200 } { "NLM_CONNECTIVITY_IPV6_LOCALNETWORK" }
        { $_ -band 0x0400 } { "NLM_CONNECTIVITY_IPV6_INTERNET" }
    }
    ""
}