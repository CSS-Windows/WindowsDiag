<# AuditTCPConnections.ps1
    Disclaimer

    The sample scripts are not supported under any Microsoft standard support program or service.
    The sample scripts are provided AS IS without warranty of any kind.
    Microsoft further disclaims all implied warranties including, without limitation, any implied warranties of merchantability
    or of fitness for a particular purpose.
    The entire risk arising out of the use or performance of the sample scripts and documentation remains with you.
    In no event shall Microsoft, its authors, or anyone else involved in the creation, production,
    or delivery of the scripts be liable for any damages whatsoever (including, without limitation,
    damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss)
    arising out of the use of or inability to use the sample scripts or documentation,
    even if Microsoft has been advised of the possibility of such damages.
    
    .SYNOPSIS
    Author: Marcus Ferreira marcus.ferreira[at]microsoft[dot]com
    Version: 0.1

    .DESCRIPTION
    This script will get all TCP established connections and match them with its process.
    Similar output is thrown by using: netstat -ano
    
    .EXAMPLE
    .\AuditTCPConnections.ps1
#>

$AllConnections = @()
$Connections = Get-NetTCPConnection -State Established | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess

ForEach($Connection In $Connections) {
    $ProcessInfo = Get-Process -PID $Connection.OwningProcess -IncludeUserName | Select-Object Path,UserName,StartTime,Name,Id

    $Obj = New-Object -TypeName PSObject
    Add-Member -InputObject $Obj -MemberType NoteProperty -Name LocalAddress -Value $Connection.LocalAddress
    Add-Member -InputObject $Obj -MemberType NoteProperty -Name LocalPort -Value $Connection.LocalPort
    Add-Member -InputObject $Obj -MemberType NoteProperty -Name RemoteAddress -Value $Connection.RemoteAddress
    Add-Member -InputObject $Obj -MemberType NoteProperty -Name RemotePort -Value $Connection.RemotePort
    Add-Member -InputObject $Obj -MemberType NoteProperty -Name OwningProcessID -Value $Connection.OwningProcess
    Add-Member -InputObject $Obj -MemberType NoteProperty -Name ProcessName -Value $ProcessInfo.Name
    Add-Member -InputObject $Obj -MemberType NoteProperty -Name UserName -Value $ProcessInfo.UserName
    Add-Member -InputObject $Obj -MemberType NoteProperty -Name CommandLine -Value $ProcessInfo.Path
    Add-Member -InputObject $Obj -MemberType NoteProperty -Name StartTime -Value $ProcessInfo.StartTime

    $AllConnections += $Obj
}

$AllConnections | format-table -autosize