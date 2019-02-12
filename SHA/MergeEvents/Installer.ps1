# Installer
$PathToScript = (Split-Path ((Get-Variable MyInvocation).Value).MyCommand.Path)+"\MergeEventsInside.ps1"

$PathToTheIcon = "%SystemRoot%\\System32\\eventvwr.exe,0"
$PathToPowershell = $PSHOME+"\Powershell.exe"


# Registry Hives for Current User \ Directory

$ContextMenuName = "Merge events inside this folder"

$ContextMenuPath = "HKCU:\Software\Classes\Directory\shell\"+$ContextMenuName
$ContextMenuCommandPath = $ContextMenuPath+"\command"
$DefaultValue = $PathToPowershell+" "+$PathToScript+" \`"%1\`""

# Set the registry key
New-Item -Path $ContextMenuPath -force
New-Item -Path $ContextMenuCommandPath -force
Set-ItemProperty -Path $ContextMenuCommandPath -Name '(Default)' -Value $DefaultValue -Force
Set-ItemProperty -Path $ContextMenuPath -Name 'Icon' -Value $PathToTheIcon

