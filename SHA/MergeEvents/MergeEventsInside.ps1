#
# MergeEventsInside.ps1
#
# - v2 : Fixed Installer bug (setting wrong registry keys in v1)
#      : Add the possibility to run the script manually or just double click on it
#
# - v3 : Fixed a bug in FolderPath management to handle path with special characters such ad '[' & ']'
#        Using -LiteralPath instead of -Path and Out-File instead of Add-Content 
#

param(
    [string]$FolderPath
)

# Check if an argument is provided
# If no argument: Look for evtx files in the current folder, supposing it's been started manually 

if (!$FolderPath)
{
    $FolderPath = Split-Path ((Get-Variable MyInvocation).Value).MyCommand.Path
}

write-host $FolderPath -ForegroundColor Cyan

# Check the argument is a folder

if ((Test-Path -LiteralPath $FolderPath -PathType Container)-eq $false) {
    $wshell = New-Object -ComObject Wscript.Shell
    $wshell.Popup("This folder doesn't exist!",0,$FolderPath,0x1)
}
else
{
    $ListOfEvtxFiles = (Get-ChildItem -LiteralPath $FolderPath -File -Filter *.evtx | ? { $_.Name -ne "Merge.evtx" }).FullName
    
    # Check if the folder contains .evtx files
    
    if ($ListOfEvtxFiles.count -eq 0)
    {
        $wshell = New-Object -ComObject Wscript.Shell
        $wshell.Popup("Invalid path: Doesn't contain any evtx files!",0,$FolderPath,0x1)
    }
    else
    {

        # Informing the user

        Write-Host "Merge the event files found in the `"$FolderPath`" folder ..."

        # Generate the XML File for the merge operation

        $Filter = "*"
        $StructuredQueryFilePath = $FolderPath+"\StructuredQuery.xml"
        $StructuredQueryXMLFile = New-Item -Path $StructuredQueryFilePath -ItemType File -Force
        
        $String = "<QueryList>`n"
        $String += "  <Query Id=`"0`" Path=`"file://"+$ListOfEvtxFiles[0]+"`">`n"
        $ListOfEvtxFiles | % {
            $String += "    <Select Path=`"file://$_`">"+$Filter+"</Select>`n"
        }
        $String += "  </Query>`n"
        $String += "</QueryList>`n"

        $string | Out-File -LiteralPath $StructuredQueryXMLFile
  
        # Generate the merge operation

        wevtutil /sq epl $StructuredQueryXMLFile "$FolderPath\Merge.evtx" /ow:true

        Write-Host "All the events are merged into the $FolderPath\Merge.evtx file"

        $wshell = New-Object -ComObject Wscript.Shell
        $wshell.Popup("Done in $FolderPath\Merge.evtx",0,"Merge operation",0x1)

    }
}