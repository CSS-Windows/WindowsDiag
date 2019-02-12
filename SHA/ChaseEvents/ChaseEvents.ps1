Param(
    [string[]]$EventId,                                                     # The EventId we're looking for 
    [ValidateSet("Critical","Error","Warning","Information","Verbose")][string[]]$EventLevel,    # We can also filter by level
    [int]$Days,                                                             # The history in Days we want to read
    [switch]$Help,                                                          # Show the help
    [ValidateSet("YMD","YMDH","YMDHM","YMDHMS","YMDHMSm")][string]$TimeFormat, # This is the level of precision we want
    [switch]$Verbose,                                                       # Used for verbose debugging output
    [ValidateSet("Minimal","Standard","Verbose")][string]$Verbosity="Minimal",  # To display detail information
    [switch]$Multiline                                                      # Switch to choose to have events on multiline
)

# ::::: CHASE-SEVERAL-EVENTS :::::
#
#   Merges the events we ask for in several columns 
#   v1.3 : Added handling of events 41, 1001, 6008 & 6013
#          Added the -Multiline switch to decide wether to write all the events data
#          in one line or split it into multiple lines
#   v1.2 : Fixed a bug in the way we look for the system event logs
#
#   Improvements in vNext : 
#   - Write to an Excel file instead of csv to add colors and more sophisticated outputs
#

#region FUNCTIONS DEFINITIONS

# ::::: FUNCTIONS :::::
#
#   Show_Help()                     : Shows the help
#   Check_Arguments()               : Check if either EventID or EventLevel is mentionned
#   Check_TimeFormat()              : Check if the output format is supported
#   Check_Set_Delay()               : Set the history used if set
#   Build_Query()                   : Build the XML Query according to the arguments provided
#   GetEventFromCellString()        : Export the EventID from a string
#   GetEventCountFromCellString()   : Export the number of occurences from a string
#   Get_Detail()                    : Get additional information from the event
#

#region Help function
function Show_Help(){
    Write-Host "Chase-Events.ps1 (v1.1)`n" -ForegroundColor Yellow
    Write-Host "Put the script in your SDP report output and run it with the following switches"
    Write-Host "It will parse all the system event logs in the current folder, looking for the ID you're looking for`n"
    Write-Host "In each column you have the EventID and the number of time it's been logged"
    write-host " -help       : Shows this help"
    write-host " -Days       : Number of days you want to go back (if not set, we'll go as far as the event log goes)"
    write-host " -EventID    : Choose one or several events to filter. For example -EventID 5120 or -EventID 1069,1146,1135 *"
    write-host " -EventLevel : Choose one or several Levels to filter. For example -EventLevel Critical or -EventLevel Critical,Error *"
    write-host "               Accepted values are Critical, Error, Warning, Information, Verbose"
    write-host " -TimeFormat : The output format you want to display"
    write-host "               - YMD (Default)    : An output of only Year-Month-Day"
    write-host "               - YMDH             : An output of only Year-Month-Day Hourh"
    write-host "               - YMDHM            : An output of only Year-Month-Day Hour:Minute"
    write-host "               - YMDHMS           : An output of only Year-Month-Day Hour:Minute:Second"
    write-host "               - YMDHMm           : An output of only Year-Month-Day Hour:Minute:Second.Millisecond"
    write-host " -Verbosity  : The table can display different level data"
    write-host "               - Minimal (Defaul) : Just counts the occurence of events with no detail on the event"
    write-host "               - Standard         : Adds a detail on the event (often the 1rst parameter)"
    write-host "               - Verbose          : Adds details on the event`n"
    write-host " -Multiline  : Gives the possibility to split the events details in multiple lines"
    write-host "               Default Value is unset : All the data ia appended to the same line"
    write-host " Notes : "
    write-host "   - If the path of the current folder contains `[ or `] the script will fail"
    write-host "     Powershell apparently does not like these characters`n"
    write-host "   * It is mandatory to provide either EventId or EventLevel"
    write-host "     You can give one of them or both, but none will stop.`n"
    write-host " Examples:`n"
    write-host "   .\Chase-Several-Events.ps1 -EventId 5120 -Format YMDH -Days 7"
    write-host "       Will look for event IDs 5120 that happened in the last 7 days in all the"
    write-host "       system event logs of the current folder`n"
    write-host "   .\Chase-Several-Events.ps1 -EventID 5120 -Format YMDH -Days 7 -Verbosity Verbose"
    write-host "       Same as above but will add the CSV that had an error and its error code`n"
    write-host "   .\Chase-Several-Events.ps1 -EventId 1069,1146 -Format YMD -Days 30"
    write-host "       Will look for event IDs 1069 & 1146 that happened in the last month`n"
    write-host "   .\Chase-Several-Events.ps1 -EventLevel Critical -Format YMD"
    write-host "       Will look for all the critical events that were logged`n"
    Write-Host "Run this tool from a machine with Powershell 5.1 or above (Win10 is fine)"
    write-host " (`$Host to know the version you're running on)."
    Write-Host ""
    break
}
#endregion

function Check_Arguments(){
    if (!$EventId -and !$EventLevel)
    {
        Write-Host "Either EventId or EventLevel is mandatory"
        Write-Host "Run with -Help for more information`n"
        Break
    }
}

function Check_TimeFormat(){

    if ($TimeFormat)
    {
        if (($TimeFormat -notmatch "YMD") -and ($TimeFormat -notmatch "YMDH") -and ($TimeFormat -notmatch "YMDHM") -and ($TimeFormat -notmatch "YMDHMS") -and ($TimeFormat -notmatch "YMDHMSm"))
        {
            Write-Host "Bad output format. Must be either YMD, YMDH or YMDHM"
            Write-Host "Run -help for more information"
            break
        }
    }
}

function  Check_Set_Delay(){
    # ----- 1 day = 86400000 milliseconds
    [long]$Delay_1D = 86400000  
    if (-not $Days)
    {
        $Global:Ever = $true
    }
    else
    {
        $Global:Ever = $false
        $Global:Delay = $Delay_1D*$Days
    }
}

function Build_Query(){

    # ----- Very convenient way to have tables of everything
    #       indexed with everything
    $EventLevelToString = @{}
    $EventLevelToString['Critical'] = "Level=1"
    $EventLevelToString['Error'] = "Level=2"
    $EventLevelToString['Warning'] = "Level=3"
    $EventLevelToString['Information'] = "Level=4 or Level=0"
    $EventLevelToString['Verbose'] = "Level=5"

    # ----- Build the Event ID's list
    if ($EventId.Count -ne 0){
        $StrListOfEvents = "EventID="+$EventId[0]
        for ($i = 1; $i -lt $EventId.Count; $i++){
            $StrListOfEvents += " or EventID="+$EventId[$i]
        }
        $StrListOfEvents = "("+$StrListOfEvents+")"
    }
    else{
        $StrListOfEvents = "(no id)"
    }
    
    # ----- Build the Event Level's list
    if ($EventLevel.Count -ne 0){
        $StrListOfLevels = $EventLevelToString[$EventLevel[0]]
        for ($i = 1; $i -lt $EventLevel.Count; $i++){
            $StrListOfLevels += " or "+$EventLevelToString[$EventLevel[$i]]
        }
        $StrListOfLevels = "("+$StrListOfLevels+")"
    }
    else{
        $StrListOfLevels = "(no level)"
    }

    # ----- Build the ID + Level string
    if ($EventId -and $EventLevel){
        $StrFilter = $StrListOfEvents+" and "+$StrListOfLevels
    }
    elseif($EventId -and !$EventLevel){
        $StrFilter = $StrListOfEvents
    }elseif(!$EventId -and $EventLevel){
        $StrFilter = $StrListOfLevels
    }else{
        $StrFilter = "Ouelou!"
    }

    # Build the XML Query
    if ($Ever)
    {
        $Global:Query = "<QueryList><Query><Select>*[System["+$StrFilter+"]]</Select></Query></QueryList>"
    }
    else
    {
        $Global:Query = "<QueryList><Query><Select>*[System["+$StrFilter+" and TimeCreated[timediff(@SystemTime) &lt;= $Delay]]]</Select></Query></QueryList>"
    }
}

function GetEventFromCellString([string]$String){
    return $String.split('()')[0]
}

function GetEventCountFromCellString([string]$String){
    return [convert]::ToInt32($String.split('()')[1],10)
}

function Pause(){
    Read-Host 'Press Enter to continue...' | Out-Null
}

function Get_Detail([System.Diagnostics.Eventing.Reader.EventRecord]$EventRecord, 
                    [string]$OutputLevel){
    #   $OutputLevel reflects the $Output argument
    #   It can be "Minimal", "Standard" or "Verbose"

    if ($Multiline){
        $Sep = "`n"
    }
    else{
        $Sep = '|'
    }
    # write-host "Id:"$EventRecord.Id -ForegroundColor Yellow
    if ($OutputLevel -eq "Minimal"){
        $Result = ""
    }
    else{
        switch ($EventRecord.Id){
            "1069"{ # ----- Resource Failed - WS16
                    #       Properties[0]: ResourceName
                    #       Properties[1]: ResourceGroup
                    #       Properties[2]: ResTypeDll
                if ($OutputLevel -eq "Standard"){
                    $Result = $EventRecord.Properties[0].Value
                }
                else{
                    $Result = $EventRecord.Properties[0].Value+$Sep+$EventRecord.Properties[1].Value+$Sep+$EventRecord.Properties[2].Value
                }
                break
            }
            "1135"{ # ----- Connection loss with a node - Get the node name
                $Result = $EventRecord.Properties[0].Value
                break        
            }
            "1177"{ # ----- Cluster Service is shutting down - Nothing in the event but the name of the current node
                $Result = $EventRecord.Properties[0].Value
                break
            }
            "1146"{ # ----- RHS Deadlock - Nothing in the event but the name of the current node
                $Result = $EventRecord.Properties[0].Value
                break
            }
            "1230"{ # ----- Cluster resource Timeout - For WS16
                    #       Properties[0]: ResourceName
                    #       Properties[1]: ResourceType
                    #       Properties[2]: ResTypeDll
                    if ($OutputLevel -eq "Standard"){
                        $Result = $EventRecord.Properties[0].Value 
                    }
                    else{
                        $Result = $EventRecord.Properties[0].Value + $Sep + $EventRecord.Properties[1].Value + $Sep + $EventRecord.Properties[2].Value 
                    }
                break
            }
            "1564"{ # ----- Failed to arbitrate for the file share 
                    #       Properties[0]: ResourceName
                    #       Properties[1]: ShareName
                    #       Properties[2]: BinaryParameterLength
                    #       Properties[3]: BinaryData
                    if($OutputLevel -eq "Standard"){
                        $Result = $EventRecord.Properties[0].Value
                    }
                    else{
                        $Result = $EventRecord.Properties[0].Value + $Sep + $EventRecord.Properties[1].Value
                    }
                    break
            }
            "5120"{ # ----- CSV entered a paused state - For WS16:
                    #       Properties[0]: VolumeName (Volume5, Volume3, etc.)
                    #       Properties[1]: ResourceName (Cluster Disk 7, Cluster Disk 1, etc.)
                    #       Properties[2]: ErrorCode (STATUS_CONNECTION_DISCONNECTED, STATUS_NO_SUCH_DEVICE, etc.)
                    #       Properties[3]: DiskDeviceNumber : a number
                    #       Properties[4]: DiskDeviceGuid : a GUID
                if($OutputLevel -eq "Standard"){
                    $Result = $EventRecord.Properties[1].Value
                }
                else{
                    $Result = $EventRecord.Properties[1].Value + $Sep + $EventRecord.Properties[2].Value
                }
                break
            }
            "5142"{ # ----- CSV No longer accessible
                    #       Properties[0] : VolumeName (Volume5, Volume3, etc.)
                    #       Properties[1] : ResourceName (Cluster Disk 7, Cluster Disk 1, etc.)
                    #       Properties[2] : ErrorCode (1460, etc.)
                    #       Properties[3] : ReasonCode (UnmapReasonCsvFsStateTransitionTimeout, etc.)
                    #       Properties[4] : DiskDeviceNumber : a number
                    #       Properties[5] : DiskDeviceGUID : a GUID if any
                if ($OutputLevel -eq "Standard"){
                    $Result = $EventRecord.Properties[1].Value
                }
                else{
                    $Result = $EventRecord.Properties[1].Value + $Sep + $EventRecord.Properties[2].Value + $Sep + $EventRecord.Properties[3].Value
                }
                break
            }
            "6008"{ # ----- Unexpected Reboot
                    #       Properties[0] : Time
                    #       Properties[1] : Date
                $Result = $EventRecord.Properties[1].Value+' '+ $EventRecord.Properties[0].Value
                break
            }
            "6013"{ # ----- System Uptime
                    #       Properties[4] : Time in seconds
                $TSpan = $EventRecord.Properties[4].Value
                $Result = "d{0} {1}h{2}m{3}s" -f [timespan]::fromseconds($TSpan).Days , [timespan]::fromseconds($TSpan).Hours ,[timespan]::fromseconds($TSpan).Minutes ,[timespan]::fromseconds($TSpan).Seconds
                break
            }
            "41"{   # ----- It can contain a BSOD in the first paramerer (but the value is in decimal)
                    #       Properties[0] : "0" or BSOD if any
                if ($EventRecord.Properties[0].Value -eq "0"){
                    $Result = '-'
                }
                else{
                    $Result = 'BSOD 0x{0:X}' -f $EventRecord.Properties[0].Value
                }
                break                
            }
            "1001"{ # ----- Bugcheck
                    #       Properties[0] : The BSOD
                $Result = $EventRecord.Properties[0].Value
                break                
            }

            "7036"{ # ----- Status changed for a service
                    #       Properties[0] : Service Name
                    #       Properties[1] : Status
                if ($OutputLevel -eq "Standard"){
                    $Result = $EventRecord.Properties[0].Value
                }
                else{
                    $Result = $EventRecord.Properties[0].Value + $Sep + $EventRecord.Properties[1].Value
                }
                break
            }
            default {
                $Result = $EventRecord.Properties[0].Value
                break
            }
        }
    }
    return $Result
}

#endregion

# ::::: MAIN :::::
#
#   1. Parses the arguments
#   2. Generates the query
#   3. Runs the query
#   4. Saves the output in a CSV
#   5. Exports the output in a grid-view
#

# ::::: NEXT VERSION SHOULD INCLUDE :::::
#   - Export to a real Excel file
#       - Add some colors
#       - Add a dialog that shows the entire event content when selecting an event
#
#   - For any suggestions, contact sergeg@microsoft.com


# Show Help if asked - Includes a break
if ($Help){ 
    Show_Help 
}

# EventId is mandatory - Breaks if missing
# Check_EventId            
Check_Arguments   

# Check if the output format is set then correctly - breaks if not set correctly
Check_TimeFormat

# Check if an history is asked, then set the variables according
$Global:Ever = $false
$Global:Delay = 0
Check_Set_Delay

# Generating the query
Build_Query

# Create the output file
$CurrentDir = [System.IO.Path]::GetDirectoryName($myInvocation.MyCommand.Definition)
if ($EventId.Count -eq 1){ $FileName = $EventId[0]}
else{ $FileName = "Events" }
$OutputFile = $CurrentDir+"\"+$FileName+".csv"

# Display the query to be run
Write-Host "Running this query:" -ForegroundColor Yellow
Write-Host "  "$Query 

# Build a class that will be used by the list of events
# The Class works only starting powershell 5.1
# It gives the possibility to easily build a list of stuctured elements
# using a constructor we define
#

class Event{
    [string]$C_NodeName
    [string]$C_Date
    [string]$C_EventID
    [string]$C_Detail
    Event([string]$NodeName, [string]$Date, [string]$ID, [string]$Detail){
        $this.C_NodeName = $NodeName
        $this.C_Date = $Date
        if ($Detail){
            $this.C_Detail = $Detail
            $this.C_EventID = $ID+"["+$Detail+"]"
        }
        else{
            $this.C_EventID = $ID
        }
    }
}

$ListOfEvents = @()
$NodesList = @()

# Browse and parse the system event logs in the current folder
# We rely on the naming convention so 
# we're looking for "*System*.evtx" files
#

write-host "Events found per node (time for a coffee break)..." -ForegroundColor Yellow
Get-ChildItem | Where-Object Name -like "*System*evtx" | ForEach-Object { 
    
    # Build the list of the nodes
    # Read the first event of each evtx file, get the MachineName field and build the list 
    #

    $ServerName = (Get-WinEvent -MaxEvents 1 -Path $_.FullName).MachineName.Split('.')[0]
    
    if ($ServerName -notin $NodesList){
        $NodesList += $ServerName
    }
    
    # Collect the events and build the list
    write-host "  "$ServerName": " -NoNewline
    $EventsFound = Get-WinEvent -Path $_.FullName -FilterXPath $Query -ErrorAction SilentlyContinue

    if ($EventsFound.count -eq 0)
    {
        write-host "none"
    }
    else
    {
        write-host $EventsFound.count

        $EventsFound | ForEach-Object {

            if ($_.TimeCreated.Month -lt 10) { $Month = "0"+$_.TimeCreated.Month } else { $Month = $_.TimeCreated.Month }
            if ($_.TimeCreated.Day -lt 10) { $Day = "0"+$_.TimeCreated.Day } else { $Day = $_.TimeCreated.Day }
            if ($_.TimeCreated.Hour -lt 10) { $Hour = "0"+$_.TimeCreated.Hour } else { $Hour = $_.TimeCreated.Hour }
            if ($_.TimeCreated.Minute -lt 10) { $Minute = "0"+$_.TimeCreated.Minute } else { $Minute = $_.TimeCreated.Minute }
            if ($_.TimeCreated.Second -lt 10) { $Second = "0"+$_.TimeCreated.Second } else { $Second = $_.TimeCreated.Second }
            if ($_.TimeCreated.Millisecond -lt 10){ 
                $Millisecond = "00"+ $_.TimeCreated.Millisecond
            }elseif($_.TimeCreated.Millisecond -lt 100){ 
                $Millisecond = "0"+ $_.TimeCreated.Millisecond
            }else{
                $Millisecond = $_.TimeCreated.Millisecond
            }
            
            # TimeFomrat can be : "YMD","YMDH","YMDHM","YMDHMS","YMDHMSm"
            if (!$TimeFormat -or $TimeFormat -eq "YMDHMS"){
                $Date = ("{0} {1} {2}-{3}:{4}:{5}" -f $_.TimeCreated.Year, $Month, $Day, $Hour, $Minute, $Second)
            }
            elseif ($TimeFormat -eq "YMD")
            {
                $Date = ("{0} {1} {2}" -f $_.TimeCreated.Year, $Month, $Day)
            }
            elseif ($TimeFormat -eq "YMDH"){
                $Date = ("{0} {1} {2}-{3}" -f $_.TimeCreated.Year, $Month, $Day, $Hour)
            }
            elseif ($TimeFormat -eq "YMDHM") {
                $Date = ("{0} {1} {2}-{3}:{4}" -f $_.TimeCreated.Year, $Month, $Day, $Hour, $Minute)
            }
            else {
                $Date = ("{0} {1} {2}-{3}:{4}:{5}.{6}" -f $_.TimeCreated.Year, $Month, $Day, $Hour, $Minute, $Second, $Millisecond)
            }
            
            # $Verbosity can be either "Minimal", "Standard" or "Verbose"
            if ($Verbosity -eq "Minimal"){
                $ListOfEvents += [Event]::New($ServerName, $Date, $_.ID,$null)
            }
            else{
                $EventDetail = Get_Detail $_ $Verbosity
                $ListOfEvents += [Event]::New($ServerName, $Date, $_.ID,$EventDetail)
            }
            
            
        }
    }
}

# Arranging the nodes list by alphabetical order
# <IMPROVEMENTS>
#   In a clustering content, add the node number in ()
#   This should be possible by loading the registry hive availavle in an SDP Report
# </IMPROVEMENTS>

# Ordering the list of nodes 
$NodesList = $NodesList | Sort-Object

# Ordering events per date and group per date
$ListOfEvents = $ListOfEvents | Sort-Object C_Date -Descending

if ($ListOfEvents.Count -eq 0){
    Write-Host "Nothing to display, but the result is saved."
}
else {

    # ----- Creation of an Excel sheet

    $excel = New-Object -ComObject Excel.Application
    $excel.Visible = $false
    $workbook = $excel.Workbooks.Add()
    $Sheet = $workbook.worksheets.Item(1)

    if ($EventId.Count -eq 1){ 
        $Sheet.Name = $EventId[0]
    }
    else{ 
        $Sheet.Name = "Events"
    }
    
    # ----- Build the list of columns
    
    $Sheet.Cells.Item(1,1) = "Date Time"
    for ($Column = 0; $Column -lt $NodesList.Count; $Column++){
        $Sheet.Cells.Item(1,$Column+2) = $NodesList[$Column]
    }

    # ----- NodesToColumn allows to get the column name from the node name
    $NodesToColumn = @{}
    for ($i = 0; $i -lt $NodesList.Count; $i++){
        $NodesToColumn[$NodesList[$i]] = $i+2
    }
    
    # Fill the tables with the data
    <#

        The EventsList is already ordered by Date

        Each cell contains either noting, or an EventID with the number of occurences it's been logged at the same time
        For example: "1234(7)" means that seven 1234 events have been logged at the same time by the same node

        For each event : Look for the date in the first column of the table
        - If no date in the table matches the date of the event
            - Add a new line to the table and set the date to the first column
            - Add the EventID to Cell corresponding to the new date and the node
        - Else
            - If the cell corresponding to the Node and the Date is empty
                - Add the EventId to the cell with an occurence counte set to 1
            - Else (The cell is not empty)
                - If the Cell contains the same EventID : Increment the count by 1
                - Else (the Cell contains a different EventID) : 
                    - Add a new line to the table and set the date to the first column
                    - Add the EventID to Cell corresponding to the new date and the node
    #>
    
    Write-Host "Building the table (time for a second coffee break)..." -ForegroundColor Yellow
    # --- Browse the events list
    
    $index = 0
    $ListOfEvents | ForEach-Object {
        $index++
        $ThisEvent = $_
        if ($Verbose){
            write-host "Handling event"$index" : " -NoNewline -ForegroundColor Yellow
            $ThisEvent
        }

        # ============================= Looking for a date in the table that matches the event date

        # ----- Define the Date column 
        #       Better to reset the date range for each new event as I don't know 
        #       if 'EntireColumn' is really entire or stops at the last used row
        #      
        $DateRange = $Sheet.Range("A1").EntireColumn

        # ----- Look for the dates in the first column
        #       $CorrespondingDates is the list of rows containing a matching date
        #
        $CorrespondingDates = $null
        $CorrespondingDates = @()
        $DateFound = $false
        
        $TargetDate = $DateRange.Find($ThisEvent.C_Date)
        if ($null -ne $TargetDate){
            $DateFound = $true
            $FirstDateFound = $TargetDate
            Do{
                $CorrespondingDates += [convert]::ToInt32($TargetDate.row,10)
                $TargetDate = $DateRange.FindNext($TargetDate)
            }While (( $null -ne $TargetDate) -and ($TargetDate.AddressLocal() -ne $FirstDateFound.AddressLocal()))
        }
        
        # ========================= We haven't found any line with the same date : Create a new one
        #
        if ($DateFound -eq $false){

            # ----- Add a new line a the end of the table
            #       We add it at the end because $ListOfEvents is already sorted by date
            $LastUsedLine = $Sheet.UsedRange.Rows.Count
            
            # Add the date to the following row
            $Sheet.Cells.Item($LastUsedLine+1,1) = $ThisEvent.C_Date
            
            # Add EventId to the cell that corresponds to the node, and give it a count of (1) as it is the first occurence
            $Sheet.Cells.Item($LastUsedLine+1,$NodesToColumn[$ThisEvent.C_NodeName]) = $ThisEvent.C_EventID+"(1)"
        }

        # ====================================== We have found at least one line with the same date
        #
        else{ 
            
            # ------------------------------------ If We find only one matching date (the easy one)
            # ----- We check if the event corresponds
            #       - If the cell is empty : Add the new event with count(1)
            #       - If the cell is not empty : Check the content
            #           - If the event corresponds : Increment the count
            #           - If the event does not correspond : Add a new row
            #

            if ($CorrespondingDates.count -eq 1){ 

                # ----- Read the cell 
                $TheCellRow = [convert]::ToInt32($CorrespondingDates[0],10)
                $TheCellCol = [convert]::ToInt32($NodesToColumn[$ThisEvent.C_NodeName],10)
                $CellContent = $Sheet.Cells.Item($TheCellRow,$TheCellCol).text
               
                # ----- The cell is empty : Add the event
                if ($CellContent -eq "") # an empty cell is not $null but ""
                {
                    $NewCellValue = $ThisEvent.C_EventID+"(1)"
                    $Sheet.Cells.Item($TheCellRow,$TheCellCol) = $NewCellValue
                }
                # ----- The cell is not empty : Check the content
                #       - If the EventId is the same : Increment the count
                #       - If the EventId is different : Add a new row
                else{
                    # ----- Get the Event Part
                    $EventInTheCell = GetEventFromCellString($CellContent)
                    
                    # ----- The cell contains the same EventId : Increment the count
                    if ($EventInTheCell -eq $ThisEvent.C_EventID){
                        $TheCellRow = [convert]::ToInt32($CorrespondingDates[0],10)
                        $TheCellCol = [convert]::ToInt32($NodesToColumn[$ThisEvent.C_NodeName],10)
                        
                        [int32]$EventsCount = GetEventCountFromCellString($CellContent)
                        $EventsCount+=1
                        
                        [string]$strEventCount = "("+[convert]::ToString($EventsCount)+")"
                        $NewCellValue = $ThisEvent.C_EventID+$strEventCount
                        
                        $Sheet.Cells.Item($TheCellRow,$TheCellCol) = $NewCellValue
                    }
                    # ------ The Cell contains a different EventId : Create a new row and fill the date & cell
                    else{
                        # Get the last row of the table
                        $LastUsedLine = $Sheet.UsedRange.Rows.Count
                        
                        # Add a new row, then fill it with the new data
                        $NewRow = $LastUsedLine+1
                        $Sheet.Cells.Item($NewRow,1) = $ThisEvent.C_Date
                        $Sheet.Cells.Item($NewRow,$TheCellCol) = $ThisEvent.C_EventID+"(1)"
                    }
                }
            } #  End of block "One matching date"

            # --------------------------------------------------- If We find several matching dates
            # ----- We check if one of them matches the event
            #       - If one of them matches the event : Increment the count
            #       - If none of them matches the event
            #           - If one of them is empty : Add the date
            #           - If none is empty : Add a line
            #   Recall:
            #     $CorrespondingDates @()     : Contains the list of the rows with the same date
            #     $ThisEvent                  : Contains the current event
            #         C_Date
            #         C_EventId
            #         C_NodeName
            #     $Sheet.Cells.Item()         : 
            #     $Sheet.Cells.Item().text    : Content of the Cell
            #   

            else{

                # ----- Check if one of the cells matches the event
                $TheCellCol = [convert]::ToInt32($NodesToColumn[$ThisEvent.C_NodeName],10)
                $MatchFound = $false
                $MatchingRow = 0
                $EmptyRows = @()

                # ----- We use a for loop instead of a ForEach-Object because 
                #       break would leave the program instead of the only block
                for ( $i=0 ; $i -lt $CorrespondingDates.count; $i++){
                    $TheCellRow = $CorrespondingDates[$i]
                    $CellContent = $Sheet.Cells.Item($TheCellRow,$TheCellCol).text
                    $EventInTheCell = GetEventFromCellString($CellContent)

                    # --- If the cell is empty, add it to a list of empty cells
                    #     We'll use the first of them to add the EventId if don't catch a matching Event Id
                    if ($EventInTheCell -eq ""){
                        $EmptyRows += $CorrespondingDates[$i]
                    }
                    elseif ($EventInTheCell -eq $ThisEvent.C_EventID){
                        $MatchingRow = $TheCellRow
                        $MatchFound = $true
                        break
                    }
                }

                # ----- If we find one, we increment the count
                #       No need to read back the cell content : It's been read in the above look
                #       No need to reset the cell column : It's been set at the top of the block
                #       We're using the $MatchinRow as TheCellRow because it's been set in the above loop
                if ($MatchFound -eq $true){
                    [int32]$EventsCount = GetEventCountFromCellString($CellContent)
                    $EventsCount+=1
                    [string]$strEventCount = "("+[convert]::ToString($EventsCount)+")"
                    $NewCellValue = $ThisEvent.C_EventID+$strEventCount
                    $Sheet.Cells.Item($MatchingRow,$TheCellCol) = $NewCellValue
                }
                # ----- No match found : We must know there is an empty space
                #       - If there is an empty cell : Update this cell
                #       - If there is no empty cell and no matching event : Create a new row
                else {
                    # ----- There is an empty cell : Set the cell with the EventId
                    if ($EmptyRows.count -ne 0){
                        $NewCellValue = $ThisEvent.C_EventID+"(1)"
                        $TheCellRow = [convert]::ToInt32($EmptyRows[0],10)
                        $Sheet.Cells.Item($TheCellRow,$TheCellCol) = $NewCellValue
                    } 
                    # ------ There is neither empty cell nor matching event : Add a new line
                    else {
                        $LastUsedLine = $Sheet.UsedRange.Rows.Count
                        $NewRow = $LastUsedLine+1
                        $Sheet.Cells.Item($NewRow,1) = $ThisEvent.C_Date
                        $Sheet.Cells.Item($NewRow,$TheCellCol) = $ThisEvent.C_EventID+"(1)"
                    }
                }
            } #  End of block "Several matching dates"
            
        } # End of block "At least one line with the same event is found"

    } # End of $ListOfEvents loop

} # End if block" ListOfEvents -ne 0"

# Save the Excel file quit Excel
$Sheet.SaveAs($OutputFile,6)
$excel.Quit()

# Display the output file using a GridView
# The output file is still available as a CSV

write-host "The result is store in : " -ForegroundColor Yellow -NoNewline
Write-Host $OutputFile

Write-Host "Exporting the result in a grid-view" -ForegroundColor Yellow
Import-Csv $OutputFile | Out-GridView -Title $FileName