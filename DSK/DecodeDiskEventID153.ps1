<#
    .Disclaimer
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
    Author: Marcus Ferreira <marcus.ferreira@microsoft.com>
    Contributor:  Alexandre Balbi <alexandre.balbi@microsoft.com>
    Version: 1.0

    .DESCRIPTION
    This script decodes the event id 153 where source = disk.
    It reads all data and extracts the binary data from the event.
    The binary data is contained in the event tree Event.Event.EventData.Binary,
    the content is similar to:
    0F0118000400400000000000990004800000000000000000000000000000000000000000000000000002042A70000B000000000A000000004400000000002D2D
    The aim of this script is to translate this binary data into useful information in troubleshooting storage issues.
    
    .EXAMPLE
    Get all events from file "C:\temp\System.evtx"
    .\DecodeDiskEventID153.ps1 -EvtxPath "C:\temp\System.evtx" -AllEvents

    .EXAMPLE
    Get events from file "C:\temp\System.evtx", between "3/12/2019" and "3/15/2019"
    .\DecodeDiskEventID153.ps1 -EvtxPath "C:\temp\System.evtx" -StartDate "3/12/2019" -EndDate "3/15/2019"

    .EXAMPLE
    Get events from local machine, between "3/12/2019" and "3/15/2019"
    .\DecodeDiskEventID153.ps1 -StartDate "3/12/2019" -EndDate "3/15/2019"

    .EXAMPLE
    Get all events from local machine.
    .\DecodeDiskEventID153.ps1 -AllEvents

    .EXAMPLE
    Get events from local machine, be prompted for interval. Cancel date prompt to get all events.
    .\DecodeDiskEventID153.ps1
#>

Param(
    # Begin date
    [Parameter(Mandatory = $false)]
    [DateTime] $StartDate,

    # End date
    [Parameter(Mandatory = $false)]
    [DateTime] $EndDate,

    [Parameter(Mandatory = $false)]
    [string] $EvtxPath = "",

    [Parameter(Mandatory = $false)]
    [switch] $AllEvents
)

#region: Script Functions

Function GetSCSICMD([string] $cmd) {
    <#
	  .Synopsis
		Translates SCSI commands into easy to read data
	  .Description
		SCSI commands extracted from https://en.wikipedia.org/wiki/SCSI_command
	  .Parameter cmd
		SCSI command to translate
    #>
    
    switch ($cmd) {
        "00" { "TEST UNIT READY" }
        "01" { "REWIND" }
        "03" { "REQUEST SENSE" }
        "04" { "FORMAT" }
        "05" { "READ BLOCK LIMITS" }
        "07" { "REASSIGN BLOCKS" }
        "07" { "INITIALIZE ELEMENT STATUS" }
        "08" { "READ(6)" }
        "0A" { "WRITE(6)" }
        "0B" { "SEEK(6)" }
        "0F" { "READ REVERSE(6)" }
        "10" { "WRITE FILEMARKS(6)" }
        "11" { "SPACE(6)" }
        "12" { "INQUIRY" }
        "13" { "VERIFY(6)" }
        "14" { "RECOVER BUFFERED DATA" }
        "15" { "MODE SELECT(6)" }
        "16" { "RESERVE(6)" }
        "17" { "RELEASE(6)" }
        "18" { "COPY" }
        "19" { "ERASE (6)" }
        "1A" { "MODE SENSE (6)" }
        "1B" { "START STOP UNIT" }
        "1B" { "LOAD UNLOAD" }
        "1C" { "RECEIVE DIAGNOSTIC RESULTS" }
        "1D" { "SEND DIAGNOSTIC" }
        "1E" { "PREVENT ALLOW MEDIUM REMOVAL" }
        "23" { "READ FORMAT CAPACITIES" }
        "25" { "READ CAPACITY(10)" }
        "28" { "READ(10)" }
        "29" { "READ GENERATION" }
        "2A" { "WRITE(10)" }
        "2B" { "SEEK(10)" }
        "2B" { "LOCATE(10)" }
        "2C" { "ERASE(10)" }
        "2D" { "READ UPDATED BLOCK" }
        "2E" { "WRITE AND VERIFY(10)" }
        "2F" { "VERIFY(10)" }
        "33" { "SET LIMITS(10)" }
        "34" { "PRE-FETCH(10)" }
        "34" { "READ POSITION" }
        "35" { "SYNCHRONIZE CACHE(10)" }
        "36" { "LOCK UNLOCK CACHE(10)" }
        "37" { "READ DEFECT DATA(10)" }
        "37" { "INITIALIZE ELEMENT STATUS WITH RANGE" }
        "38" { "MEDIUM SCAN" }
        "39" { "COMPARE" }
        "3A" { "COPY AND VERIFY" }
        "3B" { "WRITE BUFFER" }
        "3C" { "READ BUFFER" }
        "3D" { "UPDATE BLOCK" }
        "3E" { "READ LONG(10)" }
        "3F" { "WRITE LONG(10)" }
        "40" { "CHANGE DEFINITION" }
        "41" { "WRITE SAME(10)" }
        "42" { "UNMAP" }
        "43" { "READ TOC/PMA/ATIP" }
        "44" { "REPORT DENSITY SUPPORT" }
        "45" { "PLAY AUDIO(10)" }
        "46" { "GET CONFIGURATION" }
        "47" { "PLAY AUDIO MSF" }
        "48" { "SANITIZE" }
        "4A" { "GET EVENT STATUS NOTIFICATION" }
        "4B" { "PAUSE/RESUME" }
        "4C" { "LOG SELECT" }
        "4D" { "LOG SENSE" }
        "50" { "XDWRITE(10)" }
        "51" { "XPWRITE(10)" }
        "51" { "READ DISC INFORMATION" }
        "52" { "XDREAD(10)" }
        "53" { "XDWRITEREAD(10)" }
        "54" { "SEND OPC INFORMATION" }
        "55" { "MODE SELECT(10)" }
        "56" { "RESERVE(10)" }
        "57" { "RELEASE(10)" }
        "58" { "REPAIR TRACK" }
        "5A" { "MODE SENSE(10)" }
        "5B" { "CLOSE TRACK/SESSION" }
        "5C" { "READ BUFFER CAPACITY" }
        "5D" { "SEND CUE SHEET" }
        "5E" { "PERSISTENT RESERVE IN" }
        "5F" { "PERSISTENT RESERVE OUT" }
        "7E" { "extended CDB" }
        "7F" { "variable length CDB" }
        "80" { "XDWRITE EXTENDED(16)" }
        "80" { "WRITE FILEMARKS(16)" }
        "81" { "READ REVERSE(16)" }
        "83" { "Third-party Copy OUT commands" }
        "84" { "Third-party Copy IN commands" }
        "85" { "ATA PASS-THROUGH(16)" }
        "86" { "ACCESS CONTROL IN" }
        "87" { "ACCESS CONTROL OUT" }
        "88" { "READ(16)" }
        "89" { "COMPARE AND WRITE" }
        "8A" { "WRITE(16)" }
        "8B" { "ORWRITE" }
        "8C" { "READ ATTRIBUTE" }
        "8D" { "WRITE ATTRIBUTE" }
        "8E" { "WRITE AND VERIFY(16)" }
        "8F" { "VERIFY(16)" }
        "90" { "PRE-FETCH(16)" }
        "91" { "SYNCHRONIZE CACHE(16)" }
        "91" { "SPACE(16)" }
        "92" { "LOCK UNLOCK CACHE(16)" }
        "92" { "LOCATE(16)" }
        "93" { "WRITE SAME(16)" }
        "93" { "ERASE(16)" }
        "9D" { "SERVICE ACTION BIDIRECTIONAL" }
        "9E" { "SERVICE ACTION IN(16)" }
        "9F" { "SERVICE ACTION OUT(16)" }
        "A0" { "REPORT LUNS" }
        "A1" { "ATA PASS-THROUGH(12)" }
        "A2" { "SECURITY PROTOCOL IN" }
        "A3" { "MAINTENANCE IN" }
        "A4" { "MAINTENANCE OUT" }
        "A4" { "REPORT KEY" }
        "A5" { "MOVE MEDIUM" }
        "A5" { "PLAY AUDIO 12" }
        "A6" { "EXCHANGE MEDIUM" }
        "A7" { "MOVE MEDIUM ATTACHED" }
        "A8" { "READ(12)" }
        "A9" { "SERVICE ACTION OUT(12)" }
        "AA" { "WRITE(12)" }
        "AB" { "SERVICE ACTION IN(12)" }
        "AC" { "ERASE(12)" }
        "AD" { "READ DVD STRUCTURE" }
        "AE" { "WRITE AND VERIFY(12)" }
        "AF" { "VERIFY(12)" }
        "B0" { "SEARCH DATA HIGH(12)" }
        "B1" { "SEARCH DATA EQUAL(12)" }
        "B2" { "SEARCH DATA LOW(12)" }
        "B3" { "SET LIMITS(12)" }
        "B4" { "READ ELEMENT STATUS ATTACHED" }
        "B5" { "SECURITY PROTOCOL OUT" }
        "B6" { "SEND VOLUME TAG" }
        "B7" { "READ DEFECT DATA(12)" }
        "B8" { "READ ELEMENT STATUS" }
        "B9" { "READ CD MSF" }
        "BA" { "REDUNDANCY GROUP (IN)" }
        "BB" { "REDUNDANCY GROUP (OUT)" }
        "BC" { "SPARE (IN)" }
        "BD" { "SPARE (OUT)" }
        "BE" { "VOLUME SET (IN)" }
        "BF" { "VOLUME SET (OUT)" }
    }
}

Function GetSCSIStatus([string] $scsistatus) {
    <#
	  .Synopsis
		Translates SCSI status into easy to read data
	  .Description
		SCSI statuses extracted from https://en.wikipedia.org/wiki/SCSI_Status_Code
	  .Parameter scsistatus
		SCSI status to translate
    #>
    switch ($scsistatus) {
        "00" { "Good" }
        "02" { "Check Condition" }
        "04" { "Condition Met" }
        "08" { "Busy" }
        "10" { "Intermediate (obsolete)" }
        "14" { "Intermediate - Condition Met (obsolete)" }
        "18" { "Reservation Conflict" }
        "22" { "Command Terminated (obsolete)" }
        "28" { "Task Set Full" }
        "30" { "ACA Active" }
        "40" { "Task Aborted" }        
    }
}

Function GetSRBStatus([string] $SRBStatus) {
    <#
	  .Synopsis
		Translates SRB status into easy to read data
	  .Description
		SRB statuses extracted from https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rsvd/e41faee5-d3b0-471f-a713-aed273f78693
	  .Parameter SRBStatus
		SRB status to translate
    #>

    switch ($SRBStatus) {
        "00" { "The request status is pending." }
        "01" { "The request was completed successfully." }
        "02" { "The request was aborted." }
        "06" { "The Shared Virtual Disk does not support the given request." }
        "08" { "The Shared Virtual Disk device is no longer available." }
        "0A" { "The SCSI device selection timed out." }
        "12" { "A data overrun or underrun error occurred." }
        "04" { "The request completed with any other error." }
    }
}

Function GetSenseDataInfo([string] $SenseInfoKey) {
    <#
	  .Synopsis
		Translates 'Key Code Qualifiers' into easy to read data
	  .Description
		Key Code Qualifiers extracted from https://en.wikipedia.org/wiki/Key_Code_Qualifier
	  .Parameter SenseInfoKey
		Key Code Qualifier to translate
    #>

    switch($SenseInfoKey){
        #No Sense	
        "000000" { "No error"  }
        "005D00" { "No sense - PFA threshold reached"  }
        #Soft Error
        "010100" { "Recovered Write error - no index"  }
        "010200" { "Recovered no seek completion"  }
        "010300" { "Recovered Write error - write fault"  }
        "010900" { "Track following error"  }
        "010B01" { "Temperature warning"  }
        "010C01" { "Recovered Write error with auto-realloc - reallocated"  }
        "010C03" { "Recovered Write error - recommend reassign"  }
        "011201" { "Recovered data without ECC using prev logical block ID"  }
        "011202" { "Recovered data with ECC using prev logical block ID"  }
        "011401" { "Recovered Record Not Found"  }
        "011600" { "Recovered Write error - Data Sync Mark Error"  }
        "011601" { "Recovered Write error - Data Sync Error - data rewritten"  }
        "011602" { "Recovered Write error - Data Sync Error - recommend rewrite"  }
        "011603" { "Recovered Write error - Data Sync Error - data auto-reallocated"  }
        "011604" { "Recovered Write error - Data Sync Error - recommend reassignment"  }
        "011700" { "Recovered data with no error correction applied"  }
        "011701" { "Recovered Read error - with retries"  }
        "011702" { "Recovered data using positive offset"  }
        "011703" { "Recovered data using negative offset"  }
        "011705" { "Recovered data using previous logical block ID"  }
        "011706" { "Recovered Read error - without ECC, auto reallocated"  }
        "011707" { "Recovered Read error - without ECC, recommend reassign"  }
        "011708" { "Recovered Read error - without ECC, recommend rewrite"  }
        "011709" { "Recovered Read error - without ECC, data rewritten"  }
        "011800" { "Recovered Read error - with ECC"  }
        "011801" { "Recovered data with ECC and retries"  }
        "011802" { "Recovered Read error - with ECC, auto reallocated"  }
        "011805" { "Recovered Read error - with ECC, recommend reassign"  }
        "011806" { "Recovered data using ECC and offsets"  }
        "011807" { "Recovered Read error - with ECC, data rewritten"  }
        "011C00" { "Defect List not found"  }
        "011C01" { "Primary defect list not found"  }
        "011C02" { "Grown defect list not found"  }
        "011F00" { "Partial defect list transferred"  }
        "014400" { "Internal target failure"  }
        "015D00" { "PFA threshold reached"  }
        #Not Ready
        "020400" { "Not Ready - Cause not reportable."  }
        "020401" { "Not Ready - becoming ready"  }
        "020402" { "Not Ready - need initialise command (start unit)"  }
        "020403" { "Not Ready - manual intervention required"  }
        "020404" { "Not Ready - format in progress"  }
        "020409" { "Not Ready - self-test in progress"  }
        "023100" { "Not Ready - medium format corrupted"  }
        "023101" { " Not Ready - format command failed"  }
        "023502" { "Not Ready - enclosure services unavailable"  }
        "023A00" { "Not Ready - medium not present"  }
        "023A01" { " Not Ready - medium not present - tray closed"  }
        "023A02" { "Not Ready - medium not present - tray open"  }
        "023A03" { "Not Ready - medium not present - loadable"  }
        "023A04" { "Not Ready - medium not present - medium auxiliary memory accessible"  }
        "024C00" { "Diagnostic Failure - config not loaded"  }
        #Medium Error
        "030200" { "Medium Error - No Seek Complete"  }
        "030300" { "Medium Error - write fault"  }
        "031000" { "Medium Error - ID CRC error"  }
        "031100" { "Medium Error - unrecovered read error"  }
        "031101" { "Medium Error - read retries exhausted"  }
        "031102" { "Medium Error - error too long to correct"  }
        "031104" { "Medium Error - unrecovered read error - auto re-alloc failed"  }
        "03110B" { "Medium Error - unrecovered read error - recommend reassign"  }
        "031401" { "Medium Error - record not found"  }
        "031600" { "Medium Error - Data Sync Mark error"  }
        "031604" { "Medium Error - Data Sync Error - recommend reassign"  }
        "031900" { "Medium Error - defect list error"  }
        "031901" { "Medium Error - defect list not available"  }
        "031902" { "Medium Error - defect list error in primary list"  }
        "031903" { "Medium Error - defect list error in grown list"  }
        "03190E" { "Medium Error - fewer than 50% defect list copies"  }
        "033100" { "Medium Error - medium format corrupted"  }
        "033101" { "Medium Error - format command failed"  }
        #Hardware Error
        "040100" { "Hardware Error - no index or sector"  }
        "040200" { "Hardware Error - no seek complete"  }
        "040300" { "Hardware Error - write fault"  }
        "040900" { "Hardware Error - track following error"  }
        "041100" { "Hardware Error - unrecovered read error in reserved area"  }
        "041501" { "Hardware Error - Mechanical positioning error"  }
        "041600" { "Hardware Error - Data Sync Mark error in reserved area"  }
        "041900" { "Hardware Error - defect list error"  }
        "041902" { "Hardware Error - defect list error in Primary List"  }
        "041903" { "Hardware Error - defect list error in Grown List"  }
        "043200" { "Hardware Error - no defect spare available"  }
        "043500" { "Hardware Error - enclosure services failure"  }
        "043501" { "Hardware Error - unsupported enclosure function"  }
        "043502" { "Hardware Error - enclosure services unavailable"  }
        "043503" { "Hardware Error - enclosure services transfer failure"  }
        "043504" { "Hardware Error - enclosure services refused"  }
        "043505" { "Hardware Error - enclosure services checksum error"  }
        "043E00" { "Hardware Error - logical unit has not self configured yet"  }
        "043E01" { "Hardware Error - logical unit failed"  }
        "043E02" { "Hardware Error - timeout on logical unit"  }
        "043E03" { "Hardware Error - self-test failed"  }
        "043E04" { "Hardware Error - unable to update self-test log"  }
        "044400" { "Hardware Error - internal target failure"  }
        #Illegal Request
        "051A00" { "Illegal Request - parm list length error"  }
        "052000" { "Illegal Request - invalid/unsupported command code"  }
        "052100" { "Illegal Request - LBA out of range"  }
        "052400" { "Illegal Request - invalid field in CDB (Command Descriptor Block)"  }
        "052500" { "Illegal Request - invalid LUN"  }
        "052600" { "Illegal Request - invalid fields in parm list"  }
        "052601" { "Illegal Request - parameter not supported"  }
        "052602" { "Illegal Request - invalid parm value"  }
        "052603" { "Illegal Request - invalid field parameter - threshold parameter"  }
        "052604" { "Illegal Request - invalid release of persistent reservation"  }
        "052C00" { "Illegal Request - command sequence error"  }
        "053501" { "Illegal Request - unsupported enclosure function"  }
        "054900" { "Illegal Request - invalid message"  }
        "055300" { "Illegal Request - media load or eject failed"  }
        "055301" { "Illegal Request - unload tape failure"  }
        "055302" { "Illegal Request - medium removal prevented"  }
        "055500" { "Illegal Request - system resource failure"  }
        "055501" { "Illegal Request - system buffer full"  }
        "055504" { "Illegal Request - Insufficient Registration Resources"  }
        #Unit Attention
        "062800" { "Unit Attention - not-ready to ready transition (format complete)"  }
        "062900" { "Unit Attention - POR or device reset occurred"  }
        "062901" { "Unit Attention - POR occurred"  }
        "062902" { "Unit Attention - SCSI bus reset occurred"  }
        "062903" { "Unit Attention - TARGET RESET occurred"  }
        "062904" { "Unit Attention - self-initiated-reset occurred"  }
        "062905" { "Unit Attention - transceiver mode change to SE"  }
        "062906" { "Unit Attention - transceiver mode change to LVD"  }
        "062A00" { "Unit Attention - parameters changed"  }
        "062A01" { "Unit Attention - mode parameters changed"  }
        "062A02" { "Unit Attention - log select parms changed"  }
        "062A03" { "Unit Attention - Reservations pre-empted"  }
        "062A04" { "Unit Attention - Reservations released"  }
        "062A05" { "Unit Attention - Registrations pre-empted"  }
        "062F00" { "Unit Attention - commands cleared by another initiator"  }
        "063F00" { "Unit Attention - target operating conditions have changed"  }
        "063F01" { "Unit Attention - microcode changed"  }
        "063F02" { "Unit Attention - changed operating definition"  }
        "063F03" { "Unit Attention - inquiry parameters changed"  }
        "063F04" { "Unit Attention - component device attached"  }
        "063F05" { "Unit Attention - device identifier changed"  }
        "063F06" { "Unit Attention - redundancy group created or modified"  }
        "063F07" { " Unit Attention - redundancy group deleted"  }
        "063F08" { "Unit Attention - spare created or modified"  }
        "063F09" { "Unit Attention - spare deleted"  }
        "063F0A" { "Unit Attention - volume set created or modified"  }
        "063F0B" { "Unit Attention - volume set deleted"  }
        "063F0C" { "Unit Attention - volume set deassigned"  }
        "063F0D" { "Unit Attention - volume set reassigned"  }
        "063F0E" { "Unit Attention - reported LUNs data has changed"  }
        "063F0F" { "Unit Attention - echo buffer overwritten"  }
        "063F10" { "Unit Attention - medium loadable"  }
        "063F11" { "Unit Attention - medium auxiliary memory accessible"  }
        "063F12" { "Unit Attention - iSCSI IP address added"  }
        "063F13" { "Unit Attention - iSCSI IP address removed"  }
        "063F14" { "Unit Attention - iSCSI IP address changed"  }
        "063F15" { "Unit Attention - inspect referrals sense descriptors"  }
        "063F16" { "Unit Attention - microcode has been changed without reset"  }
        "063F17" { "Unit Attention - zone transition to full"  }
        "063F18" { "Unit Attention - bind completed"  }
        "063F19" { "Unit Attention - bind redirected"  }
        "063F1A" { "Unit Attention - subsidiary binding changed"  }
        "065D00" { "Unit Attention - PFA threshold reached"  }
        #Data Protect
        "072002" { "Access Denied - No Access Rights"  }
        "072700" { "Write Protect - command not allowed"  }
        #Aborted Command
        "0B0000" { "Aborted Command - no additional sense code"  }
        "0B1B00" { "Aborted Command - sync data transfer error (extra ACK)"  }
        "0B2500" { "Aborted Command - unsupported LUN"  }
        "0B3F0F" { "Aborted Command - echo buffer overwritten"  }
        "0B4300" { "Aborted Command - message reject error"  }
        "0B4400" { "Aborted Command - internal target failure"  }
        "0B4500" { "Aborted Command - Selection/Reselection failure"  }
        "0B4700" { "Aborted Command - SCSI parity error"  }
        "0B4800" { "Aborted Command - initiator-detected error message received"  }
        "0B4900" { "Aborted Command - inappropriate/illegal message"  }
        "0B5503" { "Aborted Command - insufficient resources"  }
        "0B4B00" { "Aborted Command - data phase error"  }
        "0B4E00" { "Aborted Command - overlapped commands attempted"  }
        "0B4F00" { "Aborted Command - due to loop initialisation"  }
        #Other
        "0E1D00" { "Miscompare - during verify byte check operation"  }
        "0x0500" { "Illegal request"  }
        "0x0600" { "Unit attention"  }
        "0x0700" { "Data protect"  }
        "0x0800" { "LUN communication failure"  }
        "0x0801" { "LUN communication timeout"  }
        "0x0802" { "LUN communication parity error"  }
        "0x0803" { "LUN communication CRC error"  }
        "0x0900" { "vendor specific sense key"  }
        "0x0901" { "servo fault"  }
        "0x0904" { "head select fault"  }
        "0x0A00" { "error log overflow"  }
        "0x0B00" { "aborted command"  }
        "0x0C00" { "write error"  }
        "0x0C02" { "write error - auto-realloc failed"  }
        "0x0E00" { "data miscompare"  }
        "0x1200" { "address mark not found for ID field"  }
        "0x1400" { "logical block not found"  }
        "0x1500" { "random positioning error"  }
        "0x1501" { "mechanical positioning error"  }
        "0x1502" { "positioning error detected by read of medium"  }
        "0x2700" { "write protected"  }
        "0x2900" { "POR or bus reset occurred"  }
        "0x3101" { "format failed"  }
        "0x3201" { "defect list update error"  }
        "0x3202" { "no spares available"  }
        "0x3501" { "unspecified enclosure services failure"  }
        "0x3700" { "parameter rounded"  }
        "0x3D00" { "invalid bits in identify message"  }
        "0x3E00" { "LUN not self-configured yet"  }
        "0x4001" { "DRAM parity error"  }
        "0x4002" { "DRAM parity error"  }
        "0x4200" { "power-on or self-test failure"  }
        "0x4C00" { "LUN failed self-configuration"  }
        "0x5C00" { "RPL status change"  }
        "0x5C01" { "spindles synchronised"  }
        "0x5C02" { "spindles not synchronised"  }
        "0x6500" { "voltage fault"  }
    }
 }       

Function GetSenseCategory([string] $SenseCategory) {
    <#
	  .Synopsis
		Translates sense categories into easy to read data
	  .Description
		Sense categories extracted from https://en.wikipedia.org/wiki/Key_Code_Qualifier
	  .Parameter SenseCategory
		Sense category to translate
    #>

    switch ($SenseCategory) {
        "00" { "No Sense" }
        "01" { "Soft Error" }
        "02" { "Not Ready" }
        "03" { "Medium Error" }
        "04" { "Hardware Error" }
        "05" { "Illigal Request." }
        "06" { "Unit Attention" }
        "07" { "Data Protect" }
        "0B" { "Aborted Command" }
        "0E" { "Other" }
        "0X" { "Other" }
    }
}

Function ParameterPicker {
    <#
	  .Synopsis
        Shows dialog to select detail level and date range
        We are using this instead of Show-Command for hte date picker
        Test this in PowerShell not in VSCode to see actual output
	  .Description
		This function was reused from https://github.com/Shasankp/CSVSA/blob/master/CSVSABeta1.0.ps1
    #>

    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    [System.Windows.Forms.Application]::EnableVisualStyles()
    
    $Form = New-Object Windows.Forms.Form
    $Form.MaximizeBox = $false
    $Form.FormBorderStyle = "FixedDialog"
    
    $Form.Text = 'Calendar'
    $Form.Size = New-Object Drawing.Size @(245, 300)
    $Form.StartPosition = 'CenterScreen'
    

    $CalendarLabel = New-Object System.Windows.Forms.Label
    $CalendarLabel.Text = "Select Date: "
    $CalendarLabel.Height = 15
    $CalendarLabel.Width = 120
    $CalendarLabel.Location = New-Object System.Drawing.Point(0, 50) 
    $Form.Controls.Add($CalendarLabel)

    $Calendar = New-Object System.Windows.Forms.MonthCalendar
    $Calendar.Location = New-Object System.Drawing.Point(0, 65)
    $Calendar.ShowTodayCircle = $true
    $Calendar.MaxSelectionCount = 300
    $Form.Controls.Add($Calendar)
    
    $OKButton = New-Object System.Windows.Forms.Button
    $OKButton.Location = New-Object System.Drawing.Point(38, 235)
    $OKButton.Size = New-Object System.Drawing.Size(75, 23)
    $OKButton.Text = 'OK'
    $OKButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $Form.AcceptButton = $OKButton
    $Form.Controls.Add($OKButton)
    
    $CancelButton = New-Object System.Windows.Forms.Button
    $CancelButton.Location = New-Object System.Drawing.Point(113, 235)
    $CancelButton.Size = New-Object System.Drawing.Size(75, 23)
    $CancelButton.Text = 'Cancel'
    $CancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $Form.CancelButton = $CancelButton
    $Form.Controls.Add($CancelButton)
    
    $Form.Topmost = $true
    
    
    [void] $Form.ShowDialog()

    if ($calendar.SelectionStart -eq $calendar.SelectionEnd) {
        $calendar.SelectionEnd = $calendar.SelectionEnd.AddDays(1)
    }

    return [PSCustomObject]@{
        DialogResult = $Form.DialogResult
        StartDate    = $calendar.SelectionStart
        EndDate      = $calendar.SelectionEnd
    }
}
#endregion: Script Functions

#region: Validate date range
If ($AllEvents) {
    [DateTime] $StartDate = "01/01/1900"
    [DateTime] $EndDate = (Get-Date).ToString("MM/dd/yyyy")
}

Write-Information "ENTER: Validate date that you want to search the events"

If (!($StartDate) -or !($EndDate)) {
    Write-Information  "Prompting for date interval."
    $ScriptParameters = ParameterPicker
    If ($ScriptParameters.DialogResult -eq "OK") {
        $StartDate = $ScriptParameters.StartDate
        $EndDate = $ScriptParameters.EndDate
    }
    Else {
        #User Cancelled the dialog
        Write-Host "Date prompt cancelled. Assuming all events."
        [DateTime] $StartDate = "01/01/1900"
        [DateTime] $EndDate = (Get-Date).ToString("MM/dd/yyyy")
    }
}
#endregion: Validate date range

#region: Variables
$SRBStatus = ""
$SenseData = ""
$SenseInfoKey = ""
$SenseDataASC = ""
$SenseDataASCQ = ""
$SenseCategory = ""
$SenseDataErrorCondition = ""
$Events153Info = @()
#endregion: Variables

#region: Reading events
Try {
    If ($EvtxPath) {
        If ((Test-Path -Path $EvtxPath -ErrorAction SilentlyContinue)) {
            Write-Host "Reading 153 events from $($EvtxPath)"
            $Events = Get-WinEvent -Path $EvtxPath -ErrorAction SilentlyContinue -ErrorVariable $OutError | `
            Where-Object {$_.Id -eq 153 -And $_.ProviderName -eq "Disk" -and $_.TimeCreated -gt $StartDate -and $_.TimeCreated -lt $EndDate } | `
            Sort-Object -Property TimeCreated -Descending
        } Else {
            Write-Host "File $($EvtxPath) not found."
            return
        }
    } Else {
        Write-Host "Reading events from current machine..."

        $Events = Get-WinEvent -LogName SYSTEM -ErrorAction SilentlyContinue -ErrorVariable $OutError | `
        Where-Object {$_.Id -eq 153 -and $_.ProviderName -eq "Disk" -and $_.TimeCreated -gt $StartDate -and $_.TimeCreated -lt $EndDate } | `
        Sort-Object -Property TimeCreated -Descending

        If ($Events) {
            $AllDisks = Get-Disk
            $AllDiskInfo = @()
    
            Write-Host "Getting disk information..."
            ForEach ($Disk In $AllDisks) {
                $DiskInfo  = New-Object -TypeName psobject
                $DiskInfo  | Add-Member -Name DeviceId -MemberType NoteProperty -Value $Disk.Number
                $DiskInfo  | Add-Member -Name UniqueId -MemberType NoteProperty -Value $Disk.UniqueId
                $DiskInfo  | Add-Member -Name FileSystemLabel -MemberType NoteProperty -Value $(($Disk | Get-Partition | Get-Volume).FileSystemLabel)
    
                $AllDiskInfo += $DiskInfo
            }
        } Else {
            Write-Host "No events id 153 and source = 'Disk' found on the current machine. Try specifying an .evtx file or interval." -ForegroundColor Yellow
            return
        }
    }
} Catch {
    $Error[0].Exception
}
#endregion: Reading events

#region: Get Event Info
$Events | ForEach-Object {
    Try {
        $Event = [xml]$_.toXml()
        $Binary = $Event.Event.EventData.Binary
        $InfoData = $Event.Event.EventData
        $EventInfo = $Event.Event.System
        $DevicePath = $InfoData.Data[0]
        $LBA = $InfoData.Data[1]
        $DiskId = $InfoData.Data[2]

        $Split = @()

        # Decode binary string
        $II = 0  
        For($I = $Binary.Length ; $I -le $Binary.Length -and $I -gt 0; $I -=16) {
            If ($I -ge 16) {
                $Split += $Binary.Substring($II,16)
                $II += 16
            } Elseif ($I -le 8 -and $I -ge 0) {
                $II = ($Binary.Length - 8)
                $Split += $Binary.Substring($II,8)
            }
        }
    
        $BinErrorCode = $Split[1]
        $ErrorCode = "0x" + $BinErrorCode.SubString(14,2) + $BinErrorCode.SubString(12,2) + $BinErrorCode.SubString(10,2) + $BinErrorCode.SubString(8,2)

        $BinFinalStatus = $Split[2]
        $FinalStatus = "0x" + $BinFinalStatus.SubString(14,2) + $BinFinalStatus.SubString(12,2) + $BinFinalStatus.SubString(10,2) + $BinFinalStatus.SubString(8,2)

        $BinSCSISRBStatus = $Split[5]
        $SCSIStatus = GetSCSIStatus $BinSCSISRBStatus.Substring(2,2)
        $SCSICmd = GetSCSICMD $BinSCSISRBStatus.Substring(6,2)
        
        If ($Binary.Length -gt 88) {
            $SRBStatus = GetSRBStatus $BinSCSISRBStatus.Substring(4,2)

            #Add Sense Data from 153 event - by Balbi
            $SenseData = $Split[7]

            $SenseInfoKey = $BinSCSISRBStatus.Substring(12,2)
            $SenseDataASC = $SenseData.Substring(0,2)
            $SenseDataASCQ = $SenseData.Substring(2,2)

            $SenseData = $SenseInfoKey + $SenseDataASC + $SenseDataASCQ 

            $SenseCategory = GetSenseCategory $SenseData.Substring(0,2)

            $SenseDataErrorCondition = GetSenseDataInfo $SenseData
        }

        $Event153  = New-Object -TypeName psobject
        $Event153  | Add-Member -Name ComputerName -MemberType NoteProperty -Value $($Event.Event.System.Computer)
        $Event153  | Add-Member -Name TimeCreated -MemberType NoteProperty -Value $(Get-Date $EventInfo.TimeCreated.SystemTime)
        $Event153  | Add-Member -Name LBA  -MemberType NoteProperty -Value $($LBA)
        $Event153  | Add-Member -Name Disk -MemberType NoteProperty -Value $($DiskId)
        If (-Not $EvtxPath) {
            # If specifying an evtx, assume not running on the server
            # where event was created therefore, not getting disk info
            $Event153  | Add-Member -Name LUNID -MemberType NoteProperty -Value $(($AllDiskInfo | Where-Object {$_.DeviceId -eq $DiskId}).UniqueId)
            $Event153  | Add-Member -Name DiskLabel -MemberType NoteProperty -Value $(($AllDiskInfo | Where-Object {$_.DeviceId -eq $DiskId}).FileSystemLabel)
        }
        $Event153  | Add-Member -Name Device -MemberType NoteProperty -Value $($DevicePath)
        $Event153  | Add-Member -Name Error -MemberType NoteProperty -Value $($ErrorCode)
        $Event153  | Add-Member -Name SCSICommand -MemberType NoteProperty -Value `"$($SCSICmd)`"
        $Event153  | Add-Member -Name FinalStatus -MemberType NoteProperty -Value $($FinalStatus)
        $Event153  | Add-Member -Name SRBStatus -MemberType NoteProperty -Value `"$($SRBStatus)`"
        $Event153  | Add-Member -Name SCSIStatus -MemberType NoteProperty -Value `"$($SCSIStatus)`"
        $Event153  | Add-Member -Name SenseDataCategory -MemberType NoteProperty -Value `"$($SenseCategory)`"
        $Event153  | Add-Member -Name SenseData -MemberType NoteProperty -Value $($SenseData)
        $Event153  | Add-Member -Name SenseDataErrorCondition -MemberType NoteProperty -Value `"$($SenseDataErrorCondition)`"

        $Events153Info += $Event153
    } Catch {
        $Error[0].Exception
    }
}
#endregion: Get Event Info

# Generating output
If ($Events153Info) { 
    $EventsReport = $(Join-Path (Get-Location).Path "ExtractedEvents153.csv")
    If (Test-Path $EventsReport -ErrorAction SilentlyContinue) { Remove-Item $EventsReport -Confirm:$false }
    $Events153Info | Export-Csv -NoTypeInformation -Path $EventsReport
    Write-Host "Report $($EventsReport) generated. $($Events153Info.Count) events found." -ForegroundColor Green
    $Events153Info | Out-GridView -Title "Decoded event id 153"
} Else {
    Write-Host "No events id 153 and source = 'Disk' found on the current machine. Try specifying an .evtx file or interval." -ForegroundColor Yellow
    return
}