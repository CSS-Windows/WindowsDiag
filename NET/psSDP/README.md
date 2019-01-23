# psSDP
psSDP: PowerShell based SDP (Support Diagnostic Package)

as an alternative to traditional Microsoft **Support Diagnostic Packages**

### Purpose
Collect **SDP** speciality report on Microsoft Windows systems

### Usage
To start data collection, run in an elevated PowerShell window

 ` .\get-psSDP.ps1 [Net|Dom|CTS|Print|HyperV|Setup|Cluster|Perf|SQLbase|Mini|Nano] `
 
 Example for SDP Networking Diagnostic: 
 
  `.\get-psSDP.ps1 Net`

 Example for SDP Basic (mini) data collection: 
 
 `.\get-psSDP.ps1 Mini`
 
  Example for SDP Net without zipping results:
  `.\get-psSDP.ps1 Net NoCab`
   
If you get an error that running scripts is disabled, run "Set-ExecutionPolicy Bypass -force -Scope Process" and verify with 'Get-ExecutionPolicy -List' that no ExecutionPolicy with higher precedence is blocking execution of this script.
Then run ".\Get-psSDP.ps1 <speciality-of-SDP>" again.

Alternate method is to sign scripts: run in elevated CMD "tss_PS1sign.cmd Get-psSDP"

Action: Send us the file _psSDP_NET_%computername%_<date-time>.zip_


### Powershell ExecutionPolicy
--------------------------
Make sure script execution is allowed in PowerShell

-	Run: 

 ` Get-ExecutionPolicy`

-	If the policy comes back AllSigned, Default, or Restricted then scripting needs to be enabled.
-	Save the output to restore the policy when troubleshooting is complete

-	Then run: 

`  Set-ExecutionPolicy -ExecutionPolicy Unrestricted`

**Alternate method** to allow this script is to sign the PowerShell script, to do so, run in elevated CMD command window:
  `tss_PS1sign.cmd Get-psSDP`
or in elevated PowerShell window
  `.\tss_PS1sign.cmd Get-psSDP`
