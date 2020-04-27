# psSDP
psSDP: PowerShell based SDP (Support Diagnostic Package) - fully included in :star: TSS, https://aka.ms/getTSS

as an ultimate alternative to all traditional Microsoft **Support Diagnostic Packages** MSDT

### Purpose
Collect **SDP** speciality report on Microsoft Windows systems. One package for invoking many different SDP spcialties.

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

Alternate method#1: sign .PS1 scripts: run in elevated CMD "tss_PS1sign.cmd Get-psSDP"
Alternate method#2:  if scripts are blocked by Policy, run in elevated Powershell: 

  `Set-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell -Name ExecutionPolicy -Value ByPass`

Action: Send us the file _psSDP_NET_%computername%_<date-time>.zip_

Note: in case of any errors please start with uplaoding a mini SDP report: 
 `.\get-psSDP.ps1 Mini`


### Powershell ExecutionPolicy
--------------------------
Make sure script execution is allowed in PowerShell

-	Run: 

 ` Get-ExecutionPolicy`

-	If the policy comes back AllSigned, Default, or Restricted then scripting needs to be enabled.
-	Save the output to restore the policy when troubleshooting is complete

-	Then run: 

 `Set-ExecutionPolicy -ExecutionPolicy Unrestricted`

**Alternate method#1** to allow this script is to sign the PowerShell script, to do so, run in elevated CMD command window:
  `tss_PS1sign.cmd Get-psSDP`
or in elevated PowerShell window
  `.\tss_PS1sign.cmd Get-psSDP`
  
 **Alternate method#2**:  if your .PS1 scripts are blocked by higher precedence Execution Policy, run in elevated Powershell: 

  `Set-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell -Name ExecutionPolicy -Value ByPass`

### Hints:
   `-noNetAdapters [<SwitchParameter>]
        This switch will skip NetAdapters data collection in network section of SDPs `
        
=>	This is helpful if you try to get an SDP of a VPN/DirectAccess Client, which sometimes fails/is stuck at this stage

   `-skipBPA [<SwitchParameter>]
        This switch will skip all Best Practice Analyzer (BPA) TroubleShooter `
        
=>	This might help on ServerCORE systems, where script seems to halt at stage 'runing Best Practice Analyzer (BPA)'

   `-Transcript [<SwitchParameter>]
        use -Transcript:$true to start PS Transcription, sometimes you may see error 'Transcription cannot be started.' `
        
=>	Get a PowerShell transcript log file up to stage where script ‘hangs’ (similar on what you see on-screen)

If you try to get a mini SDP for performing later RFLcheck, you  can run (undocumented) parameter RFL

   `PS> .\get-psSDP RFL `
