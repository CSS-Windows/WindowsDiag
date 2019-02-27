# offline-SDPcheck
PowerShell based script set for analysis of SDP reports (former RFLcheck)

## Purpose
rapidly determine missing MS hotfixes or monthly cumulative updates on server or client machines

## Check_RFL/SDP setup and installation instructions

We recommend to use a team share 'ToolsShare' on a TeamServer `\\TeamServer`, in order to minimize monthly maintenance.
if you are sharing the RFL scripts on a `\\TeamServer\ToolsShare` please globally replace all strings `\\TeamServer\ToolsShare` in all `\\TeamServer\ToolsShare\RFL\*.PS1` files, and also replace `localhost\\ToolsShare`  in `\\TeamServer\ToolsShare\RFL\*.reg` files

If  using a **TeamServer**:
1. Create a new Share named 'ToolsShare' 
2. Expand the RFL.zip into the `\\TeamServer\ToolsShare`
3. for all .PS1 files: globally replace `\\LocalHost\ToolsShareRFL` with `\\TeamServer\ToolsShare`
4. Edit the Rfl-Check_ShellExtension*.reg files and replace `\\\\LocalHost\\ToolsShare` with `\\\\TeamServer\\ToolsShare`
5. on your own PC: DoubleClick the reg file `\\TeamServer\ToolsShare\RFL\Rfl-Check_ShellExtension_V2-Add.reg`


If  using your **own PC**:
1. Create a new Share named 'ToolsShare' 
2. Expand the RFL.zip into the `\\LocalHost\ToolsShare`
3. N/A - (*.PS1 files files already point to `\\LocalHost\ToolsShare`)
4. N/A - (Rfl-Check_ShellExtension*.reg files already point to `\\\\LocalHost\\ToolsShare`)
3. on your own PC: DoubleClick the reg file `\\LocalHost\ToolsShareRFL\Rfl-Check_ShellExtension_V2-Add.reg`

Now you can use the Explorer context menu on any extracted SDP folder.

The RFLcheck will automaticaly try to open resulting `*.txt` files in your favorite text Editor (default is NotePad.exe);

**hint**: if you register `*.txt` files to be opend with a more sophisticated editor like Notepad++ or TextPad, all result files will open as additional Tabs in your text Editor.

## What is RFLcheck? 
RFLcheck is a set of Explorer Plugin and PowerShell scripts that enables engineers to identify missing Hotfixes in a customer supplied SDP report. 
Useful add-ons are 
- checks for 3rd party drivers (Pstat), 
- checks for incorrect or changed Registry settings, 
- PerformanceMonitorAnalysis (PMA), 
- Pstat-Compare, 
- Event-summary up to 6h before SDP collection, 
- check for specific Events, 
- re-Arrange-SDPFolders (for Cluster)
Details see in MS internal KB3070416




