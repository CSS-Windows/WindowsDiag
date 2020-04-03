# xray 
*tdimli, March 2020*

#### Script to identify and help resolve known issues

We have known issues documented in multiple places, xray aims to automate the detection of these known issues and reduce down time

*Please contact tdimli if you can help create scripts to identify and resolve even more issues.  
Or just report known issues and how to identify them to us and we can create the script.*

#### Usage:
```
xray by tdimli, v1.0.200402.0

Checks for known Windows issues

Usage:
 .\xray.ps1 [-Area: <area(s)>] | [-Component: <component(s)>] [-DataPath <path for output files>]
xray.ps1 -Area <string[]> [-DataPath <string[]>] [-Offline] [-WaitBeforeClose] [<CommonParameters>]
xray.ps1 -Component <string[]> [-DataPath <string[]>] [-Offline] [-WaitBeforeClose] [<CommonParameters>]
xray.ps1 [-Help]
        Parameters:
        Specify either Area or Component to check for (they are mutually exclusive), multiple items can be specified (comma-separated).
                When area(s) specified, all components within the specified area(s) are checked
                Area:all or Area:* checks all areas
        -DataPath: Path for input/output files
        -Offline: Not running on the actual machine being examined (some -not all- diagnostics can use data files to search for issues)
        -WaitBeforeClose: Pauses the script just before window closes, use when script is run in a new window to read output before it closes
         
         Example: .\xray.ps1 -Component dhcpsrv,dnssrv -DataPath c:\xray

```
