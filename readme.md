# xray 
*tdimli, March 2020*

#### Detects known issues and helps resolve them

xray aims to automate detection of known issues and help resolve them with minimal delay and effort.

xray is included with TSS and is run whenever TSS is used for data collection.  
TSS runs xray during data collection to ensure known issues are eliminated before any time is spent on reviewing the data.

#### Usage:
```
xray by tdimli, v1.0.200529.0

Checks for known issues

Usage:
xray.ps1 -Area <string[]> [-DataPath <string>] [-Offline] [-WaitBeforeClose] [-DevMode] [<CommonParameters>]
xray.ps1 -Component <string[]> [-DataPath <string>] [-Offline] [-WaitBeforeClose] [-DevMode] [<CommonParameters>]
xray.ps1 -Diagnostic <string[]> [-DataPath <string>] [-Offline] [-WaitBeforeClose] [-DevMode] [<CommonParameters>]

xray.ps1 Shows help

        Parameters:
        Specify either Area or Component to check or Diagnostic to run (they are mutually exclusive), multiple items can be specified (comma-separated).
                When area(s) specified, all components within the specified area(s) are checked
                When component(s) specified, all diagnostics within the specified component(s) are run
                When diagnostic(s) specified, only the specified diagnostics are run
                "-Area all" or "-Area *" checks all areas
        -DataPath: Path for input/output files
        -Offline: Not running on the actual machine being examined (some -not all- diagnostics can use data files to search for issues)
        -WaitBeforeClose: If any known issues are detected, pauses just before script terminates/window closes
                Use to ensure detected issues are not missed

        Example: .\xray.ps1 -Component dhcpsrv,dnssrv -DataPath c:\xray

```