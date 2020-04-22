# xray 
*tdimli, March 2020*

#### Detects known Windows issues and helps resolve them

xray aims to automate detection of known issues and help resolve them with minimal delay and effort.

#### Usage:
```
xray by tdimli, v1.0.200422.0

Checks for known Windows issues

Usage:
xray.ps1 -Area <string[]> [-DataPath <string[]>] [-Offline] [-WaitBeforeClose] [<CommonParameters>]
xray.ps1 -Component <string[]> [-DataPath <string[]>] [-Offline] [-WaitBeforeClose] [<CommonParameters>]
xray.ps1 [-Help]
        Parameters:
        Specify either Area or Component to check for (they are mutually exclusive), multiple items can be specified (comma-separated).
                When area(s) specified, all components within the specified area(s) are checked
                Area:all or Area:* checks all areas
        -DataPath: Path for input/output files
        -Offline: Not running on the actual machine being examined (some -not all- diagnostics can use data files to search for issues)
        -WaitBeforeClose: If any known issues are detected, pauses just before script terminates/window closes
                Use to ensure detected issues are not missed

        Example: .\xray.ps1 -Component dhcpsrv,dnssrv -DataPath c:\xray

```