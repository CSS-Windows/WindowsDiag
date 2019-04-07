# SMB-SrvBindings

### Detect and repair unbalanced SMB bindings on Winodws 10 v1709 (RS3)
The log files the PowerShell script generates can be used to determine if there are network adapters that should be bound to LanmanServer (ms_server, “File and Printer Sharing”, SRV, etc.) but are not. 

Note: This issue is already fixed in later Windows 10 versions
(1809) KB4490481 [RS5] NETSETUP: services not bound correctly during new network adapter install
(1803) KB4493437 [RS4] NETSETUP: services not bound correctly during new network adapter install
