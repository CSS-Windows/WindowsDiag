## Hyper-V_Tracing_Using_Channels

### Description
This script uses the event channels to trace the Hyper-V activity.
It can be usefull when a scenario is too long to fit in the VMLTrace buffer

### How it works
This script will do these actions (by default)
* Sets registry keys for verbose tracing and restart VMMS
* Enables the channels according to the OS version (RS1, RS5) and sets their size to 50 MB
* Waits for key pressed
* Stops & Exports the channels
* Evenutally adds the Hyper-V configuration, ClusDB & Cluster logs
* Compresses everything in a .zip file
* Resets the registry keys to default and restart VMMS

### How to use it
Run this command as administrator to collect to start the , reproduce the problem and press any key to complete the collection.

    .\Hyper-V_Tracing_Using_Channels.ps1

To add some configurations use:

**-HVConfig**: To dump the hyper-v configuration

**-FCConfig**: To dump the cluster hive

... other in the Get-help
