# GetFarmData

## Description

The getfarmdata.ps1 script has been created to quickly gather all the basic information about an RDS deployment.

## Example:
The machines involved and the roles running on them, the collections and all the settings they have.
It will basically echo all the information about the RDS deployment you would see in server manager (collections, certificates used, collection settings etc…).
This script is for RDS 2012 and above. It will not work on 2008R2 which does not have the same PowerShell Cmdlets.

## Usage:
This script has to be ran on the connection broker of the RDS deployment as a domain administrator.
Ensure you launch the PowerShell console "as administrator".
When you have several brokers, you will have to run it on the active management broker.
This script does not change any setting, it just reads the different settings of the deployment.

### Tool Owner: Cédric Naudy