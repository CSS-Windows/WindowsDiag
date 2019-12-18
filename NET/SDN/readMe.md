
See details on https://github.com/ViDou83/SDNNested (below content has been copied from that site) 

# SDNNested
SDNNested is a collection of PS Script that automates the Microsoft SDN deployment on a Azure VM Nested Environement.

## Infrastucture deployed with provided config files

Azure VM can be manually deployed or you can use the script:
* .\New-SDNNestedAzHost.ps1 -ConfigurationDataFile .\configfiles\SDNNestedAzHost.psd1

Azure VM acting as Hypv Server (1st level of Nested virtualization )
* One DC acting as ToR Router (router between SDN Stack and outside)
* Two Hypv host (Cluster with S2D Disk pool) where SDN stack will be deployed (with SDN Express script)
* Two tenants "physical" Gateway (Tenants Contoso L3 and Fabrikam GRE tunnel) to simulate remote tenant network (outside the SDN Stack)

On the SDN-HOST Hypv Server (2nd level of Nested virtualization ):
* One Network controller Cluster composed of 3 nodes
* Two Gateways + Tenants vGW (L3 + GRE)
* Two MUXes
* Two Contoso Tenant VMs 
* Two Fabrikam Tenant VMs

IP subnets and VLAN:
- MGMT 10.184.108.0/24 - VLAN 7
- PROVIDER 10.10.56.0/23 - VLAN 11
- CONTOSO L3 INTERCO 10.127.134.0/25 - VLAN 1001
- CONTOSO and FABRIKAM SUBNET : 172.16.1.0/24 
    *  Contoso-testVM01 - 172.16.1.10/24
    *  Contoso-testVM02 - 172.16.1.10/24
    *  Fabrikam-testVM01 - 172.16.1.10/24
    *  Fabrikam-testVM02 - 172.16.1.10/24
- Public VIP which can be reached from AzVM 
    * 41.40.40.8 -> CONTOSO
    * 41.40.40.9 -> FABRIKAM

On the Azure VM itself:
* WAC can be installed to manage S2D cluster and SDN stack (see C:\apps)
* Wireshark can be installed with PortMirroring in place to visualize most of the traffic on the SDN Stack (Non and encapsulated one - VxLAN and GRE for instance). (see C:\apps)

![image](https://github.com/ViDou83/SDNNested/blob/master/utils/pictures/diagram.jpg?raw=true)
![image](https://github.com/ViDou83/SDNNested/blob/master/utils/pictures/legende.jpg?raw=true)


## Usage
*   Deploy Azure VM :
    *   Use New-SDNNestedAzHost.ps1 script, run it from a machine with access to your Azure Subscription. Config file is AzureVM.psd1 to define :
        *   Subscription, ResourceGroupName, VMName, VMSize, VM username and  Password, AzFileShare where VHDX and misc apps/tools can be hosted
        *  Ex: .\New-SDNNestedAzHost.ps1 -ConfigurationDataFile .\configfiles\SDNNestedAzHost.psd1
        * AzFile share folder tree has to be 
            * \\AzFileShare\Template => contains sysprered vhdx (Name has to the one used).
            * \\AzFileShare\Apps => put what you want...
            *  Template folder will be replicated on the AzVM F:\VMs Drive and App under C:\
*   Deploy 1st level of Nested virtualization :
    *   Use New-SDNNestedInfra.ps1 script, run it from the Azure VM itself. Config file is SDNNested-Deploy-Infra.psd1 and can be fully customized. PREREQUISITES : You need to have VHDX generelazied hosted on the AzureVM. 
*   2nd level of Nested virtualization 
    *   Use SDNExpress script, please copy to one of SDN-HOST VM and run it locally from this host (not from a PS Session but through VM Console). You can use either the one located here, you can get the latest one from :
        https://github.com/grcusanz/SDN/tree/master/SDNExpress/scripts (not stable)
        https://github.com/microsoft/SDN/tree/master/SDNExpress/scripts(stable but not compatible with S2D)

    * Use script Add-SDNNestedTenant.ps1 script to use tenant on the SDN stack:
        * Ex: Add-SDNNestedTenant.ps1 -ConfigurationDataFile .\configfiles\SDNNested-Deploy-Tenant.psd1 
        * This script will deploy Contoso and Fabrikam Tenants with virtual gateways and VIP
            * Contoso Gw is using L3 interconnection
            * Fabrikam Gw is using GRE tunelling 
        * Public VIP which can be reached from AzVM, 
            * http://41.40.40.8 -> CONTOSO
            * https//41.40.40.9 -> FABRIK

## Contributing
Please reach vidou@microsoft.com for any feedback or question.

Some people might be new to using Git and GitHub so here is a simple workflow to facilitite Pull Requests which can be reviewed and merged easily.

Create a forked copy of the SDNNested repo from https://github.com/ViDou83/SDNNested
Clone that copy to your local machine (git clone https://github.com/*GitUserName*/sdn.git)
Create a new branch on your local machine with a descriptive name to indicate the changes you will be making (git checkout -b DescriptiveName)
Update and commit docs (git add, git commit, git push) to generate a preview viewable via GitHub (e.g. https://github.com/<GitUserName/blob/DescriptiveBranchName/filename.md)
Iterate on this branch until satisfied
Create a Pull Request into the master branch from https://github.com/ViDou83/SDNNested (Select Pull requests, New pull request) and compare across forks
At this point, the PR will be reviewed and merged into the master branch by one of the Maintainers.

## License
