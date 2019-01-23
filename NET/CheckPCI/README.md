# CheckPCI
Proactive and recative PS script for 'Ghosted NIC / Static IP Removal'  or 'NIC driver Removal' issues

## Purpose:
The CheckPCI.ps1 script can

	1. Re-assign IPv4 static IP address if it might be lost after reboot, using Task Scheduler
	
	2. Test for missing OEM INF files for network adapters
	
	3. Collect PNP PCI SetApi logs; Prereq: Start-Collection.ps1
	
Result logs and data of this script will be located in same folder where the script is invoked.
In case of NIC failure situation after reboot, the script Start-Collection.ps1 should be run again.

_CheckPCI_lost-static-IP-or_lost-NIC-driver.zip_ file contains complete Readme doc file with **FAQ** section.

-	Run the script in elevated PS window.

 ` .\CheckPCI.ps1 -AutoAssignIP Save -TestOemInf Yes -StartCollect Before `
 
If the machine is already in failing state, run:

 ` .\CheckPCI.ps1 -AutoAssignIP Save -TestOemInf Yes -StartCollect After `
