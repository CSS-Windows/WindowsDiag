## WinRM-Collect

Description:
​​​​​​​​​​​​​​​​​​​​​​​​​​PowerShell script to simplify the collection of WinRM and EventLog Forwarding troubleshooting data and make our action plans easier. 

The script collects:\
The configuration of WinRM and all the plugins\
The dump of the svchost.exe process hosting the WinRM service\
The dump of the svchost.exe process hosting the WecSvc service, if it is not the same as WinRM\
The dump of all wsmprovhost.exe processes\
The dump of sme.exe (Windows Admin Center service)\
The configuration and the runtime status of the configured subscriptions\
The details of the groups Event Log Readers and WinRMRemoteWMIUsers__\
The output of the Get-NetConnectionProfile​ command\
The firewall rules\
The netstat -anob output\
The output of ipconfig /all\
The files hosts and lmhosts\
The output of the command netsh winhttp show proxy and nslookup wpad\
The results of the SPN lookups for HTTP and WSMAN, in the domain and in the forest\
The IIS configuration\
The latest httperr.log file\
The output of Get-Hotifx\
The output of Get-WSManCredSSP​​\
The gpresult output in text and html format\
The export of the registry keys HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinRM and HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\
The export of the registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\
The export of the registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\EventCollector\
The export of the registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\EventForwarding\
The export of the registry key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog​\
The export of the registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\
The export of the registry keys HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography and HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography\
The export of the registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\
The export of the registry key HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\HTTP\
The export of the registry key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentials\
The export of the registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\
The export of the registry key ​HKEY_USERS\S-1-5-20\Control Panel\International (Network Service international settings)\
The export of the registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ServerManager\ServicingStorage\ServerComponentCache\
The export of the event logs CAPI2, Windows Remote Management, EventCollector, EventForwarding-Plugin, PowerShell/Operational, Group Policy/Operational, Windows PowerShell, ServerManagementExperience, Kernel-EventTracing, Application and System\
The channel configuration, the first and the last EventRecordID for the logs System, Security, Application and FordwardedEvents\
The output of the commands netsh http settings, netsh http urlacl, netsh http servicestate and netsh http show iplisten\
The output of Certutil -verifystore -v for MY, CA and ROOT and the list of installed certificate in .tsv format\
The details of the running processes and services\
The ServerManager configuration file\
The system information\
The WinRM-Diag​ output

Customer-friendly action plan:\
Retrieve the file WinRM-Collect.zip from the workspace\
Extract the archive WinRM-Collect.zip in a folder, such as c:\WinRM-Collect\
Open an administrative PowerShell prompt and go to that folder\
Execute .\WinRM-Collect.ps1\
The script will create a subfolder with the results, please compress the folder and upload it into the workspace\
If the script does not start, complaining about execution policy, then use Set-ExecutionPolicy -ExecutionPolicy RemoteSigned to change it.


## WinRM-Diag

Description:
​​​​​​​​​​​​​​​​​​​​​​​​​​PowerShell script that inspects the WinRM configuration and tries to identify common issues.

It checks the following:\
The listeners are listening on IP addresses available on the machine\
The certificate configured in the HTTPS listener is present in the LocalMachine\My store and it is not expired\
The certificate configured for the Service is present in the LocalMachine\My store and it is not expired​\
If the machine is configured as a EventLog Forwarding source\
The Issuer CA certificate does not contain invalid characters, it exists and it is not expired\
There is a client certificate issued by the specified CA and it the client certificate is not expired\
There is more than one client certificate issued by the CA\
The NETWORK SERVICE account is member of the EventLog Readers group\
The NETWORK SERVICE account has permissions on the private key if the certificate issued by the CA configured in the policy\
The configured subscriptions for: The number or source machines, The Issuer CA certificate, The Locale and The list of non-domain computers\
If the machine is joined to a domain, the HTTP/computername SPN is registered to a Service account\
​The availability of the group WinRMRemoteWMIUsers__\
​If the NETSH HTTP SHOW IPLISTEN list is empty or not\
The values of IPv4Filter and IPv6Filter\
The Windows Management Framework version\
The NETSH WINHTTP PROXY configuration\
The value of TrustedHosts​\
​The Client Certificate mappings\
Misplaced certificates in the Root store


Note: the script needs to be run as Administrator.​


### Tool Owner: Gianni Bragante


## DISCLAIMER:
THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.