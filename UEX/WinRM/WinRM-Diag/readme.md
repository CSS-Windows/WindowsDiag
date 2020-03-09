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