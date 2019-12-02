# GetRemoteToken

## Description

GetRemoteToken dumps security tokens of AD domain member machines and users on the target/resource machine without knowing the password of client machines or users.
GetRemoteToken can be used to dump the token of AD domain member machines and users. It must be executed on domain joined machine.
The tool works within a single forest and also over forest trust.
GetRemoteToken will display Kerberos claims (if there are any) in token.
Output resembles to whoami output (it is intentional), but it does not require interactive logon and knowledge of user's or machine's password.


## IMPORTANT: This tool is provided as it is without any support and warranty!!!

Tool Owner: milanmil

## Usage:

 GetRemoteToken -u:<fqdn_of_the_user | fqdn_of_the_machine> [-v]

  -v            - Optional switch for verbose output of token's groups and privileges 

  -?            - This message

## Examples: 

  GetRemoteToken -u:MachineAccount@contoso.com

  GetRemoteToken -u:MachineAccount.contoso.com

  GetRemoteToken -u:UserAccount@contoso.com

  GetRemoteToken -u:UserAccount.contoso.com


Scenario:
- Service on cont-mem.contoso.com runs as local system and tries to access resources on target machine fab-mem.fabrikam.com
- You need to know group membership and rights assignment that cont-mem.contoso.com will get after establishing remote logon to fab-mem.fabrikam.com
- To get this answered, you logon to to fab-mem.fabrikam.com (using normal user account), start cmd.exe and execute "getremotetoken -u:cont-mem.contoso.com" and you will get the desired information: 

GetRemoteToken.exe -u:cont-mem.contoso.com

Token user: "CONT-MEM$" from "CONTOSO"   SID:S-1-5-21-223225174-4162556680-1755042188-1105

Token group: "Domain Computers  " from "CONTOSO     "   SID:S-1-5-21-223225174-4162556680-1755042188-515   " w/ attributes 0x00000007

Token group: "Everyone          " from "            "   SID:S-1-1-0   " w/ attributes 0x00000007

Token group: "Certificate Service DCOM Access" from "BUILTIN     "   SID:S-1-5-32-574   " w/ attributes 0x00000007

Token group: "Users             " from "BUILTIN     "   SID:S-1-5-32-545   " w/ attributes 0x00000007

Token group: "NETWORK           " from "NT AUTHORITY"   SID:S-1-5-2   " w/ attributes 0x00000007

Token group: "Authenticated Users" from "NT AUTHORITY"   SID:S-1-5-11   " w/ attributes 0x00000007

Token group: "This Organization " from "NT AUTHORITY"   SID:S-1-5-15   " w/ attributes 0x00000007

Token group: "Logon Identifier  " from "            "   SID:S-1-5-5-0-135929660   " w/ attributes 0xc0000007

Token group: "Service asserted identity" from "            "   SID:S-1-18-2   " w/ attributes 0x00000007

Token group: "Medium Mandatory Level" from "Mandatory Label"   SID:S-1-16-8192   " w/ attributes 0x00000060

Token privilege: "SeChangeNotifyPrivilege   " w/ attributes 0x00000003

Desc: "Bypass traverse checking"

Token privilege: "SeIncreaseWorkingSetPrivilege" w/ attributes 0x00000003

Desc: "Increase a process working set"

Token default owner: "CONT-MEM$" from "CONTOSO"   SID:S-1-5-21-223225174-4162556680-1755042188-1105

Token default DACL ACE: Type 0x00, Mask 0x10000000

for "CONT-MEM$         " from "CONTOSO     "   SID:S-1-5-21-223225174-4162556680-1755042188-1105

Token default DACL ACE: Type 0x00, Mask 0x10000000

for "SYSTEM            " from "NT AUTHORITY"   SID:S-1-5-18



### Note: this works also for user accounts and works without password.

