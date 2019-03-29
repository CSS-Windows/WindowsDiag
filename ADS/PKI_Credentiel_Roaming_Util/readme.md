
Credential Roaming Utility (crutil) is tool for extracting the credential roaming relevant data from the AD user account, troubleshooting credential roaming issues and AD database size root cause analysis.

The tool must be executed in the security context of the account that has read rights for AD user account of the user whose credential roaming AD data needs to be investigated.
After specifying username and domainname (and optionally domain controller) and clicking "Get Credential Roaming AD User Data" button in the UI, the tool will generate CredRoamLogs folder (in the same folder where app binary is placed) and collect four csv files:

1. UserCredRoamADObjData.csv with user's AD object relevant info: User_Name, User_Email_Addresses, User_Distinguisehd_Name, MsPKITimeCreationDate, MsPKITimeModifiedDate and PwdLastSetDateTime

2. UserCredRoamADAttrData.csv with user's AD credential roaming attributes relevant info (please note that this information is stored as BLOB in AD): DIMS_Roaming_Status, Token_Type, Token_ID, Token_Size, Last_Roamed, Key_Info, Cert_Subject, Cert_Issuer and Cert_Template
(Cert_Subject, Cert_Issuer, Cert_Template will be set to "not applicable" if the inspected BLOB value is not certificate)

3. UserCredRoamLVRAttrData.csv with user's AD object relevant info: User_Name, User_Email_Addresses, User_Distinguisehd_Name, Version, Time_LastOrigChange, USN_Local_Change, USN_Originating_Change

4. UserCredRoamLVRObjData.csv with user's AD credential roaming attributes relevant infos (please note that this information is stored as BLOB in AD): DIMS_Roaming_Status, Token_Type, Token_ID, Token_Size, Last_Roamed, Key_Info, Cert_Subject, Cert_Issuer, Cert_Template
(Cert_Subject, Cert_Issuer, Cert_Template will be set to "not applicable" if the inspected BLOB value is not certificate)

For more information about credential roaming technology, please refer to:
https://social.technet.microsoft.com/wiki/contents/articles/11483.windows-credential-roaming.aspx
https://blogs.technet.microsoft.com/askds/2009/01/06/certs-on-wheels-understanding-credential-roaming/

Release Note:
29.03.2019 - version 1.0.0.0

If you have any feedback or bugs to report, please, reach out to me at milanmil@microsoft.com