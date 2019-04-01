# PKI Tools

## Getting Started
"PKI Tools" is set of Public Key Infrastructure, Security and Directory Services troubleshooting tools provided by Microsoft Customer Support Services (CSS).
"CAPI2 Log Explorer" tools is presented in the initial screen of "PKI Tools".
Using "Tools" menu you can start further PKI tools and 1.1.0.0 "PKI Tools" release contains three additional tools: "LDIF Explorer", "PKI AD Parser" and "Credential Roaming Utility" (crutil.exe)

### DETAILS:

1. "CAPI2 Log Explorer" provides an easy way to view the CAPI2 event log. It represents the CAPI2 activities in a user-friendly tree view grouped by activity IDs. Root nodes contain brief summary of the CAPI2 activities. Child nodes contain important information about the CAPI2 activity.
The upper left pane contains tree view described above. The upper right pane contains summary for selected tree item and current filter settings. The lower pane contains XML representation of the selected event (child item).

2. "LDIF Explorer" provides an easy way to analyze directory export files, created using ldifde tool (out of box available on Windows Server domain controllers)
Directory export files can be created using "ldifde -f file.txt -d "distinguished_name_of_AD_subtree".
For example...executing this command on Active Direcotry domain controller:
ldifde -f pki.txt -d "CN=Public Key Services,CN=Services,CN=Configuration,DC=CONTOSO,DC=COM"
... will generate pki.txt text file that contains all objects and attributes from AD subtree "CN=Public Key Services,CN=Services,CN=Configuration,DC=CONTOSO,DC=COM".
However, pki.txt will contain unstructured text, difficult to view and parse - LDIF Explorer resolves this issue.
By selecting File->Open and specifying exported ldf file, LDIF Explorer will provide hierarchical view of all objects and attributes.
In addition to that you can save PKI relevant attributes (certificates and CRLs) into corresponding files by richt clicking the attribute and selecting "Export to Base 64".

3. "Credential Roaming Utility (crutil)" is tool for extracting the credential roaming relevant data from the AD user account, troubleshooting credential roaming issues and AD database size root cause analysis.
The tool must be executed in the security context of the account that has read rights for AD user account of the user whose credential roaming AD data needs to be investigated.
After specifying username and domainname (and optionally domain controller) and clicking "Get Credential Roaming AD User Data" button in the UI, the tool will generate CredRoamLogs folder (in the same folder where app binary is placed) and collect four csv files:
(i) UserCredRoamADObjData.csv with user's AD object relevant info: User_Name, User_Email_Addresses, User_Distinguisehd_Name, MsPKITimeCreationDate, MsPKITimeModifiedDate and PwdLastSetDateTime
(ii) UserCredRoamADAttrData.csv with user's AD credential roaming attributes relevant info (please note that this information is stored as BLOB in AD): DIMS_Roaming_Status, Token_Type, Token_ID, Token_Size, Last_Roamed, Key_Info, Cert_Subject, Cert_Issuer and Cert_Template
(Cert_Subject, Cert_Issuer, Cert_Template will be set to "not applicable" if the inspected BLOB value is not certificate)
(iii) UserCredRoamLVRAttrData.csv with user's AD object relevant info: User_Name, User_Email_Addresses, User_Distinguisehd_Name, Version, Time_LastOrigChange, USN_Local_Change, USN_Originating_Change
(iv) UserCredRoamLVRObjData.csv with user's AD credential roaming attributes relevant infos (please note that this information is stored as BLOB in AD): DIMS_Roaming_Status, Token_Type, Token_ID, Token_Size, Last_Roamed, Key_Info, Cert_Subject, Cert_Issuer, Cert_Template
(Cert_Subject, Cert_Issuer, Cert_Template will be set to "not applicable" if the inspected BLOB value is not certificate)
For more information about credential roaming technology, please refer to:
https://social.technet.microsoft.com/wiki/contents/articles/11483.windows-credential-roaming.aspx
https://blogs.technet.microsoft.com/askds/2009/01/06/certs-on-wheels-understanding-credential-roaming/

4. "PKI_AD_Parser" is PKI Troubleshooting tool used to dump and analyze PKI-relevant content in AD stored in Public Key Services container (CN=Public Key Services,CN=Services,CN=Configuration,DC=...,DC=...).
PKI_AD_Parser creates two sets of useful information:
(i) Folder structure, that mimics AD structure and contains relevant certificates and CRLs
(ii) PKIReport.txt with Certificates, CRLs and Certificate Templates relevant information and, if enabled, it provides verification of certificates and CRLs stored in AD.
The tool must be run in active directory environment; the tool reads info directly from AD.
The account used for running tool must have read access to Public Key Services container.
If DC is not specified, DC locator service will be used to find the DC.
The resulting data will be placed in the PKI folder and by default stored in the current application folder.
The location for storing the data, the name of target domain controller and option to peform certificate and crl verification can be configurred in UI.

## Versioning
04/01/2019 - version 1.1.0.0

## Tool Owner
If you have any feedback or bugs to report, please, reach out to me at milanmil@microsoft.com

## Important "General Data Protection Regulation and Legal" Notes:
The collected data may contain Personally Identifiable Information (PII) and/or sensitive data, such as (but not limited to) IP addresses, PC names, and user names.
Once the tracing and data collection has completed, the data will be saved in a folder on the local hard drive.
This folder is NOT automatically sent to Microsoft.
You can send this folder to Microsoft CSS using a secure file transfer tool - Please discuss this with your support professional and also any concerns you may have.
"PKI Tools" is provided as it is and neither Microsoft nor the author have any legal responsibility over it.


