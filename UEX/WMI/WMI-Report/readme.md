## WMI-Report

Description:
PowerShell script to inspect the content of a WMI repository.
After executing the script the following four csv files will be created:
1. Dynamic.csv - All the dynamic classes registered by each provider
2. Providers.csv - All the registered providers and related details: Hosting model, Threading model, DLL name, date and version.
3. Static.csv - Static classes with instances containing data
4. Security.csv - Namespace security


### Tool Owner: Gianni Bragante