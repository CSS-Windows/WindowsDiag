# RepairAppx

RepairAppx is a Microsoft Support troubleshooting tool used to identify and fix Modern Application issues. 


# Background

Modern applications, which are mostly coming from the Microsoft Store(s) or sideloaded from some offline packages, have a different lifecycle compared with Non-Packaged / Win32 classical apps:
- The deployment of a local package will be a two steps process: it will be *staged* once on the system to have its binaries/files deployed, then it will require to be *registered* for every user profiles which require it.
- The updates will usually come from Windows Update endpoints (Windows Store (DCat Prod) and not from WSUS servers, independently of blocking or not the Store App

This might lead to different kind of issues like:
- After an app update, some packages (mainly *frameworks* aka dependencies) might have corrupted files on disk, causing the dependent apps to fail starting with various error messages
- Some packages or frameworks might not be registered for some users, causing them not to appear from some user sessions which would expect them (not in the Start Menu) 
- Because of their tied relation with the user profiles, some issues might occur with roaming profiles, or other kind of special profiles like Citrix UPM, FSLogix and so-on



# What RepairAppx can do

This script can help you  to investigate and fix some of those situations, letting you:
- *verify* packages: Compare packages files size with AppxBlockMap.xml manifests, to look for corrupted packages
- *repair* packages: Automate Windows Update to try to force re-downloading installed apps with their frameworks
- *register* packages: Register packages and its frameworks (dependencies) for the current user profile
- Set the package state: *setstate* of packages to mark them as "Modified" or *resetstate* ("This app can't open" errors)
- Script Windows Update: Trigger a Windows *update* scan, or *cancel* current active download queue
- Gather Config details: Dumps *config* like GPOs and service states related to the Store and Windows Update


# Start with modern apps startup issues

When investigating a modern app which cannot start, look first for invalid/corrupted packages:
```
  .\RepairAppx.ps1 -action verify
```

If it finds some *invalid packages*, you will need to fix them, either downloading them again from Windows Update or getting their offline packages:

- Try to request Windows Update to download again the main apps using those packages, like below Calculator and its dependencies:
```
  .\RepairAppx.ps1 -action repair *calc*
```

- Sometimes the script won't be able to download the packages again, for instance because Windows Update would be blocked in your environment (e.g DoNotConnectToWindowsUpdateInternetLocations GPO). In that case, you should use the Microsoft Store for Business to download the required offline packages(.appx / .appxbundle files), including the required app dependencies. Then set the package to Modified state, install the offline package and reset the packages state as below:
```
   .\RepairAppx.ps1 -action setstate *calc*
   Add-AppxPackage -Path .\Microsoft.UI.Xaml.2.3_2.32002.13001.0_x64__8wekyb3d8bbwe.appx
   Add-AppxPackage -Path .\Microsoft.WindowsCalculator_2020.2004.5.70_neutral_~_8wekyb3d8bbwe.eappxbundle	
   .\RepairAppx.ps1 -action resetstate *  
```

If the verify command didn't find any invalid package, your problem will likely be a (per-user) registration issue. In that case you can try to register again the package and its dependencies. If your user isn't an admin and that you need to provide alternate credentials for an elevated prompt, do this from a *non-elevated* powershell prompt to ensure running in the user session itself.
```
   .\RepairAppx.ps1 -action register *calc*
```

In case you have some greyed modern apps icons in the Start menu or getting some blue prompts "This app can't open" - "Check the Windows Store for more info about Calculator" then the package might be corrupted, but it may also have just remained previously marked as "Modified". You might first reset the package status for the app and its dependencies and see if it helps: 
```
   .\RepairAppx.ps1 -action resetstate *calc*
```


# Managing Store Apps updates

Even if the Store app is blocked in your environment, you can control use this script for some basic tasks to manage Store apps updates.

You can check what are packages in the active download queue of Windows Store:
```
   .\RepairAppx.ps1 -action queue
```

And cancel them all using:
```
   .\RepairAppx.ps1 -action cancel
```

You can also look for all Store Apps updates:
```
   .\RepairAppx.ps1 -action update
```


# Additional features

- Dump configuration
You can dump relevant settings for modern apps in your environment  
```
   .\RepairAppx.ps1 -action config
```

- List packages dependencies
 
To quickly check which framework(s) are used by a package, or the opposite which package rely on a specific framework, you can use the "depends" action:
```
.\RepairAppx.ps1 -action depends *UI.Xaml.2.2*
```

- Usage

You will find all usage details just running RepairAppx with no parameter as below. 

Please let us know your success or issues using this tool!​


# Requirements

- This script is designed to run on Windows 10, some features might only work after RS3 (1803).
- It isn't signed so requires PS Execution Policies to be set accordingly (see Set-ExecutionPolicy).

- Working with package corruptions is recommended from an elevated prompt with an admin account.
- Fixing registration issues has to be done in the user session, prefer a non-elevated prompt. 

- It is designed to run locally from the affected user session, even though some commands might work remotely from LocalSystem.


# Version
Latest script version is 1.9

# Disclaimer

This tool is provided AS IS, no support nor warranty of any kind is provided for its usage. 

# Feedback

You can send feedback to nicolas.dietrich@microsoft.com
