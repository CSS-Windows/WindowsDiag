## MergeEvents - Script to merge all the evtx files from a specific folder into one single evtx file

### Description
When you collect several event logs from a server and you don't know yet what to look for, and can be tedious to load all of them in your event logs and explorer each of them by going from to the other.
To get quicker and avoiding loading several event logs and (and being obliged to unload them one by one) you can merge them all in one single evtx file.
This is the purpose of this tool

### How to use it
Store all the evtx files you want to merge in a unique folder and run the script by giving the -FolderPath argument.
It will merge all the events inside into a Merge.evtx file

You can also run the installer that will create some registry entries to give the possibility to right-click the folder then run the script that will merge the content
