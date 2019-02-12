## ChaseEvents - Tool to look for specific events in a subset of evtx files

### Description
Today, most of the environments are distributed across several servers and it is sometimes difficult to find where a problem started first.

The purpose of this script is to gather whatever events by IDs or by type (critical, error, warning, etc.) and concatenate all of them, and present them by column of server.

It will save the result in a csv file in the current folder and display it as a powershell grid-view.

### How to use it
Store all the system event logs inside a folder (name them whatever you want, but just keep system.evtx in the name) and run the script with the options you want.
There are a couple of prerequisits
* Powershell 5.1 : We're using Class in the script. Run a $Host command in a powershell prompt to know where you are.
* Office         : We're calling some Excel COM objects to create the CSV file
* no special characters in the path : Such as square brackets

### Available options
**-Help**       : Will display a help

**-Days**       : Number of days you want to go back (if not set, the script will  go as far as the event log goes, and you might not want to parse the events of last years
              
**-EventID**    : Choose one or several events to filter. For example -EventID 5120 or -EventID 1069,1146,1135

**-EventLevel** : Chose the event level you want to filter. For example -EventLevel Critical or -EventLevel Critical,Error. Acceptable values are : Critical, Error, Warning, Information, Verbose

**-TimeFormat** : The output time format you want to display (it is more a granularity)
  - YMD (Default)    : An output of only Year-Month-Day
  - YMDH             : An output of only Year-Month-Day Hourh
  - YMDHM            : An output of only Year-Month-Day Hour:Minute
  - YMDHMS           : An output of only Year-Month-Day Hour:Minute:Second
  - YMDHMm           : An output of only Year-Month-Day Hour:Minute:Second.Millisecond
               
**-Verbosity**  : The table can display different level of data
  - Minimal (Defaul) : Just counts the occurence of events with no detail on the event
  - Standard         : Adds a detail on the event (often the 1rst parameter)
  - Verbose          : Adds details on the event

**-Multiline**  : Adds the possibility to split the events details into several lines. The defaul value is unset (all in the same line)
  
### Examples of usage
**.\ChaseEvents.ps1 -EventId 5120 -Format YMDH -Days 7**

    Will look for event IDs 5120 that happened in the last 7 days in all the
    system event logs of the current folder

**.\ChaseEvents.ps1 -EventID 5120 -Format YMDH -Days 7 -Verbosity Verbose**

    Same as above but will add the CSV that had an error and its error code

**.\ChaseEvents.ps1 -EventId 1069,1146 -Format YMD -Days 30**

    Will look for event IDs 1069 & 1146 that happened in the last month

**.\ChaseEvents.ps1 -EventLevel Critical -Format YMD**

    Will look for all the critical events that were logged
