"use strict";

function invokeScript()
{
     var dbgout = host.diagnostics.debugLog
    //
    // Insert your script content here.  This method will be called whenever the script is
    // invoked from a client.
    //
    // See the following for more details:
    //
    //     
    //
   DumpAllLoggers2File();
}

// runs !strdump and  parses  output  to  feed  the id's  to  !logsave    -> c:\temp
function DumpAllLoggers2File()
{
var dbgout = host.diagnostics.debugLog
var ctl = host.namespace.Debugger.Utility.Control;  
var output = ctl.ExecuteCommand("!wmitrace.strdump");
var cmd1 = String("!wmitrace.logsave  ");

for (var line of output)
   {
  //dbgout("  ", line, "\n");
  //var n = false
     if (String(line).includes("Named"))
                    {
                           var cmd2 = cmd1
                           var sub1 = String(line).substr(14,4);
                             cmd2 = cmd1.concat(sub1," ",String("c:\\temp"),String("\\"),sub1,String(".etl"));
                              dbgout(cmd2);
                     var ctl2 = host.namespace.Debugger.Utility.Control;  
                     ctl2.ExecuteCommand(cmd2);
                         dbgout("\n");
                     }
   
        
   }


}