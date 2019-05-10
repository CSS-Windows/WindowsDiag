# Trace-process
Trace-process: PowerShell based data collection tool


### Purpose
Collects IDNA aka Time Travel Traces for one or several processes + run RADAR tools that helps reporting heap leaks or high heap memory

### Usage
    Collects IDNA traces of processes provided in input with -IdnaProcessToTrace + plus ability to detect heap leak and high usage of one process.
    Combining both capabilities allow investigating potential memomry leak by identifying the memory allocation "unfreed" callstack. With the IDNA/TTD
    trace(s) of the process (and for involded processes for instance those doing memalloc from API). The tool is also dump the process list running on the 
    system before and after the execution.
.PARAMETER RadarLeakProcess
    Optional parameter. Enable RADAR leak detection. 
    When RADAR attaches to a process, it starts collecting callstacks from all heap allocation calls. 
    When RADAR takes a snapshot, it produces a list of all unfreed heap allocations and their allocation callstacks. It reports every callstack once, with counts/sizes of the allocations.
.PARAMETER RadarLeakPath
    Path to rdrleakdiag.exe binary. Since RS5 rdrleakdiag is now an embedded tools.
.PARAMETER IdnaProcessToTrace
    Optional list of process to iDNA/TTD trace. Can be one or several process/service.
.PARAMETER IdnaTimer
    Optional time in seconds the iDNA/TTD trace will run on. By default, if this option is not provided, collection will run during 30sec.
.PARAMETER IdnaPath
    Path to TTTracer.exe binary. Since RS5 TTTracer is now an embedded tools.
.PARAMETER LogPath
    Folder where all traces will be flushed on disk.
.EXAMPLE
    .\Trace-Process.ps1 -RadarLeakProcess BFE -IdnaProcessToTrace BFE,IKEEXT -IdnaTimer 300 -LogPath C:\MS_DATA 
    Will collect iDNA trace of BFE and IKEEXT services for a duration of 300secs / 5 min. Then will generate a snap radar report to identify which memory allocation has not been freed during that time.
    Note that here -RadarExecutable and -IdnaExecutable has not been provided as those diag tools are embedded in latest Win10 RS5 versions 
.EXAMPLE
    .\Trace-Process.ps1 -RadarLeakProcess BFE -RadarLeakPath C:\temp\ -IdnaProcessToTrace BFE,IKEEXT -IdnaTimer 300 -IdnaPath C:\temp\TTT_x86_x64_external\x64\TTTracer.exe -LogPath C:\MS_DATA 
    Will collect iDNA trace of BFE and IKEEXT services for a duration of 300secs / 5 min. Then will generate a snap radar report to identify which memory allocation has not been freed during that time.
.NOTES
    Script developped by Vincent Douhet <vidou@microsoft.com> - Escalation Engineer / Microsoft Support CSS
        Please report him any issue using this script or regarding a ask in term of improvement and contribution


## DISCLAIMER:
    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
