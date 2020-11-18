# RDS Tracing v1.0.4.26

## RDSTracing.zip Purpose: RDSTracing collects configuration data and traces for RDS/Terminal Services clients and servers using a simple UI or via a command line

Based on the tick boxes (or command line options) it will enable various ETW providers, and trace to a number of sessions. For RDWeb and WS08 Broker it makes the registry/web.config changes directly (prompting for service restarts as required) and collects the relevant files at the end of tracing (rdweb.log and tssdis.log).

You can use the applet to simply turn on RDWeb and TSSDIS (Session Directory) logging (latter if on WS08; on R2 it is via ETW). Just open the tool; click the enable/disable button, and close. If either of these non-ETW logs are not enabled and you start tracing, the tool will enable them for the trace session, then disable them after.

Even though the WMI ETW is a pile of pants (slightly better with Insight Client decoding; which includes function name by default), you can tick it as well, and if no other fields are ticked this is a direct replacement for WMITracer. Spooler tracing is similarly available - deselecting all other options except printing will capture ETW for all types of printing issues.

When you stop tracing, all the necessary files are added to a CAB file; and you are presented (via ShellExecute) the folder where it resides; for emailing to Microsoft.

the *__RDSTRACING.log file contains run status of the tool, as well as some configuration data such as running service information.


## DISCLAIMER:
    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
