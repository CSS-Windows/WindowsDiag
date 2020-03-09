## Sched-Collect

Description:
PowerShell script to simplify the collection of data related to Task Scheduler troubleshooting and make our action plans easier.​

The script collects the following:\
The dump of the svchost.exe process running the Schedule service\
The content of the folders C:\Windows\Tasks and C:\Windows\System32\Tasks\
The export of the registry key HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Schedule\
The export of the logs: Application, System, TaskScheduler/Maintenance, TaskScheduler/Operational\
The output of the command netstat -anob\
The output of the command ipconfig /all\
The Schedule service configuration\
The list of the installed hotfixes​\
The system information

Customer-friendly action plan:\
Retrieve the file Sched-Collect.zip from the workspace\
Extract the archive Sched-Collect.zip in a folder, such as c:\Sched-Collect\
Open an administrative PowerShell prompt and go to that folder\
Execute .\Sched-Collect.ps1\
The script will create a subfolder with the results, please compress the folder and upload it into the workspace​\
If the script does not start, complaining about execution policy, then use Set-ExecutionPolicy -ExecutionPolicy RemoteSigned to change it.​


## DISCLAIMER:
THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

### Tool Owner: Gianni Bragante