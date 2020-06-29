## WMI-Collect

Description: ​​​​​​​​​​​​​​​​​​​​​​​PowerShell script to simplify the collection of WMI troubleshooting data and make our action plans easier.

If WMI is functional it collects:
- More details about running processes
- The list of the permanent subscriptions​
- The details of coupled and decoupled provider hosts
- The values in ProviderHostQuotaConfiguration
- The details of the running provider hosts (WmiPrvSe.exe)
- The details of the services 
- The system information
- The list of installed products

Even if WMI is not functional the script will collect:

- The dump of the svchost process hosting the WinMgmt service
- The dumps of all WMIPrvSE.exe processes
- The dump of the WmiApSrv.exe process
- The dump of the scrcons.exe processes
- The dumps of all processes registerd as decoupled WMI providers
- The list of running processes
- The listing of files in the WBEM folder and subfolders
- The export of the WMI-Activity logs in text format
- The export of the Application, System and WMI-Activity/Operational log
- The export of the WMI, RPC and OLE registry keys
- The COM Security configuration
- The export of the WMIPrvSE AppID registry keys
- The content of the HKLM:\SOFTWARE\Microsoft\Wbem\CIMOM\Autorecover MOFs registry value
- The ipconfig /all and netstat -anob​ output
- The list of installed hotfixes
- The configuration details for the WinMgmt​ service
- The version of some WMI DLLs
- The list of installed drivers

Customer-friendly action plan:
- Retrieve the file WMI-Collect.zip from the workspace
- Extract the archive WMI-Collect.zip in a folder, such as c:\WMI-Collect
- Open an administrative PowerShell prompt and go to that folder 
- Execute .\WMI-Collect.ps1
- The script will create a subfolder with the results, please compress the folder and upload it into the workspace

If the script does not start, complaining about execution policy, then use Set-ExecutionPolicy -ExecutionPolicy RemoteSigned to change it.​


## WMI-Report

Description:
PowerShell script to inspect the content of a WMI repository.
After executing the script the following four csv files will be created:
1. Dynamic.csv - All the dynamic classes registered by each provider
2. Providers.csv - All the registered providers and related details: Hosting model, Threading model, DLL name, date and version.
3. Static.csv - Static classes with instances containing data
4. Security.csv - Namespace security


### Tool Owner: Gianni Bragante

## DISCLAIMER:
THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


