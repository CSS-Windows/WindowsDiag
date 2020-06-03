@echo off
ECHO These commands will enable tracing:
@echo on

rem DO NOT CREATE TRACES DIRECTORY IF IT ALREADY EXISTS
if exist c:\traces goto SKIPMKDIR
mkdir c:\traces
:SKIPMKDIR

ipconfig /flushdns
nbtstat -R
KList purge

logman create trace "enduser_embedded" -ow -o c:\traces\enduser_embedded.etl -p "Microsoft-Windows-PrintService" 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets
logman update trace "enduser_embedded" -p {C9BF4A08-D547-4D11-8242-E03A18B5BE01} 0xffffffffffffffff 0xff -ets
logman update trace "enduser_embedded" -p {C9BF4A01-D547-4D11-8242-E03A18B5BE01} 0xffffffffffffffff 0xff -ets
logman update trace "enduser_embedded" -p {C9BF4A06-D547-4D11-8242-E03A18B5BE01} 0xffffffffffffffff 0xff -ets
logman update trace "enduser_embedded" -p {C9BF4A04-D547-4D11-8242-E03A18B5BE01} 0xffffffffffffffff 0xff -ets
logman update trace "enduser_embedded" -p {C9BF4A02-D547-4D11-8242-E03A18B5BE01} 0xffffffffffffffff 0xff -ets
logman update trace "enduser_embedded" -p {C9BF4A03-D547-4D11-8242-E03A18B5BE01} 0xffffffffffffffff 0xff -ets
logman update trace "enduser_embedded" -p {C9BF4A9F-D547-4D11-8242-E03A18B5BE01} 0xffffffffffffffff 0xff -ets
logman update trace "enduser_embedded" -p {C9BF4A9E-D547-4D11-8242-E03A18B5BE01} 0xffffffffffffffff 0xff -ets
logman update trace "enduser_embedded" -p {C9BF4A05-D547-4D11-8242-E03A18B5BE01} 0xffffffffffffffff 0xff -ets
logman update trace "enduser_embedded" -p "Microsoft-Windows-PrintService" 0xffffffffffffffff 0xff -ets
logman update trace "enduser_embedded" -p {EE7E960D-5E42-4C28-8F61-D8FA8B0DD84D} 0xffffffffffffffff 0xff -ets
logman update trace "enduser_embedded" -p {CE444D6A-F287-4977-BBBD-89A0DD65B71D} 0xffffffffffffffff 0xff -ets
logman update trace "enduser_embedded" -p {D34AE79A-15FB-44F9-9FD8-3098E6FFFD49} 0xffffffffffffffff 0xff -ets
logman update trace "enduser_embedded" -p {27239FD0-425E-11D8-9E39-000039252FD8} 0xffffffffffffffff 0xff -ets
logman update trace "enduser_embedded" -p {F4DF4FA4-66C2-4C14-ABB1-19D099D7E213} 0xffffffffffffffff 0xff -ets
logman update trace "enduser_embedded" -p {7663DA2F-1594-4C33-83DD-D5C64BBED68A} 0xffffffffffffffff 0xff -ets
logman update trace "enduser_embedded" -p {AAED978E-5B0C-4F71-B35C-16E9C0794FF9} 0xffffffffffffffff 0xff -ets
logman update trace "enduser_embedded" -p {9677DFEF-EACF-4173-8977-FFB0086B11E6} 0xffffffffffffffff 0xff -ets
logman update trace "enduser_embedded" -p {EE7E960D-5E42-4C28-8F61-D8FA8B0DD84D} 0xffffffffffffffff 0xff -ets
logman update trace "enduser_embedded" -p "Microsoft-Windows-PrintBRM" 0xffffffffffffffff 0xff -ets
logman update trace "enduser_embedded" -p {301CCC25-D58B-4C5E-B6A5-15BCF8B0077F} 0xffffffffffffffff 0xff -ets
logman update trace "enduser_embedded" -p {C9BF4A9E-D547-4D11-8242-E03A18B5BEEE} 0xffffffffffffffff 0xff -ets
logman update trace "enduser_embedded" -p {04160794-60B6-4EC7-96FF-4953691F94AA} 0xffffffffffffffff 0xff -ets
logman update trace "enduser_embedded" -p {3EA31F33-8F51-481D-AEB7-4CA37AB12E48} 0xffffffffffffffff 0xff -ets
logman update trace "enduser_embedded" -p "Microsoft-Windows-Spooler-LPDSVC" 0xffffffffffffffff 0xff -ets
logman update trace "enduser_embedded" -p {9E6D0D9B-1CE5-44B5-8B98-F32ED89077EC} 0xffffffffffffffff 0xff -ets
logman update trace "enduser_embedded" -p {F30FAB8E-84BB-48D4-8E80-F8967EF0FE6A} 0xffffffffffffffff 0xff -ets
logman update trace "enduser_embedded" -p "Microsoft-Windows-Spooler-LPRMON" 0xffffffffffffffff 0xff -ets
logman update trace "enduser_embedded" -p {5ED940EB-18F9-4227-A454-8EF1CE5B3272} 0xffffffffffffffff 0xff -ets
logman update trace "enduser_embedded" -p {99F5F45C-FD1E-439F-A910-20D0DC759D28} 0xffffffffffffffff 0xff -ets
logman update trace "enduser_embedded" -p "Microsoft-Windows-SpoolerTCPMon" 0xffffffffffffffff 0xff -ets
logman update trace "enduser_embedded" -p {62A0EB6C-3E3E-471D-960C-7C574A72534C} 0xffffffffffffffff 0xff -ets
logman update trace "enduser_embedded" -p {9558985E-3BC8-45EF-A2FD-2E6FF06FB886} 0xffffffffffffffff 0xff -ets
logman update trace "enduser_embedded" -p {836767A6-AF31-4938-B4C0-EF86749A9AEF} 0xffffffffffffffff 0xff -ets
logman update trace "enduser_embedded" -p {7672778D-86FE-41D0-85C8-82CAA8CE6168} 0xffffffffffffffff 0xff -ets
logman update trace "enduser_embedded" -p {6D1E0446-6C52-4B85-840D-D2CB10AF5C63} 0xffffffffffffffff 0xff -ets
logman update trace "enduser_embedded" -p {B795C7DF-07BC-4362-938E-E8ABD81A9A01} 0xffffffffffffffff 0xff -ets
logman update trace "enduser_embedded" -p {09737B09-A25E-44D8-AA75-07F7572458E2} 0xffffffffffffffff 0xff -ets
logman update trace "enduser_embedded" -p {34F7D4F8-CD95-4B06-8BF6-D929DE4AD9DE} 0xffffffffffffffff 0xff -ets
logman update trace "enduser_embedded" -p {B42BD277-C2BA-468B-AB3D-05B1A1714BA3} 0xffffffffffffffff 0xff -ets
logman update trace "enduser_embedded" -p {A83C80B9-AE01-4981-91C6-94F00C0BB8AA} 0xffffffffffffffff 0xff -ets
logman update trace "enduser_embedded" -p {EB4C6075-0B67-4A79-A0A3-7CD9DF881194} 0xffffffffffffffff 0xff -ets
logman update trace "enduser_embedded" -p {0ED38D2B-4ACC-4E23-A8EC-D0DACBC34637} 0xffffffffffffffff 0xff -ets

netsh trace start capture=yes scenario=netconnection maxsize=2048 tracefile=c:\traces\Netcapture_%computername%.etl
start psr.exe /start /output C:\traces\PSR_%computername%_.zip /maxsc 99 /sc 1 /gui 0
start procmon /AcceptEula /Quiet /Minimized /BackingFile c:\traces\procmon_%computername%.PML

@echo off
echo
ECHO Reproduce your issue and enter any key to stop tracing
@echo on
pause
procmon /Terminate
netsh trace stop
logman stop "enduser_embedded" -ets
psr.exe /stop

@echo off
echo Tracing has been captured and saved successfully to the c:\traces folder.
pause
