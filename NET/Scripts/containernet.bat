md c:\TCPTrace

logman create trace "minio_netio" -ow -o c:\TCPTrace\minio_netio.etl -p {EB004A05-9B1A-11D4-9123-0050047759BC} 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 2048 -ets
logman update trace "minio_netio" -p "Microsoft-Windows-TCPIP" 0xffffffffffffffff 0xff -ets
logman update trace "minio_netio" -p "Microsoft-Windows-Winsock-AFD" 0xffffffffffffffff 0xff -ets
logman update trace "minio_netio" -p {B40AEF77-892A-46F9-9109-438E399BB894} 0xffffffffffffffff 0xff -ets

logman create trace "net_wfp" -ow -o c:\TCPTrace\net_wfp.etl -p {2588030C-920E-4AD5-ACBF-8AA2CD761DDB} 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 2048 -ets
logman update trace "net_wfp" -p "Microsoft-Windows-Base-Filtering-Engine-Connections" 0xffffffffffffffff 0xff -ets
logman update trace "net_wfp" -p {5A1600D2-68E5-4DE7-BCF4-1C2D215FE0FE} 0xffffffffffffffff 0xff -ets
logman update trace "net_wfp" -p {AD33FA19-F2D2-46D1-8F4C-E3C3087E45AD} 0xffffffffffffffff 0xff -ets
logman update trace "net_wfp" -p "Microsoft-Windows-WFP" 0xffffffffffffffff 0xff -ets


logman create trace "hns" -ow -o c:\TCPTrace\hns.etl -p {0c885e0d-6eb6-476c-a048-2457eed3a5c1} 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets
logman update trace "hns" -p {80CE50DE-D264-4581-950D-ABADEEE0D340} 0xffffffffffffffff 0xff -ets
logman update trace "hns" -p {D0E4BC17-34C7-43fc-9A72-D89A59D6979A} 0xffffffffffffffff 0xff -ets
logman update trace "hns" -p {93f693dc-9163-4dee-af64-d855218af242} 0xffffffffffffffff 0xff -ets


logman create trace "vfp" -ow -o c:\TCPTrace\vfpext.etl -p "{9F2660EA-CFE7-428F-9850-AECA612619B0}" 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets
logman update trace "vfp" -p "Microsoft-Windows-Hyper-V-Vmswitch" 0xffffffffffffffff 0xff -ets
logman update trace "vfp" -p "Microsoft-Windows-NDIS-PacketCapture" 0xffffffffffffffff 0xff -ets

logman create trace "net_winnat" -ow -o c:\TCPTrace\net_winnat.etl -p "Microsoft-Windows-WinNat" 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets


tasklist /svc > c:\TCPTrace\task_before.txt
netsh trace start scenario=Virtualization provider=Microsoft-Windows-Hyper-V-Vmswitch capture=yes capturetype=both tracefile=c:\TCPTrace\nettrace.etl overwrite=yes maxsize=1024M 

pause

logman stop "minio_netio" -ets
logman stop "net_wfp" -ets
logman stop "net_winnat" -ets
logman stop "hns" -ets
logman stop "vfp" -ets


netsh trace stop
tasklist /svc > c:\TCPTrace\task_after.txt
