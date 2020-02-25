# WinHttpDiag
Download: Please visit the site http://aka.ms/browsertools 

Tool to diagnose proxy issues when using WinHTTP
CLR checking uses CrytoAPI2 (CAPI2) which uses WinHTTP
        See https://support.microsoft.com/en-us/help/2623724/description-of-the-cryptography-api-proxy-detection-mechanism-when-dow
Usage  : WinHTTPDiag [-?] [-a] [-n] [-d] [-i] [-r] [-p proxy] [url]
Using WinHttpGetIEProxyConfigForCurrentUser by default
-? : Displays help
-n : Forces not using WinHttpGetIEProxyConfigForCurrentUser results when calling WinHttpGetProxyForUrl
-a : Using WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY flag (Windows 8.1 and above only). Used by CryptoAPI 2 (CAPI2) on Windows 10.
-d : Displays the default WinHTTP proxy configuration from the registry using WinHttpGetDefaultProxyConfiguration which will be used with -n option
-i : Displays the proxy configuration using WinHttpGetIEProxyConfigForCurrentUser
-r : resetting auto-proxy caching using WinHttpResetAutoProxy with WINHTTP_RESET_ALL and WINHTTP_RESET_OUT_OF_PROC flags. Windows 8.0 and above only!
-p proxy: forcing usage of static proxy
url : url to use in WinHttpSendRequest (using http://crl.microsoft.com/pki/crl/products/CodeSignPCA.crl if none given)
You can use psexec (http://live.sysinternals.com) -s to run WinHTTPDiag using the NT AUTHORITY\SYSTEM (S-1-5-18) account: psexec -s c:\tools\WinHTTPProxyDiag
You can use psexec -u "nt authority\local service" to run WinHTTPDiag using the NT AUTHORITY\LOCAL SERVICE  (S-1-5-19) account
You can use psexec -u "nt authority\network service" to run WinHTTPDiag using the NT AUTHORITY\NETWORK SERVICE  (S-1-5-20) account
WinHttpGetIEProxyConfigForCurrentUser function documentation http://msdn.microsoft.com/en-us/library/windows/desktop/aa384096(v=vs.85).aspx
WinHttpGetProxyForUrl function documentation http://msdn.microsoft.com/en-us/library/windows/desktop/aa384097(v=vs.85).aspx
