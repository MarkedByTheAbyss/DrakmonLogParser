rule CreateFileExe
{
    strings:
        $NtCreateExeFileSysWOW = /PID.{50,200}NtCreateFile.{50,200}SysWOW64.{5,50}[0-9a-zA-Z]\.exe/
        $NtCreateExeFileSystem = /PID.{50,200}NtCreateFile.{50,200}System.{5,50}[0-9a-zA-Z]\.exe/
        $NtCreateExeFileSystem32 = /PID.{50,200}NtCreateFile.{50,200}System32.{5,50}[0-9a-zA-Z]\.exe/
    condition:
        any of ($NtCreateExeFileSys*)
}

rule WriteFileExeToSystem
{
    strings:
        $NtWriteExeFileSysWOW = /PID.{50,200}NtWriteFile.{100,150}SysWOW64.{5,50}[0-9a-zA-Z]\.(exe|com)/
        $NtWriteExeFileSystem = /PID.{50,200}NtWriteFile.{100,150}System.{5,50}[0-9a-zA-Z]\.(exe|com)/
        $NtWriteExeFileSystem32 = /PID.{50,200}NtWriteFile.{100,150}System32.{5,50}[0-9a-zA-Z]\.(exe|com)/
    condition:
        any of ($NtWriteExeFile*)
}

rule WriteFileExeWithDosPath
{
    strings:
        $NtWriteExeFileTemp = /PID.{50,200}NtWriteFile.*[A-Z0-9]{1,6}~[0-9].*\.exe/
    condition:
        any of ($NtWriteExeFile*)
}

rule WriteFileExe
{
    strings:
        $NtWriteExe = /PID.{50,200}NtWriteFile.*\.exe/
    condition:
        any of ($NtWriteExe*)
}


rule WriteFileExeToDesktop
{
    strings:
        $NtWriteExeFileDesktop = /PID.{50,200}NtWriteFile.{100,150}Desktop.{5,50}[0-9a-zA-Z]\.(exe|com)/
        $NtWriteExeFileTemp = /PID.{50,200}NtWriteFile.{100,150}Temp.{5,50}[0-9a-zA-Z]\.(exe|com)/
    condition:
        any of ($NtWriteExeFile*)
}


rule WriteFileExeToProgramdata
{
    strings:
        $NtWriteExeFileTemp = /PID.{50,200}NtWriteFile.{100,150}ProgramData.{5,50}[0-9a-zA-Z]\.(exe|com)/
    condition:
        any of ($NtWriteExeFile*)
}

rule WriteFileExeToTemp
{
    strings:
        $NtWriteExeFileTemp = /PID.{50,200}NtWriteFile.{100,150}Temp.{5,50}[0-9a-zA-Z]\.(exe|com)/
    condition:
        any of ($NtWriteExeFile*)
}

rule GetComputerName {
    strings:
        $GetComputerName = /PID.{50,200}GetComputerName/
    condition:
        any of them
}

rule InteractionWithDNS {
    strings:
        $Reg = /PID.*DNSClient/
        $InetDnsQuery = /PID.{50,200}DnsQuery/
        $GetAddrInfo = /PID.*GetAddrInfo/
    condition:
        any of them
}


rule CreateFileDll
{
    strings:
        $NtCreateDllFileSysWOW = /PID.{50,200}NtCreateFile.{50,200}SysWOW64.{5,50}[0-9a-zA-Z]\.dll/
        $NtCreateDllFileSystem = /PID.{50,200}NtCreateFile.{50,200}System.{5,50}[0-9a-zA-Z]\.dll/
        $NtCreateDllFileSystem32 = /PID.{50,200}NtCreateFile.{50,200}System32.{5,50}[0-9a-zA-Z]\.dll/
    condition:
        1 of ($NtCreateDllFileSys*)
}

rule WriteFileDllSystem
{
    strings:
        $NtWriteDllFileSysWOW = /PID.{50,200}NtWriteFile.{100,150}SysWOW64.{5,50}[0-9a-zA-Z]\.dll/
        $NtWriteDllFileSystem = /PID.{50,200}NtWriteFile.{100,150}System.{5,50}[0-9a-zA-Z]\.dll/
        $NtWriteDllFileSystem32 = /PID.{50,200}NtWriteFile.{100,150}System32.{5,50}[0-9a-zA-Z]\.dll/
    condition:
        1 of ($NtWriteDllFileSys*)
}

rule CreateUserProcessFromSystem
{
    strings:
        $NtCreateUserProcessSysWOW64 = /PID.{50,200}SysWOW64.{5,50}[0-9a-zA-Z]\.exe.{5,50}NtCreateUserProcess/
        $NtCreateUserProcessSystem = /PID.{50,200}System.{5,50}[0-9a-zA-Z]\.exe.{5,50}NtCreateUserProcess/
        $NtCreateUserProcessSystem32 = /PID.{50,200}System32.{5,50}[0-9a-zA-Z]\.exe.{5,50}NtCreateUserProcess/
    condition:
        any of them
}

rule DelayExecution
{
    strings:
        $NtDelayExecution = /PID.{50,200}NtDelayExecution.*DelayIntervalMs":-.*/
    condition:
        any of them
}


rule NtYieldExecution
{
    strings:
        $NtYieldExecution = /PID.{50,200}NtYieldExecution/
    condition:
        any of them
}

rule CreateMutexOnSystemExe {
    strings:
        $CreateMutex = /PID.{50,200}CreateMutant(registry|smss.exe|wininit.exe|csrss.exe|winlogon.exe|services.exe|lsass.exe|fontdrvhost.exe|svchost.exe)/
    condition:
        any of them
}



rule TerminateProcess {
    strings:
        $NtTerminateProcess = /PID.{50,200}NtTerminateProcess/
    condition:
        any of them
}

rule BinaryInRegistry {
    strings:
        $NtSetValueKey =  /PID.{50,200}NtSetValueKey.*418A073AA3BC3475/
    condition:
        any of them
}

rule GetTickCount
{
    strings:
        $GetTickCount = /PID.{50,200}GetTickCount/
    condition:
       any of them
}

rule GetFolderPath {
    strings:
        $GetFolderPathAppdata = /PID.{50,200}SHGetFolderPath.*AppData/
        $GetFolderPathSystem32 = /PID.{50,200}SHGetFolderPath.*system32/
        $GetFolderPathSysWOW64 = /PID.{50,200}SHGetFolderPath.*syswow/
        //Program Files (x86) Documents ProgramData Common Files Pictures History INetCookies INetCache
    condition:
        any of them
}

rule QueryInformationProcessDebugingPresent {
    strings:
        $NtQueryInformationProcess = /PID.{50,200}NtQueryInformationProcess.*ProcessInformationClass":"0x1f.*ProcessInformation/
    condition:
        any of them
}

rule QueryInformationProcessSystemKernelDebuggerInformation {
    strings:
        $NtQueryInformationProcessSystemKernelDebuggerInformation = /PID.{50,200}NtQueryInformationProcess.*ProcessInformationClass":"0x23.*ProcessInformation/
    condition:
        any of them
}

rule QueryInformationProcessDebugPort  {
    strings:
        $NtQueryInformationProcessDebugPort = /PID.{50,200}NtQueryInformationProcess.*ProcessInformationClass":"0x7/
    condition:
        any of them
}

rule RemoveDirectory{
    strings:
        $RemoveDirectory = /PID.{50,200}RemoveDirectory/
    condition:
        any of them
}

rule QuerySystemInformationSystemProcessInformation {
    strings:
        $NtQuerySystemInformation = /PID.{50,200}NtQuerySystemInformation.*SystemInformationClass":"0x5.*SystemInformation/
    condition:
        any of them
}

rule QuerySystemInformationSystemKernelDebuggerInformation {
    strings:
        $NtQuerySystemInformation = /PID.{50,200}NtQuerySystemInformation.*SystemInformationClass":"0x23.*SystemInformation/
    condition:
        any of them
}

rule SetWindowsHook {
    strings:
        $SetWindowsHook = /PID.{50,200}SetWindowsHook/
    condition:
        any of them
}

rule PowershellAddMpPreference {
    strings:
        $NtCreateUserProcess = /PID.{50,200}NtCreateUserProcess.*CommandLine.*powershell.*Add-MpPreference/
    condition:
        any of them
}

rule PowershellEncodedCommand {
    strings:
        $NtCreateUserProcess = /PID.{50,200}NtCreateUserProcess.*CommandLine.*powershell.*(EncodedCommand|FromBase64String|ec)/
    condition:
        any of them
}

rule PowershellDownloader {
    strings:
        $PowershellDownloader = /PID.{50,200}NtCreateUserProcess.*CommandLine.*powershell.*(iwr).*-Uri.*http/
    condition:
        any of them
}


rule PoweshellSetMpPreference {
    strings:
        $NtCreateUserProcess = /PID.{50,200}NtCreateUserProcess.*CommandLine.*powershell.*Set-MpPreference.*(ExclusionPath|DisableIntrusionPreventionSystem|DisableIOAVProtection|DisableRealtimeMonitoring|DisableScriptScanning|EnableControlledFolderAccess|EnableNetworkProtection|MAPSReporting|SubmitSamplesConsent)/
    condition:
        any of them
}


rule CreateSchtasks {
    strings:
        $CreateSchtasks = /PID.{50,200}NtCreateUserProcess.*schtasks.*Create.*/
    condition:
        any of them
}

rule DeleteFile {
    strings:
        $DeleteFile = /PID.{50,200}DeleteFile/
    condition:
        any of them
}

rule DeleteKey {
    strings:
        $NtDeleteKey = /PID.{50,200}NtDeleteKey/
    condition:
        any of them
}

rule CheckStorageProperty {
    strings:
        $NtDeviceIoControlFile = /PID.{50,200}NtDeviceIoControlFile.*IoControlCode":"0x2D1400.*InputBuffer/
    condition:
        any of them
}

rule CreateUserProcessExe {
    strings:
        $NtCreateUserProcess1 = /PID.{50,200}NtCreateUserProcess.*CommandLine.*\.exe/
    condition:
        any of them
}

rule CreateUserProcessBat {
    strings:
        $NtCreateUserProcess2 = /PID.{50,200}NtCreateUserProcess.*CommandLine.*\.bat/
    condition:
        any of them
}

rule CreateUserProcessPS {
    strings:
        $NtCreateUserProcess3 = /PID.{50,200}NtCreateUserProcess.*CommandLine.*\.ps/
    condition:
        any of them
}

rule CreateProcessWScript {
    strings:
        $WScript = /PID.{50,200}NtCreateUserProcess.*CommandLine.*(cscript|WScript).*\.(vb|js)/
    condition:
        any of them
}

rule GetCursorPos {
    strings:
        $NtUserGetCursorPos = /PID.{50,200}NtUserGetCursorPos/
    condition:
        any of them
}

rule SetCursorPos {
    strings:
        $NtUserSetCursor = /PID.{50,200}NtUserSetCursorPos/
    condition:
        any of them
}

rule RegEnumerateDirectory {
    strings:
        $NtQueryValueKey1 = /PID.{50,200}NtQueryValueKey.*Category/
        $NtQueryValueKey2 = /PID.{50,200}NtQueryValueKey.*Name/
        $NtQueryValueKey3 = /PID.{50,200}NtQueryValueKey.*ParentFolder/
        $NtQueryValueKey4 = /PID.{50,200}NtQueryValueKey.*Description/
        $NtQueryValueKey5 = /PID.{50,200}NtQueryValueKey.*RelativePath/
        $NtQueryValueKey6 = /PID.{50,200}NtQueryValueKey.*ParsingName/
        $NtQueryValueKey7 = /PID.{50,200}NtQueryValueKey.*InfoTip/
        $NtQueryValueKey8 = /PID.{50,200}NtQueryValueKey.*LocalizedName/
    condition:
        all of them
}


rule BrowserDataStorage {
    strings:
        $Chromium = /PID.{50,200}.*(Edge|Chrome|Chromium|YandexBrowser|Kometa|Orbitum|Dragon|Torch|Amigo).*User Data.*/
        $ChromiumCookies = /PID.{50,200}.*(Edge|Chrome|Chromium|Brave|YandexBrowser|Kometa|Orbitum|Dragon|Torch|Amigo).*User Data.*Default(.*Network)?.*(Cookies|Login Data|History|Local State|Web Data)/
        $Mozilla = /PID.{50,200}.*Mozilla.*Firefox.*profiles(\.ini)/
    condition:
        any of them
}

rule MicrosoftCredentials
{
    strings:
        $AppData = /PID.*AppData.*Microsoft.*(Vault|Credentials)/
        $vcrd = /PID.*(\.vcrd|Policy.vpol|Windows Credentials|CredEnumerate|listcreds:|vaultcmd(\.exe))/
    condition:
        any of them
}

rule EncryptData {
    strings:
        $Chromium = /PID.{50,200}.*NtWriteFile.*Program Files.*(Edge|Chrome|Chromium|YandexBrowser|Kometa|Orbitum|Dragon|Torch|Amigo).*\.(exe|dat)/
        $encrypted = /PID.{50,200}.*NtSetInformationFile.*\.(encrypted)/
    condition:
        all of them
}


rule TracingMaliciousDownloads {
    strings:
        $NtSetValueKey = /PID.{50,200}NtSetValueKey.*(FileTracingMask|EnableConsoleTracing|ConsoleTracingMask|EnableFileTracing|EnableAutoFileTracing)/
        $NtCreateKeyRASAPI32 = /PID.{50,200}NtCreateKey.*REGISTRY.*Tracing.*RASAPI32/
        $NtCreateKeyRASMANCS = /PID.{50,200}NtCreateKey.*REGISTRY.*Tracing.*RASMANCS/
    condition:
        $NtSetValueKey and 1 of ($NtCreateKey*)
}

rule WorkWithCryptLib
{
    strings:
        $CryptAcquireContextA = /PID.{50,200}(CryptHashData|CryptAcquireContext)/
    condition:
        any of them
}

rule CreateSHA1Crypt 
{
    strings:
        $CryptCreateHash = /PID.{50,200}CryptCreateHash.*Arg1=0x8004.*Arg2/
    condition:
        any of them
}

rule HideTheadFromDebugger
{
    strings:
        $NtSetInformationThread = /PID.{50,200}NtSetInformationThread.*ThreadInformationClass":"0x11.*ThreadInformation/
    condition:
        any of them
}

rule SetWindowsHookKeyLogger {
    strings:
        $SetWindowsHookKeyLogger1 = /PID.{50,200}SetWindowsHook.*Arg0=0xd.*Arg1/
        $SetWindowsHookKeyLogger2 = /PID.{50,200}SetWindowsHook.*Arg0=0x2.*Arg1/
    condition:
        any of them
}

rule SetGlobalApplicationHook {
    strings:
        $0xd = /PID.{50,200}SetWindowsHook.*Arg0=0x3.*Arg1/
    condition:
        any of them
}

rule Reboot {
    strings:
       $reboot = /PID.{50,200}(ShutdownWithoutLogonHideRestart|HideShutDown|HideSignOut|ExitWindows|InitiateSystemShutdown|InitiateShutdown)/
    condition:
        any of them
}

rule KeyLogApi {
    strings:
        $GetAsyncKeyState = /PID.{50,200}GetAsyncKeyState/
        $GetKeyState = /PID.{50,200}GetKeyState/
        $GetKeyboardState = /PID.{50,200}GetKeyboardState/
        $VkKeyScan = /PID.{50,200}VkKeyScan/
        $VkKeyScanEx = /PID.{50,200}VkKeyScanEx/
        $GetKeyNameText = /PID.{50,200}GetKeyNameText/
    condition:
        any of them
}


rule UnhookWindowsHook {
    strings:
        $UnhookWindowsHook = /PID.{50,200}UnhookWindowsHook/
    condition:
        any of them
}

rule CreateMD5Crypt 
{
    strings:
        $CryptCreateHash = /PID.{50,200}CryptCreateHash.*Arg1=0x8003.*Arg2/
    condition:
        any of them
}

/*
rule Powershell
{
    strings:
        $powershell1 = /PID.*powershell.exe/
        $powershell2 = /PID.*powershell32.exe/
    condition:
        any of ($powershell*)
}
*/

rule CreateKeyInjectCLSID
{
    strings:
        $NtCreateKeyInProcServer32 = /PID.{50,200}NtCreateKey.*CLSID.*InProcServer32/
        $NtCreateKeyInLocalServer32 = /PID.{50,200}NtCreateKey.*CLSID.*LocalServer32/
        $NtCreateKeyInTreatAs = /PID.{50,200}NtCreateKey.*CLSID.*TreatAs/
    condition:
        1 of ($NtCreateKeyIn*)
}

rule AppCompatFlags
{
    strings:
        $RegAppCompatFlags = /PID.{50,200}NtOpenKey.{100,300}AppCompatFlags.{5,100}[0-9a-zA-Z]\.exe/
    condition:
        1 of ($Reg*)
}

rule ShellServiceObjectDelayLoad
{
    strings:
        $RegNtCreateKeyShellServiceObjectDelayLoad = /PID.{50,200}NtCreateKey.{100,300}ShellServiceObjectDelayLoad/
    condition:
        1 of ($Reg*)
}

rule RegAutorun {
    strings:
        $autorun = /PID.{50,200}NtWriteFile.*(win.ini|system.ini|autorun.inf)/
        $regrun = /PID.{50,200}NtSetValueKey.*Key.*REGISTRY.*SOFTWARE.*MICROSOFT.*WINDOWS.*CURRENTVERSION.*(RUN|WINLOGON|WINDOWS).*Value.*\.exe/
        //$systemini = /PID.{50,200}NtWriteFile.*system.ini/
        //$autorun = /PID.{50,200}NtWriteFile.*autorun.inf/
        //$NtSetValueKey = /PID.{50,200}NtCreateKey.*Users.*Desktop.*exe/
    condition:
        any of them
}

rule StartUpFoldier {
    strings:
        $Startup = /PID.{50,200}(NtWriteFile|CopyFile).*Start Menu.*Programs.*Startup.*/
    condition:
        any of them
}

rule SocketUsage {
    strings:
        $Inetsocket = /PID.{50,200}socket/
        $InetWSASocket = /PID.{50,200}WSASocket/
        $select = /PID.{50,200}select/
        $setsockopt = /PID.{50,200}setsockopt/
    condition:
        any of them
}

rule CheckWineInReg
{
    strings:
        $NtOpenkey = /PID.{50,200}NtOpenKey.*Software.*Wine"/
    condition:
        any of them
}

rule PossibleDeadDropSteam
{
    strings:
        $WinHttpConnect = /PID.{50,200}WinHttpConnect.*steamcommunity.com/
        $WinHttpOpenRequest = /PID.{50,200}WinHttpOpenRequest.*Arg1=.*GET.*Arg2.*profiles.[0-9a-zA-Z]/
    condition:
        all of them
}

rule ManipulateBootConfiguration {
    strings:
        $bcdedit = /PID.*bcdedit.exe/
        $deletevalue = /PID.*bcdedit.exe.*deletevalue safeboot/

        $bootini = /PID.*boot.ini/
    condition:
        any of them
}

rule gpresult {
    strings:
        $gpresult = /PID.*gpresult/
    condition:
        any of them
}

rule EnumerateDeviceDrivers
{
    strings:
        $gpresult = /PID.*driverquery(.exe)?/
    condition:
        any of them
}

rule GetGeolocationWindows
{
    strings:
        $geolocation = /PID.*microsoft-windows-geolocation-framework/
    condition:
        any of them
}

rule DisableCodeSigning
{
    strings:
        $bcdedit = /PID.*bcdedit\.exe -set TESTSIGNING ON/
    condition:
        any of them
}

rule SafeBootReg
{
    strings:
        $SafeBoot = /PID.*System.*CurrentControlSet.*Control.*SafeBoot.*Minimal/
    condition:
        all of them
}

rule Schedule
{
    strings:
        $SafeBoot = /PID.*NtSetValueKey.*Key.*REGISTRY.*MACHINE.*SYSTEM.*SYSTEM.*CONTROLSET001.*SERVICES.*SCHEDULE.*Value.*\.exe/
    condition:
        all of them
}

rule CreateService
{
    strings:
        $NtCreateUserProcess = /PID.{50,200}NtCreateUserProcess.*sc.exe create/
    condition:
        all of them
}

rule StartService
{
    strings:
        $NtCreateUserProcess = /PID.{50,200}NtCreateUserProcess.*sc.exe start/
    condition:
        all of them
}

rule StopService
{
    strings:
        $NtCreateUserProcess = /PID.{50,200}NtCreateUserProcess.*sc.exe stop/
    condition:
        all of them
}

rule InternetConnectToIp{
    strings:
        $InternetConnect = /PID.{50,200}(InternetConnect|InternetOpenUrl|WinHttpGetProxyForUrl|URLDownloadToFile|WinHttpConnect).*"Arg1=.*((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}.*Arg2/
        // $InternetOpenUrl = /PID.{50,200}InternetOpenUrl.*"Arg1=.*((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}.*Arg2/
        // $WinHttpGetProxyForUrl = /PID.{50,200}WinHttpGetProxyForUrl.*"Arg1=.*((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}.*Arg2/
        // $WinHttpConnect = /PID.{50,200}WinHttpConnect.*"Arg1=.*((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}.*Arg2/

    //{"Plugin":"apimon","TimeStamp":"1741880635.600971","PID":2936,"PPID":968,"TID":3968,"UserName":"SessionID","UserId":1,"ProcessName":"\\Device\\HarddiskVolume2\\Users\\egor\\AppData\\Local\\Temp\\3140a3c17c\\Gxtuum.exe","Method":"HttpOpenRequestA","EventUID":"0x108c5e","Event":"api_called","CLSID":null,"CalledFrom":"0x7906c5","ReturnValue":"0xcc000c","Arguments":["Arg0=0xcc0008","Arg1=0x268f9e0:\"POST\"","Arg2=0x5e2f00:\"/pNdj30Vs11/index.php\"","Arg3=0x0:\"\"","Arg4=0x0:\"\"","Arg5=0x0:\"\"","Arg6=0x0","Arg7=0x1"]}
    //{"Plugin":"apimon","TimeStamp":"1741880635.604754","PID":2936,"PPID":968,"TID":3968,"UserName":"SessionID","UserId":1,"ProcessName":"\\Device\\HarddiskVolume2\\Users\\egor\\AppData\\Local\\Temp\\3140a3c17c\\Gxtuum.exe","Method":"HttpAddRequestHeadersA","EventUID":"0x108c69","Event":"api_called","CLSID":null,"CalledFrom":"0x7400f789","ReturnValue":"0x1","Arguments":["Arg0=0xcc000c","Arg1=0x5da6a0:\"Content-Type: application/x-www-form-urlencoded\"","Arg2=0x2f","Arg3=0xa0000000"]}

    condition:
        any of them
}

rule InternetConnect {
    strings:
        $InternetConnect = /PID.{50,200}InternetConnect.*"Arg1=.*Arg2/
        $InternetOpenUrl = /PID.{50,200}InternetOpenUrl.*"Arg1=.*Arg2/
        $WinHttpGetProxyForUrl = /PID.{50,200}WinHttpGetProxyForUrl.*"Arg1=.*Arg2/
        $WinHttpConnect = /PID.{50,200}WinHttpConnect.*"Arg1=.*Arg2/
    condition:
        any of them
}

rule BitBltFullScrean
{
    strings:
        $GdiBitBlt =  /PID.{50,200}GdiBitBlt.*"x":"0x0","y":"0x0","cx":"0x400.*cy":"0x300/
    condition:
        any of them
}

rule GetIpFrom {
    strings:
        $InternetConnect = /PID.{50,200}(InternetConnect|InternetOpenUrl|WinHttpGetProxyForUrl|WinHttpConnect).*"Arg1=.*(bot.whatismyipaddress.com|ipinfo.io|checkip.dyndns.org|ifconfig.me|ipecho.net|api.ipify.org|checkip.amazonaws.com|icanhazip.com|wtfismyip.com|api.myip.com|ip-api.com|ip.tool.chinaz.com|1234i.com|ip138.com|myip.com.tw|taobao.com\/help\/getip.php|chaipip.com|sojson.com).*Arg2/
    condition:
        any of them
}

rule GetUserName {
    strings:
        $GetUserName = /PID.{50,200}GetUserName/
    condition:
        any of them
}

rule GetFreeSpace {
    strings:
        $GetFreeSpace = /PID.{50,200}GetFreeSpace/
        $GetDiskFreeSpace = /PID.{50,200}GetDiskFreeSpace/
    condition:
        any of them
}

rule SuspendThread {
    strings:
        $NtSuspendThread = /PID.{50,200}NtSuspendThread/
        $NtResumeThread =  /PID.{50,200}NtResumeThread/
    condition:
        all of them
}


rule GetCpuInfo {
    strings:
        $CentralProcessor = /PID.*System.*CentralProcessor/
    condition:
        any of them
}

rule DisableWinDefendService {
    strings:
        $OpenService = /PID.{50,200}OpenService.*WinDefend/
        $ControlService = /PID.{50,200}ControlService.*Arg1=0x1.*Arg2/
    condition:
        all of them
}


rule WinDefendRemoveDefinitions {
    strings:
        $RemoveDefinitions = /PID.*Program Files.*Windows Defender.*MpCmdRun.exe.*-RemoveDefinitions -All/
    condition:
        all of them
}

rule FindDebuggerInWindow
{
    strings:
       $FindWindowRegmon = /PID.{50,200}FindWindow.*Regmonclass/
       $FindWindow184 = /PID.{50,200}FindWindow.*18467-41/
       $FindWindowFilemon = /PID.{50,200}FindWindow.*Filemonclass/
       $FindWindowProcmon = /PID.{50,200}FindWindow.*PROCMON_WINDOW_CLASS/

       $FindWindowOlly = /PID.{50,200}FindWindow.*OLLYDBG/
       $FindWindowGBDYLLO = /PID.{50,200}FindWindow.*GBDYLLO/
       $FindWindowPediy06 = /PID.{50,200}FindWindow.*pediy06/
    condition:
        any of them
}

rule FindShellTrayWnd {
    strings:
       $FindWindow184 = /PID.{50,200}FindWindow.*Shell_TrayWnd/
    condition:
        any of them
}

rule SetInformationFileHidden {
    strings:
        $FILE_ATTRIBUTE_HIDDEN = /PID.{50,200}NtSetInformationFile.*FileName.*\.exe.*FileAttributes.*FILE_ATTRIBUTE_HIDDEN/
    condition:
        any of them
}


rule FindWindowTaskManager {
    strings:
        $WindowTaskManager = /PID.{50,200}FindWindowA.*Windows Task Manager/
    condition:
        any of them
}

rule Padodor {
    strings:
        $SHELLSERVICEOBJECTDELAYLOAD = /PID.*NtSetValueKey.*REGISTRY.*MICROSOFT.*WINDOWS.*CURRENTVERSION.*SHELLSERVICEOBJECTDELAYLOAD.*ValueName.*Web Event Logger.*Value.*79FEACFF-FFCE-815E-A900-316290B5B738/
        $INPROCSERVER32 = /PID.*NtSetValueKey.*REGISTRY.*MACHINE.*SOFTWARE.*SOFTWARE.*CLASSES.*CLSID.*79FEACFF-FFCE-815E-A900-316290B5B738.*INPROCSERVER32.*ValueName.*ThreadingModel/
    condition:
        all of them
}

rule WerFaultStart
{
    strings:
        $WindowTaskManager = /PID.{50,200}NtCreateUserProcess.*WerFault.exe.*-u.*-p.*-s/
        //NtCreateUserProcess C:\\Windows\\SysWOW64\\WerFault.exe -u -p 4400 -s 924 
    condition:
        any of them
}

rule CreateLnk {
    strings:
        $lnk = /PID.{50,200}WriteFile.*\.lnk/
    condition:
        any of them
}

rule htacmdstart {
    strings:
        $htacmdstart = /PID.{50,200}NtCreateUserProcess.*Windows.*(SysWOW64|System32).*mshta.exe.*1E460BD7-F1C3-4B2E-88BF-4E770A288AF5/
    condition:
        any of them
}

rule bitsadminDownload {
    strings:
        $bitsadmin = /PID.{50,200}NtCreateUserProcess.*Windows.*(SysWOW64|System32).*bitsadmin.exe.*(http|https|((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}).*/
    condition:
        any of them
}

rule ShellOpenCommandRegistry {
    strings:
       $NtSetValueKey = /PID.{50,200}NtSetValueKey.*SOFTWARE.*CLASSES.*(TEXTFILE|EXEFILE).*SHELL.*OPEN.*COMMAND.*/
       $NtCreateKey = /PID.{50,200}NtSetValueKey.*SOFTWARE.*CLASSES.*(TEXTFILE|EXEFILE).*SHELL.*OPEN.*COMMAND.*/
    condition:
        any of them
}

rule CreateServiceViaReg
{
    strings:
       $NtCreateKey = /PID.{50,200}NtSetValueKey.*SYSTEM.*CurrentControlSet.*Services.*/
    condition:
        any of them
}

rule EnumarateProcess
{
    strings:
        $Process32FirstW = /PID.{50,200}Process32FirstW/
        $Process32NextW = /PID.{50,200}Process32NextW/

        $CreateToolhelp32Snapshot = /PID.{50,200}CreateToolhelp32Snapshot.*Arg0.*0xf.*Arg1/

    condition:
        1 of ($Process*) or $CreateToolhelp32Snapshot
}

rule ReadNtdll
{
    strings:
        $NtReadFile = /PID.{50,200}NtReadFile.*ntdll\.dll/
    condition:
        all of them
}

rule ChangeRegistryTimestamp {
    strings:
        $NtSetInformationKey = /PID.{50,200}NtSetInformationKey.*KeySetInformationClass.*"0x8".*KeySetInformation/
        // https://www.inversecos.com/2022/04/malicious-registry-timestamp.html
    condition:
        any of them
}

rule CreateTasksInJob
{
    strings:
        $NtWriteFile = /PID.{50,200}NtWriteFile.*Windows.*Tasks.*\.job/
    condition:
        any of them
}

rule PosiblePadodor
{
    strings:
        $_asdasds = /adsadwgfrege/
    condition:
        CreateFileExe
}



// regasm/*/
    