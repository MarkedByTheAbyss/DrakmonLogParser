rule CreateFileExe 
{
    strings:
        $NtCreateExeFileSysWOW = /NtCreateFile.{50,200}SysWOW64.{5,50}[0-9a-zA-Z]\.exe/
        $NtCreateExeFileSystem = /NtCreateFile.{50,200}System.{5,50}[0-9a-zA-Z]\.exe/
        $NtCreateExeFileSystem32 = /NtCreateFile.{50,200}System32.{5,50}[0-9a-zA-Z]\.exe/
    condition:
        any of ($NtCreateExeFileSys*)
}

rule WriteFileExeToSystem
{
    strings:
        $NtWriteExeFileSysWOW = /NtWriteFile.{100,150}SysWOW64.{5,50}[0-9a-zA-Z]\.(exe|com)/
        $NtWriteExeFileSystem = /NtWriteFile.{100,150}System.{5,50}[0-9a-zA-Z]\.(exe|com)/
        $NtWriteExeFileSystem32 = /NtWriteFile.{100,150}System32.{5,50}[0-9a-zA-Z]\.(exe|com)/
    condition:
        any of ($NtWriteExeFile*)
}

rule WriteFileExeWithDosPath
{
    strings:
        $NtWriteExeFileTemp = /NtWriteFile.*[A-Z0-9]{1,6}~[0-9].*\.exe/
    condition:
        any of ($NtWriteExeFile*)
}

rule WriteFileExe
{
    strings:
        $NtWriteExe = /NtWriteFile.*\.exe/
    condition:
        any of ($NtWriteExe*)
}


rule WriteFileExeToDesktop
{
    strings:
        $NtWriteExeFileDesktop = /NtWriteFile.{100,150}Desktop.{5,50}[0-9a-zA-Z]\.(exe|com)/
        $NtWriteExeFileTemp = /NtWriteFile.{100,150}Temp.{5,50}[0-9a-zA-Z]\.(exe|com)/
    condition:
        any of ($NtWriteExeFile*)
}


rule WriteFileExeToProgramdata
{
    strings:
        $NtWriteExeFileTemp = /NtWriteFile.{100,150}ProgramData.{5,50}[0-9a-zA-Z]\.(exe|com)/
    condition:
        any of ($NtWriteExeFile*)
}

rule WriteFileExeToTemp
{
    strings:
        $NtWriteExeFileTemp = /NtWriteFile.{100,150}Temp.{5,50}[0-9a-zA-Z]\.(exe|com)/
    condition:
        any of ($NtWriteExeFile*)
}

rule GetComputerName {
    strings:
        $GetComputerName = /GetComputerName/
    condition:
        any of them
}

rule InteractionWithDNS {
    strings:
        $Reg = /DNSClient/
        $InetDnsQuery = /DnsQuery/
        $GetAddrInfo = /GetAddrInfo/
    condition:
        any of them
}


rule CreateFileDll
{
    strings:
        $NtCreateDllFileSysWOW = /NtCreateFile.{50,200}SysWOW64.{5,50}[0-9a-zA-Z]\.dll/
        $NtCreateDllFileSystem = /NtCreateFile.{50,200}System.{5,50}[0-9a-zA-Z]\.dll/
        $NtCreateDllFileSystem32 = /NtCreateFile.{50,200}System32.{5,50}[0-9a-zA-Z]\.dll/
    condition:
        1 of ($NtCreateDllFileSys*)
}

rule WriteFileDllSystem
{
    strings:
        $NtWriteDllFileSysWOW = /NtWriteFile.{100,150}SysWOW64.{5,50}[0-9a-zA-Z]\.dll/
        $NtWriteDllFileSystem = /NtWriteFile.{100,150}System.{5,50}[0-9a-zA-Z]\.dll/
        $NtWriteDllFileSystem32 = /NtWriteFile.{100,150}System32.{5,50}[0-9a-zA-Z]\.dll/
    condition:
        1 of ($NtWriteDllFileSys*)
}

rule CreateUserProcessFromSystem
{
    strings:
        $NtCreateUserProcessSysWOW64 = /SysWOW64.{5,50}[0-9a-zA-Z]\.exe.{5,50}NtCreateUserProcess/
        $NtCreateUserProcessSystem = /System.{5,50}[0-9a-zA-Z]\.exe.{5,50}NtCreateUserProcess/
        $NtCreateUserProcessSystem32 = /System32.{5,50}[0-9a-zA-Z]\.exe.{5,50}NtCreateUserProcess/
    condition:
        any of them
}

rule DelayExecution
{
    strings:
        $NtDelayExecution = /NtDelayExecution.*DelayIntervalMs":-.*/
    condition:
        any of them
}


rule NtYieldExecution
{
    strings:
        $NtYieldExecution = /NtYieldExecution/
    condition:
        any of them
}

rule CreateMutexOnSystemExe {
    strings:
        $CreateMutex = /CreateMutant(registry|smss.exe|wininit.exe|csrss.exe|winlogon.exe|services.exe|lsass.exe|fontdrvhost.exe|svchost.exe)/
    condition:
        any of them
}



rule TerminateProcess {
    strings:
        $NtTerminateProcess = /NtTerminateProcess/
    condition:
        any of them
}

rule BinaryInRegistry {
    strings:
        $NtSetValueKey =  /NtSetValueKey.*418A073AA3BC3475/
    condition:
        any of them
}

rule GetTickCount
{
    strings:
        $GetTickCount = /GetTickCount/
    condition:
       any of them
}

rule GetFolderPath {
    strings:
        $GetFolderPathAppdata = /SHGetFolderPath.*AppData/
        $GetFolderPathSystem32 = /SHGetFolderPath.*system32/
        $GetFolderPathSysWOW64 = /SHGetFolderPath.*syswow/
        //Program Files (x86) Documents ProgramData Common Files Pictures History INetCookies INetCache
    condition:
        any of them
}

rule QueryInformationProcessDebugingPresent {
    strings:
        $NtQueryInformationProcess = /NtQueryInformationProcess.*ProcessInformationClass":"0x1f.*ProcessInformation/
    condition:
        any of them
}

rule QueryInformationProcessSystemKernelDebuggerInformation {
    strings:
        $NtQueryInformationProcessSystemKernelDebuggerInformation = /NtQueryInformationProcess.*ProcessInformationClass":"0x23.*ProcessInformation/
    condition:
        any of them
}

rule QueryInformationProcessDebugPort  {
    strings:
        $NtQueryInformationProcessDebugPort = /NtQueryInformationProcess.*ProcessInformationClass":"0x7/
    condition:
        any of them
}

rule RemoveDirectory{
    strings:
        $RemoveDirectory = /RemoveDirectory/
    condition:
        any of them
}

rule QuerySystemInformationSystemProcessInformation {
    strings:
        $NtQuerySystemInformation = /NtQuerySystemInformation.*SystemInformationClass":"0x5.*SystemInformation/
    condition:
        any of them
}

rule QuerySystemInformationSystemKernelDebuggerInformation {
    strings:
        $NtQuerySystemInformation = /NtQuerySystemInformation.*SystemInformationClass":"0x23.*SystemInformation/
    condition:
        any of them
}

rule SetWindowsHook {
    strings:
        $SetWindowsHook = /SetWindowsHook/
    condition:
        any of them
}

rule PowershellAddMpPreference {
    strings:
        $NtCreateUserProcess = /NtCreateUserProcess.*CommandLine.*powershell.*Add-MpPreference/
    condition:
        any of them
}

rule PowershellEncodedCommand {
    strings:
        $NtCreateUserProcess = /NtCreateUserProcess.*CommandLine.*powershell.*(EncodedCommand|FromBase64String|ec)/
    condition:
        any of them
}

rule PowershellDownloader {
    strings:
        $PowershellDownloader = /NtCreateUserProcess.*CommandLine.*powershell.*(iwr).*-Uri.*http/
    condition:
        any of them
}


rule PoweshellSetMpPreference {
    strings:
        $NtCreateUserProcess = /NtCreateUserProcess.*CommandLine.*powershell.*Set-MpPreference.*(ExclusionPath|DisableIntrusionPreventionSystem|DisableIOAVProtection|DisableRealtimeMonitoring|DisableScriptScanning|EnableControlledFolderAccess|EnableNetworkProtection|MAPSReporting|SubmitSamplesConsent)/
    condition:
        any of them
}


rule CreateSchtasks {
    strings:
        $CreateSchtasks = /NtCreateUserProcess.*schtasks.*Create.*/
    condition:
        any of them
}

rule DeleteFile {
    strings:
        $DeleteFile = /DeleteFile/
    condition:
        any of them
}

rule DeleteKey {
    strings:
        $NtDeleteKey = /NtDeleteKey/
    condition:
        any of them
}

rule CheckStorageProperty {
    strings:
        $NtDeviceIoControlFile = /NtDeviceIoControlFile.*IoControlCode":"0x2D1400.*InputBuffer/
    condition:
        any of them
}

rule CreateUserProcessExe {
    strings:
        $NtCreateUserProcess1 = /NtCreateUserProcess.*CommandLine.*\.exe/
    condition:
        any of them
}

rule CreateUserProcessBat {
    strings:
        $NtCreateUserProcess2 = /NtCreateUserProcess.*CommandLine.*\.bat/
    condition:
        any of them
}

rule CreateUserProcessPS {
    strings:
        $NtCreateUserProcess3 = /NtCreateUserProcess.*CommandLine.*\.ps/
    condition:
        any of them
}

rule CreateProcessWScript {
    strings:
        $WScript = /NtCreateUserProcess.*CommandLine.*(cscript|WScript).*\.(vb|js)/
    condition:
        any of them
}

rule GetCursorPos {
    strings:
        $NtUserGetCursorPos = /NtUserGetCursorPos/
    condition:
        any of them
}

rule SetCursorPos {
    strings:
        $NtUserSetCursor = /NtUserSetCursorPos/
    condition:
        any of them
}

rule RegEnumerateDirectory {
    strings:
        $NtQueryValueKey1 = /NtQueryValueKey.*Category/
        $NtQueryValueKey2 = /NtQueryValueKey.*Name/
        $NtQueryValueKey3 = /NtQueryValueKey.*ParentFolder/
        $NtQueryValueKey4 = /NtQueryValueKey.*Description/
        $NtQueryValueKey5 = /NtQueryValueKey.*RelativePath/
        $NtQueryValueKey6 = /NtQueryValueKey.*ParsingName/
        $NtQueryValueKey7 = /NtQueryValueKey.*InfoTip/
        $NtQueryValueKey8 = /NtQueryValueKey.*LocalizedName/
    condition:
        all of them
}


rule BrowserDataStorage {
    strings:
        $Chromium = /.*(Edge|Chrome|Chromium|YandexBrowser|Kometa|Orbitum|Dragon|Torch|Amigo).*User Data.*/
        $ChromiumCookies = /.*(Edge|Chrome|Chromium|Brave|YandexBrowser|Kometa|Orbitum|Dragon|Torch|Amigo).*User Data.*Default(.*Network)?.*(Cookies|Login Data|History|Local State|Web Data)/
        $Mozilla = /.*Mozilla.*Firefox.*profiles(\.ini)/
    condition:
        any of them
}

rule MicrosoftCredentials
{
    strings:
        $AppData = /AppData.*Microsoft.*(Vault|Credentials)/
        $vcrd = /(\.vcrd|Policy.vpol|Windows Credentials|CredEnumerate|listcreds:|vaultcmd(\.exe))/
    condition:
        any of them
}

rule EncryptData {
    strings:
        $Chromium = /.*NtWriteFile.*Program Files.*(Edge|Chrome|Chromium|YandexBrowser|Kometa|Orbitum|Dragon|Torch|Amigo).*\.(exe|dat)/
        $encrypted = /.*NtSetInformationFile.*\.(encrypted)/
    condition:
        all of them
}


rule TracingMaliciousDownloads {
    strings:
        $NtSetValueKey = /NtSetValueKey.*(FileTracingMask|EnableConsoleTracing|ConsoleTracingMask|EnableFileTracing|EnableAutoFileTracing)/
        $NtCreateKeyRASAPI32 = /NtCreateKey.*REGISTRY.*Tracing.*RASAPI32/
        $NtCreateKeyRASMANCS = /NtCreateKey.*REGISTRY.*Tracing.*RASMANCS/
    condition:
        $NtSetValueKey and 1 of ($NtCreateKey*)
}

rule WorkWithCryptLib
{
    strings:
        $CryptAcquireContextA = /(CryptHashData|CryptAcquireContext)/
    condition:
        any of them
}

rule CreateSHA1Crypt 
{
    strings:
        $CryptCreateHash = /CryptCreateHash.*Arg1=0x8004.*Arg2/
    condition:
        any of them
}

rule HideTheadFromDebugger
{
    strings:
        $NtSetInformationThread = /NtSetInformationThread.*ThreadInformationClass":"0x11.*ThreadInformation/
    condition:
        any of them
}

rule SetWindowsHookKeyLogger {
    strings:
        $SetWindowsHookKeyLogger1 = /SetWindowsHook.*Arg0=0xd.*Arg1/
        $SetWindowsHookKeyLogger2 = /SetWindowsHook.*Arg0=0x2.*Arg1/
    condition:
        any of them
}

rule SetGlobalApplicationHook {
    strings:
        $0xd = /SetWindowsHook.*Arg0=0x3.*Arg1/
    condition:
        any of them
}

rule Reboot {
    strings:
       $reboot = /(ShutdownWithoutLogonHideRestart|HideShutDown|HideSignOut|ExitWindows|InitiateSystemShutdown|InitiateShutdown)/
    condition:
        any of them
}

rule KeyLogApi {
    strings:
        $GetAsyncKeyState = /GetAsyncKeyState/
        $GetKeyState = /GetKeyState/
        $GetKeyboardState = /GetKeyboardState/
        $VkKeyScan = /VkKeyScan/
        $VkKeyScanEx = /VkKeyScanEx/
        $GetKeyNameText = /GetKeyNameText/
    condition:
        any of them
}


rule UnhookWindowsHook {
    strings:
        $UnhookWindowsHook = /UnhookWindowsHook/
    condition:
        any of them
}

rule CreateMD5Crypt 
{
    strings:
        $CryptCreateHash = /CryptCreateHash.*Arg1=0x8003.*Arg2/
    condition:
        any of them
}

/*
rule Powershell
{
    strings:
        $powershell1 = /powershell.exe/
        $powershell2 = /powershell32.exe/
    condition:
        any of ($powershell*)
}
*/

rule CreateKeyInjectCLSID
{
    strings:
        $NtCreateKeyInProcServer32 = /NtCreateKey.*CLSID.*InProcServer32/
        $NtCreateKeyInLocalServer32 = /NtCreateKey.*CLSID.*LocalServer32/
        $NtCreateKeyInTreatAs = /NtCreateKey.*CLSID.*TreatAs/
    condition:
        1 of ($NtCreateKeyIn*)
}

rule AppCompatFlags
{
    strings:
        $RegAppCompatFlags = /NtOpenKey.{100,300}AppCompatFlags.{5,100}[0-9a-zA-Z]\.exe/
    condition:
        1 of ($Reg*)
}

rule ShellServiceObjectDelayLoad
{
    strings:
        $RegNtCreateKeyShellServiceObjectDelayLoad = /NtCreateKey.{100,300}ShellServiceObjectDelayLoad/
    condition:
        1 of ($Reg*)
}

rule RegAutorun {
    strings:
        $autorun = /NtWriteFile.*(win.ini|system.ini|autorun.inf)/
        $regrun = /NtSetValueKey.*Key.*REGISTRY.*SOFTWARE.*MICROSOFT.*WINDOWS.*CURRENTVERSION.*(RUN|WINLOGON|WINDOWS).*Value.*\.exe/
        //$systemini = /NtWriteFile.*system.ini/
        //$autorun = /NtWriteFile.*autorun.inf/
        //$NtSetValueKey = /NtCreateKey.*Users.*Desktop.*exe/
    condition:
        any of them
}

rule StartUpFoldier {
    strings:
        $Startup = /(NtWriteFile|CopyFile).*Start Menu.*Programs.*Startup.*/
    condition:
        any of them
}

rule SocketUsage {
    strings:
        $Inetsocket = /socket/
        $InetWSASocket = /WSASocket/
        $select = /select/
        $setsockopt = /setsockopt/
    condition:
        any of them
}

rule CheckWineInReg
{
    strings:
        $NtOpenkey = /NtOpenKey.*Software.*Wine"/
    condition:
        any of them
}

rule PossibleDeadDropSteam
{
    strings:
        $WinHttpConnect = /WinHttpConnect.*steamcommunity.com/
        $WinHttpOpenRequest = /WinHttpOpenRequest.*Arg1=.*GET.*Arg2.*profiles.[0-9a-zA-Z]/
    condition:
        all of them
}

rule ManipulateBootConfiguration {
    strings:
        $bcdedit = /bcdedit.exe/
        $deletevalue = /bcdedit.exe.*deletevalue safeboot/

        $bootini = /boot.ini/
    condition:
        any of them
}

rule gpresult {
    strings:
        $gpresult = /gpresult/
    condition:
        any of them
}

rule EnumerateDeviceDrivers
{
    strings:
        $gpresult = /driverquery(.exe)?/
    condition:
        any of them
}

rule GetGeolocationWindows
{
    strings:
        $geolocation = /microsoft-windows-geolocation-framework/
    condition:
        any of them
}

rule DisableCodeSigning
{
    strings:
        $bcdedit = /bcdedit\.exe -set TESTSIGNING ON/
    condition:
        any of them
}

rule SafeBootReg
{
    strings:
        $SafeBoot = /System.*CurrentControlSet.*Control.*SafeBoot.*Minimal/
    condition:
        all of them
}

rule Schedule
{
    strings:
        $SafeBoot = /NtSetValueKey.*Key.*REGISTRY.*MACHINE.*SYSTEM.*SYSTEM.*CONTROLSET001.*SERVICES.*SCHEDULE.*Value.*\.exe/
    condition:
        all of them
}

rule CreateService
{
    strings:
        $NtCreateUserProcess = /NtCreateUserProcess.*sc.exe create/
    condition:
        all of them
}

rule StartService
{
    strings:
        $NtCreateUserProcess = /NtCreateUserProcess.*sc.exe start/
    condition:
        all of them
}

rule StopService
{
    strings:
        $NtCreateUserProcess = /NtCreateUserProcess.*sc.exe stop/
    condition:
        all of them
}

rule InternetConnectToIp : IP 
{
    strings:
        $InternetConnect = /(InternetConnect|InternetOpenUrl|WinHttpGetProxyForUrl|URLDownloadToFile|WinHttpConnect).*"Arg1=.*((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}.*Arg2/
        // $InternetOpenUrl = /InternetOpenUrl.*"Arg1=.*((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}.*Arg2/
        // $WinHttpGetProxyForUrl = /WinHttpGetProxyForUrl.*"Arg1=.*((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}.*Arg2/
        // $WinHttpConnect = /WinHttpConnect.*"Arg1=.*((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}.*Arg2/

    //{"Plugin":"apimon","TimeStamp":"1741880635.600971","PID":2936,"PPID":968,"TID":3968,"UserName":"SessionID","UserId":1,"ProcessName":"\\Device\\HarddiskVolume2\\Users\\egor\\AppData\\Local\\Temp\\3140a3c17c\\Gxtuum.exe","Method":"HttpOpenRequestA","EventUID":"0x108c5e","Event":"api_called","CLSID":null,"CalledFrom":"0x7906c5","ReturnValue":"0xcc000c","Arguments":["Arg0=0xcc0008","Arg1=0x268f9e0:\"POST\"","Arg2=0x5e2f00:\"/pNdj30Vs11/index.php\"","Arg3=0x0:\"\"","Arg4=0x0:\"\"","Arg5=0x0:\"\"","Arg6=0x0","Arg7=0x1"]}
    //{"Plugin":"apimon","TimeStamp":"1741880635.604754","PID":2936,"PPID":968,"TID":3968,"UserName":"SessionID","UserId":1,"ProcessName":"\\Device\\HarddiskVolume2\\Users\\egor\\AppData\\Local\\Temp\\3140a3c17c\\Gxtuum.exe","Method":"HttpAddRequestHeadersA","EventUID":"0x108c69","Event":"api_called","CLSID":null,"CalledFrom":"0x7400f789","ReturnValue":"0x1","Arguments":["Arg0=0xcc000c","Arg1=0x5da6a0:\"Content-Type: application/x-www-form-urlencoded\"","Arg2=0x2f","Arg3=0xa0000000"]}

    condition:
        any of them
}

rule InternetConnect : URL 
{
    strings:
        $InternetConnect = /InternetConnect.*"Arg1=.*Arg2/
        $InternetOpenUrl = /InternetOpenUrl.*"Arg1=.*Arg2/
        $WinHttpGetProxyForUrl = /WinHttpGetProxyForUrl.*"Arg1=.*Arg2/
        $WinHttpConnect = /WinHttpConnect.*"Arg1=.*Arg2/
    condition:
        any of them
}

rule BitBltFullScrean
{
    strings:
        $GdiBitBlt =  /GdiBitBlt.*"x":"0x0","y":"0x0","cx":"0x400.*cy":"0x300/
    condition:
        any of them
}

rule GetIpFrom {
    strings:
        $InternetConnect = /(InternetConnect|InternetOpenUrl|WinHttpGetProxyForUrl|WinHttpConnect).*"Arg1=.*(bot.whatismyipaddress.com|ipinfo.io|checkip.dyndns.org|ifconfig.me|ipecho.net|api.ipify.org|checkip.amazonaws.com|icanhazip.com|wtfismyip.com|api.myip.com|ip-api.com|ip.tool.chinaz.com|1234i.com|ip138.com|myip.com.tw|taobao.com\/help\/getip.php|chaipip.com|sojson.com).*Arg2/
    condition:
        any of them
}

rule GetUserName {
    strings:
        $GetUserName = /GetUserName/
    condition:
        any of them
}

rule GetFreeSpace {
    strings:
        $GetFreeSpace = /GetFreeSpace/
        $GetDiskFreeSpace = /GetDiskFreeSpace/
    condition:
        any of them
}

rule SuspendThread {
    strings:
        $NtSuspendThread = /NtSuspendThread/
        $NtResumeThread =  /NtResumeThread/
    condition:
        all of them
}


rule GetCpuInfo {
    strings:
        $CentralProcessor = /System.*CentralProcessor/
    condition:
        any of them
}

rule DisableWinDefendService {
    strings:
        $OpenService = /OpenService.*WinDefend/
        $ControlService = /ControlService.*Arg1=0x1.*Arg2/
    condition:
        all of them
}


rule WinDefendRemoveDefinitions {
    strings:
        $RemoveDefinitions = /Program Files.*Windows Defender.*MpCmdRun.exe.*-RemoveDefinitions -All/
    condition:
        all of them
}

rule FindDebuggerInWindow
{
    strings:
       $FindWindowRegmon = /FindWindow.*Regmonclass/
       $FindWindow184 = /FindWindow.*18467-41/
       $FindWindowFilemon = /FindWindow.*Filemonclass/
       $FindWindowProcmon = /FindWindow.*PROCMON_WINDOW_CLASS/

       $FindWindowOlly = /FindWindow.*OLLYDBG/
       $FindWindowGBDYLLO = /FindWindow.*GBDYLLO/
       $FindWindowPediy06 = /FindWindow.*pediy06/
    condition:
        any of them
}

rule FindShellTrayWnd {
    strings:
       $FindWindow184 = /FindWindow.*Shell_TrayWnd/
    condition:
        any of them
}

rule SetInformationFileHidden {
    strings:
        $FILE_ATTRIBUTE_HIDDEN = /NtSetInformationFile.*FileName.*\.exe.*FileAttributes.*FILE_ATTRIBUTE_HIDDEN/
    condition:
        any of them
}


rule FindWindowTaskManager {
    strings:
        $WindowTaskManager = /FindWindowA.*Windows Task Manager/
    condition:
        any of them
}

rule Padodor {
    strings:
        $SHELLSERVICEOBJECTDELAYLOAD = /NtSetValueKey.*REGISTRY.*MICROSOFT.*WINDOWS.*CURRENTVERSION.*SHELLSERVICEOBJECTDELAYLOAD.*ValueName.*Web Event Logger.*Value.*79FEACFF-FFCE-815E-A900-316290B5B738/
        $INPROCSERVER32 = /NtSetValueKey.*REGISTRY.*MACHINE.*SOFTWARE.*SOFTWARE.*CLASSES.*CLSID.*79FEACFF-FFCE-815E-A900-316290B5B738.*INPROCSERVER32.*ValueName.*ThreadingModel/
    condition:
        all of them
}

rule WerFaultStart
{
    strings:
        $WindowTaskManager = /NtCreateUserProcess.*WerFault.exe.*-u.*-p.*-s/
        //NtCreateUserProcess C:\\Windows\\SysWOW64\\WerFault.exe -u -p 4400 -s 924 
    condition:
        any of them
}

rule CreateLnk {
    strings:
        $lnk = /WriteFile.*\.lnk/
    condition:
        any of them
}

rule htacmdstart {
    strings:
        $htacmdstart = /NtCreateUserProcess.*Windows.*(SysWOW64|System32).*mshta.exe.*1E460BD7-F1C3-4B2E-88BF-4E770A288AF5/
    condition:
        any of them
}

rule bitsadminDownload {
    strings:
        $bitsadmin = /NtCreateUserProcess.*Windows.*(SysWOW64|System32).*bitsadmin.exe.*(http|https|((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}).*/
    condition:
        any of them
}

rule ShellOpenCommandRegistry {
    strings:
       $NtSetValueKey = /NtSetValueKey.*SOFTWARE.*CLASSES.*(TEXTFILE|EXEFILE).*SHELL.*OPEN.*COMMAND.*/
       $NtCreateKey = /NtSetValueKey.*SOFTWARE.*CLASSES.*(TEXTFILE|EXEFILE).*SHELL.*OPEN.*COMMAND.*/
    condition:
        any of them
}

rule CreateServiceViaReg
{
    strings:
       $NtCreateKey = /NtSetValueKey.*SYSTEM.*CurrentControlSet.*Services.*/
    condition:
        any of them
}

rule EnumarateProcess
{
    strings:
        $Process32FirstW = /Process32FirstW/
        $Process32NextW = /Process32NextW/

        $CreateToolhelp32Snapshot = /CreateToolhelp32Snapshot.*Arg0.*0xf.*Arg1/

    condition:
        1 of ($Process*) or $CreateToolhelp32Snapshot
}

rule ReadNtdll
{
    strings:
        $NtReadFile = /NtReadFile.*ntdll\.dll/
    condition:
        all of them
}

rule ChangeRegistryTimestamp {
    strings:
        $NtSetInformationKey = /NtSetInformationKey.*KeySetInformationClass.*"0x8".*KeySetInformation/
        // https://www.inversecos.com/2022/04/malicious-registry-timestamp.html
    condition:
        any of them
}

rule CreateTasksInJob
{
    strings:
        $NtWriteFile = /NtWriteFile.*Windows.*Tasks.*\.job/
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
    