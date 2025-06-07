rule CommonAPIMonitoring : SaveMatch
{
    strings:
        // 1.Registry
        $reg_create = /"TimeStamp".*NtCrea  teKey.*/
        $reg_open = /"TimeStamp".*NtOpenKey.*/
        $reg_query = /"TimeStamp".*NtQueryValueKey.*/
        $reg_set = /"TimeStamp".*NtSetValueKey.*/
        $reg_delete = /"TimeStamp".*NtDeleteKey.*/
        $reg_enum = /"TimeStamp".*NtEnumerateKey.*/
        $reg_enum_value = /"TimeStamp".*NtEnumerateValueKey.*/
        $reg_query_key = /"TimeStamp".*NtQueryKey.*/
        $reg_notify = /"TimeStamp".*NtNotifyChangeKey.*/
        $reg_save = /"TimeStamp".*NtSaveKey.*/
        $reg_restore = /"TimeStamp".*NtRestoreKey.*/
        
        // 2.File System
        $file_create = /"TimeStamp".*NtCreateFile.*/
        $file_write = /"TimeStamp".*NtWriteFile.*/
        $file_read = /"TimeStamp".*NtReadFile.*/
        $file_query = /"TimeStamp".*NtQueryInformationFile.*/
        $file_set = /"TimeStamp".*NtSetInformationFile.*/
        $file_attr = /"TimeStamp".*NtQueryAttributesFile.*/
        $file_dir = /"TimeStamp".*NtQueryDirectoryFile.*/
        $file_delete = /"TimeStamp".*NtDeleteFile.*/
        $file_rename = /"TimeStamp".*NtRenameFile.*/
        $file_lock = /"TimeStamp".*NtLockFile.*/
        
        // 3.Process/Thread
        $proc_create = /"TimeStamp".*NtCreateProcess.*/
        $proc_user_create = /"TimeStamp".*NtCreateUserProcess.*/
        $proc_open = /"TimeStamp".*NtOpenProcess.*/
        $proc_query = /"TimeStamp".*NtQueryInformationProcess.*/
        $proc_set = /"TimeStamp".*NtSetInformationProcess.*/
        $thread_create = /"TimeStamp".*NtCreateThread.*/
        $thread_suspend = /"TimeStamp".*NtSuspendThread.*/
        $thread_resume = /"TimeStamp".*NtResumeThread.*/
        $thread_query = /"TimeStamp".*NtQueryInformationThread.*/
        $thread_set = /"TimeStamp".*NtSetInformationThread.*/
        $proc_terminate = /"TimeStamp".*NtTerminateProcess.*/
        
        // 4.Memory
        $mem_alloc = /"TimeStamp".*NtAllocateVirtualMemory.*/
        $mem_protect = /"TimeStamp".*NtProtectVirtualMemory.*/
        $mem_query = /"TimeStamp".*NtQueryVirtualMemory.*/
        $mem_write = /"TimeStamp".*NtWriteVirtualMemory.*/
        $mem_read = /"TimeStamp".*NtReadVirtualMemory.*/
        $mem_free = /"TimeStamp".*NtFreeVirtualMemory.*/
        $mem_map = /"TimeStamp".*NtMapViewOfSection.*/
        
        // 5.Network
        // $dns_query = /"TimeStamp".*DnsQuery.*/
        // $get_addr = /"TimeStamp".*GetAddrInfo.*/
        // $inet_open = /"TimeStamp".*InternetOpen.*/
        // $inet_connect = /"TimeStamp".*InternetConnect.*/
        // $inet_open_url = /"TimeStamp".*InternetOpenUrl.*/
        // $socket_create = /"TimeStamp".*socket.*/
        // $wsa_socket = /"TimeStamp".*WSASocket.*/
        // $connect = /"TimeStamp".*connect.*/
        // $send = /"TimeStamp".*send.*/
        // $recv = /"TimeStamp".*recv.*/
        
        // 6.System Info
        $query_system = /"TimeStamp".*NtQuerySystemInformation.*/
        $query_object = /"TimeStamp".*NtQueryObject.*/
        $query_perf = /"TimeStamp".*NtQueryPerformanceCounter.*/
        $get_tick = /"TimeStamp".*GetTickCount.*/
        $get_computer = /"TimeStamp".*GetComputerName.*/
        $get_user = /"TimeStamp".*GetUserName.*/
        $get_folder = /"TimeStamp".*SHGetFolderPath.*/
        
        // 7.Crypto
        $crypt_acquire = /"TimeStamp".*CryptAcquireContext.*/
        $crypt_create_hash = /"TimeStamp".*CryptCreateHash.*/
        $crypt_hash_data = /"TimeStamp".*CryptHashData.*/
        $crypt_encrypt = /"TimeStamp".*CryptEncrypt.*/
        $crypt_decrypt = /"TimeStamp".*CryptDecrypt.*/
        
        // 8.Hooks/Injection
        $set_hook = /"TimeStamp".*SetWindowsHookEx.*/
        $create_remote = /"TimeStamp".*CreateRemoteThread.*/
        $queue_apc = /"TimeStamp".*NtQueueApcThread.*/
        $adjust_priv = /"TimeStamp".*AdjustTokenPrivileges.*/
        
        // 9.Additional
        $delay_exec = /"TimeStamp".*NtDelayExecution.*/
        $yield_exec = /"TimeStamp".*NtYieldExecution.*/
        $create_mutex = /"TimeStamp".*NtCreateMutant.*/
        $open_mutex = /"TimeStamp".*NtOpenMutant.*/
        $create_event = /"TimeStamp".*NtCreateEvent.*/
        $create_section = /"TimeStamp".*NtCreateSection.*/
        $create_timer = /"TimeStamp".*NtCreateTimer.*/
        $query_auid = /"TimeStamp".*NtQueryInformationToken.*/

    condition:
        any of them
}