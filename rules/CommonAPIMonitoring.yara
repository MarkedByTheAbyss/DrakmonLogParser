rule CommonAPIMonitoring : SaveMatch
{
    strings:
        // 1.Registry
        $reg_create = /NtCreateKey.*/
        $reg_open = /NtOpenKey.*/
        $reg_query = /NtQueryValueKey.*/
        $reg_set = /NtSetValueKey.*/
        $reg_delete = /NtDeleteKey.*/
        $reg_enum = /NtEnumerateKey.*/
        $reg_enum_value = /NtEnumerateValueKey.*/
        $reg_query_key = /NtQueryKey.*/
        $reg_notify = /NtNotifyChangeKey.*/
        $reg_save = /NtSaveKey.*/
        $reg_restore = /NtRestoreKey.*/
        
        // 2.File System
        $file_create = /NtCreateFile.*/
        $file_write = /NtWriteFile.*/
        $file_read = /NtReadFile.*/
        $file_query = /NtQueryInformationFile.*/
        $file_set = /NtSetInformationFile.*/
        $file_attr = /NtQueryAttributesFile.*/
        $file_dir = /NtQueryDirectoryFile.*/
        $file_delete = /NtDeleteFile.*/
        $file_rename = /NtRenameFile.*/
        $file_lock = /NtLockFile.*/
        
        // 3.Process/Thread
        $proc_create = /NtCreateProcess.*/
        $proc_user_create = /NtCreateUserProcess.*/
        $proc_open = /NtOpenProcess.*/
        $proc_query = /NtQueryInformationProcess.*/
        $proc_set = /NtSetInformationProcess.*/
        $thread_create = /NtCreateThread.*/
        $thread_suspend = /NtSuspendThread.*/
        $thread_resume = /NtResumeThread.*/
        $thread_query = /NtQueryInformationThread.*/
        $thread_set = /NtSetInformationThread.*/
        $proc_terminate = /NtTerminateProcess.*/
        
        // 4.Memory
        $mem_alloc = /NtAllocateVirtualMemory.*/
        $mem_protect = /NtProtectVirtualMemory.*/
        $mem_query = /NtQueryVirtualMemory.*/
        $mem_write = /NtWriteVirtualMemory.*/
        $mem_read = /NtReadVirtualMemory.*/
        $mem_free = /NtFreeVirtualMemory.*/
        $mem_map = /NtMapViewOfSection.*/
        
        // 5.Network
        // $dns_query = /DnsQuery.*/
        // $get_addr = /GetAddrInfo.*/
        // $inet_open = /InternetOpen.*/
        // $inet_connect = /InternetConnect.*/
        // $inet_open_url = /InternetOpenUrl.*/
        // $socket_create = /socket.*/
        // $wsa_socket = /WSASocket.*/
        // $connect = /connect.*/
        // $send = /send.*/
        // $recv = /recv.*/
        
        // 6.System Info
        $query_system = /NtQuerySystemInformation.*/
        $query_object = /NtQueryObject.*/
        $query_perf = /NtQueryPerformanceCounter.*/
        $get_tick = /GetTickCount.*/
        $get_computer = /GetComputerName.*/
        $get_user = /GetUserName.*/
        $get_folder = /SHGetFolderPath.*/
        
        // 7.Crypto
        $crypt_acquire = /CryptAcquireContext.*/
        $crypt_create_hash = /CryptCreateHash.*/
        $crypt_hash_data = /CryptHashData.*/
        $crypt_encrypt = /CryptEncrypt.*/
        $crypt_decrypt = /CryptDecrypt.*/
        
        // 8.Hooks/Injection
        $set_hook = /SetWindowsHookEx.*/
        $create_remote = /CreateRemoteThread.*/
        $queue_apc = /NtQueueApcThread.*/
        $adjust_priv = /AdjustTokenPrivileges.*/
        
        // 9.Additional
        $delay_exec = /NtDelayExecution.*/
        $yield_exec = /NtYieldExecution.*/
        $create_mutex = /NtCreateMutant.*/
        $open_mutex = /NtOpenMutant.*/
        $create_event = /NtCreateEvent.*/
        $create_section = /NtCreateSection.*/
        $create_timer = /NtCreateTimer.*/
        $query_auid = /NtQueryInformationToken.*/

    condition:
        any of them
}