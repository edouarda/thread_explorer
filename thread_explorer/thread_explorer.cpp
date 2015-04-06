
/*

Copyright (c) 2015, Edouard A.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <Winternl.h>

#include <iostream>
#include <cstdint>

#include <memory>

typedef struct {
  HANDLE UniqueProcess;
  HANDLE UniqueThread;
} CLIENT_ID;

typedef LONG       KPRIORITY;

typedef struct _THREAD_BASIC_INFORMATION
{
    NTSTATUS ExitStatus;
    PTEB TebBaseAddress;
    CLIENT_ID ClientId;
    ULONG_PTR AffinityMask;
    KPRIORITY Priority;
    LONG BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

typedef NTSTATUS ( WINAPI *NQIT )( HANDLE, LONG, PVOID, ULONG, PULONG );

NQIT __ntqit = reinterpret_cast<NQIT>(GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationThread"));

std::uint64_t GetThreadAffinityMask(DWORD dwThreadId)
{
    // will close handle when we leave the scope, C++ 11 magic ;)
    std::shared_ptr<void> thread_handle(OpenThread(THREAD_QUERY_INFORMATION, FALSE, dwThreadId), &::CloseHandle);

    if (!thread_handle)
    {
        return 0ull;
    }

    THREAD_BASIC_INFORMATION tbi;

    ZeroMemory(&tbi, sizeof(tbi));

    NTSTATUS result = __ntqit(thread_handle.get(), 
        static_cast<THREADINFOCLASS>(0), // ThreadBasicInformation, undocumented
        &tbi,
        sizeof(tbi),
        nullptr);

    return !result ? static_cast<std::uint64_t>(tbi.AffinityMask) : 0ull;
}

bool ListProcessThreads(DWORD dwOwnerPID) 
{  
    // Take a snapshot of all running threads  
    std::shared_ptr<void> hThreadSnap(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0), &::CloseHandle); 
    if (hThreadSnap.get() == INVALID_HANDLE_VALUE) 
        return false;
 
    THREADENTRY32 te32; 

    // Fill in the size of the structure before using it. 
    te32.dwSize = sizeof(THREADENTRY32); 
 
    // Retrieve information about the first thread,
    // and exit if unsuccessful
    if(!Thread32First(hThreadSnap.get(), &te32)) 
    {
        wprintf(L"Could not print first thread: %d\n", GetLastError());
        return false;
    }

    int threads_count = 0;

    // Now walk the thread list of the system,
    // and display information about each thread
    // associated with the specified process
    do 
    { 
        if (te32.th32OwnerProcessID == dwOwnerPID)
        {
            wprintf(L"    - thread id %08d - priority %02d (delta %02d) - affinity 0x%08x\n", te32.th32ThreadID, te32.tpBasePri, te32.tpDeltaPri, GetThreadAffinityMask(te32.th32ThreadID));
            ++threads_count;
        }
    } 
    while(Thread32Next(hThreadSnap.get(), &te32 ));

    wprintf(L"Found %d threads in PID %d\n", threads_count, dwOwnerPID);
    
    return true;
}

int wmain(int argc, wchar_t *argv[])
{
    if (argc < 2)
    {
        wprintf(L"Please specify PID to scan!\n");
        return EXIT_FAILURE;
    }

    if (!__ntqit)
    {
        wprintf(L"Missing NtQueryInformationThread function\n");
        return EXIT_FAILURE;
    }

    DWORD pid = _wtoi(argv[1]);

    wprintf(L"Listing threads in PID %d\n", pid);

    if (!ListProcessThreads(pid))
    {
        wprintf(L"could not list threads for PID %d\n", pid);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;    
}