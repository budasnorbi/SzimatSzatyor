#include <iostream>
#include <string>
#include <WS2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

#include "ConsoleManager.h"
#include "HookEntryManager.h"
#include "HookManager.h"
#include <Shlwapi.h>
#include <Windows.h>
#include <vector>

using namespace std;

// static member initilization
volatile bool *ConsoleManager::_sniffingLoopCondition = NULL;

// needed to correctly shutdown the sniffer
HINSTANCE instanceDLL = NULL;
// true when a SIGINT occured
volatile bool isSigIntOccured = false;

// global access to the build number
WORD buildNumber = 0;

DWORD __fastcall SendHook(void * /* thisPTR */, void * /* dummy */, void * /* param1 */, void * /* param2 */);

// this send prototype fits with the client's one
typedef DWORD(__thiscall *SendProto)(void *, void *, void *);

// address of WoW's send function
DWORD sendAddress = 0;
// global storage for the "the hooking" machine code which
// hooks client's send function
BYTE machineCodeHookSend[JMP_INSTRUCTION_SIZE] = {0};
// global storage which stores the
// untouched first 5 bytes machine code from the client's send function
BYTE defaultMachineCodeSend[JMP_INSTRUCTION_SIZE] = {0};

// this function will be called when recv called in the client
DWORD __fastcall RecvHook(void * /* thisPTR */, void * /* dummy */, void * /* param1 */, void * /* param2 */, void * /* param3 */);

// this recv prototype fits with the client's one
typedef DWORD(__thiscall *RecvProto)(void *, void *, void *, void *);
// clients which has build number <= 8606 have different prototype
typedef DWORD(__thiscall *RecvProto8606)(void *, void *, void *);

// clients which has build number 18379 >=
typedef DWORD(__thiscall *RecvProto18379)(void *, void *, void *, void *, void *);

// address of WoW's recv function
DWORD recvAddress = 0;
// global storage for the "the hooking" machine code which
// hooks client's recv function
BYTE machineCodeHookRecv[JMP_INSTRUCTION_SIZE] = {0};
// global storage which stores the
// untouched first 5 bytes machine code from the client's recv function
BYTE defaultMachineCodeRecv[JMP_INSTRUCTION_SIZE] = {0};

// these are false if "hook functions" don't called yet
// and they are true if already called at least once
bool sendHookGood = false;
bool recvHookGood = false;

// basically this method controls what the sniffer should do
// pretty much like a "main method"
DWORD MainThreadControl(LPVOID /* param */);

// entry point of the DLL
BOOL APIENTRY DllMain(HINSTANCE instDLL, DWORD reason, LPVOID /* reserved */)
{
    // called when the DLL is being loaded into the
    // virtual address space of the current process (where to be injected)
    if (reason == DLL_PROCESS_ATTACH)
    {
        instanceDLL = instDLL;
        // disables thread notifications (DLL_THREAD_ATTACH, DLL_THREAD_DETACH)
        DisableThreadLibraryCalls(instDLL);

        // creates a thread to execute within the
        // virtual address space of the calling process (WoW)
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&MainThreadControl, NULL, 0, NULL);
    }
    // the DLL is being unloaded
    else if (reason == DLL_PROCESS_DETACH)
    {
        ConsoleManager::Destroy();
    }
    return TRUE;
}

DWORD MainThreadControl(LPVOID /* param */)
{
    // creates the console
    if (!ConsoleManager::Create(&isSigIntOccured))
    {
        FreeLibraryAndExitThread((HMODULE)instanceDLL, 0);
    }

    // inits the HookManager
    HookEntryManager::FillHookEntries();

    // is there any hooks?
    if (HookEntryManager::IsEmpty())
    {
        printf("There are no hooks.\n");
        printf("So the sniffer can't do anything useful.\n\n");
        system("pause");
        FreeLibraryAndExitThread((HMODULE)instanceDLL, 0);
    }

    // is there any invalid hooks?
    WORD invalidHookBuildNumber = HookEntryManager::GetFirstInvalidHookExp();
    if (invalidHookBuildNumber)
    {
        printf("The hook with the following build number is invalid: %hu\n\n",
               invalidHookBuildNumber);
        system("pause");
        FreeLibraryAndExitThread((HMODULE)instanceDLL, 0);
    }

    // gets the build number
    buildNumber = HookEntryManager::GetBuildNumberFromProcess();
    // error occured
    if (!buildNumber)
    {
        printf("Can't determine build number.\n\n");
        system("pause");
        FreeLibraryAndExitThread((HMODULE)instanceDLL, 0);
    }
    printf("Detected build number: %hu\n", buildNumber);

    // checks this build is supported or not
    if (!HookEntryManager::IsHookEntryExists(buildNumber))
    {
        printf("ERROR: This build number is not supported.\n\n");
        system("pause");
        FreeLibraryAndExitThread((HMODULE)instanceDLL, 0);
    }

    // path of the DLL
    char dllPath[MAX_PATH];
    // gets where is the DLL which injected into the client
    DWORD dllPathSize = GetModuleFileName((HMODULE)instanceDLL, dllPath, MAX_PATH);

    if (!dllPathSize)
    {
        printf("\nERROR: Can't get the injected DLL's location, ");
        printf("ErrorCode: %u\n\n", GetLastError());
        system("pause");
        FreeLibraryAndExitThread((HMODULE)instanceDLL, 0);
    }

    // removes the DLL name from the path
    PathRemoveFileSpec(dllPath);

    // "calculates" the path of the file which enables
    // the "user friendly" log format

    // get the base address of the current process
    DWORD baseAddress = (DWORD)GetModuleHandle(NULL);

    HookEntryManager::HookEntry const &
        hookEntry = HookEntryManager::GetHookEntry(buildNumber);

    // gets address of NetClient::Send2
    sendAddress = hookEntry.send2_AddressOffset;
    // plus the base address
    sendAddress += baseAddress;
    // hooks client's send function
    HookManager::Hook(sendAddress, (DWORD)SendHook, machineCodeHookSend, defaultMachineCodeSend);

    printf("Send is hooked.\n");

    // gets address of NetClient::ProcessMessage
    recvAddress = hookEntry.processMessage_AddressOffset;
    // plus the base address
    recvAddress += baseAddress;

    DWORD hookFunctionAddress = 0;
    // gets the expansion of the build number (hook)
    HookEntryManager::HOOK_WOW_EXP hookVersion = hookEntry.expansion;
    // selects the proper hook function
    // the selection is based on the expansion of the build
    switch (hookVersion)
    {
    case HookEntryManager::HOOK_WOW_EXP::EXP_CLASSIC:
    case HookEntryManager::HOOK_WOW_EXP::EXP_TBC:
    case HookEntryManager::HOOK_WOW_EXP::EXP_WLK:
    case HookEntryManager::HOOK_WOW_EXP::EXP_CATA:
    case HookEntryManager::HOOK_WOW_EXP::EXP_MOP:
        hookFunctionAddress = (DWORD)RecvHook;
        break;
    default:
        printf("Invalid hook expansion: %d\n\n", (int)hookVersion);
        system("pause");
        FreeLibraryAndExitThread((HMODULE)instanceDLL, 0);
        break;
    }

    // hooks client's recv function
    HookManager::Hook(recvAddress,
                      hookFunctionAddress,
                      machineCodeHookRecv,
                      defaultMachineCodeRecv);

    printf("Recv is hooked.\n");

    // loops until SIGINT (CTRL-C) occurs
    while (!isSigIntOccured)
        Sleep(50); // sleeps 50 ms to be nice

    // unhooks functions
    HookManager::UnHook(sendAddress, defaultMachineCodeSend);
    HookManager::UnHook(recvAddress, defaultMachineCodeRecv);

    // shutdowns the sniffer
    // note: after that DLL's entry point will be called with
    // reason DLL_PROCESS_DETACH
    FreeLibraryAndExitThread((HMODULE)instanceDLL, 0);
    return 0;
}

void sendBuffer(DWORD packetOpcode, DWORD buffer, DWORD packetSize, WORD initialReadOffset)
{
    if (packetSize == 0)
    {
        return;
    }

    WSAData data;
    WORD version = MAKEWORD(2, 2);

    int wsResult = WSAStartup(version, &data);
    if(wsResult != 0){
        return;
    }

    // Fill in a hint structure
    sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons(54000);
    inet_pton(AF_INET, "127.0.0.1", &server.sin_addr);

    // Create socket
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, 0);

    vector<char> byteArray;

    DWORD readOffset1 = initialReadOffset;
    for (DWORD i = 0; i < packetSize; ++i)
    {
        char hexData = *(char*)(buffer + readOffset1++);
        byteArray.push_back(hexData);
    }

    byteArray.resize(byteArray.size() - initialReadOffset);

    char b0 = (char)(packetOpcode & 0x000000ff);
    char b1 = (char)((packetOpcode & 0x0000ff00) >> 8);
    char b2 = (char)((packetOpcode & 0x00ff0000) >> 16);
    char b3 = (char)((packetOpcode & 0xff000000) >> 24);

    byteArray.insert(byteArray.begin(), b3);
    byteArray.insert(byteArray.begin(), b2);
    byteArray.insert(byteArray.begin(), b1);
    byteArray.insert(byteArray.begin(), b0);

    int sendResult = sendto(sock, byteArray.data(), byteArray.size(), 0, (sockaddr*)&server, sizeof(server));
    if (sendResult == SOCKET_ERROR)
    {
        return;
    }

    closesocket(sock);
    WSACleanup();
}

DWORD __fastcall SendHook(void *thisPTR, void * /* dummy */, void *param1, void *param2)
{
    WORD packetOpcodeSize = 4; // 4 bytes for all versions

    DWORD buffer = *(DWORD *)((DWORD)param1 + 4);
    DWORD packetOcode = *(DWORD *)buffer;              // packetOpcodeSize
    DWORD packetSize = *(DWORD *)((DWORD)param1 + 16); // totalLength, writePos

    WORD initialReadOffset = packetOpcodeSize;

    sendBuffer(packetOcode, buffer, packetSize, initialReadOffset);

    // unhooks the send function
    HookManager::UnHook(sendAddress, defaultMachineCodeSend);

    // now let's call client's function
    // so it can send the packet to the server
    DWORD returnValue = SendProto(sendAddress)(thisPTR, param1, param2);

    // hooks again to catch the next outgoing packets also
    HookManager::ReHook(sendAddress, machineCodeHookSend);

    if (!sendHookGood)
    {
        printf("Send hook is working.\n");
        sendHookGood = true;
    }

    return returnValue;
}

DWORD __fastcall RecvHook(void *thisPTR, void * /* dummy */, void *param1, void *param2, void *param3)
{
    DWORD buffer = *(DWORD *)((DWORD)param2 + 4);

    DWORD packetOcode = *(WORD*)buffer;

    DWORD packetSize = *(DWORD *)((DWORD)param2 + 16); // totalLength, writePos

    WORD initialReadOffset = 2;

    sendBuffer(packetOcode, buffer, packetSize, initialReadOffset);

    // unhooks the recv function
    HookManager::UnHook(recvAddress, defaultMachineCodeRecv);

    // calls client's function so it can processes the packet
    DWORD returnValue = 0;
    if (buildNumber <= WOW_TBC_8606)
    {
        returnValue = RecvProto8606(recvAddress)(thisPTR, param1, param2);
    }
    else
    {
        returnValue = RecvProto(recvAddress)(thisPTR, param1, param2, param3);
    }

    // hooks again to catch the next incoming packets also
    HookManager::ReHook(recvAddress, machineCodeHookRecv);

    if (!recvHookGood)
    {
        printf("Recv hook is working.\n");
        recvHookGood = true;
    }

    return returnValue;
}