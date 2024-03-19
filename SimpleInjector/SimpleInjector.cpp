#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <sstream>
#include <Windows.h>
#include <iostream>

// Function to load a DLL into the memory space of a target process
bool ManualMapInject(DWORD processId, const char* dllPath) {
    // Open the target process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (hProcess == NULL) {
        std::cout << "Failed to open the target process. Error code: " << GetLastError() << std::endl;
        return false;
    }

    // Allocate memory in the target process for the DLL path
    LPVOID dllPathAddr = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (dllPathAddr == NULL) {
        std::cout << "Failed to allocate memory in the target process. Error code: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    // Write the DLL path to the allocated memory in the target process
    if (!WriteProcessMemory(hProcess, dllPathAddr, dllPath, strlen(dllPath) + 1, NULL)) {
        std::cout << "Failed to write the DLL path to the target process. Error code: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, dllPathAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Get the address of the LoadLibraryA function in the target process
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32 == NULL) {
        std::cout << "Failed to get the address of kernel32.dll in the target process. Error code: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, dllPathAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    LPVOID loadLibraryAddr = GetProcAddress(hKernel32, "LoadLibraryA");
    if (loadLibraryAddr == NULL) {
        std::cout << "Failed to get the address of LoadLibraryA in the target process. Error code: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, dllPathAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Create a remote thread in the target process to execute the LoadLibraryA function with the DLL path as the argument
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, dllPathAddr, 0, NULL);
    if (hThread == NULL) {
        std::cout << "Failed to create a remote thread in the target process. Error code: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, dllPathAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Wait for the remote thread to finish
    WaitForSingleObject(hThread, INFINITE);

    // Clean up
    VirtualFreeEx(hProcess, dllPathAddr, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return true;
}

uintptr_t GetProcessID(const char* szProcessName)
{
    uintptr_t processID = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnap != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 pe32{};
        pe32.dwSize = sizeof(pe32);

        if (Process32First(hSnap, &pe32))
        {
            do
            {
                if (!_strcmpi(szProcessName, (const char*)pe32.szExeFile))
                {
                    processID = pe32.th32ProcessID;
                    break;
                }

            } while (Process32Next(hSnap, &pe32));
        }
    }

    if (hSnap)
        CloseHandle(hSnap);

    return processID;
}

void inject()
{
    std::string szDllPath = "";
    std::cout << "Enter the dll path: "; std::cin >> szDllPath; std::cout << '\n';

    std::string szExe = "";
    std::cout << "Enter your target process name: "; std::cin >> szExe;

    int iInput = 0;
    bool bManualMapping = false;

    uintptr_t processID = 0;

    while (!processID)
    {
        processID = GetProcessID(szExe.c_str());
        Sleep(50);
    }

    std::cout << "ProcessID found: " << processID << "...\n";
    std::cout << "Process \"" << szExe << "\" found initializing injection...\n";
    std::cout << "Opening process...\n";
    std::cout << "Do you want to use 1. manual mapping or 2. standard LoadLibrary injection? (1/2): "; std::cin >> iInput; std::cout << '\n';

    if (iInput == 1) {
        ManualMapInject(processID, szDllPath.c_str());
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, processID);

    if (hProcess && hProcess != INVALID_HANDLE_VALUE && iInput == 2)
    {   
        void* pLoc = VirtualAllocEx(hProcess, 0, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        std::cout << "Allocating memory...\n";

        if (pLoc)
            WriteProcessMemory(hProcess, pLoc, szDllPath.c_str(), szDllPath.length() + 1, NULL);

        std::cout << "Writing to memory...\n";

        HANDLE hThread = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, pLoc, 0, 0);

        std::cout << "Creating RemoteThread...\n";

        if (hThread)
            CloseHandle(hThread);

        std::cout << "Closing Thread Handle...\n";
    }

    std::cout << "Successfully injected!\n";

    if (hProcess)
        CloseHandle(hProcess);

    std::cout << "Closing Process Handle...\n";
}

int main()
{
    bool bExit = false;

    while (!bExit)
    {
        inject();
        std::cout << "Inject again? y/n ?\n";
        char cInp;

        std::cin >> cInp;

        if (cInp != 'y' && cInp != 'Y')
            bExit = true;

        Sleep(100);
    }

    std::cout << "Ending Injection!\n";

    return 0;
}

