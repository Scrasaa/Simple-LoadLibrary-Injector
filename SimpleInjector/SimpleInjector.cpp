#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <sstream>
#include <Windows.h>
#include <iostream>

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
    
    uintptr_t processID = 0;

    while (!processID)
    {
        processID = GetProcessID(szExe.c_str());
        Sleep(50);
    }

    std::cout << "ProcessID found: " << processID << "...\n";
    std::cout << "Process \"" << szExe << "\" found initializing injection...\n";
    std::cout << "Opening process...\n";

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

