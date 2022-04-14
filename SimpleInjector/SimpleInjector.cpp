#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <sstream>

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

int main()
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

    std::cout << "Process \"" << szExe << "\" found initializing injection...\n";

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, processID);

    if (hProcess && hProcess != INVALID_HANDLE_VALUE)
    {
        void* pLoc = VirtualAllocEx(hProcess, 0, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (pLoc)
            WriteProcessMemory(hProcess, pLoc, szDllPath.c_str(), szDllPath.length() + 1, NULL);

        HANDLE hThread = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, pLoc, 0, 0);

        if (hThread)
            CloseHandle(hThread);
    }

    std::cout << "Successfully injected!\n";

    if (hProcess)
        CloseHandle(hProcess);
  
    std::cout << "Ending Injection!\n";

    return 0;
}

