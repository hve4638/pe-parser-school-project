#pragma once
#include "IPEReader.h"
#include <winternl.h>

namespace PEParse {
    typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(IN HANDLE ProcessHandle, IN PROCESSINFOCLASS ProcessInformationClass,
        OUT PVOID ProcessInformation, IN ULONG ProcessInformationLength, OUT PULONG ReturnLength OPTIONAL);

    class PEProcessReader : public IPEReader {
    private:
        DWORD m_processId = NULL;
        HANDLE m_processHandle = NULL;
        LPVOID m_peBaseAddress = NULL;
        tstring m_peFilePath;
        PEB m_peb = { 0, };
        pNtQueryInformationProcess m_pNtQueryInformationProcess = NULL;

    private:
        BOOL parseImageBaseAddress(void);

    public:
        PEProcessReader();
        ~PEProcessReader() override;
        void close(void) override;
        BOOL open(DWORD pid, const TCHAR* pfilePath) override;
        tstring getPEString(PEPOS rva) override;
        tstring getPEStringNoBase(PEPOS rva) override;
        SSIZE_T readData(PEPOS rva, LPVOID bufferAddress, SIZE_T bufferSize) override;
        SSIZE_T readDataNoBase(PEPOS rva, LPVOID bufferAddress, SIZE_T bufferSize) override;
        LPVOID getBaseAddress() override;
        tstring getFilePath() override;
        QWORD getRAW(QWORD rva) override;

    public:
        BOOL open(DWORD pid);
        BOOL createProcess(tstring filePath);
        LoadedDllsInfo getLoadedDlls(void);
    };

};


