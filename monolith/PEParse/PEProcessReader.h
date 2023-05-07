#pragma once
#include "IPEReader.h"
#include <winternl.h>
#include "Logger.h"

using namespace LogUtils;

namespace PEParse {
    typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(IN HANDLE ProcessHandle, IN PROCESSINFOCLASS ProcessInformationClass,
        OUT PVOID ProcessInformation, IN ULONG ProcessInformationLength, OUT PULONG ReturnLength OPTIONAL);

    class PEProcessReader : public IPEReader {
        DWORD m_processId = NULL;
        HANDLE m_processHandle = NULL;
        LPVOID m_peBaseAddress = NULL;
        tstring m_peFilePath;
        Logger m_logger = { LogLevel::ALL, LogDirection::DEBUGVIEW };
        PEB m_peb = { 0, };
        pNtQueryInformationProcess m_pNtQueryInformationProcess = NULL;

        BOOL parseImageBaseAddress();
        BOOL parsePEFilePath();
    public:
        PEProcessReader();
        ~PEProcessReader() override;
        void close(void) override;
        BOOL open(DWORD pid, const TCHAR* pfilePath) override;
        tstring getPEString(QWORD rva) override;
        tstring getPEStringNoBase(QWORD rva) override;
        SSIZE_T readData(QWORD rva, LPVOID bufferAddress, SIZE_T bufferSize) override;
        SSIZE_T readDataNoBase(QWORD rva, LPVOID bufferAddress, SIZE_T bufferSize) override;
        LPVOID getBaseAddress() override;
        tstring getFilePath() override;
        QWORD getRAW(QWORD rva) override;

        BOOL open(DWORD pid);
        BOOL createProcess(tstring filePath);
        LoadedDllsInfo getLoadedDlls(void);
    };

};


