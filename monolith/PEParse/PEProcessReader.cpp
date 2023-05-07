#pragma once

#include "PEProcessReader.h"
#include "PEUtils.h"
#include <iostream>
#include <format>

using namespace std;
using namespace PEUtils;

namespace PEParse {

    PEProcessReader::PEProcessReader() {
        HMODULE hModule = GetModuleHandle(_T("ntdll.dll"));

        if (hModule != NULL) {
            // ntdll.dll 에서 NtQueryInformationProcess 함수를 동적으로 가져옴
            m_pNtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(hModule, "NtQueryInformationProcess");
            if (m_pNtQueryInformationProcess != NULL) {

            }
        }
    };

    PEProcessReader::~PEProcessReader() {
        close();
    };

    void PEProcessReader::close() {
        m_processId = NULL;
        m_peBaseAddress = NULL;
        memset(&m_peb, 0, sizeof(PEB));
        if (m_processHandle != NULL) {
            CloseHandle(m_processHandle);
            m_processHandle = NULL;
        }
    };

    BOOL PEProcessReader::open(DWORD pid, const TCHAR* pfilePath) {
        if (pid <= 0x4) {
            return FALSE;
        }

        m_processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);

        if (m_processHandle == NULL) {
            m_logger << LogLevel::ERR;
            m_logger << ErrorLogInfo(_T("Open process fail")) << NL;
            return FALSE;
        }
        else {
            if (parseImageBaseAddress()) {
                m_processId = pid;
                return TRUE;
            }
            else {
                // Image Base Address를 얻지 못한 경우 실패
                close();

                m_logger << LogLevel::ERR;
                m_logger << ErrorLogInfo(_T("Open process fail : fail to get ImageBaseAddress ")) << NL;
                return FALSE;
            }
        }

        return FALSE;
    };

    LPVOID PEProcessReader::getBaseAddress(void) {
        return m_peBaseAddress;
    };

    tstring PEProcessReader::getFilePath(void) {
        return m_peFilePath;
    };

    tstring PEProcessReader::getPEString(ULONGLONG rva) {
        BYTE bytes[2] = { 0, };
        ULONGLONG offset = rva;
        string src;

        while (1) {
            // 문자열의 길이를 알 수 없기 때문에 한문자씩 읽어들임
            if (readData(offset, &bytes, sizeof(BYTE)) >= 0) {
                src.append((char*)bytes);
                offset++;
            }

            if (bytes[0] != '\0') break;
        }

        if (CHAR_IS_TCHAR) {
            return tstring().assign(src.begin(), src.end());
        }
        else {
            // UTF-8로 저장된 문자열을 WCHAR로 변환
            int bufferLen = MultiByteToWideChar(CP_UTF8, 0, reinterpret_cast<LPCCH>(src.data()), -1, NULL, 0);

            TCHAR* buffer = new TCHAR[bufferLen];
            MultiByteToWideChar(CP_UTF8, 0, reinterpret_cast<LPCCH>(src.data()), -1, buffer, bufferLen);

            tstring dest = buffer;
            delete[] buffer;

            return dest;
        }
    };

    tstring PEProcessReader::getPEStringNoBase(ULONGLONG rva) {
        //WIP
        return getPEString(rva);
    };

    SSIZE_T PEProcessReader::readData(ULONGLONG rva, LPVOID bufferAddress, SIZE_T bufferSize) {
        if (m_processHandle == NULL) {
            return -1;
        }
        else {
            BOOL result;
            SIZE_T readLength = 0;
            result = ReadProcessMemory(m_processHandle, (LPCVOID)((ULONGLONG)m_peBaseAddress + rva), bufferAddress, bufferSize, &readLength);

            if (!result) {
                m_logger << LogLevel::DEBUG;
                m_logger << ErrorLogInfo(format(_T("ReadProcessMemory fail (RVA : 0x{:x})"), rva)) << NL;
                return -1;
            }
            else {
                return readLength;
            }
        }
    };

    SSIZE_T PEProcessReader::readDataNoBase(ULONGLONG rva, LPVOID bufferAddress, SIZE_T bufferSize) {   
        if (m_processHandle == NULL) {
            return -1;
        }
        else {
            BOOL result;
            SIZE_T readLength = 0;
            result = ReadProcessMemory(m_processHandle, (LPCVOID)(rva), bufferAddress, bufferSize, &readLength);

            if (!result) {
                m_logger << LogLevel::ALL;
                m_logger << ErrorLogInfo(format(_T("ReadProcessMemory fail (RVA : 0x{:x})"), rva)) << NL;
                return -1;
            }
            else {
                return readLength;
            }
        }
    };

    BOOL PEProcessReader::createProcess(tstring filePath) {
        BOOL result = FALSE;
        STARTUPINFO si;
        PROCESS_INFORMATION pi;

        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        ZeroMemory(&pi, sizeof(pi));

        // 변수 초기화
        close();

        // Start the child process. 
        if (CreateProcess(NULL,       // No module name (use command line)
            (LPTSTR)filePath.c_str(), // Command line
            NULL,                     // Process handle not inheritable
            NULL,                     // Thread handle not inheritable
            FALSE,                    // Set handle inheritance to FALSE
            0,                        // No creation flags
            NULL,                     // Use parent's environment block
            NULL,                     // Use parent's starting directory 
            &si,                      // Pointer to STARTUPINFO structure
            &pi))                     // Pointer to PROCESS_INFORMATION structure
        {
            m_processId = pi.dwProcessId;
            m_processHandle = pi.hProcess;

            result = parseImageBaseAddress();
            if (!result) {
                // Image Base Address를 얻지 못한 경우 실패로 처리(변수 초기화)
                close();
                m_logger << LogLevel::ERR;
                m_logger << ErrorLogInfo(_T("Create process fail : get image base address fail")) << NL;
            }
        }
        else {
            m_logger << LogLevel::ERR;
            m_logger << ErrorLogInfo(_T("Create process fail")) << NL;
        }
        return result;
    };

    // CreateProcess로 생성한 경우에는 DLL 로딩전이기 때문에 출력 할 수 없음
    LoadedDllsInfo PEProcessReader::getLoadedDlls(void){
        SIZE_T readData = 0;
        tstring dllPath;
        LoadedDllsInfo loadedDlls;
        PEB_LDR_DATA pebLdrData = { 0, };
        BYTE dllNameBuffer[MAX_PATH * 4] = { 0, };
        PLDR_DATA_TABLE_ENTRY pFirstListEntry = NULL;
        PLDR_DATA_TABLE_ENTRY pListEntry = NULL;
        LDR_DATA_TABLE_ENTRY ldrDataTable = { 0, };
        /*
        m_peBaseAddress != NULL && m_peb.Ldr != NULL
        */
        
        if (m_peBaseAddress == NULL || m_peb.Ldr == NULL) {
            m_logger << LogLevel::ERR;
            m_logger << ErrorLogInfo(_T("Get loaded dlls fail - PEB.Ldr is NULL.")) << NL;
        }
        else if (ReadProcessMemory(m_processHandle, m_peb.Ldr, &pebLdrData, sizeof(PEB_LDR_DATA), &readData)) {
            // CONTAINING_RECORD 매크로
            // 첫번째 인자인 Address에는 현재알고 있는 구조체 필드중의 포인트를 입력하고 두번째 인자는 알고자하는 구조체 변수를 세번째 인자는 첫번째 알고있는 포인트 주소의 구조체 내에서 필드변수를 넣어줌
            // 그러면 두 번째에 입력했던 구조체 변수의 포인트 주소를 리턴함
            pFirstListEntry = CONTAINING_RECORD(pebLdrData.InMemoryOrderModuleList.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
            pListEntry = pFirstListEntry;
            if (pListEntry != NULL) {
                do {
                    if (ReadProcessMemory(m_processHandle, pListEntry, &ldrDataTable, sizeof(LDR_DATA_TABLE_ENTRY), &readData)) {
                        if ((ULONGLONG)ldrDataTable.DllBase == 0x0) {
                            pListEntry = NULL;
                        }
                        else {
                            // 맨 처음 항목이 프로세스 자신
                            if (ReadProcessMemory(m_processHandle, ldrDataTable.FullDllName.Buffer, dllNameBuffer, ldrDataTable.FullDllName.Length, &readData)) {
                                //copyStringToTString();
                                if (CHAR_IS_TCHAR) {
                                    wstring modulePath = (PWSTR)dllNameBuffer;
                                    dllPath.assign(modulePath.begin(), modulePath.end());
                                }
                                else {
                                    dllPath = (PWSTR)dllNameBuffer;
                                }
                                LoadedDllInfo dllInfo;
                                dllInfo.DllBase = (QWORD)ldrDataTable.DllBase;
                                dllInfo.Path = dllPath;

                                loadedDlls.push_back(dllInfo);
                            }
                            pListEntry = CONTAINING_RECORD(ldrDataTable.InMemoryOrderLinks.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
                        }
                    }
                    else {
                        pListEntry = NULL;
                    }
                    memset(&ldrDataTable, 0, sizeof(LDR_DATA_TABLE_ENTRY));
                    memset(&dllNameBuffer, 0, sizeof(dllNameBuffer));
                } while ((pListEntry != NULL) && (pListEntry != pFirstListEntry));
            }
        }
        return loadedDlls;
    }

    QWORD PEProcessReader::getRAW(QWORD rva) {
        return rva;
    }
};
