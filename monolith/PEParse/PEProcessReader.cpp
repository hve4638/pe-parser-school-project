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
            m_pNtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(hModule, "NtQueryInformationProcess");
            if (m_pNtQueryInformationProcess != NULL) {

            }
        }
    };

    PEProcessReader::~PEProcessReader(void) {
        close();
    };

    void PEProcessReader::debug(tstring debugMessage) {
        OutputDebugStringT(debugMessage.c_str());
        OutputDebugStringT(_T("\n"));
    };

    void PEProcessReader::close(void) {
        m_processId = NULL;
        m_peBaseAddress = NULL;
        memset(&m_peb, 0, sizeof(PEB));
        if (m_processHandle != NULL) {
            CloseHandle(m_processHandle);
            m_processHandle = NULL;
        }
    };

    BOOL PEProcessReader::open(DWORD pid, const TCHAR* pfilePath) {
        BOOL result = FALSE;

        if (pid > 0x4) {
            m_processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
            if (m_processHandle != NULL) {
                result = parseImageBaseAddress();
                if (result) {
                    m_processId = pid;
                }
                else {
                    // Image Base Address�� ���� ���� ��� ���з� ó��(���� �ʱ�ȭ)
                    close();
                    debug(_T("Open process fail : get image base address fail"));
                }
            }
            else {
                debug(format(_T("Open process fail : 0x{:x}"), (DWORD)GetLastError()));
            }
        }
        return result;
    };

    LPVOID PEProcessReader::getBaseAddress(void) {
        return m_peBaseAddress;
    };

    tstring PEProcessReader::getFilePath(void) {
        return m_peFilePath;
    };

    // PE �м� �������� ����� ���ڿ��� �о���̴� �Լ�
    // ���μ��� �޸𸮸� �о�� �ϴµ� ���ڿ��� ũ�⸦ �� �� ���� ������ 1����Ʈ �� ����
    tstring PEProcessReader::getPEString(ULONGLONG rva) {
        SIZE_T readLength = 0;
        BYTE byteChar[2] = { 0, };
        ULONGLONG curOffset = rva;
        string src;
        do {
            // �� ����Ʈ�� ���ڿ��� ����
            if (readData(curOffset, &byteChar, sizeof(BYTE)) >= 0) {
                src.append((char*)byteChar);
                curOffset++;
            }
        } while (byteChar[0] != 0x0);
        return (tstring().assign(src.begin(), src.end()));
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
                debugPrint(format(_T("ReadProcessMemory fail : 0x{:x}, 0x{:x}"), (DWORD)GetLastError(), rva));
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
                debugPrint(format(_T("ReadProcessMemory fail : 0x{:x}, 0x{:x}"), (DWORD)GetLastError(), rva));
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

        // ���� �ʱ�ȭ
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
                // Image Base Address�� ���� ���� ��� ���з� ó��(���� �ʱ�ȭ)
                close();
                debugPrint(_T("Create process fail : get image base address fail"));
            }
        }
        else {
            debugPrint(format(_T("Create process fail : 0x{:x}"), (DWORD)GetLastError()));
        }
        return result;
    };

    // CreateProcess�� ������ ��쿡�� DLL �ε����̱� ������ ��� �� �� ����
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
            debugPrint(_T("Get loaded dlls fail - PEB.Ldr is NULL."));
        }
        else if (ReadProcessMemory(m_processHandle, m_peb.Ldr, &pebLdrData, sizeof(PEB_LDR_DATA), &readData)) {
            // CONTAINING_RECORD ��ũ��
            // ù��° ������ Address���� ����˰� �ִ� ����ü �ʵ����� ����Ʈ�� �Է��ϰ� �ι�° ���ڴ� �˰����ϴ� ����ü ������ ����° ���ڴ� ù��° �˰��ִ� ����Ʈ �ּ��� ����ü ������ �ʵ庯���� �־���
            // �׷��� �� ��°�� �Է��ߴ� ����ü ������ ����Ʈ �ּҸ� ������
            pFirstListEntry = CONTAINING_RECORD(pebLdrData.InMemoryOrderModuleList.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
            pListEntry = pFirstListEntry;
            if (pListEntry != NULL) {
                do {
                    if (ReadProcessMemory(m_processHandle, pListEntry, &ldrDataTable, sizeof(LDR_DATA_TABLE_ENTRY), &readData)) {
                        if ((ULONGLONG)ldrDataTable.DllBase == 0x0) {
                            pListEntry = NULL;
                        }
                        else {
                            // �� ó�� �׸��� ���μ��� �ڽ�
                            if (ReadProcessMemory(m_processHandle, ldrDataTable.FullDllName.Buffer, dllNameBuffer, ldrDataTable.FullDllName.Length, &readData)) {
                                //copyStringToTString();
                                if (sizeof(TCHAR) == sizeof(char)) {
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
};
