#pragma once

#include "PEProcessReader.h"
#include "PEUtils.h"
#include <iostream>
#include <format>

using namespace std;
using namespace PEUtils;

// CONTAINING_RECORD 매크로
// 첫번째 인자인 Address에는 현재알고 있는 구조체 필드중의 포인트를 입력하고 두번째 인자는 알고자하는 구조체 변수를 세번째 인자는 첫번째 알고있는 포인트 주소의 구조체 내에서 필드변수를 넣어줌
// 그러면 두 번째에 입력했던 구조체 변수의 포인트 주소를 리턴함

namespace PEParse {
    BOOL PEProcessReader::parseImageBaseAddress() {
        NTSTATUS status = 0;
        SIZE_T readSize = 0;
        PROCESS_BASIC_INFORMATION processBasicInformation = { 0, };

        if (m_processHandle == NULL || m_pNtQueryInformationProcess == NULL) {
            return FALSE;
        }
        else {
            status = m_pNtQueryInformationProcess(m_processHandle, ProcessBasicInformation, &processBasicInformation, sizeof(PROCESS_BASIC_INFORMATION), (DWORD*)&readSize);
            if (!NT_SUCCESS(status)) {
                return FALSE;
            }
            else if (processBasicInformation.PebBaseAddress == NULL) {
                return FALSE;
            }
            else if (!ReadProcessMemory(m_processHandle, processBasicInformation.PebBaseAddress, &m_peb, sizeof(PEB), &readSize)) {
                m_logger << LogLevel::ERR;
                m_logger << ErrorLogInfo(_T("ReadProcessMemory fail")) << NL;
                return FALSE;
            }
            else {
                m_peBaseAddress = m_peb.Reserved3[1]; // 프로세스의 ImageBaseAddress가 저장된 필드
                if (m_peBaseAddress == NULL) {
                    m_logger << LogLevel::ERR;
                    m_logger << ErrorLogInfo(_T("Get ImageBaseAddress fail")) << NL;
                    return FALSE;
                }
                else {
                    m_logger << LogLevel::DEBUG;
                    m_logger << format(_T("Process ImageBaseAddress : 0x{:x}"), (ULONGLONG)m_peBaseAddress) << NL;

                    parsePEFilePath();                    
                    return TRUE;
                }
            }
        }
    };

    BOOL PEProcessReader::parsePEFilePath() {
        PEB_LDR_DATA pebLdrData = { 0, };
        PLDR_DATA_TABLE_ENTRY firstListEntry = NULL;
        LDR_DATA_TABLE_ENTRY ldrDataTable = { 0, };
        BYTE moduleNameBuffer[MAX_PATH * 4] = { 0, };
        SIZE_T readSize = 0; 

        if (ReadProcessMemory(m_processHandle, m_peb.Ldr, &pebLdrData, sizeof(PEB_LDR_DATA), &readSize)) {
            auto pInMemoryOrderLinks = pebLdrData.InMemoryOrderModuleList.Flink;
            // pInMemoryOrderLinks는 LDR_DATA_TABLE_ENTRY.InMemoryOrderLinks 필드의 주소
            // 역산하여 LDR_DATA_TABLE_ENTRY 구조체의 첫 주소를 가져온다
            firstListEntry = CONTAINING_RECORD(pInMemoryOrderLinks, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

            if (firstListEntry == NULL) {}
            else if (ReadProcessMemory(m_processHandle, firstListEntry, &ldrDataTable, sizeof(LDR_DATA_TABLE_ENTRY), &readSize)) {}
            else if ((ULONGLONG)ldrDataTable.DllBase == NULL) {}
            else {
                // 맨 처음 항목이 프로세스 자신
                if (ReadProcessMemory(m_processHandle, ldrDataTable.FullDllName.Buffer, moduleNameBuffer, ldrDataTable.FullDllName.Length, &readSize)) {
                    if (CHAR_IS_TCHAR) {
                        wstring modulePath = (PWSTR)moduleNameBuffer;
                        m_peFilePath.assign(modulePath.begin(), modulePath.end());
                    }
                    else {
                        m_peFilePath = (PWSTR)moduleNameBuffer;
                    }

                    m_logger << LogLevel::DEBUG;
                    m_logger << format(_T("Module : 0x{:x}, {:s}"), (ULONGLONG)ldrDataTable.DllBase, m_peFilePath) << NL;
                }
            }
        }
        return TRUE;
    }
}