#pragma once

#include "PEProcessReader.h"
#include "PEUtils.h"
#include <iostream>
#include <format>

using namespace std;
using namespace PEUtils;

namespace PEParse {

    BOOL PEProcessReader::parseImageBaseAddress(void)
    {
        BOOL result = FALSE;
        NTSTATUS status = 0;
        HANDLE procHeap = NULL;
        SIZE_T readData = 0;
        PROCESS_BASIC_INFORMATION processBasicInformation = { 0, };
        BYTE moduleNameBuffer[MAX_PATH * 4] = { 0, };
        PEB_LDR_DATA pebLdrData = { 0, };
        PLDR_DATA_TABLE_ENTRY pFirstListEntry = NULL;
        LDR_DATA_TABLE_ENTRY ldrDataTable = { 0, };

        if (m_processHandle == NULL || m_pNtQueryInformationProcess == NULL) {
            return FALSE;
        }
        else {
            status = m_pNtQueryInformationProcess(m_processHandle, ProcessBasicInformation, &processBasicInformation, sizeof(PROCESS_BASIC_INFORMATION), (DWORD*)&readData);
            if (!NT_SUCCESS(status)) {
                return FALSE;
            }
            else if (processBasicInformation.PebBaseAddress == NULL) {
                return FALSE;
            }
            else if (!ReadProcessMemory(m_processHandle, processBasicInformation.PebBaseAddress, &m_peb, sizeof(PEB), &readData)) {
                debugPrint(format(_T("ReadProcessMemory fail : 0x{:x}"), (DWORD)GetLastError()));
                return FALSE;
            }
            else {
                // 프로세스의 Image Base Address가 저장되어 있는 필드
                // OS 내부적으로 사용한다고 되어 있어서 향후에는 사용하지 못할 수 있음
                // (ToolHelp32 API를 통해서 구하는 방법도 있음)
                m_peBaseAddress = m_peb.Reserved3[1];
                if (m_peBaseAddress == NULL) {
                    debugPrint(format(_T("Get image base address fail : 0x{:x}"), (DWORD)GetLastError()));
                    return FALSE;
                }
                else {
                    debugPrint(format(_T("Process image base address : 0x{:x}"), (ULONGLONG)m_peBaseAddress));

                    if (ReadProcessMemory(m_processHandle, m_peb.Ldr, &pebLdrData, sizeof(PEB_LDR_DATA), &readData)) {
                        // CONTAINING_RECORD 매크로
                        // 첫번째 인자인 Address에는 현재알고 있는 구조체 필드중의 포인트를 입력하고 두번째 인자는 알고자하는 구조체 변수를 세번째 인자는 첫번째 알고있는 포인트 주소의 구조체 내에서 필드변수를 넣어줌
                        // 그러면 두 번째에 입력했던 구조체 변수의 포인트 주소를 리턴함
                        pFirstListEntry = CONTAINING_RECORD(pebLdrData.InMemoryOrderModuleList.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
                        if (pFirstListEntry != NULL) {
                            if (ReadProcessMemory(m_processHandle, pFirstListEntry, &ldrDataTable, sizeof(LDR_DATA_TABLE_ENTRY), &readData)) {
                                if ((ULONGLONG)ldrDataTable.DllBase != 0x0) {
                                    // 맨 처음 항목이 프로세스 자신
                                    if (ReadProcessMemory(m_processHandle, ldrDataTable.FullDllName.Buffer, moduleNameBuffer, ldrDataTable.FullDllName.Length, &readData)) {
                                        if (sizeof(TCHAR) == sizeof(char)) {
                                            wstring modulePath = (PWSTR)moduleNameBuffer;
                                            m_peFilePath.assign(modulePath.begin(), modulePath.end());
                                        }
                                        else {
                                            m_peFilePath = (PWSTR)moduleNameBuffer;
                                        }
                                        debugPrint(format(_T("Module : 0x{:x}, {:s}"), (ULONGLONG)ldrDataTable.DllBase, m_peFilePath));
                                    }
                                }
                            }
                        }
                    }
                    result = TRUE;
                    return TRUE;
                }
            }
        }
        return result;
    };


}