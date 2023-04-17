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
                // ���μ����� Image Base Address�� ����Ǿ� �ִ� �ʵ�
                // OS ���������� ����Ѵٰ� �Ǿ� �־ ���Ŀ��� ������� ���� �� ����
                // (ToolHelp32 API�� ���ؼ� ���ϴ� ����� ����)
                m_peBaseAddress = m_peb.Reserved3[1];
                if (m_peBaseAddress == NULL) {
                    debugPrint(format(_T("Get image base address fail : 0x{:x}"), (DWORD)GetLastError()));
                    return FALSE;
                }
                else {
                    debugPrint(format(_T("Process image base address : 0x{:x}"), (ULONGLONG)m_peBaseAddress));

                    if (ReadProcessMemory(m_processHandle, m_peb.Ldr, &pebLdrData, sizeof(PEB_LDR_DATA), &readData)) {
                        // CONTAINING_RECORD ��ũ��
                        // ù��° ������ Address���� ����˰� �ִ� ����ü �ʵ����� ����Ʈ�� �Է��ϰ� �ι�° ���ڴ� �˰����ϴ� ����ü ������ ����° ���ڴ� ù��° �˰��ִ� ����Ʈ �ּ��� ����ü ������ �ʵ庯���� �־���
                        // �׷��� �� ��°�� �Է��ߴ� ����ü ������ ����Ʈ �ּҸ� ������
                        pFirstListEntry = CONTAINING_RECORD(pebLdrData.InMemoryOrderModuleList.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
                        if (pFirstListEntry != NULL) {
                            if (ReadProcessMemory(m_processHandle, pFirstListEntry, &ldrDataTable, sizeof(LDR_DATA_TABLE_ENTRY), &readData)) {
                                if ((ULONGLONG)ldrDataTable.DllBase != 0x0) {
                                    // �� ó�� �׸��� ���μ��� �ڽ�
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