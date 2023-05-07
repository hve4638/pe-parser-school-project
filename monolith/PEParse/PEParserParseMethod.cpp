#pragma once
#include <format>
#include "PEParser.h"
#include "PEFileReader.h"
#include "PEUtils.h"
#include "ReserveDelete.h"

using namespace std;
using namespace PEUtils;

namespace PEParse {
    BOOL PEParser::parseDosHeader() {
        if (m_peReader->readData(0x0, &m_peStruct->dosHeader, sizeof(IMAGE_DOS_HEADER)) < 0) {
            m_logger << LogLevel::ERR;
            m_logger << ErrorLogInfo(_T("Error: Fail to read DOS header")) << NL;

            return FALSE;
        }
        else if (m_peStruct->dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
            m_logger << LogLevel::ERR;
            m_logger << ErrorLogInfo(_T("Error: Invalid DOS header signature")) << NL;

            return FALSE;
        }
        else {
            return TRUE;
        }
    }

    BOOL PEParser::parseNtHeader() {
        QWORD pNtHeader = m_peStruct->dosHeader.e_lfanew;
        IMAGE_NT_HEADERS32 ntHeader = { 0, };
        if (m_peReader->readData(pNtHeader, &ntHeader, sizeof(IMAGE_NT_HEADERS32)) < 0) {
            m_logger << LogLevel::ERR;
            m_logger << ErrorLogInfo(_T("Error: Fail to read NT header")) << NL;

            return FALSE;
        }
        else if (ntHeader.Signature != IMAGE_NT_SIGNATURE) {
            m_logger << LogLevel::ERR;
            m_logger << ErrorLogInfo(_T("Error: Invalid NT header signature")) << NL;

            return FALSE;
        }
        else {
            LPVOID bufferAddress;
            SIZE_T bufferSize;
            WORD machineType = ntHeader.FileHeader.Machine;

            if ((WORD)machineType == IMAGE_FILE_MACHINE_I386) {
                m_peStruct->machineType = x86;
                bufferAddress = &m_peStruct->ntHeader32;
                bufferSize = sizeof(IMAGE_NT_HEADERS32);
            }
            else {
                m_peStruct->machineType = x64;
                bufferAddress = &m_peStruct->ntHeader64;
                bufferSize = sizeof(IMAGE_NT_HEADERS64);
            }

            return (m_peReader->readData(pNtHeader, bufferAddress, bufferSize) >= 0);
        }
    }

    BOOL PEParser::parseSectionHeader() {
        size_t sectionHeaderOffset;
        WORD numberOfSections;
        
        if (m_peStruct->machineType == x86) {
            sectionHeaderOffset = m_peStruct->dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS32);
            numberOfSections = m_peStruct->ntHeader32.FileHeader.NumberOfSections;
        }
        else {
            sectionHeaderOffset = m_peStruct->dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS64);
            numberOfSections = m_peStruct->ntHeader64.FileHeader.NumberOfSections;
        }

        SIZE_T count;
        count = updateSectionHeaders(sectionHeaderOffset, numberOfSections);

        return (count > 0);
    }

    SIZE_T PEParser::updateSectionHeaders(size_t sectionHeaderOffset, WORD numberOfSections) {
        SIZE_T count = 0;
        SectionInfo sectionInfo;
        IMAGE_SECTION_HEADER sectionHeader = { 0, };

        for (WORD index = 0; index < numberOfSections; index++) {
            if (m_peReader->readData(sectionHeaderOffset, &sectionHeader, sizeof(IMAGE_SECTION_HEADER)) >= 0) {
                sectionInfo.Name = getString((const char*)sectionHeader.Name, IMAGE_SIZEOF_SHORT_NAME);
                sectionInfo.VirtualAddress = sectionHeader.VirtualAddress;
                sectionInfo.PointerToRawData = sectionHeader.PointerToRawData;
                sectionInfo.SizeOfRawData = sectionHeader.SizeOfRawData;
                sectionInfo.Characteristics = sectionHeader.Characteristics;

                m_peStruct->sectionList.push_back(sectionInfo);
                count++;
            }
            sectionHeaderOffset += sizeof(IMAGE_SECTION_HEADER);
            memset(&sectionHeader, 0, sizeof(IMAGE_SECTION_HEADER));
        }
        return count;
    }

    BOOL PEParser::parseDataDirectory() {
        size_t dataSize = sizeof(IMAGE_DATA_DIRECTORY) * IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
        IMAGE_DATA_DIRECTORY *dataDirectory;
        if (m_peStruct->machineType == x86) {
            dataDirectory = m_peStruct->ntHeader32.OptionalHeader.DataDirectory;
        }
        else {
            dataDirectory = m_peStruct->ntHeader64.OptionalHeader.DataDirectory;
        }

        memcpy_s(&m_peStruct->dataDirectory, dataSize, dataDirectory, dataSize);
        return TRUE;
    }


    BOOL PEParser::parseEAT() {
        ReserveDelete reserveDelete;
        vector<PEFunctionInfo> funcInfoVector;
        IMAGE_EXPORT_DIRECTORY exportDirectory = { 0, };
        WORD* nameOrdinals = NULL;
        DWORD* nameAddresses = NULL;
        DWORD* functionAddresses = NULL;
        DWORD* functionNamesRVA = NULL;
        DWORD va = m_peStruct->dataDirectory[0].VirtualAddress;
        if (va == 0x0) {
            return FALSE;
        }
        else if (m_peReader->readData(va, &exportDirectory, sizeof(IMAGE_EXPORT_DIRECTORY)) < 0) {
            return FALSE;
        }

        // 등록한 동적 할당된 주소를 함수 종료시 할당해제하는 코드
        reserveDelete
            .addRef((void**)&nameOrdinals)
            .addRef((void**)&nameAddresses)
            .addRef((void**)&functionAddresses)
            .addRef((void**)&functionNamesRVA);

        nameOrdinals = new WORD[exportDirectory.NumberOfNames];
        nameAddresses = new DWORD[exportDirectory.NumberOfNames];
        functionAddresses = new DWORD[exportDirectory.NumberOfFunctions];

        // 전체 함수 주소 배열에서 함수 이름이 존재하는 함수를 체크하기 위한 배열 생성
        // 함수 이름이 존재하는 함수 주소의 위치에 이름 문자열의 RVA를 배열에 저장
        functionNamesRVA = new DWORD[exportDirectory.NumberOfFunctions];
        memset(functionNamesRVA, NULL, sizeof(DWORD) * exportDirectory.NumberOfFunctions);

        if (tryReadExportDirectoryInfo(exportDirectory, functionAddresses, nameAddresses, nameOrdinals)) {
            // 이름이 존재하는 함수들의 이름 RVA를 pFunctionList에 저장
            for (DWORD i = 0; i < exportDirectory.NumberOfNames; i++) {
                WORD index = nameOrdinals[i];
                functionNamesRVA[index] = nameAddresses[i];
            }

            DWORD ordinalBase = (DWORD)exportDirectory.Base;
            PEFunctionInfo funcInfo = { 0, };
            for (DWORD i = 0; i < exportDirectory.NumberOfFunctions; i++) {
                DWORD nameRVA = functionNamesRVA[i];             // 이름이 존재하는 함수
                DWORD addressOfIAT = functionAddresses[i];       // Ordinal로만 Export하는 함수
                DWORD ordinal = ordinalBase + i;                 // ordinal = Base + functionAddress index(nameOrdinal)

                if (nameRVA != NULL && addressOfIAT != NULL) {
                    m_logger << LogLevel::DEBUG;
                    m_logger << ErrorLogInfo(_T("Export address is invalid > 0x{:x}, 0x{:x}")) << NL;
                }
                else {
                    funcInfo.AddressOfIAT = addressOfIAT;
                    funcInfo.Ordinal = ordinal;

                    if (nameRVA == NULL) {
                        funcInfo.Name = tstring(_T(""));
                    }
                    else {
                        funcInfo.Name = m_peReader->getPEString(nameRVA);
                    }

                    funcInfoVector.push_back(funcInfo);
                }
            }
            
            if (funcInfoVector.empty()) {
                return FALSE;
            }
            else {
                PEExportInfo exportInfo;
                tstring moduleName = m_peReader->getPEString(exportDirectory.Name);
                exportInfo.Name = moduleName;
                exportInfo.FunctionInfo = funcInfoVector;

                m_peStruct->exportList.push_back(exportInfo);

                return TRUE;
            }
        }
        else {
            return FALSE;
        }
    }

    BOOL PEParser::tryReadExportDirectoryInfo(IMAGE_EXPORT_DIRECTORY exportDirectory, DWORD* pFuncAddress, DWORD* pNameAddress, WORD* pNameOrdinal) {
        if (m_peReader->readData(exportDirectory.AddressOfFunctions, pFuncAddress, sizeof(DWORD) * exportDirectory.NumberOfFunctions) < 0) return FALSE;
        if (m_peReader->readData(exportDirectory.AddressOfNames, pNameAddress, sizeof(DWORD) * exportDirectory.NumberOfNames) < 0) return FALSE;
        if (m_peReader->readData(exportDirectory.AddressOfNameOrdinals, pNameOrdinal, sizeof(WORD) * exportDirectory.NumberOfNames) < 0) return FALSE;
        return TRUE;
    }

    BOOL PEParser::parseIAT() {
        BOOL result = FALSE;
        IMAGE_IMPORT_DESCRIPTOR importDescriptor = { 0, };
        DWORD va = m_peStruct->dataDirectory[1].VirtualAddress;

        if (va == 0x0) {
            return FALSE;
        }
        else {
            // ImportDescriptor 구조체의 배열을 차례대로 읽어옴
            // 배열의 끝은 NULL 구조체
            while (m_peReader->readData(va, &importDescriptor, sizeof(IMAGE_IMPORT_DESCRIPTOR)) >= 0 && (importDescriptor.OriginalFirstThunk != 0x0)) {
                if (m_peStruct->machineType == x86) {
                    if (parseImportDescriptor32(importDescriptor)) {
                        result = TRUE;
                    }
                }
                else {
                    if (parseImportDescriptor64(importDescriptor)) {
                        result = TRUE;
                    }
                }

                va += sizeof(IMAGE_IMPORT_DESCRIPTOR);
            }
        }

        return result;
    }
    
    BOOL PEParser::parseImportDescriptor32(IMAGE_IMPORT_DESCRIPTOR& importDescriptor) {
        const ULONGLONG TRUNK_DATASIZE = sizeof(IMAGE_THUNK_DATA32);
        IMAGE_THUNK_DATA32 thunkData = { 0, };

        vector<PEFunctionInfo> funcInfoVector;
        WORD funcNameOrdinal = 0;

        // IMAGE_THUNK_DATA32 (Import Name Table) 구조체의 배열을 차례대로 읽어옴
        // 배열의 끝은 NULL 구조체
        DWORD firstThunkAddress = importDescriptor.FirstThunk;
        DWORD importNameTablePosition = importDescriptor.OriginalFirstThunk;
        while ((m_peReader->readData((DWORD)firstThunkAddress, &thunkData, TRUNK_DATASIZE) >= 0) && (thunkData.u1.AddressOfData != 0x0)) {
            DWORD addressOfIAT = thunkData.u1.AddressOfData;

            if (m_peReader->readData((DWORD)importNameTablePosition, &thunkData, TRUNK_DATASIZE) >= 0) {
                DWORD ordinalValue = (thunkData.u1.Ordinal << 1) >> 1; // 최상위 비트 제거

                // 원래 값과 비교해서 다르면 최상위 비트가 1로 설정 됐다는 의미
                // 최상위 비트가 1로 설정된 경우에는 이름없이 Ordinal만 있는 함수
                if (ordinalValue != thunkData.u1.Ordinal) {
                    PEFunctionInfo funcInfo;
                    funcInfo.AddressOfIAT = addressOfIAT;
                    funcInfo.Ordinal = ordinalValue;
                    funcInfo.Name = tstring(_T(""));

                    funcInfoVector.push_back(funcInfo);
                }
                // Ordinal, 함수 이름 읽기
                else if (m_peReader->readData(thunkData.u1.AddressOfData, &funcNameOrdinal, sizeof(WORD)) >= 0) {
                    PEFunctionInfo funcInfo;
                    funcInfo.AddressOfIAT = addressOfIAT;
                    funcInfo.Ordinal = funcNameOrdinal;
                    funcInfo.Name = m_peReader->getPEString((DWORD)(thunkData.u1.AddressOfData + sizeof(WORD)));

                    funcInfoVector.push_back(funcInfo);
                }
            }
            firstThunkAddress += TRUNK_DATASIZE;
            importNameTablePosition += TRUNK_DATASIZE;
        }

        if (funcInfoVector.size() > 0) {
            PEImportInfo importInfo;
            importInfo.Name = m_peReader->getPEString(importDescriptor.Name);
            importInfo.FunctionInfo = funcInfoVector;

            m_peStruct->importList.push_back(importInfo);
            return TRUE;
        }
        else {
            return FALSE;
        }
    }

    BOOL PEParser::parseImportDescriptor64(IMAGE_IMPORT_DESCRIPTOR& importDescriptor) {
        const ULONGLONG TRUNK_DATASIZE = sizeof(IMAGE_THUNK_DATA64);
        IMAGE_THUNK_DATA64 thunkData = { 0, };

        vector<PEFunctionInfo> funcInfoVector;
        WORD funcNameOrdinal = 0;

        DWORD firstThunkAddress = importDescriptor.FirstThunk;
        DWORD importNameTablePosition = importDescriptor.OriginalFirstThunk;
        while ((m_peReader->readData((DWORD)firstThunkAddress, &thunkData, TRUNK_DATASIZE) >= 0) && (thunkData.u1.AddressOfData != 0x0)) {
            QWORD addressOfIAT = thunkData.u1.AddressOfData;

            if (m_peReader->readData((DWORD)importNameTablePosition, &thunkData, TRUNK_DATASIZE) >= 0) {
                QWORD ordinalValue = (thunkData.u1.Ordinal << 1) >> 1;

                if (ordinalValue != thunkData.u1.Ordinal) {
                    PEFunctionInfo funcInfo;
                    funcInfo.AddressOfIAT = addressOfIAT;
                    funcInfo.Ordinal = (DWORD)ordinalValue;
                    funcInfo.Name = tstring(_T(""));

                    funcInfoVector.push_back(funcInfo);
                }
                else {
                    if (m_peReader->readData(thunkData.u1.AddressOfData, &funcNameOrdinal, sizeof(WORD)) >= 0) {
                        PEFunctionInfo funcInfo;
                        funcInfo.AddressOfIAT = addressOfIAT;
                        funcInfo.Ordinal = funcNameOrdinal;
                        funcInfo.Name = m_peReader->getPEString(thunkData.u1.AddressOfData + sizeof(WORD));

                        funcInfoVector.push_back(funcInfo);
                    }
                }
            }
            firstThunkAddress += TRUNK_DATASIZE;
            importNameTablePosition += TRUNK_DATASIZE;
        }

        if (funcInfoVector.size() > 0) {
            PEImportInfo importInfo;
            importInfo.Name = m_peReader->getPEString(importDescriptor.Name);
            importInfo.FunctionInfo = funcInfoVector;

            m_peStruct->importList.push_back(importInfo);
            return TRUE;
        }
        else {
            return FALSE;
        }
    }

    BOOL PEParser::parseTLS() {
        auto va = m_peStruct->dataDirectory[9].VirtualAddress;
        if (va == 0x0) {
            return FALSE;
        }
        if (m_peStruct->machineType == x86) {
            return parseTLS32();
        }
        else {
            return parseTLS64();
        }
    }

    BOOL PEParser::parseTLS32() {
        auto va = m_peStruct->dataDirectory[9].VirtualAddress;
        IMAGE_TLS_DIRECTORY32 tlsDirectory = { 0, };
        DWORD callbackAddress = 0;

        if (m_peReader->readData((DWORD)va, &tlsDirectory, sizeof(IMAGE_TLS_DIRECTORY32)) >= 0) {
            DWORD curCallbackArrayAddress = tlsDirectory.AddressOfCallBacks;

            // 프로세스에서는 IMAGE_TLS_DIRECTORY32 구조체 내의 값들이 RVA가 아닌 실제 주소로 저장되어 있음으로 readDataNoBase를 사용
            // 마지막이 NULL 구조체인 배열 형태
            while ((m_peReader->readDataNoBase((DWORD)curCallbackArrayAddress, &callbackAddress, sizeof(DWORD)) >= 0) && (callbackAddress != 0x0)) {
                m_peStruct->tlsCallbackList.push_back((QWORD)callbackAddress);
                curCallbackArrayAddress += sizeof(DWORD);
            }

            // 파일에서는 콜백 함수 주소 배열을 얻을 수 없기 때문에 구조체에 저장된 주소를 그대로 저장
            if (m_peStruct->tlsCallbackList.size() == 0) {
                m_peStruct->tlsCallbackList.push_back((DWORD)tlsDirectory.AddressOfCallBacks);
            }
            return TRUE;
        }
        else {
            return FALSE;
        }
    }

    BOOL PEParser::parseTLS64() {
        auto va = m_peStruct->dataDirectory[9].VirtualAddress;
        IMAGE_TLS_DIRECTORY64 tlsDirectory = { 0, };
        QWORD callbackAddress = 0;

        if (m_peReader->readData(va, &tlsDirectory, sizeof(IMAGE_TLS_DIRECTORY64)) >= 0) {
            QWORD curCallbackArrayAddress = tlsDirectory.AddressOfCallBacks;

            // 프로세스에서는 IMAGE_TLS_DIRECTORY32 구조체 내의 값들이 RVA가 아닌 실제 주소(VA)로 저장되어 있기 때문에 m_peBaseAddress를 더해주지 않고 메모리 주소 그대로 읽음
            while ((m_peReader->readDataNoBase((QWORD)curCallbackArrayAddress, &callbackAddress, sizeof(QWORD)) >= 0) && (callbackAddress != 0x0)) {
                m_peStruct->tlsCallbackList.push_back((ULONGLONG)callbackAddress);
                curCallbackArrayAddress += sizeof(QWORD);
            }

            if (m_peStruct->tlsCallbackList.size() == 0) {
                // 파일에서는 콜백 함수 주소 배열을 얻을 수 없기 때문에 구조체에 저장된 주소를 그대로 저장
                m_peStruct->tlsCallbackList.push_back((QWORD)tlsDirectory.AddressOfCallBacks);
            }
            return TRUE;
        }
        else {
            return FALSE;
        }
    }

    BOOL PEParser::parseDebug() {
        DWORD va = m_peStruct->dataDirectory[6].VirtualAddress;
        BOOL result = FALSE;

        if (va == 0x0) {
            return FALSE;
        }
        else {
            IMAGE_DEBUG_DIRECTORY debugDirectory = { 0, };
            DWORD callbackAddress = 0;
            IMAGE_PDB_INFO pdbInfo = { 0, };

            if (m_peReader->readData(va, &debugDirectory, sizeof(IMAGE_DEBUG_DIRECTORY)) < 0) {
                return FALSE;
            }
            else if ((debugDirectory.Type != IMAGE_DEBUG_TYPE_CODEVIEW)) {
                return FALSE;
            }
            else if (m_peReader->readData((DWORD)debugDirectory.AddressOfRawData, &pdbInfo, sizeof(IMAGE_PDB_INFO)) < 0) {
                return FALSE;
            }
            else if (pdbInfo.Signature != IMAGE_PDB_SIGNATURE) {
                return FALSE;
            }
            else {
                // PDB 경로 저장
                QWORD rva = (DWORD)debugDirectory.AddressOfRawData + (sizeof(DWORD) * 2) + (sizeof(BYTE) * 16);
                m_peStruct->pdbPath = m_peReader->getPEString(rva);

                return TRUE;
            }
        }
        return result;
    };

}