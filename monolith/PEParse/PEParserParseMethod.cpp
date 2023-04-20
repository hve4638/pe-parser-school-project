#pragma once
#include <format>
#include "PEParser.h"
#include "PEFileReader.h"
#include "PEUtils.h"
#include "ReserveDelete.h"

using namespace std;
using namespace PEUtils;

namespace PEParse {    BOOL PEParser::parseDosHeader(void) {
        if (m_peReader->readData(0x0, &m_peStruct->dosHeader, sizeof(IMAGE_DOS_HEADER)) >= 0) {
            if (m_peStruct->dosHeader.e_magic == IMAGE_DOS_SIGNATURE) {
                return TRUE;
            }
            else {
                debugPrint(_T("Error: Invalid DOS header signature\n"));
            }
        }
        else {
            debugPrint(_T("Error: Fail to read DOS header\n"));
        }

        return FALSE;
    }
    BOOL PEParser::parseNtHeader(void) {
        PEPOS pNtHeader = m_peStruct->dosHeader.e_lfanew;
        IMAGE_NT_HEADERS32 ntHeader = { 0, };
        if (m_peReader->readData(pNtHeader, &ntHeader, sizeof(IMAGE_NT_HEADERS32)) >= 0) {
            if (ntHeader.Signature != IMAGE_NT_SIGNATURE) {
                debugPrint(_T("Error: Invalid NT header signature\n"));
            }
            else {
                WORD machineType = ntHeader.FileHeader.Machine;
                if ((WORD)machineType == IMAGE_FILE_MACHINE_I386) {
                    m_peStruct->machineType = x86;
                    return (m_peReader->readData(pNtHeader, &m_peStruct->ntHeader32, sizeof(IMAGE_NT_HEADERS32)) >= 0);
                }
                else {
                    m_peStruct->machineType = x64;
                    return (m_peReader->readData(pNtHeader, &m_peStruct->ntHeader64, sizeof(IMAGE_NT_HEADERS64)) >= 0);
                }
            }
        }
        return FALSE;
    }
    BOOL PEParser::parseSectionHeader(void) {
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
        if (m_peStruct->machineType == x86) {
            auto dataDirectory = m_peStruct->ntHeader32.OptionalHeader.DataDirectory;
            memcpy_s(&m_peStruct->dataDirectory, dataSize, dataDirectory, dataSize);
        }
        else {
            auto dataDirectory = m_peStruct->ntHeader64.OptionalHeader.DataDirectory;
            memcpy_s(&m_peStruct->dataDirectory, dataSize, dataDirectory, dataSize);
        }
        return TRUE;
    }
    BOOL PEParser::parseEAT() {
        ReserveDelete reserveDelete;
        vector<PEFunctionInfo> funcInfoVector;
        IMAGE_EXPORT_DIRECTORY exportDirectory = { 0, };

        WORD* pNameOrdinal = NULL;
        DWORD* pNameAddress = NULL;
        DWORD* pFuncAddress = NULL;
        DWORD* pFunctionList = NULL;

        reserveDelete
            .addRef((void**)&pNameOrdinal)
            .addRef((void**)&pNameAddress)
            .addRef((void**)&pFuncAddress)
            .addRef((void**)&pFunctionList);

        auto va = m_peStruct->dataDirectory[0].VirtualAddress;
        if (va == 0x0) {
            return FALSE;
        }
        else if (m_peReader->readData(va, &exportDirectory, sizeof(IMAGE_EXPORT_DIRECTORY)) < 0) {
            return FALSE;
        }

        pNameOrdinal = new WORD[exportDirectory.NumberOfNames];
        pNameAddress = new DWORD[exportDirectory.NumberOfNames];
        pFuncAddress = new DWORD[exportDirectory.NumberOfFunctions];

        tstring moduleName = m_peReader->getPEString(exportDirectory.Name);     // Export Directory Name : 함수를 제공하는 exe나 dll의 이름
        DWORD odinalBase = (DWORD)exportDirectory.Base;                         // Ordinal 은 function address index + Base 값

        pFunctionList = new DWORD[exportDirectory.NumberOfFunctions];                   // 전체 함수 주소 배열에서 함수 이름이 존재하는 함수를 체크하기 위한 배열 생성
        memset(pFunctionList, 0, sizeof(DWORD) * exportDirectory.NumberOfFunctions);    // 함수 이름이 존재하는 함수 주소의 위치에 이름 문자열의 RVA를 배열에 저장

        if (tryReadExportDirectoryInfo(exportDirectory, pFuncAddress, pNameAddress, pNameOrdinal)) {
            for (DWORD i = 0; i < exportDirectory.NumberOfNames; i++) {             // 이름이 존재하는 함수들의 이름 RVA를 pFunctionList에 저장
                WORD index = pNameOrdinal[i];
                DWORD nameRva = pNameAddress[i];
                pFunctionList[index] = nameRva;
            }

            PEFunctionInfo funcInfo = { 0, };
            for (DWORD i = 0; i < exportDirectory.NumberOfFunctions; i++) { // Export하는 전체 함수들에 대한 정보를 출력
                if (pFunctionList[i] == 0x0) {
                    if ((DWORD)pFuncAddress[i] != 0x0) { // Ordinal로만 Export하는 함수
                        funcInfo.AddressOfIAT = pFuncAddress[i];
                        funcInfo.Ordinal = odinalBase + i;
                        funcInfo.Name = tstring(_T(""));

                        funcInfoVector.push_back(funcInfo);
                    }
                    else {
                        debugPrint(format(_T("Export address is invalid > 0x{:x}, 0x{:x}"), (DWORD)pFuncAddress[i], (WORD)odinalBase + i));
                    }
                }
                else {
                    funcInfo.AddressOfIAT = pFuncAddress[i];
                    funcInfo.Ordinal = odinalBase + i;
                    funcInfo.Name = m_peReader->getPEString(pFunctionList[i]);

                    funcInfoVector.push_back(funcInfo);
                }
            }

            if (!funcInfoVector.empty()) {
                PEExportInfo exportInfo;
                exportInfo.Name = moduleName;
                exportInfo.FunctionInfo = funcInfoVector;

                m_peStruct->exportList.push_back(exportInfo);

                return TRUE;
            }
            else {
                return FALSE;
            }
        }
        else {
            return FALSE;
        }
    }

    inline BOOL PEParser::tryReadExportDirectoryInfo(IMAGE_EXPORT_DIRECTORY exportDirectory, DWORD* pFuncAddress, DWORD* pNameAddress, WORD* pNameOrdinal) {
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
            while (m_peReader->readData(va, &importDescriptor, sizeof(IMAGE_IMPORT_DESCRIPTOR)) >= 0 && (importDescriptor.OriginalFirstThunk != 0x0)) {
                if (m_peStruct->machineType == x86) {
                    if (parseIAT32(importDescriptor)) {
                        result = TRUE;
                    }
                }
                else {
                    if (parseIAT64(importDescriptor)) {
                        result = TRUE;
                    }
                }

                va += sizeof(IMAGE_IMPORT_DESCRIPTOR);
            }
        }

        return result;
    }

    BOOL PEParser::parseIAT32(IMAGE_IMPORT_DESCRIPTOR& importDescriptor) {
        const ULONGLONG TRUNK_DATASIZE = sizeof(IMAGE_THUNK_DATA32);
        IMAGE_THUNK_DATA32 thunkData = { 0, };

        vector<PEFunctionInfo> funcInfoVector;
        WORD funcNameOrdinal = 0;

        DWORD firstThunkAddress = importDescriptor.FirstThunk;
        DWORD importNameTablePosition = importDescriptor.OriginalFirstThunk;
        while ((m_peReader->readData((DWORD)firstThunkAddress, &thunkData, TRUNK_DATASIZE) >= 0) && (thunkData.u1.AddressOfData != 0x0)) {
            DWORD addressOfIAT = thunkData.u1.AddressOfData;

            if (m_peReader->readData((DWORD)importNameTablePosition, &thunkData, TRUNK_DATASIZE) >= 0) {
                DWORD ordinalValue = (thunkData.u1.Ordinal << 1) >> 1; // 최상위 비트를 없앰(최상위 비트를 제거한 값이 Ordinal 값)

                // 원래 값과 비교해서 다르면 최상위 비트가 1로 설정 됐다는 의미
                // 최상위 비트가 1로 설정된 경우에는 Ordinal만 있는 함수
                if (ordinalValue != thunkData.u1.Ordinal) {
                    PEFunctionInfo funcInfo;
                    funcInfo.AddressOfIAT = addressOfIAT;
                    funcInfo.Ordinal = ordinalValue;
                    funcInfo.Name = tstring(_T(""));

                    funcInfoVector.push_back(funcInfo);
                }
                else {
                    // Hint(Ordinal)와 함수 이름 읽기
                    // IMAGE_IMPORT_BY_NAME 구조체를 통하지 않는 이유는 실제 프로세스 메모리에서 데이터를 읽어야 하는데 IMAGE_IMPORT_BY_NAME 구조체가 Hint(WORD), Name(Char[1])으로만
                    // 정의되어 있어서 3Byte만 읽을 뿐 전체 함수 이름을 다 읽어 올 수 없는 문제가 있음(함수 이름의 크기를 알수 없기 때문에)
                    // 그래서 thunkData.u1.AddressOfData 주소를 통해서 Hint를 읽고 WORD 크기 만큼 주소를 증가 시켜서 getString 함수로 함수 이름을 읽도록 함
                    if (m_peReader->readData(thunkData.u1.AddressOfData, &funcNameOrdinal, sizeof(WORD)) >= 0) {
                        PEFunctionInfo funcInfo;
                        funcInfo.AddressOfIAT = addressOfIAT;
                        funcInfo.Ordinal = funcNameOrdinal;
                        funcInfo.Name = m_peReader->getPEString((DWORD)(thunkData.u1.AddressOfData + sizeof(WORD)));

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

    BOOL PEParser::parseIAT64(IMAGE_IMPORT_DESCRIPTOR& importDescriptor) {
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

            // 프로세스에서는 IMAGE_TLS_DIRECTORY32 구조체 내의 값들이 RVA가 아닌 실제 주소(VA)로 저장되어 있기 때문에 m_peBaseAddress를 더해주지 않고 메모리 주소 그대로 읽음
            while ((m_peReader->readDataNoBase((DWORD)curCallbackArrayAddress, &callbackAddress, sizeof(DWORD)) >= 0) && (callbackAddress != 0x0)) {
                m_peStruct->tlsCallbackList.push_back((ULONGLONG)callbackAddress);
                curCallbackArrayAddress += sizeof(DWORD);
            }

            if (m_peStruct->tlsCallbackList.size() == 0) {
                // 파일에서는 콜백 함수 주소 배열을 얻을 수 없기 때문에 구조체에 저장된 주소를 그대로 저장
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
            else if (m_peReader->readData((DWORD)debugDirectory.AddressOfRawData, &pdbInfo, sizeof(IMAGE_PDB_INFO)) >= 0) {
                return FALSE;
            }
            else if (pdbInfo.Signature != IMAGE_PDB_SIGNATURE) {
                return FALSE;
            }
            else {
                QWORD rva = (DWORD)debugDirectory.AddressOfRawData + (sizeof(DWORD) * 2) + (sizeof(BYTE) * 16);
                m_peStruct->pdbPath = m_peReader->getPEString(rva);

                return TRUE;
            }
        }
        return result;
    };

}