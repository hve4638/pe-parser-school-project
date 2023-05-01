#pragma once
#include <format>
#include "PEParser.h"
#include "PEFileReader.h"
#include "PEUtils.h"
#include "ReserveDelete.h"
#include "HashMD5Utils.h"


using namespace std;
using namespace PEUtils;

namespace PEParse {
    tstring PEParser::getString(const char* srcString, size_t srcLength = IMAGE_SIZEOF_SHORT_NAME) {
        shared_ptr<BYTE> byteBuffer(new BYTE[srcLength + 1]);
        memcpy_s(byteBuffer.get(), srcLength, srcString, srcLength);
        
        if (CHAR_IS_TCHAR) {
            return reinterpret_cast<const TCHAR*>(byteBuffer.get());
        }
        else {
            return convertToUTF8(byteBuffer.get(), srcLength);
        }
    }

    DWORD PEParser::getAddressOfEntryPoint() {
        if (m_peStruct->machineType == x86) {
            return m_peStruct->ntHeader32.OptionalHeader.AddressOfEntryPoint;
        }
        else {
            return m_peStruct->ntHeader64.OptionalHeader.AddressOfEntryPoint;
        }
    }

    BOOL PEParser::findSectionAsName(const TCHAR* sectionName, SectionInfo& info) {
        if (sectionName == NULL) return FALSE;
        for (SectionInfo section : m_peStruct->sectionList) {
            if (section.Name.compare(sectionName) == 0) {
                info = section;
                return TRUE;
            }
        }
        return FALSE;
    }

    BOOL PEParser::findSectionAsOffset(DWORD offset, SectionInfo &sectionInfo) {
        for (SectionInfo section : m_peStruct->sectionList) {
            DWORD offsetBegin = section.VirtualAddress;
            DWORD offsetEnd = offsetBegin + section.SizeOfRawData;

            if (offset >= offsetBegin && offset < offsetEnd) {
                sectionInfo = section;

                return TRUE;
            }
        }
        return FALSE;
    }


    BOOL PEParser::tryMakeHashMD5(DWORD rva, SIZE_T size, tstring& hash) {
        HashMD5Utils md5;
        vector<BYTE> sectionData(size);

        if (m_peReader->readData(rva, sectionData.data(), size) >= 0) {
            return md5.tryGetMD5(sectionData.data(), size, hash);
        }
        else {
            return FALSE;
        }
    }
}