#pragma once
#include <format>
#include "PEParser.h"
#include "PEFileReader.h"
#include "PEProcessReader.h"
#include "PEUtils.h"
#include "HashMD5Utils.h"

using namespace std;
using namespace PEUtils;
//using namespace PEMemMapUtil;
//using namespace PEProcessUtil;

namespace PEParse {
    PEParser::PEParser() {
        m_peStruct.reset(new PEStructure());
    }

    PEParser::~PEParser() {
        close();
    }

    void PEParser::close() {
        m_peStruct->machineType = other;
        m_peStruct->sectionList.clear();
        m_peStruct->exportList.clear();
        m_peStruct->importList.clear();
        m_peStruct->tlsCallbackList.clear();
    };

    BOOL PEParser::parsePEFile(const TCHAR* filePath) {
        return parsePE(NULL, filePath);
    }
    BOOL PEParser::parsePEProcess(DWORD pid) {
        return parsePE(pid, NULL);
    }

    BOOL PEParser::parsePE(DWORD pid, const TCHAR* pfilePath) {
        if (pfilePath == NULL) {
            m_peReader.reset(new PEProcessReader());
        }
        else {
            m_peReader.reset(new PEFileReader());
        }

        if (m_peReader->open(pid, pfilePath)) {
            if (parseDosHeader() && parseNtHeader()) {
                parseSectionHeader();
                parseDataDirectory();
                parseEAT();
                parseIAT();
                parseTLS();
                parseDebug();

                m_peStruct->baseAddress = m_peReader->getBaseAddress();
                m_peStruct->filePath = m_peReader->getFilePath();
                return TRUE;
            }
            else {
                return FALSE;
            }
        }
        else {
            close();
            return FALSE;
        }
    }

    shared_ptr<PEStructure> PEParser::getPEStructure() {
        return m_peStruct;
    }

    BOOL PEParser::tryGetSectionHash(const TCHAR* sectionName, tstring& hash) {
        SectionInfo section;
        if (findSectionAsName(sectionName, section)) {
            DWORD va = section.VirtualAddress;
            DWORD size = section.SizeOfRawData;
            return tryMakeHashMD5(va, size, hash);
        }
        else {
            return FALSE;
        }
    }

    BOOL PEParser::tryGetCodeSectionHash(tstring& hash) {
        DWORD offset;
        DWORD size;
        
        if (m_peStruct->machineType == x86) {
            offset = m_peStruct->ntHeader64.OptionalHeader.BaseOfCode;
            size = m_peStruct->ntHeader64.OptionalHeader.SizeOfCode;
        }
        else {
            offset = m_peStruct->ntHeader64.OptionalHeader.BaseOfCode;
            size = m_peStruct->ntHeader64.OptionalHeader.SizeOfCode;
        }
        return tryMakeHashMD5(offset, size, hash);
    }

    BOOL PEParser::tryGetEntryPointSectionHash(tstring& hash) {
        SectionInfo section;

        DWORD entryPoint = getAddressOfEntryPoint();
        if (findSectionAsOffset(entryPoint, section)) {
            DWORD va = section.VirtualAddress;
            DWORD size = section.SizeOfRawData;
            return tryMakeHashMD5(va, size, hash);
        }
        else {
            return FALSE;
        }
    };

    BOOL PEParser::tryGetPDBFilePathHash(tstring& hash) {
        SectionInfo section;

        tstring& pdbPath = m_peStruct->pdbPath;
        auto bytes = reinterpret_cast<const BYTE*>(pdbPath.c_str());
        auto length = (DWORD)(pdbPath.size()) * sizeof(TCHAR);

        HashMD5Utils md5;
        return md5.tryGetMD5(bytes, length, hash);
    }
}