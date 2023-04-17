#pragma once
#include <format>
#include "PEParser.h"
#include "PEFileReader.h"
#include "PEUtils.h"

using namespace std;
//using namespace PEMemMapUtil;
//using namespace PEProcessUtil;

namespace PEParse {
    PEParser::PEParser() {

    }

    PEParser::~PEParser() {
        close();
    }

    void PEParser::close(void) {
        m_peStruct.machineType = other;
        m_peStruct.sectionList.clear();
        m_peStruct.exportList.clear();
        m_peStruct.importList.clear();
        m_peStruct.tlsCallbackList.clear();
        if (m_peReader != NULL) {
            PEUtils::deleteStruct((VOID**)&m_peReader);
        }
    };

    BOOL PEParser::parsePEFile(const TCHAR* filePath) {
        return parsePE(NULL, filePath);
    }
    BOOL PEParser::parsePEProcess(DWORD pid) {
        return parsePE(pid, NULL);
    }

    BOOL PEParser::parsePE(DWORD pid, const TCHAR* pfilePath) {
        if (pfilePath == NULL) {
            // WIP
            return FALSE;
        }
        else {
            m_peReader = new PEFileReader();
        }

        // PE(process or file) parsing
        if (m_peReader->open(pid, pfilePath)) {
            if (parseDosHeader() && parseNtHeader()) {
                parseSectionHeader();
                parseDataDirectory();
                parseEAT();
                parseIAT();
                parseTLS();

                m_peStruct.baseAddress = m_peReader->getBaseAddress();
                m_peStruct.filePath = m_peReader->getFilePath();
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

    const PEStructure& PEParser::getPEStructure(void) {
        return m_peStruct;
    }
}