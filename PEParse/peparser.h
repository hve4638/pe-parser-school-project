#pragma once
#include "IPEReader.h"
#include "IPEParser.h"

namespace PEParse {
    class PEParser : IPEParser {
    protected:
        PEStructure m_peStruct;
        IPEReader* m_peReader = NULL;

    private:
        tstring getString(const char* srcString, size_t srcLength);
        BOOL parseDosHeader();
        BOOL parseNtHeader();
        BOOL parseSectionHeader();
        SIZE_T updateSectionHeaders(size_t sectionHeaderOffset, WORD numberOfSections);
        BOOL parseDataDirectory();
        BOOL parseEAT();
        BOOL parseIAT();
        BOOL parseIAT32(IMAGE_IMPORT_DESCRIPTOR& importDescriptor);
        BOOL parseIAT64(IMAGE_IMPORT_DESCRIPTOR& importDescriptor);
        BOOL parseTLS();
        BOOL parseTLS32();
        BOOL parseTLS64();

        BOOL tryReadExportDirectoryInfo(IMAGE_EXPORT_DIRECTORY exportDirectory, DWORD* pFuncAddress, DWORD* pNameAddress, WORD* pNameOrdinal);

    public:
        PEParser();
        ~PEParser() override;
        void close() override;
        BOOL parsePEFile(const TCHAR* pfilePath);
        BOOL parsePEProcess(DWORD pid);
        BOOL parsePE(DWORD pid, const TCHAR* pfilePath) override;

        const PEStructure& getPEStructure(void) override;
    };
}