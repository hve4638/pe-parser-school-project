#pragma once
#include "IPEReader.h"

namespace PEParse {
    class PEFileReader : public IPEReader {
    private:
        struct RAWInfo {
            PEPOS startAddress = 0;
            PEPOS endAddress = 0;
            PEPOS virtualAddress = 0;
            PEPOS pointerToRawData = 0;
        };
        struct SectionInfo {
            PEPOS sizeOfHeaders = 0;
            DWORD numberOfSections = 0;
            IMAGE_SECTION_HEADER* headerAddress = NULL;
        };

        tstring m_filePath;
        HANDLE m_fileHandle = NULL;
        HANDLE m_fileMapping = NULL;
        PBYTE m_baseAddress = NULL;
        //IMAGE_SECTION_HEADER *m_sectionHeader = NULL;
        struct RAWInfo m_rawInfo;
        struct SectionInfo m_sectionInfo;

    private:
        BOOL setRvaToRawInfo(PEPOS rav);
        PEPOS rvaToRaw(PEPOS rav, PEPOS addPosition);

        void updateSectionInfo();
        BOOL tryUpdateRawInfo(PEPOS rva);

    public:
        PEFileReader();
        ~PEFileReader() override;
        BOOL open(const TCHAR* pfilePath);
        BOOL open(DWORD pid, const TCHAR* pfilePath) override;
        void close() override;
        LPVOID getBaseAddress() override;
        tstring getFilePath() override;
        tstring getPEString(PEPOS rva) override;
        tstring getPEStringNoBase(PEPOS rva) override;
        SSIZE_T readData(PEPOS rva, LPVOID bufferAddress, SIZE_T bufferSize) override;
        SSIZE_T readDataNoBase(PEPOS rva, LPVOID bufferAddress, SIZE_T bufferSize) override;
    };

};


