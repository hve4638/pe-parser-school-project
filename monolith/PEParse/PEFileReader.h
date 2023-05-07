#pragma once
#include "IPEReader.h"
#include "Logger.h"
using namespace LogUtils;

namespace PEParse {
    class PEFileReader : public IPEReader {
        struct RAWInfo {
            QWORD startAddress = 0;
            QWORD endAddress = 0;
            QWORD virtualAddress = 0;
            QWORD pointerToRawData = 0;
        };
        struct SectionInfo {
            QWORD sizeOfHeaders = 0;
            DWORD numberOfSections = 0;
            IMAGE_SECTION_HEADER* headerAddress = NULL;
        };

        Logger m_logger = { LogLevel::ALL, LogDirection::DEBUGVIEW };
        tstring m_filePath;
        HANDLE m_fileHandle = NULL;
        HANDLE m_fileMapping = NULL;
        PBYTE m_baseAddress = NULL;
        struct RAWInfo m_rawInfo;
        struct SectionInfo m_sectionInfo;

        BOOL setRvaToRawInfo(QWORD rav);
        QWORD rvaToRaw(QWORD rav, QWORD addPosition);
        void updateSectionInfo();
        BOOL tryUpdateRawInfo(QWORD rva);

    public:
        PEFileReader();
        ~PEFileReader() override;
        BOOL open(const TCHAR* pfilePath);
        BOOL open(DWORD pid, const TCHAR* pfilePath) override;
        void close() override;
        LPVOID getBaseAddress() override;
        QWORD getRAW(QWORD rva) override;
        tstring getFilePath() override;
        tstring getPEString(QWORD rva) override;
        tstring getPEStringNoBase(QWORD rva) override;
        SSIZE_T readData(QWORD rva, LPVOID bufferAddress, SIZE_T bufferSize) override;
        SSIZE_T readDataNoBase(QWORD rva, LPVOID bufferAddress, SIZE_T bufferSize) override;
    };

};


