#include <iostream>
#include <format>
#include "PEFileReader.h"
#include "PEUtils.h"

using namespace PEUtils;

namespace PEParse {
	PEFileReader::PEFileReader() {

	}

	PEFileReader::~PEFileReader() {
		close();
	}

	void PEFileReader::close() {
        if (m_fileMapping != NULL) {
            UnmapViewOfFile(m_baseAddress);
            CloseHandle(m_fileMapping);
        }
        if (m_fileHandle != NULL) {
            CloseHandle(m_fileHandle);
        }
        m_baseAddress = NULL;
	}

    BOOL PEFileReader::open(DWORD pid, const TCHAR* filePath) {
        return open(filePath);
    }

	BOOL PEFileReader::open(const TCHAR* filePath) {
        if (filePath == NULL) {
            return FALSE;
        }
        close();

        m_filePath = filePath;
        debugPrint(format(_T("Create memory map : {:s}\n"), m_filePath));

        m_fileHandle = CreateFile(m_filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (m_fileHandle == INVALID_HANDLE_VALUE) {
            debugPrint(_T("Error: Cannot open file\n"));
            return FALSE;
        }

        m_fileMapping = CreateFileMapping(m_fileHandle, NULL, PAGE_READONLY, 0, 0, NULL);
        if (m_fileMapping == NULL) {
            CloseHandle(m_fileHandle);
            m_fileHandle = NULL;
            debugPrint(_T("Error: Cannot create file mapping\n"));
            return FALSE;
        }

        m_baseAddress = reinterpret_cast<BYTE*>(MapViewOfFile(m_fileMapping, FILE_MAP_READ, 0, 0, 0));
        if (m_baseAddress == NULL) {
            CloseHandle(m_fileMapping);
            CloseHandle(m_fileHandle);
            m_fileMapping = NULL;
            m_fileHandle = NULL;
            debugPrint(_T("Error: Cannot map view of file\n"));
            return FALSE;
        }

        return TRUE;
	}

	LPVOID PEFileReader::getBaseAddress() {
        return m_baseAddress;
	}
	tstring PEFileReader::getFilePath() {
        return m_filePath;
    }

    tstring PEFileReader::getPEString(PEPOS rva) {
        QWORD offset = rva;
        BYTE bytes[2] = { 0, };

        if (setRvaToRawInfo(rva)) {
            QWORD raw = rvaToRaw(rva, reinterpret_cast<QWORD>(m_baseAddress));

            if (sizeof(TCHAR) == sizeof(char)) {
                return (TCHAR*)(raw);
            }
            else {
                int bufferLen = MultiByteToWideChar(CP_UTF8, 0, (LPCCH)(raw), -1, NULL, 0);

                tstring dest;
                auto buffer = new TCHAR[bufferLen];
                MultiByteToWideChar(CP_UTF8, 0, (LPCCH)(raw), -1, buffer, bufferLen);
                dest = buffer;
                
                delete[] buffer;
                return dest;
            }
        }

        return _T("");
    }

    tstring PEFileReader::getPEStringNoBase(PEPOS rva) {
        QWORD offset = rva;
        BYTE bytes[2] = { 0, };

        if (setRvaToRawInfo(rva)) {
            QWORD raw = rvaToRaw(rva, 0x0);

            if (sizeof(TCHAR) == sizeof(char)) {
                return (TCHAR*)(raw);
            }
            else {
                int bufferLen = MultiByteToWideChar(CP_UTF8, 0, (LPCCH)(raw), -1, NULL, 0);

                tstring dest;
                auto buffer = new TCHAR[bufferLen];
                MultiByteToWideChar(CP_UTF8, 0, (LPCCH)(raw), -1, buffer, bufferLen);
                dest = buffer;

                delete[] buffer;
                return dest;
            }
        }

        return _T("");
    };
    
    SSIZE_T PEFileReader::readData(PEPOS rva, LPVOID bufferAddress, SIZE_T bufferSize) {
        LPVOID realAddress = NULL;

        if (setRvaToRawInfo(rva)) {
            realAddress = (LPVOID)rvaToRaw(rva, (PEPOS)m_baseAddress);
            memcpy_s(bufferAddress, bufferSize, realAddress, bufferSize);

            return bufferSize;
        }
        else {
            debugPrint(format(_T("RVA to RAW fail : 0x{:x}, 0x{:x}"), (DWORD)GetLastError(), rva));

            return -1;
        }
    }
    
    SSIZE_T PEFileReader::readDataNoBase(PEPOS rva, LPVOID bufferAddress, SIZE_T bufferSize) {
        LPVOID realAddress = NULL;
        
        if (setRvaToRawInfo(rva)) {
            realAddress = (LPVOID)rvaToRaw(rva, 0);

            memcpy_s(bufferAddress, bufferSize, realAddress, bufferSize);
            return bufferSize;
        }
        else {
            debugPrint(format(_T("RVA to RAW fail : 0x{:x}, 0x{:x}"), (DWORD)GetLastError(), rva));

            return FALSE;
        }
    }

    QWORD PEFileReader::getRAW(QWORD rva) {
        if (setRvaToRawInfo(rva)) {
            return rvaToRaw(rva, 0);
        }
        else {
            return 0;
        }
    }
}