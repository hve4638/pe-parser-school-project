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
        /*
            파일을 열고 메모리에 매핑한다.
            모든 과정이 성공시 TRUE를 리턴하고, 실패시 과정 중 연 핸들을 정리하고 FALSE를 리턴한다.
        */
        if (filePath == NULL) {
            return FALSE;
        }
        close();

        m_filePath = filePath;
        m_logger << LogLevel::DEBUG;
        m_logger << format(_T("Create memory map : {:s}"), m_filePath) << NL;

        m_fileHandle = CreateFile(m_filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (m_fileHandle == INVALID_HANDLE_VALUE) {
            m_logger << LogLevel::ERR;
            m_logger << ErrorLogInfo(_T("Error: Cannot open file")) << NL;

            return FALSE;
        }

        m_fileMapping = CreateFileMapping(m_fileHandle, NULL, PAGE_READONLY, 0, 0, NULL);
        if (m_fileMapping == NULL) {
            CloseHandle(m_fileHandle);
            m_fileHandle = NULL;

            m_logger << LogLevel::ERR;
            m_logger << ErrorLogInfo(_T("Error: Cannot create file mapping")) << NL;
            return FALSE;
        }

        m_baseAddress = reinterpret_cast<BYTE*>(MapViewOfFile(m_fileMapping, FILE_MAP_READ, 0, 0, 0));
        if (m_baseAddress == NULL) {
            CloseHandle(m_fileMapping);
            CloseHandle(m_fileHandle);
            m_fileMapping = NULL;
            m_fileHandle = NULL;

            m_logger << LogLevel::ERR;
            m_logger << ErrorLogInfo(_T("Error: Cannot map view of file")) << NL;
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

    tstring PEFileReader::getPEString(QWORD rva) {
        QWORD offset = rva;
        BYTE bytes[2] = { 0, };

        // rva가 raw로 변환가능하다면 TRUE 리턴
        if (setRvaToRawInfo(rva)) {
            // rva를 raw로 변환하고 base 주소를 더함
            QWORD raw = rvaToRaw(rva, reinterpret_cast<QWORD>(m_baseAddress));

            if (CHAR_IS_TCHAR) {
                return (TCHAR*)(raw);
            }
            else {
                // UTF-8로 저장된 문자열을 WCHAR로 변환
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

    tstring PEFileReader::getPEStringNoBase(QWORD rva) {
        QWORD offset = rva;
        BYTE bytes[2] = { 0, };

        // rva가 raw로 변환가능하다면 TRUE 리턴
        if (setRvaToRawInfo(rva)) {
            // rva를 raw로 변환
            QWORD raw = rvaToRaw(rva, 0x0);
            
            if (CHAR_IS_TCHAR) {
                return (TCHAR*)(raw);
            }
            else {
                // UTF-8로 저장된 문자열을 WCHAR로 변환
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
    
    SSIZE_T PEFileReader::readData(QWORD rva, LPVOID bufferAddress, SIZE_T bufferSize) {
        // rva가 raw로 변환가능하다면 TRUE 리턴
        if (setRvaToRawInfo(rva)) {
            // rva를 raw로 변환하고 base 주소를 추가한 값을 리턴
            LPVOID realAddress = (LPVOID)rvaToRaw(rva, (QWORD)m_baseAddress);
            memcpy_s(bufferAddress, bufferSize, realAddress, bufferSize);

            return bufferSize;
        }
        else {
            m_logger << LogLevel::DEBUG;
            m_logger << ErrorLogInfo(format(_T("RVA to RAW fail (rva : 0x{:x})"), rva)) << NL;

            return -1;
        }
    }
    
    SSIZE_T PEFileReader::readDataNoBase(QWORD rva, LPVOID bufferAddress, SIZE_T bufferSize) {
        // rva가 raw로 변환가능하다면 TRUE 리턴
        if (setRvaToRawInfo(rva)) {
            // rva를 raw로 변환, base 주소를 추가하지 않음
            LPVOID realAddress = (LPVOID)rvaToRaw(rva, 0x00);
            memcpy_s(bufferAddress, bufferSize, realAddress, bufferSize);

            return bufferSize;
        }
        else {
            m_logger << LogLevel::DEBUG;
            m_logger << ErrorLogInfo(format(_T("RVA to RAW fail (rva : 0x{:x})"), rva)) << NL;

            return -1;
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