//#include <iostream>
#include <format>
#include "PEFileReader.h"
#include "PEUtils.h"

using namespace PEUtils;

namespace PEParse {
    QWORD PEFileReader::rvaToRaw(QWORD rva, QWORD addPosition = 0) {
        // RAW = RVA - VirtualAddress + PointerToRawData
        if (addPosition != 0) {
            return addPosition + (rva - m_rawInfo.virtualAddress + m_rawInfo.pointerToRawData);
        }
        else {
            return (rva - m_rawInfo.virtualAddress + m_rawInfo.pointerToRawData);
        }
    }


    BOOL PEFileReader::setRvaToRawInfo(QWORD rva) {
        if (m_sectionInfo.headerAddress == NULL) {
            // rvaToRaw를 위한 정보를 업데이트
            updateSectionInfo();
        }
        
        // rva 주소가 PEHeader 부분일 경우
        // PEHeader의 rva은 raw와 동일
        if (rva < m_sectionInfo.sizeOfHeaders) {
            m_rawInfo.startAddress = 0;
            m_rawInfo.endAddress = 0;
            m_rawInfo.virtualAddress = 0;
            m_rawInfo.pointerToRawData = 0;

            return TRUE;
        }
        // 이미 변환 준비가 되었을때
        else if (rva >= m_rawInfo.startAddress && rva < m_rawInfo.endAddress) { 
            return TRUE;
        }
        else {
            return tryUpdateRawInfo(rva);
        }
    }

    // SectionHeader 정보를 멤버변수에 저장
    void PEFileReader::updateSectionInfo() {
        IMAGE_NT_HEADERS32* pNtHeader32 = reinterpret_cast<IMAGE_NT_HEADERS32*>(m_baseAddress + (LONG)((IMAGE_DOS_HEADER*)m_baseAddress)->e_lfanew);

        if (pNtHeader32->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
            IMAGE_NT_HEADERS64* pNtHeader64 = reinterpret_cast<IMAGE_NT_HEADERS64*>(m_baseAddress + (LONG)((IMAGE_DOS_HEADER*)m_baseAddress)->e_lfanew);
            
            m_sectionInfo.sizeOfHeaders = pNtHeader64->OptionalHeader.SizeOfHeaders;
            m_sectionInfo.numberOfSections = pNtHeader64->FileHeader.NumberOfSections;
            m_sectionInfo.headerAddress = reinterpret_cast<PIMAGE_SECTION_HEADER>((PBYTE)pNtHeader64 + sizeof(IMAGE_NT_HEADERS64));
        }
        else {
            m_sectionInfo.sizeOfHeaders = pNtHeader32->OptionalHeader.SizeOfHeaders;
            m_sectionInfo.numberOfSections = pNtHeader32->FileHeader.NumberOfSections;
            m_sectionInfo.headerAddress = reinterpret_cast<PIMAGE_SECTION_HEADER>((PBYTE)pNtHeader32 + sizeof(IMAGE_NT_HEADERS32));
        }
    }

    BOOL PEFileReader::tryUpdateRawInfo(QWORD rva) {
        m_rawInfo.startAddress = 0;
        m_rawInfo.endAddress = 0;
        m_rawInfo.virtualAddress = 0;
        m_rawInfo.pointerToRawData = 0;

        /*
            각 섹션의 VirtualAddress부터 Virtualaddress + SizeOfRawData 범위 내에 있는지 체크후 rawInfo 설정
            VirtualSize내에 포함되어도 SizeOfRawData를 벗어난다면 raw를 정의할 수 없음
            어떤 섹션의 범위에도 포함되지 않는다면 raw로 변환할 수 없음
        */
        auto count = m_sectionInfo.numberOfSections;
        for (DWORD i = 0; i < count; i++) {
            IMAGE_SECTION_HEADER& header = (m_sectionInfo.headerAddress[i]);

            QWORD rangeStart = header.VirtualAddress;
            QWORD rangeEnd = rangeStart + header.SizeOfRawData;
            if (rva >= rangeStart && rva < rangeEnd) {
                m_rawInfo.startAddress = (ULONGLONG)header.VirtualAddress;
                m_rawInfo.endAddress = (ULONGLONG)m_rawInfo.startAddress + header.SizeOfRawData;
                m_rawInfo.virtualAddress = (ULONGLONG)header.VirtualAddress;
                m_rawInfo.pointerToRawData = (ULONGLONG)header.PointerToRawData;

                return TRUE;
            }
        }
        return FALSE;
    }
}