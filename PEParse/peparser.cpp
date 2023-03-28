#include "peparser.h"

using namespace std;

namespace PEParse {
	PEParser::PEParser(LPCSTR filename) {
		Parse(filename);
	}

	void PEParser::Parse(LPCSTR filename) {
		ReadFileAndMapping(filename);
		ParseDosHeader();
		ParseNTHeaderAndSetMachineType();

		if (m_machineType == x86) Parse32();
		else if (m_machineType == x64) Parse64();
	}

	void PEParser::ParseDosHeader() {
		m_dosHeader = (IMAGE_DOS_HEADER*)m_base;
		if (m_dosHeader->e_magic != IMAGE_DOS_SIGNATURE) CloseAndAbort("parse fail: DOS_HEADER");
	}
	void PEParser::ParseNTHeaderAndSetMachineType() {
		m_ntHeader = (IMAGE_NT_HEADERS32*)((BYTE*)m_base + m_dosHeader->e_lfanew);
		if (m_ntHeader->Signature != IMAGE_NT_SIGNATURE) CloseAndAbort("parse fail: NT_HEADER");

		switch (m_ntHeader->FileHeader.Machine) {
		case IMAGE_FILE_MACHINE_I386:
			m_machineType = x86;
			break;
		case IMAGE_FILE_MACHINE_IA64:
		case IMAGE_FILE_MACHINE_AMD64:
			m_machineType = x64;
			break;
		default:
			m_machineType = other;
		}
	}

	void PEParser::Parse32() {
		auto ntHeader = (IMAGE_NT_HEADERS32*)m_ntHeader;

		WORD sizeOfOptionalHeader = ntHeader->FileHeader.SizeOfOptionalHeader;
		DWORD sizeOfHeader = ntHeader->OptionalHeader.SizeOfHeaders;
		int textSectionSize = ntHeader->OptionalHeader.SizeOfCode;

		m_sectionCount = ntHeader->FileHeader.NumberOfSections;
		BYTE* bodyStartPosition = (BYTE*)m_base;
		BYTE* sectionStartPosition = ((BYTE*)&(ntHeader->OptionalHeader) + sizeOfOptionalHeader);

		ParseSections(sectionStartPosition, bodyStartPosition, m_sectionCount);
	}
	void PEParser::Parse64() {
		auto ntHeader = (IMAGE_NT_HEADERS64*)m_ntHeader;

		WORD sizeOfOptionalHeader = ntHeader->FileHeader.SizeOfOptionalHeader;
		DWORD sizeOfHeader = ntHeader->OptionalHeader.SizeOfHeaders;
		int textSectionSize = ntHeader->OptionalHeader.SizeOfCode;

		m_sectionCount = ntHeader->FileHeader.NumberOfSections;
		BYTE* bodyStartPosition = (BYTE*)m_base;
		BYTE* sectionStartPosition = ((BYTE*)&(ntHeader->OptionalHeader) + sizeOfOptionalHeader);

		ParseSections(sectionStartPosition, bodyStartPosition, m_sectionCount);
	}

	void PEParser::ReadFileAndMapping(LPCSTR filename) {
		m_fileHandle = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

		m_mapping = CreateFileMappingA(m_fileHandle, NULL, PAGE_READONLY, 0, 0, NULL);
		if (m_mapping == NULL) CloseAndAbort("fail to execute CreateFileMappingA");

		m_base = MapViewOfFile(m_mapping, FILE_MAP_READ, 0, 0, 0);
		if (m_base == NULL) CloseAndAbort("fail to mapping");
	}

	void PEParser::ParseSections(BYTE* sectionStartPosition, BYTE* bodyStartPosition, size_t count) {
		BYTE* position = sectionStartPosition;

		for (size_t i = 0; i < count; i++) {
			m_sectionHeader[i] = (IMAGE_SECTION_HEADER*)(position);
			m_section[i] = (BYTE*)(bodyStartPosition + m_sectionHeader[i]->PointerToRawData);

			position += sizeof(IMAGE_SECTION_HEADER);
		}
	}

	void PEParser::CloseAndAbort(LPCSTR message) {
		cout << message << endl;
		this->~PEParser();

		exit(1);
	}

	PEParser::~PEParser() {
		if (m_fileHandle != NULL) CloseHandle(m_fileHandle);
		if (m_mapping != NULL) CloseHandle(m_mapping);
		if (m_base != NULL) UnmapViewOfFile(m_base);
	}


	MACHINE_TYPE PEParser::GetMachineType() {
		return m_machineType;
	}
}