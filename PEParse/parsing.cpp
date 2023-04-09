#include "peparser.h"

using namespace std;

namespace PEParse {
	PEParser::PEParser(LPCSTR filename) {
		parse(filename);

		m_view.type = m_machineType;
		m_view.header = &m_header;
		m_view.body = &m_body;
		m_view.base = m_base;
	}

	PEParser::~PEParser() {
		if (m_fileHandle != NULL) CloseHandle(m_fileHandle);
		if (m_mapping != NULL) CloseHandle(m_mapping);
		if (m_base != NULL) UnmapViewOfFile(m_base);
		if (m_header.sectionHeader != NULL) delete m_header.sectionHeader;
		if (m_body.section != NULL) delete m_body.section;
	}

	void PEParser::parse(LPCSTR filename) {
		readFileAndMapping(filename);
		parseDosHeader();
		parseNTHeaderAndSetMachineType();

		if (m_machineType == x86) parse32();
		else if (m_machineType == x64) parse64();
	}

	void PEParser::readFileAndMapping(LPCSTR filename) {
		m_fileHandle = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

		m_mapping = CreateFileMappingA(m_fileHandle, NULL, PAGE_READONLY, 0, 0, NULL);
		if (m_mapping == NULL) closeAndAbort("fail to execute CreateFileMappingA");

		m_base = MapViewOfFile(m_mapping, FILE_MAP_READ, 0, 0, 0);
		if (m_base == NULL) closeAndAbort("fail to mapping");
	}

	void PEParser::parseDosHeader() {
		m_header.dosHeader = (IMAGE_DOS_HEADER*)m_base;
		if (m_header.dosHeader->e_magic != IMAGE_DOS_SIGNATURE) closeAndAbort("parse fail: DOS_HEADER");
	}

	void PEParser::parseNTHeaderAndSetMachineType() {
		m_header.ntHeader.x86 = (IMAGE_NT_HEADERS32*)((BYTE*)m_base + m_header.dosHeader->e_lfanew);
		if (m_header.ntHeader.x86->Signature != IMAGE_NT_SIGNATURE) closeAndAbort("parse fail: NT_HEADER");

		switch (m_header.ntHeader.x86->FileHeader.Machine) {
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

	void PEParser::parse32() {
		auto ntHeader = m_header.ntHeader.x86;

		WORD sizeOfOptionalHeader = ntHeader->FileHeader.SizeOfOptionalHeader;
		m_header.sectionCount = ntHeader->FileHeader.NumberOfSections;
		BYTE* sectionStartPosition = ((BYTE*)&(ntHeader->OptionalHeader) + sizeOfOptionalHeader);

		m_header.DataDirectory = ntHeader->OptionalHeader.DataDirectory;

		parseSections(sectionStartPosition);
	}
	void PEParser::parse64() {
		auto ntHeader = m_header.ntHeader.x64;
		//아래 코드부터 parse32와 동일
		WORD sizeOfOptionalHeader = ntHeader->FileHeader.SizeOfOptionalHeader;

		m_header.sectionCount = ntHeader->FileHeader.NumberOfSections;
		BYTE* sectionStartPosition = ((BYTE*)&(ntHeader->OptionalHeader) + sizeOfOptionalHeader);

		m_header.DataDirectory = ntHeader->OptionalHeader.DataDirectory;

		parseSections(sectionStartPosition);
	}

	void PEParser::parseSections(BYTE* sectionStartPosition) {
		BYTE* base = (BYTE*)m_base;
		BYTE* position = sectionStartPosition;
		size_t count = m_header.sectionCount;

		IMAGE_SECTION_HEADER** sectionHeader = new IMAGE_SECTION_HEADER*[count + 1];
		BYTE** section = new BYTE*[count + 1];
		for (size_t i = 0; i < count; i++) {
			sectionHeader[i] = (IMAGE_SECTION_HEADER*)(position);
			section[i] = (BYTE*)(base + sectionHeader[i]->PointerToRawData);

			position += sizeof(IMAGE_SECTION_HEADER);
		}

		m_header.sectionHeader = sectionHeader;
		m_body.section = section;
	}

	void PEParser::closeAndAbort(LPCSTR message) {
		tcout << message << endl;
		this->~PEParser();

		exit(1);
	}


	MACHINE_TYPE PEParser::getMachineType() {
		return m_machineType;
	}

	PEHeader PEParser::getPEHeader() {
		return m_header;
	}

	PEBody PEParser::getPEBody() {
		return m_body;
	}

	void PEParser::parseDataDirectory() {
		m_dataDirectoryParser = { &m_view };
		m_dataDirectoryParser.parse();
		//m_dataDirectoryParser.show();
	}
}