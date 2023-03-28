#include "peparser.h"
#include <iostream>


using namespace std;

namespace PEParse {
	void PEParser::Show() {
		if (m_machineType == x86) {
			Show32();
		}
		else if (m_machineType == x64) {
			Show64();
		}
		else {
			tcout << "Show() : nothing to show" << endl;
			return;
		}

		ShowPosition();
		//ShowSectionHeaders();
	}

	LPVOID PEParser::GetStoragePosition(LPVOID position) {
		long long positionPtr = (long long)position;
		long long basePtr = (long long)m_base;

		return (LPVOID)(positionPtr - basePtr);
	}

	void PEParser::ShowPosition() {
		tcout << "Position:" << endl;
		tcout << hex << "  Dos Header: 0x" << GetStoragePosition(m_dosHeader) << endl;
		tcout << hex << "  NT Header : 0x" << GetStoragePosition(m_ntHeader) << endl;

		for (int i = 0; i < m_sectionCount; i++) {
			auto header = m_sectionHeader[i];
			tcout << "  section header (" << (char*)header->Name << ") : 0x" << GetStoragePosition(header) << endl;
		}

		for (int i = 0; i < m_sectionCount; i++) {
			auto header = m_sectionHeader[i];
			auto section = m_section[i];
			tcout << "  sections (" << (char*)header->Name << ") : 0x" << GetStoragePosition(section) << endl;
		}
	}

	void PEParser::Show32() {
		auto ntHeader = (IMAGE_NT_HEADERS32*)m_ntHeader;
		tcout << "PE header information:" << endl;
		tcout << hex << "  Machine type: 0x" << ntHeader->FileHeader.Machine << endl;
		tcout << dec << "  Number of sections: " << ntHeader->FileHeader.NumberOfSections << endl;
		tcout << hex << "  Timestamp: 0x" << ntHeader->FileHeader.TimeDateStamp << endl;
		tcout << hex << "  Entry point address: 0x" << ntHeader->OptionalHeader.AddressOfEntryPoint << endl;
		tcout << hex << "  ImageBase address: 0x" << ntHeader->OptionalHeader.ImageBase << endl;
		tcout << dec << "  Section alignment: " << ntHeader->OptionalHeader.SectionAlignment << endl;
		tcout << dec << "  File alignment: " << ntHeader->OptionalHeader.FileAlignment << endl;
		tcout << dec << "  Size of image: " << ntHeader->OptionalHeader.SizeOfImage << endl;
		tcout << dec << "  Size of headers: " << ntHeader->OptionalHeader.SizeOfHeaders << endl;
		tcout << dec << "  Subsystem: " << ntHeader->OptionalHeader.Subsystem << endl;
		tcout << dec << "  Number of RVA and sizes: " << ntHeader->OptionalHeader.NumberOfRvaAndSizes << endl;
		tcout << dec;
		tcout << endl;
	}

	void PEParser::Show64() {
		auto ntHeader = (IMAGE_NT_HEADERS64*)m_ntHeader;
		tcout << "PE header information:" << endl;
		tcout << hex << "  Machine type: 0x" << ntHeader->FileHeader.Machine << endl;
		tcout << dec << "  Number of sections: " << ntHeader->FileHeader.NumberOfSections << endl;
		tcout << hex << "  Timestamp: 0x" << ntHeader->FileHeader.TimeDateStamp << endl;
		tcout << hex << "  Entry point address: 0x" << ntHeader->OptionalHeader.AddressOfEntryPoint << endl;
		tcout << hex << "  ImageBase address: 0x" << ntHeader->OptionalHeader.ImageBase << endl;
		tcout << dec << "  Section alignment: " << ntHeader->OptionalHeader.SectionAlignment << endl;
		tcout << dec << "  File alignment: " << ntHeader->OptionalHeader.FileAlignment << endl;
		tcout << dec << "  Size of image: " << ntHeader->OptionalHeader.SizeOfImage << endl;
		tcout << dec << "  Size of headers: " << ntHeader->OptionalHeader.SizeOfHeaders << endl;
		tcout << dec << "  Subsystem: " << ntHeader->OptionalHeader.Subsystem << endl;
		tcout << dec << "  Number of RVA and sizes: " << ntHeader->OptionalHeader.NumberOfRvaAndSizes << endl;
		tcout << dec;
		tcout << endl;
	}

	void PEParser::ShowSectionHeaders() {
		tcout << "Section Headers (" << m_sectionCount << ")" << endl;
		for (int i = 0; i < m_sectionCount; i++) {
			IMAGE_SECTION_HEADER* header = m_sectionHeader[i];
			printf("[%d] %s\n", i, header->Name);
			printf("     Size of rawdata: (0x%x)\n", header->SizeOfRawData);
			printf("     Pointer to rawdata : (0x%x)\n", header->PointerToRawData);
			printf("     Virtual size : (0x%x)\n", header->VirtualAddress);
			printf("     Characteristics : (0x%x)\n", header->Characteristics);
		}
	}
}