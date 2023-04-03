#include "peparser.h"
#include <iostream>

using namespace std;

namespace PEParse {
	void PEParser::showBuffer(BYTE* buffer, size_t size) {
		for (size_t i = 0; i < size; i += 16) {
			for (size_t j = i; j < size && j < i + 16; j++) {
				printf("%02x ", buffer[j]);
				if (j % 8 == 7) printf(" ");
			}
			for (size_t j = i; j < size && j < i + 16; j++) {
				char ch = buffer[j];
				if (isprint(ch)) printf("%c", ch);
				else printf(".");
			}

			printf("\n");
		}
	}

	void PEParser::show() {
		if (m_machineType == x86) {
			show32();
		}
		else if (m_machineType == x64) {
			show64();
		}
		else {
			tcout << "show() : nothing to show" << endl;
			return;
		}

		showPosition();
	}

	LPVOID PEParser::getDiskPosition(LPVOID position) {
		long long positionPtr = (long long)position;
		long long basePtr = (long long)m_base;

		return (LPVOID)(positionPtr - basePtr);
	}

	void PEParser::showPosition() {
		tcout << "Position:" << endl;
		tcout << hex << "  Dos Header: 0x" << getDiskPosition(m_header.dosHeader) << endl;
		tcout << hex << "  NT Header : 0x" << getDiskPosition(m_header.ntHeader.x64) << endl;

		for (int i = 0; i < m_header.sectionCount; i++) {
			auto header = m_header.sectionHeader[i];
			tcout << "  section header (" << (char*)header->Name << ") : 0x" << getDiskPosition(header) << endl;
		}

		for (int i = 0; i < m_header.sectionCount; i++) {
			auto header = m_header.sectionHeader[i];
			auto section = m_body.section[i];
			tcout << "  sections (" << (char*)header->Name << ") : 0x" << getDiskPosition(section) << endl;
		}
	}

	void PEParser::show32() {
		auto ntHeader = m_header.ntHeader.x86;
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

	void PEParser::show64() {
		auto ntHeader = m_header.ntHeader.x64;
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

	void PEParser::showSectionHeaders() {
		tcout << "Section Headers (" << m_header.sectionCount << ")" << endl;
		for (int i = 0; i < m_header.sectionCount; i++) {
			IMAGE_SECTION_HEADER* header = m_header.sectionHeader[i];
			printf("[%d] %s\n", i, header->Name);
			printf("     Size of rawdata: (0x%x)\n", header->SizeOfRawData);
			printf("     Pointer to rawdata : (0x%x)\n", header->PointerToRawData);
			printf("     Virtual size : (0x%x)\n", header->VirtualAddress);
			printf("     Characteristics : (0x%x)\n", header->Characteristics);
		}
	}
}