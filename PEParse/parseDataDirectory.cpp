#include "peparser.h"

using namespace std;

namespace PEParse {
	const char* PEDataDirectoryParser::directoryName[16] = {
		"Export Directory",
		"Import Directory",
		"RESOURCE Directory",
		"EXCEPTION Directory",
		"SECURITY Directory",
		"BASERLOC Directory",
		"DEBUG Directory",
		"COPYRIGHT Directory",
		"GLOBALPTR Directory",
		"TLS Directory",
		"LOAD_CONFIG Directory",
		"BOUND_IMPORT Directory",
		"IAT Directory",
		"DELAY Directory",
		"COM Directory",
		"Reversed Directory",
	};

	PEDataDirectoryParser::PEDataDirectoryParser() {

	}
	PEDataDirectoryParser::PEDataDirectoryParser(PEView *view) {
		m_view = view;
		initDataDirectory();
	}
	void PEDataDirectoryParser::initDataDirectory() {
		if (m_view->type == x64) m_dataDirectory = m_view->header->ntHeader.x64->OptionalHeader.DataDirectory;
		else if (m_view->type == x86) m_dataDirectory = m_view->header->ntHeader.x86->OptionalHeader.DataDirectory;
		else throw "file is neither x86 nor x64";

		//m_virtualAddress = m_view->header->ntHeader->;
		//m_pointerOfRawData = 0;
	}

	DWORD PEDataDirectoryParser::getRAW(DWORD RVA, int headerIndex) {
		IMAGE_SECTION_HEADER *header = m_view->header->sectionHeader[headerIndex];
		return RVA - header->VirtualAddress + header->PointerToRawData;
	}

	void PEDataDirectoryParser::setDataDirectory(IMAGE_DATA_DIRECTORY* dataDirectory) {
		m_dataDirectory = dataDirectory;
	}

	void PEDataDirectoryParser::parseExportDirectory() {
		DWORD rva = m_dataDirectory[0].VirtualAddress;
		DWORD size = m_dataDirectory[0].Size;
		long long base = (DWORD)m_view->base;

		if (rva == NULL) {
			tcout << "no" << endl;
		}
		else {
			int index = findHeader(rva);
			auto raw = getRAW(rva, index);
			IMAGE_EXPORT_DIRECTORY* exportDirectory = (IMAGE_EXPORT_DIRECTORY*)(raw + base);
			
			tcout << hex;
			tcout << "RVA - " << rva << endl;
			tcout << "RAW - " << raw << endl;
			tcout << "result : " << exportDirectory << endl;
			tcout << "base: " << base << endl;

			tcout << dec;
			tcout << "index - " << index << endl;


			printBuffer((BYTE*)exportDirectory, size);
		}
	}

	void PEDataDirectoryParser::show() {
		
		tcout << "DataDirectory" << endl;
		for (int i = 0; i < 16; i++) {
			tcout << "------------------------------------" << endl;
			tcout << "  " << directoryName[i] << endl;
			tcout << "    RVA : 0x" << hex << m_dataDirectory[i].VirtualAddress << dec << endl;
			tcout << "    Size: " << m_dataDirectory[i].Size << endl;
		}

	}

	int PEDataDirectoryParser::findHeader(DWORD RVA) {
		int count = m_view->header->sectionCount;
		for (int i = 1; i < count; i++) {
			IMAGE_SECTION_HEADER* header = m_view->header->sectionHeader[i];
			DWORD vaBegin = header->VirtualAddress;// -header->PointerToRawData;
			DWORD vaEnd = vaBegin + header->SizeOfRawData;
			tcout << hex;
			tcout << vaBegin << " <= " << RVA << " < " << vaEnd << endl;
			tcout << dec;

			if (RVA >= vaBegin && RVA < vaEnd) return i;
		}
		
		return -1;
	}
}