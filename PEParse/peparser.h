#pragma once
#include <stdio.h>
#include <windows.h>
#include <tchar.h>
#include <iostream>

typedef std::basic_string<TCHAR> tstring;
#if defined(UNICODE) || defined(_UNICODE)
	#define tcout std::wcout
	#define OutputDebugStringT OutputDebugStringW;
#else
	#define tcout std::cout
	#define OutputDebugStringT OutputDebugStringA;
#endif

namespace PEParse {
	enum MACHINE_TYPE {
		x64,
		x86,
		other,
	};

	/*
	typedef struct {
		tstring sectionName;
		DWORD VirtualAddress;
		DWORD PointerToRawData;
		DWORD SizeOfRawData;
	};/**/

	typedef struct {
		IMAGE_DOS_HEADER* dosHeader;
		union {
			IMAGE_NT_HEADERS32* x86;
			IMAGE_NT_HEADERS64* x64;
		} ntHeader;
		IMAGE_SECTION_HEADER** sectionHeader;
		IMAGE_DATA_DIRECTORY* DataDirectory;
		int sectionCount;
	} PEHeader;

	typedef struct {
		BYTE* dosStub;
		BYTE** section;
	} PEBody;

	typedef struct {
		PEHeader* header;
		PEBody* body;
		MACHINE_TYPE type;
		LPVOID base;
	} PEView;

	class PEDataDirectoryParser {
	private:
		static const char* directoryName[16];
		PEView* m_view;
		IMAGE_DATA_DIRECTORY* m_dataDirectory;
		bool m_dataDirectoryExists[16] = { 0, };
		DWORD m_virtualAddress = 0;
		DWORD m_pointerOfRawData = 0;

		void initDataDirectory();
		DWORD getRAW(DWORD, int);
		int findHeader(DWORD);
	public:
		PEDataDirectoryParser();
		PEDataDirectoryParser(PEView*);
		void setDataDirectory(IMAGE_DATA_DIRECTORY*);

		void parseExportDirectory();
		void show();
	};

	class PEParser {
	private:
		PEView m_view;
		PEHeader m_header;
		PEBody m_body;
		PEDataDirectoryParser m_dataDirectoryParser;
		MACHINE_TYPE m_machineType = other;
		HANDLE m_fileHandle = NULL;
		HANDLE m_mapping = NULL;
		LPVOID m_base = NULL;

		void readFileAndMapping(LPCSTR);
		void parseDosHeader();
		void parse32();
		void parse64();
		void show32();
		void show64();
		void closeAndAbort(LPCSTR);
		void parseSections(BYTE*, BYTE*);
		void parseNTHeaderAndSetMachineType();
		LPVOID getDiskPosition(LPVOID);
		void showBuffer(BYTE*, size_t size);
	public:
		PEParser(LPCSTR);
		~PEParser();
		void parse(LPCSTR);
		void show();
		void showSectionHeaders();
		void showPosition();
		PEHeader getPEHeader();
		PEBody getPEBody();
		void parseDataDirectory();

		MACHINE_TYPE getMachineType();
	};

	void printBuffer(BYTE*, size_t);
}