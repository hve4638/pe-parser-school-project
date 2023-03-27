#pragma once
#include <stdio.h>
#include <windows.h>
#include <tchar.h>
#include <iostream>

typedef std::basic_string<TCHAR> tstring;
#if defined(UNICODE) || defined(_UNICODE)
	#define tcout std::wout
	#define OutputDebugStringT OutputDebugStringW;
#else
	#define tcout std::cout
	#define OutputDebugStringT OutputDebugStringA;
#endif

enum MACHINE_TYPE {
	x64,
	x86,
	other,
};

extern IMAGE_DOS_HEADER* DosHeader;
extern IMAGE_NT_HEADERS32* NTHeader32;
extern IMAGE_NT_HEADERS64* NTHeader64;

extern int SectionCount;
extern IMAGE_SECTION_HEADER* SectionHeader[128];
extern BYTE* Section[128];

extern void Show();
extern void Show32();
extern void Show64();
extern void ShowSection(int);

extern void Parse(const char*);
extern void Parse32();
extern void Parse64();

class PEParser {
private:
	MACHINE_TYPE m_machineType = other;
	HANDLE m_fileHandle = NULL;
	HANDLE m_mapping = NULL;
	LPVOID m_base = NULL;
	IMAGE_DOS_HEADER* m_dosHeader = NULL;
	IMAGE_NT_HEADERS32* m_ntHeader = NULL;
	IMAGE_NT_HEADERS32* m_ntHeader32 = NULL;
	IMAGE_NT_HEADERS64* m_ntHeader64 = NULL;

	int m_sectionCount;
	IMAGE_SECTION_HEADER* m_sectionHeader[128];
	BYTE* m_section[128];

	void ReadFileAndMapping(LPCSTR);
	void ParseDosHeader();
	void Parse32();
	void Parse64();
	void Show32();
	void Show64();
	void CloseAndAbort(LPCSTR);
	void ParseSections(BYTE*, BYTE*, size_t);
	void ParseNTHeaderAndSetMachineType();
public:
	PEParser(LPCSTR);
	~PEParser();
	void Parse(LPCSTR);
	void Show();
	MACHINE_TYPE GetMachineType();
};