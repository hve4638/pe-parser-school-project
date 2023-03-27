#include "peparser.h"

HANDLE HFile = NULL;
HANDLE HMapping = NULL;
LPVOID LPBase = NULL;

IMAGE_DOS_HEADER* DosHeader = NULL;
IMAGE_NT_HEADERS32* NTHeader32 = NULL;
IMAGE_NT_HEADERS64* NTHeader64 = NULL;
IMAGE_SECTION_HEADER* SectionHeader[128];
int SectionCount = 0;
BYTE* Section[128] = { 0 };

void ParseDosHeader(const char*);
void ParseSections(BYTE*, BYTE*, size_t);
int Is32Bit();

void Close(const char* message) {
	printf("%s\n", message);
	if (HFile != NULL) CloseHandle(HFile);
	if (HMapping != NULL) CloseHandle(HMapping);
	if (LPBase != NULL) UnmapViewOfFile(LPBase);

	exit(1);
}

void Parse(const char* file) {
	ParseDosHeader(file);

	if (Is32Bit()) {
		
		Parse32();
	}
	else {
		Parse64();
	}
	
}

void ParseDosHeader(const char* file) {
	HFile = CreateFileA(file, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	HMapping = CreateFileMappingA(HFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (HMapping == NULL) Close("fail to execute CreateFileMappingA");

	LPBase = MapViewOfFile(HMapping, FILE_MAP_READ, 0, 0, 0);
	if (LPBase == NULL) Close("fail to mapping");

	DosHeader = (IMAGE_DOS_HEADER*)LPBase;
	if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE) Close("parse fail: DOS_HEADER");
}

int Is32Bit() {
	IMAGE_NT_HEADERS32* ntHeader;
	ntHeader = (IMAGE_NT_HEADERS32*)((BYTE*)LPBase + DosHeader->e_lfanew);
	if (ntHeader->Signature != IMAGE_NT_SIGNATURE) Close("parse fail: NT_HEADER32 in Is32Bit()");

	WORD magic = ntHeader->OptionalHeader.Magic;
	if (magic == 0x010B) { //x86
		return 1;
	}
	else if (magic == 0x020B) { // x64
		return 0;
	}
	else {
		return -1;
	}
}

void Parse32() {
	IMAGE_NT_HEADERS32* ntHeader;
	ntHeader = (IMAGE_NT_HEADERS32*)((BYTE*)LPBase + DosHeader->e_lfanew);
	if (ntHeader->Signature != IMAGE_NT_SIGNATURE) Close("parse fail: NT_HEADER32");

	NTHeader32 = ntHeader;

	WORD sizeOfOptionalHeader = ntHeader->FileHeader.SizeOfOptionalHeader;
	DWORD sizeOfHeader = ntHeader->OptionalHeader.SizeOfHeaders;
	int textSectionSize = ntHeader->OptionalHeader.SizeOfCode;

	SectionCount = ntHeader->FileHeader.NumberOfSections;
	BYTE* bodyStartPosition = (BYTE*)LPBase;
	BYTE* sectionStartPosition = ((BYTE*)&(ntHeader->OptionalHeader) + sizeOfOptionalHeader);

	ParseSections(sectionStartPosition, bodyStartPosition, SectionCount);
}

void Parse64() {
	IMAGE_NT_HEADERS64* ntHeader;
	ntHeader = (IMAGE_NT_HEADERS64*)((BYTE*)LPBase + DosHeader->e_lfanew);
	if (ntHeader->Signature != IMAGE_NT_SIGNATURE) Close("parse fail: NT_HEADER64");

	NTHeader64 = ntHeader;

	WORD sizeOfOptionalHeader = ntHeader->FileHeader.SizeOfOptionalHeader;
	DWORD sizeOfHeader = ntHeader->OptionalHeader.SizeOfHeaders;
	int textSectionSize = ntHeader->OptionalHeader.SizeOfCode;

	SectionCount = ntHeader->FileHeader.NumberOfSections;
	BYTE* bodyStartPosition = (BYTE*)LPBase;
	BYTE* sectionStartPosition = ((BYTE*)&(ntHeader->OptionalHeader) + sizeOfOptionalHeader);

	ParseSections(sectionStartPosition, bodyStartPosition, SectionCount);
}

void ParseSections(BYTE* sectionStartPosition, BYTE* bodyStartPosition, size_t count) {
	BYTE* position = sectionStartPosition;

	for (size_t i = 0; i < count; i++) {
		SectionHeader[i] = (IMAGE_SECTION_HEADER*)(position);
		Section[i] = (BYTE*)(bodyStartPosition + SectionHeader[i]->PointerToRawData);

		position += sizeof(IMAGE_SECTION_HEADER);
	}
}