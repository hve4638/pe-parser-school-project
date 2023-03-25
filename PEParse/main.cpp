#include <stdio.h>
#include <windows.h>
#include <assert.h>

HANDLE HFile = NULL;
HANDLE HMapping = NULL;
LPVOID LPBase = NULL;

IMAGE_DOS_HEADER* DosHeader;
IMAGE_NT_HEADERS32* NTHeader32;
IMAGE_NT_HEADERS64* NTHeader64;
IMAGE_SECTION_HEADER* SectionHeader[128];
int SectionCount = 0;
BYTE* Section[128] = { 0 };

void Show();
void Show32();
void ShowSection(int);
void Close(const char*);
void Parse(char*);
BYTE* ReadSection(BYTE*, size_t);
void ParseDosHeader(char*);
void Parse32();
void Parse64();

void Close(const char* message) {
	printf("%s\n", message);
	if (HFile != NULL) CloseHandle(HFile);
	if (HMapping != NULL) CloseHandle(HMapping);
	if (LPBase != NULL) UnmapViewOfFile(LPBase);

	exit(1);
}

void Show() {
	Show32();
}
void Show32() {
	WORD magic = NTHeader32->OptionalHeader.Magic;
	if (magic == 0x010B) printf("x86\n");
	else if (magic == 0x020B) printf("x64\n");
	else printf("neither x86 nor x64\n");

	printf("MACHINE Type 0x%x\n", NTHeader32->FileHeader.Machine);
	printf("NumberOfSection 0x%x\n", NTHeader32->FileHeader.NumberOfSections);
	printf("TimeStamp 0x%x\n", NTHeader32->FileHeader.TimeDateStamp);

	printf("\nSection\n");
	for (int i = 0; i < SectionCount; i++) {
		printf("[%d] %s (0x%p)\n", i, SectionHeader[i]->Name, Section[i]);
	}

	ShowSection(7);

	return;
}

int CanShow(char ch) {
	switch (ch) {
	case 0x20:
	case 0x0d:
	case 0x0a:
		return false;
	default:
		return true;
	}
}

void ShowSection(int index) {
	BYTE* position = Section[index];
	size_t size = SectionHeader[index]->SizeOfRawData;
	printf("\nSection [%s]\n", SectionHeader[index]->Name);
	printf("StartPosition : 0x%p\n", position);
	printf("Size: %d\n", size);

	for (size_t i = 0; i < size; i += 16) {
		for (size_t j = i; j < size && j < i + 16; j++) {
			printf("%02x ", position[j]);
			if (j % 8 == 7) printf(" ");
		}
		for (size_t j = i; j < size && j < i + 16; j++) {
			char ch = position[j];
			if (CanShow(ch)) printf("%c", ch);
			else printf(" ");
		}

		printf("\n");
	}
}

void Parse(char* file) {
	ParseDosHeader(file);

	Parse32();
}

void ParseDosHeader(char* file) {
	HFile = CreateFileA(file, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	HMapping = CreateFileMappingA(HFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (HMapping == NULL) Close("fail to execute CreateFileMappingA");

	LPBase = MapViewOfFile(HMapping, FILE_MAP_READ, 0, 0, 0);
	if (LPBase == NULL) Close("fail to mapping");

	DosHeader = (IMAGE_DOS_HEADER*)LPBase;
	if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE) Close("parse fail: DOS_HEADER");
}

void Parse32() {
	IMAGE_NT_HEADERS32* ntHeader;
	ntHeader = (IMAGE_NT_HEADERS32*)((BYTE*)LPBase + DosHeader->e_lfanew);
	if (ntHeader->Signature != IMAGE_NT_SIGNATURE) Close("parse fail: NT_HEADER");

	WORD sizeOfOptionalHeader = ntHeader->FileHeader.SizeOfOptionalHeader;
	DWORD sizeOfHeader = ntHeader->OptionalHeader.SizeOfHeaders;
	int textSectionSize = ntHeader->OptionalHeader.SizeOfCode;

	SectionCount = ntHeader->FileHeader.NumberOfSections;

	BYTE* sectionStartPosition = (BYTE*)LPBase;// +sizeOfHeader;
	BYTE* position = ((BYTE*)&(ntHeader->OptionalHeader) + sizeOfOptionalHeader);

	for (int i = 0; i < SectionCount; i++) {
		SectionHeader[i] = (IMAGE_SECTION_HEADER*)(position);
		Section[i] = ReadSection((BYTE*)(sectionStartPosition + SectionHeader[i]->PointerToRawData), SectionHeader[i]->SizeOfRawData);

		position += sizeof(IMAGE_SECTION_HEADER);
	}
}

void Parse64() {
	IMAGE_NT_HEADERS64* ntHeader;
	ntHeader = (IMAGE_NT_HEADERS64*)((BYTE*)LPBase + DosHeader->e_lfanew);
	if (ntHeader->Signature != IMAGE_NT_SIGNATURE) Close("parse fail: NT_HEADER");

	WORD sizeOfOptionalHeader = ntHeader->FileHeader.SizeOfOptionalHeader;
	DWORD sizeOfHeader = ntHeader->OptionalHeader.SizeOfHeaders;
	int textSectionSize = ntHeader->OptionalHeader.SizeOfCode;

	SectionCount = ntHeader->FileHeader.NumberOfSections;

	BYTE* sectionStartPosition = (BYTE*)LPBase;// +sizeOfHeader;
	BYTE* position = ((BYTE*)&(ntHeader->OptionalHeader) + sizeOfOptionalHeader);

	for (int i = 0; i < SectionCount; i++) {
		SectionHeader[i] = (IMAGE_SECTION_HEADER*)(position);
		Section[i] = ReadSection((BYTE*)(sectionStartPosition + SectionHeader[i]->PointerToRawData), SectionHeader[i]->SizeOfRawData);

		position += sizeof(IMAGE_SECTION_HEADER);
	}
}

BYTE* ReadSection(BYTE* position, size_t size) {
	BYTE* section = (BYTE*)malloc(sizeof(BYTE) * size);
	assert(section != 0);
	memset(section, 0xFF, sizeof(BYTE) * size);

	for (size_t i = 0; i < size; i++) {
		section[i] = position[i];
	}

	return section;
}

int main(int argc, char* argv[]) {
	Parse(argv[0]);
	Show();
}

