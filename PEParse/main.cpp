#include <stdio.h>
#include <windows.h>

HANDLE HFile = NULL;
HANDLE HMapping = NULL;
LPVOID LPBase = NULL;

IMAGE_DOS_HEADER* DosHeader;
IMAGE_NT_HEADERS* NTHeader;

void Close(const char* message) {
	printf("%s\n", message);
	if (HFile != NULL) CloseHandle(HFile);
	if (HMapping != NULL) CloseHandle(HMapping);
	if (LPBase != NULL) UnmapViewOfFile(LPBase);

	exit(1);
}

void Show() {
	WORD magic = NTHeader->OptionalHeader.Magic;
	if (magic == 0x010B) printf("x86\n");
	else if (magic == 0x020B) printf("x64\n");
	else printf("neither x86 nor x64\n");

	printf("MACHINE Type 0x%x\n", NTHeader->FileHeader.Machine);
	printf("NumberOfSection 0x%x\n", NTHeader->FileHeader.NumberOfSections);
	printf("TimeStamp 0x%x\n", NTHeader->FileHeader.TimeDateStamp);
}

void Parse(char* file) {
	HFile = CreateFileA(file, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	HMapping = CreateFileMappingA(HFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (HMapping == NULL) Close("fail to execute CreateFileMappingA");

	LPBase = MapViewOfFile(HMapping, FILE_MAP_READ, 0, 0, 0);
	if (LPBase == NULL) Close("fail to mapping");

	DosHeader = (IMAGE_DOS_HEADER*)LPBase;
	if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE) Close("parse fail: DOS_HEADER");

	NTHeader = (IMAGE_NT_HEADERS*)((BYTE*)LPBase + DosHeader->e_lfanew);
	if (NTHeader->Signature != IMAGE_NT_SIGNATURE) Close("parse fail: NT_HEADER");


	WORD sizeOfOptionalHeader = NTHeader->FileHeader.SizeOfOptionalHeader;
	int sectionCount = NTHeader->FileHeader.SizeOfOptionalHeader;
	int textSectionSize = NTHeader->OptionalHeader.SizeOfCode;
	int numberOfSection = NTHeader->FileHeader.NumberOfSections;


}

int main(int argc, char* argv[]) {
	Parse(argv[1]);
	Show();
}

