#include "peparser.h"

const char* GetMachineType(WORD optionalHeaderMagic) {
	switch (optionalHeaderMagic) {
	case 0x010B:
		return "x86";
	case 0x020B:
		return "x64";
	default:
		return "neither x86 nor x64";
	}
}


void Show() {
	if (NTHeader32 != NULL) {
		Show32();
	}
	else if (NTHeader64 != NULL) {
		Show64();
	}
	else {
		printf("Show() : nothing to show");
	}
}

void Show32() {
	IMAGE_NT_HEADERS32* ntHeader = NTHeader32;
	printf("PE header information:\n");
	printf("  Target: %s\n", GetMachineType(ntHeader->OptionalHeader.Magic));
	printf("  Machine type: 0x%x\n", ntHeader->FileHeader.Machine);
	printf("  Number of sections: %d\n", ntHeader->FileHeader.NumberOfSections);
	printf("  Timestamp: 0x%x\n", ntHeader->FileHeader.TimeDateStamp);
	printf("  Entry point address: 0x%x\n", ntHeader->OptionalHeader.AddressOfEntryPoint);
	printf("  Image base address: 0x%x\n", ntHeader->OptionalHeader.ImageBase);
	printf("  Section alignment: %d\n", ntHeader->OptionalHeader.SectionAlignment);
	printf("  File alignment: %d\n", ntHeader->OptionalHeader.FileAlignment);
	printf("  Size of image: %d\n", ntHeader->OptionalHeader.SizeOfImage);
	printf("  Size of headers: %d\n", ntHeader->OptionalHeader.SizeOfHeaders);
	printf("  Subsystem: %d\n", ntHeader->OptionalHeader.Subsystem);
	printf("  Number of RVA and sizes: %d\n", ntHeader->OptionalHeader.NumberOfRvaAndSizes);


	printf("\nSection\n");
	for (int i = 0; i < SectionCount; i++) {
		IMAGE_SECTION_HEADER* header = SectionHeader[i];
		printf("[%d] %s\n", i, header->Name);
		printf("     Size of rawdata: (0x%x)\n", header->SizeOfRawData);
		printf("     Pointer to rawdata : (0x%x)\n", header->PointerToRawData);
		printf("     Virtual size : (0x%x)\n", header->VirtualAddress);
		printf("     Characteristics : (0x%x)\n", header->Characteristics);
	}

	return;
}

void Show64() {
	IMAGE_NT_HEADERS64* ntHeader = NTHeader64;
	printf("PE header information:\n");
	printf("  Target: %s\n", GetMachineType(ntHeader->OptionalHeader.Magic));
	printf("  Machine type: 0x%x\n", ntHeader->FileHeader.Machine);
	printf("  Number of sections: %d\n", ntHeader->FileHeader.NumberOfSections);
	printf("  Timestamp: 0x%x\n", ntHeader->FileHeader.TimeDateStamp);
	printf("  Entry point address: 0x%x\n", ntHeader->OptionalHeader.AddressOfEntryPoint);
	printf("  Image base address: 0x%x\n", ntHeader->OptionalHeader.ImageBase);
	printf("  Section alignment: %d\n", ntHeader->OptionalHeader.SectionAlignment);
	printf("  File alignment: %d\n", ntHeader->OptionalHeader.FileAlignment);
	printf("  Size of image: %d\n", ntHeader->OptionalHeader.SizeOfImage);
	printf("  Size of headers: %d\n", ntHeader->OptionalHeader.SizeOfHeaders);
	printf("  Subsystem: %d\n", ntHeader->OptionalHeader.Subsystem);
	printf("  Number of RVA and sizes: %d\n", ntHeader->OptionalHeader.NumberOfRvaAndSizes);


	printf("\nSection\n");
	for (int i = 0; i < SectionCount; i++) {
		IMAGE_SECTION_HEADER* header = SectionHeader[i];
		printf("[%d] %s\n", i, header->Name);
		printf("     Size of rawdata: (0x%x)\n", header->SizeOfRawData);
		printf("     Pointer to rawdata : (0x%x)\n", header->PointerToRawData);
		printf("     Virtual size : (0x%x)\n", header->VirtualAddress);
		printf("     Characteristics : (0x%x)\n", header->Characteristics);
	}

	return;
}