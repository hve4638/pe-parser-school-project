#pragma once
#include <stdio.h>
#include <windows.h>

extern IMAGE_DOS_HEADER* DosHeader;
extern IMAGE_NT_HEADERS32* NTHeader32;
extern IMAGE_NT_HEADERS64* NTHeader64;

extern int SectionCount;
extern IMAGE_SECTION_HEADER* SectionHeader[128];
extern BYTE* Section[128];

extern void Show();
extern void Show32();
extern void Show64();

void Parse(const char*);
void Parse32();
void Parse64();

/*
BYTE* ReadSection(BYTE*, size_t);
void ParseDosHeader(char*);
*/