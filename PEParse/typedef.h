#pragma once

#include <windows.h>
#include <tchar.h>
#include <vector>
#include <iostream>

using namespace std;

#if defined(UNICODE) || defined(_UNICODE)
#define tcout wcout
#define OutputDebugStringT OutputDebugStringW
#else
#define tcout cout
#define OutputDebugStringT OutputDebugStringA
#endif

typedef ULONGLONG PEPOS;
typedef basic_string<TCHAR> tstring;
// Tuple 순서 : Base address(exe or DLL), Path(exe or DLL)
typedef vector<tuple<ULONGLONG, tstring>> LoadedDllsInfo;
// Tuple 순서 : Name, VirtualAddress, PointerToRawData, SizeOfRawData, Characteristics
typedef tuple<tstring, DWORD, DWORD, DWORD, DWORD> SectionInfoTuple;
// Tuple 순서 : function address, function ordinal, function name
typedef vector<tuple<ULONGLONG, DWORD, tstring>> functionInfoList;
// Tuple 순서 : Name(exe or DLL), vector<functionInfoList>
typedef tuple<tstring, functionInfoList> ImportExportInfoTuple;

typedef ULONGLONG QWORD;

typedef struct _PEFunctionInfo {
    PEPOS AddressOfIAT;
    DWORD Ordinal;
    tstring Name;
} PEFunctionInfo, PEImportFunctionInfo;

typedef struct _PEExportImportInfo {
    tstring Name;
    vector<PEFunctionInfo> FunctionInfo;
} PEExportImportInfo, PEImportInfo, PEExportInfo;

//typedef vector<PEFunctionInfo> PEImportFunctionInfo;

enum MACHINE_TYPE {
    x64,
    x86,
    other,
};

typedef struct _PEStructure
{
    MACHINE_TYPE machineType;
    LPVOID baseAddress = NULL;
    tstring filePath;
    IMAGE_DOS_HEADER dosHeader = { 0, };
    IMAGE_NT_HEADERS32 ntHeader32 = { 0, };
    IMAGE_NT_HEADERS64 ntHeader64 = { 0, };
    IMAGE_DATA_DIRECTORY dataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES] = { 0, };
    vector<SectionInfoTuple> sectionList;
    vector<PEExportImportInfo> importList;
    vector<PEExportImportInfo> exportList;
    vector<ULONGLONG> tlsCallbackList;
} PEStructure;
