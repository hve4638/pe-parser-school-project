#pragma once
#include "typedef.h"

interface IPEReader {
public:
    virtual ~IPEReader() {};
    virtual void close() abstract;
    virtual BOOL open(DWORD pid, const TCHAR* pfilePath) abstract;
    virtual LPVOID getBaseAddress() abstract;
    virtual tstring getFilePath() abstract;
    virtual tstring getPEString(ULONGLONG rva) abstract;
    virtual tstring getPEStringNoBase(ULONGLONG rva) abstract;
    virtual SSIZE_T readData(QWORD rva, LPVOID bufferAddress, SIZE_T bufferSize) abstract;
    virtual SSIZE_T readDataNoBase(QWORD rva, LPVOID bufferAddress, SIZE_T bufferSize) abstract;
    virtual QWORD getRAW(QWORD rva) abstract;
};

