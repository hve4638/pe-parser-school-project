#pragma once
#include "typedef.h"

namespace PEParse {
    interface IPEParser {
    public:
        virtual ~IPEParser() {};
        virtual void close(void)abstract;
        virtual BOOL parsePE(DWORD pid, const TCHAR* pfilePath) abstract;
        virtual const PEStructure& getPEStructure(void) abstract;
    };
}