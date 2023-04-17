#pragma once
#include "pch.h"
#include "PE.h"

namespace PEUtils {
    void debugPrint(tstring debugMessage);
    void copyStringToTString(LPVOID& src, tstring& dst);
    void printBuffer(BYTE*, SIZE_T);
    void deleteStruct(void**);
}