#pragma once
#include "typedef.h"

namespace PEUtils {
    void debugPrint(tstring debugMessage);
    void copyStringToTString(LPVOID& src, tstring& dst);
    void printBuffer(BYTE*, SIZE_T);
    void deleteStruct(void**);
    tstring convertToUTF8(BYTE* byteBuffer, size_t srcLength);
}