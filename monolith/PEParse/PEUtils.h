#pragma once
#include "typedef.h"

namespace PEUtils {
    void debugPrint(tstring debugMessage);
    tstring copyStringToTString(string& source);
    void printBuffer(BYTE* offset, SIZE_T size);
    void deleteStruct(void**);
    tstring convertToUTF8(BYTE* byteBuffer, size_t srcLength);
    vector<tstring> splitString(tstring str);
}