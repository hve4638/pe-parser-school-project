#include "pch.h"
#include "PEUtils.h"
//#define _MY_DEBUG

namespace PEUtils {
    void debugPrint(tstring debugMessage) {
        OutputDebugStringT(debugMessage.c_str());
        OutputDebugStringT(_T("\n"));
    }

    void copyStringToTString(LPVOID& src, tstring& dst) {
        if (sizeof(TCHAR) == sizeof(char)) {
            dst = reinterpret_cast<TCHAR*>(src);
        }
        else {
            string tmpString = reinterpret_cast<char*>(src);
            dst.assign(tmpString.begin(), tmpString.end());
        }
    }

    void printBuffer(BYTE* buffer, SIZE_T size) {
        for (SIZE_T i = 0; i < size; i += 16) {
            for (SIZE_T j = i; j < size && j < i + 16; j++) {
                printf("%02x ", buffer[j]);
                if (j % 8 == 7) printf(" ");
            }
            for (SIZE_T j = i; j < size && j < i + 16; j++) {
                unsigned char ch = buffer[j];
                if (isprint(ch)) tcout << (char)ch;
                else tcout << ".";
                if (j % 8 == 7) printf(" ");
            }

            printf("\n");
        }
    }

    void deleteStruct(void** pStruct)
    {
        if ((*pStruct) != NULL) {
            delete (*pStruct);
            (*pStruct) = NULL;
        }
    };
}