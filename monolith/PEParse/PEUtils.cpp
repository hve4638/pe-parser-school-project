#include "PEUtils.h"
#define _MY_DEBUG

namespace PEUtils {
    void debugPrint(tstring debugMessage) {
#ifdef _MY_DEBUG
        OutputDebugStringT(debugMessage.c_str());
        OutputDebugStringT(_T("\n"));
#endif
    }

    tstring copyStringToTString(string& source) {
        tstring dest;
        if (CHAR_IS_TCHAR) {
            dest.assign(source.begin(), source.end());
        }
        else {
            int bufferLen = MultiByteToWideChar(CP_UTF8, 0, reinterpret_cast<LPCCH>(source.data()), -1, NULL, 0);

            auto buffer = make_shared<TCHAR>(bufferLen);
            //TCHAR* readBuffer = new TCHAR[bufferLen];
            
            MultiByteToWideChar(CP_UTF8, 0, reinterpret_cast<LPCCH>(source.data()), -1, buffer.get(), bufferLen);
            dest = buffer.get();
        }

        return dest;
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

    void deleteStruct(void** pStruct) {
        if ((*pStruct) != NULL) {
            delete (*pStruct);
            (*pStruct) = NULL;
        }
    };

    tstring convertToUTF8(BYTE* byteBuffer, size_t srcLength) {
        tstring readString;
        shared_ptr<TCHAR> byteBufferW(new TCHAR[srcLength + 1]);

        int bufferLen = MultiByteToWideChar(CP_UTF8, 0, reinterpret_cast<LPCCH>(byteBuffer), -1, NULL, 0);
        MultiByteToWideChar(CP_UTF8, 0, reinterpret_cast<LPCCH>(byteBuffer), -1, byteBufferW.get(), bufferLen);
        readString = byteBufferW.get();

        return readString;
    }

    vector<tstring> splitString(tstring str) {
        vector<basic_string<TCHAR>> tokens;
        basic_string<TCHAR> temp;
        
        for (const auto& ch : str) {
            if (ch != _T(' ')) {
                temp += ch;
            }
            else if (!temp.empty()) {
                tokens.push_back(temp);
                temp.clear();
            }
        }
        if (!temp.empty()) {
            tokens.push_back(temp);
        }
        return tokens;
    }
}