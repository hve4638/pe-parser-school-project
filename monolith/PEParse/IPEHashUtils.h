#pragma once
#include "typedef.h"

namespace PEUtils {
    interface IPEHashUtils {
        virtual BOOL compareBytes(const BYTE* srcBytes, DWORD srcLength, const BYTE* destBytes, DWORD destLength);
        virtual BOOL calculateHash(const BYTE* srcBytes, DWORD srcLength) abstract;
        virtual BOOL getMD5(BYTE* md5Bytes, DWORD* md5BufferLength) abstract;
        virtual BOOL getMD5(tstring& md5String) abstract;
    };
}