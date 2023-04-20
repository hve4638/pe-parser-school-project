#pragma once
#include "IPEHashUtils.h"

namespace PEUtils {
    class PEHashUtils : IPEHashUtils {
        DWORD m_hashSize = 0;
        DWORD m_hashSizeBufferLength = sizeof(DWORD);
        HCRYPTPROV m_prov = NULL;
        HCRYPTHASH m_hash = NULL;

    public:
        virtual BOOL compareBytes(const BYTE* srcBytes, DWORD srcLength, const BYTE* destBytes, DWORD destLength);
        virtual BOOL calculateHash(const BYTE* srcBytes, DWORD srcLength) abstract;
        virtual BOOL getMD5(BYTE* md5Bytes, DWORD* md5BufferLength) abstract;
        virtual BOOL getMD5(tstring& md5String) abstract;
    };
}