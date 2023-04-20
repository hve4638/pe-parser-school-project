#include "PEHashUtils.h"

namespace PEUtils {
    BOOL PEHashUtils::compareBytes(const BYTE* srcBytes, DWORD srcLength, const BYTE* destBytes, DWORD destLength) {

    }
    BOOL PEHashUtils::calculateHash(const BYTE* srcBytes, DWORD srcLength) {

    }
    BOOL PEHashUtils::getMD5(BYTE* md5Bytes, DWORD* md5BufferLength) {
        BOOL result = FALSE;

        if (m_hash == NULL) {

        }
        // Get the hash size
        if ((m_hash != NULL) && (CryptGetHashParam(m_hash, HP_HASHSIZE, (BYTE*)&m_hashSize, &m_hashSizeBufferLength, 0) != 0)) {
            // Check buufer size
            if (*md5BufferLength >= m_hashSize) {
                // Get the hash value
                if (CryptGetHashParam(m_hash, HP_HASHVAL, md5Bytes, md5BufferLength, 0)) {
                    result = TRUE;
                }
            }
        }
        return result;
    }
    BOOL PEHashUtils::getMD5(tstring& md5String) {
        BYTE md5HashBytes[MD5_LENGTH] = { 0, };
        DWORD md5BufferLength = MD5_LENGTH;

        return (getMD5(md5HashBytes, &md5BufferLength) && toString(md5HashBytes, MD5_LENGTH, md5String));
    }
}