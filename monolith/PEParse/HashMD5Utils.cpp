#include "HashMD5Utils.h"
#include <format>

namespace PEUtils {

    HashMD5Utils::HashMD5Utils() {
        open();
    }
    HashMD5Utils::~HashMD5Utils() {
        close();
    }
    BOOL HashMD5Utils::open() {
        if (!CryptAcquireContext(&m_prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
            std::cerr << "Error: CryptAcquireContext failed." << std::endl;
            close();
            return FALSE;
        }
        else if (!CryptCreateHash(m_prov, CALG_MD5, 0, 0, &m_hash)) {
            std::cerr << "Error: CryptCreateHash failed." << std::endl;
            close();
            return FALSE;
        }
        else {
            return TRUE;
        }
    }
    BOOL HashMD5Utils::close() {
        if (m_prov != NULL) CryptReleaseContext(m_prov, 0);
        if (m_hash != NULL) CryptDestroyHash(m_hash);

        m_prov = NULL;
        m_hash = NULL;
        return TRUE;
    }

    BOOL HashMD5Utils::tryGetMD5(const BYTE* data, size_t len, BYTE* outputBytes) {
        return tryGetMD5ToBytes(data, len, outputBytes);
    }
    BOOL HashMD5Utils::tryGetMD5(const BYTE* data, size_t len, tstring& outputString) {
        return tryGetMD5ToString(data, len, outputString);
    }

    BOOL HashMD5Utils::tryGetMD5ToBytes(const BYTE* data, size_t len, BYTE* hash) {
        DWORD hashLen = 16;
        if (!CryptHashData(m_hash, data, (DWORD)len, 0)) {
            m_logger << LogLevel::ERR;
            m_logger << ErrorLogInfo(_T("CryptHashData failed.")) << NL;
            return FALSE;
        }
        else if (!CryptGetHashParam(m_hash, HP_HASHVAL, hash, &hashLen, 0)) {
            m_logger << LogLevel::ERR;
            m_logger << ErrorLogInfo(_T("CryptGetHashParam failed")) << NL;
            return FALSE;
        }
        else {
            return TRUE;
        }
    }

    BOOL HashMD5Utils::tryGetMD5ToString(const BYTE* data, size_t len, tstring& hash) {
        BYTE buffer[MD5_LENGTH] = { 0, };
        DWORD md5Length = MD5_LENGTH;

        vector<BYTE> bytes(len);
        if (!tryGetMD5ToBytes(data, len, buffer)) {
            return FALSE;
        }
        else {
            return bytesToString(buffer, md5Length, hash);
        }
    }

    BOOL HashMD5Utils::bytesToString(const BYTE* hashBytes, DWORD srcLength, tstring& outString) {
        outString = _T("");

        if (hashBytes == NULL) {
            return FALSE;
        }
        else {
            for (DWORD i = 0; i < srcLength; i++) {
                outString.append(format(_T("{:02x}"), hashBytes[i]));
            }
            return (!outString.empty());
        }
    };
}