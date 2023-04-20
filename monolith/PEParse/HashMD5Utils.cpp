#include "HashMD5Utils.h"
#include "HashMD5Use.h"

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
    IUse* HashMD5Utils::use() {
        if (m_prov == NULL) {
            return new HashMD5Use(this);
        }
        else {
            return new HashMD5Use();
        }
    }

    BOOL HashMD5Utils::tryGetMD5(const BYTE* data, size_t len, BYTE* hash) {
        // 해시 결과 가져오기
        DWORD hashLen = 16;
        if (!CryptHashData(m_hash, data, len, 0)) {
            std::cerr << "Error: CryptHashData failed." << std::endl;
            return FALSE;
        }
        else if (!CryptGetHashParam(m_hash, HP_HASHVAL, hash, &hashLen, 0)) {
            std::cerr << "Error: CryptGetHashParam failed." << std::endl;
            return FALSE;
        }
        else {
            return TRUE;
        }

    }
}