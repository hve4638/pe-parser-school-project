#include "IHashUtils.h"
#include "Logger.h"
using namespace LogUtils;

namespace PEUtils {
    class HashMD5Utils : public IHashUtils {
        HCRYPTPROV m_prov = NULL;
        HCRYPTHASH m_hash = NULL;
        Logger m_logger = { LogDirection::DEBUGVIEW, LogLevel::DEBUG };

        BOOL bytesToString(const BYTE* hashBytes, DWORD srcLength, tstring& outString);
    public:
        HashMD5Utils();
        ~HashMD5Utils();
        BOOL open() override;
        BOOL close() override;
        BOOL tryGetMD5ToBytes(const BYTE* data, size_t len, BYTE* hashBytes);
        BOOL tryGetMD5ToString(const BYTE* data, size_t len, tstring& hashString);
        BOOL tryGetMD5(const BYTE* data, size_t len, BYTE* hashBytes);
        BOOL tryGetMD5(const BYTE* data, size_t len, tstring& hashString);
    };
}