#include "IPEHashUtils.h"

namespace PEUtils {
    class HashMD5Utils : public IHashUtils {
        HCRYPTPROV m_prov = NULL;
        HCRYPTHASH m_hash = NULL;

    public:
        HashMD5Utils();
        ~HashMD5Utils();
        IUse* use() override;
        BOOL open() override;
        BOOL close() override;
        BOOL tryGetMD5(const BYTE* data, size_t len, BYTE* hash);
    };
}