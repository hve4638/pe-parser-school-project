#pragma once
#include "IPEHashUtils.h"

namespace PEUtils {
    class HashMD5Use : public IUse {
        IHashUtils *m_hashUtils;
        BOOL m_ready = FALSE;
    public:
        HashMD5Use();
        HashMD5Use(IHashUtils*);
        ~HashMD5Use();
        BOOL ready() override;
    };
}