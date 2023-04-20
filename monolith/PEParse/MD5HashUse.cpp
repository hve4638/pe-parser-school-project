#pragma once
#include "HashMD5Use.h"

namespace PEUtils {
    HashMD5Use::HashMD5Use() {
        m_hashUtils = NULL;
        m_ready = FALSE;
    }
    HashMD5Use::HashMD5Use(IHashUtils* hashUtils) {
        m_hashUtils = hashUtils;
        m_ready = m_hashUtils->open();
    }
    HashMD5Use::~HashMD5Use() {
        if (m_ready) {
            m_hashUtils->close();
            m_ready = FALSE;
        }
    }
    BOOL HashMD5Use::ready() {
        return m_ready;
    }
}