#pragma once

namespace LogUtils {
    enum class LogLevel {
        DISABLE = 0x0,
        ALL = 0x1,
        DEBUG = 0x2,
        INFO = 0x3,
        WARN = 0x4,
        ERR = 0x5,
        FATAL = 0x6
    };
}