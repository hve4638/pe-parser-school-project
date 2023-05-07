#pragma once
#include "typedef.h"
#include "LogLevel.h"

namespace LogUtils {
    enum ErrorLogExtraInfo {
        ERRLOG_EXTRA_NONE = 0x0,
        ERRLOG_EXTRA_FUNCTION = 0x1
    };

    struct ErrorLogInfo {
        ErrorLogInfo(tstring message = _T(""), DWORD errorCode = GetLastError(), ErrorLogExtraInfo extraInfo = ERRLOG_EXTRA_NONE,
            const char* __fname = __builtin_FUNCTION(), int __fline = __builtin_LINE());
        
        int extraInfo = ERRLOG_EXTRA_NONE;
        tstring logMessage = _T("");
        DWORD errorCode = GetLastError();
        const char* funcName;
        int funcLine;
    };

}