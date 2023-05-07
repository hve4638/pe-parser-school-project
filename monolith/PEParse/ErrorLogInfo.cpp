#include "ErrorLogInfo.h"

namespace LogUtils {
    ErrorLogInfo::ErrorLogInfo(tstring message, DWORD errorCode, ErrorLogExtraInfo extraInfo, const char* __fname, int __fline) {
        logMessage = message;
        this->extraInfo = extraInfo;
        this->errorCode = errorCode;
        funcName = __fname;
        funcLine = __fline;
    }
}