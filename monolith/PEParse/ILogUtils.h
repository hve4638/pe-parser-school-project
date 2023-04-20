#pragma once
#include "typedef.h"
#include "LogLevel.h"
#include "LogDirection.h"

namespace LogUtil {
    
    interface ILogUtils {
        void setLogType(LogLevel logLevel, LogDirection logDirection);
        ILogUtils& operator<<(tstring);
        ILogUtils& operator<<(const TCHAR*);
        ILogUtils& operator<<(LogLevel);
        ILogUtils& operator<<(LogDirection);
    };
}