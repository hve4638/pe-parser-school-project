#pragma once
#include "typedef.h"
#include "LogLevel.h"
#include "LogDirection.h"
#include "LogNL.h"
#include "ErrorLogInfo.h"

namespace LogUtils {
    interface ILogger {
        virtual void setLogLevel(LogLevel) abstract;
        virtual void setLogDirection(LogDirection) abstract;
        virtual ILogger& operator<<(const tstring&) abstract;
        virtual ILogger& operator<<(const TCHAR*) abstract;
        virtual ILogger& operator<<(LogLevel) abstract;
        virtual ILogger& operator<<(LogDirection) abstract;
        virtual ILogger& operator<<(const ErrorLogInfo&) abstract;
    };
}