#pragma once
#include "ILogger.h"

namespace LogUtils {
    class Logger : public ILogger {
        LogLevel m_logLevel = LogLevel::ALL;
        LogDirection m_logDirection = LogDirection::CONSOLE;
        LogLevel m_currentLogLevel = LogLevel::ALL;

        BOOL enabled();
        void write(const tstring&);
        void writeln(const tstring&);
    public:
        Logger(LogLevel);
        Logger(LogDirection);
        Logger(LogLevel, LogDirection);
        Logger(LogDirection, LogLevel);
        void setLogLevel(LogLevel) override;
        void setLogDirection(LogDirection) override;
        ILogger& operator<<(const tstring&) override;
        ILogger& operator<<(const TCHAR*) override;
        ILogger& operator<<(LogLevel) override;
        ILogger& operator<<(LogDirection) override;
        ILogger& operator<<(const ErrorLogInfo&) override;
    };
}


