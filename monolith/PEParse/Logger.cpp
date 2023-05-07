#include "Logger.h"
#include <format>

namespace LogUtils {

    Logger::Logger(LogLevel logLevel) {
        setLogLevel(logLevel);
    }
    Logger::Logger(LogDirection logDirection) {
        setLogDirection(logDirection);
    }
    Logger::Logger(LogLevel logLevel, LogDirection logDirection) {
        setLogLevel(logLevel);
        setLogDirection(logDirection); 
    }
    Logger::Logger(LogDirection logDirection, LogLevel logLevel) {
        setLogLevel(logLevel);
        setLogDirection(logDirection); 
    }

    void Logger::setLogLevel(LogLevel logLevel) {
        m_logLevel = logLevel;
    }
    void Logger::setLogDirection(LogDirection logDirection) {
        m_logDirection = logDirection;
    }

    inline BOOL Logger::enabled() {
        return (m_currentLogLevel >= m_logLevel);
    }

    void Logger::write(const tstring& message) {
        if (m_logDirection == LogDirection::DEBUGVIEW) {
            OutputDebugStringT(message.c_str());
        }
        else if (m_logDirection == LogDirection::CONSOLE) {
            tcout << message;
        }
    };

    void Logger::writeln(const tstring& message) {
        write(message);
        if (m_logDirection == LogDirection::DEBUGVIEW) {
            OutputDebugStringT(_T("\n"));
        }
        else if (m_logDirection == LogDirection::CONSOLE) {
            tcout << endl;
        }
    }

    ILogger& Logger::operator<<(const tstring& message) {
        if (enabled()) {
            write(message);
        }
        return *this;
    }

    ILogger& Logger::operator<<(const TCHAR* message) {
        if (enabled()) {
            write(format(_T("{:s}"), message));
        }
        return *this;
    }

    ILogger& Logger::operator<<(const ErrorLogInfo& info) {
        if (enabled()) {
            if (info.extraInfo & ERRLOG_EXTRA_FUNCTION) {
                string funcName = info.funcName;
                tstring funcNameT = tstring().assign(funcName.begin(), funcName.end());
                write(
                    format(_T("Function = {:s}({:d}), Code = 0x{:x}({:d}), Msg = {:s}"),
                        funcNameT, 
                        info.funcLine,
                        info.errorCode,
                        info.errorCode,
                        info.logMessage
                    )
                );
            }
            else {
                write(
                    format(_T("Code = 0x{:x}({:d}), Msg = {:s}"),
                        info.errorCode,
                        info.errorCode,
                        info.logMessage
                    )
                );
            }
        }
        return *this;
    }


    ILogger& Logger::operator<<(LogLevel logLevel) {
        m_currentLogLevel = logLevel;
        return *this;
    }


    ILogger& Logger::operator<<(LogDirection logDirection) {
        m_logDirection = logDirection;
        return *this;
    }
}