#pragma once
#include "ICommandLineParser.h"
#include "ICommandNode.h"
#include "RunnableLambda.h"
#include "Logger.h"
#include <functional>
using namespace LogUtils;

namespace CommandLineUtils {
    class CommandLineParser : public ICommandLineParser {
        shared_ptr<ICommandNode> m_root;
        Logger m_logger = { LogLevel::ALL, LogDirection::DEBUGVIEW };

    public:
        CommandLineParser();
        void runCommand(IArgsPtr args) override;
        void addCommand(IArgsPtr args, shared_ptr<IRunnable> runnable) override;

        void runCommand(tstring cmd);
        void addCommand(tstring cmd, shared_ptr<IRunnable> runnable);
        void addCommand(IArgsPtr args, CommandLambda lambda);
        void addCommand(tstring cmd, CommandLambda lambda);
    };
}