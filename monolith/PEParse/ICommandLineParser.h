#pragma once
#include "typedef.h"
#include "IArgs.h"
#include "IRunnable.h"

namespace CommandLineUtils {
    interface ICommandLineParser {
        virtual void runCommand(IArgsPtr) abstract;
        virtual void addCommand(IArgsPtr, shared_ptr<IRunnable>) abstract;
    };
}
