#pragma once
#include "typedef.h"
#include "IArgs.h"
#include "IRunnable.h"

namespace CommandLineUtils {
    interface ICommandLineParser {
        virtual void runCommand(shared_ptr<IArgs>) abstract;
        virtual void addCommand(shared_ptr<IArgs>, shared_ptr<IRunnable>) abstract;
    };
}
