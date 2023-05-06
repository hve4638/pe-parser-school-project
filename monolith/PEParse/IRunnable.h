#pragma once
#include "typedef.h"
#include "IArgs.h"

namespace CommandLineUtils {
    interface IRunnable {
        virtual ~IRunnable() {};
        virtual BOOL run(IArgsPtr) abstract;
    };

    typedef shared_ptr<IRunnable> IRunnablePtr;
}