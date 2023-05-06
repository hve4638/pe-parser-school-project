#pragma once
#include <functional>
#include "IRunnable.h"

namespace CommandLineUtils {
    typedef function<void(shared_ptr<IArgs>)> CommandLambda;

    interface IRunnableLambda : public virtual IRunnable {
        virtual ~IRunnableLambda() {};
    };
}