#pragma once
#include <functional>
#include "IRunnableLambda.h"

namespace CommandLineUtils {
    class RunnableLambda : public virtual IRunnableLambda {
        CommandLambda m_call;

    public:
        RunnableLambda(CommandLambda call);
        BOOL run(shared_ptr<IArgs>) override;
    };
}