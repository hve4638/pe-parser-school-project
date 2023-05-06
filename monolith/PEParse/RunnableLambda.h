#pragma once
#include <functional>
#include "IRunnableLambda.h"

namespace CommandLineUtils {
    class RunnableLambda : public virtual IRunnableLambda {
        function<void(shared_ptr<IArgs>)> m_call;

    public:
        RunnableLambda(CommandLambda call);
        BOOL run(shared_ptr<IArgs>) override;
    };
}