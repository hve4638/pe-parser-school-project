#include "RunnableLambda.h"

namespace CommandLineUtils {
    RunnableLambda::RunnableLambda(CommandLambda call) {
        m_call = call;
    }

    BOOL RunnableLambda::run(shared_ptr<IArgs> args) {
        m_call(args);

        return TRUE;
    }
}