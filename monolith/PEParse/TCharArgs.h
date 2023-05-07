#pragma once
#include "IArgs.h"

namespace CommandLineUtils {
    class TCharArgs : public IArgs {
        int m_current = -1;
        int m_argc = 0;
        TCHAR** m_argv = NULL;

        BOOL isValidIndex(int index);
    public:
        TCharArgs(int argc, TCHAR* argv[]);
        tstring current() override;
        tstring next() override;
        BOOL hasNext() override;
        tstring previous() override;
        BOOL hasPrevious() override;
    };
}