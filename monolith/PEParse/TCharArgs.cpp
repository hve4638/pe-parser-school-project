#include "TCharArgs.h"

namespace CommandLineUtils {
    TCharArgs::TCharArgs(int argc, TCHAR* argv[]) {
        m_argc = argc;
        m_argv = argv;
    }

    tstring TCharArgs::current() {
        auto index = this->m_current;
        if (isValidIndex(index)) {
            return m_argv[index];
        }
        else {
            return _T("");
        }
    }

    tstring TCharArgs::next() {
        m_current++;
        return current();
    }

    BOOL TCharArgs::hasNext() {
        return isValidIndex(this->m_current + 1);
    }

    inline BOOL TCharArgs::isValidIndex(int index) {
        return (0 <= index && index < m_argc);
    }

    tstring TCharArgs::previous() {
        m_current--;
        return current();
    }

    BOOL TCharArgs::hasPrevious() {
        return isValidIndex(this->m_current - 1);
    }

}