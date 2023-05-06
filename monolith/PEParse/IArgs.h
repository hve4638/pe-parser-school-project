#pragma once
#include "typedef.h"

namespace CommandLineUtils {
    interface IArgs {
        virtual tstring current() abstract;
        virtual tstring next() abstract;
        virtual BOOL hasNext() abstract;
        virtual tstring previous() abstract;
        virtual BOOL hasPrevious() abstract;
    };

    typedef shared_ptr<IArgs> IArgsPtr;
}