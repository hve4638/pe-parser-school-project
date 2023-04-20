#pragma once
#include "typedef.h"

namespace PEUtils {
    interface IHashUtils {
        virtual BOOL open() abstract;
        virtual BOOL close() abstract;
        virtual IUse* use() abstract;
    };

    interface IUse {
        IUse() {};
        ~IUse() {};
        virtual BOOL ready() abstract;
    };
}