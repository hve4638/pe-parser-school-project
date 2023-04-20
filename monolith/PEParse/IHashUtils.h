#pragma once
#include "typedef.h"

namespace PEUtils {
    interface IHashUtils {
        virtual BOOL open() abstract;
        virtual BOOL close() abstract;
    };

}