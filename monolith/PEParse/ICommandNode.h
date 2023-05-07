#pragma once
#include "typedef.h"
#include "TCharArgs.h"
#include "IRunnable.h"


namespace CommandLineUtils {
    interface ICommandNode {
        virtual ~ICommandNode() {};
        virtual BOOL run(shared_ptr<IArgs>) abstract;
        virtual BOOL isRunnable() abstract;
        virtual void setRunnable(shared_ptr<IRunnable> runnable) abstract;
        virtual weak_ptr<ICommandNode> findNodeForcefully(shared_ptr<IArgs>) abstract;
        virtual weak_ptr<ICommandNode> findNode(shared_ptr<IArgs>) abstract;
        virtual weak_ptr<ICommandNode> getPtr() abstract;
        virtual void setPtr(weak_ptr<ICommandNode>) abstract;
    };

    typedef shared_ptr<ICommandNode> ICommandNodePtr;
}