#pragma once
#include "IArgs.h"

namespace CommandLineUtils {
    class TStringArgs : public IArgs {
        enum class StoreType {
            ARRAY,
            VECTOR,
            NONE,
        };

        int m_current = -1;
        SIZE_T m_argc = 0;
        StoreType m_storeType = StoreType::NONE;
        tstring *m_array = NULL;
        shared_ptr<vector<tstring>> m_vector = NULL;

        BOOL isValidIndex(int index);
    public:
        TStringArgs(const vector<tstring>& copy) : TStringArgs(make_shared<vector<tstring>>(copy)) {}
        TStringArgs(int argc, tstring argv[]);
        TStringArgs(shared_ptr<vector<tstring>> argv);
        TStringArgs(int argc, shared_ptr<vector<tstring>> argv);
        TStringArgs(const TStringArgs&); 
        tstring current() override;
        tstring next() override;
        BOOL hasNext() override;
        tstring previous() override;
        BOOL hasPrevious() override;
    };

    extern shared_ptr<TStringArgs> makeArgs(tstring);
}
