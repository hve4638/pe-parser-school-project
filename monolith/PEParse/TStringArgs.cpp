#include "TStringArgs.h"
#include "PEUtils.h"

namespace CommandLineUtils {
    shared_ptr<TStringArgs> makeArgs(tstring line) {
        auto tokens = PEUtils::splitString(line);

        return make_shared<TStringArgs>(tokens);;
    }

    TStringArgs::TStringArgs(const TStringArgs& copy) {
        m_argc = copy.m_argc;
        m_array = copy.m_array;
        m_vector = copy.m_vector;
        m_storeType = copy.m_storeType;
    }

    TStringArgs::TStringArgs(int argc, tstring argv[]) {
        m_argc = argc;
        m_array = argv;
        m_storeType = StoreType::ARRAY;
    }

    TStringArgs::TStringArgs(int argc, shared_ptr<vector<tstring>> argv) {
        m_argc = argc;
        m_vector = argv;
        m_storeType = StoreType::VECTOR;
    }

    TStringArgs::TStringArgs(shared_ptr<vector<tstring>> argv) {
        m_argc = argv->size();
        m_vector = argv;
        m_storeType = StoreType::VECTOR;
    }

    tstring TStringArgs::current() {
        auto index = this->m_current;
        if (isValidIndex(index)) {
            switch (m_storeType) {
            case StoreType::VECTOR:
                return m_vector->at(index);

            case StoreType::ARRAY:
                return m_array[index];

            default:
                return _T("");
            }
        }
        else {
            return _T("");
        }
    }

    tstring TStringArgs::next() {
        m_current++;
        return current();
    }

    BOOL TStringArgs::hasNext() {
        return isValidIndex(this->m_current + 1);
    }

    tstring TStringArgs::previous() {
        m_current--;
        return current();   
    }

    BOOL TStringArgs::hasPrevious() {
        return isValidIndex(this->m_current - 1);
    }

    inline BOOL TStringArgs::isValidIndex(int index) {
        return (0 <= index && index < m_argc);
    }
}
