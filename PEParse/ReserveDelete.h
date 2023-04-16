#pragma once
#include <queue>

class ReserveDelete {
private:
    std::queue<void**> reservedRef;
    std::queue<void*> reserved;

public:
    ReserveDelete();
    ~ReserveDelete();
    ReserveDelete& addRef(void**);
    ReserveDelete& add(void*);
    void reset();
};