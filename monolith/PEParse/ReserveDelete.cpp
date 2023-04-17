#include "typedef.h"
#include "ReserveDelete.h"

ReserveDelete::ReserveDelete() {
}
ReserveDelete::~ReserveDelete() {
    reset();
}
ReserveDelete& ReserveDelete::addRef(void** ptr) {
    reservedRef.push(ptr);
    return *this;
}
ReserveDelete& ReserveDelete::add(void* ptr) {
    reserved.push(ptr);
    return *this;
}
void ReserveDelete::reset() {
    while (!reserved.empty()) {
        void* ptr = reserved.front();
        reserved.pop();

        if (ptr != NULL) {
            delete ptr;
        }
    }

    while (!reservedRef.empty()) {
        void** ptr = reservedRef.front();
        reservedRef.pop();

        if (ptr != NULL && *ptr != NULL) {
            delete (*ptr);
        }
    }
}