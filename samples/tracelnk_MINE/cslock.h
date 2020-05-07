#pragma once

#include <synchapi.h> // CRITICAL_SECTION

namespace MHC_NS {

class CriticalSection {
    CRITICAL_SECTION cs;
public:
    CriticalSection() noexcept {
        InitializeCriticalSection(&cs);
    }
    ~CriticalSection() {
        DeleteCriticalSection(&cs);
    }
    CRITICAL_SECTION &get() { return cs; }
};

class CSLock {
    CRITICAL_SECTION &cs;
public:
    CSLock(CRITICAL_SECTION &cs) noexcept
        : cs(cs) {
        EnterCriticalSection(&this->cs);
    }
    CSLock(CriticalSection &cs) noexcept
        : cs(cs.get()) {
        EnterCriticalSection(&this->cs);
    }
    ~CSLock() {
        LeaveCriticalSection(&this->cs);
    }
};

} // namespace MHC_NS

#define MHC_CSLOCK MHC_NS::CSLock cs_lock ## __LINE__(cs)
