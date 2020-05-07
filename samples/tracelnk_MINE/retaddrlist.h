#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <string>

#define MHC_RetAddrList_NPARAMS 5
extern LONG s_nTlsThread;

namespace MHC_NS {

// forward-declarations
class COMSpy;

struct RetAddrList {
    COMSpy *comSpyPtr;
    const void *retAddr;
    LONG_PTR orig_esp;
    RetAddrList *next;
    LONG funcNo;
    LONG_PTR args[MHC_RetAddrList_NPARAMS]; // arg[0] is THIS
    std::wstring progIdStr;

    // One list by thread!
    static RetAddrList *retAddrList[];

    static LONG getNThread() noexcept {
        LONG nThread = 0;
        if (s_nTlsThread >= 0) nThread = (LONG)(LONG_PTR)TlsGetValue(s_nTlsThread);
        return nThread;
    }

    static RetAddrList *popMustFree() noexcept {
        auto nThread = getNThread();
        auto ret = retAddrList[nThread];
        retAddrList[nThread] = retAddrList[nThread]->next;
        return ret;
    }

    static void push(RetAddrList *newElem) noexcept {
        auto nThread = getNThread();
        newElem->next = retAddrList[nThread];
        retAddrList[nThread] = newElem;
    }
};

} // namespace MHC_NS
