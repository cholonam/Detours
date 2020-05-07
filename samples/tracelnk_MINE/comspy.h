#pragma once

#include <guiddef.h> // IID
#include <synchapi.h> // CRITICAL_SECTION

#include <string>

// Forward-declarations
struct IUnknown;
static void comspy_delegateAndPostprocess() noexcept;
VOID _PrintEnter(const CHAR *psz, ...);
VOID _PrintExit(const CHAR *psz, ...);
VOID _Print(const CHAR *psz, ...);
VOID _VPrint(PCSTR msg, va_list args, PCHAR pszBuf, LONG cbBuf);

namespace MHC_NS {

class COMSpy {
    using FuncPtr = void *;
    FuncPtr *vftable; // <- This has to be the first one!
    /// The class we are spying!
    IUnknown *m_inner; // <- This MUST be the second one!

    CRITICAL_SECTION list_cs; // keep this protected and use methods for access
public:
    IID m_iid;     std::wstring m_iidStr;
    CLSID m_clsid; std::wstring m_clsidStr;
    std::wstring m_progIdStr;

public:
    COMSpy(IUnknown *inner, const IID &iid, REFCLSID clsid, const std::wstring progIdStr) noexcept;
    ~COMSpy();

    IUnknown *getInner() { return m_inner; }

    BOOL __stdcall preprocess2(
        //void *thisPtr,
        const void* pReturnAddr,
        int nVtblOffset,
        DWORD *pArgs,
        LONG_PTR orig_esp) noexcept;

    static std::wstring params2String(LONG_PTR *params, size_t nParams, size_t maxParams) noexcept;
};

}
