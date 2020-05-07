#include "precomp.h"
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include "comspy.h"

#include <iomanip>
#include <sstream>

#include "iiddb.h"
// define COMSPY_VTBL_SIZE
#include "retaddrlist.h"
#include "tostring.h"
#include "vtbl_repeat.h"

#define DEBUG_COMSPY 1

#ifdef DEBUG_COMSPY
#   define _DebugEnter(...) _PrintEnter(__VA_ARGS__)
#   define _DebugExit(...) _PrintExit(__VA_ARGS__)
#   define _Debug(...) _Print(__VA_ARGS__)
#else
#   define _DebugEnter(...) do { (void) 0; } while(0)
#   define _DebugExit(...) do { (void) 0; } while(0)
#   define _Debug(...) do { (void) 0; } while(0)
#endif
VOID _PrintEnter(const CHAR *psz, ...);
VOID _PrintExit(const CHAR *psz, ...);
VOID _Print(const CHAR *psz, ...);

#define MHC_USE_PARAM_EXT_INFO 1
#define MHC_TRACK_STACK 1
#define MHC_PTR_FMT "%x"
#define MHC_PTR_FMTW L"%x"

namespace MHC_NS {

#define MHC_V(n) \
    static void __declspec(naked) f##n(void) { \
        __asm push (n*4) \
        __asm jmp comspy_delegateAndPostprocess \
    }
#   include "vtbl_repeat.h"
#undef MHC_V

COMSpy::COMSpy(IUnknown *inner, const IID &iid, REFCLSID clsid, const std::wstring progIdStr) noexcept
    : m_inner(inner)
    , m_iid(iid)
    , m_clsid(clsid)
    , m_progIdStr(progIdStr)
{
    InitializeCriticalSection(&list_cs);
    m_iidStr = toString(iid);
    m_clsidStr = toString(clsid);
    _Print("COMSpy init: this=%p, iid=%ls\n", this, m_iidStr.c_str());

    // initialize vtable
    {   auto iidDb = IIDDb::getLockedInstance();
        auto interfaceInfo = iidDb->getInterfaceInfo(iid);
        if (interfaceInfo != nullptr && interfaceInfo->vTbl != nullptr) {
            // reuse virtual table
            vftable = (FuncPtr *) interfaceInfo->vTbl;
        } else {
            vftable = new FuncPtr[COMSPY_VTBL_SIZE];
#define MHC_V(n) vftable[n] = f##n;
#   include "vtbl_repeat.h"
#undef MHC_V
            if (interfaceInfo != nullptr) interfaceInfo->vTbl = vftable;
        }
    }
}

BOOL COMSpy::preprocess2(
    //void *thisPtr,
    const void* pReturnAddr,
    int nVtblOffset,
    DWORD *pArgs,
    LONG_PTR orig_esp) noexcept
{
    int nVtblIdx = nVtblOffset / sizeof(void *);

    // Get cached interface information
    //_Print("preprocess2: this=%p, m_iidStr=%ls iid=%ls", this, m_iidStr.c_str(), toString(m_iid).c_str());

    RetAddrList *newElem = new RetAddrList();
    newElem->comSpyPtr = this;
    newElem->retAddr = pReturnAddr;
    newElem->orig_esp = orig_esp;
    newElem->funcNo = nVtblIdx;
    newElem->args[0] = (LONG_PTR) this->m_inner; // thisPtr;
    newElem->args[1] = (LONG_PTR) pArgs[0];
    newElem->args[2] = (LONG_PTR) pArgs[1];
    newElem->args[3] = (LONG_PTR) pArgs[2];
    newElem->args[4] = (LONG_PTR) pArgs[3];
    newElem->progIdStr = m_progIdStr.length() > 2 ? m_progIdStr : m_iidStr;

    RetAddrList::push(newElem);
    switch (nVtblIdx) {
    case 0: {
        IID *iid = (IID *)(pArgs[0]);
        _PrintEnter("==> Function %ls(%ls " MHC_PTR_FMT ")->QI(%ls) (retAddr: " MHC_PTR_FMT ")\n",
            this->m_progIdStr.c_str(),
            this->m_iidStr.c_str(),
            this->m_inner,
            toString(*iid).c_str(),
            pReturnAddr);
#if DEBUG_COMSPY
        {   auto ii = IIDDb::getLockedInstance()->getInterfaceInfo(*iid);
            if (ii != nullptr) {
                _Debug("Interface found! Name: %ls", ii->toString().c_str());
            }
        }
#endif // DEBUG_COMSPY
        break;
    }
    case 1: {
#ifdef CINTERFACE
        auto nRefs = this->m_inner->lpVtbl->AddRef(this->m_inner) - 1;
        this->m_inner->lpVtbl->Release(this->m_inner);
#else
        auto nRefs = this->m_inner->AddRef() - 1;
        this->m_inner->Release();
#endif
        _PrintEnter("==> Function %ls(%ls " MHC_PTR_FMT ")->AddRef() (retAddr: " MHC_PTR_FMT ") (refs before: %d)\n",
            m_progIdStr.c_str(), this->m_iidStr.c_str(), this->m_inner, pReturnAddr, nRefs);
        break;
    }
    case 2: {
#ifdef CINTERFACE
        auto nRefs = this->m_inner->lpVtbl->AddRef(this->m_inner) - 1;
        this->m_inner->lpVtbl->Release(this->m_inner);
#else
        auto nRefs = this->m_inner->AddRef() - 1;
        this->m_inner->Release();
#endif
        _PrintEnter("==> Function %ls(%ls " MHC_PTR_FMT ")->Release() (retAddr: " MHC_PTR_FMT ") (refs before: %d)\n",
            m_progIdStr.c_str(), this->m_iidStr.c_str(), this->m_inner, pReturnAddr, nRefs);
        break;
    }
    default: {
        auto interfaceInfo = IIDDb::getLockedInstance()->getInterfaceInfo(this->m_iid);
        _PrintEnter("==> Function %ls(%ls " MHC_PTR_FMT ")->[#%d]%ls (retAddr: " MHC_PTR_FMT ")\n",
            m_progIdStr.c_str(), this->m_iidStr.c_str(), this->m_inner,
             nVtblIdx,
             interfaceInfo ? interfaceInfo->getMethod(nVtblIdx).c_str() : L"",
            pReturnAddr);
        break;
    }}
    return TRUE; // TRUE means success
}

COMSpy::~COMSpy() {
    DeleteCriticalSection(&list_cs);
    delete vftable;
}

namespace {
BOOL canReadMem(const void *memAddr) {
    BOOL ret = FALSE;
    MEMORY_BASIC_INFORMATION info;
    if (VirtualQuery(memAddr, &info, sizeof(MEMORY_BASIC_INFORMATION))) {
        ret = (info.Protect & (PAGE_READONLY|PAGE_READWRITE|PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE)) != 0;
        if (!ret) _Print("Cannot read (PERM: %ls)\n", toStringMemProtect(info.Protect));
    }
    return ret;
}

BOOL variant2Str(const VARIANT *v, std::wstring &outStr) noexcept {
    BOOL ret = false;
    VARIANT temp;
    __try {
        VariantInit(&temp);
        if (SUCCEEDED(VariantChangeType(&temp, v, VARIANT_ALPHABOOL, VT_BSTR))) {
            outStr = temp.bstrVal;
            ret = true;
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        _Debug("WARNING: Exception raised trying to convert variant to string.\n");
    }
    VariantClear(&temp);
    return ret;
}

} // anonymous namespace

template<typename TCHR>
inline BOOL mhcIsString(TCHR *mem) {
    auto isChar = [](TCHR c) {
        return c >= (TCHR) ' '
            && c <= (TCHR) '~';
    };

    if (!isChar(mem[0])) return FALSE;
    size_t strLen = 1, MINLEN = 4;
    for (size_t i = 1; i < MAX_PATH; i++) {
        if (mem[i] == (TCHR) 0) return strLen >= MINLEN; // end of string
        if (!isChar(mem[i])) return FALSE;
        strLen++;
    }
    return strLen >= MINLEN; // looks like a string
}

std::wstring COMSpy::params2String(LONG_PTR *params, size_t nParams, size_t maxParams) noexcept {
    // Check memory type
    std::wstring ret;
    MEMORY_BASIC_INFORMATION info;
    std::wostringstream ss;
    for (size_t i = 0; i < nParams; i++) {
        if (i) ss << L", ";
        if (i >= maxParams) {
            ss << L"?";
        } else {
            if (VirtualQuery((LPCVOID) params[i], &info, sizeof(MEMORY_BASIC_INFORMATION))) {
                switch (info.Protect) {
                    case 1: ss << (signed) params[i] ; break; // probably not an address
                    case 2:
                    case 4:
                    case 8:
                    case 32: {
                        // try to dump as string
                        {
                            try {
                                LPCWSTR maybeWStr = (LPCWSTR) params[i];
                                LPCSTR maybeStr = (LPCSTR) params[i];
                                if (mhcIsString(maybeWStr)) {
                                    ss << L"WSTR(" << std::quoted(maybeWStr) << L")";
                                } else if (mhcIsString(maybeStr)) {
                                    WCHAR buf[MAX_PATH] = { 0 };
                                    mbstate_t state = { 0 };
                                    size_t retVal;
                                    errno_t err = mbsrtowcs_s(&retVal, buf, MAX_PATH, &maybeStr, _TRUNCATE, &state);
                                    if (err == 0) {
                                        ss << L"STR(" << std::quoted(buf) << L")";
                                    } else {
                                        _Debug("err=%d, ret=%d\n", err, retVal);
                                    }
                                }
                            } catch(...) {
                                _Print("ERROR: writing string!\n");
                            }
                        }
                        // try to dump as variant
                        VARIANT *varPtr = (VARIANT *)params[i];
                        if (varPtr->vt == VT_BSTR && canReadMem(varPtr->bstrVal)) {
                            ss << L"VT_BSTR(" << std::quoted(varPtr->bstrVal) << L")";
                        } else {
                            std::wstring varStr;
                            if (variant2Str(varPtr, varStr)) {
                                ss << toString(varPtr->vt) << L"(" << varStr.c_str() << L")";
                            } else {
                                ss << L"0x" << std::uppercase << std::setfill(L'0') << std::setw(8) << std::hex << params[i] << std::dec
                                << L"(" << toStringMemProtect(info.Protect) << ")";
                            }
                        }
                        break;
                    } default:
                        ss << L"0x" << std::uppercase << std::setfill(L'0') << std::setw(8) << std::hex << params[i] << std::dec << L" (PERM:" << info.Protect << L")";
                }
            } else {
                ss << params[i] << L" (ERR:0x" << std::hex << GetLastError() << std::dec << L")";
            }

        }
    }
    ret = ss.str();
    return ret;
}

int __stdcall postprocess(
    HRESULT hrOrRefCntFromInner,
    LONG_PTR esp_after,
    const void** ppReturnAddr /* must be the last argument! */)
{
    RetAddrList *elem = RetAddrList::popMustFree();
    *ppReturnAddr = elem->retAddr;
    LONG_PTR orig_esp = elem->orig_esp;

    auto stackDiff = (int)(esp_after - orig_esp);
    int nArgs = (stackDiff / sizeof(void *)) - 1; // number of arguments not counting 'this'
    {
        WCHAR buf[400] = { 0 };
        switch (elem->funcNo) {
        case 0: { // QueryInterface() -> Return a new COMSpy if the returned pointer is different (different interface)
#if 1
            IUnknown **retAddr = (IUnknown **) elem->args[2];
            IUnknown *ifaceToBeReturned = *retAddr;
            if (SUCCEEDED(hrOrRefCntFromInner) && ifaceToBeReturned != nullptr) {
                if (ifaceToBeReturned != elem->comSpyPtr->getInner()) {
                    _Debug("CREATING NEW COMSpy! new=%p this=%p\n", ifaceToBeReturned, elem->comSpyPtr->getInner());
                    auto p = new COMSpy(ifaceToBeReturned, elem->comSpyPtr->m_iid, elem->comSpyPtr->m_clsid, elem->progIdStr);
                    *retAddr = (IUnknown *) p; // overwrite return!
                } else {
                    _Debug("NOT CREATING NEW COMSpy since the interface returned is the same (already patched)\n");
                }
            }
#endif
            _snwprintf_s(buf, 400, L"%ls(%ls " MHC_PTR_FMTW L")->QI(", elem->progIdStr.c_str(), elem->comSpyPtr->m_iidStr.c_str(), (ULONG_PTR) elem->args[0]);
            break;
        }
        case 1: {
            _snwprintf_s(buf, 400, L"%ls(%ls " MHC_PTR_FMTW L")->AddRef(", elem->progIdStr.c_str(), elem->comSpyPtr->m_iidStr.c_str(), (ULONG_PTR) elem->args[0]);
            break;
        }
        case 2: {
            _snwprintf_s(buf, 400, L"%ls(%ls " MHC_PTR_FMTW L")->Release(", elem->progIdStr.c_str(), elem->comSpyPtr->m_iidStr.c_str(), (ULONG_PTR) elem->args[0]);
            break;
        }
        default: {
            _snwprintf_s(buf, 400, L"%ls(%ls " MHC_PTR_FMTW L")->#%d(", elem->progIdStr.c_str(), elem->comSpyPtr->m_iidStr.c_str(), (ULONG_PTR) elem->args[0], elem->funcNo);
            break;
        }}

#if MHC_USE_PARAM_EXT_INFO
        if (elem->progIdStr == L"MSOFD.Engine.12" && elem->funcNo == 23) {}
        else wcscat_s(buf, 400, COMSpy::params2String(&elem->args[1], nArgs, MHC_RetAddrList_NPARAMS - 1).c_str());
#else // MHC_USE_PARAM_EXT_INFO
        WCHAR buf2[400];
        // append arguments
        for (auto i = 0; i < nArgs; i++) {
            if (i < (sizeof(elem->args)/sizeof(elem->args[0]))) // number saved arguments
                _snwprintf_s(buf2, 20, L"%s%p", i == 0 ? L"" : L", ", (void *) elem->args[i+1]);
            else
                _snwprintf_s(buf2, 20, L"%s", i == 0 ? L"?" : L", ?");
            wcscat_s(buf, 400, buf2);
        }
#endif
        wcscat_s(buf, 400, L")");
        if (elem->funcNo != 1 && elem->funcNo != 2 && hrOrRefCntFromInner != S_OK) {
            _PrintExit("<== Function %ls => 0x%08x (%ls)\n", buf, hrOrRefCntFromInner, toString(hrOrRefCntFromInner).c_str());
        } else {
            _PrintExit("<== Function %ls => %d\n", buf, hrOrRefCntFromInner);
        }
    }
    delete elem;
    return hrOrRefCntFromInner; // Important! this is what's returned to the client
}
} // namespace MHC_NS

static const char *GLBL="HI!";
#define ASM_TRC \
        __asm { mov  eax, GLBL } \
        __asm { push eax }\
        __asm { mov  eax, offset _Print } \
        __asm { call eax } \
        __asm { pop  eax }

static void __declspec(naked) comspy_delegateAndPostprocess() noexcept {
    __asm {
        // get the vtbl index
        pop  eax			// eax = vtbl index (in bytes)
        sub  esp, 8
        push eax
        push ebp			// set up simple stack frame
        mov  ebp, esp

        // ebp+4  = local variable: vtbl offset (in bytes)
        // ebp+8  = local variable: result of context allocation
        // ebp+12 = local variable: address of inner's method
        // ebp+16 = retaddr
        // ebp+20 = this
        // ebp+24 = args

#if MHC_TRACK_STACK
        lea  eax, [esp + 12]
        push eax // original esp
#else
        push 0
#endif
        lea  eax, [ebp+24]	// eax = preprocess2( this, pReturnAddr, nVtblOffset, pArgs );
        push eax
        push [ebp+4]
        push [ebp+16]
        push [ebp+20]
        call MHC_NS::COMSpy::preprocess2
        mov  [ebp+8], eax	// store result of context allocation

        mov  eax, [ebp+20]	// this = eax = pInner
        mov  eax, [eax+4]
        mov  [ebp+20], eax	

        mov  eax, [eax]		// store address of inner's virtual function
        add  eax, [ebp+4]
        mov  eax, [eax]		
        mov  [ebp+12], eax

        pop  ebp			// tear down stack frame
        pop  eax			// discard vtbl offset

        pop  eax			// was context alloc successful?
        test eax, 1
        jnz allocSuccessful

        pop	 eax			// delegate without postprocessing
        jmp  eax

    allocSuccessful:
        pop  eax
        add  esp, 4			// remove caller's return addr from stack and call inner
        call eax

        sub  esp, 4			// make room for original return addr
        push esp			// eax = postprocess( eax, stack_diff, ppReturnAddr )
#if MHC_TRACK_STACK
        push  esp
#else
        push  0
#endif
        push eax
        call MHC_NS::postprocess

        ret
    }

} // namespace MHC_NS
