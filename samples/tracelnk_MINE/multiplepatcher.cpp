#include "precomp.h"

#include "multiplepatcher.h"

#include "cslock.h"
#include "tostring.h"

#ifdef DEBUG_MULTIPLEPATCHER
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

extern std::map<FARPROC, FARPROC> newAddrOrigAddrMap;

using DllGetClassObjectFType = HRESULT (STDAPICALLTYPE *)(REFCLSID rclsid, REFIID riid, PVOID *ppv);
static CRITICAL_SECTION cs; // default name because we're using MHC_CSLOCK
std::map<FARPROC, FARPROC> newAddrOrigAddrMap;
const char * MHC_GLOBAL_MESSAGE = "Hola!\n";

void multiplePatcherInitialize() {
    InitializeCriticalSection(&cs);
}

// This should have one more parameter (origAddr)
HRESULT STDAPICALLTYPE MyGenericDllGetClassObject(REFCLSID rclsid,
                                               REFIID riid, PVOID *ppv
                                               , FARPROC myFuncAddr /* extra parameters */) {
    MHC_CSLOCK;

    _PrintEnter("MyGenericDllGetClassObject(%ls, %ls)\n",
        toString(rclsid).c_str(),
        toString(riid).c_str());

    auto original = newAddrOrigAddrMap.find(myFuncAddr);
    if (original == newAddrOrigAddrMap.end()) {
        _PrintExit("ERROR: Original address not found from %p!!\n", myFuncAddr);
        return -1;
    }
    auto ret = ((DllGetClassObjectFType) original->second)(rclsid, riid, ppv);
    _PrintExit("MyGenericDllGetClassObject => 0x%x", ret);
    return ret;
}

void __declspec(naked) MyDllGetClassObject(REFCLSID rclsid,
                                               REFIID riid, PVOID *ppv) {
    (void) rclsid; (void) riid; (void) ppv;

    // get my address
    __asm {
        call  next
    next:
        pop   eax
        sub   eax, 5 // size of the call instruction
        push  eax // address of this function is now the last argument in the call
    }
/*
    _Print(MHC_GLOBAL_MESSAGE); // This crashes since the call will use a relative offset!

    __asm {
        mov  eax, MHC_GLOBAL_MESSAGE // do not use "offset MHC_GLOBAL_MESSAGE"!!!
        push eax
        mov  eax, offset _Print // make sure we use absolute address
        call eax
        pop  eax // balance stack
    }*/

    // call generic with my address
    __asm {
        push [esp + 16] // ppv
        push [esp + 16] // riid
        push [esp + 16] // rclsid
        mov  eax, offset MyGenericDllGetClassObject
        call eax
        retn 12
    }
}

void *allocExecBufferAndCopyFunc(const void *toCopy, size_t nBytes) {
    const DWORD page_size = 4096;

    // prepare the memory in which the machine code will be put (it's not executable yet):
    auto const buffer = VirtualAlloc(nullptr, page_size, MEM_COMMIT, PAGE_READWRITE);

    // copy the machine code into that memory:
    std::memcpy(buffer, toCopy, nBytes);

    // mark the memory as executable:
    DWORD dummy;
    VirtualProtect(buffer, nBytes, PAGE_EXECUTE_READ, &dummy);

    return buffer;
}

FARPROC MultiplePatcherAdd(FARPROC realFunction) {
    MHC_CSLOCK;

    FARPROC ret = realFunction;
    // Make a new function (the function will use its own address to obtain the realFunction to call)
    FARPROC newFunction = (FARPROC) allocExecBufferAndCopyFunc(MyDllGetClassObject, BUFSIZ); // TODO: Size of the function?
    _Debug("Real addr: %p, New addr: %p\n", realFunction, newFunction);
    newAddrOrigAddrMap[newFunction] = realFunction;
    ret = newFunction;
    return ret;
}
