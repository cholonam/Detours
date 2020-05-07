#include "precomp.h"
//////////////////////////////////////////////////////////////////////////////
//
//  Detours Test Program (trclnk.cpp of trclnk.dll)
//
//  Microsoft Research Detours Package
//
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//
//#define _WIN32_WINNT        0x0400
#define WIN32
#define NT

#define DBG_TRACE   0
#define MHC 1
#define EXPERIMENTAL_DYNAMIC_METHOD_DETOUR 1

#if MHC
//#define CINTERFACE
#define MHC_TRACK_IUNK 1
#define USE_COMSPY 1
#endif
#include <windows.h>
#include <stdio.h>
#include "detours.h"
#include "syelog.h"
#include "tostring.h"
#include "multiplepatcher.h"

#if MHC
#include "comspy.h"
#include "iiddb.h"
#include "retaddrlist.h"

using MHC_NS::COMSpy;
using MHC_NS::IIDDb;
using MHC_NS::RetAddrList;

#endif

#if MHC
#else
#   define PULONG_PTR          PVOID
#   define PLONG_PTR           PVOID
#   define ULONG_PTR           PVOID
#   define ENUMRESNAMEPROCA    PVOID
#   define ENUMRESNAMEPROCW    PVOID
#   define ENUMRESLANGPROCA    PVOID
#   define ENUMRESLANGPROCW    PVOID
#   define ENUMRESTYPEPROCA    PVOID
#   define ENUMRESTYPEPROCW    PVOID
#   define STGOPTIONS          PVOID
#endif

//////////////////////////////////////////////////////////////////////////////
#pragma warning(disable:4127)   // Many of our asserts are constants.

#define ASSERT_ALWAYS(x)   \
    do {                                                        \
    if (!(x)) {                                                 \
            AssertMessage(#x, __FILE__, __LINE__);              \
            DebugBreak();                                       \
    }                                                           \
    } while (0)

#ifndef NDEBUG
#define ASSERT(x)           ASSERT_ALWAYS(x)
#else
#define ASSERT(x)
#endif

#define UNUSED(c)    (c) = (c)

//////////////////////////////////////////////////////////////////////////////
static HMODULE s_hInst = NULL;
static WCHAR s_wzDllPath[MAX_PATH];

BOOL ProcessEnumerate();
BOOL InstanceEnumerate(HINSTANCE hInst);
BOOL ImportEnumerate(HINSTANCE hInst);

////////////////////////////////////////////////////////////// Logging System.
//
static BOOL s_bLog = 1;
static LONG s_nTlsIndent = -1;
/*static*/ LONG s_nTlsThread = -1;
static LONG s_nThreadCnt = 0;

VOID _PrintEnter(const CHAR *psz, ...);
VOID _PrintExit(const CHAR *psz, ...);
VOID _Print(const CHAR *psz, ...);
VOID _VPrint(PCSTR msg, va_list args, PCHAR pszBuf, LONG cbBuf);

VOID AssertMessage(CONST PCHAR pszMsg, CONST PCHAR pszFile, ULONG nLine);

#if MHC
BOOL __stdcall preprocess2(
    void *thisPtr,
    const void* pReturnAddr,
    int nVtblOffset,
    DWORD *pArgs,
    LONG_PTR orig_esp)
{
    int nVtblIdx = nVtblOffset / sizeof(void *);
    RetAddrList *newElem = new RetAddrList();
    newElem->retAddr = pReturnAddr;
    newElem->orig_esp = orig_esp;
    newElem->funcNo = nVtblIdx;
    newElem->args[0] = (LONG_PTR) thisPtr;
    newElem->args[1] = (LONG_PTR) pArgs[0];
    newElem->args[2] = (LONG_PTR) pArgs[1];
    newElem->args[3] = (LONG_PTR) pArgs[2];
    newElem->args[4] = (LONG_PTR) pArgs[3];
    
    RetAddrList::push(newElem);
//    _PrintEnter("=== MSOFD Function #%d called (retAddr: %p)\n",
//        nVtblIdx, pReturnAddr);
    _PrintEnter("");
    return TRUE; // TRUE means success
}

HRESULT __stdcall postprocess(
    HRESULT hrFromInner,
    LONG_PTR esp_after,
    const void** ppReturnAddr /* must be the last argument! */)
{
    RetAddrList *elem = RetAddrList::popMustFree();
    *ppReturnAddr = elem->retAddr;
    LONG_PTR orig_esp = elem->orig_esp;
    if (*ppReturnAddr == nullptr) {
        _Print("NULLPTR FOUND!!!\n");
    }
    auto stackDiff = (int)(esp_after - orig_esp);
    int nArgs = (stackDiff / sizeof(void *)) - 1; // number of arguments not counting 'this'
    {
        char buf[200] = { 0 };
        char buf2[20];
        _snprintf_s(buf, 200, "(%p)->#%d(", (void *) elem->args[0], elem->funcNo);
        // append arguments
        for (auto i = 0; i < nArgs; i++) {
            if (i < (sizeof(elem->args)/sizeof(elem->args[0]))) // number saved arguments
                _snprintf_s(buf2, 20, "%s%p", i == 0 ? "" : ", ", (void *) elem->args[i+1]);
            else
                _snprintf_s(buf2, 20, "%s", i == 0 ? "?" : ", ?");
            strcat_s(buf, 200, buf2);
        }
        strcat_s(buf, 200, ")");
        _PrintExit("=== MSOFD Function %s => 0x%x\n", buf, hrFromInner);

    }
    delete elem;
    return hrFromInner; // Important! this is what's returned to the client
}

#include "fake_vtable.h"
#endif // MHC

//////////////////////////////////////////////////////////////////////////////
//
// Trampolines
//
extern "C" {
    //  Trampolines for SYELOG library.
    //
    HANDLE (WINAPI *
            Real_CreateFileW)(LPCWSTR a0, DWORD a1, DWORD a2,
                              LPSECURITY_ATTRIBUTES a3, DWORD a4, DWORD a5,
                              HANDLE a6)
        = CreateFileW;

    BOOL (WINAPI *
          Real_WriteFile)(HANDLE hFile,
                          LPCVOID lpBuffer,
                          DWORD nNumberOfBytesToWrite,
                          LPDWORD lpNumberOfBytesWritten,
                          LPOVERLAPPED lpOverlapped)
        = WriteFile;
    BOOL (WINAPI *
          Real_FlushFileBuffers)(HANDLE hFile)
        = FlushFileBuffers;
    BOOL (WINAPI *
          Real_CloseHandle)(HANDLE hObject)
        = CloseHandle;

    BOOL (WINAPI *
          Real_WaitNamedPipeW)(LPCWSTR lpNamedPipeName, DWORD nTimeOut)
        = WaitNamedPipeW;
    BOOL (WINAPI *
          Real_SetNamedPipeHandleState)(HANDLE hNamedPipe,
                                        LPDWORD lpMode,
                                        LPDWORD lpMaxCollectionCount,
                                        LPDWORD lpCollectDataTimeout)
        = SetNamedPipeHandleState;

    DWORD (WINAPI *
           Real_GetCurrentProcessId)(VOID)
        = GetCurrentProcessId;
    VOID (WINAPI *
          Real_GetSystemTimeAsFileTime)(LPFILETIME lpSystemTimeAsFileTime)
        = GetSystemTimeAsFileTime;

    VOID (WINAPI *
          Real_InitializeCriticalSection)(LPCRITICAL_SECTION lpSection)
        = InitializeCriticalSection;
    VOID (WINAPI *
          Real_EnterCriticalSection)(LPCRITICAL_SECTION lpSection)
        = EnterCriticalSection;
    VOID (WINAPI *
          Real_LeaveCriticalSection)(LPCRITICAL_SECTION lpSection)
        = LeaveCriticalSection;
}

#if MHC
// Added by cholonam
HRESULT (WINAPI *Real_CoCreateInstanceEx)(CONST IID& a0,
                                          IUnknown* a1,
                                          DWORD a2,
                                          COSERVERINFO* a3,
                                          DWORD a4,
                                          MULTI_QI* a5)
    = CoCreateInstanceEx;
#endif // MHC

BOOL (WINAPI *Real_FreeLibrary)(HMODULE a0)
    = FreeLibrary;

DWORD (WINAPI *Real_GetModuleFileNameW)(HMODULE a0,
                                LPWSTR a1,
                                DWORD a2)
    = GetModuleFileNameW;

HMODULE (WINAPI *Real_GetModuleHandleW)(LPCWSTR a0)
    = GetModuleHandleW;

FARPROC (WINAPI *Real_GetProcAddress)(HMODULE a0,
                              LPCSTR a1)
    = GetProcAddress;

HMODULE (WINAPI *Real_LoadLibraryExW)(LPCWSTR a0,
                              HANDLE a1,
                              DWORD a2)
    = LoadLibraryExW;

HMODULE (WINAPI *Real_LoadLibraryW)(LPCWSTR a0)
    = LoadLibraryW;

//////////////////////////////////////////////////////////////////////////////
//

#if MHC
bool skipLog(const std::wstring &progId) {
    LPCWSTR toFilter = L"InetBase.InetBase.12";

    return progId == toFilter
        || progId == L"Msxml2.DOMDocument.3.0" // Crashes
        || progId == L"PFPlan.DLL.12"; // Crashes
}

bool hackVTable(const std::wstring &progId) {
    LPCWSTR msofd = L"MSOFD.Engine.12";
    //msofd = L"Msxml2.DOMDocument.3.0";
    //msofd = L"MnyCore";

    return true ||
           progId == msofd
        || progId == L"MnyCore";
}

bool MHC_ProgIDFromCLSID(REFCLSID clsid, std::wstring &progId) {
    LPOLESTR tmp;
    if (SUCCEEDED(ProgIDFromCLSID(clsid, &tmp))) {
        progId = tmp;
        CoTaskMemFree(tmp);
        return true;
    } else {
        return false;
    }
}

HRESULT WINAPI Mine_CoCreateInstanceEx(REFCLSID a0,
                                       IUnknown* a1,
                                       DWORD a2,
                                       COSERVERINFO* a3,
                                       DWORD a4,
                                       MULTI_QI* a5)
{
    bool noLog = false;
    bool hackVTbl = false;
    std::wstring clsidStr = toString(a0);
    std::wstring progIdStr;
    if (MHC_ProgIDFromCLSID(a0, progIdStr)) {
        noLog = skipLog(progIdStr);
        if (!noLog) {
            _PrintEnter("CoCreateInstanceEx(%ls (%ls),%p,clsctx=%d,si=%p,cnt=%d,res=%p)\n",
                progIdStr.c_str(), clsidStr.c_str(), a1, a2, a3, a4, a5);
        }
        hackVTbl = !noLog && hackVTable(progIdStr);
    } else {
        _PrintEnter("CoCreateInstanceEx(%ls,clsctx=%d,si=%p,cnt=%d,res=%p)\n",
            clsidStr.c_str(), a1, a2, a3, a4, a5);
    }

    HRESULT rv = 0;
    rv = Real_CoCreateInstanceEx(a0, a1, a2, a3, a4, a5);
    if (!noLog) {
        if (rv == S_OK && a5 && *(DWORD *)a5 && a4 == 1) {
            for (DWORD i = 0; i < a4; i++) {
                IUnknown *thisInterface = a5[i].pItf;
                _Print("MULTI_QI[%d] = %ls %p\n", i, toString(*a5[i].pIID).c_str(), thisInterface);
                if (hackVTbl) {
                    using FuncPtr = void *;
                    FuncPtr *vtbl = ((FuncPtr **)thisInterface)[0];
                    auto iidDb = IIDDb::getLockedInstance(); // This keeps the db locked!
                    if (!iidDb->putClassId(a0)) {
                        // if failed, add just the interface, as null
                        _Print("Adding manually, since it failed...\n");
                        if (!iidDb->isInterfaceCached(*a5[i].pIID)) {
                            iidDb->maybePutInterfaceInfo(*a5[i].pIID, nullptr);
                        } else {
                            _Print("Interface was already cached!\n");
                        }
                    } else {
                        // interface should now be cached, warn in case it's not
                        if (!iidDb->isInterfaceCached(*a5[i].pIID)) {
                            _Print("WARNING: Interface %ls should have been cached, but it's not.\n", toString(*a5[i].pIID).c_str());
                        }

                    }
                    _Print("vtbl addr = %p\n", vtbl);
#if !USE_COMSPY
                    hackVtable(vtbl);
#else
                    auto p = new COMSpy(thisInterface, *a5[i].pIID, a0, progIdStr);
                    a5[0].pItf = (IUnknown *) p;
#endif
                }
            }
        }
        _PrintExit("CoCreateInstanceEx(,,,,,) -> %x\n", rv);
    }
    return rv;
}
#endif // MHC


BOOL WINAPI Mine_FreeLibrary(HMODULE a0)
{
    (void)a0;

    return TRUE;
}

DWORD WINAPI Mine_GetModuleFileNameW(HMODULE a0,
                                     LPWSTR a1,
                                     DWORD a2)
{
    _Print("GetModuleFileNameW\n");
    return Real_GetModuleFileNameW(a0, a1, a2);
}

HMODULE WINAPI Mine_GetModuleHandleW(LPCWSTR a0)
{
    _Print("GetModuleHandleW\n");
    return Real_GetModuleHandleW(a0);
}

#if EXPERIMENTAL_DYNAMIC_METHOD_DETOUR
#endif // EXPERIMENTAL_DYNAMIC_METHOD_DETOUR

BOOL canReadMem(const void *memAddr) {
    BOOL ret = FALSE;
    MEMORY_BASIC_INFORMATION info;
    if (VirtualQuery(memAddr, &info, sizeof(MEMORY_BASIC_INFORMATION))) {
        ret = (info.Protect & (PAGE_READONLY|PAGE_READWRITE|PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE)) != 0;
        if (!ret) _Print("Cannot read (PERM: %ls)\n", toStringMemProtect(info.Protect));
    }
    return ret;
}

BOOL isDllFunc(LPCSTR fName) {
    // OJO: We can't use any 3rd library function because ddls have not yet been loaded!
    if (fName == nullptr) return false;
    if (((ULONG_PTR) fName & 0xffff0000) == 0) return false; // function ordinal instead of name!
    //_Print("CanRead");
    if (!canReadMem(fName)) {
        _Print("Cannot read fName string! (%hs)", fName);
        // Try to change permissions
        DWORD oldProt, dummy;
        if (VirtualProtect((void *) fName, 3, PAGE_READONLY, &oldProt)) {
            _Print("Protected string was: %hs\n", fName);
            if (!VirtualProtect((void *) fName, 3, oldProt, &dummy)) {
                _Print("Protection restore failed!\n");
            }
        } else {
            _Print("Could not unprotect memory location %p! (error = 0x%08x)\n", fName, GetLastError());
        }
        return false;
    }
    //_Print("D");
    if (fName[0] != 'D') return false;
    //_Print("l");
    if (fName[1] != 'l') return false;
    //_Print("l");
    if (fName[2] != 'l') return false;
    return true;
}

FARPROC WINAPI Mine_GetProcAddress(HMODULE a0,
                                   LPCSTR a1)
{
    // OJO: a1 may be an ordinal and not a pointer!!
    BOOL isDll = isDllFunc(a1);

    if (isDll) {
        WCHAR wzModule[256];
        GetModuleFileNameW(a0, wzModule, sizeof(wzModule)/sizeof(WCHAR));
        _PrintEnter("GetProcAddress(%ls,%hs)\n", wzModule, a1);
    }

    FARPROC rv = 0;
    __try {
        rv = Real_GetProcAddress(a0, a1);
#if EXPERIMENTAL_DYNAMIC_METHOD_DETOUR
        if (isDll) {
            if (strcmp(a1, "DllGetClassObject") == 0) {
                static bool init = false;
                if (!init) {
                    multiplePatcherInitialize(); // TODO: Make this a class and leverage constructor/destructor
                    init = true; // hope the first call is sill single thread
                }
                rv = MultiplePatcherAdd(rv);
            }
        }
#endif // EXPERIMENTAL_DYNAMIC_METHOD_DETOUR
    } __finally {
        if (isDll) _PrintExit("GetProcAddress(,) -> %p\n", rv);
    }
    return rv;
}

HMODULE WINAPI Mine_LoadLibraryExW(LPCWSTR a0,
                                   HANDLE a1,
                                   DWORD a2)
{
    _PrintEnter("LoadLibraryExW(%ls,%p,%x)\n", a0, a1, a2);

    HMODULE rv = 0;
    __try {
        rv = Real_LoadLibraryExW(a0, a1, a2);
    } __finally {
        _PrintExit("LoadLibraryExW(,,) -> %p\n", rv);
        if (rv) {
            // Too noisy! InstanceEnumerate(rv);
            // Too noisy! ImportEnumerate(rv);
        }
    };
    return rv;
}

HMODULE WINAPI Mine_LoadLibraryW(LPCWSTR a0)
{
    _PrintEnter("LoadLibraryW(%ls)\n", a0);

    HMODULE rv = 0;
    __try {
        rv = Real_LoadLibraryW(a0);
    } __finally {
        _PrintExit("LoadLibraryW() -> %p\n", rv);
    };
    return rv;
}

/////////////////////////////////////////////////////////////
// AttachDetours
//
PCHAR DetRealName(PCHAR psz)
{
    PCHAR pszBeg = psz;
    // Move to end of name.
    while (*psz) {
        psz++;
    }
    // Move back through A-Za-z0-9 names.
    while (psz > pszBeg &&
           ((psz[-1] >= 'A' && psz[-1] <= 'Z') ||
            (psz[-1] >= 'a' && psz[-1] <= 'z') ||
            (psz[-1] >= '0' && psz[-1] <= '9'))) {
        psz--;
    }
    return psz;
}

VOID DetAttach(PVOID *ppbReal, PVOID pbMine, PCHAR psz)
{
    LONG l = DetourAttach(ppbReal, pbMine);
    if (l != 0) {
        Syelog(SYELOG_SEVERITY_NOTICE,
               "Attach failed: `%s': error %d\n", DetRealName(psz), l);
    }
}

VOID DetDetach(PVOID *ppbReal, PVOID pbMine, PCHAR psz)
{
    LONG l = DetourDetach(ppbReal, pbMine);
    if (l != 0) {
        Syelog(SYELOG_SEVERITY_NOTICE,
               "Detach failed: `%s': error %d\n", DetRealName(psz), l);
    }
}

#define ATTACH(x)       DetAttach(&(PVOID&)Real_##x,Mine_##x,#x)
#define DETACH(x)       DetDetach(&(PVOID&)Real_##x,Mine_##x,#x)

LONG AttachDetours(VOID)
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

//    ATTACH(FreeLibrary);
//    ATTACH(GetModuleHandleW);
    ATTACH(GetProcAddress);
#if MHC
//    ATTACH(CoCreateInstance);
    ATTACH(CoCreateInstanceEx);
#endif // MHC
//    ATTACH(LoadLibraryExW);
//    ATTACH(LoadLibraryW);

    return DetourTransactionCommit();
}

LONG DetachDetours(VOID)
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

//    DETACH(FreeLibrary);
//    DETACH(GetModuleHandleW);
    DETACH(GetProcAddress);
#if MHC
//    DETACH(CoCreateInstance);
    DETACH(CoCreateInstanceEx);
#endif // MHC

//    DETACH(LoadLibraryExW);
//    DETACH(LoadLibraryW);

    return DetourTransactionCommit();
}

VOID _PrintEnter(const CHAR *psz, ...)
{
    DWORD dwErr = GetLastError();

    LONG nIndent = 0;
    LONG nThread = 0;
    if (s_nTlsIndent >= 0) {
        nIndent = (LONG)(LONG_PTR)TlsGetValue(s_nTlsIndent);
        TlsSetValue(s_nTlsIndent, (PVOID)(LONG_PTR)(nIndent + 1));
    }
    if (s_nTlsThread >= 0) {
        nThread = (LONG)(LONG_PTR)TlsGetValue(s_nTlsThread);
    }

    if (s_bLog && psz) {
        CHAR szBuf[1024];
        PCHAR pszBuf = szBuf;
        PCHAR pszEnd = szBuf + ARRAYSIZE(szBuf) - 1;
        LONG nLen = (nIndent > 0) ? (nIndent < 35 ? nIndent * 2 : 70) : 0;
        *pszBuf++ = (CHAR)('0' + ((nThread / 100) % 10));
        *pszBuf++ = (CHAR)('0' + ((nThread / 10) % 10));
        *pszBuf++ = (CHAR)('0' + ((nThread / 1) % 10));
        *pszBuf++ = ' ';
        while (nLen-- > 0) {
            *pszBuf++ = ' ';
        }

        va_list  args;
        va_start(args, psz);

        while ((*pszBuf++ = *psz++) != 0 && pszBuf < pszEnd) {
            // Copy characters.
        }
        *pszEnd = '\0';
        SyelogV(SYELOG_SEVERITY_INFORMATION, szBuf, args);

        va_end(args);
    }
    SetLastError(dwErr);
}

VOID _PrintExit(const CHAR *psz, ...)
{
    DWORD dwErr = GetLastError();

    LONG nIndent = 0;
    LONG nThread = 0;
    if (s_nTlsIndent >= 0) {
        nIndent = (LONG)(LONG_PTR)TlsGetValue(s_nTlsIndent) - 1;
        ASSERT(nIndent >= 0);
        TlsSetValue(s_nTlsIndent, (PVOID)(LONG_PTR)nIndent);
    }
    if (s_nTlsThread >= 0) {
        nThread = (LONG)(LONG_PTR)TlsGetValue(s_nTlsThread);
    }

    if (s_bLog && psz) {
        CHAR szBuf[1024];
        PCHAR pszBuf = szBuf;
        PCHAR pszEnd = szBuf + ARRAYSIZE(szBuf) - 1;
        LONG nLen = (nIndent > 0) ? (nIndent < 35 ? nIndent * 2 : 70) : 0;
        *pszBuf++ = (CHAR)('0' + ((nThread / 100) % 10));
        *pszBuf++ = (CHAR)('0' + ((nThread / 10) % 10));
        *pszBuf++ = (CHAR)('0' + ((nThread / 1) % 10));
        *pszBuf++ = ' ';
        while (nLen-- > 0) {
            *pszBuf++ = ' ';
        }

        va_list  args;
        va_start(args, psz);

        while ((*pszBuf++ = *psz++) != 0 && pszBuf < pszEnd) {
            // Copy characters.
        }
        *pszEnd = '\0';
        SyelogV(SYELOG_SEVERITY_INFORMATION, szBuf, args);

        va_end(args);
    }
    SetLastError(dwErr);
}

VOID _Print(const CHAR *psz, ...)
{
    DWORD dwErr = GetLastError();

    LONG nIndent = 0;
    LONG nThread = 0;
    if (s_nTlsIndent >= 0) {
        nIndent = (LONG)(LONG_PTR)TlsGetValue(s_nTlsIndent);
    }
    if (s_nTlsThread >= 0) {
        nThread = (LONG)(LONG_PTR)TlsGetValue(s_nTlsThread);
    }

    if (s_bLog && psz) {
        CHAR szBuf[1024];
        PCHAR pszBuf = szBuf;
        PCHAR pszEnd = szBuf + ARRAYSIZE(szBuf) - 1;
        LONG nLen = (nIndent > 0) ? (nIndent < 35 ? nIndent * 2 : 70) : 0;
        *pszBuf++ = (CHAR)('0' + ((nThread / 100) % 10));
        *pszBuf++ = (CHAR)('0' + ((nThread / 10) % 10));
        *pszBuf++ = (CHAR)('0' + ((nThread / 1) % 10));
        *pszBuf++ = ' ';
        while (nLen-- > 0) {
            *pszBuf++ = ' ';
        }

        va_list  args;
        va_start(args, psz);

        while ((*pszBuf++ = *psz++) != 0 && pszBuf < pszEnd) {
            // Copy characters.
        }
        *pszEnd = '\0';
        SyelogV(SYELOG_SEVERITY_INFORMATION, szBuf, args);

        va_end(args);
    }
    SetLastError(dwErr);
}

VOID AssertMessage(CONST PCHAR pszMsg, CONST PCHAR pszFile, ULONG nLine)
{
    Syelog(SYELOG_SEVERITY_FATAL,
           "ASSERT(%s) failed in %s, line %d.\n", pszMsg, pszFile, nLine);
}

//////////////////////////////////////////////////////////////////////////////
//
PIMAGE_NT_HEADERS NtHeadersForInstance(HINSTANCE hInst)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hInst;
    __try {
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            SetLastError(ERROR_BAD_EXE_FORMAT);
            return NULL;
        }

        PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)pDosHeader +
                                                          pDosHeader->e_lfanew);
        if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) {
            SetLastError(ERROR_INVALID_EXE_SIGNATURE);
            return NULL;
        }
        if (pNtHeader->FileHeader.SizeOfOptionalHeader == 0) {
            SetLastError(ERROR_EXE_MARKED_INVALID);
            return NULL;
        }
        return pNtHeader;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
    }
    SetLastError(ERROR_EXE_MARKED_INVALID);

    return NULL;
}

static inline PBYTE RvaToVa(PBYTE pbBase, DWORD nOffset)
{
    return nOffset ? pbBase + nOffset : NULL;
}

#if _MSC_VER >= 1900
#pragma warning(push)
#pragma warning(disable:4456) // declaration hides previous local declaration
#endif

BOOL ImportEnumerate(HINSTANCE hInst)
{
    PBYTE pbBase = (PBYTE)hInst;
    PIMAGE_NT_HEADERS pNtHeader;                    // Read & Write
    PIMAGE_SECTION_HEADER pSectionHeaders;
    DWORD nPeOffset;
    DWORD nSectionsOffset;

    ////////////////////////////////////////////////////// Process DOS Header.
    //
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pbBase;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return FALSE;
    }
    nPeOffset = pDosHeader->e_lfanew;

    /////////////////////////////////////////////////////// Process PE Header.
    //
    pNtHeader = (PIMAGE_NT_HEADERS)RvaToVa(pbBase, nPeOffset);
    if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) {
        return FALSE;
    }
    if (pNtHeader->FileHeader.SizeOfOptionalHeader == 0) {
        return FALSE;
    }
    nSectionsOffset = nPeOffset
        + sizeof(pNtHeader->Signature)
        + sizeof(pNtHeader->FileHeader)
        + pNtHeader->FileHeader.SizeOfOptionalHeader;

    ///////////////////////////////////////////////// Process Section Headers.
    //
    pSectionHeaders = (PIMAGE_SECTION_HEADER)RvaToVa(pbBase, nSectionsOffset);

    //////////////////////////////////////////////////////// Get Import Table.
    //
    DWORD rvaImageDirectory = pNtHeader->OptionalHeader
        .DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    PIMAGE_IMPORT_DESCRIPTOR iidp
        = (PIMAGE_IMPORT_DESCRIPTOR)RvaToVa(pbBase, rvaImageDirectory);

    if (iidp == NULL) {
        return FALSE;
    }

    DWORD nFiles = 0;
    for (; iidp[nFiles].Characteristics != 0; nFiles++) {
        // Count the files.
    }

    for (DWORD n = 0; n < nFiles; n++, iidp++) {
        DWORD rvaName = iidp->Name;
        PCHAR pszName = (PCHAR)RvaToVa(pbBase, rvaName);

        DWORD rvaThunk = (DWORD)iidp->OriginalFirstThunk;
        PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)RvaToVa(pbBase, rvaThunk);
        rvaThunk = (DWORD)iidp->FirstThunk;
        PIMAGE_THUNK_DATA pBoundThunk = (PIMAGE_THUNK_DATA)RvaToVa(pbBase, rvaThunk);

        Syelog(SYELOG_SEVERITY_INFORMATION,
               "%s [%p %p]\n", pszName, pThunk, pBoundThunk);

        DWORD nNames = 0;
        if (pThunk == NULL) {
            break;
        }

        for (; pThunk[nNames].u1.Ordinal; nNames++) {
            // Count the imports.
        }

        for (DWORD f = 0; f < nNames; f++) {
            DWORD nOrdinal = 0;
            PCHAR pszName = NULL;
            PDWORD pFunc = (PDWORD)pBoundThunk[f].u1.Function;
            DWORD rvaName = (DWORD)pThunk[f].u1.Ordinal;

            if (rvaName & IMAGE_ORDINAL_FLAG) {
                nOrdinal = IMAGE_ORDINAL(rvaName);
            }
            else {
                PIMAGE_IMPORT_BY_NAME pName
                    = (PIMAGE_IMPORT_BY_NAME)RvaToVa(pbBase, rvaName);
                if (pName) {
                    pszName = (PCHAR)pName->Name;
                }
            }
            Syelog(SYELOG_SEVERITY_INFORMATION,
                   "  %-32.32s %4I64d %p\n", pszName, nOrdinal, pFunc);
        }
    }
    return TRUE;
}

#if _MSC_VER >= 1900
#pragma warning(pop)
#endif

BOOL InstanceEnumerate(HINSTANCE hInst)
{
    WCHAR wzDllName[MAX_PATH];

    PIMAGE_NT_HEADERS pinh = NtHeadersForInstance(hInst);
    if (pinh && Real_GetModuleFileNameW(hInst, wzDllName, ARRAYSIZE(wzDllName))) {
        Syelog(SYELOG_SEVERITY_INFORMATION,
               "### %08lx: %-43.43ls %08x\n",
               hInst, wzDllName, pinh->OptionalHeader.CheckSum);
        return TRUE;
    }
    return FALSE;
}

BOOL ProcessEnumerate()
{
    Syelog(SYELOG_SEVERITY_INFORMATION,
           "######################################################### Binaries\n");
    for (HINSTANCE hInst = NULL; (hInst = DetourEnumerateModules(hInst)) != NULL;) {
        InstanceEnumerate(hInst);
    }
    Syelog(SYELOG_SEVERITY_INFORMATION, "###\n");

    return ImportEnumerate(GetModuleHandle(NULL));
}

//////////////////////////////////////////////////////////////////////////////
//
// DLL module information
//
BOOL ThreadAttach(HMODULE hDll)
{
    (void)hDll;

    if (s_nTlsIndent >= 0) {
        TlsSetValue(s_nTlsIndent, (PVOID)0);
    }
    if (s_nTlsThread >= 0) {
        LONG nThread = InterlockedIncrement(&s_nThreadCnt);
        TlsSetValue(s_nTlsThread, (PVOID)(LONG_PTR)nThread);
    }
    return TRUE;
}

BOOL ThreadDetach(HMODULE hDll)
{
    (void)hDll;

    if (s_nTlsIndent >= 0) {
        TlsSetValue(s_nTlsIndent, (PVOID)0);
    }
    if (s_nTlsThread >= 0) {
        TlsSetValue(s_nTlsThread, (PVOID)0);
    }
    return TRUE;
}

BOOL ProcessAttach(HMODULE hDll)
{
    s_bLog = FALSE;
    s_nTlsIndent = TlsAlloc();
    s_nTlsThread = TlsAlloc();
    ThreadAttach(hDll);

    WCHAR wzExeName[MAX_PATH];

    s_hInst = hDll;
    Real_GetModuleFileNameW(hDll, s_wzDllPath, ARRAYSIZE(s_wzDllPath));
    Real_GetModuleFileNameW(NULL, wzExeName, ARRAYSIZE(wzExeName));

    SyelogOpen("trclnk" DETOURS_STRINGIFY(DETOURS_BITS), SYELOG_FACILITY_APPLICATION);
    // Too noisy! ProcessEnumerate();

    LONG error = AttachDetours();
    if (error != NO_ERROR) {
        Syelog(SYELOG_SEVERITY_FATAL, "### Error attaching detours: %d\n", error);
    }
    _Print("Hello world!\n");


    s_bLog = TRUE;
    return TRUE;
}

BOOL ProcessDetach(HMODULE hDll)
{
    ThreadDetach(hDll);
    s_bLog = FALSE;

    LONG error = DetachDetours();
    if (error != NO_ERROR) {
        Syelog(SYELOG_SEVERITY_FATAL, "### Error detaching detours: %d\n", error);
    }

    Syelog(SYELOG_SEVERITY_NOTICE, "### Closing.\n");
    SyelogClose(FALSE);

    if (s_nTlsIndent >= 0) {
        TlsFree(s_nTlsIndent);
    }
    if (s_nTlsThread >= 0) {
        TlsFree(s_nTlsThread);
    }

    return TRUE;
}

BOOL APIENTRY DllMain(HINSTANCE hModule, DWORD dwReason, PVOID lpReserved)
{
    (void)hModule;
    (void)lpReserved;

    if (DetourIsHelperProcess()) {
        return TRUE;
    }

    switch (dwReason) {
      case DLL_PROCESS_ATTACH:
        DetourRestoreAfterWith();
        return ProcessAttach(hModule);
      case DLL_PROCESS_DETACH:
        return ProcessDetach(hModule);
      case DLL_THREAD_ATTACH:
        return ThreadAttach(hModule);
      case DLL_THREAD_DETACH:
        return ThreadDetach(hModule);
    }
    return TRUE;
}
//
///////////////////////////////////////////////////////////////// End of File.
