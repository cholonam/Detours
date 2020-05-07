#include "precomp.h"

#include "iiddb.h"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <combaseapi.h> // StringFromIID
#include <Shlwapi.h> // PathUnExpandEnvStringsW
#include <synchapi.h> // CRITICAL_SECTION

#include <map>

#include "cslock.h"
#include "tostring.h"

#ifdef DEBUG_IIDDB
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

int operator<(const GUID &a, const GUID&b) {
    uint64_t *aa = (uint64_t *) &a;
    uint64_t *bb = (uint64_t *) &b;

    return  aa[1] <  bb[1]
        || (aa[1] == bb[1] && aa[0] < bb[0]);
}

namespace {
CRITICAL_SECTION cs;
static std::map<
    IID,
    MHC_NS::IIDDb::InterfaceInfoSPtr
> iidInfoMap;

static std::map<
    CLSID,
    bool
> clsidInfoMap;

// More high-level. Use this!
LONG GetRegistryStringValue(HKEY hKey, const std::wstring &keyPath, LPCWSTR valueOrNullForDefault, std::wstring &ret) noexcept {
    WCHAR szBuffer[512];
    DWORD dwBufferSize = sizeof(szBuffer);
    LONG err;
    HKEY hOpenKey = nullptr;

    err = RegOpenKeyExW(hKey, keyPath.c_str(), 0, KEY_QUERY_VALUE, &hOpenKey);
    if (err != ERROR_SUCCESS) goto cleanup;

    err = RegQueryValueExW(hOpenKey, valueOrNullForDefault, 0, nullptr, (LPBYTE) szBuffer, &dwBufferSize);
    if (err != ERROR_SUCCESS) goto cleanup;

    ret = szBuffer;
cleanup:
    if (hOpenKey) RegCloseKey(hOpenKey);
    return err;
}

LONG GetStringRegKey(HKEY hKey, const std::wstring &strValueName, std::wstring &strValue, const std::wstring &strDefaultValue) noexcept
{
    strValue = strDefaultValue;
    WCHAR szBuffer[512];
    DWORD dwBufferSize = sizeof(szBuffer);
    ULONG nError;
    nError = RegQueryValueExW(hKey, strValueName.c_str(), 0, NULL, (LPBYTE)szBuffer, &dwBufferSize);
    if (ERROR_SUCCESS == nError)
    {
        strValue = szBuffer;
    }
    return nError;
}

} // anonymous namespace

namespace MHC_NS {

IIDDb::IIDDb() {
    InitializeCriticalSection(&cs);
}
IIDDb::~IIDDb() {
    DeleteCriticalSection(&cs);
}

IIDDb *IIDDb::getInstance() noexcept {
    static IIDDb internal;
    return &internal;
}

IIDDb::LockedIIDDb IIDDb::getLockedInstance() noexcept {
    return IIDDb::LockedIIDDb(*getInstance());
}

bool IIDDb::putClassId(REFCLSID clsid) noexcept {
    MHC_CSLOCK;

    bool ret = false;

    auto pos = clsidInfoMap.find(clsid);
    if (pos != clsidInfoMap.end()) { return true; } // already added

    clsidInfoMap[clsid] = true; // just mark as added
    // find dll and add all interfaces to database
    LPOLESTR iidStr = nullptr;
    StringFromIID(clsid, &iidStr);
    std::wstring path = L"SOFTWARE\\Classes\\CLSID\\";
    path = path + iidStr + L"\\InprocServer32";
    HKEY hKey = 0;
    LONG lRes = RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.c_str(), 0, KEY_QUERY_VALUE, &hKey);
    if (lRes != ERROR_SUCCESS) {
        _Print("RegOpenKeyEx failed (%d)\n", lRes);
        ret = false;
        goto cleanup;
    }
    {
        LONG err;
        std::wstring typeLibPath;
        if ((err = GetStringRegKey(hKey, L"", typeLibPath, L"")) == ERROR_SUCCESS) {
            // path may contain environment variables...
            if (typeLibPath.find(L'%') != typeLibPath.npos) {
                _Print("Expanding path: %ls\n", typeLibPath.c_str());
                WCHAR buf[MAX_PATH];
                if (ExpandEnvironmentStringsW(typeLibPath.c_str(), buf, MAX_PATH) != 0) {
                    _Print("buf: %ls", buf);
                    typeLibPath = buf;
                } else {
                    _Print("ExpandEnvironmentStringsW failed! (Error: 0x%x)\n", GetLastError());
                }
            }
            if (SUCCEEDED(processTypeLib(clsid, typeLibPath))) {
                // _Print("TypeLib %ls (%ls) loaded\n", toString(clsid).c_str(), typeLibPath.c_str());
            } else {
                _Print("TypeLib %ls (%ls) load failed!\n", toString(clsid).c_str(), typeLibPath.c_str());
                goto cleanup;
            }
        } else {
            _Print("GetStringRegKey failed (%d)\n", err);
            goto cleanup;
        }
    }
    ret = true;
cleanup:
    CoTaskMemFree(iidStr);
    if (hKey) RegCloseKey(hKey);
    return ret;
}

IIDDb::InterfaceInfoSPtr IIDDb::getCachedInterfaceInfo(const IID &iidRef) noexcept {
    MHC_CSLOCK;

    auto pos = iidInfoMap.find(iidRef);
    if (pos != iidInfoMap.end()) return pos->second;
    else return nullptr;
}


IIDDb::InterfaceInfoSPtr IIDDb::getInterfaceInfo(const IID &iidRef, bool shouldNotExist) noexcept {
    MHC_CSLOCK;

    auto pos = iidInfoMap.find(iidRef);
    if (pos != iidInfoMap.end()) return pos->second;

    std::wstring iidStr = ::toString(iidRef);
    // Interface not yet cached. Find it!
    if (!shouldNotExist) {
        _Print("TODO: An interface has been requested which is not yet cached (%ls)\n", iidStr.c_str());
    }

    // Find in registry
    std::wstring path = std::wstring(L"Software\\Classes\\Interface\\") + iidStr;
    std::wstring iFaceName;
    if (GetRegistryStringValue(HKEY_LOCAL_MACHINE, path.c_str(), nullptr, iFaceName) == ERROR_SUCCESS) {
        // _Print("Interface name from regsitry: %ls\n", iFaceName.c_str());
        path += L"\\TypeLib";
        std::wstring typeLibGuidStr;
        if (GetRegistryStringValue(HKEY_LOCAL_MACHINE, path.c_str(), nullptr, typeLibGuidStr) == ERROR_SUCCESS) {
            // _Print("TypeLib found in regsitry (%ls)\n", typeLibGuidStr.c_str());
            std::wstring typeLibVersion;
            if (GetRegistryStringValue(HKEY_LOCAL_MACHINE, path.c_str(), L"Version", typeLibVersion) == ERROR_SUCCESS) {
                // _Print("TypeLib version: %ls\n", typeLibVersion.c_str());
                path = std::wstring(L"Software\\Classes\\TypeLib\\") + typeLibGuidStr + L"\\" + typeLibVersion + L"\\0\\win32";
                std::wstring typeLibPath;
                if (GetRegistryStringValue(HKEY_LOCAL_MACHINE, path.c_str(), nullptr, typeLibPath) == ERROR_SUCCESS) {
                    // _Print("TypeLib path: %ls\n", typeLibPath.c_str());
                    _Print("***** TODO: Continue from here (one method that process the typelib from the path...)\n");
                    iidInfoMap[iidRef] = nullptr;
                }
            }
        }
    }
    return nullptr;
}

bool IIDDb::isInterfaceCached(const IID &iidRef) noexcept {
    MHC_CSLOCK;

    auto pos = iidInfoMap.find(iidRef);
    return pos != iidInfoMap.end();
}

void IIDDb::maybePutInterfaceInfo(const IID &iidRef, InterfaceInfoSPtr interfaceInfo) noexcept {
    MHC_CSLOCK;

    if (isInterfaceCached(iidRef)) {
        _Print("ERROR: Interface %ls already in DB!! Adding again...\n", toString(iidRef).c_str());
    }
    auto ii = getCachedInterfaceInfo(iidRef);
    if (ii != nullptr) {
        _Print("Present: %ls (DLL: %ls)\n", ii->typeLibInfoStr().c_str(), ii->dllPath.c_str());
        _Print("New    : %ls (DLL: %ls)\n", ii->typeLibInfoStr().c_str(), ii->dllPath.c_str());
    }
    iidInfoMap[iidRef] = interfaceInfo;
}

std::wstring IIDDb::GetDll(const IID &iidRef) noexcept {
    MHC_CSLOCK;
    auto pos = iidInfoMap.find(iidRef);
    if (pos != iidInfoMap.end()) return pos->second->dllPath;

    // return an empty string
    return std::wstring();
}

HRESULT IIDDb::processTypeLib(REFCLSID clsid, const std::wstring &typeLibPath) noexcept {
        ITypeLib *tl = nullptr;
        HRESULT hr = LoadTypeLibEx(typeLibPath.c_str(), REGKIND_NONE, &tl);
        if (SUCCEEDED(hr)) {
            hr = processTypeLib(tl, typeLibPath);
            if (SUCCEEDED(hr)) {
                clsidInfoMap[clsid] = true; // mark as load succeeded
            } else {
                _Print("processTypeLib error: %x\n", (int) hr);
                clsidInfoMap[clsid] = false; // mark as load failed
            }
        } else {
            _Debug("LoadTypeLibEx error: %x\n", (int) hr);
            clsidInfoMap[clsid] = false; // mark as load failed
        }
        if (tl) tl->Release();
        return hr;
}

// This function should add ALL the interfaces in the type lib to the database
// This function DOES NOT LOCK THE CRITICAL SECTION (MUST BE CALLED WITH THE CRITICAL SECTION LOCKED)
HRESULT IIDDb::processTypeLib(ITypeLib *tl, const std::wstring &typeLibPath) noexcept {
    ITypeInfo *typeInfo;
    HRESULT hr = S_OK;

    UINT typeCnt = tl->GetTypeInfoCount();
    for (UINT i = 0; i < typeCnt; i++) {
        TYPEKIND typeKind;
        if (FAILED(tl->GetTypeInfoType(i, &typeKind))) {
            _Print("GetTypeInfoType(%d) failed!\n", i);
            hr++; // return number of failed
            continue;
        }
        if (/*typeKind == TKIND_COCLASS
            ||*/ typeKind == TKIND_INTERFACE
            || typeKind == TKIND_DISPATCH) {
            if (FAILED(tl->GetTypeInfo(i, &typeInfo))) {
                _Print("GetTypeInfo(%d) failed!\n", i);
                hr++; // return number of failed
                continue;
            };
            TYPEATTR *typeAttr = nullptr;
            typeInfo->GetTypeAttr(&typeAttr);
            if (!typeAttr) {
                hr++; // return number of failed
                continue;
            }
            {   BSTR name = nullptr;
                typeInfo->GetDocumentation(MEMBERID_NIL, &name, nullptr, nullptr, nullptr);
                _Print("Type kind=%ls uuid=%ls name=%ls\n", toString(typeKind), toString(typeAttr->guid).c_str(), name);
                SysFreeString(name);
            }
            GUID guid = typeAttr->guid;
            UINT cImplTypes = (UINT) typeAttr->cImplTypes;
            // Get parent interfaces (there should be just one)
            for (UINT j = 0; j < cImplTypes; j++) {
                BSTR iName = nullptr;
                HREFTYPE hRefType;
                ITypeInfo *classTypeInfo;
                typeInfo->GetRefTypeOfImplType(j, &hRefType);
                typeInfo->GetRefTypeInfo(hRefType, &classTypeInfo);
                if (SUCCEEDED(classTypeInfo->GetDocumentation(MEMBERID_NIL, &iName, nullptr, nullptr, nullptr))) {
                    if (!iName) {
                        _Print(" - Iface name is null!\n");
                    } else if (
                        // wcscmp does not validate its parameters!
                        typeKind == TKIND_INTERFACE && wcscmp(iName ? iName : L"", L"IUnknown") ||
                        typeKind == TKIND_DISPATCH  && wcscmp(iName ? iName : L"", L"IDispatch")) {
                        // Print only if it's a weird case...
                        _Print(" - Iface name=%ls\n", iName);
                    }
                } else {
                    _Print(" - Iface GetDocumentation() failed!\n");
                }
                classTypeInfo->Release();
                SysFreeString(iName);
            }

            auto interfaceInfo = std::make_shared<MHC_NS::InterfaceInfo>(); // new interface (TO BE ADDED)

            // methods
            UINT cFuncs = typeAttr->cFuncs;
            for (UINT j = 0; j < cFuncs; j++) {
                FUNCDESC *funcDesc;
                if (SUCCEEDED(typeInfo->GetFuncDesc(j, &funcDesc))) {
                    // Get Function Name
                    BSTR fName = nullptr;
                    UINT cNames = 0;
                    if (FAILED(typeInfo->GetNames(funcDesc->memid, &fName, 1, &cNames))) {
                        _Print("GetNames(%d) failed!\n", funcDesc->memid);
                    } else {
                        if (cNames != 1) _Print("cNames = %d\n", cNames);
                    }
#if 0
                    _Print(" - FUNCDESC(%ls):%s%s"
                        " cParams:%d cParamsOpt:%d"
                        " cScodes:%d"
                        "%s%s"
                        " invkind:%s lprgelemdescParam:0x%x"
                        " lprgscode:0x%x memid:%d"
                        " oVft:0x%x(%d) wFuncFlags:0x%x\n",
                        fName,
                        funcDesc->callconv == CC_STDCALL ? "" : " callconv:",
                        funcDesc->callconv == CC_STDCALL ? "" : toString(funcDesc->callconv),
                        funcDesc->cParams, funcDesc->cParamsOpt,
                        (int) funcDesc->cScodes,
                        funcDesc->funckind == FUNC_PUREVIRTUAL ? "" : " funckind:",
                        funcDesc->funckind == FUNC_PUREVIRTUAL ? "" : toString(funcDesc->funckind),
                        toString(funcDesc->invkind), funcDesc->lprgelemdescParam,
                        funcDesc->lprgscode, funcDesc->memid,
                        (int) funcDesc->oVft, (int) funcDesc->oVft / sizeof(void *), (int) funcDesc->wFuncFlags);
#endif

                    interfaceInfo->addMethod(funcDesc->oVft / sizeof(void *), fName); // TODO: Add full signature, including parameters and retval!

                    typeInfo->ReleaseFuncDesc(funcDesc);
                    SysFreeString(fName);
                } else {
                    _Print("typeInfo->GetFuncDesc() failed!\n");
                }
            }
            typeInfo->ReleaseTypeAttr(typeAttr);
            typeInfo->Release();

            // Add new interface
            interfaceInfo->dllPath = typeLibPath;
            interfaceInfo->typeLib = tl; tl->AddRef();
            interfaceInfo->m_iid = guid;
            //_Print("Maybe adding interface info (%ls)\n", toString(guid).c_str());
            MHC_NS::IIDDb::getInstance()->maybePutInterfaceInfo(guid, interfaceInfo);
        } else {
            // _Print("Other: typeKind=%d\n", typeKind);
        }
    }
    return hr;
}

void IIDDb::lock() noexcept {
    EnterCriticalSection(&cs);
}

void IIDDb::unlock() noexcept {
    LeaveCriticalSection(&cs);
}


} // namespace MHC_NS
