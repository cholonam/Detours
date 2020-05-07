#include "precomp.h"

#include "iiddb.h"
using MHC_NS::IIDDb;
#include "tostring.h"

#include <combaseapi.h> // StringFromIID, CoTaskMemFree

#define DEBUG_TOSTRING 1

#ifdef DEBUG_TOSTRING
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

#define MHC_CASE(ENUMNAME) case ENUMNAME: return L#ENUMNAME
#define MHC_CASE2(ENUMNAME, TXT) case ENUMNAME: return L#TXT
#define MHC_DEFAULT(TXT) default: return L#TXT

MHC_NS::RETTYPE toString(CALLCONV e) noexcept {
    switch (e) {
        MHC_CASE2(CC_FASTCALL  , __fastcall);
        MHC_CASE2(CC_CDECL     , __cdecl);
        MHC_CASE2(CC_PASCAL    , __pascal);
        MHC_CASE2(CC_MACPASCAL , __macpascal);
        MHC_CASE2(CC_STDCALL   , __stdcall);
        MHC_CASE2(CC_FPFASTCALL, __fpfastcall);
        MHC_CASE2(CC_SYSCALL   , __syscal);
        MHC_CASE2(CC_MPWCDECL  , __mpwcdecl);
        MHC_CASE2(CC_MPWPASCAL , __mpwpascal);
        MHC_CASE2(CC_MAX       , __max);
        MHC_DEFAULT(?);
    }
}

MHC_NS::RETTYPE toString(FUNCKIND e) noexcept {
    switch (e) {
        MHC_CASE2(FUNC_VIRTUAL    , Virtual);
        MHC_CASE2(FUNC_PUREVIRTUAL, PureVirt);
        MHC_CASE2(FUNC_NONVIRTUAL , NonVirt);
        MHC_CASE2(FUNC_STATIC     , Static);
        MHC_CASE2(FUNC_DISPATCH   , Dispatch);
        MHC_DEFAULT(?);
    }
}

MHC_NS::RETTYPE toString(INVOKEKIND e) noexcept {
    switch (e) {
        MHC_CASE2(INVOKE_FUNC          , Func);
        MHC_CASE2(INVOKE_PROPERTYGET   , PropGet);
        MHC_CASE2(INVOKE_PROPERTYPUT   , PropPut);
        MHC_CASE2(INVOKE_PROPERTYPUTREF, PutRef);
        MHC_DEFAULT(?);
    }
}

MHC_NS::RETTYPE toString(TYPEKIND e) noexcept {
    switch (e) {
        MHC_CASE2(TKIND_RECORD   , Record);
        MHC_CASE2(TKIND_MODULE   , Module);
        MHC_CASE2(TKIND_INTERFACE, Interface);
        MHC_CASE2(TKIND_DISPATCH , Dispatch);
        MHC_CASE2(TKIND_ENUM     , Enum);
        MHC_CASE2(TKIND_COCLASS  , CoClass);
        MHC_CASE2(TKIND_ALIAS    , Alias);
        MHC_CASE2(TKIND_UNION    , Union);
        MHC_CASE2(TKIND_MAX      , Max);
        MHC_DEFAULT(?);
    }
}


MHC_NS::RETTYPE toStringMemProtect(DWORD e) noexcept {
    switch (e) {
        MHC_CASE2(0x01, NOACCESS);
        MHC_CASE2(0x02, RO);
        MHC_CASE2(0x04, RW);
        MHC_CASE2(0x08, WC);
        MHC_CASE2(0x10, XO);
        MHC_CASE2(0x20, XR);
        MHC_CASE2(0x40, XRW);
        MHC_CASE2(0x80, XWC);
        MHC_DEFAULT(?);
    }
}

std::wstring toString(const GUID &guid) noexcept {
    std::wstring ret;
    if (guid == IID_IUnknown) {
        ret = L"IUnknown";
    } else if (guid == IID_IClassFactory) {
        ret = L"IClassFactory";
    } else {
        LPOLESTR tmp = nullptr;
        StringFromIID(guid, &tmp);
        ret = tmp;
        CoTaskMemFree(tmp);
        // check only cached interfaces
        auto ii = IIDDb::getLockedInstance()->getCachedInterfaceInfo((IID) guid);
        if (ii != nullptr) {
            ret = ret + L" (" + ii->dllPath + L")";
        }
    }
    return ret;
}

MHC_NS::RETTYPE toString(VARTYPE vt) noexcept {
    switch (vt) {
        MHC_CASE(VT_EMPTY);
        MHC_CASE(VT_NULL);
        MHC_CASE(VT_I2);
        MHC_CASE(VT_I4);
        MHC_CASE(VT_R4);
        MHC_CASE(VT_R8);
        MHC_CASE(VT_CY);
        MHC_CASE(VT_DATE);
        MHC_CASE(VT_BSTR);
        MHC_CASE(VT_DISPATCH);
        MHC_CASE(VT_ERROR);
        MHC_CASE(VT_BOOL);
        MHC_CASE(VT_VARIANT);
        MHC_CASE(VT_UNKNOWN);
        MHC_CASE(VT_DECIMAL);
        MHC_CASE(VT_I1);
        MHC_CASE(VT_UI1);
        MHC_CASE(VT_UI2);
        MHC_CASE(VT_UI4);
        MHC_CASE(VT_I8);
        MHC_CASE(VT_UI8);
        MHC_CASE(VT_INT);
        MHC_CASE(VT_UINT);
        MHC_CASE(VT_VOID);
        MHC_CASE(VT_HRESULT);
        MHC_CASE(VT_PTR);
        MHC_CASE(VT_SAFEARRAY);
        MHC_CASE(VT_CARRAY);
        MHC_CASE(VT_USERDEFINED);
        MHC_CASE(VT_LPSTR);
        MHC_CASE(VT_LPWSTR);
        MHC_CASE(VT_RECORD);
        MHC_CASE(VT_INT_PTR);
        MHC_CASE(VT_UINT_PTR);
        MHC_CASE(VT_FILETIME);
        MHC_CASE(VT_BLOB);
        MHC_CASE(VT_STREAM);
        MHC_CASE(VT_STORAGE);
        MHC_CASE(VT_STREAMED_OBJECT);
        MHC_CASE(VT_STORED_OBJECT);
        MHC_CASE(VT_BLOB_OBJECT);
        MHC_CASE(VT_CF);
        MHC_CASE(VT_CLSID);
        MHC_CASE(VT_VERSIONED_STREAM);
        MHC_CASE(VT_BSTR_BLOB);
        MHC_CASE(VT_VECTOR);
        MHC_CASE(VT_ARRAY);
        MHC_CASE(VT_BYREF);
        MHC_CASE(VT_RESERVED);
        MHC_CASE(VT_ILLEGAL);
        default: {
            _Debug("WARNING: VT not found: %d\n", vt);
            return L"?";
        }
    }
}

namespace {
/// FROM https://stackoverflow.com/questions/7008047/is-there-a-way-to-get-the-string-representation-of-hresult-value-using-win-api
LPWSTR SRUTIL_WinErrorMsg(int nErrorCode, LPWSTR pStr, WORD wLength )
{
    try
    {
        LPWSTR  szBuffer = pStr;
        int nBufferSize = wLength;

        //
        // prime buffer with error code
        //
        wsprintfW( szBuffer, L"Error code %u", nErrorCode);

        //
        // if we have a message, replace default with msg.
        //
        FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM,
                NULL, nErrorCode,
                LANG_USER_DEFAULT, // Default language
                (LPWSTR) szBuffer,   
                nBufferSize,    
                NULL );
    }
    catch(...)
    {
    }
    return pStr;
} // End of SRUTIL_WinErrorMsg()
} // anonymous namespace

std::wstring toString(HRESULT hr) noexcept {
    std::wstring ret;
    WCHAR errMsg[BUFSIZ] = { 0 };

    SRUTIL_WinErrorMsg(hr, errMsg, BUFSIZ);
    // just to be safe...
    errMsg[BUFSIZ - 1] = 0;
    ret = errMsg;
    // if a CRLF at the end, remove it..
    if (ret.length() > 0 && ret[ret.length() - 1] == L'\n') ret = ret.substr(0, ret.length() - 1);
    if (ret.length() > 0 && ret[ret.length() - 1] == L'\r') ret = ret.substr(0, ret.length() - 1);
    return ret;
}
