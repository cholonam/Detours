#include "precomp.h"

#include "interfaceinfo.h"

#include <atlbase.h> // CCom*
#include <sstream> // std::ostringstream

#include "cslock.h"
#include "tostring.h"

// code from: <<http://yanaware.com/com4me/typeinfo2.php-author=Sean%20BAXTER&mail=spec@ript.net&url=http---ript.net-~spec-&idTute=13.htm>>
std::string stringifyCustomType(HREFTYPE refType, ITypeInfo* pti) {
    CComPtr<ITypeInfo> pTypeInfo(pti);
    CComPtr<ITypeInfo> pCustTypeInfo;
    HRESULT hr(pTypeInfo->GetRefTypeInfo(refType, &pCustTypeInfo));
    if(hr) return "UnknownCustomType";
    CComBSTR bstrType;
    hr = pCustTypeInfo->GetDocumentation(-1, &bstrType, 0, 0, 0);
    if(hr) return "UnknownCustomType";
    char ansiType[MAX_PATH];
    WideCharToMultiByte(CP_ACP, 0, bstrType, bstrType.Length() + 1,
        ansiType, MAX_PATH, 0, 0);
    return ansiType;
}

// code from: <<http://yanaware.com/com4me/typeinfo2.php-author=Sean%20BAXTER&mail=spec@ript.net&url=http---ript.net-~spec-&idTute=13.htm>>
std::string stringifyTypeDesc(TYPEDESC* typeDesc, ITypeInfo* pTypeInfo) {
    std::ostringstream oss;
    if(typeDesc->vt == VT_PTR) {
        oss<< stringifyTypeDesc(typeDesc->lptdesc, pTypeInfo)<< '*';
        return oss.str();
    }
    if(typeDesc->vt == VT_SAFEARRAY) {
        oss<< "SAFEARRAY("
            << stringifyTypeDesc(typeDesc->lptdesc, pTypeInfo)<< ')';
        return oss.str();
    }
    if(typeDesc->vt == VT_CARRAY) {
        oss<< stringifyTypeDesc(&typeDesc->lpadesc->tdescElem, pTypeInfo);
        for(int dim(0); typeDesc->lpadesc->cDims; ++dim)
            oss<< '['<< typeDesc->lpadesc->rgbounds[dim].lLbound<< "..."
                << (typeDesc->lpadesc->rgbounds[dim].cElements +
                typeDesc->lpadesc->rgbounds[dim].lLbound - 1)<< ']';
        return oss.str();
    }
    if(typeDesc->vt == VT_USERDEFINED) {
        oss<< stringifyCustomType(typeDesc->hreftype, pTypeInfo);
        return oss.str();
    }
   
    switch(typeDesc->vt) {
        // VARIANT/VARIANTARG compatible types
    case VT_I2: return "short";
    case VT_I4: return "long";
    case VT_R4: return "float";
    case VT_R8: return "double";
    case VT_CY: return "CY";
    case VT_DATE: return "DATE";
    case VT_BSTR: return "BSTR";
    case VT_DISPATCH: return "IDispatch*";
    case VT_ERROR: return "SCODE";
    case VT_BOOL: return "VARIANT_BOOL";
    case VT_VARIANT: return "VARIANT";
    case VT_UNKNOWN: return "IUnknown*";
    case VT_UI1: return "BYTE";
    case VT_DECIMAL: return "DECIMAL";
    case VT_I1: return "char";
    case VT_UI2: return "USHORT";
    case VT_UI4: return "ULONG";
    case VT_I8: return "__int64";
    case VT_UI8: return "unsigned __int64";
    case VT_INT: return "int";
    case VT_UINT: return "UINT";
    case VT_HRESULT: return "HRESULT";
    case VT_VOID: return "void";
    case VT_LPSTR: return "char*";
    case VT_LPWSTR: return "wchar_t*";
    }
    return "BIG ERROR!";
}

namespace MHC_NS {

InterfaceInfo::InterfaceInfo() noexcept
    : dllPath()
    , typeLib(nullptr) {}

InterfaceInfo::InterfaceInfo(const InterfaceInfo &that) noexcept {
    this->dllPath = that.dllPath;
    this->typeLib = that.typeLib;
    if (this->typeLib) this->typeLib->AddRef();
}

InterfaceInfo::~InterfaceInfo() {
    if (typeLib) typeLib->Release();
}

void InterfaceInfo::addMethod(unsigned vtblIdx, std::wstring def) noexcept {
    MHC_CSLOCK;
    if (vtblIdx >= this->m_methodDefs.size()) { // need to increase vector size
        m_methodDefs.resize(vtblIdx + 1);
    }
    m_methodDefs[vtblIdx] = def;
}

std::wstring InterfaceInfo::getMethod(unsigned vtblIdx) noexcept {
    MHC_CSLOCK;
    if (vtblIdx >= m_methodDefs.size()) return std::wstring();
    return m_methodDefs[vtblIdx];
}

std::wstring InterfaceInfo::toString() const noexcept {
    std::wostringstream ret;
    ret << "IID: " << ::toString(this->m_iid) << " Functions:\n";
    for (size_t i = 0; i < m_methodDefs.size(); i ++) {
        ret << "  #" << i << " -> [" << m_methodDefs[i] << "]\n";
    }
    return ret.str();
}

std::wstring InterfaceInfo::typeLibInfoStr() const noexcept {
    std::wstring ret;
    typeLib->AddRef(); // just in case...
    BSTR name = nullptr;
    BSTR docString = nullptr;
    if (typeLib->GetDocumentation(MEMBERID_NIL, &name, &docString, nullptr, nullptr) == S_OK) {
        if (name && SysStringLen(name) > 0)
            ret += name;
        if (docString && SysStringLen(docString) > 0) {
            ret = ret + L" (" + docString + L")";
        }
    }
    SysFreeString(name);
    SysFreeString(docString);
    typeLib->Release();
    return ret;
}


} // namespace MHC_NS
