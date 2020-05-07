#pragma once

#include <guiddef.h>
#include <OAIdl.h> // ITypeLib

#include <string>
#include <map>
#include <vector>

#include "cslock.h" // MHC_NS::CriticalSection

namespace MHC_NS {

struct InterfaceInfo {
    std::wstring dllPath;
    ITypeLib *typeLib; // this is shared with other interfaceinfo
    CriticalSection cs; // to protect m_methodDefs
    std::vector<std::wstring> m_methodDefs;
    IID m_iid;
    void *vTbl; // cached vtable (reused by all the instances of the same interface)
public:
    InterfaceInfo() noexcept;
    InterfaceInfo(const InterfaceInfo &that) noexcept;
    ~InterfaceInfo();

    void addMethod(unsigned vtblIdx, std::wstring def) noexcept;
    std::wstring getMethod(unsigned vtblIdx) noexcept;

    std::wstring toString() const noexcept;
    std::wstring typeLibInfoStr() const noexcept;
};

} // namespace MHC_NS
