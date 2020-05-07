#pragma once

#include <guiddef.h> // RECCLSID, IID

#include <memory> // std::shared_ptr
#include <string> // std::wstring

#include "interfaceinfo.h"

namespace MHC_NS {


class IIDDb {
private:
    class LockedIIDDb {
        IIDDb &m_db;
    public:
        LockedIIDDb(IIDDb &db) noexcept : m_db(db) { m_db.lock(); }
        ~LockedIIDDb() { m_db.unlock(); }
        IIDDb *operator->() noexcept { return &m_db; }
    };
    IIDDb();
    ~IIDDb();
    static IIDDb *getInstance() noexcept; // clients no longer need to call this, but it's called internally (by getLockedInstance)
    void lock() noexcept;
    void unlock() noexcept;
public:
    using InterfaceInfoSPtr = std::shared_ptr<InterfaceInfo>;
    static LockedIIDDb getLockedInstance() noexcept;

    /// Parses the type lib and adds all interfaces
    /// Returns false if the typelib could not be loaded
    bool putClassId(REFCLSID clsid) noexcept;

    /// This will return the interface only if it's already cached
    InterfaceInfoSPtr getCachedInterfaceInfo(const IID &iidRef) noexcept;

    /// This will try to load the interface's typelib from the registry if it's not cached
    InterfaceInfoSPtr getInterfaceInfo(const IID &iidRef, bool shouldNotExist = false) noexcept;

    /// Returns true if the interface is cached, even if it was not found
    bool isInterfaceCached(const IID &iidRef) noexcept;

    void maybePutInterfaceInfo(const IID &iidRef, InterfaceInfoSPtr interfaceInfo) noexcept;
    std::wstring GetDll(const IID &iidRef) noexcept;
private:
    /// Will end up calling the below function
    HRESULT processTypeLib(REFCLSID clsid, const std::wstring &typeLibPath) noexcept;

    /// typeLibPath is needed because it will be added to all interfaces as info
    HRESULT processTypeLib(ITypeLib *tl, const std::wstring &typeLibPath) noexcept;
};

} // namespace MHC_NS
