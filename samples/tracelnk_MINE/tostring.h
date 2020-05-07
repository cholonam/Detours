#pragma once

#include <OAIdl.h> // CALLCONV, FUNCKIND, INVOKEKIND

#include <string>

#if _HAS_CXX17
#   include <string_view>
    namespace MHC_NS { using RETTYPE = std::wstring_view; }
#else
    namespace MHC_NS { using RETTYPE = const wchar_t *; }
#endif

MHC_NS::RETTYPE toString(CALLCONV e) noexcept;
MHC_NS::RETTYPE toString(FUNCKIND e) noexcept;
MHC_NS::RETTYPE toString(INVOKEKIND e) noexcept;
MHC_NS::RETTYPE toString(TYPEKIND e) noexcept;
MHC_NS::RETTYPE toStringMemProtect(DWORD e) noexcept;
std::wstring    toString(const GUID &guid) noexcept;
MHC_NS::RETTYPE toString(VARTYPE vt) noexcept;
std::wstring    toString(HRESULT hr) noexcept;
