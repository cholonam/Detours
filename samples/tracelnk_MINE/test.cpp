#include "precomp.h"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <combaseapi.h> // CLSIDFromString

#include <cstdio>
#include <iostream>
#include <map>
#include <string>

int operator<(const GUID &a, const GUID&b) {
    uint64_t *aa = (uint64_t *) &a;
    uint64_t *bb = (uint64_t *) &b;

    return  aa[1] <  bb[1]
        || (aa[1] == bb[1] && aa[0] < bb[0]);
}
std::map<GUID, std::wstring> m;

int main() {
    LPOLESTR clsidStr = L"{00000303-0000-0000-C000-000000000046}";
    GUID guid = { 0 };
    #pragma comment(lib, "Ole32.lib")
    CLSIDFromString(clsidStr, &guid);
    m[guid] = L"HERE";

    if (m.find(guid) != m.end())
        printf("Found! (%ls)\n", m[guid].c_str());

    return 0;
}
