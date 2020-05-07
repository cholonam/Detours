#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <map> // std::map

extern std::map<FARPROC, FARPROC> newAddrOrigAddrMap;

using DllGetClassObjectFType = HRESULT (STDAPICALLTYPE *)(REFCLSID rclsid, REFIID riid, PVOID *ppv);

// TODO: Make this a constructor
void multiplePatcherInitialize();

// This should have one more parameter (origAddr)
HRESULT STDAPICALLTYPE MyGenericDllGetClassObject(REFCLSID rclsid,
                                               REFIID riid, PVOID *ppv
                                               , FARPROC myFuncAddr /* extra parameters */);

void MyDllGetClassObject(REFCLSID rclsid, REFIID riid, PVOID *ppv);
void *allocExecBufferAndCopyFunc(const void *toCopy, size_t nBytes);

FARPROC MultiplePatcherAdd(FARPROC realFunction);
