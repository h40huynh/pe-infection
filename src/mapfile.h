#ifndef __MAPPING__
#define __MAPPING__

#include <stdio.h>
#include <windows.h>

PBYTE MappingReadOnly(HANDLE *hFile, HANDLE *hFileMapping);
PBYTE MappingWrite(HANDLE *hFile, HANDLE *hFileMapping, DWORD nsize);
BOOL Unmap(HANDLE *hFileMapping, PBYTE pMapView);

#endif