#include "mapfile.h"

PBYTE MappingReadOnly(HANDLE *hFile, HANDLE *hFileMapping)
{
    *hFileMapping = CreateFileMapping(*hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    return (PBYTE)MapViewOfFile(*hFileMapping, FILE_MAP_READ, 0, 0, 0);
}

PBYTE MappingWrite(HANDLE *hFile, HANDLE *hFileMapping, DWORD nsize)
{
    *hFileMapping = CreateFileMapping(*hFile, NULL, PAGE_READWRITE, 0, nsize, NULL);
    return (PBYTE)MapViewOfFile(*hFileMapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
    return 0;
}

BOOL Unmap(HANDLE *hFileMapping, PBYTE pMapView)
{
    BOOL isUnmap = UnmapViewOfFile((PVOID)pMapView);
    BOOL isCloseHandle = CloseHandle(*hFileMapping);
    return isUnmap && isCloseHandle;
}