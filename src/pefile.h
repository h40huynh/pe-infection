#ifndef __PEFILE__
#define __PEFILE__

#include <stdio.h>
#include <windows.h>

#define VIRTUAL_SIZE 0x2000

typedef struct pefile
{
    PIMAGE_DOS_HEADER pDOSHeader;
    PIMAGE_NT_HEADERS pNTHeaders;
    PIMAGE_SECTION_HEADER pFirstSectionHeader;
} PEFILE, *PPEFILE;

BOOL ParsePEHeader(PBYTE pMapView, PPEFILE pPefile);
DWORD Align(DWORD x, DWORD align);
DWORD AddEmptySection(PPEFILE pe, WORD wNumnberOfSections, DWORD dwSectionAlignment, PBYTE pMapView);

#endif