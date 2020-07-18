#include "pefile.h"
#include <math.h>

BOOL ParsePEHeader(PBYTE pMapView, PPEFILE pPefile)
{
    pPefile->pDOSHeader = (PIMAGE_DOS_HEADER)pMapView;
    if (pPefile->pDOSHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        printf("[ERR] Not valid DOS header");
        return 0;
    }

    pPefile->pNTHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pPefile->pDOSHeader + pPefile->pDOSHeader->e_lfanew);
    pPefile->pFirstSectionHeader = (PIMAGE_SECTION_HEADER)((PBYTE)pPefile->pNTHeaders + sizeof(IMAGE_NT_HEADERS));
    return 1;
}

DWORD Align(DWORD x, DWORD align)
{
    return x <= align ? align : ceil((double)x / align) * align;
}

DWORD AddEmptySection(PPEFILE pe, WORD wNumnberOfSections, DWORD dwSectionAlignment, PBYTE pMapView)
{
    PIMAGE_SECTION_HEADER pLasSection = &pe->pFirstSectionHeader[wNumnberOfSections - 1];
    PIMAGE_SECTION_HEADER pNewSection = &pe->pFirstSectionHeader[wNumnberOfSections];

    const PSTR pNewSectionName = ".uit";
    memset(pNewSection, 0, sizeof(IMAGE_SECTION_HEADER));
    memcpy(&pNewSection->Name, pNewSectionName, 5);

    pNewSection->Misc.VirtualSize = VIRTUAL_SIZE;
    pNewSection->VirtualAddress = Align(pLasSection->VirtualAddress + pLasSection->Misc.VirtualSize, dwSectionAlignment);
    pNewSection->SizeOfRawData = Align(dwSectionAlignment, dwSectionAlignment);
    pNewSection->PointerToRawData = Align(pLasSection->PointerToRawData + pLasSection->SizeOfRawData, dwSectionAlignment);
    pNewSection->Characteristics = 0xE0000020;

    wNumnberOfSections += 1;
    pe->pNTHeaders->FileHeader.NumberOfSections = wNumnberOfSections;
    pe->pNTHeaders->OptionalHeader.SizeOfImage = Align(pNewSection->VirtualAddress + pNewSection->Misc.VirtualSize, dwSectionAlignment);
    memset((PBYTE)pMapView + pNewSection->PointerToRawData, 0, pNewSection->SizeOfRawData);

    return pNewSection->PointerToRawData;
}