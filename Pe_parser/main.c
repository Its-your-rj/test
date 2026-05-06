#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

// Convert an RVA (relative virtual address) to a file offset using section headers.
DWORD RvaToOffset(DWORD rva, PIMAGE_SECTION_HEADER sections, int numberOfSections) {
    for (int i = 0; i < numberOfSections; i++) {
        DWORD va = sections[i].VirtualAddress;
        DWORD size = sections[i].Misc.VirtualSize ? sections[i].Misc.VirtualSize : sections[i].SizeOfRawData;
        if (rva >= va && rva < va + size) {
            return sections[i].PointerToRawData + (rva - va);
        }
    }
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <path_to_pe_file>\n", argv[0]);
        return 1;
    }

    const char *path = argv[1];

    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Error: Could not open file '%s' (GetLastError=%lu)\n", path, GetLastError());
        return 1;
    }

    LARGE_INTEGER liSize;
    if (!GetFileSizeEx(hFile, &liSize)) {
        printf("Error: Could not get file size.\n");
        CloseHandle(hFile);
        return 1;
    }

    if (liSize.QuadPart == 0) {
        printf("Empty file.\n");
        CloseHandle(hFile);
        return 1;
    }

    if (liSize.QuadPart > 0x7FFFFFF0) {
        printf("File too large to process in this simple demo.\n");
        CloseHandle(hFile);
        return 1;
    }

    DWORD fileSize = (DWORD)liSize.QuadPart;
    BYTE *buf = (BYTE *)malloc(fileSize);
    if (!buf) {
        printf("Memory allocation failed.\n");
        CloseHandle(hFile);
        return 1;
    }

    DWORD bytesRead = 0;
    if (!ReadFile(hFile, buf, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        printf("Error reading file.\n");
        free(buf);
        CloseHandle(hFile);
        return 1;
    }

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)buf;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("Not a PE file (missing MZ).\n");
        free(buf);
        CloseHandle(hFile);
        return 1;
    }

    if ((DWORD)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > fileSize) {
        printf("Invalid e_lfanew.\n");
        free(buf);
        CloseHandle(hFile);
        return 1;
    }

    unsigned char *ntBase = buf + dos->e_lfanew;
    if (*(DWORD *)ntBase != IMAGE_NT_SIGNATURE) {
        printf("Invalid PE signature.\n");
        free(buf);
        CloseHandle(hFile);
        return 1;
    }

    // FILE HEADER and Optional Header base pointers
    PIMAGE_FILE_HEADER fileHeader = (PIMAGE_FILE_HEADER)(ntBase + sizeof(DWORD));
    unsigned char *optHeaderPtr = (unsigned char *)fileHeader + sizeof(IMAGE_FILE_HEADER);

    // Determine PE32 vs PE32+
    WORD optMagic = *(WORD *)optHeaderPtr;
    int isPE32Plus = (optMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);

    // Section headers start immediately after optional header
    PIMAGE_SECTION_HEADER sections = (PIMAGE_SECTION_HEADER)(optHeaderPtr + fileHeader->SizeOfOptionalHeader);
    int numSections = fileHeader->NumberOfSections;

    // DOS Header
    printf("******* DOS HEADER *******\n");
    printf("\t0x%X\tMagic number\n", dos->e_magic);
    printf("\t0x%X\tBytes on last page of file\n", dos->e_cblp);
    printf("\t0x%X\tPages in file\n", dos->e_cp);
    printf("\t0x%X\tRelocations\n", dos->e_crlc);
    printf("\t0x%X\tSize of header in paragraphs\n", dos->e_cparhdr);
    printf("\t0x%X\tMinimum extra paragraphs needed\n", dos->e_minalloc);
    printf("\t0x%X\tMaximum extra paragraphs needed\n", dos->e_maxalloc);
    printf("\t0x%X\tInitial (relative) SS value\n", dos->e_ss);
    printf("\t0x%X\tInitial SP value\n", dos->e_sp);
    printf("\t0x%X\tChecksum\n", dos->e_csum);
    printf("\t0x%X\tInitial IP value\n", dos->e_ip);
    printf("\t0x%X\tInitial (relative) CS value\n", dos->e_cs);
    printf("\t0x%X\tFile address of relocation table\n", dos->e_lfarlc);
    printf("\t0x%X\tOverlay number\n", dos->e_ovno);
    printf("\t0x%X\tOEM identifier\n", dos->e_oemid);
    printf("\t0x%X\tOEM information\n", dos->e_oeminfo);
    printf("\t0x%X\tFile address of new exe header (e_lfanew)\n", dos->e_lfanew);

    // NT Headers and File Header
    printf("\n******* NT HEADERS *******\n");
    printf("\tSignature: 0x%X\n", *(DWORD *)ntBase);
    printf("\n******* FILE HEADER *******\n");
    printf("\t0x%X\tMachine\n", fileHeader->Machine);
    printf("\t0x%X\tNumber of Sections\n", fileHeader->NumberOfSections);
    printf("\t0x%X\tTime Stamp\n", fileHeader->TimeDateStamp);
    printf("\t0x%X\tPointer to Symbol Table\n", fileHeader->PointerToSymbolTable);
    printf("\t0x%X\tNumber of Symbols\n", fileHeader->NumberOfSymbols);
    printf("\t0x%X\tSize of Optional Header\n", fileHeader->SizeOfOptionalHeader);
    printf("\t0x%X\tCharacteristics\n", fileHeader->Characteristics);

    // Optional Header (handle PE32 vs PE32+)
    printf("\n******* OPTIONAL HEADER *******\n");
    PIMAGE_OPTIONAL_HEADER32 opt32 = NULL;
    PIMAGE_OPTIONAL_HEADER64 opt64 = NULL;
    IMAGE_DATA_DIRECTORY *dataDirs = NULL;
    if (isPE32Plus) {
        opt64 = (PIMAGE_OPTIONAL_HEADER64)optHeaderPtr;
        dataDirs = (IMAGE_DATA_DIRECTORY *)opt64->DataDirectory;
    } else {
        opt32 = (PIMAGE_OPTIONAL_HEADER32)optHeaderPtr;
        dataDirs = (IMAGE_DATA_DIRECTORY *)opt32->DataDirectory;
    }

    if (isPE32Plus) {
        printf("\tMagic: 0x%X (PE32+)\n", opt64->Magic);
        printf("\tMajor Linker Version: 0x%X\n", opt64->MajorLinkerVersion);
        printf("\tMinor Linker Version: 0x%X\n", opt64->MinorLinkerVersion);
        printf("\tSize Of Code: 0x%X\n", opt64->SizeOfCode);
        printf("\tSize Of Initialized Data: 0x%X\n", opt64->SizeOfInitializedData);
        printf("\tSize Of Uninitialized Data: 0x%X\n", opt64->SizeOfUninitializedData);
        printf("\tAddress Of Entry Point: 0x%X\n", opt64->AddressOfEntryPoint);
        printf("\tBase Of Code: 0x%X\n", opt64->BaseOfCode);
        printf("\tImage Base: 0x%llX\n", (unsigned long long)opt64->ImageBase);
        printf("\tSection Alignment: 0x%X\n", opt64->SectionAlignment);
        printf("\tFile Alignment: 0x%X\n", opt64->FileAlignment);
        printf("\tSize Of Image: 0x%X\n", opt64->SizeOfImage);
        printf("\tSize Of Headers: 0x%X\n", opt64->SizeOfHeaders);
        printf("\tSubsystem: 0x%X\n", opt64->Subsystem);
        printf("\tDllCharacteristics: 0x%X\n", opt64->DllCharacteristics);
    } else {
        printf("\tMagic: 0x%X (PE32)\n", opt32->Magic);
        printf("\tMajor Linker Version: 0x%X\n", opt32->MajorLinkerVersion);
        printf("\tMinor Linker Version: 0x%X\n", opt32->MinorLinkerVersion);
        printf("\tSize Of Code: 0x%X\n", opt32->SizeOfCode);
        printf("\tSize Of Initialized Data: 0x%X\n", opt32->SizeOfInitializedData);
        printf("\tSize Of Uninitialized Data: 0x%X\n", opt32->SizeOfUninitializedData);
        printf("\tAddress Of Entry Point: 0x%X\n", opt32->AddressOfEntryPoint);
        printf("\tBase Of Code: 0x%X\n", opt32->BaseOfCode);
        printf("\tBase Of Data: 0x%X\n", opt32->BaseOfData);
        printf("\tImage Base: 0x%X\n", (unsigned int)opt32->ImageBase);
        printf("\tSection Alignment: 0x%X\n", opt32->SectionAlignment);
        printf("\tFile Alignment: 0x%X\n", opt32->FileAlignment);
        printf("\tSize Of Image: 0x%X\n", opt32->SizeOfImage);
        printf("\tSize Of Headers: 0x%X\n", opt32->SizeOfHeaders);
        printf("\tSubsystem: 0x%X\n", opt32->Subsystem);
        printf("\tDllCharacteristics: 0x%X\n", opt32->DllCharacteristics);
    }

    // Data Directories (print all standard entries)
    const char *dirNames[] = {
        "Export Directory", "Import Directory", "Resource Directory", "Exception Directory",
        "Security Directory", "Base Relocation Table", "Debug Directory", "Architecture",
        "Global Ptr", "TLS Directory", "Load Config Directory", "Bound Import", "IAT",
        "Delay Import Descriptor", "CLR Runtime Header", "Reserved"
    };
    printf("\n******* DATA DIRECTORIES *******\n");
    for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
        printf("\t%-24s RVA: 0x%X; Size: 0x%X\n", dirNames[i], dataDirs[i].VirtualAddress, dataDirs[i].Size);
    }

    // Section Headers (reordered: Raw Addr, Raw Size, Virtual Addr, Virtual Size ...)
    printf("\n******* SECTION HEADERS *******\n");
    for (int i = 0; i < numSections; i++) {
        PIMAGE_SECTION_HEADER sh = &sections[i];
        printf("\t%.8s\n", sh->Name);
        printf("\t\tPointer To Raw Data: 0x%08X\n", sh->PointerToRawData);
        printf("\t\tSize Of Raw Data:    0x%08X\n", sh->SizeOfRawData);
        printf("\t\tVirtual Address:     0x%08X\n", sh->VirtualAddress);
        printf("\t\tVirtual Size:        0x%08X\n", sh->Misc.VirtualSize);
        printf("\t\tCharacteristics:     0x%08X\n", sh->Characteristics);
        printf("\t\tPointer To Relocs:   0x%08X\n", sh->PointerToRelocations);
        printf("\t\tPointer To LineNums: 0x%08X\n", sh->PointerToLinenumbers);
        printf("\t\tNumber Of Relocs:    0x%X\n", sh->NumberOfRelocations);
        printf("\t\tNumber Of LineNums:  0x%X\n", sh->NumberOfLinenumbers);
    }

    DWORD importRVA = dataDirs[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (importRVA == 0) {
        printf("No import directory present.\n");
        free(buf);
        CloseHandle(hFile);
        return 0;
    }

    DWORD importOffset = RvaToOffset(importRVA, sections, numSections);
    if (importOffset == 0 || importOffset >= fileSize) {
        printf("Could not locate import directory in file.\n");
        free(buf);
        CloseHandle(hFile);
        return 1;
    }

    PIMAGE_IMPORT_DESCRIPTOR imp = (PIMAGE_IMPORT_DESCRIPTOR)(buf + importOffset);

    printf("\nImported DLLs and functions:\n");
    for (; imp->Name != 0; imp++) {
        DWORD nameOff = RvaToOffset(imp->Name, sections, numSections);
        if (nameOff == 0 || nameOff >= fileSize) break;
        char *dllName = (char *)(buf + nameOff);
        printf("  %s:\n", dllName);

        DWORD thunkRVA = imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk;
        if (thunkRVA == 0) continue;
        DWORD thunkOff = RvaToOffset(thunkRVA, sections, numSections);
        if (thunkOff == 0 || thunkOff >= fileSize) continue;

        PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)(buf + thunkOff);
        for (; thunk->u1.AddressOfData != 0; thunk++) {
            // Imported by ordinal?
            if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                WORD ord = (WORD)(thunk->u1.Ordinal & 0xFFFF);
                printf("    Ordinal: %u\n", ord);
            } else {
                DWORD nameRva2 = (DWORD)thunk->u1.AddressOfData;
                DWORD nameOff2 = RvaToOffset(nameRva2, sections, numSections);
                if (nameOff2 == 0 || nameOff2 >= fileSize) continue;
                PIMAGE_IMPORT_BY_NAME ibn = (PIMAGE_IMPORT_BY_NAME)(buf + nameOff2);
                printf("    %s\n", ibn->Name);
            }
        }
    }

    free(buf);
    CloseHandle(hFile);
    return 0;
}