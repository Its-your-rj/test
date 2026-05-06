# PE Parser 

Overview
--------

This repository contains a compact Portable Executable (PE) header parser written in C for Windows. The parser reads a PE file (EXE/DLL) from disk, parses the DOS header, NT / File / Optional headers, Data Directories, Section Headers, and prints imported DLLs and their functions.

Why parse PE files?
-------------------

- PE is the standard executable format on Windows; its headers instruct the OS loader how to map the file into memory and resolve imports.
- Parsing PE headers is essential for reverse engineering, malware analysis, compatibility checks, dependency inspection, and forensic investigation.

Input
-----

- A single PE file on disk (path passed as the first argument to the program). Example inputs:
  - `C:\Windows\System32\notepad.exe`
  - `C:\Path\to\your.dll`
- The parser reads the entire file into memory and inspects the header structures — it expects a valid PE file (MZ header + PE signature).

Output
------

The program prints human-readable information grouped into sections. Key output blocks and what they mean:

- DOS HEADER: low-level DOS stub fields and `e_lfanew` (file offset to NT headers).
- NT HEADERS / FILE HEADER: machine type, number of sections, timestamp, size of optional header, and characteristics (executable, DLL, etc.).
- OPTIONAL HEADER: indicates PE32 vs PE32+ and contains runtime fields such as `ImageBase`, `AddressOfEntryPoint`, `SizeOfImage`, alignment and the Data Directory table.
- DATA DIRECTORIES: a list of standard tables (Export, Import, Resource, Relocations, Debug, IAT, etc.) shown as RVAs and sizes. RVAs are runtime addresses — the parser converts them to file offsets when extracting content.
- SECTION HEADERS: the section table with each section's `PointerToRawData`, `SizeOfRawData`, `VirtualAddress` and `VirtualSize`. These allow mapping an RVA to the file offset for reading payloads.
- IMPORTS: for each imported DLL the parser lists the functions imported by name or ordinal (this is resolved from the Import Directory using `RvaToOffset()`).

What you can analyze from the output
------------------------------------

- Imported DLLs and functions: reveals external dependencies and potentially suspicious imports (e.g., `CreateRemoteThread`, `VirtualAlloc` used by injection tools/malware).
- ImageBase and relocations: if `ImageBase` is unusual or base relocations are large, it may indicate packing, custom loaders, or intentional relocation activity.
- Section table: mismatches between `SizeOfRawData` and `VirtualSize`, or strange section names/permissions, often indicate packing or tampering.
- Data directories: presence/absence of certain directories (e.g., Debug present/absent, large Resource directory) tells you about build/debug info or embedded resources.
- Optional header flags: `DllCharacteristics`, `Subsystem`, stack/heap reserve/commit sizes — useful to detect ASLR/NX/DEP-related flags and other runtime properties.

Code details (what the program does)
-----------------------------------

- `RvaToOffset()` — converts an RVA to a file offset using the section table. This is required because many PE tables are referenced by RVA, not file offsets.
- `main()` — opens and reads the file into memory, validates `MZ` and `PE\0\0`, parses the File Header and determines where the Optional Header and Section Table reside.
- The parser detects PE32 vs PE32+ (32-bit vs 64-bit) by checking the Optional Header `Magic` value and uses the appropriate structure to read `ImageBase` and other fields.
- Data Directories are read from the Optional Header and displayed. For the Import Directory the parser converts the directory RVA to a file offset and iterates the `IMAGE_IMPORT_DESCRIPTOR` array to list DLLs and imported functions.

Examples and interpretation
---------------------------

- Example: Import Directory shows `KERNEL32.dll` with `CreateFileW`, `ReadFile`, `WriteFile` — indicates common filesystem usage.
- Example: IAT and Import R VAs point into the `.rdata` section; use the section table printed earlier to confirm the conversion to file offsets (this is what `RvaToOffset()` does).

Placeholders for images
-----------------------

Add screenshots to `docs/images/` and reference them here. Suggested images and captions:

- `docs/images/dos-nt-screenshot.png` — DOS header + NT signature and File Header (show `e_lfanew`, Machine, Number of Sections).
- `docs/images/optional-dirs.png` — Optional Header and Data Directories (show `ImageBase`, `AddressOfEntryPoint`, Import RVA/Size).
- `docs/images/sections-imports.png` — Section table and snippet of imports mapping from RVA→file offset.

Insert images like this:

![DOS and NT headers screenshot](docs/images/dos-nt-screenshot.png)

Compile & run
-------------

Prerequisites: Windows with MinGW or MSVC. Build the parser with the same target architecture you plan to analyze (build 64-bit for 64-bit targets).

MinGW (gcc):
```bash
gcc -o pe_parser.exe main.c
```

MSVC (Developer Command Prompt):
```powershell
cl /nologo /W3 /EHsc main.c
```

Run:
```powershell
.\pe_parser.exe C:\Windows\System32\notepad.exe
```

Sample output (trimmed)
----------------------

```
******* NT HEADERS *******
    Signature: 0x4550

******* FILE HEADER *******
    0x8664    Machine
    0x8       Number of Sections

******* OPTIONAL HEADER *******
    Magic: 0x20B (PE32+)
    Image Base: 0x140000000

******* DATA DIRECTORIES *******
    Import Directory: RVA: 0x274BC; Size: 0x1F4
    IAT:              RVA: 0x27000; Size: 0x4B8

Imported DLLs and functions:
  KERNEL32.dll:
    CreateFileW
    ReadFile
    WriteFile
```

Tips & Troubleshooting
----------------------

- If you see wrong section counts or garbage values: ensure the parser correctly finds the File Header and uses `SizeOfOptionalHeader` to locate the section table. The code in `main.c` already computes this correctly.
- If `windows.h` is missing, install the Windows SDK or use a MinGW distribution that bundles Windows headers.
- MSVC printf format: MSVC uses different length specifiers for 64-bit integers; for printing `unsigned long long` use `%llu` or `%I64u` depending on your toolchain.

Limitations & next steps
------------------------

- The parser focuses on headers and imports. It does not fully parse exports, resources, relocations or certificates.
- Suggested extensions: JSON output, export table parsing, resource extraction, flag decoding (human-friendly characteristics), and automated checks for suspicious patterns.

License & contributing
----------------------

Add a `LICENSE` (e.g., MIT) and open issues/PRs for improvements.

---

If you want, I can add example screenshots into `docs/images/` and commit them, or further format the README for GitHub (table of contents, badges, etc.).
