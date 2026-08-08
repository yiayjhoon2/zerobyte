
// Maps payload.dll into a target process by hand and starts payload_main on a thread there.
// Avoids LoadLibrary in the target and needs no -agentpath on the target command line.
// Usage:
//   inject.exe <pid> [payload.dll]
//   inject.exe -wait <exe-name> [payload.dll]
//   inject.exe -wait <exe-name> -match <cmdline-substr> [payload.dll]
//
// The -match form skips PIDs whose command line lacks the substring. Use it when a
// launcher spawns a short-lived helper JVM before the real one and you only want the
// real launch, e.g.:
//   inject.exe -wait javaw.exe -match MYMINECRAFTINSTANCE payload.dll

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdint.h>

// Read a process's command line out of its PEB. Returns 0 on success.
// Uses NtQueryInformationProcess + ReadProcessMemory; no static ntdll dependency at link
// time (resolved at runtime so the injector still links with kernel32 alone).
static int read_cmdline(DWORD pid, char* out, DWORD outcap) {
    typedef LONG (NTAPI *NtQIP_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    static NtQIP_t NtQIP = NULL;
    if (!NtQIP) {
        HMODULE nt = GetModuleHandleA("ntdll.dll");
        if (!nt) return 1;
        NtQIP = (NtQIP_t)GetProcAddress(nt, "NtQueryInformationProcess");
        if (!NtQIP) return 1;
    }
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h) return 1;

    // PROCESS_BASIC_INFORMATION → PebBaseAddress
    struct { PVOID r0; PVOID PebBaseAddress; PVOID r2[4]; } pbi;
    ULONG ret = 0;
    if (NtQIP(h, 0, &pbi, sizeof(pbi), &ret) < 0) { CloseHandle(h); return 1; }

    // PEB+0x20 → ProcessParameters (RTL_USER_PROCESS_PARAMETERS*)
    PVOID params = NULL;
    if (!ReadProcessMemory(h, (char*)pbi.PebBaseAddress + 0x20, &params, sizeof(params), NULL) || !params) {
        CloseHandle(h); return 1;
    }
    // RTL_USER_PROCESS_PARAMETERS+0x70 → UNICODE_STRING CommandLine { USHORT Len, USHORT Max, PWSTR Buf }
    struct { USHORT len, max; ULONG _pad; PVOID buf; } us;
    if (!ReadProcessMemory(h, (char*)params + 0x70, &us, sizeof(us), NULL) || !us.buf) {
        CloseHandle(h); return 1;
    }
    USHORT n = us.len; if (n >= 8192) n = 8190;
    wchar_t* w = (wchar_t*)malloc(n + 2);
    if (!w) { CloseHandle(h); return 1; }
    if (!ReadProcessMemory(h, us.buf, w, n, NULL)) { free(w); CloseHandle(h); return 1; }
    w[n/2] = 0;
    CloseHandle(h);

    // narrow it for substring matching
    int wrote = WideCharToMultiByte(CP_UTF8, 0, w, -1, out, (int)outcap, NULL, NULL);
    free(w);
    return wrote > 0 ? 0 : 1;
}

static int contains_ci(const char* hay, const char* needle) {
    if (!needle || !*needle) return 1;
    size_t hn = strlen(hay), nn = strlen(needle);
    if (nn > hn) return 0;
    for (size_t i = 0; i + nn <= hn; ++i) {
        size_t k = 0;
        while (k < nn) {
            char a = hay[i + k], b = needle[k];
            if (a >= 'A' && a <= 'Z') a += 32;
            if (b >= 'A' && b <= 'Z') b += 32;
            if (a != b) break;
            ++k;
        }
        if (k == nn) return 1;
    }
    return 0;
}

static unsigned char* read_file(const char* path, DWORD* out_size) {
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;
    DWORD sz = GetFileSize(h, NULL), rd = 0;
    unsigned char* buf = (unsigned char*)malloc(sz);
    if (!buf || !ReadFile(h, buf, sz, &rd, NULL) || rd != sz) { CloseHandle(h); return NULL; }
    CloseHandle(h);
    *out_size = sz;
    return buf;
}

// Find the first running PID whose image name matches `exe` AND whose command line contains
// `match` (case-insensitive). `match` may be NULL/empty to skip the cmdline filter.
// `skip_pid` is a PID to ignore (e.g. one we already inspected and rejected) — pass 0 to
// disable. Returns 0 when no match exists yet.
static DWORD find_pid(const char* exe, const char* match, DWORD skip_pid) {
    DWORD pid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe = { sizeof(pe) };
    if (Process32First(snap, &pe)) do {
        if (pe.th32ProcessID == skip_pid) continue;
        if (_stricmp(pe.szExeFile, exe) != 0) continue;
        if (match && *match) {
            char cmd[8192] = {0};
            if (read_cmdline(pe.th32ProcessID, cmd, sizeof(cmd)) != 0) continue;
            if (!contains_ci(cmd, match)) continue;
        }
        pid = pe.th32ProcessID;
        break;
    } while (Process32Next(snap, &pe));
    CloseHandle(snap);
    return pid;
}

// Map an RVA to a file offset using the on-disk section table. Used ONLY against the raw `file`
// buffer (export-table parsing). The staged `local` buffer is virtual-layout — index it by RVA
// directly, never through this function.
static DWORD rva_to_off(unsigned char* file, DWORD rva) {
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(file + ((IMAGE_DOS_HEADER*)file)->e_lfanew);
    IMAGE_SECTION_HEADER* s = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++s)
        if (rva >= s->VirtualAddress && rva < s->VirtualAddress + s->SizeOfRawData)
            return s->PointerToRawData + (rva - s->VirtualAddress);
    return rva;
}

static DWORD export_rva(unsigned char* file, const char* want) {
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(file + ((IMAGE_DOS_HEADER*)file)->e_lfanew);
    IMAGE_DATA_DIRECTORY ed = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!ed.VirtualAddress) return 0;
    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(file + rva_to_off(file, ed.VirtualAddress));
    DWORD* names = (DWORD*)(file + rva_to_off(file, exp->AddressOfNames));
    WORD*  ords  = (WORD*) (file + rva_to_off(file, exp->AddressOfNameOrdinals));
    DWORD* funcs = (DWORD*)(file + rva_to_off(file, exp->AddressOfFunctions));
    for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
        const char* nm = (const char*)(file + rva_to_off(file, names[i]));
        if (strcmp(nm, want) == 0) return funcs[ords[i]];
    }
    return 0;
}

// Build the image at its mapped layout in a local staging buffer, fix it up for `remote`,
// then copy it into the target and run payload_main there. We resolve imports against our
// own address space — kernel32/KernelBase/ntdll get one ASLR slide per boot, so their
// function addresses are identical in every process. payload.dll's imports are kernel32-only
// (verified: CreateFile/VirtualProtect/AddVectoredExceptionHandler/etc.), so this holds.
static int map_and_run(HANDLE proc, unsigned char* file) {
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(file + ((IMAGE_DOS_HEADER*)file)->e_lfanew);
    DWORD image_size = nt->OptionalHeader.SizeOfImage;

    unsigned char* remote = (unsigned char*)VirtualAllocEx(
        proc, NULL, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote) { printf("VirtualAllocEx failed %lu\n", GetLastError()); return 1; }

    unsigned char* local = (unsigned char*)VirtualAlloc(
        NULL, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!local) { printf("local stage alloc failed\n"); return 1; }

    // Headers verbatim, then each section dropped at its VirtualAddress (not file offset).
    memcpy(local, file, nt->OptionalHeader.SizeOfHeaders);
    IMAGE_SECTION_HEADER* s = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++s) {
        if (s->SizeOfRawData) {
            memcpy(local + s->VirtualAddress,
                   file  + s->PointerToRawData,
                   s->SizeOfRawData);
        }
        // VirtualAlloc returns zeroed pages, so no explicit zero-pad needed.
    }

    // Base relocations: 64-bit fixups against the delta between actual remote base and
    // the DLL's preferred ImageBase. Walk IMAGE_BASE_RELOCATION blocks; honor only
    // IMAGE_REL_BASED_DIR64 (type 10) and ABSOLUTE (type 0 — padding, skip).
    uintptr_t delta = (uintptr_t)remote - (uintptr_t)nt->OptionalHeader.ImageBase;
    IMAGE_DATA_DIRECTORY reloc_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (delta && reloc_dir.VirtualAddress && reloc_dir.Size) {
        IMAGE_BASE_RELOCATION* reloc = (IMAGE_BASE_RELOCATION*)(local + reloc_dir.VirtualAddress);
        IMAGE_BASE_RELOCATION* end   = (IMAGE_BASE_RELOCATION*)(local + reloc_dir.VirtualAddress + reloc_dir.Size);
        while (reloc < end && reloc->VirtualAddress && reloc->SizeOfBlock) {
            DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* entries = (WORD*)((char*)reloc + sizeof(IMAGE_BASE_RELOCATION));
            for (DWORD i = 0; i < count; ++i) {
                DWORD type   = entries[i] >> 12;
                DWORD offset = entries[i] & 0xFFF;
                if (type == IMAGE_REL_BASED_DIR64) {
                    ULONGLONG* fix = (ULONGLONG*)(local + reloc->VirtualAddress + offset);
                    *fix += (ULONGLONG)delta;
                }
                // type 0 = ABSOLUTE (block padding): skip silently.
            }
            reloc = (IMAGE_BASE_RELOCATION*)((char*)reloc + reloc->SizeOfBlock);
        }
    }

    // Imports: walk descriptors; for each, resolve every named/ordinal entry against our
    // own kernel32, then write the resolved 64-bit address into the IAT slot in `local`.
    // The whole `local` image is later WriteProcessMemory'd to `remote`, so writing to the
    // local IAT slot is equivalent to writing it in the target.
    IMAGE_DATA_DIRECTORY imp_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (imp_dir.VirtualAddress) {
        IMAGE_IMPORT_DESCRIPTOR* imp = (IMAGE_IMPORT_DESCRIPTOR*)(local + imp_dir.VirtualAddress);
        for (; imp->Name; ++imp) {
            const char* dll_name = (const char*)(local + imp->Name);
            HMODULE mod = GetModuleHandleA(dll_name);
            if (!mod) mod = LoadLibraryA(dll_name);
            if (!mod) { printf("import: %s not loadable\n", dll_name); return 1; }

            // OriginalFirstThunk holds the name/ordinal hints; FirstThunk is the IAT we patch.
            // If OFT is null (bound imports), the loader expects FirstThunk to still hold hints.
            DWORD oft_rva = imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk;
            IMAGE_THUNK_DATA64* oft = (IMAGE_THUNK_DATA64*)(local + oft_rva);
            IMAGE_THUNK_DATA64* iat = (IMAGE_THUNK_DATA64*)(local + imp->FirstThunk);

            for (DWORD i = 0; oft[i].u1.AddressOfData; ++i) {
                FARPROC fn;
                if (IMAGE_SNAP_BY_ORDINAL64(oft[i].u1.Ordinal)) {
                    fn = GetProcAddress(mod, (LPCSTR)IMAGE_ORDINAL64(oft[i].u1.Ordinal));
                } else {
                    IMAGE_IMPORT_BY_NAME* by_name =
                        (IMAGE_IMPORT_BY_NAME*)(local + oft[i].u1.AddressOfData);
                    fn = GetProcAddress(mod, by_name->Name);
                }
                if (!fn) { printf("import resolve failed in %s\n", dll_name); return 1; }
                iat[i].u1.Function = (ULONGLONG)(uintptr_t)fn;
            }
        }
    }

    // Push the fixed image to the target.
    if (!WriteProcessMemory(proc, remote, local, image_size, NULL)) {
        printf("WriteProcessMemory failed %lu\n", GetLastError());
        return 1;
    }

    // Locate payload_main and start it on a remote thread. No DllMain runs (manual map),
    // which is fine — the LoadLibrary validation path's DllMain only spawns payload_main
    // anyway, so the injector reaches the same entry point directly.
    DWORD pm_rva = export_rva(file, "payload_main");
    if (!pm_rva) { printf("payload_main not found in DLL\n"); return 1; }
    uintptr_t pm_remote = (uintptr_t)remote + pm_rva;

    HANDLE th = CreateRemoteThread(proc, NULL, 0,
                                   (LPTHREAD_START_ROUTINE)pm_remote, NULL, 0, NULL);
    if (!th) {
        printf("CreateRemoteThread failed %lu\n", GetLastError());
        return 1;
    }

    printf("Injected: remote=0x%p payload_main=0x%p tid=%lu\n",
           (void*)remote, (void*)pm_remote, GetThreadId(th));
    CloseHandle(th);
    VirtualFree(local, 0, MEM_RELEASE);
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("Usage: inject.exe <pid> [payload.dll]\n");
        printf("       inject.exe -wait <exe-name> [payload.dll]\n");
        printf("       inject.exe -wait <exe-name> -match <cmdline-substr> [payload.dll]\n");
        return 1;
    }

    DWORD pid = 0;
    const char* dll_path = "payload.dll";
    const char* match = NULL;

    if (_stricmp(argv[1], "-wait") == 0) {
        if (argc < 3) {
            printf("Usage: inject.exe -wait <exe-name> [-match <substr>] [payload.dll]\n");
            return 1;
        }
        int ai = 3;
        if (ai + 1 < argc && _stricmp(argv[ai], "-match") == 0) {
            match = argv[ai + 1];
            ai += 2;
        }
        if (ai < argc) dll_path = argv[ai];

        if (match) printf("Waiting for %s with cmdline containing '%s'...\n", argv[2], match);
        else       printf("Waiting for %s...\n", argv[2]);
        while (!(pid = find_pid(argv[2], match, 0))) Sleep(50);
    } else {
        pid = (DWORD)atoi(argv[1]);
        if (argc > 2) dll_path = argv[2];
    }

    HANDLE proc = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
        PROCESS_VM_READ      | PROCESS_QUERY_INFORMATION,
        FALSE, pid);
    if (!proc) { printf("OpenProcess(%lu) failed %lu\n", pid, GetLastError()); return 1; }

    printf("Target PID: %lu, DLL: %s\n", pid, dll_path);

    DWORD dll_size = 0;
    unsigned char* dll_data = read_file(dll_path, &dll_size);
    if (!dll_data) { printf("Failed to read %s\n", dll_path); CloseHandle(proc); return 1; }

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)dll_data;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("Not a PE: bad DOS magic\n"); free(dll_data); CloseHandle(proc); return 1;
    }
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(dll_data + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        printf("Not a PE: bad NT sig\n"); free(dll_data); CloseHandle(proc); return 1;
    }
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        printf("Payload must be x64 (machine=0x%x)\n", nt->FileHeader.Machine);
        free(dll_data); CloseHandle(proc); return 1;
    }

    int result = map_and_run(proc, dll_data);
    free(dll_data);
    CloseHandle(proc);
    return result;
}
