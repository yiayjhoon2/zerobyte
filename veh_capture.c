// 
//
// Validation build: creates a JVM in-process via JNI_CreateJavaVM and hooks the
// internal class-define funnel, proving the hook reads class bytes with ZERO code
// bytes modified and ZERO debug registers used — only a page-protection flag that
// is re-armed after every hit.
//
// Two target modes (-mode):
//   0  KlassFactory::create_from_stream  (the internal class-define funnel; RVA-located).
//        Rcx = ClassFileStream*, Rdx = Symbol* name.  Firing this during plain JVM
//        startup dumps hundreds of boot java/* classes — the proof we want.
//   1  JVM_DefineClassWithSource         (exported; mechanism-only cross-check).
//        Rcx = JNIEnv*, Rdx = const char* name, R9 = const jbyte* buf,
//        [rsp+0x28] = jsize len.
//
// Build: see build.bat (cl.exe, links jvm.lib from the JDK).

#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

// ----- JNI invocation API (minimal, no jni.h dependency) -----
typedef struct JavaVM_ JavaVM;
typedef struct JNIEnv_ JNIEnv;
typedef struct { char* optionString; void* extraInfo; } JavaVMOption;
typedef struct {
    int version;
    int nOptions;
    JavaVMOption* options;
    unsigned char ignoreUnrecognized;
} JavaVMInitArgs;
#define JNI_VERSION_21 0x00150000

typedef int (__stdcall *CreateJavaVM_t)(JavaVM**, void**, void*);
typedef int (__stdcall *DestroyJavaVM_t)(JavaVM*);

// ----- config / state -----
static uintptr_t g_target   = 0;     // hooked funnel address
static uintptr_t g_pagebase = 0;     // page containing the target
static SIZE_T    g_pagesize = 0x1000;
static int       g_mode     = 0;
static char      g_outdir[MAX_PATH] = "dump";
static volatile LONG g_count = 0;
static int       g_verbose  = 0;

// re-arm the guard on the target's page
static void arm_guard(void) {
    DWORD old;
    VirtualProtect((void*)g_pagebase, g_pagesize, PAGE_EXECUTE_READ | PAGE_GUARD, &old);
}

static void sanitize(char* s) {
    for (; *s; ++s) if (*s == '/' || *s == '\\' || *s == ':' || *s == '<' ||
                        *s == '>' || *s == '|' || *s == '?' || *s == '*' || *s=='"') *s = '_';
}

static unsigned short be16(const unsigned char* p) { return (p[0] << 8) | p[1]; }

// extract the internal class name (this_class -> Class -> Utf8) straight from the
// classfile bytes. funnel-agnostic; works no matter which register held the Symbol.
static int classname_from_bytes(const unsigned char* b, size_t len, char* out, int outcap) {
    if (len < 10 || be16(b) != 0xCAFE) return 0;
    unsigned short cpcount = be16(b + 8);
    if (cpcount == 0) return 0;
    // record offset of each CP entry's payload, keyed by index
    static const int MAXCP = 70000;
    if (cpcount > MAXCP) return 0;
    size_t* off = (size_t*)calloc(cpcount, sizeof(size_t));
    unsigned char* tag = (unsigned char*)calloc(cpcount, 1);
    if (!off || !tag) { free(off); free(tag); return 0; }
    size_t p = 10;
    int ok = 1;
    for (int i = 1; i < cpcount && ok; ++i) {
        if (p >= len) { ok = 0; break; }
        unsigned char t = b[p]; tag[i] = t; off[i] = p + 1;
        switch (t) {
            case 1:  { if (p + 3 > len) { ok = 0; break; } unsigned short l = be16(b + p + 1); p += 3 + l; } break;
            case 7: case 8: case 16: case 19: case 20:           p += 3; break;
            case 15:                                             p += 4; break;
            case 3: case 4: case 9: case 10: case 11: case 12:
            case 17: case 18:                                    p += 5; break;
            case 5: case 6:                                      p += 9; ++i; break; // 2 slots
            default: ok = 0; break;
        }
    }
    int got = 0;
    if (ok && p + 6 <= len) {
        unsigned short this_class = be16(b + p + 2);  // after access_flags(u2)
        if (this_class && this_class < cpcount && tag[this_class] == 7) {
            unsigned short ni = be16(b + off[this_class]);
            if (ni && ni < cpcount && tag[ni] == 1) {
                size_t so = off[ni];
                unsigned short sl = be16(b + so);
                if (so + 2 + sl <= len) {
                    int n = sl < outcap - 1 ? sl : outcap - 1;
                    memcpy(out, b + so + 2, n);
                    out[n] = 0;
                    got = n;
                }
            }
        }
    }
    free(off); free(tag);
    return got;
}

static void write_class(const unsigned char* buf, size_t len, const char* name) {
    char path[MAX_PATH];
    char safe[512];
    LONG n = InterlockedIncrement(&g_count);
    char frombytes[512] = {0};
    if (classname_from_bytes(buf, len, frombytes, sizeof(frombytes)) > 0)
        name = frombytes;                      // bytes are authoritative
    if (name && *name) {
        strncpy(safe, name, sizeof(safe) - 1);
        safe[sizeof(safe) - 1] = 0;
        sanitize(safe);
    } else {
        sprintf(safe, "unnamed_%ld", n);
    }
    sprintf(path, "%s\\%04ld_%s.class", g_outdir, n, safe);
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD wr;
        WriteFile(h, buf, (DWORD)len, &wr, NULL);
        CloseHandle(h);
        if (g_verbose) fprintf(stderr, "[veh] #%ld %s (%zu bytes)\n", n, safe, len);
    }
}

// read a HotSpot Symbol* into a C string buffer. layout (JDK21):
//   +0 u4 hash_and_refcount, +4 u2 length, +6 u1 body[length]  (not NUL-terminated)
static int read_symbol(uintptr_t sym, char* out, int outcap) {
    if (!sym || IsBadReadPtr((void*)sym, 6)) return 0;
    unsigned short len = *(unsigned short*)(sym + 4);
    if (len == 0 || len > 4000) return 0;
    if (IsBadReadPtr((void*)(sym + 6), len)) return 0;
    int n = len < outcap - 1 ? len : outcap - 1;
    memcpy(out, (void*)(sym + 6), n);
    out[n] = 0;
    return n;
}

// ClassFileStream (has a vtable): +0x08 buffer_start, +0x10 buffer_end.
// returns 0/len; validates the 0xCAFEBABE magic, probing a couple of offsets.
static size_t read_classfilestream(uintptr_t cfs, const unsigned char** out_buf) {
    static const int starts[] = { 0x08, 0x10, 0x00 };
    for (int i = 0; i < 3; ++i) {
        int so = starts[i], eo = so + 8;
        if (IsBadReadPtr((void*)(cfs + eo), 8)) continue;
        const unsigned char* b = *(const unsigned char**)(cfs + so);
        const unsigned char* e = *(const unsigned char**)(cfs + eo);
        if (!b || e <= b) continue;
        size_t len = (size_t)(e - b);
        if (len < 4 || len > 64 * 1024 * 1024) continue;
        if (IsBadReadPtr((void*)b, 4)) continue;
        if (b[0] == 0xCA && b[1] == 0xFE && b[2] == 0xBA && b[3] == 0xBE) {
            *out_buf = b;
            return len;
        }
    }
    return 0;
}

static LONG CALLBACK veh(EXCEPTION_POINTERS* ep) {
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    CONTEXT* ctx = ep->ContextRecord;

    if (code == STATUS_GUARD_PAGE_VIOLATION) {
        // OS auto-cleared PAGE_GUARD for this one fault. If the faulting RIP is our
        // target, grab the args; either way single-step one instruction then re-arm.
        if (ctx->Rip == g_target) {
            if (g_mode == 0) {
                if (g_verbose && g_count < 6) {
                    fprintf(stderr, "[hit] rcx=%p rdx=%p r8=%p r9=%p\n",
                            (void*)ctx->Rcx, (void*)ctx->Rdx, (void*)ctx->R8, (void*)ctx->R9);
                    // scan rcx[0..0x40] and r9/rdx for a CAFEBABE buffer pointer
                    uintptr_t regs[4] = { ctx->Rcx, ctx->Rdx, ctx->R8, ctx->R9 };
                    const char* rn[4] = { "rcx", "rdx", "r8", "r9" };
                    for (int r = 0; r < 4; ++r) {
                        for (int off = 0; off <= 0x40; off += 8) {
                            if (IsBadReadPtr((void*)(regs[r] + off), 8)) continue;
                            unsigned char* p = *(unsigned char**)(regs[r] + off);
                            if (!IsBadReadPtr(p, 4) && p[0]==0xCA && p[1]==0xFE && p[2]==0xBA && p[3]==0xBE)
                                fprintf(stderr, "      CAFEBABE via *(%s+0x%02x)=%p\n", rn[r], off, p);
                        }
                    }
                }
                const unsigned char* buf = NULL;
                size_t len = read_classfilestream(ctx->Rcx, &buf);
                if (len) {
                    char name[600] = {0};
                    read_symbol(ctx->Rdx, name, sizeof(name));
                    write_class(buf, len, name);
                }
            } else if (g_mode == 3) {
                // ClassFileParser ctor: rdx=ClassFileStream*, r8=Symbol* name
                const unsigned char* buf = NULL;
                size_t len = read_classfilestream(ctx->Rdx, &buf);
                if (len) {
                    char name[600] = {0};
                    read_symbol(ctx->R8, name, sizeof(name));
                    write_class(buf, len, name);
                }
            } else {
                const unsigned char* buf = (const unsigned char*)ctx->R9;
                // 5th arg (len) at [rsp+0x28] at function entry
                int len = 0;
                if (!IsBadReadPtr((void*)(ctx->Rsp + 0x28), 4))
                    len = *(int*)(ctx->Rsp + 0x28);
                const char* name = (const char*)ctx->Rdx;
                char nm[600] = {0};
                if (name && !IsBadReadPtr((void*)name, 1)) {
                    strncpy(nm, name, sizeof(nm) - 1);
                }
                if (buf && len > 4 && !IsBadReadPtr((void*)buf, 4) &&
                    buf[0] == 0xCA && buf[1] == 0xFE)
                    write_class(buf, len, nm);
            }
        }
        ctx->EFlags |= 0x100; // trap flag -> single-step the next instruction
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    if (code == STATUS_SINGLE_STEP) {
        // re-arm the guard for the next pass; clear trap flag.
        arm_guard();
        ctx->EFlags &= ~0x100;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

// scan jvm.dll .text for a byte pattern; '?' (0x100) = wildcard.
static uintptr_t pattern_scan(uintptr_t base, size_t size, const int* pat, int patlen) {
    for (size_t i = 0; i + patlen <= size; ++i) {
        const unsigned char* p = (const unsigned char*)(base + i);
        int ok = 1;
        for (int j = 0; j < patlen; ++j) {
            if (pat[j] != 0x100 && p[j] != (unsigned char)pat[j]) { ok = 0; break; }
        }
        if (ok) return base + i;
    }
    return 0;
}

static void module_text_range(HMODULE mod, uintptr_t* out_base, size_t* out_size) {
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)mod;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((uintptr_t)mod + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (memcmp(sec[i].Name, ".text", 5) == 0) {
            *out_base = (uintptr_t)mod + sec[i].VirtualAddress;
            *out_size = sec[i].Misc.VirtualSize;
            return;
        }
    }
    *out_base = 0; *out_size = 0;
}

int main(int argc, char** argv) {
    // RVA of KlassFactory::create_from_stream within jvm.dll, derived from disasm
    // of this exact build (21.0.10.7). 0 => locate by pattern instead.
    uintptr_t create_rva = 0;
    int pat[64]; int patlen = 0;

    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "-mode") && i + 1 < argc)      g_mode = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-rva") && i + 1 < argc)  create_rva = strtoull(argv[++i], NULL, 16);
        else if (!strcmp(argv[i], "-out") && i + 1 < argc)  strncpy(g_outdir, argv[++i], MAX_PATH - 1);
        else if (!strcmp(argv[i], "-v"))                    g_verbose = 1;
    }

    SYSTEM_INFO si; GetSystemInfo(&si); g_pagesize = si.dwPageSize;
    CreateDirectoryA(g_outdir, NULL);

    HMODULE jvm = LoadLibraryA("jvm.dll");
    if (!jvm) jvm = LoadLibraryA(
        "C:\\Program Files\\Eclipse Adoptium\\jdk-21.0.10.7-hotspot\\bin\\server\\jvm.dll");
    if (!jvm) { fprintf(stderr, "[veh] cannot load jvm.dll (%lu)\n", GetLastError()); return 1; }

    if (g_mode == 0 || g_mode == 3) {
        if (create_rva) {
            g_target = (uintptr_t)jvm + create_rva;
        } else {
            fprintf(stderr, "[veh] mode %d needs -rva <hex>\n", g_mode);
            return 1;
        }
    } else {
        // mechanism validation: JVM_DefineClass is exported and shares the arg layout
        // (Rcx=env, Rdx=name, R9=buf, [rsp+0x28]=len). Triggered below via JNI DefineClass.
        g_target = (uintptr_t)GetProcAddress(jvm, "JVM_DefineClass");
        if (!g_target) { fprintf(stderr, "[veh] no JVM_DefineClass\n"); return 1; }
    }

    // sanity: target must land inside jvm.dll .text
    uintptr_t tbase; size_t tsize;
    module_text_range(jvm, &tbase, &tsize);
    fprintf(stderr, "[veh] jvm.dll=%p .text=%p..+%zx target=%p mode=%d\n",
            (void*)jvm, (void*)tbase, tsize, (void*)g_target, g_mode);
    if (g_target < tbase || g_target >= tbase + tsize) {
        fprintf(stderr, "[veh] WARNING: target outside .text — wrong RVA?\n");
    }
    // show first bytes of target (these must remain unchanged — zero-byte proof)
    {
        unsigned char* t = (unsigned char*)g_target;
        fprintf(stderr, "[veh] target prologue:");
        for (int i = 0; i < 16; ++i) fprintf(stderr, " %02x", t[i]);
        fprintf(stderr, "\n");
    }

    if (!AddVectoredExceptionHandler(1, veh)) {
        fprintf(stderr, "[veh] AddVectoredExceptionHandler failed\n"); return 1;
    }
    // mode 0 target (create_from_stream) is known now and fires during startup -> arm first.
    // mode 1 target is jni_DefineClass, only known after the VM exists -> arm later.
    if (g_mode != 1) {
        g_pagebase = g_target & ~(uintptr_t)(g_pagesize - 1);
        arm_guard();
        fprintf(stderr, "[veh] guard armed on page %p, starting JVM...\n", (void*)g_pagebase);
    }

    CreateJavaVM_t CreateJavaVM = (CreateJavaVM_t)GetProcAddress(jvm, "JNI_CreateJavaVM");
    JavaVM* vm = NULL; void* env = NULL;
    JavaVMInitArgs args; memset(&args, 0, sizeof(args));
    args.version = JNI_VERSION_21;
    args.ignoreUnrecognized = 1;
    JavaVMOption opts[2];
    int no = 0;
    opts[no++].optionString = "-Xshare:off";      // disable CDS so boot classes parse via the funnel
    char cp[] = "-Djava.class.path=.";
    opts[no++].optionString = cp;
    args.nOptions = no;
    args.options = opts;

    int rc = CreateJavaVM(&vm, &env, &args);
    fprintf(stderr, "[veh] JNI_CreateJavaVM rc=%d  classes captured so far=%ld\n", rc, g_count);

    // mode 1: trigger an exported-funnel define so the mechanism is exercised.
    // Read a real .class off disk and push it through (*env)->DefineClass (index 5).
    if (rc == 0 && env && g_mode == 1) {
        void** ftab = *(void***)env;              // JNIEnv -> JNINativeInterface*
        typedef void* (__stdcall *DefineClass_t)(void* env, const char* name,
                                                 void* loader, const unsigned char* buf, int len);
        DefineClass_t DefineClass = (DefineClass_t)ftab[5];
        // hook the ACTUAL jni_DefineClass (table entry), not exported JVM_DefineClass.
        g_target = (uintptr_t)ftab[5];
        g_pagebase = g_target & ~(uintptr_t)(g_pagesize - 1);
        unsigned char* t = (unsigned char*)g_target;
        fprintf(stderr, "[veh] mode1 target jni_DefineClass=%p prologue:", (void*)g_target);
        for (int i = 0; i < 8; ++i) fprintf(stderr, " %02x", t[i]);
        fprintf(stderr, "\n");
        arm_guard();
        const char* sample = "classes_sample.class";
        HANDLE fh = CreateFileA(sample, GENERIC_READ, FILE_SHARE_READ, NULL,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (fh == INVALID_HANDLE_VALUE) {
            fprintf(stderr, "[veh] mode1: put any .class at %s to trigger\n", sample);
        } else {
            DWORD sz = GetFileSize(fh, NULL), got = 0;
            unsigned char* cb = (unsigned char*)malloc(sz);
            ReadFile(fh, cb, sz, &got, NULL); CloseHandle(fh);
            fprintf(stderr, "[veh] mode1: DefineClass on %lu-byte sample...\n", got);
            DefineClass(env, "veh/Probe", NULL, cb, (int)got);  // verify may reject; hook fires at entry
            free(cb);
        }
    }

    if (rc == 0 && vm) {
        DestroyJavaVM_t DestroyJavaVM = (DestroyJavaVM_t)GetProcAddress(jvm, "JNI_DestroyJavaVM");
        if (DestroyJavaVM) DestroyJavaVM(vm);
    }

    fprintf(stderr, "[veh] DONE. total classes captured = %ld -> %s\n", g_count, g_outdir);
    return 0;
}