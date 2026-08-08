// packaged to run INSIDE a live javaw.exe.
//
// Mechanism: hardware breakpoint on DR0. The original page-guard approach captured
// cleanly during validation but couldn't survive a real workload: the 4 KB page containing
// ClassFileParser is shared with hot JIT/GC code, so each of those nearby executions also
// tripped STATUS_GUARD_PAGE_VIOLATION. Real-load telemetry: 1.29M guard fires for 165
// useful captures (7836:1 waste). VEH dispatch overhead held the JVM under perf collapse
// long enough for framework init to time out.
//
// HW breakpoint fires ONLY when the CPU is about to execute the exact target byte. Cost is
// ~2 VEH dispatches per class (BP fire + step-over single-step), not millions per second.
//
// Tradeoff vs page-guard: DR0/DR7 contain target VA, visible to GetThreadContext. If
// the target's native code scans debug registers, this is detectable; the page-guard approach was
// only DR-clean. We've validated empirically that page-guard is non-viable under real load,
// so the DR-scan question is now the next thing to find out — if it's a problem we'll know.
//
// Entry points: payload_install() and a polling payload_main() thread. Also exports DllMain
// for LoadLibrary-based validation.

#include <windows.h>
#include <tlhelp32.h>
#include <stdint.h>

// ClassFileParser ctor RVA inside jvm.dll. This is JDK-build-specific — the value
// below is Adoptium Temurin JDK 21.0.10.7. Override at runtime by setting the env
// var ZEROBYTE_FUNNEL_RVA to a hex string (e.g. 0x212160) before the target starts;
// otherwise re-derive per README and rebuild.
#define FUNNEL_RVA 0x215720
#define CFS_BUF_OFF 0x08             // ClassFileStream._buffer_start
#define CFS_END_OFF 0x10             // ClassFileStream._buffer_end

static uintptr_t g_target;
static volatile LONG g_count;
static volatile LONG g_bp_hits;      // diag: HW BP fired with Rip == target
static volatile LONG g_step_hits;    // diag: single-step after step-over completed
// Output directory. Resolved lazily by resolve_outdir() before first write:
//   1. env var ZEROBYTE_OUT if set
//   2. else %LOCALAPPDATA%\zerobyte\dump_live
//   3. else C:\zerobyte_dump  (last-resort)
static WCHAR     g_outdir[MAX_PATH] = L"";
static int       g_filter = 0;       // 1 = only names matching g_filter_prefix (edit + rebuild)
// Compile-time slash-form prefix filter. Leave empty for capture-all; add entries to
// scope captures to a specific mod / obfuscator namespace. Example:
//   static const char* g_filter_prefix[] = { "com/example/mymod", NULL };
static const char* g_filter_prefix[] = { NULL };

// Our own thread IDs. Excluded from arming so the watchdog/installer threads never trip
// a HW BP themselves (they don't touch jvm.dll, but exclude defensively anyway).
static volatile DWORD g_my_tids[32];
static volatile LONG  g_my_tid_count;

static void register_self(void) {
    DWORD tid = GetCurrentThreadId();
    LONG idx = InterlockedIncrement(&g_my_tid_count) - 1;
    if (idx < 32) g_my_tids[idx] = tid;
}

static int is_my_thread(DWORD tid) {
    LONG n = g_my_tid_count;
    if (n > 32) n = 32;
    for (LONG i = 0; i < n; ++i) if (g_my_tids[i] == tid) return 1;
    return 0;
}

// ---- tiny helpers (no CRT) ----
static int peq4(const unsigned char* p, unsigned a, unsigned b, unsigned c, unsigned d) {
    return p[0]==a && p[1]==b && p[2]==c && p[3]==d;
}
static unsigned short be16(const unsigned char* p) { return (p[0] << 8) | p[1]; }
static int starts(const char* s, const char* pre) {
    while (*pre) { if (*s++ != *pre++) return 0; } return 1;
}

static int safe_read(const void* p, SIZE_T n) {
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery(p, &mbi, sizeof(mbi))) return 0;
    if (mbi.State != MEM_COMMIT) return 0;
    DWORD ok = PAGE_READONLY|PAGE_READWRITE|PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_WRITECOPY|PAGE_EXECUTE_WRITECOPY;
    if (!(mbi.Protect & ok)) return 0;
    return 1;
}

static void diag_write(const wchar_t* fname, const char* text, int len);

// classfile this_class -> Class -> Utf8 name, straight from the bytes (funnel-agnostic).
static int classname(const unsigned char* b, SIZE_T len, char* out, int outcap) {
    if (len < 10 || !(b[0]==0xCA && b[1]==0xFE)) return 0;
    unsigned short cpcount = be16(b + 8);
    if (cpcount == 0 || cpcount > 70000) return 0;
    static unsigned int off[70000];
    static unsigned char tag[70000];
    SIZE_T p = 10; int i;
    for (i = 1; i < cpcount; ++i) {
        if (p >= len) return 0;
        unsigned char t = b[p]; tag[i] = t; off[i] = (unsigned int)(p + 1);
        switch (t) {
            case 1:  { if (p+3 > len) return 0; p += 3 + be16(b + p + 1); } break;
            case 7: case 8: case 16: case 19: case 20: p += 3; break;
            case 15: p += 4; break;
            case 3: case 4: case 9: case 10: case 11: case 12: case 17: case 18: p += 5; break;
            case 5: case 6: p += 9; ++i; break;
            default: return 0;
        }
    }
    if (p + 6 > len) return 0;
    unsigned short tc = be16(b + p + 2);
    if (!tc || tc >= cpcount || tag[tc] != 7) return 0;
    unsigned short ni = be16(b + off[tc]);
    if (!ni || ni >= cpcount || tag[ni] != 1) return 0;
    SIZE_T so = off[ni]; unsigned short sl = be16(b + so);
    if (so + 2 + sl > len) return 0;
    int n = sl < outcap - 1 ? sl : outcap - 1;
    for (int k = 0; k < n; ++k) out[k] = b[so + 2 + k];
    out[n] = 0;
    return n;
}

static void write_class(const unsigned char* buf, SIZE_T len, const char* name) {
    LONG n = InterlockedIncrement(&g_count);
    if (g_filter) {
        int keep = 0;
        for (int i = 0; g_filter_prefix[i]; ++i) if (starts(name, g_filter_prefix[i])) { keep = 1; break; }
        if (!keep) return;
    }
    WCHAR path[1024]; int pi = 0;
    for (int k = 0; g_outdir[k] && pi < 700; ++k) path[pi++] = g_outdir[k];
    path[pi++] = L'\\';
    WCHAR num[8]; int d = 0; LONG v = n;
    do { num[d++] = L'0' + (v % 10); v /= 10; } while (v && d < 6);
    while (d < 4) num[d++] = L'0';
    while (d > 0) path[pi++] = num[--d];
    path[pi++] = L'_';
    for (int k = 0; name[k] && pi < 1024 - 16; ++k) {
        char c = name[k];
        if (c=='/'||c=='\\'||c==':'||c=='<'||c=='>'||c=='|'||c=='?'||c=='*'||c=='"') c = '_';
        path[pi++] = (WCHAR)c;
    }
    const WCHAR ext[] = L".class";
    for (int k = 0; k < 6; ++k) path[pi++] = ext[k];
    path[pi] = 0;

    HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) { DWORD wr; WriteFile(h, buf, (DWORD)len, &wr, NULL); CloseHandle(h); }
    else if (n == 1) {
        DWORD e = GetLastError();
        char b[400]; int bn = 0;
        const char* p1 = "CreateFileW err="; for (int k=0;p1[k];k++) b[bn++]=p1[k];
        char d2[12]; int dn2=0; LONG ev=(LONG)e; do{d2[dn2++]='0'+(ev%10);ev/=10;}while(ev); while(dn2>0)b[bn++]=d2[--dn2];
        const char* p2 = " path="; for (int k=0;p2[k];k++) b[bn++]=p2[k];
        for (int k=0; path[k] && bn<390; k++) b[bn++]=(char)path[k];
        b[bn++]='\n';
        diag_write(L"_writeerr.log", b, bn);
    }
}

// DR7 layout for breakpoint 0: L0 (bit 0) = local enable, RW0 (bits 16-17) = 00 execute,
// LEN0 (bits 18-19) = 00 one byte. To arm: Dr0 = target, Dr7 = (Dr7 & ~0xF0003) | 1.
#define DR7_BP0_MASK (1ULL | (1ULL<<1) | (0xFULL<<16))
#define DR7_BP0_ARM  (1ULL)

static void arm_one(DWORD tid) {
    if (is_my_thread(tid)) return;
    HANDLE h = OpenThread(THREAD_GET_CONTEXT|THREAD_SET_CONTEXT|THREAD_SUSPEND_RESUME, FALSE, tid);
    if (!h) return;
    if (SuspendThread(h) == (DWORD)-1) { CloseHandle(h); return; }
    CONTEXT ctx; memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(h, &ctx)) {
        if (ctx.Dr0 != (DWORD64)g_target || (ctx.Dr7 & 1ULL) == 0) {
            ctx.Dr0 = (DWORD64)g_target;
            ctx.Dr7 = (ctx.Dr7 & ~DR7_BP0_MASK) | DR7_BP0_ARM;
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            SetThreadContext(h, &ctx);
        }
    }
    ResumeThread(h);
    CloseHandle(h);
}

static void arm_all_threads(void) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    THREADENTRY32 te; te.dwSize = sizeof(te);
    DWORD pid = GetCurrentProcessId();
    if (Thread32First(snap, &te)) do {
        if (te.th32OwnerProcessID == pid) arm_one(te.th32ThreadID);
    } while (Thread32Next(snap, &te));
    CloseHandle(snap);
}

// Both HW execute breakpoints and the trap flag raise STATUS_SINGLE_STEP. Distinguish by
// Rip: HW BP fires *before* the target instruction executes, so Rip == target on entry.
// Trap-flag single-step fires *after* the target instruction executes, so Rip != target.
static LONG CALLBACK veh(EXCEPTION_POINTERS* ep) {
    if (ep->ExceptionRecord->ExceptionCode != STATUS_SINGLE_STEP) return EXCEPTION_CONTINUE_SEARCH;
    CONTEXT* ctx = ep->ContextRecord;

    if (ctx->Rip == g_target) {
        InterlockedIncrement(&g_bp_hits);
        uintptr_t cfs = ctx->Rdx;
        if (safe_read((void*)(cfs + CFS_END_OFF), 8)) {
            const unsigned char* b = *(const unsigned char**)(cfs + CFS_BUF_OFF);
            const unsigned char* e = *(const unsigned char**)(cfs + CFS_END_OFF);
            if (b && e > b) {
                SIZE_T len = (SIZE_T)(e - b);
                if (len >= 4 && len < 64*1024*1024 && safe_read(b, 4) &&
                    peq4(b, 0xCA, 0xFE, 0xBA, 0xBE)) {
                    char nm[600];
                    if (classname(b, len, nm, sizeof(nm)) <= 0) { nm[0]='_'; nm[1]=0; }
                    write_class(b, len, nm);
                }
            }
        }
        // Step over the target instruction: turn off DR0's enable bit and set the trap
        // flag. The OS executes one instruction, then re-enters us via STATUS_SINGLE_STEP.
        ctx->Dr7 &= ~DR7_BP0_ARM;
        ctx->EFlags |= 0x100;
        ctx->ContextFlags |= CONTEXT_DEBUG_REGISTERS;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    // Post-step: re-arm DR0 and clear the trap flag.
    InterlockedIncrement(&g_step_hits);
    ctx->Dr0 = (DWORD64)g_target;
    ctx->Dr7 = (ctx->Dr7 & ~DR7_BP0_MASK) | DR7_BP0_ARM;
    ctx->EFlags &= ~0x100;
    ctx->ContextFlags |= CONTEXT_DEBUG_REGISTERS;
    return EXCEPTION_CONTINUE_EXECUTION;
}

static void hex64(uintptr_t v, char* out) {
    const char* H = "0123456789abcdef";
    out[0]='0'; out[1]='x';
    for (int i = 0; i < 16; ++i) out[2+i] = H[(v >> ((15-i)*4)) & 0xF];
    out[18] = 0;
}
static void diag_write(const wchar_t* fname, const char* text, int len) {
    WCHAR path[MAX_PATH]; int pi = 0;
    for (int k = 0; g_outdir[k]; ++k) path[pi++] = g_outdir[k];
    path[pi++] = L'\\';
    for (int k = 0; fname[k]; ++k) path[pi++] = fname[k];
    path[pi] = 0;
    HANDLE h = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) { DWORD wr; WriteFile(h, text, len, &wr, NULL); CloseHandle(h); }
}

// Polls every 100 ms and arms DR0 on any thread we haven't seen yet. JVM spawns its worker
// pool, GC threads, JIT compiler threads, render thread etc. through the launch — without
// this they'd execute the funnel without firing our BP.
static DWORD WINAPI arm_watch(LPVOID a) {
    (void)a; register_self();
    for (;;) {
        arm_all_threads();
        Sleep(100);
    }
}

// Counter watchdog: snapshots hit counts to dump_live/_hits.log so post-mortem we can tell
// how many funnel hits the BP saw and how many landed bytes.
static DWORD WINAPI diag_watch(LPVOID a) {
    (void)a; register_self();
    for (int i = 0; i < 1200; ++i) {
        char buf[200]; int n = 0;
        const char* l1 = "bp_hits="; for (int k=0;l1[k];k++) buf[n++]=l1[k];
        LONG v = g_bp_hits; char d[16]; int dn=0; do{d[dn++]='0'+(v%10);v/=10;}while(v); while(dn>0)buf[n++]=d[--dn];
        const char* l2 = " step_hits="; for (int k=0;l2[k];k++) buf[n++]=l2[k];
        v = g_step_hits; dn=0; do{d[dn++]='0'+(v%10);v/=10;}while(v); while(dn>0)buf[n++]=d[--dn];
        const char* l3 = " written="; for (int k=0;l3[k];k++) buf[n++]=l3[k];
        v = g_count; dn=0; do{d[dn++]='0'+(v%10);v/=10;}while(v); while(dn>0)buf[n++]=d[--dn];
        const char* l4 = " our_threads="; for (int k=0;l4[k];k++) buf[n++]=l4[k];
        v = g_my_tid_count; dn=0; do{d[dn++]='0'+(v%10);v/=10;}while(v); while(dn>0)buf[n++]=d[--dn];
        buf[n++]='\n';
        diag_write(L"_hits.log", buf, n);
        Sleep(100);
    }
    return 0;
}

// Copy narrow -> wide onto dst[0..cap-1], NUL-terminated. Returns chars written (excl. NUL).
static int wcopy_a(WCHAR* dst, int cap, const char* src) {
    int i = 0; while (src[i] && i < cap - 1) { dst[i] = (WCHAR)(unsigned char)src[i]; ++i; }
    dst[i] = 0; return i;
}
static int wcopy_w(WCHAR* dst, int cap, const WCHAR* src) {
    int i = 0; while (src[i] && i < cap - 1) { dst[i] = src[i]; ++i; }
    dst[i] = 0; return i;
}

// mkdir -p equivalent for wide paths. Walks the path, creating each component in turn.
static void mkdirs_w(const WCHAR* path) {
    WCHAR tmp[MAX_PATH]; int n = wcopy_w(tmp, MAX_PATH, path);
    for (int i = 1; i < n; ++i) {
        if (tmp[i] == L'\\' || tmp[i] == L'/') {
            WCHAR save = tmp[i]; tmp[i] = 0;
            CreateDirectoryW(tmp, NULL);
            tmp[i] = save;
        }
    }
    CreateDirectoryW(tmp, NULL);
}

// Populate g_outdir. Precedence: ZEROBYTE_OUT env var -> %LOCALAPPDATA%\zerobyte\dump_live
// -> C:\zerobyte_dump. mkdir -p'd. Safe to call from multiple threads (idempotent).
static void resolve_outdir(void) {
    if (g_outdir[0]) return;
    DWORD n = GetEnvironmentVariableW(L"ZEROBYTE_OUT", g_outdir, MAX_PATH);
    if (n > 0 && n < MAX_PATH) { mkdirs_w(g_outdir); return; }
    WCHAR base[MAX_PATH];
    n = GetEnvironmentVariableW(L"LOCALAPPDATA", base, MAX_PATH);
    if (n > 0 && n < MAX_PATH - 32) {
        int pi = wcopy_w(g_outdir, MAX_PATH, base);
        const WCHAR tail[] = L"\\zerobyte\\dump_live";
        for (int k = 0; tail[k] && pi < MAX_PATH - 1; ++k) g_outdir[pi++] = tail[k];
        g_outdir[pi] = 0;
        mkdirs_w(g_outdir);
        return;
    }
    wcopy_a(g_outdir, MAX_PATH, "C:\\zerobyte_dump");
    mkdirs_w(g_outdir);
}

__declspec(dllexport) int payload_install(void) {
    HMODULE jvm = GetModuleHandleW(L"jvm.dll");
    if (!jvm) return 1;
    resolve_outdir();
    uintptr_t rva = FUNNEL_RVA;
    {
        WCHAR ov[32]; DWORD n = GetEnvironmentVariableW(L"ZEROBYTE_FUNNEL_RVA", ov, 32);
        if (n > 0 && n < 32) {
            int i = 0; uintptr_t v = 0;
            if (ov[0] == L'0' && (ov[1] == L'x' || ov[1] == L'X')) i = 2;
            for (; ov[i]; ++i) {
                WCHAR c = ov[i]; unsigned d;
                if (c >= L'0' && c <= L'9') d = c - L'0';
                else if (c >= L'a' && c <= L'f') d = 10 + c - L'a';
                else if (c >= L'A' && c <= L'F') d = 10 + c - L'A';
                else { v = 0; break; }
                v = (v << 4) | d;
            }
            if (v) rva = v;
        }
    }
    g_target = (uintptr_t)jvm + rva;

    // Log what we hooked + the target prologue bytes (proof: the in-memory .text bytes at
    // the funnel are unchanged; HW BPs live in CPU debug registers, not in code).
    {
        char buf[256]; int n = 0;
        const char* a1 = "jvm="; for (int k=0;a1[k];k++) buf[n++]=a1[k];
        char hx[19]; hex64((uintptr_t)jvm, hx); for (int k=0;hx[k];k++) buf[n++]=hx[k];
        const char* a2 = " target="; for (int k=0;a2[k];k++) buf[n++]=a2[k];
        hex64(g_target, hx); for (int k=0;hx[k];k++) buf[n++]=hx[k];
        const char* a3 = " prologue="; for (int k=0;a3[k];k++) buf[n++]=a3[k];
        unsigned char* t = (unsigned char*)g_target;
        const char* H = "0123456789abcdef";
        for (int i=0;i<16;i++){ buf[n++]=H[(t[i]>>4)&0xF]; buf[n++]=H[t[i]&0xF]; buf[n++]=' '; }
        buf[n++]='\n';
        diag_write(L"_install.log", buf, n);
    }

    if (!AddVectoredExceptionHandler(1, veh)) return 2;
    arm_all_threads();
    CreateThread(NULL, 0, diag_watch, NULL, 0, NULL);
    CreateThread(NULL, 0, arm_watch, NULL, 0, NULL);
    return 0;
}

__declspec(dllexport) DWORD WINAPI payload_main(LPVOID arg) {
    (void)arg; register_self();
    for (int tries = 0; tries < 6000; ++tries) {
        if (payload_install() == 0) return 0;
        Sleep(10);
    }
    return 1;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        CreateThread(NULL, 0, payload_main, NULL, 0, NULL);
    }
    return TRUE;
}
