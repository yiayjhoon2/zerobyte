// validate_payload.c — proves payload.dll installs itself correctly inside a live JVM.
// Creates a VM in-process, LoadLibrary's payload.dll (its DllMain arms the guard against
// the already-loaded jvm.dll — exactly what the injected case does), then forces a
// GUARANTEED-fresh class parse via JNI DefineClass on a synthetic class whose name carries
// a GetTickCount64 suffix (so it cannot already be loaded), and confirms it lands in
// dump_live. A fresh parse is the only honest proof the armed guard catches live defines —
// FindClass on stock JDK classes is unreliable because the -Xshare:off bootstrap already
// parsed them before the payload armed.

#include <windows.h>
#include <stdio.h>
#include <string.h>

typedef struct JavaVM_ JavaVM;
typedef struct { char* optionString; void* extraInfo; } JavaVMOption;
typedef struct { int version; int nOptions; JavaVMOption* options; unsigned char ign; } InitArgs;
#define JNI_VERSION_21 0x00150000
typedef int (__stdcall *CreateJavaVM_t)(JavaVM**, void**, void*);

static void put_u16(unsigned char* p, unsigned v) { p[0] = (v >> 8) & 0xFF; p[1] = v & 0xFF; }

// Build a minimal valid classfile:  public class <name> extends java/lang/Object {}
// CP: #1 Utf8 name, #2 Class #1, #3 Utf8 "java/lang/Object", #4 Class #3
static int build_class(unsigned char* out, const char* name) {
    int nlen = (int)strlen(name);
    const char* sup = "java/lang/Object";
    int slen = (int)strlen(sup);
    unsigned char* p = out;
    *p++ = 0xCA; *p++ = 0xFE; *p++ = 0xBA; *p++ = 0xBE; // magic
    put_u16(p, 0); p += 2;                               // minor
    put_u16(p, 65); p += 2;                              // major (Java 21)
    put_u16(p, 5); p += 2;                               // constant_pool_count = 5 (entries 1..4)
    *p++ = 1; put_u16(p, nlen); p += 2; memcpy(p, name, nlen); p += nlen;   // #1 Utf8 name
    *p++ = 7; put_u16(p, 1); p += 2;                                        // #2 Class -> #1
    *p++ = 1; put_u16(p, slen); p += 2; memcpy(p, sup, slen); p += slen;    // #3 Utf8 super
    *p++ = 7; put_u16(p, 3); p += 2;                                        // #4 Class -> #3
    put_u16(p, 0x0001); p += 2;   // access_flags = public
    put_u16(p, 2); p += 2;        // this_class = #2
    put_u16(p, 4); p += 2;        // super_class = #4
    put_u16(p, 0); p += 2;        // interfaces_count
    put_u16(p, 0); p += 2;        // fields_count
    put_u16(p, 0); p += 2;        // methods_count
    put_u16(p, 0); p += 2;        // attributes_count
    return (int)(p - out);
}

int main(void) {
    char* jvmpath = "C:\\Program Files\\Eclipse Adoptium\\jdk-21.0.10.7-hotspot\\bin\\server\\jvm.dll";
    HMODULE jvm = LoadLibraryA("jvm.dll");
    if (!jvm) jvm = LoadLibraryA(jvmpath);
    if (!jvm) { fprintf(stderr, "no jvm.dll\n"); return 1; }

    CreateJavaVM_t CreateJavaVM = (CreateJavaVM_t)GetProcAddress(jvm, "JNI_CreateJavaVM");
    JavaVM* vm = NULL; void* env = NULL;
    InitArgs a; memset(&a, 0, sizeof(a));
    a.version = JNI_VERSION_21; a.ign = 1;
    JavaVMOption o[1]; o[0].optionString = "-Xshare:off"; a.nOptions = 1; a.options = o;
    int rc = CreateJavaVM(&vm, &env, &a);
    fprintf(stderr, "[val] CreateJavaVM rc=%d\n", rc);
    if (rc) return 1;

    // arm the guard exactly as the injector will (here delivered via LoadLibrary).
    HMODULE pl = LoadLibraryA("payload.dll");
    if (!pl) { fprintf(stderr, "[val] LoadLibrary payload.dll failed %lu\n", GetLastError()); return 1; }
    Sleep(200);  // let payload_main arm the guard

    void** ftab = *(void***)env;
    typedef void* (__stdcall *DefineClass_t)(void*, const char*, void*, const unsigned char*, int);
    DefineClass_t DefineClass = (DefineClass_t)ftab[5];   // JNI index 5

    // Define N unique classes. Each name carries GetTickCount64 + index so none can already
    // be loaded -> every call is a genuine funnel hit. Counting how many of N land in
    // dump_live tells us whether the armed-guard-on-live-define path works, and how lossy a
    // one-shot PAGE_GUARD on a hot shared page is when many defines stream through.
    const int N = 300;
    unsigned long long base = GetTickCount64();
    int defined_ok = 0;
    for (int j = 0; j < N; ++j) {
        char name[64];
        const char* pre = "ZeroByteProbe_";
        int i = 0; while (pre[i]) { name[i] = pre[i]; i++; }
        unsigned long long t = base + (unsigned long long)j * 1000003ull;
        char digits[24]; int d = 0;
        do { digits[d++] = (char)('0' + (t % 10)); t /= 10; } while (t);
        while (d > 0) name[i++] = digits[--d];
        name[i] = 0;

        unsigned char cls[256];
        int len = build_class(cls, name);
        void* c = DefineClass(env, name, NULL, cls, len);
        if (c) defined_ok++;
    }
    Sleep(300);
    fprintf(stderr, "[val] defined_ok=%d / %d ; check dump_live count\n", defined_ok, N);
    return 0;
}
