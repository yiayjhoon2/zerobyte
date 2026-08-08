// validate_inject.c — proves inject.exe maps payload.dll into a running JVM and the guard
// catches live defines from outside. Spins up a JVM, pauses for ~5s (window for the injector
// to attach), then defines 300 synthetic classes through JNI DefineClass. Count of files in
// dump_live tells us whether the injected payload caught them.
//
// Usage (two terminals):
//   T1: validate_inject.exe
//   T2: inject.exe -wait validate_inject.exe payload.dll

#include <windows.h>
#include <stdio.h>
#include <string.h>

typedef struct JavaVM_ JavaVM;
typedef struct { char* optionString; void* extraInfo; } JavaVMOption;
typedef struct { int version; int nOptions; JavaVMOption* options; unsigned char ign; } InitArgs;
#define JNI_VERSION_21 0x00150000
typedef int (__stdcall *CreateJavaVM_t)(JavaVM**, void**, void*);

static void put_u16(unsigned char* p, unsigned v) { p[0] = (v >> 8) & 0xFF; p[1] = v & 0xFF; }

static int build_class(unsigned char* out, const char* name) {
    int nlen = (int)strlen(name);
    const char* sup = "java/lang/Object";
    int slen = (int)strlen(sup);
    unsigned char* p = out;
    *p++ = 0xCA; *p++ = 0xFE; *p++ = 0xBA; *p++ = 0xBE;
    put_u16(p, 0);  p += 2;
    put_u16(p, 65); p += 2;
    put_u16(p, 5);  p += 2;
    *p++ = 1; put_u16(p, nlen); p += 2; memcpy(p, name, nlen); p += nlen;
    *p++ = 7; put_u16(p, 1); p += 2;
    *p++ = 1; put_u16(p, slen); p += 2; memcpy(p, sup, slen); p += slen;
    *p++ = 7; put_u16(p, 3); p += 2;
    put_u16(p, 0x0001); p += 2;
    put_u16(p, 2); p += 2;
    put_u16(p, 4); p += 2;
    put_u16(p, 0); p += 2;
    put_u16(p, 0); p += 2;
    put_u16(p, 0); p += 2;
    put_u16(p, 0); p += 2;
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
    fprintf(stderr, "[vi] CreateJavaVM rc=%d pid=%lu\n", rc, GetCurrentProcessId());
    if (rc) return 1;

    fprintf(stderr, "[vi] JVM up. waiting 5s for injector...\n");
    Sleep(5000);

    void** ftab = *(void***)env;
    typedef void* (__stdcall *DefineClass_t)(void*, const char*, void*, const unsigned char*, int);
    DefineClass_t DefineClass = (DefineClass_t)ftab[5];

    const int N = 300;
    unsigned long long base = GetTickCount64();
    int defined_ok = 0;
    for (int j = 0; j < N; ++j) {
        char name[64];
        const char* pre = "InjectProbe_";
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
    Sleep(500);
    fprintf(stderr, "[vi] defined_ok=%d / %d ; check dump_live for InjectProbe_*.class\n",
            defined_ok, N);
    return 0;
}
