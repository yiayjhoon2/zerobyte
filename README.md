# zerobyte

Disclaimer this is very ai-coded for anyone who cares. 

Observe every class a HotSpot JVM defines at runtime, without `-javaagent`,
`-agentpath`, `LoadLibrary` in the target, or any bytes changed in `jvm.dll`.

Mechanism: a hardware execute breakpoint (DR0) on the internal
`ClassFileParser` constructor. Every class-define path in HotSpot bottoms out
there. On each hit a vectored exception handler reads `ClassFileStream*` from
`rdx`, pulls `buffer_start` / `buffer_end`, validates the classfile magic,
resolves the name from the constant pool, and writes the bytes to disk.

Two-piece design: `payload.dll` is the hook engine that runs inside the
target JVM. `inject.exe` is a manual-map loader that delivers `payload.dll`
without calling `LoadLibrary` in the target, so the DLL never appears in
`EnumProcessModules` or the PEB loader list.


## Files

| file | role |
|---|---|
| `payload.c` → `payload.dll` | hook engine; installs the HW BP, writes captured classes |
| `inject.c` → `inject.exe` | manual PE-map injector |
| `veh_capture.c` → `veh_capture.exe` | self-contained validation harness; spawns its own in-process JVM, useful for probing the funnel RVA on a new JDK build |
| `validate_payload.c` → `validate_payload.exe` | in-process `LoadLibrary` test for `payload.dll` |
| `validate_inject.c` → `validate_inject.exe` | end-to-end test for `inject.exe` |

## Build

Requires VS2022 with the x64 build environment (`vcvars64.bat`).

```cmd
build.bat            REM veh_capture.exe
build_payload.bat    REM payload.dll + validate_payload.exe
build_inject.bat     REM inject.exe + validate_inject.exe
```

## Funnel RVA

The DR0 target is pinned at:

```
FUNNEL_RVA = 0x215720    (payload.c)
```

This is `ClassFileParser::ClassFileParser` in Adoptium Temurin
JDK 21.0.10.7 `jvm.dll` (image base `0x180000000`). It will not match other
JDK builds. Two ways to override:

- Set env var `ZEROBYTE_FUNNEL_RVA=0x212160` (hex) in the target's environment
  before it launches.
- Edit `FUNNEL_RVA` in `payload.c` and rebuild.

To re-derive on an unfamiliar JDK, use `veh_capture.exe -mode 0 -rva <hex>`
against an in-process JVM. Look for the prologue reported by `_install.log`
to match the target function.

## Run

Two shells. Shell 1 arms the injector; shell 2 starts the JVM you want to
observe.

Shell 1:

```cmd
del /q dump_live\*.class 2>NUL
inject.exe -wait javaw.exe -match <cmdline-substring> payload.dll
```

`-match` filters by a substring of the target's command line. Useful when a
launcher (Prism, Mojang, custom) spawns a short-lived helper JVM before the
real one — pick a substring only the real launch has.

Shell 2: start the JVM.

Within ~100 ms of the JVM spawning, shell 1 prints:

```
Injected: remote=0x... payload_main=0x... tid=...
```

Class files start landing in `%LOCALAPPDATA%\zerobyte\dump_live\`
(overridable with `ZEROBYTE_OUT`).

## Quick Verification:

```cmd
type %LOCALAPPDATA%\zerobyte\dump_live\_install.log
```

Expected: `jvm=0x... target=0x... prologue=48 89 5c 24 20 55 56 57 41 54 41 55 41 56 41 57`.
Prologue mismatch means the RVA is wrong for this JDK.

```cmd
type %LOCALAPPDATA%\zerobyte\dump_live\_hits.log
```

Expected over time: `bp_hits=N step_hits=N written=N our_threads=3`.
`bp_hits == step_hits == written` is the healthy invariant.

## Filtering

`payload.c` has a compile-time slash-form prefix filter (`g_filter_prefix`)
and a `g_filter` toggle. Set the toggle to `1` and populate the array to
capture only classes whose names start with your prefix. Defaults to
capture-all.

## Detection surface

What zerobyte doesnt do:

- `-javaagent` / `-agentpath` on the command line.
- `java.instrument` module loaded.
- New entry in the target's PEB module list.
- Changes to `jvm.dll` `.text` bytes (in memory or on disk).
- Changes to page protection (HW BP, not page-guard).

What remains observable to the target:

- `GetThreadContext` reads DR0/DR7 on any target thread — the breakpoint VA
  and `Dr7 & 1 == 1` are visible.
- Vectored exception handler chain enumeration.
- The remote allocation created by the injector shows in a VAD walk.

## Validating a change

Before running a rebuilt `payload.dll` against something:

```cmd
build_payload.bat
del /q dump_live\*.class 2>NUL
validate_payload.exe
```

Expected: `[val] defined_ok=300 / 300`, and `_hits.log` last line
`bp_hits=300 step_hits=300 written=300`.

For injector changes:

Shell 1: `validate_inject.exe`
Shell 2: `inject.exe -wait validate_inject.exe payload.dll`

After ~7 s, `dump_live\` should contain 300 `*InjectProbe_*.class` files.


## License

GPL-3.0. See [LICENSE](LICENSE).
