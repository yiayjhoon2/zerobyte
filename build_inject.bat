@echo off
setlocal
cd /d %~dp0
if not defined VSCMD_VER call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
cl /nologo /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS inject.c /Fe:inject.exe
echo INJECT_EXIT=%errorlevel%
cl /nologo /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS validate_inject.c /Fe:validate_inject.exe
echo VALIDATE_INJECT_EXIT=%errorlevel%
endlocal
