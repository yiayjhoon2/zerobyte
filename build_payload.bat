@echo off
setlocal
cd /d %~dp0
if not defined VSCMD_VER call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
cl /nologo /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS /LD payload.c /Fe:payload.dll
echo PAYLOAD_EXIT=%errorlevel%
cl /nologo /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS validate_payload.c /Fe:validate_payload.exe
echo VALIDATE_PAYLOAD_EXIT=%errorlevel%
endlocal
