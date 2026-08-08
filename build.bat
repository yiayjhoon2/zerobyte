@echo off
setlocal
cd /d %~dp0
if not defined VSCMD_VER call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
cl /nologo /O2 /W3 /MT /D_CRT_SECURE_NO_WARNINGS veh_capture.c /Fe:veh_capture.exe
echo VEH_CAPTURE_EXIT=%errorlevel%
endlocal
