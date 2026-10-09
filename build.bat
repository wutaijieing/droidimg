@echo off
rem ===========================================================================
rem  build.bat - build the fix_kaslr_arm64 Win32 port (faithful + safe variants)
rem              with both MinGW-w64 GCC and MSVC 2022.
rem
rem  Artifacts:
rem    build\fix_kaslr_arm64.exe            MinGW  - strictly faithful to upstream
rem    build\fix_kaslr_arm64_safe.exe       MinGW  - compiled with -DFK_SAFE_BOUND
rem    build\fix_kaslr_arm64_msvc.exe       MSVC   - strictly faithful to upstream
rem    build\fix_kaslr_arm64_safe_msvc.exe  MSVC   - compiled with /DFK_SAFE_BOUND
rem
rem  The default ("faithful") build preserves the upstream algorithm byte for
rem  byte. The "safe" build adds ONLY an opt-in bound check (-DFK_SAFE_BOUND)
rem  that prevents the out-of-bounds entry read when a file has no .rela table;
rem  on any valid KASLR image it returns before the boundary, so its output is
rem  identical to the faithful build.
rem ===========================================================================
setlocal enabledelayedexpansion
cd /d "%~dp0"

set "SRC=fix_kaslr_arm64_win32.c"
set "OUTDIR=build"
set "GCC=G:\msys64\mingw64\bin\gcc.exe"
set "VCVARS=I:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"

if not exist "%OUTDIR%" mkdir "%OUTDIR%"

echo ============================================================
echo  [1/2] MinGW-w64 GCC toolchain
echo ============================================================
if exist "%GCC%" (
    "%GCC%" -O2 -Wall -o "%OUTDIR%\fix_kaslr_arm64.exe" "%SRC%"
    if errorlevel 1 (echo [MinGW] faithful BUILD FAILED) else (echo [MinGW] faithful BUILD OK)
    "%GCC%" -O2 -Wall -DFK_SAFE_BOUND -o "%OUTDIR%\fix_kaslr_arm64_safe.exe" "%SRC%"
    if errorlevel 1 (echo [MinGW] safe BUILD FAILED) else (echo [MinGW] safe BUILD OK)
) else (
    echo [MinGW] gcc not found at "%GCC%"
)

echo.
echo ============================================================
echo  [2/2] MSVC 2022 toolchain
echo ============================================================
if exist "%VCVARS%" call "%VCVARS%" >nul 2>&1
set "SDCOK="
echo !INCLUDE! | findstr /i /c:"Windows Kits" >nul 2>&1 && set "SDCOK=1"
if not defined SDCOK (
    echo [MSVC] vcvars64.bat did not provide the Windows SDK -^> using manual environment
    set "MSVCROOT=I:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Tools\MSVC\14.44.35207"
    set "SDKROOT=C:\Program Files (x86)\Windows Kits\10"
    set "SDKVER=10.0.26100.0"
    set "INCLUDE=!MSVCROOT!\include;!SDKROOT!\Include\!SDKVER!\ucrt;!SDKROOT!\Include\!SDKVER!\um;!SDKROOT!\Include\!SDKVER!\shared"
    set "LIB=!MSVCROOT!\lib\x64;!SDKROOT!\Lib\!SDKVER!\ucrt\x64;!SDKROOT!\Lib\!SDKVER!\um\x64"
    set "PATH=!MSVCROOT!\bin\Hostx64\x64;!PATH!"
)
if not defined INCLUDE (
    echo [MSVC] cannot locate MSVC headers on this machine
) else (
    cl /nologo /O2 /W3 /TC /Fe:"%OUTDIR%\fix_kaslr_arm64_msvc.exe" /Fo:"%OUTDIR%\msvc_faithful.obj" "%SRC%"
    if errorlevel 1 (echo [MSVC] faithful BUILD FAILED) else (echo [MSVC] faithful BUILD OK)
    cl /nologo /O2 /W3 /TC /DFK_SAFE_BOUND /Fe:"%OUTDIR%\fix_kaslr_arm64_safe_msvc.exe" /Fo:"%OUTDIR%\msvc_safe.obj" "%SRC%"
    if errorlevel 1 (echo [MSVC] safe BUILD FAILED) else (echo [MSVC] safe BUILD OK)
    del /q "%OUTDIR%\msvc_faithful.obj" "%OUTDIR%\msvc_safe.obj" 2>nul
)

echo.
echo ============================================================
echo  Artifacts (path / size / md5)
echo ============================================================
for %%F in (
    "%OUTDIR%\fix_kaslr_arm64.exe"
    "%OUTDIR%\fix_kaslr_arm64_safe.exe"
    "%OUTDIR%\fix_kaslr_arm64_msvc.exe"
    "%OUTDIR%\fix_kaslr_arm64_safe_msvc.exe"
) do (
    if exist "%%~fF" (
        for %%Z in ("%%~fF") do echo %%~fF  size=%%~zZ bytes
        certutil -hashfile "%%~fF" MD5 | findstr /v ":"
    ) else (
        echo %%~fF  MISSING
    )
)
echo.
echo Done.
endlocal
