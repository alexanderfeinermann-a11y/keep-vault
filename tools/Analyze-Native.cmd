@echo off
setlocal

set "ROOT=%~dp0.."
set "VSDEVCMD=C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat"

if not exist "%VSDEVCMD%" (
  set "VSDEVCMD=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat"
)

if not exist "%VSDEVCMD%" (
  echo Visual Studio Developer Command Prompt was not found.
  exit /b 1
)

call "%VSDEVCMD%" -arch=x64 -host_arch=x64
if errorlevel 1 exit /b 1

cd /d "%ROOT%"
if not exist build-analysis mkdir build-analysis

set "ANALYZE=/nologo /c /analyze /W4 /sdl"

cl %ANALYZE% /DNOJIT /EHsc /Fobuild-analysis\zpaq.obj /analyze:log build-analysis\zpaq.xml external\zpaq\zpaq.cpp
if errorlevel 1 exit /b 1

cl %ANALYZE% /DNOJIT /EHsc /Fobuild-analysis\libzpaq.obj /analyze:log build-analysis\libzpaq.xml external\zpaq\libzpaq.cpp
if errorlevel 1 exit /b 1

cl %ANALYZE% /WX /Fobuild-analysis\kalyna_ref_export.obj /analyze:log build-analysis\kalyna_ref_export.xml native\kalyna_ref_export.c
if errorlevel 1 exit /b 1

cl %ANALYZE% /WX /D_CRT_SECURE_NO_WARNINGS ^
  /Iexternal\Skein-reference\NIST\CD\Reference_Implementation ^
  /Fobuild-analysis\threefish_ref_export.obj ^
  /analyze:log build-analysis\threefish_ref_export.xml ^
  native\threefish_ref_export.c
if errorlevel 1 exit /b 1

cl %ANALYZE% /WX /D_CRT_SECURE_NO_WARNINGS ^
  /Iexternal\phc-winner-argon2\include ^
  /Iexternal\phc-winner-argon2\src ^
  /Iexternal\phc-winner-argon2\src\blake2 ^
  /Fobuild-analysis\argon2_ref_export.obj ^
  /analyze:log build-analysis\argon2_ref_export.xml ^
  native\argon2_ref_export.c
if errorlevel 1 exit /b 1

cl %ANALYZE% /WX /D_CRT_SECURE_NO_WARNINGS /DDILITHIUM_MODE=5 ^
  /Iexternal\ML-DSA-reference\ref ^
  /Fobuild-analysis\mldsa_mldsa87_ref_export.obj ^
  /analyze:log build-analysis\mldsa_mldsa87_ref_export.xml ^
  native\mldsa87_ref_export.c
if errorlevel 1 exit /b 1

for %%F in (
  external\ML-DSA-reference\ref\sign.c
  external\ML-DSA-reference\ref\packing.c
  external\ML-DSA-reference\ref\polyvec.c
  external\ML-DSA-reference\ref\poly.c
  external\ML-DSA-reference\ref\ntt.c
  external\ML-DSA-reference\ref\reduce.c
  external\ML-DSA-reference\ref\rounding.c
  external\ML-DSA-reference\ref\symmetric-shake.c
  external\ML-DSA-reference\ref\fips202.c
) do (
  cl %ANALYZE% /D_CRT_SECURE_NO_WARNINGS /DDILITHIUM_MODE=5 ^
    /Iexternal\ML-DSA-reference\ref ^
    /Fobuild-analysis\mldsa_%%~nF.obj ^
    /analyze:log build-analysis\mldsa_%%~nF.xml ^
    %%F
  if errorlevel 1 exit /b 1
)

echo Native static analysis complete.
