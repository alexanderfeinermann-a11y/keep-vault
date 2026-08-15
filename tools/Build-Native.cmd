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
if not exist tools mkdir tools

pwsh -NoProfile -ExecutionPolicy Bypass -File tools\Verify-MldsaReference.ps1
if errorlevel 1 exit /b 1

set "HARDEN_COMPILE=/O2 /MT /GS /sdl /guard:cf"
set "HARDEN_LINK=/link /guard:cf /CETCOMPAT"

cl %HARDEN_COMPILE% /DNOJIT /EHsc /Fetools\zpaq.exe external\zpaq\zpaq.cpp external\zpaq\libzpaq.cpp advapi32.lib %HARDEN_LINK%
if errorlevel 1 exit /b 1

cl %HARDEN_COMPILE% /LD /Fetools\kalyna_ref.dll native\kalyna_ref_export.c external\Kalyna-reference\kalyna.c external\Kalyna-reference\tables.c %HARDEN_LINK%
if errorlevel 1 exit /b 1

cl %HARDEN_COMPILE% /LD /D_CRT_SECURE_NO_WARNINGS ^
  /Iexternal\Skein-reference\NIST\CD\Reference_Implementation ^
  /Fetools\threefish_ref.dll ^
  native\threefish_ref_export.c ^
  external\Skein-reference\NIST\CD\Reference_Implementation\skein.c ^
  external\Skein-reference\NIST\CD\Reference_Implementation\skein_block.c ^
  %HARDEN_LINK%
if errorlevel 1 exit /b 1

cl %HARDEN_COMPILE% /LD /D_CRT_SECURE_NO_WARNINGS /DDILITHIUM_MODE=5 ^
  /Iexternal\ML-DSA-reference\ref ^
  /Fetools\mldsa87_ref.dll ^
  native\mldsa87_ref_export.c ^
  external\ML-DSA-reference\ref\sign.c ^
  external\ML-DSA-reference\ref\packing.c ^
  external\ML-DSA-reference\ref\polyvec.c ^
  external\ML-DSA-reference\ref\poly.c ^
  external\ML-DSA-reference\ref\ntt.c ^
  external\ML-DSA-reference\ref\reduce.c ^
  external\ML-DSA-reference\ref\rounding.c ^
  external\ML-DSA-reference\ref\symmetric-shake.c ^
  external\ML-DSA-reference\ref\fips202.c ^
  bcrypt.lib ^
  %HARDEN_LINK%
if errorlevel 1 exit /b 1

if exist external\phc-winner-argon2 (
  cl %HARDEN_COMPILE% /LD /D_CRT_SECURE_NO_WARNINGS ^
    /Iexternal\phc-winner-argon2\include ^
    /Iexternal\phc-winner-argon2\src ^
    /Iexternal\phc-winner-argon2\src\blake2 ^
    /Fetools\argon2_ref.dll ^
    native\argon2_ref_export.c ^
    external\phc-winner-argon2\src\argon2.c ^
    external\phc-winner-argon2\src\core.c ^
    external\phc-winner-argon2\src\encoding.c ^
    external\phc-winner-argon2\src\ref.c ^
    external\phc-winner-argon2\src\thread.c ^
    external\phc-winner-argon2\src\blake2\blake2b.c ^
    %HARDEN_LINK%
  if errorlevel 1 exit /b 1

  cl %HARDEN_COMPILE% /D_CRT_SECURE_NO_WARNINGS ^
    /Iexternal\phc-winner-argon2\include ^
    /Iexternal\phc-winner-argon2\src ^
    /Iexternal\phc-winner-argon2\src\blake2 ^
    /Fetools\argon2.exe ^
    external\phc-winner-argon2\src\run.c ^
    external\phc-winner-argon2\src\argon2.c ^
    external\phc-winner-argon2\src\core.c ^
    external\phc-winner-argon2\src\encoding.c ^
    external\phc-winner-argon2\src\ref.c ^
    external\phc-winner-argon2\src\thread.c ^
    external\phc-winner-argon2\src\blake2\blake2b.c ^
    %HARDEN_LINK%
  if errorlevel 1 exit /b 1
)

echo Native build complete.
