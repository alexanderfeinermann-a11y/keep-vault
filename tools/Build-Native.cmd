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

rem Crypto++ supplies MARS, SHACAL-2, AES and ChaCha20-Poly1305, which this
rem repository has no reference implementation of. It is compiled once into a
rem static library rather than listed file by file next to each adapter: its
rem algorithm sources cannot be cherry-picked, because rijndael.cpp and its
rem siblings reach cryptlib, misc, secblock, algparam and from there the whole
rem integer machinery. CRYPTOPP_DISABLE_ASM must be identical here and for
rem every adapter compiled against the library, since the headers branch on it.
set "CRYPTOPP_HARDEN=/O2 /MT /GS /guard:cf"
set "CRYPTOPP_FLAGS=/std:c++17 /DCRYPTOPP_DISABLE_ASM /EHsc /Iexternal\cryptopp"
set "CRYPTOPP_LIB=build-obj\cryptopp\cryptopp.lib"

if not exist build-obj\cryptopp mkdir build-obj\cryptopp

if not exist "%CRYPTOPP_LIB%" (
  del /q build-obj\cryptopp\*.obj 2>nul
  del /q build-obj\cryptopp\sources.txt 2>nul
  rem The validation, benchmark and self-test drivers ship in the same
  rem directory as the library and pull in a main(). The *_simd translation
  rem units are compiled by Crypto++'s own makefile with per-file -arch flags;
  rem this build uses one flag set, so the portable C++ paths are used instead.
  for %%F in (external\cryptopp\*.cpp) do (
    echo %%~nxF | findstr /i /r /c:"^test\.cpp$" /c:"^bench[123]\.cpp$" /c:"^datatest\.cpp$" /c:"^dlltest\.cpp$" /c:"^fipsalgt\.cpp$" /c:"^adhoc\.cpp$" /c:"^regtest.*\.cpp$" /c:"^validat.*\.cpp$" /c:"_simd\.cpp$" >nul || (
      echo %%F>> build-obj\cryptopp\sources.txt
    )
  )
  if not exist build-obj\cryptopp\sources.txt (
    echo No Crypto++ sources were found; external\cryptopp is missing or empty.
    exit /b 1
  )
  cl %CRYPTOPP_HARDEN% %CRYPTOPP_FLAGS% /MP /c /Fobuild-obj\cryptopp\ @build-obj\cryptopp\sources.txt
  if errorlevel 1 exit /b 1
  lib /nologo /OUT:%CRYPTOPP_LIB% build-obj\cryptopp\*.obj
  if errorlevel 1 exit /b 1
)

for %%A in (mars shacal2 aes chachapoly) do (
  cl %CRYPTOPP_HARDEN% %CRYPTOPP_FLAGS% /LD /Fetools\%%A_ref.dll native\%%A_ref_export.cpp %CRYPTOPP_LIB% %HARDEN_LINK%
  if errorlevel 1 exit /b 1
)

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
