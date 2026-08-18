#!/bin/zsh
# Builds the portable Keep Vault release for macOS, the counterpart of
# tools/Build-Portable.ps1 on Windows.
#
# "Portable" means the result runs from wherever it is unpacked — a USB stick,
# an external disk, a home directory — without an installer, without a .NET
# runtime, and without touching /Applications. The folder carries the signed
# app bundle, a standalone release verifier, and a README naming the pins that
# were compiled in. The ZIP and both hash manifests are signed with the same
# hybrid RSA-PSS + ML-DSA-87 pair as everything else, so the download can be
# checked before anything is launched.
set -euo pipefail
umask 077

script_dir=${0:A:h}
repo_root=${script_dir:h}
mac_project=${repo_root}/KeepVaultMac
packaging_dir=${mac_project}/Packaging
verifier_project=${repo_root}/KeepVaultMac.ReleaseVerifier/KeepVaultMac.ReleaseVerifier.csproj
team_identifier='2T6K9PGS55'
bundle_identifier='de.michael-feinermann.keep-vault'
output_name='Keep Vault-portable-macOS'
architecture='universal'
identity=${KEEPVAULT_CODESIGN_IDENTITY:-}
pfx_path=${KEEPVAULT_HYBRID_PFX:-${HOME}/Library/Application Support/Keep Vault/ReleaseKeys/hybrid-rsa4096.pfx}
mldsa_private_key=${KEEPVAULT_MLDSA_PRIVATE_KEY:-${HOME}/Library/Application Support/Keep Vault/ReleaseKeys/mldsa87-private.key}
mldsa_private_key_encrypted=${KEEPVAULT_MLDSA_PRIVATE_KEY_ENCRYPTED:-${mldsa_private_key}.enc}
mldsa_keychain_service=${KEEPVAULT_MLDSA_KEYCHAIN_SERVICE:-de.michael-feinermann.keep-vault.hybrid-wrapping-key}
pfx_password_encrypted=${KEEPVAULT_PFX_PASSWORD_ENCRYPTED:-${pfx_path}.password.enc}
mldsa_keychain_account=${KEEPVAULT_MLDSA_KEYCHAIN_ACCOUNT:-${USER:-}}

# Both halves of the hybrid certificate are released by one Keychain
# confirmation once they have been wrapped: a signature counts only when
# RSA-PSS and ML-DSA-87 both verify, so gating them separately would mean two
# prompts for one indivisible decision. The unwrapped paths stay as a fallback
# so a tree that has not been migrated still builds.
mldsa_key_arguments=(--mldsa-private-key ${mldsa_private_key})
if [[ -f ${mldsa_private_key_encrypted} && ! -L ${mldsa_private_key_encrypted} ]]; then
  mldsa_key_arguments=(
    --mldsa-private-key-encrypted ${mldsa_private_key_encrypted}
    --mldsa-key-keychain-service ${mldsa_keychain_service}
    --mldsa-key-keychain-account ${mldsa_keychain_account}
  )
fi
pfx_password_arguments=()
if [[ -f ${pfx_password_encrypted} && ! -L ${pfx_password_encrypted} ]]; then
  pfx_password_arguments=(--pfx-password-encrypted ${pfx_password_encrypted})
fi

mldsa_public_key=${KEEPVAULT_MLDSA_PUBLIC_KEY:-${packaging_dir}/Keys/mldsa87-public.key}
pfx_password_service=${KEEPVAULT_PFX_KEYCHAIN_SERVICE:-de.michael-feinermann.keep-vault.hybrid-pfx}
pfx_password_account=${KEEPVAULT_PFX_KEYCHAIN_ACCOUNT:-${USER:-}}
dotnet_command=${KEEPVAULT_DOTNET:-/Users/michael/.dotnet-keepvault/dotnet}
source_app=${repo_root}/dist/Keep\ Vault-macOS/Keep\ Vault.app

usage() {
  print -u2 'Usage: Build-Portable-macOS.sh [--app "Keep Vault.app"] [--identity HASH] [--output-name NAME]'
  print -u2 '       [--architecture universal|arm64] [--dotnet /path/to/dotnet]'
  exit 64
}

while (( $# != 0 )); do
  case $1 in
    --app) (( $# >= 2 )) || usage; source_app=$2; shift 2 ;;
    --identity) (( $# >= 2 )) || usage; identity=$2; shift 2 ;;
    --output-name) (( $# >= 2 )) || usage; output_name=$2; shift 2 ;;
    --architecture) (( $# >= 2 )) || usage; architecture=$2; shift 2 ;;
    --dotnet) (( $# >= 2 )) || usage; dotnet_command=$2; shift 2 ;;
    *) usage ;;
  esac
done

if [[ ${architecture} != universal && ${architecture} != arm64 ]]; then
  print -u2 'Only universal or arm64 portable releases are supported.'
  exit 64
fi
if [[ ! ${output_name} =~ '^[A-Za-z0-9][A-Za-z0-9._ -]{0,126}[A-Za-z0-9]$' ]]; then
  print -u2 'The output name must be a plain 2-128 character file name without trailing punctuation.'
  exit 64
fi
if [[ ! -d ${source_app} || -L ${source_app} ]]; then
  print -u2 "Signed app bundle not found or is a symbolic link: ${source_app}"
  print -u2 'Run tools/Build-KeepVault-macOS.sh first.'
  exit 1
fi
if [[ ! -x ${dotnet_command} || -L ${dotnet_command} ]]; then
  print -u2 "The official .NET SDK host is unavailable or a symbolic link: ${dotnet_command}"
  exit 1
fi
for required_command in xcrun codesign security ditto shasum lipo; do
  command -v ${required_command} >/dev/null 2>&1 || {
    print -u2 "Required release tool is unavailable: ${required_command}"
    exit 1
  }
done

if [[ -z ${identity} ]]; then
  identity=$(security find-identity -v -p codesigning | awk '/Apple Development/{print $2; exit}')
fi
[[ -n ${identity} ]] || {
  print -u2 'No Apple Development code-signing identity was found.'
  exit 1
}

build_root=$(mktemp -d "${TMPDIR:-/tmp}/keep-vault-portable.XXXXXXXX")
cleanup() {
  [[ -n ${build_root:-} && -d ${build_root} ]] && rm -rf -- ${build_root}
}
trap cleanup EXIT INT TERM

# --- Standalone release verifier -------------------------------------------
verifier_slices=()
verifier_runtimes=(osx-arm64)
[[ ${architecture} == universal ]] && verifier_runtimes+=(osx-x64)
for runtime in ${verifier_runtimes[@]}; do
  publish_dir=${build_root}/verifier-${runtime}
  (
    cd ${repo_root}/KeepVaultMac.ReleaseVerifier
    ${dotnet_command} publish ${verifier_project} \
      -c Release \
      -r ${runtime} \
      --self-contained true \
      --nologo \
      -p:PublishAot=true \
      -p:PublishTrimmed=true \
      -p:StripSymbols=true \
      -o ${publish_dir}
  )
  slice=${publish_dir}/Keep\ Vault\ Release\ Verifier
  [[ -f ${slice} && ! -L ${slice} ]] || {
    print -u2 "The NativeAOT verifier was not produced for ${runtime}."
    exit 1
  }
  verifier_slices+=(${slice})
done

verifier_path=${build_root}/Keep\ Vault\ Release\ Verifier
if (( ${#verifier_slices} > 1 )); then
  xcrun lipo -create ${verifier_slices[@]} -output ${verifier_path}
  xcrun lipo ${verifier_path} -verify_arch arm64 x86_64
else
  ditto ${verifier_slices[1]} ${verifier_path}
fi
chmod 0755 ${verifier_path}
codesign \
  --force \
  --sign ${identity} \
  --options runtime \
  --identifier ${bundle_identifier}.releaseverifier \
  ${verifier_path}
codesign --verify --strict ${verifier_path}

# --- Portable folder --------------------------------------------------------
dist_dir=${repo_root}/dist
portable_dir=${dist_dir}/${output_name}
portable_zip=${dist_dir}/${output_name}.zip
for existing in ${portable_dir} ${portable_zip} ${portable_zip}.sha3 ${portable_zip}.skein \
    ${portable_zip}.khsig ${portable_zip}.sha3.khsig ${portable_zip}.skein.khsig; do
  if [[ -e ${existing} || -L ${existing} ]]; then
    print -u2 "Refusing to overwrite an existing portable artifact: ${existing}"
    exit 1
  fi
done

mkdir -p ${portable_dir}
ditto ${source_app} ${portable_dir}/Keep\ Vault.app

# The launcher's dual signature covers the bundle's main executable, whose bytes
# codesign rewrites when it seals the bundle — so it cannot live inside. It sits
# beside the app and is checked at every launch; without it the app refuses to
# start, which makes it part of the portable payload.
for launcher_sidecar_suffix in .sha3 .skein .khsig .sha3.khsig .skein.khsig; do
  launcher_sidecar=${source_app}.launcher${launcher_sidecar_suffix}
  if [[ ! -f ${launcher_sidecar} || -L ${launcher_sidecar} ]]; then
    print -u2 "The launcher self-signature is missing from the source: ${launcher_sidecar:t}"
    exit 1
  fi
  ditto ${launcher_sidecar} ${portable_dir}/Keep\ Vault.app.launcher${launcher_sidecar_suffix}
done
ditto ${verifier_path} ${portable_dir}/Keep\ Vault\ Release\ Verifier

# The QR scanner rides along when it has been built. It is a separate program
# with its own identifier, signature and sandbox, and shares no code with Keep
# Vault — it travels in the same package only because the two are used together
# and should be versioned together.
scanner_app=${repo_root}/QrCodeScanner/dist/QR-Scanner.app
bundled_scanner=0
if [[ -d ${scanner_app} && ! -L ${scanner_app} ]]; then
  ditto ${scanner_app} ${portable_dir}/QR-Scanner.app
  codesign --verify --strict --verbose=2 ${portable_dir}/QR-Scanner.app
  bundled_scanner=1
  print "bundled_scanner=${portable_dir}/QR-Scanner.app"
else
  print -u2 'QR-Scanner.app was not built; the package will contain Keep Vault only.'
fi

props=${mac_project}/Directory.Build.props
read_pin() {
  /usr/bin/sed -n "s|.*<$1>\(.*\)</$1>.*|\1|p" ${props} | head -1
}

cat > ${portable_dir}/PORTABLE_README.txt <<README
Keep Vault Portable (macOS)
===========================

Start:
  Keep Vault.app
  Keep Vault.app.launcher.khsig (plus .sha3/.skein sidecars)

Reading the printed QR codes:
  QR-Scanner.app — a separate, sandboxed program. Keep Vault itself never
  touches the camera and declares no hardware capability at all.

This folder is self-contained for macOS ${architecture} and requires no
installer and no .NET runtime. Keep the app bundle, the verifier, and the
.sha3, .skein and .khsig files together.

Check the download before launching anything:
  "./Keep Vault Release Verifier" "Keep Vault.app"
  "./Keep Vault Release Verifier" "${output_name}.zip"

Every executable carries an Apple code signature bound to the pinned Team ID
below, plus a detached RSA-PSS/SHA-512 and ML-DSA-87 signature. The hash
manifests are signed the same way. Verification requires BOTH signatures: the
classical RSA one and the post-quantum ML-DSA-87 one.

Because macOS reserves Contents/MacOS for executables, the detached manifests
and signatures live in Contents/Resources/HybridSignatures, mirroring the
layout below Contents/MacOS.

Pinned Apple Team ID: ${team_identifier}
Pinned RSA SHA-256(SPKI): $(read_pin KalynaExpectedSignerSha256)
Pinned RSA SHA3-512(SPKI): $(read_pin KalynaExpectedSignerSha3_512)
Pinned RSA Skein-1024(SPKI): $(read_pin KalynaExpectedSignerSkein1024)
Pinned ML-DSA-87 SHA-256: $(read_pin KalynaExpectedMldsa87Sha256)
Pinned ML-DSA-87 SHA3-512: $(read_pin KalynaExpectedMldsa87Sha3_512)
Pinned ML-DSA-87 Skein-1024: $(read_pin KalynaExpectedMldsa87Skein1024)

This build is signed with a local Apple Development identity and is NOT
notarized. Gatekeeper will therefore refuse it on another Mac until it is
signed with a Developer ID Application certificate and notarized by Apple.
The app accepts only its exact compiled pins regardless.

macOS cannot enforce an application-level exclusion from screenshots or screen
recording the way Windows can. Keep Vault conceals secret views when it is
deactivated, but capture prevention cannot be guaranteed on this platform.
README

# The hybrid signer and its scratch keychain are resolved once here: the scanner
# is signed before the archive is built, and the archive is signed after, so both
# steps need them.
signer_dll=${packaging_dir}/HybridSigner/bin/Release/net10.0/KeepVaultMac.HybridSigner.dll
if [[ ! -f ${signer_dll} || -L ${signer_dll} ]]; then
  (
    cd ${mac_project}
    ${dotnet_command} build Packaging/HybridSigner/KeepVaultMac.HybridSigner.csproj -c Release --nologo
  )
fi
keychain_temp=${build_root}/keychain-temp
mkdir -p ${keychain_temp}

# Everything in the package that is executable code gets the same post-quantum
# pair, so no component rests on Apple's signature alone. That includes the
# verifier itself: a tool that vouches for the rest while carrying no signature
# of its own is the obvious thing to replace.
#
# The scanner's sidecars go beside its bundle rather than inside it. Apple's
# seal covers Contents/Resources, so a file added there afterwards would
# invalidate the very signature it sits under -- the same reason the launcher's
# own signature lives outside the bundle.
package_signature_arguments=(
  ${signer_dll}
  sign
  --pfx ${pfx_path}
  ${mldsa_key_arguments[@]}
  ${pfx_password_arguments[@]}
  --mldsa-public-key ${mldsa_public_key}
  --reference-library ${mac_project}/Native/osx-arm64/libmldsa87_ref.dylib
  --policy ${props}
  --launcher-pins ${build_root}/PackageHybridPins.swift
  --target ${portable_dir}/Keep\ Vault\ Release\ Verifier
)
(( bundled_scanner )) && package_signature_arguments+=(--target ${portable_dir}/QR-Scanner.app/Contents/MacOS/QR-Scanner)
if [[ -n ${pfx_password_service} ]]; then
  package_signature_arguments+=(--pfx-password-keychain-service ${pfx_password_service})
  [[ -n ${pfx_password_account} ]] && package_signature_arguments+=(--pfx-keychain-account ${pfx_password_account})
fi
(
  cd ${mac_project}
  TMPDIR=${keychain_temp} \
    KEEPVAULT_KEYCHAIN_TEMP_ROOT=${keychain_temp} \
    DOTNET_EnableDiagnostics=0 \
    ${dotnet_command} ${package_signature_arguments[@]}
)
print "verifier_dual_signature=${portable_dir}/Keep Vault Release Verifier.khsig"

if (( bundled_scanner )); then
  scanner_sidecar_source=${portable_dir}/QR-Scanner.app/Contents/MacOS/QR-Scanner
  for sidecar_suffix in .sha3 .skein .khsig .sha3.khsig .skein.khsig; do
    if [[ ! -f ${scanner_sidecar_source}${sidecar_suffix} ]]; then
      print -u2 "The scanner's dual signature is incomplete: ${sidecar_suffix}"
      exit 1
    fi
    mv -- ${scanner_sidecar_source}${sidecar_suffix} ${portable_dir}/QR-Scanner.app${sidecar_suffix}
  done

  # Moving the sidecars out again leaves the bundle byte-identical to what Apple
  # sealed, which this re-check proves rather than assumes.
  codesign --verify --strict --verbose=2 ${portable_dir}/QR-Scanner.app
  print "scanner_dual_signature=${portable_dir}/QR-Scanner.app.khsig"
fi

# --- Archive, manifests, hybrid signatures ----------------------------------
# Signing the archive also emits its SHA3-512 and Skein-1024 manifests and signs
# those in turn, so all five sidecars appear next to the ZIP.
ditto -c -k --sequesterRsrc --keepParent ${portable_dir} ${portable_zip}

signer_arguments=(
  ${signer_dll}
  sign
  --pfx ${pfx_path}
  ${mldsa_key_arguments[@]}
  ${pfx_password_arguments[@]}
  --mldsa-public-key ${mldsa_public_key}
  --reference-library ${mac_project}/Native/osx-arm64/libmldsa87_ref.dylib
  --policy ${props}
  --launcher-pins ${build_root}/HybridPins.swift
  --target ${portable_zip}
)
if [[ -n ${pfx_password_service} ]]; then
  signer_arguments+=(--pfx-password-keychain-service ${pfx_password_service})
  [[ -n ${pfx_password_account} ]] && signer_arguments+=(--pfx-keychain-account ${pfx_password_account})
fi

(
  cd ${mac_project}
  TMPDIR=${keychain_temp} \
    KEEPVAULT_KEYCHAIN_TEMP_ROOT=${keychain_temp} \
    DOTNET_EnableDiagnostics=0 \
    ${dotnet_command} ${signer_arguments[@]}
)

# --- Final gate -------------------------------------------------------------
# Check the shipped artifacts with the verifier that ships alongside them, so a
# release cannot be published unless its own tool accepts it.
${portable_dir}/Keep\ Vault\ Release\ Verifier ${portable_zip}
${portable_dir}/Keep\ Vault\ Release\ Verifier ${portable_dir}/Keep\ Vault.app
# The whole folder, which is what a user actually points the tool at: it covers
# the scanner and the verifier as well and refuses any executable that has no
# signature.
${portable_dir}/Keep\ Vault\ Release\ Verifier ${portable_dir}

print "portable_folder=${portable_dir}"
print "portable_archive=${portable_zip}"
print "verifier=${portable_dir}/Keep Vault Release Verifier"
print 'notarization=not_performed (Developer ID and notary credentials are a separate release gate)'
