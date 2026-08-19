#!/bin/zsh
# Produces a set of native components that the comprehensive test suite can
# actually execute.
#
# The shipped helpers (zpaq, argon2) are signed with com.apple.security.inherit,
# so they adopt the sandbox of the app that spawns them and the kernel refuses
# to start them under any other parent — including a test runner. That is
# correct production behaviour and is verified separately by
# Verify-KeepVault-macOS.sh, which asserts the shipped entitlements.
#
# For the functional groups the suite therefore uses copies re-signed with the
# same Apple identity and hardened runtime but without the sandbox
# entitlements. Every other trust gate stays fully in force: the Team ID pin,
# the dual SHA3-512/Skein-1024 manifests, and the hybrid RSA-PSS + ML-DSA-87
# signatures are all regenerated for the re-signed bytes.
set -euo pipefail
umask 077

script_dir=${0:A:h}
repo_root=${script_dir:h}
mac_project=${repo_root}/KeepVaultMac
packaging_dir=${mac_project}/Packaging
source_app=${repo_root}/dist/Keep\ Vault-macOS/Keep\ Vault.app
destination=${repo_root}/KeepVaultMac.Tests/bin/Release/net10.0/osx-arm64/Native
identity=${KEEPVAULT_CODESIGN_IDENTITY:-}
pfx_path=${KEEPVAULT_HYBRID_PFX:-${HOME}/Library/Application Support/Keep Vault/ReleaseKeys/hybrid-rsa4096.pfx}
mldsa_private_key=${KEEPVAULT_MLDSA_PRIVATE_KEY:-${HOME}/Library/Application Support/Keep Vault/ReleaseKeys/mldsa87-private.key}
mldsa_private_key_encrypted=${KEEPVAULT_MLDSA_PRIVATE_KEY_ENCRYPTED:-${mldsa_private_key}.enc}
mldsa_keychain_service=${KEEPVAULT_MLDSA_KEYCHAIN_SERVICE:-de.michael-feinermann.keep-vault.hybrid-wrapping-key}
mldsa_keychain_account=${KEEPVAULT_MLDSA_KEYCHAIN_ACCOUNT:-${USER:-}}
pfx_password_encrypted=${KEEPVAULT_PFX_PASSWORD_ENCRYPTED:-${pfx_path}.password.enc}

# Same key handling as the release builds: once both halves are wrapped they are
# released by one Keychain confirmation, and the unwrapped paths remain only as
# a fallback for a tree that has not been migrated. Staging signs the two helper
# executables after re-signing them with codesign, so it needs the keys exactly
# as a release build does -- leaving it on the deleted plaintext path made it
# skip that step and hand the test suite natives whose manifests no longer
# matched.
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

# A wrapping key on removable media lets a build run unattended while that
# volume is mounted; unplug it and signing falls back to the Keychain prompt.
# Physical presence is a weaker gate than the prompt -- anything running as this
# user can read a mounted volume -- but it is bounded by something the key
# holder can see and pull out, and it keeps routine development from being four
# confirmations long.
wrapping_key_file=${KEEPVAULT_WRAPPING_KEY_FILE:-}
if [[ -z ${wrapping_key_file} ]]; then
  for candidate in /Volumes/*/Keep\ Vault\ ReleaseKeys*/wrapping-key.b64(N); do
    [[ -f ${candidate} && ! -L ${candidate} ]] || continue
    wrapping_key_file=${candidate}
    break
  done
fi
if [[ -n ${wrapping_key_file} && -f ${wrapping_key_file} && ! -L ${wrapping_key_file} ]]; then
  mldsa_key_arguments+=(--wrapping-key-file ${wrapping_key_file})
  print "wrapping_key=removable media (${wrapping_key_file:h:t})"
else
  print "wrapping_key=Keychain (confirmation required per signing pass)"
fi
mldsa_public_key=${KEEPVAULT_MLDSA_PUBLIC_KEY:-${packaging_dir}/Keys/mldsa87-public.key}
pfx_password_service=${KEEPVAULT_PFX_KEYCHAIN_SERVICE:-de.michael-feinermann.keep-vault.hybrid-pfx}
pfx_password_account=${KEEPVAULT_PFX_KEYCHAIN_ACCOUNT:-${USER:-}}
dotnet_command=${KEEPVAULT_DOTNET:-/Users/michael/.dotnet-keepvault/dotnet}

usage() {
  print -u2 'Usage: Stage-TestNatives-macOS.sh [--app "Keep Vault.app"] [--destination DIR] [--identity HASH]'
  exit 64
}

while (( $# != 0 )); do
  case $1 in
    --app) (( $# >= 2 )) || usage; source_app=$2; shift 2 ;;
    --destination) (( $# >= 2 )) || usage; destination=$2; shift 2 ;;
    --identity) (( $# >= 2 )) || usage; identity=$2; shift 2 ;;
    *) usage ;;
  esac
done

if [[ ! -d ${source_app} || -L ${source_app} ]]; then
  print -u2 "Signed app bundle not found or is a symbolic link: ${source_app}"
  exit 1
fi
if [[ ! -x ${dotnet_command} || -L ${dotnet_command} ]]; then
  print -u2 "The official .NET SDK host is unavailable or a symbolic link: ${dotnet_command}"
  exit 1
fi

if [[ -z ${identity} ]]; then
  identity=$(security find-identity -v -p codesigning \
    | awk '/Apple Development/{print $2; exit}')
fi
if [[ -z ${identity} ]]; then
  print -u2 'No Apple Development code-signing identity was found.'
  exit 1
fi

source_natives=${source_app}/Contents/MacOS/Native
signature_root=${source_app}/Contents/Resources/HybridSignatures/Native
components=(zpaq argon2 libaes_ref.dylib libargon2_ref.dylib libchachapoly_ref.dylib libkalyna_ref.dylib libmars_ref.dylib libshacal2_ref.dylib libthreefish_ref.dylib)
# Only the two helper executables carry sandbox entitlements and therefore need
# re-signing; the libraries ship without entitlements and keep their release
# signatures and manifests untouched.
resigned=(zpaq argon2)

mkdir -p ${destination}
for component in ${components[@]}; do
  if [[ ! -f ${source_natives}/${component} || -L ${source_natives}/${component} ]]; then
    print -u2 "Signed native component is missing: ${component}"
    exit 1
  fi
  ditto ${source_natives}/${component} ${destination}/${component}
  for suffix in .sha3 .skein .khsig .sha3.khsig .skein.khsig; do
    if [[ ! -f ${signature_root}/${component}${suffix} ]]; then
      print -u2 "Release sidecar is missing: ${component}${suffix}"
      exit 1
    fi
    ditto ${signature_root}/${component}${suffix} ${destination}/${component}${suffix}
  done
done

# The ML-DSA reference adapter is a test oracle only: it is deliberately not
# shipped inside the app, so it comes from the project tree rather than from the
# signed bundle and carries no hybrid sidecars.
mldsa_reference=${mac_project}/Native/osx-arm64/libmldsa87_ref.dylib
if [[ ! -f ${mldsa_reference} || -L ${mldsa_reference} ]]; then
  print -u2 "ML-DSA-87 reference oracle is missing: ${mldsa_reference}"
  exit 1
fi
ditto ${mldsa_reference} ${destination}/libmldsa87_ref.dylib

build_root=$(mktemp -d "${TMPDIR:-/tmp}/keep-vault-test-natives.XXXXXXXX")
cleanup() {
  [[ -n ${build_root:-} && -d ${build_root} ]] && rm -rf -- ${build_root}
}
trap cleanup EXIT INT TERM

signer_dll=${packaging_dir}/HybridSigner/bin/Release/net10.0/KeepVaultMac.HybridSigner.dll
if [[ ! -f ${signer_dll} || -L ${signer_dll} ]]; then
  print -u2 'The hybrid signer has not been built; run Build-KeepVault-macOS.sh first.'
  exit 1
fi

signer_arguments=(
  ${signer_dll}
  sign
  --pfx ${pfx_path}
  ${mldsa_key_arguments[@]}
  ${pfx_password_arguments[@]}
  --mldsa-public-key ${mldsa_public_key}
  --reference-library ${mac_project}/Native/osx-arm64/libmldsa87_ref.dylib
  --policy ${mac_project}/Directory.Build.props
  --launcher-pins ${build_root}/HybridPins.swift
)

for component in ${resigned[@]}; do
  target=${destination}/${component}
  # Same identity and hardened runtime as the release, no entitlements: without
  # com.apple.security.inherit the helper no longer requires a sandboxed parent.
  codesign \
    --force \
    --sign ${identity} \
    --options runtime \
    --identifier de.michael-feinermann.keep-vault.test.${component} \
    ${target}
  if codesign -d --entitlements - ${target} 2>&1 | grep -q 'com.apple.security'; then
    print -u2 "Test component still carries sandbox entitlements: ${component}"
    exit 1
  fi
  chmod 0755 ${target}
  signer_arguments+=(--target ${target})
done

if [[ -n ${pfx_password_service} ]]; then
  signer_arguments+=(--pfx-password-keychain-service ${pfx_password_service})
  [[ -n ${pfx_password_account} ]] && signer_arguments+=(--pfx-keychain-account ${pfx_password_account})
fi

keychain_temp=${build_root}/keychain-temp
mkdir -p ${keychain_temp}
(
  cd ${mac_project}
  TMPDIR=${keychain_temp} \
    KEEPVAULT_KEYCHAIN_TEMP_ROOT=${keychain_temp} \
    DOTNET_EnableDiagnostics=0 \
    ${dotnet_command} ${signer_arguments[@]}
)

# A component killed for a code-signature or sandbox violation dies on SIGTRAP
# (exit 133). Any ordinary usage/exit status means it started, which is all this
# check needs to establish.
for component in ${resigned[@]}; do
  target=${destination}/${component}
  launch_status=0
  ${target} >/dev/null 2>&1 || launch_status=$?
  if (( launch_status == 133 )); then
    print -u2 "Re-signed test component still cannot start standalone: ${component}"
    exit 1
  fi
done

print "test_natives=${destination}"
