#!/bin/zsh
set -euo pipefail
umask 077

script_dir=${0:A:h}
repo_root=${script_dir:h}
mac_project=${repo_root}/KeepVaultMac
packaging_dir=${mac_project}/Packaging
team_identifier='2T6K9PGS55'
bundle_identifier='de.michael-feinermann.keep-vault'
core_identifier='de.michael-feinermann.keep-vault.core'
configuration='Release'
architecture='universal'
marketing_version='5.0.0'
build_version='10'
preflight_only=0
release_mode=0
identity=${KEEPVAULT_CODESIGN_IDENTITY:-}
# Name of an "xcrun notarytool store-credentials" keychain profile. Empty means
# the build stops short of notarization; the secrets never live here.
notary_profile=${KEEPVAULT_NOTARY_PROFILE:-}
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
pfx_password_environment=${KEEPVAULT_PFX_PASSWORD_ENV:-KEEPVAULT_HYBRID_PFX_PASSWORD}
dotnet_command=${KEEPVAULT_DOTNET:-/Users/michael/.dotnet-keepvault/dotnet}
expected_main_lock_sha256='CE79838C19ED716DBB3276EFB75A47510B2BD6B41B4D2B25687166523FF81546'
expected_signer_lock_sha256='B07635B8B5CF158644267CBB99E6483D6F947F37D3B9918B4FF39407EB6BA5EB'

usage() {
  print -u2 'Usage: Build-KeepVault-macOS.sh [--architecture universal|arm64] [--identity HASH_OR_NAME]'
  print -u2 '       [--pfx FILE] [--mldsa-private-key FILE] [--mldsa-public-key FILE]'
  print -u2 '       [--pfx-password-keychain-service NAME] [--pfx-keychain-account NAME]'
  print -u2 '       [--dotnet /path/to/official/dotnet] [--version X.Y.Z] [--build-number N]'
  print -u2 '       [--notary-profile NOTARYTOOL_KEYCHAIN_PROFILE] [--preflight]'
  exit 64
}

while (( $# != 0 )); do
  case $1 in
    --architecture)
      (( $# >= 2 )) || usage
      architecture=$2
      shift 2
      ;;
    --identity)
      (( $# >= 2 )) || usage
      identity=$2
      shift 2
      ;;
    --pfx)
      (( $# >= 2 )) || usage
      pfx_path=$2
      shift 2
      ;;
    --mldsa-private-key)
      (( $# >= 2 )) || usage
      mldsa_private_key=$2
      shift 2
      ;;
    --mldsa-public-key)
      (( $# >= 2 )) || usage
      mldsa_public_key=$2
      shift 2
      ;;
    --pfx-password-keychain-service)
      (( $# >= 2 )) || usage
      pfx_password_service=$2
      shift 2
      ;;
    --pfx-keychain-account)
      (( $# >= 2 )) || usage
      pfx_password_account=$2
      shift 2
      ;;
    --dotnet)
      (( $# >= 2 )) || usage
      dotnet_command=$2
      shift 2
      ;;
    --version)
      (( $# >= 2 )) || usage
      marketing_version=$2
      shift 2
      ;;
    --build-number)
      (( $# >= 2 )) || usage
      build_version=$2
      shift 2
      ;;
    --release)
      release_mode=1
      shift
      ;;
    --notary-profile)
      (( $# >= 2 )) || usage
      notary_profile=$2
      shift 2
      ;;
    --preflight)
      preflight_only=1
      shift
      ;;
    *) usage ;;
  esac
done

if [[ ${architecture} != universal && ${architecture} != arm64 ]]; then
  print -u2 'Only universal or arm64 release architectures are supported.'
  exit 64
fi
if [[ ! ${marketing_version} =~ '^[0-9]+([.][0-9]+){1,2}$' || ! ${build_version} =~ '^[1-9][0-9]*$' ]]; then
  print -u2 'Version values must be numeric (for example 1.0.0 and build 1).'
  exit 64
fi
if [[ -L ${repo_root} || -L ${mac_project} || -L ${packaging_dir} ]]; then
  print -u2 'Refusing to build through a symbolic-link workspace or packaging path.'
  exit 1
fi

for required_command in xcrun codesign security plutil ditto file shasum openssl; do
  if ! command -v ${required_command} >/dev/null 2>&1; then
    print -u2 "Required release tool is unavailable: ${required_command}"
    exit 1
  fi
done

dotnet_command=${dotnet_command:A}
if [[ ! -x ${dotnet_command} || -L ${dotnet_command} ]]; then
  print -u2 "The explicitly selected official .NET SDK host is unavailable or a symbolic link: ${dotnet_command}"
  exit 1
fi
if ! ${dotnet_command} --list-sdks | grep -q '^10[.]0[.]400 '; then
  print -u2 'Keep Vault release builds require the reviewed official .NET SDK 10.0.400.'
  exit 1
fi

if [[ -z ${identity} ]]; then
  identity=$(security find-identity -v -p codesigning \
    | awk '($0 ~ /Developer ID Application:/) { print $2; exit }')
  if [[ -z ${identity} ]]; then
    identity=$(security find-identity -v -p codesigning \
      | awk '($0 ~ /Apple Development:/) { print $2; exit }')
  fi
fi
if [[ -z ${identity} ]]; then
  print -u2 "RELEASE GATE: no Apple code-signing identity for team ${team_identifier} is available."
  exit 2
fi

identity_details=$(security find-identity -v -p codesigning | grep -F -- "${identity}" || true)
if [[ -z ${identity_details} ]]; then
  print -u2 'The selected Apple signing identity is absent.'
  exit 2
fi
identity_label=${identity_details#*\"}
identity_label=${identity_label%%\"*}
certificate_subject=$(security find-certificate -c ${identity_label} -p \
  | openssl x509 -noout -subject -nameopt RFC2253 2>/dev/null || true)
if [[ ${certificate_subject} != *"OU=${team_identifier}"* ]]; then
  print -u2 "The selected Apple signing certificate does not belong to team ${team_identifier}."
  exit 2
fi
timestamp_arguments=(--timestamp=none)
if [[ ${identity_label} == 'Developer ID Application:'* ]]; then
  timestamp_arguments=(--timestamp)
  if [[ -z ${notary_profile} ]]; then
    print -u2 'RELEASE GATE: Developer ID release requires --notary-profile.'
    exit 2
  fi
elif [[ ${identity_label} == 'Apple Development:'* ]]; then
  timestamp_arguments=(--timestamp=none)
  if (( release_mode )); then
    print -u2 'RELEASE GATE: published release requires Developer ID.'
    exit 2
  fi
else
  print -u2 'The selected identity is neither Apple Development nor Developer ID Application.'
  exit 2
fi

if [[ -z ${pfx_path} || -z ${mldsa_private_key} ]]; then
  print -u2 'RELEASE GATE: macOS hybrid-signing private keys are not available.'
  print -u2 'Provide an external RSA-4096/SHA-512 code-signing PFX and ML-DSA-87 private key.'
  print -u2 'Private keys are intentionally never generated in or copied into the repository.'
  exit 2
fi

pfx_path=${pfx_path:A}
mldsa_private_key=${mldsa_private_key:A}
mldsa_private_key_encrypted=${mldsa_private_key_encrypted:A}
mldsa_public_key=${mldsa_public_key:A}
# Once the key has been wrapped the plaintext file is meant to be gone, so the
# gate checks whichever form this tree actually signs with.
mldsa_key_material=${mldsa_private_key}
if [[ ${mldsa_key_arguments[1]} == --mldsa-private-key-encrypted ]]; then
  mldsa_key_material=${mldsa_private_key_encrypted}
fi
for private_path in ${pfx_path} ${mldsa_key_material}; do
  if [[ ${private_path} == ${repo_root}/* ]]; then
    print -u2 "RELEASE GATE: private signing material must remain outside the repository: ${private_path}"
    exit 2
  fi
  if [[ ! -f ${private_path} || -L ${private_path} ]]; then
    print -u2 "Private signing material is missing or a symbolic link: ${private_path}"
    exit 2
  fi
  if [[ $(stat -f %u ${private_path}) != ${EUID} ]]; then
    print -u2 "Private signing material is not owned by the current user: ${private_path}"
    exit 2
  fi
  private_mode=$(( 8#$(stat -f %Lp ${private_path}) ))
  if (( (private_mode & 8#077) != 0 )); then
    print -u2 "Private signing material must be mode 0600 or stricter: ${private_path}"
    exit 2
  fi
  private_parent=${private_path:h}
  if [[ ! -d ${private_parent} || -L ${private_parent} || $(stat -f %u ${private_parent}) != ${EUID} ]]; then
    print -u2 "Private signing directory is unsafe: ${private_parent}"
    exit 2
  fi
  private_parent_mode=$(( 8#$(stat -f %Lp ${private_parent}) ))
  if (( (private_parent_mode & 8#077) != 0 )); then
    print -u2 "Private signing directory must be mode 0700 or stricter: ${private_parent}"
    exit 2
  fi
done
if [[ ! -f ${mldsa_public_key} || -L ${mldsa_public_key} ]]; then
  print -u2 "Pinned ML-DSA-87 public key is missing or a symbolic link: ${mldsa_public_key}"
  exit 2
fi
if [[ -z ${pfx_password_service} && -z ${(P)pfx_password_environment:-} ]]; then
  print -u2 "RELEASE GATE: store the PFX password in macOS Keychain or set ${pfx_password_environment}."
  exit 2
fi

main_lock=${mac_project}/packages.lock.json
signer_lock=${packaging_dir}/HybridSigner/packages.lock.json
for lock_file expected_lock_hash in \
  ${main_lock} ${expected_main_lock_sha256} \
  ${signer_lock} ${expected_signer_lock_sha256}; do
  if [[ ! -f ${lock_file} || -L ${lock_file} ]]; then
    print -u2 "RELEASE GATE: reviewed NuGet lockfile is missing or a symbolic link: ${lock_file}"
    exit 2
  fi
  actual_lock_hash=$(shasum -a 256 ${lock_file} | awk '{print toupper($1)}')
  if [[ ${actual_lock_hash} != ${expected_lock_hash} ]]; then
    print -u2 "RELEASE GATE: reviewed NuGet lockfile digest changed: ${lock_file}"
    exit 2
  fi
done

if (( preflight_only )); then
  print "preflight=passed"
  print "identity=${identity}"
  print "architecture=${architecture}"
  exit 0
fi

(
  cd ${mac_project}
  ${dotnet_command} restore KeepVaultMac.csproj --locked-mode --nologo
  ${dotnet_command} restore Packaging/HybridSigner/KeepVaultMac.HybridSigner.csproj --locked-mode --nologo
)

build_root=$(mktemp -d "${TMPDIR:-/tmp}/keep-vault-release.XXXXXXXX")
chmod 0700 ${build_root}
cleanup() {
  if [[ -n ${build_root:-} && -d ${build_root} && ${build_root} == */keep-vault-release.* ]]; then
    rm -rf -- ${build_root}
  fi
}
trap cleanup EXIT INT TERM

hybrid_keychain_tmp=${build_root}/hybrid-keychain-tmp
mkdir -m 0700 ${hybrid_keychain_tmp}
keychain_inventory_counter=0
run_hybrid_signer() {
  local before_inventory=${build_root}/keychains-before-${keychain_inventory_counter}.txt
  local after_inventory=${build_root}/keychains-after-${keychain_inventory_counter}.txt
  local new_keychain_paths=${build_root}/keychains-new-${keychain_inventory_counter}.txt
  (( keychain_inventory_counter += 1 ))
  if find ${hybrid_keychain_tmp} -mindepth 1 -print -quit | grep -q .; then
    print -u2 'RELEASE GATE: the isolated temporary-keychain directory was not empty before PFX loading.'
    return 2
  fi
  if [[ -d ${HOME}/Library/Keychains && ! -L ${HOME}/Library/Keychains ]]; then
    find -x ${HOME}/Library/Keychains -print | LC_ALL=C sort > ${before_inventory}
  else
    : > ${before_inventory}
  fi

  local signer_status=0
  TMPDIR=${hybrid_keychain_tmp} \
    KEEPVAULT_KEYCHAIN_TEMP_ROOT=${hybrid_keychain_tmp} \
    DOTNET_EnableDiagnostics=0 \
    ${dotnet_command} "$@" || signer_status=$?

  if [[ -d ${HOME}/Library/Keychains && ! -L ${HOME}/Library/Keychains ]]; then
    find -x ${HOME}/Library/Keychains -print | LC_ALL=C sort > ${after_inventory}
  else
    : > ${after_inventory}
  fi
  comm -13 ${before_inventory} ${after_inventory} > ${new_keychain_paths}
  if find ${hybrid_keychain_tmp} -mindepth 1 -print -quit | grep -q . \
      || [[ -s ${new_keychain_paths} ]]; then
    print -u2 'RELEASE GATE: macOS PFX loading left a temporary keychain object behind.'
    [[ ! -s ${new_keychain_paths} ]] || sed 's/^/  /' ${new_keychain_paths} >&2
    return 2
  fi
  return ${signer_status}
}

${script_dir}/Build-Native-macOS.sh

publish_runtime() {
  local runtime=$1
  local output=$2
  (
    cd ${mac_project}
    ${dotnet_command} publish KeepVaultMac.csproj \
      -c ${configuration} \
      -r ${runtime} \
      --no-restore \
      --self-contained true \
      --nologo \
      -p:PublishAot=true \
      -p:PublishTrimmed=true \
      -p:StripSymbols=true \
      -o ${output}
  )
}

arm_publish=${build_root}/publish-arm64
publish_runtime osx-arm64 ${arm_publish}
merged_publish=${build_root}/publish-merged
ditto ${arm_publish} ${merged_publish}

if [[ ${architecture} == universal ]]; then
  x64_publish=${build_root}/publish-x64
  publish_runtime osx-x64 ${x64_publish}
  while IFS= read -r -d '' arm_file; do
    relative=${arm_file#${arm_publish}/}
    [[ ${relative} == Native/* ]] && continue
    # Debug-symbol bundles are architecture-specific by construction (the
    # relocation directory is named after the slice, aarch64 versus x86_64),
    # so they have no cross-architecture counterpart. They are stripped from
    # the staged bundle below and never ship, so skip them here.
    [[ ${relative} == *.dSYM/* ]] && continue
    x64_file=${x64_publish}/${relative}
    merged_file=${merged_publish}/${relative}
    if [[ ! -f ${x64_file} || -L ${x64_file} ]]; then
      print -u2 "Universal publish counterpart is missing: ${relative}"
      exit 1
    fi
    if file -b ${arm_file} | grep -q 'Mach-O'; then
      if ! file -b ${x64_file} | grep -q 'Mach-O'; then
        print -u2 "Universal publish architecture mismatch: ${relative}"
        exit 1
      fi
      arm_architectures=$(xcrun lipo ${arm_file} -archs)
      x64_architectures=$(xcrun lipo ${x64_file} -archs)
      [[ " ${arm_architectures} " == *' arm64 '* ]] || {
        print -u2 "The arm64 publish lacks an arm64 Mach-O slice: ${relative}"
        exit 1
      }
      [[ " ${x64_architectures} " == *' x86_64 '* ]] || {
        print -u2 "The x86_64 publish lacks an x86_64 Mach-O slice: ${relative}"
        exit 1
      }
      arm_slice=${build_root}/universal-arm64-slice
      x64_slice=${build_root}/universal-x86_64-slice
      if [[ ${arm_architectures} == arm64 ]]; then
        ditto ${arm_file} ${arm_slice}
      else
        xcrun lipo ${arm_file} -thin arm64 -output ${arm_slice}
      fi
      if [[ ${x64_architectures} == x86_64 ]]; then
        ditto ${x64_file} ${x64_slice}
      else
        xcrun lipo ${x64_file} -thin x86_64 -output ${x64_slice}
      fi
      xcrun lipo -create ${arm_slice} ${x64_slice} -output ${merged_file}
      chmod $(stat -f %Lp ${arm_file}) ${merged_file}
      xcrun lipo ${merged_file} -verify_arch arm64 x86_64
      rm -- ${arm_slice} ${x64_slice}
    elif ! cmp -s ${arm_file} ${x64_file}; then
      print -u2 "Non-Mach-O publish outputs differ between architectures: ${relative}"
      exit 1
    fi
  done < <(find ${arm_publish} -type f -print0)
  while IFS= read -r -d '' x64_file; do
    relative=${x64_file#${x64_publish}/}
    [[ ${relative} == Native/* ]] && continue
    [[ ${relative} == *.dSYM/* ]] && continue
    [[ -f ${arm_publish}/${relative} ]] || {
      print -u2 "Unexpected x86_64-only publish output: ${relative}"
      exit 1
    }
  done < <(find ${x64_publish} -type f -print0)
else
  while IFS= read -r -d '' merged_file; do
    [[ ${merged_file#${merged_publish}/} == Native/* ]] && continue
    [[ ${merged_file#${merged_publish}/} == *.dSYM/* ]] && continue
    file -b ${merged_file} | grep -q 'Mach-O' || continue
    published_architectures=$(xcrun lipo ${merged_file} -archs)
    [[ " ${published_architectures} " == *' arm64 '* ]] || {
      print -u2 "The arm64 publish contains a Mach-O without an arm64 slice: ${merged_file#${merged_publish}/}"
      exit 1
    }
    if [[ ${published_architectures} != arm64 ]]; then
      thinned_file=${build_root}/arm64-publish-slice
      xcrun lipo ${merged_file} -thin arm64 -output ${thinned_file}
      chmod $(stat -f %Lp ${merged_file}) ${thinned_file}
      mv ${thinned_file} ${merged_file}
      xcrun lipo ${merged_file} -verify_arch arm64
    fi
  done < <(find ${merged_publish} -type f -print0)
fi

# Debug symbols must not ship inside the signed bundle: they would add
# unsigned Mach-O payload under Contents/MacOS and hand a reverse engineer a
# full symbol map of the security core. Move them next to the release instead.
symbols_dir=${build_root}/symbols
mkdir -p ${symbols_dir}
while IFS= read -r -d '' dsym_path; do
  [[ ${dsym_path} == ${merged_publish}/* ]] || continue
  ditto ${dsym_path} ${symbols_dir}/${dsym_path:t}
  rm -rf -- ${dsym_path}
done < <(find ${merged_publish} -type d -name '*.dSYM' -print0)
if find ${merged_publish} -name '*.dSYM' -print -quit | grep -q .; then
  print -u2 'Debug-symbol bundles survived removal from the staged payload.'
  exit 1
fi

native_dir=${merged_publish}/Native
if [[ -d ${native_dir} && ${native_dir} == ${build_root}/* ]]; then
  rm -rf -- ${native_dir}
fi
mkdir -p ${native_dir}
native_source=${repo_root}/KeepVaultMac/Native/$([[ ${architecture} == universal ]] && print osx-universal || print osx-arm64)
for native_name in zpaq argon2 libaes_ref.dylib libargon2_ref.dylib libchachapoly_ref.dylib libkalyna_ref.dylib libmars_ref.dylib libshacal2_ref.dylib libthreefish_ref.dylib; do
  ditto ${native_source}/${native_name} ${native_dir}/${native_name}
done

core_path=${merged_publish}/Keep\ Vault
if [[ ! -f ${core_path} || -L ${core_path} ]]; then
  print -u2 "NativeAOT core was not produced: ${core_path}"
  exit 1
fi

app_stage=${build_root}/Keep\ Vault.app
contents=${app_stage}/Contents
macos_dir=${contents}/MacOS
resources_dir=${contents}/Resources
mkdir -p ${macos_dir} ${resources_dir}
ditto ${merged_publish} ${macos_dir}

sed \
  -e "s/@@MARKETING_VERSION@@/${marketing_version}/g" \
  -e "s/@@BUILD_VERSION@@/${build_version}/g" \
  ${packaging_dir}/Info.plist.template > ${contents}/Info.plist
plutil -lint ${contents}/Info.plist

icon_work=${build_root}/icon
iconset=${icon_work}/KeepVault.iconset
mkdir -p ${iconset}
xcrun swift ${packaging_dir}/GenerateIcon.swift ${icon_work}/KeepVault-1024.png
for icon_size in 16 32 128 256 512; do
  sips -z ${icon_size} ${icon_size} ${icon_work}/KeepVault-1024.png --out ${iconset}/icon_${icon_size}x${icon_size}.png >/dev/null
  double_size=$(( icon_size * 2 ))
  sips -z ${double_size} ${double_size} ${icon_work}/KeepVault-1024.png --out ${iconset}/icon_${icon_size}x${icon_size}@2x.png >/dev/null
done
iconutil -c icns ${iconset} -o ${resources_dir}/KeepVault.icns

sign_macho() {
  local macho_path=$1
  local identifier_value=$2
  local entitlements=${3:-}
  local arguments=(--force --sign ${identity} --options runtime ${timestamp_arguments[@]} --identifier ${identifier_value})
  if [[ -n ${entitlements} ]]; then
    arguments+=(--entitlements ${entitlements})
  fi
  codesign ${arguments[@]} ${macho_path}
}

while IFS= read -r -d '' candidate; do
  [[ ${candidate} == ${macos_dir}/Keep\ Vault ]] && continue
  if file -b ${candidate} | grep -q 'Mach-O'; then
    relative=${candidate#${macos_dir}/}
    helper_id=${bundle_identifier}.component.$(print -n ${relative} | shasum -a 256 | awk '{print substr($1,1,16)}')
    if [[ ${candidate:t} == zpaq || ${candidate:t} == argon2 ]]; then
      sign_macho ${candidate} ${helper_id} ${packaging_dir}/Helper.entitlements
    else
      sign_macho ${candidate} ${helper_id}
    fi
  fi
done < <(find ${macos_dir} -type f -print0)
sign_macho ${macos_dir}/Keep\ Vault ${core_identifier} ${packaging_dir}/KeepVault.entitlements

launcher_architectures=(arm64)
[[ ${architecture} == universal ]] && launcher_architectures+=(x86_64)

signer_project=${packaging_dir}/HybridSigner/KeepVaultMac.HybridSigner.csproj
(
  cd ${mac_project}
  ${dotnet_command} build Packaging/HybridSigner/KeepVaultMac.HybridSigner.csproj -c Release --no-restore --nologo
)
signer_dll=${packaging_dir}/HybridSigner/bin/Release/net10.0/KeepVaultMac.HybridSigner.dll
if [[ ! -f ${signer_dll} || -L ${signer_dll} ]]; then
  print -u2 'The reviewed hybrid signer did not produce its managed entry assembly.'
  exit 1
fi

signer_arguments=(
  ${signer_dll}
  sign
  --pfx ${pfx_path}
  ${mldsa_key_arguments[@]}
  ${pfx_password_arguments[@]}
  --mldsa-public-key ${mldsa_public_key}
  --reference-library ${repo_root}/KeepVaultMac/Native/$([[ ${architecture} == universal ]] && print osx-universal || print osx-arm64)/libmldsa87_ref.dylib
  --policy ${mac_project}/Directory.Build.props
  --launcher-pins ${build_root}/HybridPins.swift
)

# Every Mach-O below Contents/MacOS gets a hybrid signature, enumerated from the
# bundle rather than listed by hand. A hand-written list only covers what
# somebody remembered to add: the three Avalonia and Skia libraries were signed
# by Apple in the loop above and then left out here, so they ran inside the
# process that holds the archive keys protected by Apple's signature alone --
# exactly the layer the post-quantum pair exists to stop relying on.
#
# The supervisor and the launcher are skipped here because each gets its own
# later pass: the supervisor after its cdhash pin is generated, and the launcher
# because it carries the bundle seal and its signature has to live outside the
# bundle. Neither is compiled into the bundle yet at this point; the guard is
# there so reordering the build cannot silently sign them twice.
hybrid_target_count=0
while IFS= read -r -d '' hybrid_candidate; do
  [[ ${hybrid_candidate:t} == 'Keep Vault Supervisor' || ${hybrid_candidate:t} == 'Keep Vault Launcher' ]] && continue
  file -b ${hybrid_candidate} | grep -q 'Mach-O' || continue
  signer_arguments+=(--target ${hybrid_candidate})
  (( hybrid_target_count += 1 ))
done < <(find ${macos_dir} -type f -print0 | sort -z)
if (( hybrid_target_count < 10 )); then
  print -u2 "Too few Mach-O hybrid-signing targets were found: ${hybrid_target_count}"
  exit 1
fi
if [[ -n ${pfx_password_service} ]]; then
  signer_arguments+=(--pfx-password-keychain-service ${pfx_password_service})
  [[ -n ${pfx_password_account} ]] && signer_arguments+=(--pfx-keychain-account ${pfx_password_account})
else
  signer_arguments+=(--pfx-password-env ${pfx_password_environment})
fi
(
  cd ${mac_project}
  run_hybrid_signer ${signer_arguments[@]}
)

generate_cdhash_pins() {
  local signed_binary=$1
  local output_source=$2
  local enum_name=$3
  shift 3
  local temporary_source=${output_source}.tmp
  : > ${temporary_source}
  print -r -- '// Generated by Build-KeepVault-macOS.sh. Do not edit.' >> ${temporary_source}
  print -r -- "enum ${enum_name} {" >> ${temporary_source}
  print -r -- '    static let cdHashes = [' >> ${temporary_source}
  local requested_architecture signature_output cdhash
  for requested_architecture in "$@"; do
    signature_output=$(codesign -dvvv --arch ${requested_architecture} ${signed_binary} 2>&1)
    cdhash=$(print -r -- ${signature_output} | awk -F= '/^CDHash=/{print $2; exit}')
    if [[ ! ${cdhash} =~ '^[0-9A-Fa-f]{40}$' ]]; then
      print -u2 "Unable to derive the signed ${requested_architecture} CDHash: ${signed_binary}"
      return 1
    fi
    print -r -- "        \"${cdhash:u}\"," >> ${temporary_source}
  done
  print -r -- '    ]' >> ${temporary_source}
  print -r -- '}' >> ${temporary_source}
  mv ${temporary_source} ${output_source}
}

core_apple_pins=${build_root}/CoreApplePins.swift
generate_cdhash_pins \
  ${macos_dir}/Keep\ Vault \
  ${core_apple_pins} \
  KeepVaultCoreApplePins \
  ${launcher_architectures[@]}

supervisor_thin=()
for supervisor_arch in ${launcher_architectures[@]}; do
  thin_supervisor=${build_root}/Keep\ Vault\ Supervisor-${supervisor_arch}
  xcrun swiftc \
    -target ${supervisor_arch}-apple-macos14.0 \
    -O -whole-module-optimization -parse-as-library \
    ${packaging_dir}/Supervisor.swift ${core_apple_pins} \
    -framework Foundation -framework Security \
    -o ${thin_supervisor}
  supervisor_thin+=(${thin_supervisor})
done

supervisor_path=${macos_dir}/Keep\ Vault\ Supervisor
if [[ ${architecture} == universal ]]; then
  xcrun lipo -create ${supervisor_thin[@]} -output ${supervisor_path}
  xcrun lipo ${supervisor_path} -verify_arch arm64 x86_64
else
  ditto ${supervisor_thin[1]} ${supervisor_path}
fi
chmod 0755 ${supervisor_path}
sign_macho ${supervisor_path} ${bundle_identifier}.supervisor ${packaging_dir}/Helper.entitlements

# The supervisor embeds the signed core's pins, so it cannot exist before the
# first hybrid pass and gets its own. It is checked against the same
# post-quantum pair as the core: its Apple signature and its cdhash pin are both
# anchored in RSA and ECDSA, and resting one process on that alone would
# undercut the assumption the whole chain is built on.
supervisor_signature_arguments=(
  ${signer_dll}
  sign
  --pfx ${pfx_path}
  ${mldsa_key_arguments[@]}
  ${pfx_password_arguments[@]}
  --mldsa-public-key ${mldsa_public_key}
  --reference-library ${repo_root}/KeepVaultMac/Native/$([[ ${architecture} == universal ]] && print osx-universal || print osx-arm64)/libmldsa87_ref.dylib
  --policy ${mac_project}/Directory.Build.props
  --launcher-pins ${build_root}/SupervisorHybridPins.swift
  --target ${supervisor_path}
)
if [[ -n ${pfx_password_service} ]]; then
  supervisor_signature_arguments+=(--pfx-password-keychain-service ${pfx_password_service})
  [[ -n ${pfx_password_account} ]] && supervisor_signature_arguments+=(--pfx-keychain-account ${pfx_password_account})
else
  supervisor_signature_arguments+=(--pfx-password-env ${pfx_password_environment})
fi
(
  cd ${mac_project}
  run_hybrid_signer ${supervisor_signature_arguments[@]}
)

supervisor_apple_pins=${build_root}/SupervisorApplePins.swift
generate_cdhash_pins \
  ${supervisor_path} \
  ${supervisor_apple_pins} \
  KeepVaultSupervisorApplePins \
  ${launcher_architectures[@]}

launcher_sources=(
  ${repo_root}/native/mldsa87_ref_export.c
  ${repo_root}/external/ML-DSA-reference/ref/sign.c
  ${repo_root}/external/ML-DSA-reference/ref/packing.c
  ${repo_root}/external/ML-DSA-reference/ref/polyvec.c
  ${repo_root}/external/ML-DSA-reference/ref/poly.c
  ${repo_root}/external/ML-DSA-reference/ref/ntt.c
  ${repo_root}/external/ML-DSA-reference/ref/reduce.c
  ${repo_root}/external/ML-DSA-reference/ref/rounding.c
  ${repo_root}/external/ML-DSA-reference/ref/symmetric-shake.c
  ${repo_root}/external/ML-DSA-reference/ref/fips202.c
)
launcher_thin=()
for launcher_arch in ${launcher_architectures[@]}; do
  object_dir=${build_root}/launcher-objects-${launcher_arch}
  mkdir -p ${object_dir}
  object_files=()
  object_index=0
  for launcher_source in ${launcher_sources[@]}; do
    object_path=${object_dir}/${object_index}.o
    xcrun clang \
      -arch ${launcher_arch} \
      -mmacosx-version-min=14.0 \
      -O2 -DNDEBUG -DDILITHIUM_MODE=5 \
      -fstack-protector-strong -fvisibility=hidden -fno-common \
      -I${repo_root}/external/ML-DSA-reference/ref \
      -c ${launcher_source} -o ${object_path}
    object_files+=(${object_path})
    (( object_index += 1 ))
  done
  # The rollback floor the launcher enforces against the machine-wide anchor.
  launcher_version_source=${build_root}/KeepVaultBuildVersion.swift
  print "enum KeepVaultBuild { static let version: UInt64 = ${build_version} }" > ${launcher_version_source}
  thin_launcher=${build_root}/Keep\ Vault\ Launcher-${launcher_arch}
  xcrun swiftc \
    -target ${launcher_arch}-apple-macos14.0 \
    -O -whole-module-optimization -parse-as-library \
    ${packaging_dir}/Launcher.swift ${build_root}/HybridPins.swift ${supervisor_apple_pins} \
    ${launcher_version_source} \
    ${object_files[@]} \
    -framework AppKit -framework Security \
    -o ${thin_launcher}
  launcher_thin+=(${thin_launcher})
done

launcher_path=${macos_dir}/Keep\ Vault\ Launcher
if [[ ${architecture} == universal ]]; then
  xcrun lipo -create ${launcher_thin[@]} -output ${launcher_path}
  xcrun lipo ${launcher_path} -verify_arch arm64 x86_64
else
  ditto ${launcher_thin[1]} ${launcher_path}
fi
chmod 0755 ${launcher_path}

# Apple's bundle format reserves Contents/MacOS for Mach-O executables. The
# detached hash and hybrid-signature sidecars written next to each binary above
# are not code, and codesign refuses to seal a bundle that carries them there.
# Relocate them under Contents/Resources, mirroring the layout below
# Contents/MacOS, which also brings them under the bundle's CodeResources seal.
# This must precede signing the launcher: codesign resolves the path of a
# bundle's main executable to the enclosing bundle, so that step already seals
# the whole app.
signature_dir=${resources_dir}/HybridSignatures
mkdir -p ${signature_dir}
relocated_sidecars=0
while IFS= read -r -d '' sidecar_path; do
  relative=${sidecar_path#${macos_dir}/}
  destination=${signature_dir}/${relative}
  mkdir -p ${destination:h}
  mv -- ${sidecar_path} ${destination}
  relocated_sidecars=$(( relocated_sidecars + 1 ))
done < <(find ${macos_dir} -type f \( -name '*.sha3' -o -name '*.skein' -o -name '*.khsig' \) -print0)
if (( relocated_sidecars == 0 )); then
  print -u2 'No hybrid-signature sidecars were found to relocate; the signing chain is incomplete.'
  exit 1
fi
if find ${macos_dir} -type f \( -name '*.sha3' -o -name '*.skein' -o -name '*.khsig' \) -print -quit | grep -q .; then
  print -u2 'Hybrid-signature sidecars survived relocation out of Contents/MacOS.'
  exit 1
fi
print "relocated_sidecars=${relocated_sidecars}"

sign_macho ${launcher_path} ${bundle_identifier}.launcher ${packaging_dir}/Launcher.entitlements

codesign \
  --force \
  --sign ${identity} \
  --options runtime \
  ${timestamp_arguments[@]} \
  --entitlements ${packaging_dir}/Launcher.entitlements \
  --identifier ${bundle_identifier} \
  ${app_stage}

${script_dir}/Verify-KeepVault-macOS.sh \
  --app ${app_stage} \
  --allow-development \
  --mldsa-public-key ${mldsa_public_key}

dist_dir=${repo_root}/dist/Keep\ Vault-macOS
mkdir -p ${dist_dir}

# Keep build output out of Spotlight. Without this the release copy, the
# portable copy and the installed app all answer to a search for "Keep Vault",
# and the user is left guessing which of them they are about to open.
dist_stage=${build_root}/dist-stage
mkdir -p ${dist_stage}

final_app=${dist_stage}/Keep\ Vault.app
final_zip=${dist_stage}/Keep\ Vault-macOS-${architecture}.zip

ditto ${app_stage} ${final_app}

# The launcher is the bundle's main executable, so codesign writes the bundle
# seal into that very file. A hybrid signature over its own bytes therefore
# cannot live inside the bundle: adding it would change the seal and invalidate
# itself. It is signed now, once the bytes are final, and placed beside the app
# — which is also what gets published, so the one component that was covered by
# Apple's signature alone now carries the dual signature too.
launcher_signature_common=(
  ${signer_dll}
  sign
  --pfx ${pfx_path}
  ${mldsa_key_arguments[@]}
  ${pfx_password_arguments[@]}
  --mldsa-public-key ${mldsa_public_key}
  --reference-library ${repo_root}/KeepVaultMac/Native/$([[ ${architecture} == universal ]] && print osx-universal || print osx-arm64)/libmldsa87_ref.dylib
  --policy ${mac_project}/Directory.Build.props
  --launcher-pins ${build_root}/SelfHybridPins.swift
  --target ${final_app}/Contents/MacOS/Keep\ Vault\ Launcher
)
if [[ -n ${pfx_password_service} ]]; then
  launcher_signature_common+=(--pfx-password-keychain-service ${pfx_password_service})
  [[ -n ${pfx_password_account} ]] && launcher_signature_common+=(--pfx-keychain-account ${pfx_password_account})
else
  launcher_signature_common+=(--pfx-password-env ${pfx_password_environment})
fi
(
  cd ${mac_project}
  run_hybrid_signer ${launcher_signature_common[@]}
)

# Move the launcher's sidecars out of the bundle and beside it, under the app's
# own name, which is where the launcher looks for them at startup.
launcher_sidecar_source=${final_app}/Contents/MacOS/Keep\ Vault\ Launcher
for sidecar_suffix in .sha3 .skein .khsig .sha3.khsig .skein.khsig; do
  if [[ ! -f ${launcher_sidecar_source}${sidecar_suffix} ]]; then
    print -u2 "The launcher self-signature is incomplete: ${sidecar_suffix}"
    exit 1
  fi
  mv -- ${launcher_sidecar_source}${sidecar_suffix} ${final_app}.launcher${sidecar_suffix}
done
print "launcher_self_signature=${final_app}.launcher.khsig"
final_symbols=${dist_stage}/Keep\ Vault-macOS-${architecture}.dSYMs
rm -rf -- ${final_symbols}
ditto ${symbols_dir} ${final_symbols}

# The launcher will not start without its own dual signature, so the sidecars
# have to be inside the distribution archive as well. Archiving the contents of
# a staging directory (rather than --keepParent on the bundle) keeps the app at
# the archive root and puts the sidecars beside it, exactly as installed.
zip_stage=${build_root}/zip-stage
rm -rf -- ${zip_stage}
mkdir -p ${zip_stage}
ditto ${final_app} ${zip_stage}/Keep\ Vault.app
for sidecar_suffix in .sha3 .skein .khsig .sha3.khsig .skein.khsig; do
  ditto ${final_app}.launcher${sidecar_suffix} ${zip_stage}/Keep\ Vault.app.launcher${sidecar_suffix}
done
ditto -c -k --sequesterRsrc ${zip_stage} ${final_zip}

archive_common=(
  ${signer_dll}
  sign
  --pfx ${pfx_path}
  ${mldsa_key_arguments[@]}
  ${pfx_password_arguments[@]}
  --mldsa-public-key ${mldsa_public_key}
  --reference-library ${repo_root}/KeepVaultMac/Native/$([[ ${architecture} == universal ]] && print osx-universal || print osx-arm64)/libmldsa87_ref.dylib
  --policy ${mac_project}/Directory.Build.props
  --launcher-pins ${build_root}/ArchiveHybridPins.swift
  --target ${final_zip}
)
if [[ -n ${pfx_password_service} ]]; then
  archive_common+=(--pfx-password-keychain-service ${pfx_password_service})
  [[ -n ${pfx_password_account} ]] && archive_common+=(--pfx-keychain-account ${pfx_password_account})
else
  archive_common+=(--pfx-password-env ${pfx_password_environment})
fi
(
  cd ${mac_project}
  run_hybrid_signer ${archive_common[@]}
)

archive_check=${build_root}/archive-check
mkdir -p ${archive_check}
ditto -x -k ${final_zip} ${archive_check}
if [[ ! -d ${archive_check}/Keep\ Vault.app || -L ${archive_check}/Keep\ Vault.app ]]; then
  print -u2 'The distribution archive did not reproduce the Keep Vault app bundle.'
  exit 1
fi
${script_dir}/Verify-KeepVault-macOS.sh \
  --app ${archive_check}/Keep\ Vault.app \
  --allow-development \
  --require-launcher-signature \
  --mldsa-public-key ${mldsa_public_key}

${script_dir}/Verify-KeepVault-macOS.sh \
  --app ${final_app} \
  --allow-development \
  --require-launcher-signature \
  --mldsa-public-key ${mldsa_public_key}

print 'RELEASE GATE: running native slice KATs across architectures...'
native_kats_source=${packaging_dir}/NativeKats.c
native_kats_arm64=${build_root}/native-kats-arm64
xcrun clang -arch arm64 -O2 ${native_kats_source} -o ${native_kats_arm64}
${native_kats_arm64} ${repo_root}/KeepVaultMac/Native/osx-arm64

if [[ ${architecture} == universal ]]; then
  native_kats_x64=${build_root}/native-kats-x64
  xcrun clang -arch x86_64 -O2 ${native_kats_source} -o ${native_kats_x64}
  arch -x86_64 ${native_kats_x64} ${repo_root}/KeepVaultMac/Native/osx-x64
fi

print 'RELEASE GATE: staging test natives and running comprehensive tests + key-sheet render verification...'
${script_dir}/Stage-TestNatives-macOS.sh \
  --app ${final_app} \
  --identity ${identity}
(
  cd ${repo_root}
  ${dotnet_command} run --project KeepVaultMac.Tests/KeepVaultMac.Tests.csproj -c Release -- --full
  test_sheet_dir=$(mktemp -d "${TMPDIR:-/tmp}/keep-vault-test-sheets.XXXXXX")
  ${dotnet_command} run --project KeepVaultMac.Tests/KeepVaultMac.Tests.csproj -c Release -- --dump-key-sheets "${test_sheet_dir}"
  rm -rf -- "${test_sheet_dir}"
)

# Notarization. Apple must see the build before Gatekeeper will accept it on
# another Mac. Credentials are never passed on the command line or stored in
# this repository: create a keychain profile once with
#
#     xcrun notarytool store-credentials "Keep Vault" \
#       --apple-id <your-apple-id> --team-id <your-team-id> \
#       --password <app-specific-password>
#
# and then pass --notary-profile "Keep Vault". The profile name is all this
# script ever sees; the secrets stay in the login keychain.
if [[ -z ${notary_profile} ]]; then
  print 'notarization=not_performed (pass --notary-profile NAME once a Developer ID certificate and a notarytool profile exist)'
else
  if [[ ${identity_details} != *'Developer ID Application'* ]]; then
    print -u2 'Notarization requires a Developer ID Application identity; an Apple Development certificate is rejected by the notary service.'
    exit 1
  fi

  xcrun notarytool submit ${final_zip} --keychain-profile ${notary_profile} --wait
  xcrun stapler staple ${final_app}
  xcrun stapler validate ${final_app}

  # The stapled ticket changes the bundle, so the distribution archive and its
  # signed manifests have to be rebuilt from the stapled app including all 5 launcher sidecars.
  rm -f -- ${final_zip} ${final_zip}.sha3 ${final_zip}.skein \
    ${final_zip}.khsig ${final_zip}.sha3.khsig ${final_zip}.skein.khsig
  rm -rf -- ${zip_stage}
  mkdir -p ${zip_stage}
  ditto ${final_app} ${zip_stage}/Keep\ Vault.app
  for sidecar_suffix in .sha3 .skein .khsig .sha3.khsig .skein.khsig; do
    ditto ${final_app}.launcher${sidecar_suffix} ${zip_stage}/Keep\ Vault.app.launcher${sidecar_suffix}
  done
  ditto -c -k --sequesterRsrc ${zip_stage} ${final_zip}
  (
    cd ${mac_project}
    run_hybrid_signer ${archive_common[@]}
  )

  # Re-verify the unzipped post-notarization bundle
  rm -rf -- ${archive_check}
  mkdir -p ${archive_check}
  ditto -x -k ${final_zip} ${archive_check}
  ${script_dir}/Verify-KeepVault-macOS.sh \
    --app ${archive_check}/Keep\ Vault.app \
    --require-launcher-signature \
    --require-notarization \
    --mldsa-public-key ${mldsa_public_key}

  spctl --assess --type execute -vv ${final_app}
  print "notarization=stapled (${notary_profile})"
fi

# ATOMIC PUBLISH: Only official, Developer-ID-signed and notarized release artifacts
# land in dist/. Development and local builds land in build/dev/ to avoid accidental distribution.
publish_target_dir=''
if (( release_mode )) && [[ -n ${notary_profile:-} && ${identity_details} == *'Developer ID Application'* ]]; then
  publish_target_dir=${repo_root}/dist/Keep\ Vault-macOS
else
  publish_target_dir=${repo_root}/build/dev/Keep\ Vault-macOS
  print "publish_mode=development (outputs placed in build/dev/; dist/ is reserved for Developer ID + notarized production releases)"
fi

publish_parent=${publish_target_dir:h}
mkdir -p ${publish_parent}

publish_stage=${publish_parent}/.publish_stage.$$.$RANDOM
rm -rf -- ${publish_stage}
ditto ${dist_stage} ${publish_stage}

if [[ -e ${publish_target_dir} ]]; then
  publish_old=${publish_parent}/.publish_old.$$.$RANDOM
  mv ${publish_target_dir} ${publish_old}
  mv ${publish_stage} ${publish_target_dir}
  rm -rf -- ${publish_old}
else
  mv ${publish_stage} ${publish_target_dir}
fi

touch ${publish_parent}/.metadata_never_index

print "published_app=${publish_target_dir}/Keep Vault.app"
print "published_archive=${publish_target_dir}/Keep Vault-macOS-${architecture}.zip"
