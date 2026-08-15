#!/bin/zsh
set -euo pipefail

script_dir=${0:A:h}
repo_root=${script_dir:h}
expected_team='2T6K9PGS55'
expected_bundle='de.michael-feinermann.keep-vault'
app_path=''
allow_development=0
require_notarization=0
mldsa_public_key=${KEEPVAULT_MLDSA_PUBLIC_KEY:-${repo_root}/KeepVaultMac/Packaging/Keys/mldsa87-public.key}
dotnet_command=${KEEPVAULT_DOTNET:-/Users/michael/.dotnet-keepvault/dotnet}
expected_signer_lock_sha256='B07635B8B5CF158644267CBB99E6483D6F947F37D3B9918B4FF39407EB6BA5EB'

usage() {
  print -u2 'Usage: Verify-KeepVault-macOS.sh --app "Keep Vault.app" [--allow-development]'
  print -u2 '       [--require-notarization] [--mldsa-public-key FILE]'
  exit 64
}

while (( $# != 0 )); do
  case $1 in
    --app)
      (( $# >= 2 )) || usage
      app_path=$2
      shift 2
      ;;
    --allow-development)
      allow_development=1
      shift
      ;;
    --require-notarization)
      require_notarization=1
      shift
      ;;
    --mldsa-public-key)
      (( $# >= 2 )) || usage
      mldsa_public_key=$2
      shift 2
      ;;
    *) usage ;;
  esac
done

[[ -n ${app_path} ]] || usage
app_path=${app_path:A}
if [[ ! -d ${app_path} || -L ${app_path} || ${app_path:e} != app ]]; then
  print -u2 "App bundle is missing, not a directory, or a symbolic link: ${app_path}"
  exit 1
fi
if find ${app_path} -type l -print -quit | grep -q .; then
  print -u2 'The Keep Vault bundle contains a symbolic link and is rejected.'
  exit 1
fi
if find ${app_path} -type f -links +1 -print -quit | grep -q .; then
  print -u2 'The Keep Vault bundle contains hard-linked files and is rejected.'
  exit 1
fi
if find ${app_path} -perm -022 -print -quit | grep -q .; then
  print -u2 'The Keep Vault bundle contains group- or world-writable objects and is rejected.'
  exit 1
fi

info_plist=${app_path}/Contents/Info.plist
plutil -lint ${info_plist} >/dev/null
plist_value() {
  /usr/libexec/PlistBuddy -c "Print :$1" ${info_plist}
}

[[ $(plist_value CFBundleIdentifier) == ${expected_bundle} ]] || {
  print -u2 'Unexpected CFBundleIdentifier.'
  exit 1
}
[[ $(plist_value CFBundleDisplayName) == 'Keep Vault' ]] || {
  print -u2 'Unexpected CFBundleDisplayName.'
  exit 1
}
[[ $(plist_value CFBundleExecutable) == 'Keep Vault Launcher' ]] || {
  print -u2 'The bundle does not name the integrity launcher as its entry point.'
  exit 1
}
[[ $(plist_value LSMinimumSystemVersion) == '14.0' ]] || {
  print -u2 'Unexpected minimum macOS version.'
  exit 1
}
[[ $(plist_value CFBundleDocumentTypes:0:CFBundleTypeExtensions:0) == kzpaq ]] || {
  print -u2 'The .kzpaq file association is missing.'
  exit 1
}
[[ $(plist_value CFBundleDocumentTypes:1:CFBundleTypeExtensions:0) == zpaq ]] || {
  print -u2 'The .zpaq file association is missing.'
  exit 1
}

launcher=${app_path}/Contents/MacOS/Keep\ Vault\ Launcher
core=${app_path}/Contents/MacOS/Keep\ Vault
supervisor=${app_path}/Contents/MacOS/Keep\ Vault\ Supervisor
native_dir=${app_path}/Contents/MacOS/Native
required_native=(zpaq argon2 libargon2_ref.dylib libkalyna_ref.dylib libthreefish_ref.dylib)
for required_path in ${launcher} ${core} ${supervisor} ${required_native[@]/#/${native_dir}/}; do
  if [[ ! -f ${required_path} || -L ${required_path} ]]; then
    print -u2 "Required executable component is missing or a symbolic link: ${required_path}"
    exit 1
  fi
  [[ -x ${required_path} ]] || {
    print -u2 "Required executable component is not executable: ${required_path}"
    exit 1
  }
  file -b ${required_path} | grep -q 'Mach-O' || {
    print -u2 "Required executable component is not Mach-O: ${required_path}"
    exit 1
  }
done

codesign --verify --deep --strict --verbose=4 ${app_path}
outer_requirement="identifier \"${expected_bundle}\" and anchor apple generic and certificate leaf[subject.OU] = \"${expected_team}\""
core_requirement="identifier \"${expected_bundle}.core\" and anchor apple generic and certificate leaf[subject.OU] = \"${expected_team}\""
supervisor_requirement="identifier \"${expected_bundle}.supervisor\" and anchor apple generic and certificate leaf[subject.OU] = \"${expected_team}\""
codesign --verify --strict -R=${outer_requirement} ${app_path}
codesign --verify --strict -R=${core_requirement} ${core}
codesign --verify --strict -R=${supervisor_requirement} ${supervisor}

macho_files=()
while IFS= read -r -d '' candidate; do
  if file -b ${candidate} | grep -q 'Mach-O'; then
    macho_files+=(${candidate})
  fi
done < <(find ${app_path}/Contents -type f -print0)
(( ${#macho_files[@]} >= 8 )) || {
  print -u2 'The signed bundle has fewer Mach-O components than expected.'
  exit 1
}

expected_architectures=$(xcrun lipo ${launcher} -archs | tr ' ' '\n' | sort | xargs)
for macho in ${macho_files[@]}; do
  codesign --verify --strict --verbose=2 ${macho}
  signature_details=$(codesign -dvvv ${macho} 2>&1)
  [[ ${signature_details} == *"TeamIdentifier=${expected_team}"* ]] || {
    print -u2 "Unexpected or absent Apple TeamIdentifier: ${macho}"
    exit 1
  }
  [[ ${signature_details} == *'flags='*'runtime'* ]] || {
    print -u2 "Hardened Runtime is absent: ${macho}"
    exit 1
  }
  architectures=$(xcrun lipo ${macho} -archs)
  [[ " ${architectures} " == *' arm64 '* ]] || {
    print -u2 "arm64 slice is absent: ${macho}"
    exit 1
  }
  normalized_architectures=$(print -r -- ${architectures} | tr ' ' '\n' | sort | xargs)
  [[ ${normalized_architectures} == ${expected_architectures} ]] || {
    print -u2 "Mach-O architecture set differs from the launcher: ${macho}"
    exit 1
  }
  while IFS= read -r dependency; do
    dependency=$(print -r -- ${dependency} | sed -E 's/^[[:space:]]+//; s/[[:space:]]+\(.*$//')
    [[ -z ${dependency} ]] && continue
    case ${dependency} in
      /System/Library/*|/usr/lib/*|@rpath/*|@loader_path/*|@executable_path/*) ;;
      *)
        print -u2 "Non-system absolute Mach-O dependency is blocked: ${macho} -> ${dependency}"
        exit 1
        ;;
    esac
  done < <(otool -L ${macho} | tail -n +2)
done

core_details=$(codesign -dvvv ${core} 2>&1)
supervisor_details=$(codesign -dvvv ${supervisor} 2>&1)
outer_details=$(codesign -dvvv ${app_path} 2>&1)
[[ ${outer_details} == *"Identifier=${expected_bundle}"* ]] || {
  print -u2 'The outer app signature identifier is incorrect.'
  exit 1
}
[[ ${core_details} == *'Identifier=de.michael-feinermann.keep-vault.core'* ]] || {
  print -u2 'The nested NativeAOT Core identifier is incorrect.'
  exit 1
}
[[ ${supervisor_details} == *'Identifier=de.michael-feinermann.keep-vault.supervisor'* ]] || {
  print -u2 'The suspended-execution Supervisor identifier is incorrect.'
  exit 1
}

entitlement_root=$(mktemp -d "${TMPDIR:-/tmp}/keep-vault-entitlements.XXXXXXXX")
cleanup() {
  if [[ -n ${entitlement_root:-} && -d ${entitlement_root} && ${entitlement_root} == */keep-vault-entitlements.* ]]; then
    rm -rf -- ${entitlement_root}
  fi
}
trap cleanup EXIT INT TERM

extract_entitlements() {
  local executable=$1
  local output=$2
  codesign -d --entitlements :- --xml ${executable} > ${output} 2>/dev/null
  plutil -lint ${output} >/dev/null
}

core_entitlements=${entitlement_root}/core.plist
launcher_entitlements=${entitlement_root}/launcher.plist
zpaq_entitlements=${entitlement_root}/zpaq.plist
argon_entitlements=${entitlement_root}/argon.plist
supervisor_entitlements=${entitlement_root}/supervisor.plist
extract_entitlements ${core} ${core_entitlements}
extract_entitlements ${launcher} ${launcher_entitlements}
extract_entitlements ${native_dir}/zpaq ${zpaq_entitlements}
extract_entitlements ${native_dir}/argon2 ${argon_entitlements}
extract_entitlements ${supervisor} ${supervisor_entitlements}

for app_entitlements in ${core_entitlements} ${launcher_entitlements}; do
  [[ $(/usr/libexec/PlistBuddy -c 'Print :com.apple.security.app-sandbox' ${app_entitlements}) == true ]]
  [[ $(/usr/libexec/PlistBuddy -c 'Print :com.apple.security.files.user-selected.read-write' ${app_entitlements}) == true ]]
  [[ $(/usr/libexec/PlistBuddy -c 'Print :com.apple.security.print' ${app_entitlements}) == true ]]
done
for helper_entitlements in ${zpaq_entitlements} ${argon_entitlements} ${supervisor_entitlements}; do
  [[ $(/usr/libexec/PlistBuddy -c 'Print :com.apple.security.app-sandbox' ${helper_entitlements}) == true ]]
  [[ $(/usr/libexec/PlistBuddy -c 'Print :com.apple.security.inherit' ${helper_entitlements}) == true ]]
done

disallowed_entitlements=(
  com.apple.security.get-task-allow
  com.apple.security.cs.allow-jit
  com.apple.security.cs.allow-unsigned-executable-memory
  com.apple.security.cs.disable-library-validation
  com.apple.security.cs.disable-executable-page-protection
  com.apple.security.network.client
  com.apple.security.network.server
  com.apple.security.device.audio-input
  com.apple.security.device.camera
  com.apple.security.device.usb
  com.apple.security.device.bluetooth
  com.apple.security.automation.apple-events
)
for entitlement_file in ${core_entitlements} ${launcher_entitlements} ${zpaq_entitlements} ${argon_entitlements} ${supervisor_entitlements}; do
  for disallowed in ${disallowed_entitlements[@]}; do
    if /usr/libexec/PlistBuddy -c "Print :${disallowed}" ${entitlement_file} >/dev/null 2>&1; then
      print -u2 "Disallowed entitlement is present: ${disallowed}"
      exit 1
    fi
  done
done

hybrid_targets=(${core} ${required_native[@]/#/${native_dir}/})
for target in ${hybrid_targets[@]}; do
  for suffix in .sha3 .skein .khsig .sha3.khsig .skein.khsig; do
    sidecar=${target}${suffix}
    if [[ ! -f ${sidecar} || -L ${sidecar} ]]; then
      print -u2 "Required hybrid integrity sidecar is missing or a symbolic link: ${sidecar}"
      exit 1
    fi
  done
done

if [[ -x ${dotnet_command} && ! -L ${dotnet_command} && -f ${mldsa_public_key} ]]; then
  signer_lock=${repo_root}/KeepVaultMac/Packaging/HybridSigner/packages.lock.json
  if [[ ! -f ${signer_lock} || -L ${signer_lock} \
      || $(shasum -a 256 ${signer_lock} | awk '{print toupper($1)}') != ${expected_signer_lock_sha256} ]]; then
    print -u2 'The reviewed hybrid-verifier NuGet lockfile is missing or changed.'
    exit 1
  fi
  signer_dll=${repo_root}/KeepVaultMac/Packaging/HybridSigner/bin/Release/net10.0/KeepVaultMac.HybridSigner.dll
  (
    cd ${repo_root}/KeepVaultMac
    ${dotnet_command} restore Packaging/HybridSigner/KeepVaultMac.HybridSigner.csproj --locked-mode --nologo
    ${dotnet_command} build Packaging/HybridSigner/KeepVaultMac.HybridSigner.csproj -c Release --no-restore --nologo
  )
  [[ -f ${signer_dll} && ! -L ${signer_dll} ]] || {
    print -u2 'The locked hybrid verifier build did not produce its managed entry assembly.'
    exit 1
  }
  verify_arguments=(
    ${signer_dll}
    verify
    --mldsa-public-key ${mldsa_public_key}
    --policy ${repo_root}/KeepVaultMac/Directory.Build.props
  )
  for target in ${hybrid_targets[@]}; do
    verify_arguments+=(--target ${target})
  done
  (
    cd ${repo_root}/KeepVaultMac
    ${dotnet_command} ${verify_arguments[@]}
  )
else
  print -u2 'The independent managed hybrid verifier or pinned ML-DSA public key is unavailable.'
  exit 1
fi

if spctl --assess --type execute --verbose=4 ${app_path}; then
  print 'gatekeeper=accepted'
else
  app_signature=$(codesign -dvvv ${app_path} 2>&1)
  if (( allow_development )) && [[ ${app_signature} == *'Authority=Apple Development:'* ]]; then
    print 'gatekeeper=not_accepted (expected for local Apple Development signing)'
  else
    print -u2 'Gatekeeper did not accept the app bundle.'
    exit 1
  fi
fi

if (( require_notarization )); then
  xcrun stapler validate ${app_path}
  print 'notarization=stapled-and-valid'
else
  print 'notarization=not-required-by-this-local-verification'
fi

print "bundle_verified=${app_path}"
