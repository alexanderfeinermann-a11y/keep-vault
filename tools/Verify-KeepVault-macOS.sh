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
required_native=(zpaq argon2 libargon2_ref.dylib libkalyna_ref.dylib libthreefish_ref.dylib keep-vault-scanner)
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
  # Enumerate real load-time dependencies straight from the Mach-O load
  # commands instead of parsing "otool -L". That listing repeats an unindented
  # header for every universal slice, and for a library its first entry is the
  # file's own LC_ID_DYLIB install name rather than a dependency — Avalonia's
  # native library, for instance, is named /usr/local/lib/... without ever
  # loading from there. Selecting the LC_LOAD_* commands covers every slice and
  # every load kind while excluding the install name by construction.
  while IFS= read -r dependency; do
    [[ -z ${dependency} ]] && continue
    case ${dependency} in
      /System/Library/*|/usr/lib/*|@rpath/*|@loader_path/*|@executable_path/*) ;;
      *)
        print -u2 "Non-system absolute Mach-O dependency is blocked: ${macho} -> ${dependency}"
        exit 1
        ;;
    esac
  done < <(otool -l ${macho} | awk '
    /^ *cmd LC_(LOAD_DYLIB|LOAD_WEAK_DYLIB|REEXPORT_DYLIB|LAZY_LOAD_DYLIB|LOAD_UPWARD_DYLIB)$/ { want = 1; next }
    /^ *cmd / { want = 0 }
    want && /^ *name / { print $2; want = 0 }')
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
scanner_entitlements=${entitlement_root}/scanner.plist
extract_entitlements ${core} ${core_entitlements}
extract_entitlements ${launcher} ${launcher_entitlements}
extract_entitlements ${native_dir}/zpaq ${zpaq_entitlements}
extract_entitlements ${native_dir}/argon2 ${argon_entitlements}
extract_entitlements ${supervisor} ${supervisor_entitlements}
extract_entitlements ${native_dir}/keep-vault-scanner ${scanner_entitlements}

# Keep Vault does not use the App Sandbox: it is mutually exclusive with the
# integrity chain on macOS, because a sandboxed process is not served a file
# panel and making the core able to own a sandbox would place it inside the
# bundle seal, whose re-sealing invalidates the hybrid signature the launcher
# verifies before running it. See KeepVault.entitlements for the full reasoning.
#
# That trade-off is only defensible if it stays deliberate, so assert the
# sandbox is absent everywhere rather than letting it reappear unnoticed and
# silently break panels again.
for image_entitlements in ${core_entitlements} ${launcher_entitlements} \
    ${zpaq_entitlements} ${argon_entitlements} ${supervisor_entitlements} ${scanner_entitlements}; do
  for sandbox_key in com.apple.security.app-sandbox com.apple.security.inherit; do
    if /usr/libexec/PlistBuddy -c "Print :${sandbox_key}" ${image_entitlements} >/dev/null 2>&1; then
      print -u2 "The App Sandbox must not be declared: ${sandbox_key} in ${image_entitlements:t}"
      exit 1
    fi
  done
done

# Only the scanner may reach hardware, and only the camera, for reading a
# printed key sheet. Every other image ships with no capability whatsoever —
# including the core, which never gains the ability to look through it.
[[ $(/usr/libexec/PlistBuddy -c 'Print :com.apple.security.device.camera' ${scanner_entitlements}) == true ]]
for bare_entitlements in ${core_entitlements} ${launcher_entitlements} ${zpaq_entitlements} ${argon_entitlements} ${supervisor_entitlements}; do
  if /usr/libexec/PlistBuddy -c 'Print :com.apple.security.device.camera' ${bare_entitlements} >/dev/null 2>&1; then
    print -u2 "Only the core may declare camera access: ${bare_entitlements:t}"
    exit 1
  fi
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

# Contents/MacOS is reserved for Mach-O executables, so the detached hash and
# hybrid-signature sidecars live under Contents/Resources/HybridSignatures,
# mirroring the layout below Contents/MacOS.
macos_root=${app_path}/Contents/MacOS
signature_root=${app_path}/Contents/Resources/HybridSignatures
hybrid_targets=(${core} ${required_native[@]/#/${native_dir}/})
for target in ${hybrid_targets[@]}; do
  sidecar_base=${signature_root}/${target#${macos_root}/}
  for suffix in .sha3 .skein .khsig .sha3.khsig .skein.khsig; do
    sidecar=${sidecar_base}${suffix}
    if [[ ! -f ${sidecar} || -L ${sidecar} ]]; then
      print -u2 "Required hybrid integrity sidecar is missing or a symbolic link: ${sidecar}"
      exit 1
    fi
  done
done

# Nothing but Mach-O payload may remain in Contents/MacOS, otherwise codesign
# cannot seal the bundle and the relocation step silently regressed.
if find ${macos_root} -type f \( -name '*.sha3' -o -name '*.skein' -o -name '*.khsig' \) -print -quit | grep -q .; then
  print -u2 'Hybrid-signature sidecars are present in Contents/MacOS; the bundle layout is invalid.'
  exit 1
fi

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
    --payload-root ${macos_root}
    --signature-root ${signature_root}
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
