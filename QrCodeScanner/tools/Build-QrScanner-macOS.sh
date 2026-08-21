#!/bin/zsh
set -euo pipefail
umask 077

# Builds, signs and verifies QR-Scanner.
#
# This app is deliberately independent of Keep Vault: its own bundle
# identifier, its own signature, its own folder, no shared code and no shared
# build step. Nothing here reads or writes anything under KeepVaultMac.
#
# Usage:
#   ./QrCodeScanner/tools/Build-QrScanner-macOS.sh
#   ./QrCodeScanner/tools/Build-QrScanner-macOS.sh --install
#   ./QrCodeScanner/tools/Build-QrScanner-macOS.sh --notary-profile "QR-Scanner"

script_dir=${0:A:h}
project_root=${script_dir:h}
packaging_dir=${project_root}/Packaging
sources_dir=${project_root}/Sources
bundle_identifier='de.michael-feinermann.qr-scanner'
app_name='QR-Scanner'
marketing_version='1.0.0'
build_version='1'
architecture='universal'
deployment_target='14.0'
install_app=0
run_tests=1
preflight_only=0
identity=${QRSCANNER_CODESIGN_IDENTITY:-}
# Name of an "xcrun notarytool store-credentials" keychain profile. Empty means
# the build stops short of notarization; no secret ever lives in this file.
notary_profile=${QRSCANNER_NOTARY_PROFILE:-}

while (( $# > 0 )); do
  case $1 in
    --install)
      install_app=1
      ;;
    --identity)
      (( $# >= 2 )) || { print -u2 'Missing value for --identity.'; exit 64; }
      identity=$2
      shift
      ;;
    --notary-profile)
      (( $# >= 2 )) || { print -u2 'Missing value for --notary-profile.'; exit 64; }
      notary_profile=$2
      shift
      ;;
    --arch)
      (( $# >= 2 )) || { print -u2 'Missing value for --arch.'; exit 64; }
      architecture=$2
      shift
      ;;
    --version)
      (( $# >= 2 )) || { print -u2 'Missing value for --version.'; exit 64; }
      marketing_version=$2
      shift
      ;;
    --build-number)
      (( $# >= 2 )) || { print -u2 'Missing value for --build-number.'; exit 64; }
      build_version=$2
      shift
      ;;
    --preflight)
      preflight_only=1
      ;;
    --skip-tests)
      run_tests=0
      ;;
    -h|--help)
      print 'Usage: Build-QrScanner-macOS.sh [--install] [--identity NAME] [--notary-profile NAME]'
      print '       [--arch universal|arm64|x86_64] [--version X.Y.Z] [--build-number N]'
      print '       [--skip-tests] [--preflight]'
      exit 0
      ;;
    *)
      print -u2 "Unknown argument: $1"
      exit 64
      ;;
  esac
  shift
done

if [[ ! ${marketing_version} =~ '^[0-9]+([.][0-9]+){1,2}$' || ! ${build_version} =~ '^[1-9][0-9]*$' ]]; then
  print -u2 'Version values must be numeric (for example 4.0.2 and build 6).'
  exit 64
fi

render_info_plist() {
  local destination=$1
  sed -e "s/@@MARKETING_VERSION@@/${marketing_version}/g" \
      -e "s/@@BUILD_VERSION@@/${build_version}/g" \
    ${packaging_dir}/Info.plist.template > ${destination}
  plutil -lint ${destination} > /dev/null
  [[ $(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' ${destination}) == ${bundle_identifier} ]] || {
    print -u2 'The rendered QR-Scanner bundle identifier is incorrect.'
    exit 1
  }
  [[ $(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' ${destination}) == ${marketing_version} ]] || {
    print -u2 'The rendered QR-Scanner marketing version is incorrect.'
    exit 1
  }
  [[ $(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' ${destination}) == ${build_version} ]] || {
    print -u2 'The rendered QR-Scanner build number is incorrect.'
    exit 1
  }
}

for required_command in xcrun codesign security plutil ditto iconutil; do
  if ! command -v ${required_command} > /dev/null 2>&1; then
    print -u2 "Required command not found: ${required_command}"
    exit 1
  fi
done

if (( preflight_only )); then
  preflight_root=$(mktemp -d "${TMPDIR:-/tmp}/qr-scanner-preflight.XXXXXXXX")
  cleanup_preflight() {
    if [[ -n ${preflight_root:-} && -d ${preflight_root} && ${preflight_root} == */qr-scanner-preflight.* ]]; then
      rm -rf -- ${preflight_root}
    fi
  }
  trap cleanup_preflight EXIT INT TERM
  render_info_plist ${preflight_root}/Info.plist
  print "preflight_version=${marketing_version}"
  print "preflight_build=${build_version}"
  exit 0
fi

# Pick a signing identity if none was named.
#
# Developer ID is what a downloaded copy needs, so it wins when it is present.
# An Apple Development certificate signs an app that runs on this machine but
# that the notary service rejects, and ad-hoc signing runs here only. All three
# are useful at different points, so the build reports which one it used rather
# than pretending they are equivalent.
if [[ -z ${identity} ]]; then
  identity=$(security find-identity -v -p codesigning \
    | grep -o 'Developer ID Application: [^"]*' | head -n 1 || true)
fi
if [[ -z ${identity} ]]; then
  identity=$(security find-identity -v -p codesigning \
    | grep -o 'Apple Development: [^"]*' | head -n 1 || true)
fi
if [[ -z ${identity} ]]; then
  identity='-'
  print 'signing=ad-hoc (no codesigning certificate found; the app runs on this Mac only)'
elif [[ ${identity} == 'Developer ID Application: '* ]]; then
  print "signing=developer-id (${identity})"
else
  print "signing=development (${identity}) — usable on this Mac; the notary service rejects this certificate"
fi

# Everything this build produces stays inside the app's own folder. Nothing is
# written to, or read from, any other project in this repository.
build_root=${project_root}/dist
rm -rf ${build_root}
mkdir -p ${build_root}

app_bundle=${build_root}/${app_name}.app
contents=${app_bundle}/Contents
macos_dir=${contents}/MacOS
resources_dir=${contents}/Resources
mkdir -p ${macos_dir} ${resources_dir}

# The unit tests cover the arbitration rule — which of two QR codes is taken —
# and that rule is the reason this app exists, so it is checked before anything
# is signed rather than after.
if (( run_tests )); then
  test_binary=${build_root}/ArbiterTests
  xcrun swiftc \
    -target arm64-apple-macos${deployment_target} \
    -O -parse-as-library \
    ${sources_dir}/CodeArbiter.swift \
    ${sources_dir}/PayloadInspector.swift \
    ${sources_dir}/Localization.swift \
    ${project_root}/Tests/ArbiterTests.swift \
    -o ${test_binary}
  ${test_binary}
  rm -f ${test_binary}
fi

architectures=(arm64)
case ${architecture} in
  universal) architectures=(arm64 x86_64) ;;
  arm64) architectures=(arm64) ;;
  x86_64) architectures=(x86_64) ;;
  *) print -u2 "Unknown architecture: ${architecture}"; exit 64 ;;
esac

# The Info.plist is linked into the executable as well as written into the
# bundle. LaunchServices reads the bundle's copy; the embedded section is what
# the camera prompt reads when the process is examined directly.
plist_path=${build_root}/Info.plist
render_info_plist ${plist_path}

thin_binaries=()
for slice in ${architectures[@]}; do
  thin=${build_root}/qr-scanner-${slice}
  xcrun swiftc \
    -target ${slice}-apple-macos${deployment_target} \
    -O -whole-module-optimization -parse-as-library \
    ${sources_dir}/CodeArbiter.swift \
    ${sources_dir}/PayloadInspector.swift \
    ${sources_dir}/Localization.swift \
    ${sources_dir}/VolatileClipboard.swift \
    ${sources_dir}/ScanSession.swift \
    ${sources_dir}/MainWindowController.swift \
    ${sources_dir}/App.swift \
    -framework AppKit -framework AVFoundation \
    -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker ${plist_path} \
    -o ${thin}
  thin_binaries+=(${thin})
done

executable=${macos_dir}/${app_name}
if (( ${#thin_binaries} > 1 )); then
  xcrun lipo -create ${thin_binaries[@]} -output ${executable}
  xcrun lipo ${executable} -verify_arch ${architectures[@]}
else
  ditto ${thin_binaries[1]} ${executable}
fi
chmod 0755 ${executable}
rm -f ${thin_binaries[@]}

ditto ${plist_path} ${contents}/Info.plist
print -n 'APPL????' > ${contents}/PkgInfo

# The icon is generated from tools/make-icon.swift, so what it depicts is
# readable source rather than a committed binary.
iconset=${build_root}/AppIcon.iconset
xcrun swift ${script_dir}/make-icon.swift ${iconset} > /dev/null
iconutil -c icns ${iconset} -o ${resources_dir}/AppIcon.icns
rm -rf ${iconset}

# Refuse the entitlements that would undo the point of the sandbox.
#
# Each of these lets another process put code into this one, and this process
# is the one holding the scanned value in memory. A signature over a bundle
# carrying any of them would be signing away the guarantee the app is making,
# so the build stops rather than producing it.
forbidden=(
  'com.apple.security.cs.disable-library-validation'
  'com.apple.security.cs.allow-unsigned-executable-memory'
  'com.apple.security.cs.allow-dyld-environment-variables'
  'com.apple.security.cs.disable-executable-page-protection'
  'com.apple.security.get-task-allow'
)
# Matched as a plist <key> element rather than as loose text, so the comment in
# the entitlements file naming these keys does not trip the check on itself.
entitlements_source=$(< ${packaging_dir}/QrScanner.entitlements)
for forbidden_key in ${forbidden[@]}; do
  if [[ ${entitlements_source} == *"<key>${forbidden_key}</key>"* ]]; then
    print -u2 "The entitlements request ${forbidden_key}, which reopens code injection."
    exit 1
  fi
done

timestamp_arguments=(--timestamp)
[[ ${identity} == '-' ]] && timestamp_arguments=()

codesign --force --sign ${identity} --options runtime ${timestamp_arguments[@]} \
  --entitlements ${packaging_dir}/QrScanner.entitlements \
  --identifier ${bundle_identifier} \
  ${app_bundle}

codesign --verify --strict --deep --verbose=2 ${app_bundle}

# Confirm the bundle actually carries what was requested. A signature that
# silently dropped the sandbox would still verify happily.
#
# The output is captured whole and matched in the shell rather than piped into
# "grep -q": grep exits at its first match, the tool upstream dies of SIGPIPE,
# and under "set -o pipefail" that turns a successful check into a failed one.
granted=$(codesign -d --entitlements :- ${app_bundle} 2>/dev/null || true)
for required_key in 'com.apple.security.app-sandbox' 'com.apple.security.device.camera'; do
  if [[ ${granted} != *${required_key}* ]]; then
    print -u2 "The signed bundle is missing ${required_key}."
    exit 1
  fi
done
for forbidden_key in ${forbidden[@]}; do
  if [[ ${granted} == *${forbidden_key}* ]]; then
    print -u2 "The signed bundle carries ${forbidden_key}."
    exit 1
  fi
done
print 'entitlements=sandbox+camera (no injection-enabling entitlements present)'

signature_details=$(codesign -dvvv ${app_bundle} 2>&1 || true)
if [[ ${signature_details} != *'flags='*'runtime'* ]]; then
  print -u2 'The signed bundle does not carry the hardened runtime.'
  exit 1
fi
print 'hardened-runtime=enabled'

# Notarization. Requires a Developer ID Application certificate and a stored
# notarytool profile:
#
#   xcrun notarytool store-credentials "QR-Scanner" \
#     --apple-id you@example.com --team-id TEAMID --password APP-SPECIFIC-PASSWORD
#
# then pass --notary-profile "QR-Scanner".
release_zip=${build_root}/${app_name}-macOS.zip
ditto -c -k --keepParent ${app_bundle} ${release_zip}

if [[ -z ${notary_profile} ]]; then
  print 'notarization=not_performed (pass --notary-profile NAME once a Developer ID certificate and a notarytool profile exist)'
elif [[ ${identity} != 'Developer ID Application: '* ]]; then
  print -u2 'Notarization requires a Developer ID Application identity; the notary service rejects an Apple Development certificate.'
  exit 1
else
  xcrun notarytool submit ${release_zip} --keychain-profile ${notary_profile} --wait
  xcrun stapler staple ${app_bundle}
  xcrun stapler validate ${app_bundle}
  spctl --assess --type execute --verbose=4 ${app_bundle}
  rm -f ${release_zip}
  ditto -c -k --keepParent ${app_bundle} ${release_zip}
  print "notarization=stapled (${notary_profile})"
fi

# --- Hybrid Signatures --------------------------------------------------------
repo_root=${project_root:h}
dotnet_command=${KEEPVAULT_DOTNET:-/Users/michael/.dotnet-keepvault/dotnet}
pfx_path=${KEEPVAULT_SIGNING_PFX:-}
if [[ -z ${pfx_path} ]]; then
  for candidate in /Volumes/*/Keep\ Vault\ ReleaseKeys*/*.pfx(N); do
    [[ -f ${candidate} && ! -L ${candidate} ]] || continue
    pfx_path=${candidate}
    break
  done
fi

mldsa_private_key=${KEEPVAULT_MLDSA_PRIVATE_KEY:-}
if [[ -z ${mldsa_private_key} ]]; then
  for candidate in /Volumes/*/Keep\ Vault\ ReleaseKeys*/mldsa87-private.key(N); do
    [[ -f ${candidate} && ! -L ${candidate} ]] || continue
    mldsa_private_key=${candidate}
    break
  done
fi
mldsa_private_key_encrypted=${KEEPVAULT_MLDSA_PRIVATE_KEY_ENCRYPTED:-${mldsa_private_key}.enc}
mldsa_keychain_service=${KEEPVAULT_MLDSA_KEYCHAIN_SERVICE:-de.michael-feinermann.keep-vault.hybrid-wrapping-key}
mldsa_keychain_account=${KEEPVAULT_MLDSA_KEYCHAIN_ACCOUNT:-${USER:-}}

mldsa_key_arguments=(--mldsa-private-key ${mldsa_private_key})
if [[ -f ${mldsa_private_key_encrypted} && ! -L ${mldsa_private_key_encrypted} ]]; then
  mldsa_key_arguments=(
    --mldsa-private-key-encrypted ${mldsa_private_key_encrypted}
    --mldsa-key-keychain-service ${mldsa_keychain_service}
    --mldsa-key-keychain-account ${mldsa_keychain_account}
  )
fi

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
fi

mldsa_public_key=${KEEPVAULT_MLDSA_PUBLIC_KEY:-${repo_root}/KeepVaultMac/Packaging/Keys/mldsa87-public.key}
pfx_password_encrypted=${KEEPVAULT_PFX_PASSWORD_ENCRYPTED:-${pfx_path}.password.enc}
pfx_password_arguments=()
if [[ -f ${pfx_password_encrypted} && ! -L ${pfx_password_encrypted} ]]; then
  pfx_password_arguments=(--pfx-password-encrypted ${pfx_password_encrypted})
fi
pfx_password_service=${KEEPVAULT_PFX_KEYCHAIN_SERVICE:-de.michael-feinermann.keep-vault.hybrid-pfx}
pfx_password_account=${KEEPVAULT_PFX_KEYCHAIN_ACCOUNT:-${USER:-}}
pfx_password_environment=${KEEPVAULT_PFX_PASSWORD_ENV:-KEEPVAULT_HYBRID_PFX_PASSWORD}

if [[ -n ${pfx_path} && -f ${pfx_path} && -n ${mldsa_private_key} && -f ${mldsa_private_key} && -x ${dotnet_command} ]]; then
  signer_dll=${repo_root}/KeepVaultMac/Packaging/HybridSigner/bin/Release/net10.0/KeepVaultMac.HybridSigner.dll
  (
    cd ${repo_root}/KeepVaultMac
    ${dotnet_command} restore Packaging/HybridSigner/KeepVaultMac.HybridSigner.csproj --locked-mode --nologo
    ${dotnet_command} build Packaging/HybridSigner/KeepVaultMac.HybridSigner.csproj -c Release --no-restore --nologo
  )
  
  hybrid_arguments=(
    ${signer_dll}
    sign
    --pfx ${pfx_path}
    ${pfx_password_arguments[@]}
    ${mldsa_key_arguments[@]}
    --mldsa-public-key ${mldsa_public_key}
    --reference-library ${repo_root}/KeepVaultMac/Native/osx-arm64/libmldsa87_ref.dylib
    --policy ${repo_root}/KeepVaultMac/Directory.Build.props
    --launcher-pins ${build_root}/ScannerPins.swift
    --target ${app_bundle}/Contents/MacOS/QR-Scanner
  )
  if [[ ${#pfx_password_arguments[@]} -eq 0 ]]; then
    if [[ -n ${pfx_password_service} ]]; then
      hybrid_arguments+=(--pfx-password-keychain-service ${pfx_password_service})
      [[ -n ${pfx_password_account} ]] && hybrid_arguments+=(--pfx-keychain-account ${pfx_password_account})
    else
      hybrid_arguments+=(--pfx-password-env ${pfx_password_environment})
    fi
  fi

  hybrid_keychain_tmp=${build_root}/hybrid-keychain-tmp
  mkdir -p -m 0700 ${hybrid_keychain_tmp}
  (
    cd ${repo_root}/KeepVaultMac
    TMPDIR=${hybrid_keychain_tmp} \
      KEEPVAULT_KEYCHAIN_TEMP_ROOT=${hybrid_keychain_tmp} \
      DOTNET_EnableDiagnostics=0 \
      ${dotnet_command} ${hybrid_arguments[@]}
  )
  rm -rf -- ${hybrid_keychain_tmp}

  scanner_bin=${app_bundle}/Contents/MacOS/QR-Scanner
  for sidecar_suffix in .sha3 .skein .khsig .sha3.khsig .skein.khsig; do
    if [[ -f ${scanner_bin}${sidecar_suffix} ]]; then
      mv -f -- ${scanner_bin}${sidecar_suffix} ${app_bundle}${sidecar_suffix}
    fi
  done
  codesign --verify --strict --verbose=2 ${app_bundle}
  print "scanner_dual_signature=${app_bundle}.khsig"
fi

if (( install_app )); then
  destination=/Applications/${app_name}.app
  backup_dir=$(mktemp -d "${TMPDIR:-/tmp}/qr-scanner-backup.XXXXXXXX")
  cleanup_backup() { rm -rf -- ${backup_dir}; }
  trap cleanup_backup EXIT INT TERM

  has_existing=0
  if [[ -e ${destination} || -L ${destination} ]]; then
    if [[ ! -d ${destination} || -L ${destination} ]]; then
      print -u2 "Refusing to replace a non-directory object: ${destination}"
      exit 1
    fi
    existing_id=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' ${destination}/Contents/Info.plist 2>/dev/null || true)
    if [[ ${existing_id} != ${bundle_identifier} ]]; then
      print -u2 "Refusing to replace foreign app at ${destination} (bundle id: ${existing_id})"
      exit 1
    fi
    has_existing=1
    ditto ${destination} ${backup_dir}/QR-Scanner.app
    for suffix in .sha3 .skein .khsig .sha3.khsig .skein.khsig; do
      if [[ -f ${destination}${suffix} ]]; then
        ditto ${destination}${suffix} ${backup_dir}/QR-Scanner.app${suffix}
      fi
    done
  fi

  # Atomic replace
  if (( has_existing )); then
    backup_name=.QR-Scanner.previous.$RANDOM.$$.app
    DESTINATION_PATH=${destination} NEW_ITEM_PATH=${app_bundle} BACKUP_ITEM_NAME=${backup_name} \
      osascript -l JavaScript <<'JAVASCRIPT'
ObjC.import('Foundation')
const env = $.NSProcessInfo.processInfo.environment
const dest = $.NSURL.fileURLWithPath(ObjC.unwrap(env.objectForKey('DESTINATION_PATH')))
const newItem = $.NSURL.fileURLWithPath(ObjC.unwrap(env.objectForKey('NEW_ITEM_PATH')))
const bName = ObjC.unwrap(env.objectForKey('BACKUP_ITEM_NAME'))
const err = Ref()
const replaced = $.NSFileManager.defaultManager.replaceItemAtURLWithItemAtURLBackupItemNameOptionsResultingItemURLError(
  dest, newItem, bName, $.NSFileManagerItemReplacementWithoutDeletingBackupItem, Ref(), err)
if (!replaced) throw new Error(err[0] ? ObjC.unwrap(err[0].localizedDescription) : 'replace failed')
JAVASCRIPT
  else
    ditto ${app_bundle} ${destination}
  fi

  # Copy sidecars
  for suffix in .sha3 .skein .khsig .sha3.khsig .skein.khsig; do
    if [[ -f ${app_bundle}${suffix} ]]; then
      ditto ${app_bundle}${suffix} ${destination}${suffix}
    fi
  done

  # Verify installed scanner
  if ! ${repo_root}/tools/Verify-QR-Scanner-macOS.sh --app ${destination} --allow-development; then
    print -u2 "Installed QR-Scanner verification failed; restoring previous version..."
    if (( has_existing )) && [[ -d ${backup_dir}/QR-Scanner.app ]]; then
      ditto ${backup_dir}/QR-Scanner.app ${destination}
      for suffix in .sha3 .skein .khsig .sha3.khsig .skein.khsig; do
        if [[ -f ${backup_dir}/QR-Scanner.app${suffix} ]]; then
          ditto ${backup_dir}/QR-Scanner.app${suffix} ${destination}${suffix}
        fi
      done
    fi
    exit 1
  fi

  chmod -R go+rX ${destination}
  /System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister \
    -f ${destination} > /dev/null 2>&1 || true
  print "installed=${destination}"
fi

print "bundle=${app_bundle}"
print "zip=${release_zip}"
