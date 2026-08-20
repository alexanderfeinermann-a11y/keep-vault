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

if (( install_app )); then
  destination=/Applications/${app_name}.app
  if [[ -e ${destination} ]]; then
    rm -rf ${destination}
  fi
  ditto ${app_bundle} ${destination}
  # The umask at the top of this script keeps build output private, which is
  # right for a build directory and wrong for /Applications: an app there is
  # readable by every account on the Mac. Restore that, without granting write
  # access to anyone but the owner.
  chmod -R go+rX ${destination}
  # LaunchServices is told about the bundle directly, so it appears in Finder,
  # Spotlight and Launchpad now instead of whenever the next scan happens to
  # run.
  /System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister \
    -f ${destination} > /dev/null 2>&1 || true
  print "installed=${destination}"
fi

print "bundle=${app_bundle}"
print "zip=${release_zip}"
