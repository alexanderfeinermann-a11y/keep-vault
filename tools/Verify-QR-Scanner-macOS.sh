#!/bin/zsh
set -euo pipefail

script_dir=${0:A:h}
repo_root=${script_dir:h}
expected_team='2T6K9PGS55'
expected_bundle='de.michael-feinermann.qr-scanner'
app_path=''
allow_development=0
require_notarization=0
mldsa_public_key=${KEEPVAULT_MLDSA_PUBLIC_KEY:-${repo_root}/KeepVaultMac/Packaging/Keys/mldsa87-public.key}
dotnet_command=${KEEPVAULT_DOTNET:-/Users/michael/.dotnet-keepvault/dotnet}
expected_signer_lock_sha256='B07635B8B5CF158644267CBB99E6483D6F947F37D3B9918B4FF39407EB6BA5EB'

usage() {
  print -u2 'Usage: Verify-QR-Scanner-macOS.sh --app "QR-Scanner.app" [--allow-development]'
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
  print -u2 "QR-Scanner app bundle is missing, not a directory, or a symbolic link: ${app_path}"
  exit 1
fi

if find ${app_path} -type l -print -quit | grep -q .; then
  print -u2 'The QR-Scanner bundle contains a symbolic link and is rejected.'
  exit 1
fi

if find ${app_path} -type f -links +1 -print -quit | grep -q .; then
  print -u2 'The QR-Scanner bundle contains hard-linked files and is rejected.'
  exit 1
fi

info_plist=${app_path}/Contents/Info.plist
if [[ ! -f ${info_plist} || -L ${info_plist} ]]; then
  print -u2 "Info.plist is missing from the QR-Scanner bundle: ${app_path}"
  exit 1
fi

bundle_id=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' ${info_plist} 2>/dev/null || true)
if [[ ${bundle_id} != ${expected_bundle} ]]; then
  print -u2 "The QR-Scanner bundle identifier '${bundle_id}' does not match '${expected_bundle}'."
  exit 1
fi

scanner_binary=${app_path}/Contents/MacOS/QR-Scanner
if [[ ! -f ${scanner_binary} || -L ${scanner_binary} || ! -x ${scanner_binary} ]]; then
  print -u2 "QR-Scanner executable is missing or not executable: ${scanner_binary}"
  exit 1
fi

# Apple Code Signature & Team verification
if ! codesign -v --strict ${app_path}; then
  print -u2 'Apple code-signature validity check failed on QR-Scanner.'
  exit 1
fi

app_signature=$(codesign -dvvv ${app_path} 2>&1)
if [[ ${app_signature} == *"TeamIdentifier=${expected_team}"* ]]; then
  print "team_id=${expected_team}"
elif (( allow_development )) && [[ ${app_signature} == *'Authority=Apple Development:'* ]]; then
  print 'team_id=development (accepted by --allow-development)'
else
  print -u2 "The QR-Scanner is not signed with pinned Team ID ${expected_team}."
  exit 1
fi

# Verify Hardened Runtime and Entitlements
if [[ ${app_signature} != *'flags='*'runtime'* ]]; then
  print -u2 'The QR-Scanner is missing the hardened runtime flag.'
  exit 1
fi

if ! codesign -d --entitlements - ${app_path} >/dev/null 2>&1; then
  print -u2 'Could not read entitlements from QR-Scanner.'
  exit 1
fi

entitlements_xml=$(mktemp "${TMPDIR:-/tmp}/qr-scanner-entitlements.XXXXXX")
cleanup() { rm -f -- ${entitlements_xml}; }
trap cleanup EXIT INT TERM

codesign -d --entitlements :${entitlements_xml} ${app_path} >/dev/null 2>&1

sandbox_val=$(/usr/libexec/PlistBuddy -c 'Print :com.apple.security.app-sandbox' ${entitlements_xml} 2>/dev/null || true)
camera_val=$(/usr/libexec/PlistBuddy -c 'Print :com.apple.security.device.camera' ${entitlements_xml} 2>/dev/null || true)

if [[ ${sandbox_val} != 'true' ]]; then
  print -u2 'The QR-Scanner is missing mandatory entitlement: com.apple.security.app-sandbox'
  exit 1
fi

if [[ ${camera_val} != 'true' ]]; then
  print -u2 'The QR-Scanner is missing mandatory entitlement: com.apple.security.device.camera'
  exit 1
fi

disallowed_entitlements=(
  com.apple.security.get-task-allow
  com.apple.security.cs.allow-jit
  com.apple.security.cs.allow-unsigned-executable-memory
  com.apple.security.cs.disable-library-validation
  com.apple.security.cs.disable-executable-page-protection
  com.apple.security.cs.allow-dyld-environment-variables
  com.apple.security.cs.allow-relative-library-loads
  com.apple.security.cs.debugger
  com.apple.security.network.client
  com.apple.security.network.server
  com.apple.security.device.audio-input
  com.apple.security.device.usb
  com.apple.security.device.bluetooth
  com.apple.security.automation.apple-events
)

for disallowed in ${disallowed_entitlements[@]}; do
  if /usr/libexec/PlistBuddy -c "Print :${disallowed}" ${entitlements_xml} >/dev/null 2>&1; then
    print -u2 "Disallowed entitlement is present in QR-Scanner: ${disallowed}"
    exit 1
  fi
done

# Verify five hybrid integrity sidecars beside the app
for suffix in .sha3 .skein .khsig .sha3.khsig .skein.khsig; do
  sidecar=${app_path}${suffix}
  if [[ ! -f ${sidecar} || -L ${sidecar} ]]; then
    print -u2 "Required hybrid signature sidecar is missing from QR-Scanner: ${sidecar}"
    exit 1
  fi
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

  scanner_stage=$(mktemp -d "${TMPDIR:-/tmp}/qr-scanner-verify.XXXXXXXX")
  ditto ${scanner_binary} ${scanner_stage}/QR-Scanner
  for suffix in .sha3 .skein .khsig .sha3.khsig .skein.khsig; do
    ditto ${app_path}${suffix} ${scanner_stage}/QR-Scanner${suffix}
  done
  scanner_status=0
  (
    cd ${repo_root}/KeepVaultMac
    ${dotnet_command} ${signer_dll} verify \
      --mldsa-public-key ${mldsa_public_key} \
      --policy ${repo_root}/KeepVaultMac/Directory.Build.props \
      --target ${scanner_stage}/QR-Scanner
  ) || scanner_status=$?
  rm -rf -- ${scanner_stage}
  (( scanner_status == 0 )) || exit ${scanner_status}
  print 'scanner_hybrid_signature=verified'
else
  print -u2 'The independent managed hybrid verifier or pinned ML-DSA public key is unavailable for QR-Scanner.'
  exit 1
fi

if spctl --assess --type execute --verbose=4 ${app_path}; then
  print 'scanner_gatekeeper=accepted'
else
  if (( allow_development )) && [[ ${app_signature} == *'Authority=Apple Development:'* ]]; then
    print 'scanner_gatekeeper=not_accepted (expected for local Apple Development signing)'
  else
    print -u2 'Gatekeeper did not accept the QR-Scanner bundle.'
    exit 1
  fi
fi

if (( require_notarization )); then
  xcrun stapler validate ${app_path}
  print 'scanner_notarization=stapled-and-valid'
fi

print "scanner_verified=${app_path}"
