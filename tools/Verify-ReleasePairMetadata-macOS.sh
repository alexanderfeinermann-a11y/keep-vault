#!/bin/zsh
set -euo pipefail

expected_keep_vault_identifier='de.michael-feinermann.keep-vault'
expected_scanner_identifier='de.michael-feinermann.qr-scanner'
keep_vault_app=''
scanner_app=''

usage() {
  print -u2 'Usage: Verify-ReleasePairMetadata-macOS.sh --app "Keep Vault.app" --scanner "QR-Scanner.app"'
  exit 64
}

while (( $# != 0 )); do
  case $1 in
    --app) (( $# >= 2 )) || usage; keep_vault_app=$2; shift 2 ;;
    --scanner) (( $# >= 2 )) || usage; scanner_app=$2; shift 2 ;;
    *) usage ;;
  esac
done

for bundle in ${keep_vault_app} ${scanner_app}; do
  if [[ -z ${bundle} || ! -d ${bundle} || -L ${bundle} ]]; then
    print -u2 "Release companion bundle is missing, not a directory, or a symbolic link: ${bundle:-<unset>}"
    exit 1
  fi
  if [[ ! -f ${bundle}/Contents/Info.plist || -L ${bundle}/Contents/Info.plist ]]; then
    print -u2 "Release companion Info.plist is missing or a symbolic link: ${bundle}"
    exit 1
  fi
  plutil -lint ${bundle}/Contents/Info.plist >/dev/null
done

plist_value() {
  local bundle=$1
  local key=$2
  /usr/libexec/PlistBuddy -c "Print :${key}" ${bundle}/Contents/Info.plist
}

[[ $(plist_value ${keep_vault_app} CFBundleIdentifier) == ${expected_keep_vault_identifier} ]] || {
  print -u2 'The Keep Vault release bundle identifier is incorrect.'
  exit 1
}
[[ $(plist_value ${scanner_app} CFBundleIdentifier) == ${expected_scanner_identifier} ]] || {
  print -u2 'The QR-Scanner release bundle identifier is incorrect.'
  exit 1
}

keep_vault_version=$(plist_value ${keep_vault_app} CFBundleShortVersionString)
keep_vault_build=$(plist_value ${keep_vault_app} CFBundleVersion)
scanner_version=$(plist_value ${scanner_app} CFBundleShortVersionString)
scanner_build=$(plist_value ${scanner_app} CFBundleVersion)
for numeric_value in ${keep_vault_version} ${scanner_version}; do
  [[ ${numeric_value} =~ '^[0-9]+([.][0-9]+){1,2}$' ]] || {
    print -u2 'A release companion has an invalid marketing version.'
    exit 1
  }
done
for numeric_value in ${keep_vault_build} ${scanner_build}; do
  [[ ${numeric_value} =~ '^[1-9][0-9]*$' ]] || {
    print -u2 'A release companion has an invalid build number.'
    exit 1
  }
done

if [[ ${keep_vault_version} != ${scanner_version} || ${keep_vault_build} != ${scanner_build} ]]; then
  print -u2 "Release companion version mismatch: Keep Vault ${keep_vault_version} (${keep_vault_build}), QR-Scanner ${scanner_version} (${scanner_build})."
  exit 1
fi

print "release_pair_version=${keep_vault_version}"
print "release_pair_build=${keep_vault_build}"
