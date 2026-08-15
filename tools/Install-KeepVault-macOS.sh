#!/bin/zsh
set -euo pipefail

script_dir=${0:A:h}
repo_root=${script_dir:h}
source_app=${repo_root}/dist/Keep\ Vault-macOS/Keep\ Vault.app
applications_dir='/Applications'
create_desktop_alias=1

usage() {
  print -u2 'Usage: Install-KeepVault-macOS.sh [--app "Keep Vault.app"]'
  print -u2 '       [--applications-dir /Applications] [--no-desktop-alias]'
  exit 64
}

while (( $# != 0 )); do
  case $1 in
    --app)
      (( $# >= 2 )) || usage
      source_app=$2
      shift 2
      ;;
    --applications-dir)
      (( $# >= 2 )) || usage
      applications_dir=$2
      shift 2
      ;;
    --no-desktop-alias)
      create_desktop_alias=0
      shift
      ;;
    *) usage ;;
  esac
done

if (( EUID == 0 )); then
  print -u2 'Do not run this installer with sudo. It must create the Finder alias for the signed-in user.'
  exit 1
fi
if [[ ! -d ${source_app} || -L ${source_app} ]]; then
  print -u2 "Keep Vault app bundle not found or is a symbolic link: ${source_app}"
  exit 1
fi
source_app=${source_app:A}
if [[ ${source_app} != ${repo_root}/* ]]; then
  print -u2 "The install source must remain inside the Keep Vault workspace: ${source_app}"
  exit 1
fi
applications_dir=${applications_dir:A}
if [[ ! -d ${applications_dir} || -L ${applications_dir} || ! -w ${applications_dir} ]]; then
  print -u2 "Applications directory is unavailable, a symbolic link, or not writable: ${applications_dir}"
  exit 1
fi

desktop_dir=''
alias_path=''
if (( create_desktop_alias )); then
  desktop_dir=$(osascript -l JavaScript -e 'ObjC.import("Foundation"); ObjC.unwrap($.NSFileManager.defaultManager.URLsForDirectoryInDomains(12, 1).firstObject.path)')
  if [[ ! -d ${desktop_dir} || -L ${desktop_dir} ]]; then
    print -u2 "Desktop directory is unavailable or a symbolic link: ${desktop_dir}"
    exit 1
  fi
  alias_path=${desktop_dir}/Keep\ Vault
  if [[ -e ${alias_path} || -L ${alias_path} ]]; then
    if [[ -L ${alias_path} || -d ${alias_path} || $(file -b ${alias_path}) != 'MacOS Alias file' ]]; then
      print -u2 "Refusing to overwrite a non-Finder-alias Desktop object: ${alias_path}"
      exit 1
    fi
  fi
fi

${script_dir}/Verify-KeepVault-macOS.sh --app ${source_app} --allow-development

install_root=$(mktemp -d "${applications_dir}/.keep-vault-install.XXXXXXXX")
staged_app=${install_root}/Keep\ Vault.app
temporary_alias_path=''
cleanup() {
  if [[ -n ${install_root:-} && -d ${install_root} && ${install_root} == ${applications_dir}/.keep-vault-install.* ]]; then
    rm -rf -- ${install_root}
  fi
  if [[ -n ${temporary_alias_path:-} && -f ${temporary_alias_path} && ! -L ${temporary_alias_path} ]]; then
    rm -- ${temporary_alias_path}
  fi
}
trap cleanup EXIT INT TERM

ditto ${source_app} ${staged_app}
${script_dir}/Verify-KeepVault-macOS.sh --app ${staged_app} --allow-development

destination=${applications_dir}/Keep\ Vault.app
backup_name=.Keep\ Vault.previous.$(date -u +%Y%m%dT%H%M%SZ).app
backup_path=${applications_dir}/${backup_name}

atomic_replace() {
  local old_path=$1
  local new_path=$2
  local retained_backup_name=$3
  DESTINATION_PATH=${old_path} NEW_ITEM_PATH=${new_path} BACKUP_ITEM_NAME=${retained_backup_name} \
    osascript -l JavaScript <<'JAVASCRIPT'
ObjC.import('Foundation')
const environment = $.NSProcessInfo.processInfo.environment
const destination = $.NSURL.fileURLWithPath(ObjC.unwrap(environment.objectForKey('DESTINATION_PATH')))
const newItem = $.NSURL.fileURLWithPath(ObjC.unwrap(environment.objectForKey('NEW_ITEM_PATH')))
const backupName = ObjC.unwrap(environment.objectForKey('BACKUP_ITEM_NAME'))
const result = Ref()
const error = Ref()
const options = $.NSFileManagerItemReplacementWithoutDeletingBackupItem
const replaced = $.NSFileManager.defaultManager.replaceItemAtURLWithItemAtURLBackupItemNameOptionsResultingItemURLError(
  destination,
  newItem,
  backupName,
  options,
  result,
  error)
if (!replaced) {
  const description = error[0] ? ObjC.unwrap(error[0].localizedDescription) : 'unknown replacement error'
  throw new Error(description)
}
JAVASCRIPT
}

if [[ -e ${destination} || -L ${destination} ]]; then
  if [[ ! -d ${destination} || -L ${destination} ]]; then
    print -u2 "Refusing to replace a non-app object or symbolic link: ${destination}"
    exit 1
  fi
  existing_identifier=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' ${destination}/Contents/Info.plist 2>/dev/null || true)
  if [[ ${existing_identifier} != de.michael-feinermann.keep-vault ]]; then
    print -u2 'The existing application does not have the Keep Vault bundle identifier and will not be replaced.'
    exit 1
  fi
  atomic_replace ${destination} ${staged_app} ${backup_name}
else
  mv ${staged_app} ${destination}
fi

if ! ${script_dir}/Verify-KeepVault-macOS.sh --app ${destination} --allow-development; then
  if [[ -d ${backup_path} && ! -L ${backup_path} ]]; then
    failed_name=.Keep\ Vault.failed.$(date -u +%Y%m%dT%H%M%SZ).app
    if atomic_replace ${destination} ${backup_path} ${failed_name}; then
      print -u2 'The new installation failed verification and the previous Keep Vault app was restored.'
    else
      print -u2 "CRITICAL: installation verification and automatic rollback both failed. Backup: ${backup_path}"
    fi
  elif [[ -d ${destination} && ! -L ${destination} ]]; then
    failed_destination=${HOME}/.Trash/Keep\ Vault\ failed\ $(date -u +%Y%m%dT%H%M%SZ).app
    mkdir -p ${HOME}/.Trash
    mv ${destination} ${failed_destination} || true
    print -u2 "The failed first installation was moved to: ${failed_destination}"
  fi
  exit 1
fi

recovery_path=''
if [[ -d ${backup_path} && ! -L ${backup_path} ]]; then
  trash_dir=${HOME}/.Trash
  mkdir -p ${trash_dir}
  recovery_path=${trash_dir}/Keep\ Vault\ previous\ $(date -u +%Y%m%dT%H%M%SZ).app
  if ! mv ${backup_path} ${recovery_path}; then
    recovery_path=${backup_path}
  fi
fi

launch_services='/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister'
${launch_services} -f ${destination}

if (( create_desktop_alias )); then
  temporary_alias_name=.Keep\ Vault.$RANDOM.$$.alias
  temporary_alias_path=${desktop_dir}/${temporary_alias_name}
  APP_TARGET=${destination} ALIAS_DIR=${desktop_dir} ALIAS_NAME=${temporary_alias_name} \
    osascript <<'APPLESCRIPT'
set targetPath to system attribute "APP_TARGET"
set destinationPath to system attribute "ALIAS_DIR"
set requestedName to system attribute "ALIAS_NAME"
tell application "Finder"
  set createdAlias to make new alias file at POSIX file destinationPath to POSIX file targetPath
  set name of createdAlias to requestedName
end tell
APPLESCRIPT
  if [[ ! -f ${temporary_alias_path} || -L ${temporary_alias_path} || $(file -b ${temporary_alias_path}) != 'MacOS Alias file' ]]; then
    print -u2 'Finder did not create a valid Keep Vault alias.'
    exit 1
  fi
  mv -f ${temporary_alias_path} ${alias_path}
  resolved_alias=$(ALIAS_PATH=${alias_path} osascript <<'APPLESCRIPT'
set aliasPath to system attribute "ALIAS_PATH"
tell application "Finder"
  -- "original item" yields a Finder object reference, and POSIX path cannot be
  -- read from one directly; coerce it to an alias first.
  set originalItem to original item of (POSIX file aliasPath as alias)
  return POSIX path of (originalItem as alias)
end tell
APPLESCRIPT
)
  [[ ${resolved_alias%/} == ${destination%/} ]] || {
    print -u2 'The Desktop Finder alias does not resolve to the installed Keep Vault app.'
    exit 1
  }
  print "desktop_alias=${alias_path}"
fi

print "installed_app=${destination}"
[[ -z ${recovery_path} ]] || print "previous_version_recoverable_at=${recovery_path}"
