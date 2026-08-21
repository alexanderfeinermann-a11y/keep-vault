#!/bin/zsh
set -euo pipefail

script_dir=${0:A:h}
repo_root=${script_dir:h}
source_app=''
applications_dir='/Applications'
create_desktop_alias=1
allow_development=0

usage() {
  print -u2 'Usage: Install-KeepVault-macOS.sh [--app "Keep Vault.app"] [--development]'
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
    --development)
      allow_development=1
      shift
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

# ACQUIRE EXCLUSIVE INSTALLATION LOCK
lock_file="${TMPDIR:-/tmp}/keep-vault-install.lock"
if ! shlock -f "${lock_file}" -p $$; then
  print -u2 'Another Keep Vault installation is currently in progress.'
  exit 1
fi

release_lock() {
  rm -f -- "${lock_file}"
}

if [[ -z ${source_app} ]]; then
  dist_candidate=${repo_root}/dist/Keep\ Vault-macOS/Keep\ Vault.app
  dev_candidate=${repo_root}/build/dev/Keep\ Vault-macOS/Keep\ Vault.app
  if (( allow_development )); then
    if [[ -d ${dev_candidate} ]]; then
      source_app=${dev_candidate}
    else
      source_app=${dist_candidate}
    fi
  else
    source_app=${dist_candidate}
  fi
fi

if (( EUID == 0 )); then
  release_lock
  print -u2 'Do not run this installer with sudo. It must create the Finder alias for the signed-in user.'
  exit 1
fi
if [[ ! -d ${source_app} || -L ${source_app} ]]; then
  release_lock
  print -u2 "Keep Vault app bundle not found or is a symbolic link: ${source_app}"
  exit 1
fi
source_app=${source_app:A}
if [[ ${source_app} != ${repo_root}/* ]]; then
  release_lock
  print -u2 "The install source must remain inside the Keep Vault workspace: ${source_app}"
  exit 1
fi
applications_dir=${applications_dir:A}
if [[ ! -d ${applications_dir} || -L ${applications_dir} || ! -w ${applications_dir} ]]; then
  release_lock
  print -u2 "Applications directory is unavailable, a symbolic link, or not writable: ${applications_dir}"
  exit 1
fi

desktop_dir=''
alias_path=''
if (( create_desktop_alias )); then
  desktop_dir=$(osascript -l JavaScript -e 'ObjC.import("Foundation"); ObjC.unwrap($.NSFileManager.defaultManager.URLsForDirectoryInDomains(12, 1).firstObject.path)')
  if [[ ! -d ${desktop_dir} || -L ${desktop_dir} ]]; then
    release_lock
    print -u2 "Desktop directory is unavailable or a symbolic link: ${desktop_dir}"
    exit 1
  fi
  alias_path=${desktop_dir}/Keep\ Vault
  if [[ -e ${alias_path} || -L ${alias_path} ]]; then
    if [[ -L ${alias_path} || -d ${alias_path} || $(file -b ${alias_path}) != 'MacOS Alias file' ]]; then
      release_lock
      print -u2 "Refusing to overwrite a non-Finder-alias Desktop object: ${alias_path}"
      exit 1
    fi
  fi
fi

install_root=$(mktemp -d "${applications_dir}/.keep-vault-install.XXXXXXXX")
staged_app=${install_root}/Keep\ Vault.app
backup_dir=${install_root}/backup
mkdir -p ${backup_dir}
temporary_alias_path=''

destination=${applications_dir}/Keep\ Vault.app
backup_name=.Keep\ Vault.previous.$(date -u +%Y%m%dT%H%M%SZ).app
backup_path=${applications_dir}/${backup_name}

scanner_destination=${applications_dir}/QR-Scanner.app
scanner_backup_name=.QR-Scanner.previous.$(date -u +%Y%m%dT%H%M%SZ).app
scanner_backup_path=${applications_dir}/${scanner_backup_name}

has_existing_installation=0
has_existing_scanner=0
transaction_active=0
transaction_committed=0
anchor_updated=0
had_existing_anchor=0
recorded_version=0
rollback_failed=0

anchor_directory='/Library/Application Support/Keep Vault'
anchor_path=${anchor_directory}/minimum-version

if [[ -e ${anchor_path} || -L ${anchor_path} ]]; then
  if [[ -L ${anchor_path} || ! -f ${anchor_path} ]]; then
    release_lock
    print -u2 "The machine-wide rollback anchor is corrupted or a symlink: ${anchor_path}"
    exit 1
  fi
  if [[ -L ${anchor_directory} || ! -d ${anchor_directory} ]]; then
    release_lock
    print -u2 "The rollback anchor directory is invalid or a symlink: ${anchor_directory}"
    exit 1
  fi
  anchor_dir_uid=$(stat -f '%u' ${anchor_directory} 2>/dev/null || print -1)
  anchor_dir_mode=$(stat -f '%Lp' ${anchor_directory} 2>/dev/null || print 0)
  if (( anchor_dir_uid != 0 || (8#${anchor_dir_mode} & 8#022) != 0 )); then
    release_lock
    print -u2 "The rollback anchor directory has insecure owner/permissions: ${anchor_directory}"
    exit 1
  fi
  anchor_uid=$(stat -f '%u' ${anchor_path} 2>/dev/null || print -1)
  anchor_links=$(stat -f '%l' ${anchor_path} 2>/dev/null || print 0)
  anchor_mode=$(stat -f '%Lp' ${anchor_path} 2>/dev/null || print 0)
  if (( anchor_uid != 0 || anchor_links != 1 || (8#${anchor_mode} & 8#022) != 0 )); then
    release_lock
    print -u2 "The rollback anchor file has insecure owner/permissions or multiple links: ${anchor_path}"
    exit 1
  fi
  had_existing_anchor=1
  recorded_version=$(<${anchor_path})
  if [[ ! ${recorded_version} =~ '^[0-9]+$' ]]; then
    release_lock
    print -u2 "The machine-wide rollback anchor contains non-numeric version: ${recorded_version}"
    exit 1
  fi
fi

execute_rollback() {
  if (( transaction_active && !transaction_committed )); then
    transaction_active=0
    set +e
    print -u2 'Installation incomplete or verification failed; executing unified rollback transaction...'
    rollback_errors=()

    # Rollback Keep Vault
    if (( has_existing_installation )) && [[ -d ${backup_path} && ! -L ${backup_path} ]]; then
      failed_name=.Keep\ Vault.failed.$(date -u +%Y%m%dT%H%M%SZ).app
      if ! atomic_replace ${destination} ${backup_path} ${failed_name}; then
        rollback_errors+=("Failed to restore previous Keep Vault app bundle from ${backup_path}")
      fi
      for launcher_sidecar_suffix in .sha3 .skein .khsig .sha3.khsig .skein.khsig; do
        if [[ -f ${backup_dir}/Keep\ Vault.app.launcher${launcher_sidecar_suffix} ]]; then
          if ! ditto ${backup_dir}/Keep\ Vault.app.launcher${launcher_sidecar_suffix} \
            ${applications_dir}/Keep\ Vault.app.launcher${launcher_sidecar_suffix}; then
            rollback_errors+=("Failed to restore launcher signature ${launcher_sidecar_suffix}")
          fi
        fi
      done
      print -u2 'Previous Keep Vault app and launcher signatures restore attempted.'
    elif [[ -d ${destination} && ! -L ${destination} ]]; then
      rm -rf -- ${destination}
      for launcher_sidecar_suffix in .sha3 .skein .khsig .sha3.khsig .skein.khsig; do
        rm -f -- ${applications_dir}/Keep\ Vault.app.launcher${launcher_sidecar_suffix}
      done
    fi

    # Rollback QR-Scanner
    if (( install_scanner )); then
      if (( has_existing_scanner )) && [[ -d ${scanner_backup_path} && ! -L ${scanner_backup_path} ]]; then
        scanner_failed_name=.QR-Scanner.failed.$(date -u +%Y%m%dT%H%M%SZ).app
        if ! atomic_replace ${scanner_destination} ${scanner_backup_path} ${scanner_failed_name}; then
          rollback_errors+=("Failed to restore previous QR-Scanner app bundle from ${scanner_backup_path}")
        fi
        for scanner_sidecar_suffix in .sha3 .skein .khsig .sha3.khsig .skein.khsig; do
          if [[ -f ${backup_dir}/QR-Scanner.app${scanner_sidecar_suffix} ]]; then
            if ! ditto ${backup_dir}/QR-Scanner.app${scanner_sidecar_suffix} \
              ${applications_dir}/QR-Scanner.app${scanner_sidecar_suffix}; then
              rollback_errors+=("Failed to restore scanner signature ${scanner_sidecar_suffix}")
            fi
          fi
        done
        print -u2 'Previous QR-Scanner app and signatures restore attempted.'
      elif [[ -d ${scanner_destination} && ! -L ${scanner_destination} ]]; then
        rm -rf -- ${scanner_destination}
        for scanner_sidecar_suffix in .sha3 .skein .khsig .sha3.khsig .skein.khsig; do
          rm -f -- ${applications_dir}/QR-Scanner.app${scanner_sidecar_suffix}
        done
      fi
    fi

    # Rollback Anchor if modified
    if (( anchor_updated )); then
      if (( had_existing_anchor )); then
        ANCHOR_PATH=${anchor_path} PREV_VERSION=${recorded_version} osascript <<'APPLESCRIPT' || rollback_errors+=("Failed to restore rollback anchor")
set anchorPath to system attribute "ANCHOR_PATH"
set prevVersion to system attribute "PREV_VERSION"
set commandText to "/usr/bin/printf '%s' " & quoted form of prevVersion & " > " & quoted form of anchorPath
do shell script commandText with administrator privileges
APPLESCRIPT
      else
        ANCHOR_PATH=${anchor_path} osascript <<'APPLESCRIPT' || rollback_errors+=("Failed to remove rollback anchor")
set anchorPath to system attribute "ANCHOR_PATH"
set commandText to "/bin/rm -f " & quoted form of anchorPath
do shell script commandText with administrator privileges
APPLESCRIPT
      fi
    fi

    # Re-verify restored state if we had an existing installation
    if (( has_existing_installation )) && [[ -d ${destination} ]]; then
      rollback_kv_flags=(--app ${destination} --require-launcher-signature)
      (( allow_development )) && rollback_kv_flags+=(--allow-development)
      if ! ${script_dir}/Verify-KeepVault-macOS.sh ${rollback_kv_flags[@]} >/dev/null 2>&1; then
        rollback_errors+=("Restored Keep Vault app failed post-rollback verification.")
      fi
    fi

    if (( has_existing_scanner )) && [[ -d ${scanner_destination} ]]; then
      rollback_scanner_flags=(--app ${scanner_destination})
      (( allow_development )) && rollback_scanner_flags+=(--allow-development)
      if ! ${script_dir}/Verify-QR-Scanner-macOS.sh ${rollback_scanner_flags[@]} >/dev/null 2>&1; then
        rollback_errors+=("Restored QR-Scanner app failed post-rollback verification.")
      fi
    fi

    if (( ${#rollback_errors[@]} > 0 )); then
      rollback_failed=1
      print -u2 'CRITICAL: Rollback failed to completely restore the previous state!'
      for err in ${rollback_errors[@]}; do
        print -u2 "  - ${err}"
      done
      print -u2 "Backup directory preserved for manual recovery: ${backup_dir}"
      [[ -d ${backup_path} ]] && print -u2 "App backup preserved at: ${backup_path}"
      [[ -d ${scanner_backup_path} ]] && print -u2 "Scanner backup preserved at: ${scanner_backup_path}"
    else
      print -u2 'Rollback completed and restored state verified successfully.'
    fi
    set -e
  fi
}

cleanup() {
  execute_rollback
  if (( ! ${rollback_failed:-0} )); then
    if [[ -n ${install_root:-} && -d ${install_root} && ${install_root} == ${applications_dir}/.keep-vault-install.* ]]; then
      rm -rf -- ${install_root}
    fi
  else
    print -u2 "CRITICAL: Retaining installation root and backups at ${install_root} due to rollback failure."
  fi
  if [[ -n ${temporary_alias_path:-} && -f ${temporary_alias_path} && ! -L ${temporary_alias_path} ]]; then
    rm -- ${temporary_alias_path}
  fi
  release_lock
}
trap cleanup EXIT INT TERM

# 1. STAGE KEEP VAULT
ditto ${source_app} ${staged_app}

for launcher_sidecar_suffix in .sha3 .skein .khsig .sha3.khsig .skein.khsig; do
  launcher_sidecar=${source_app}.launcher${launcher_sidecar_suffix}
  if [[ ! -f ${launcher_sidecar} || -L ${launcher_sidecar} ]]; then
    print -u2 "The launcher self-signature is missing from the source: ${launcher_sidecar:t}"
    exit 1
  fi
  ditto ${launcher_sidecar} ${install_root}/Keep\ Vault.app.launcher${launcher_sidecar_suffix}
done

# Check if staged app is signed with Apple Development or Developer ID
staged_sig=$(codesign -dvvv ${staged_app} 2>&1 || true)
if [[ ${staged_sig} == *'Authority=Apple Development:'* ]]; then
  if (( ! allow_development )); then
    release_lock
    print -u2 'The staged Keep Vault app is signed with Apple Development, but --development was not specified.'
    exit 1
  fi
fi

kv_verify_flags=(--app ${staged_app} --require-launcher-signature)
(( allow_development )) && kv_verify_flags+=(--allow-development)
${script_dir}/Verify-KeepVault-macOS.sh ${kv_verify_flags[@]}

# 2. READ CANDIDATE VERSION FROM VERIFIED STAGED APP
candidate_version=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' ${staged_app}/Contents/Info.plist 2>/dev/null || true)
if [[ ! ${candidate_version} =~ '^[0-9]+$' ]]; then
  print -u2 "The candidate bundle has no valid numeric CFBundleVersion: ${candidate_version}"
  exit 1
fi

if (( candidate_version < recorded_version )); then
  print -u2 "Refusing to install version ${candidate_version} over the newer ${recorded_version} recorded on this machine."
  exit 1
fi

# 3. STAGE AND VERIFY QR-SCANNER
scanner_source=${source_app:h}/QR-Scanner.app
install_scanner=0
if [[ -d ${scanner_source} && ! -L ${scanner_source} ]]; then
  install_scanner=1
  for scanner_sidecar_suffix in .sha3 .skein .khsig .sha3.khsig .skein.khsig; do
    if [[ ! -f ${scanner_source}${scanner_sidecar_suffix} || -L ${scanner_source}${scanner_sidecar_suffix} ]]; then
      print -u2 "QR-Scanner.app has no ${scanner_sidecar_suffix} signature beside it and will not be installed."
      install_scanner=0
      break
    fi
  done
  if (( install_scanner )); then
    ditto ${scanner_source} ${install_root}/QR-Scanner.app
    for scanner_sidecar_suffix in .sha3 .skein .khsig .sha3.khsig .skein.khsig; do
      ditto ${scanner_source}${scanner_sidecar_suffix} ${install_root}/QR-Scanner.app${scanner_sidecar_suffix}
    done

    scanner_verify_flags=(--app ${install_root}/QR-Scanner.app)
    (( allow_development )) && scanner_verify_flags+=(--allow-development)
    ${script_dir}/Verify-QR-Scanner-macOS.sh ${scanner_verify_flags[@]}
  fi
fi

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

# 4. BACK UP EXISTING INSTALLATION AND SIDECARS BEFORE ANY MUTATION
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
  has_existing_installation=1

  for launcher_sidecar_suffix in .sha3 .skein .khsig .sha3.khsig .skein.khsig; do
    existing_sidecar=${applications_dir}/Keep\ Vault.app.launcher${launcher_sidecar_suffix}
    if [[ -f ${existing_sidecar} && ! -L ${existing_sidecar} ]]; then
      ditto ${existing_sidecar} ${backup_dir}/Keep\ Vault.app.launcher${launcher_sidecar_suffix}
    fi
  done
fi

if (( install_scanner )) && [[ -e ${scanner_destination} || -L ${scanner_destination} ]]; then
  if [[ ! -d ${scanner_destination} || -L ${scanner_destination} ]]; then
    print -u2 "Refusing to replace a non-app object or symbolic link: ${scanner_destination}"
    exit 1
  fi
  existing_scanner_id=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' ${scanner_destination}/Contents/Info.plist 2>/dev/null || true)
  if [[ ${existing_scanner_id} != de.michael-feinermann.qr-scanner ]]; then
    print -u2 "Refusing to replace foreign application at ${scanner_destination} with identifier: ${existing_scanner_id}"
    exit 1
  fi
  has_existing_scanner=1

  for scanner_sidecar_suffix in .sha3 .skein .khsig .sha3.khsig .skein.khsig; do
    existing_scanner_sidecar=${applications_dir}/QR-Scanner.app${scanner_sidecar_suffix}
    if [[ -f ${existing_scanner_sidecar} && ! -L ${existing_scanner_sidecar} ]]; then
      ditto ${existing_scanner_sidecar} ${backup_dir}/QR-Scanner.app${scanner_sidecar_suffix}
    fi
  done
fi

# 5. BEGIN MUTATION TRANSACTION
transaction_active=1

# Execute installation of Keep Vault
if (( has_existing_installation )); then
  atomic_replace ${destination} ${staged_app} ${backup_name}
else
  mv ${staged_app} ${destination}
fi

for launcher_sidecar_suffix in .sha3 .skein .khsig .sha3.khsig .skein.khsig; do
  staged_sidecar=${install_root}/Keep\ Vault.app.launcher${launcher_sidecar_suffix}
  final_sidecar=${applications_dir}/Keep\ Vault.app.launcher${launcher_sidecar_suffix}
  mv -f -- ${staged_sidecar} ${final_sidecar}
done

# Execute installation of QR-Scanner
if (( install_scanner )); then
  for scanner_sidecar_suffix in .sha3 .skein .khsig .sha3.khsig .skein.khsig; do
    mv -f -- ${install_root}/QR-Scanner.app${scanner_sidecar_suffix} \
      ${applications_dir}/QR-Scanner.app${scanner_sidecar_suffix}
  done

  if (( has_existing_scanner )); then
    atomic_replace ${scanner_destination} ${install_root}/QR-Scanner.app ${scanner_backup_name}
  else
    mv ${install_root}/QR-Scanner.app ${scanner_destination}
  fi
  print "installed_scanner=${scanner_destination}"
fi

# Verify complete installation transaction
main_verification_passed=0
final_kv_verify_flags=(--app ${destination} --require-launcher-signature)
(( allow_development )) && final_kv_verify_flags+=(--allow-development)
if ${script_dir}/Verify-KeepVault-macOS.sh ${final_kv_verify_flags[@]}; then
  main_verification_passed=1
fi

scanner_verification_passed=1
if (( install_scanner )); then
  final_scanner_flags=(--app ${scanner_destination})
  (( allow_development )) && final_scanner_flags+=(--allow-development)
  if ! ${script_dir}/Verify-QR-Scanner-macOS.sh ${final_scanner_flags[@]}; then
    scanner_verification_passed=0
  fi
fi

if (( ! main_verification_passed || ! scanner_verification_passed )); then
  execute_rollback
  exit 1
fi

# Record this installation machine-wide as part of the commit transaction
installed_version=${candidate_version}

if (( installed_version > recorded_version )) || [[ ! -f ${anchor_path} ]]; then
  anchor_update_status=0
  ANCHOR_DIRECTORY=${anchor_directory} ANCHOR_PATH=${anchor_path} ANCHOR_VERSION=${installed_version} \
    osascript <<'APPLESCRIPT' || anchor_update_status=$?
set anchorDirectory to system attribute "ANCHOR_DIRECTORY"
set anchorPath to system attribute "ANCHOR_PATH"
set anchorVersion to system attribute "ANCHOR_VERSION"
set commandText to "/bin/mkdir -p " & quoted form of anchorDirectory & ¬
  " && /usr/sbin/chown root:wheel " & quoted form of anchorDirectory & ¬
  " && /bin/chmod 0755 " & quoted form of anchorDirectory & ¬
  " && /usr/bin/printf '%s' " & quoted form of anchorVersion & " > " & quoted form of anchorPath & ¬
  " && /usr/sbin/chown root:wheel " & quoted form of anchorPath & ¬
  " && /bin/chmod 0644 " & quoted form of anchorPath
do shell script commandText with administrator privileges
APPLESCRIPT
  anchor_owner=$(stat -f '%u' ${anchor_path} 2>/dev/null || print -1)
  if (( anchor_update_status != 0 )) || [[ ${anchor_owner} != 0 || $(<${anchor_path}) != ${installed_version} ]]; then
    print -u2 'The machine-wide installation record could not be written; rolling back installation.'
    execute_rollback
    exit 1
  fi
  anchor_updated=1
  print "rollback_anchor=${anchor_path} (${installed_version})"
else
  print "rollback_anchor=${anchor_path} (unveraendert ${recorded_version})"
fi

# COMMIT TRANSACTION
transaction_committed=1

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


