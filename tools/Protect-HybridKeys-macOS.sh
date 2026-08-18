#!/bin/zsh
# Puts the hybrid signing certificate behind one Keychain confirmation.
#
# A hybrid signature is a single decision: it counts only when RSA-PSS and
# ML-DSA-87 both verify, so releasing one half without the other buys nothing.
# Both halves therefore sit under the same 32-byte wrapping key, and one
# confirmation covers the certificate as a whole rather than two covering
# halves of it.
#
# Before this the two halves were protected unevenly. The RSA PFX was a
# password-protected container, but its password was handed out by the Keychain
# with no prompt at all -- measured, not assumed. The ML-DSA key was a raw
# 4896-byte file: whoever copied it had the post-quantum half outright.
#
# What this buys: neither file is useful once it leaves the machine -- in a Time
# Machine backup, on a cloned disk, inside a tar of the home directory.
#
# What it does not buy: protection from malware running as the same user, which
# can ask the Keychain the way the signer does. The Keychain item is therefore
# created with NO trusted application, so every read prompts. A use nobody
# started becomes visible instead of silent.
#
# Wrapping and unwrapping are the signer's own code, so the two cannot drift
# apart, and the PFX password is read inside the signer straight from the old
# Keychain item -- never on a command line, where any process could read it out
# of the process list.
#
# Nothing is deleted here. The script prints what to remove once a real signing
# run has succeeded and a backup exists off this machine.
set -euo pipefail

script_dir=${0:A:h}
repo_root=${script_dir:h}
mac_project=${repo_root}/KeepVaultMac
packaging_dir=${mac_project}/Packaging
dotnet_command=${KEEPVAULT_DOTNET:-${HOME}/.dotnet-keepvault/dotnet}

key_root=${KEEPVAULT_RELEASE_KEYS:-${HOME}/Library/Application Support/Keep Vault/ReleaseKeys}
plain_key=${KEEPVAULT_MLDSA_PRIVATE_KEY:-${key_root}/mldsa87-private.key}
envelope=${KEEPVAULT_MLDSA_PRIVATE_KEY_ENCRYPTED:-${key_root}/mldsa87-private.key.enc}
pfx_envelope=${KEEPVAULT_PFX_PASSWORD_ENCRYPTED:-${key_root}/hybrid-rsa4096.pfx.password.enc}
service=${KEEPVAULT_MLDSA_KEYCHAIN_SERVICE:-de.michael-feinermann.keep-vault.hybrid-wrapping-key}
account=${KEEPVAULT_MLDSA_KEYCHAIN_ACCOUNT:-${USER}}
pfx_service=${KEEPVAULT_PFX_KEYCHAIN_SERVICE:-de.michael-feinermann.keep-vault.hybrid-pfx}
pfx_account=${KEEPVAULT_PFX_KEYCHAIN_ACCOUNT:-${USER}}

if [[ ! -f ${plain_key} || -L ${plain_key} ]]; then
  print -u2 "The plaintext ML-DSA-87 private key was not found: ${plain_key}"
  print -u2 'It is still needed to create the envelope; nothing can be recovered without it.'
  exit 1
fi

# Re-runnable: a half that is already wrapped is skipped rather than refused.
wrap_mldsa=1
if [[ -e ${envelope} ]]; then
  print "mldsa_envelope=already present"
  wrap_mldsa=0
fi
wrap_pfx=1
if [[ -e ${pfx_envelope} ]]; then
  print "pfx_envelope=already present"
  wrap_pfx=0
fi
if (( ! wrap_mldsa && ! wrap_pfx )); then
  print 'Both halves are already wrapped; nothing to do.'
  exit 0
fi

signer_dll=${packaging_dir}/HybridSigner/bin/Release/net10.0/KeepVaultMac.HybridSigner.dll
if [[ ! -f ${signer_dll} || -L ${signer_dll} ]]; then
  (
    cd ${mac_project}
    ${dotnet_command} build Packaging/HybridSigner/KeepVaultMac.HybridSigner.csproj -c Release --nologo
  )
fi

# 32 random bytes used directly as the AES-256 key. Nothing here is a
# human-chosen password, so a password-based derivation would add cost without
# adding entropy.
#
# -T with an empty list means no application is pre-trusted, so every read
# prompts. Answer "Allow", not "Always Allow": the latter writes the asking
# binary into the item's ACL and the prompt stops, which is the whole property
# this exists to provide.
if /usr/bin/security find-generic-password -s ${service} -a ${account} >/dev/null 2>&1; then
  print "keychain_item=${service} (reusing the existing one)"
else
  /usr/bin/security add-generic-password \
    -s ${service} \
    -a ${account} \
    -w "$(/usr/bin/openssl rand -base64 32)" \
    -T '' \
    -U \
    -D 'Keep Vault hybrid signing wrapping key' \
    -j 'Releases both halves of the hybrid signing certificate. Every prompt should be one you started.'
  print "keychain_item=${service} (created)"
fi

if (( wrap_mldsa )); then
  (
    cd ${mac_project}
    ${dotnet_command} ${signer_dll} wrap-mldsa-key \
      --mldsa-private-key ${plain_key} \
      --mldsa-private-key-encrypted ${envelope} \
      --mldsa-key-keychain-service ${service} \
      --mldsa-key-keychain-account ${account}
  )
fi

if (( wrap_pfx )); then
  (
    cd ${mac_project}
    ${dotnet_command} ${signer_dll} wrap-pfx-password \
      --pfx-password-encrypted ${pfx_envelope} \
      --pfx-password-keychain-service ${pfx_service} \
      --pfx-keychain-account ${pfx_account} \
      --mldsa-key-keychain-service ${service} \
      --mldsa-key-keychain-account ${account}
  )
fi

print ''
print 'Nothing was deleted. Run one real signing build first, and make sure a'
print 'backup of the ML-DSA key exists off this machine. Then remove the two'
print 'unprotected originals:'
print ''
print "  rm -P \"${plain_key}\""
print "  security delete-generic-password -s ${pfx_service} -a ${pfx_account}"
print ''
print 'Keep that backup: the six fingerprints compiled into every published'
print 'build point at these keys, and no others can replace them.'
