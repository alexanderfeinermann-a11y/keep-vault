#!/bin/zsh
# Moves the ML-DSA-87 release private key from a raw file into an encrypted
# envelope whose wrapping key lives in the login Keychain, gated by a prompt.
#
# The RSA half has always been a PKCS#12 container whose password sits in the
# Keychain, so copying that file alone gains nothing. The ML-DSA half was a raw
# 4896-byte key: whoever copied the file had the key. This closes that gap.
#
# What it buys: the file stops being useful once it leaves this machine -- in a
# Time Machine backup, on a cloned disk, inside a tar of the home directory.
#
# What it does not buy: protection from malware running as the same user, which
# can ask the Keychain exactly the way the signer does. The Keychain item is
# therefore created with NO trusted application, so every read prompts. A use
# nobody triggered becomes visible instead of silent.
#
# The wrapping and unwrapping code is the signer's own, so the two cannot drift
# apart. This script never deletes the plaintext key; it prints the command to
# remove it, so that step stays a deliberate one taken once a backup exists.
set -euo pipefail

script_dir=${0:A:h}
repo_root=${script_dir:h}
mac_project=${repo_root}/KeepVaultMac
packaging_dir=${mac_project}/Packaging
dotnet_command=${KEEPVAULT_DOTNET:-${HOME}/.dotnet-keepvault/dotnet}

key_root=${KEEPVAULT_RELEASE_KEYS:-${HOME}/Library/Application Support/Keep Vault/ReleaseKeys}
plain_key=${KEEPVAULT_MLDSA_PRIVATE_KEY:-${key_root}/mldsa87-private.key}
envelope=${KEEPVAULT_MLDSA_PRIVATE_KEY_ENCRYPTED:-${key_root}/mldsa87-private.key.enc}
service=${KEEPVAULT_MLDSA_KEYCHAIN_SERVICE:-de.michael-feinermann.keep-vault.mldsa-key}
account=${KEEPVAULT_MLDSA_KEYCHAIN_ACCOUNT:-${USER}}

if [[ ! -f ${plain_key} || -L ${plain_key} ]]; then
  print -u2 "The plaintext ML-DSA-87 private key was not found: ${plain_key}"
  exit 1
fi

if [[ -e ${envelope} ]]; then
  print -u2 "An envelope already exists and will not be overwritten: ${envelope}"
  print -u2 'Remove it deliberately if you intend to re-wrap the key.'
  exit 1
fi

if /usr/bin/security find-generic-password -s ${service} -a ${account} >/dev/null 2>&1; then
  print -u2 "A Keychain item already exists for service ${service}."
  print -u2 'Delete it deliberately before re-wrapping, or the old envelope becomes unreadable:'
  print -u2 "  security delete-generic-password -s ${service} -a ${account}"
  exit 1
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
/usr/bin/security add-generic-password \
  -s ${service} \
  -a ${account} \
  -w "$(/usr/bin/openssl rand -base64 32)" \
  -T '' \
  -U \
  -D 'Keep Vault ML-DSA-87 wrapping key' \
  -j 'Wraps the ML-DSA-87 release signing key. Every prompt should be one you started.'
print "keychain_item=${service} (${account})"

(
  cd ${mac_project}
  ${dotnet_command} ${signer_dll} wrap-mldsa-key \
    --mldsa-private-key ${plain_key} \
    --mldsa-private-key-encrypted ${envelope} \
    --mldsa-key-keychain-service ${service} \
    --mldsa-key-keychain-account ${account}
)

print ''
print 'The plaintext key was NOT deleted. Run one real signing build first, and'
print 'make sure a backup of the key exists off this machine. Then remove it:'
print ''
print "  rm -P \"${plain_key}\""
print ''
print 'Keep that backup: the six fingerprints compiled into every published'
print 'build point at this key, and no other key can replace it.'
