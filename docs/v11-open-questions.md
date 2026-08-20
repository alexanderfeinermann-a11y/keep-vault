# Open questions for v11

Everything here was found or raised during v10 and deliberately not fixed in
v10. Each entry says what is wrong, why it was left, and what would close it.

## 1. The two signing keys share one wrapping key

RSA-PSS/SHA-512 and ML-DSA-87 are algorithmically independent, and a release is
only trusted when both verify. Operationally they are not independent: both
private halves are protected by the same 32-byte AES key held in one Keychain
item. Whoever obtains that key obtains both halves, and the hybrid signature
stops being a hybrid at exactly the moment it would matter.

Not fixed in v10 because re-wrapping requires the plaintext ML-DSA key, which
exists only on the offline backup medium — the migration cannot be done from a
build machine that only has the envelopes.

**To close it:** two Keychain items with independent random keys, one per
algorithm; `Protect-HybridKeys-macOS.sh` creates both; the signer reads each
half through its own item. Two prompts per release, which is already the
accepted behaviour. Better still, two different holders — a smartcard or HSM
for at least the RSA half — so that no single machine ever has both.

## 2. ZPAQ still runs in-process

The ZPAQ parser is a large native C++ codebase and the largest remaining attack
surface in the program. It is fenced in — path validation, no symlinks, private
snapshots, no JIT, size limits, a malformed-input corpus — but a memory-safety
bug in the parser would still execute with the full rights of the Keep Vault
process, which include the user's files and the Keychain items above.

**To close it:** move extraction and listing into a separate helper process
under a restrictive sandbox profile, with file access limited to the archive
and one output directory, and no network. The container layer already streams,
so the interface is a pipe rather than a rewrite.

## 3. Not notarized, signed with an Apple Development identity

Gatekeeper refuses the app on any Mac other than the one that built it. This is
a distribution problem, not a cryptographic one — the hybrid signature and the
dual manifests are what actually establish what the package is — but it makes
the published build awkward to install.

**To close it:** a Developer ID Application certificate and a notarization
submission in `Build-Portable-macOS.sh`. Needs a paid Apple Developer account;
nothing in the code has to change.

## 4. The PMI is observable locally even though it is not stored

The Argon2id memory cost is derived from the credentials and never written to
the header or to KPAR2. That keeps it off disk. It does not hide it from a
process watching this one: resident set size and elapsed time both track it, so
a local observer can estimate the PMI of a derivation it watches, and 16 bits of
memory profile is a small space to search.

This is documented rather than fixed because the alternative — a constant memory
cost — gives the same information away to everyone unconditionally. It is worth
restating in v11 whether the variable cost earns its complexity.

## 5. The XOR combiner in the role key schedule

Each role key is the XOR of an HKDF-HMAC-SHA3-512 output and a keyed
Skein-MAC-1024-1024 output. This combines two 1024-bit PRF outputs into one
under the assumption that both families behave as assumed and the contexts are
unique. It is not a robust combiner: two primitives that fail in correlated
ways, or a maliciously chosen pair, are not covered. The claim in the code and
in the documentation is deliberately narrow and should stay narrow.

## 6. Both Argon2id branches share BLAKE2b

The SHA3 branch and the Skein branch differ in what they are fed and in their
domains, not in their core. Argon2id is Argon2id on both sides, so a structural
break in Argon2's compression function affects both. Calling the two branches
"independent" is only true of their inputs.

## 7. Windows

`KalynaArchiver` has been carried along to v10 as source, but the WPF
application can only be built on Windows and has never been built or tested
against v10. Either build and test it on Windows or state plainly that the
Windows tree is unsupported.
