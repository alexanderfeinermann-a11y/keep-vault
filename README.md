# Keep Vault

Archiving, extraction and cryptographic erasure of ZPAQ archives for **macOS**.
Encrypted archives use container format **v11**: a chosen cascade of up to six
independent ciphers over the compressed stream, keys from two Argon2id branches
whose memory cost is itself derived from your credentials, two separate MACs,
and a four-part credential made of a passphrase, a PIN, and two 1024-bit factors
the app generates.

The application is under development. It is not a substitute for an external
cryptographic audit, an HSM, or operating-system hardening.

> **macOS only.** The Windows source tree has been carried to v11 and compiles,
> but the WPF application has never been run or tested on Windows. No Windows
> package is published, and the macOS version is the only one that should be
> used.

---

## Install

Prebuilt packages are on the
[Releases](https://github.com/michael-feinermann/keep-vault/releases) page.
Requires macOS 14 or newer, Apple silicon or Intel (universal binary).

The package contains **two applications**: `Keep Vault.app` and
`QR-Scanner.app`. The second one reads the QR codes from the printed key sheets;
it is a separate, sandboxed program with its own bundle identifier. Keep Vault
itself never requests camera access and declares no hardware capability at all.

1. Download and unpack `Keep Vault-portable-macOS.zip`.
2. Check it before launching anything — see [Verify a download](#verify-a-download).
3. Run `tools/Install-KeepVault-macOS.sh`. It verifies the signatures, installs
   to `/Applications`, installs the scanner alongside when the scanner's own
   signature is present, and puts an alias on the Desktop. It must **not** be
   run with `sudo`.

The files named `Keep Vault.app.launcher.*` belong **beside** `Keep Vault.app`
and have to stay there: the launcher checks its own dual signature at every
start and will not run without them. The same applies to `QR-Scanner.app.*`.

At every start the app checks Apple's code signature, its compiled cdhash pins,
and the dual signature of every executable in the bundle. If any of these fails,
it does not start.

### Verify a download

The package ships with the verifier that produced it:

```sh
"./Keep Vault Release Verifier" "Keep Vault-portable-macOS"
```

Point it at the whole folder — that covers the app, the scanner, the verifier
itself and every hash manifest:

```
verified_artifacts=51
RESULT: TRUSTED - RSA-PSS/SHA-512 and ML-DSA-87 verification passed.
```

It also accepts a single bundle, a single file, or the ZIP. Exit codes are `0`
for TRUSTED, `2` for NOT COVERED (a real artifact that these keys never signed),
`3` for BLOCKED, and `1` for a usage error.

A verifier that travels with the thing it vouches for can only tell you the
package is internally consistent. To make it evidence against a determined
attacker, obtain the verifier and its pins through a separate, trusted channel.

---

## Format policy

The app writes and reads container format **version 11 only**. Every other
version is refused, including version 10; there is no legacy decryption path and
none is planned. Archives written with v10 or earlier cannot be opened with this
release, and the reader says so by name rather than failing as a wrong password.

That is a deliberate choice, not an oversight. A second, older derivation kept
alive for compatibility is a second construction to attack, a second set of
domains to get wrong, and a permanent argument for whichever of the two is
weaker. The application is still in development and there are no archives worth
carrying forward, so there is nothing to weigh against removing it.

The key-derivation domain separators carry `v11`, and the header carries an
explicit `KdfMode` string naming the construction. A version number alone turned
out not to be enough: 4.0.0/4.0.1 and 4.0.2 both wrote `"Version": 9` while
deriving different Paranoia keys. `KdfMode` exists so that a future correction
changes a value a reader can see, not only a value a reader has to infer.

### The ten options

Offered in this order:

| # | Option | Layers, outermost first | Nonce | Cipher key |
|---|---|---|---|---|
| 1 | **Standard** | Threefish-1024 → Kalyna-512/512 | 192 B | 192 B |
| 2 | **Fast** | ChaCha20-Poly1305 → AES-256 | 28 B | 64 B |
| 3 | **Mixed** | ChaCha20-Poly1305 → Threefish-1024 → AES-256 | 156 B | 192 B |
| 4 | **Paranoia** | ChaCha20-Poly1305 → Threefish-1024 → Kalyna-512/512 → SHACAL-2-512 → MARS-448 → AES-256 | 268 B | 376 B |
| 5 | Threefish-1024 | single cipher | 128 B | 128 B |
| 6 | Kalyna-512/512 | single cipher | 64 B | 64 B |
| 7 | SHACAL-2-512 | single cipher | 32 B | 64 B |
| 8 | MARS-448 | single cipher | 16 B | 56 B |
| 9 | AES-256 | single cipher | 16 B | 32 B |
| 10 | ChaCha20-Poly1305 | single cipher | 12 B | 32 B |

The four cascades come first, running from the everyday choice up to the most
elaborate one. Somebody scanning the list stops at the first entry that fits,
and the option that costs six passes over the data sits at the end where it gets
chosen deliberately rather than by accident. The six individual ciphers follow
in descending key size.

Names are shown in the app and on the printed sheets in bracket notation, in
German or English depending on the selected language — for example
`Paranoia: ChaCha20-Poly1305(Threefish 1024(Kalyna 512/512(SHACAL-2 512(MARS 448(AES 256(Data))))))`.

### How a cascade works

Each layer gets its own key and its own slice of the nonce. For the standard
cascade that is 64 bytes of key and 64 bytes of nonce for the inner Kalyna
layer, 128 and 128 for the outer Threefish layer.

An earlier design cut those keys out of one flat Argon2id output, so a layer's key was a
function of where it happened to sit in that buffer, and the same cipher in two
positions could share structure. v11 derives each key separately from a
canonical context — algorithm, stage index, cipher, purpose and key width — run
through two PRF families and combined:

```
U = HKDF-Expand(HMAC-SHA3-512) over the two master halves     128 B
V = Skein-MAC-1024-1024(key = master, pers = domain, msg = context)
Z = U XOR V                                                    128 B
```

Only then is `Z` truncated to the layer's key width. Truncating earlier would
cap the wide layers at whichever primitive produced them. The XOR is documented
for what it is: a combiner of two 1024-bit PRF outputs under the assumption that
both families behave as assumed and the contexts are unique — not a robust
combiner against arbitrary or maliciously correlated primitives.

The order matters. Breaking only the outer layer yields the inner layer's
ciphertext — not the plaintext, and not the archive's structure. Every payload
byte, along with file names, sizes and timestamps, lives in the ZPAQ stream
*inside* all layers. An automated test demonstrates this rather than asserting
it: it strips the outer layer with the correct key and searches the result for a
known marker.

All layers except the outermost ChaCha20-Poly1305 are keystream constructions,
so security holds as long as at least one of them is unbroken.

### Per-chunk nonces

For **every** option, each 16 MiB chunk gets its own nonce, derived from the base
nonce and the chunk index through SHA3-512. A continuous CTR counter over
arbitrarily large archives eventually repeats, and a repeated counter block under
one key leaks the XOR of two plaintexts.

### The master key derivation

v11 asks for four credentials, and all four are mandatory: a passphrase of 24 to
256 characters, a PIN of 6 to 16 digits, and the two 1024-bit factors from the
printed key sheets. There is no reduced mode and no suite that skips one.

Two credential paths are built first, each a different shape of construction.
The SHA3 path splits each factor into its two 512-bit binary halves and pairs
them across the two sheets:

```
A1 = A[0..64)   A2 = A[64..128)
B1 = B[0..64)   B2 = B[64..128)

Q_S1 = SHA3-512(LP(D_S1) || LP(pass) || LP(pin) || LP(A1) || LP(B1))     64 B
Q_S2 = SHA3-512(LP(D_S2) || LP(pass) || LP(pin) || LP(A2) || LP(B2))     64 B
Q_S  = Q_S1 || Q_S2                                                     128 B

Q_K  = Skein-MAC-1024-1024(key = A || B, pers = D_SK, msg = LP(pass) || LP(pin))
```

The factors enter as raw bytes, not as their hexadecimal transcription, and both
halves of `Q_S` depend on both key sheets. That is the point of the split: if one
1024-bit factor is compromised, each 512-bit SHA3 half still rests on 512
uncompromised bits of the other. The Skein path is not split — it keys the MAC
with the complete 2048-bit `A || B`.

`LP` is length-prefixed framing, not concatenation: without it a passphrase of
`"ab"` with PIN `"1"` and a passphrase of `"a"` with PIN `"b1"` would hash the
same bytes and derive the same key.

Both are fed to Argon2id, in sequence, with separate salts and separate
associated data:

```
L = Argon2id(P = Q_S, S = salt_sha3,  X = "...SHA3-Branch/Round-1",  m, 4, 4, 64)
R = Argon2id(P = Q_K, S = salt_skein, X = "...Skein-Branch/Round-1", m, 4, 4, 64)
M = interleave(L, R)                                                      128 B
```

The branches run strictly one after the other and each matrix is released before
the next allocates, so peak memory stays at one matrix rather than two. The
interleave is a permutation, not mixing: it exists so no single 512-bit Argon2id
output becomes the width of the master, and the actual mixing happens afterwards
in the role key schedule.

Two things this does *not* claim. The two branches share Argon2's BLAKE2b core,
so they differ in what they are fed and in their domains, not in their
foundation. And the interleave adds no entropy.

#### The memory cost is derived, not stored

`m` is not a constant and is not written down. It comes from the credentials:

```
PMI = BE16(SHA3-512(LP(domain, Q_S, Q_K, [M1,] salt_sha3, salt_skein))[0..1])
m   = 1 GiB + 16 * PMI KiB          -- 1,048,576 to 2,097,136 KiB
```

An attacker who does not know the credentials does not know which of the 65,536
memory profiles to allocate. PMI adds no entropy — it is a deterministic
function of the credentials — and a process watching this one can still estimate
it from resident set size or elapsed time. It is off disk, not invisible.

The header's `Argon2MemoryKiB` is therefore `0`, and the reader rejects any
container that fills it in. KPAR2 does not carry it either.

#### Paranoia runs the whole thing twice

The Paranoia cascade runs a second round whose Argon2id **secret** input is the
first round's complete 1024-bit master:

```
M2 = round(Q_S, Q_K, salt_sha3_2, salt_skein_2, secret = M1, m2)
```

Round two cannot be started without finishing round one — four sequential
Argon2id calls of at least a gibibyte each, not four that can be run in
parallel. The credentials sit in the same position in both rounds; only the
secret and the salts change.

This replaces an earlier arrangement, where both rounds shared one 128-byte
credential prehash. Because the PHC adapter clears the password it is given,
4.0.0 and 4.0.1 ran their second round over 128 zero bytes. v11 does not share a
buffer between rounds at all, and the regression is checked by changing one bit
of round one and observing round two change with it — not by a round-trip, which
would pass while both sides were equally wrong.

All four salts are stored in the header, as two 1024-bit pairs. An archive whose
header carried only the first round could not be decrypted by anyone, including
the machine that wrote it.

### The container

- Magic `KZPAQ1\0`, UTF-8 JSON header, 64-byte HMAC-SHA3-512 tag, 128-byte
  Skein-1024 MAC tag, then ciphertext
- Password mode `UserPassword24to256+PIN6to16+GeneratedHex1024x2`
- KDF input mode `DualBranch-v11: SplitFactorsSHA3-512-1024 || KeyedSkeinMAC-1024-1024`
- KDF mode `DualArgon2id-SplitSHA3+Skein1024-Sequential-Master1024`
- One 1024-bit salt pair per round; Argon2id 0x13 with `t=4`, `p=4` and a memory
  cost derived from the credentials — `Argon2MemoryKiB` is stored as `0`
- 1024-bit master, from which every role key is derived separately
- Encrypt-then-MAC with two separate keys, both tags mandatory

The authenticated header binds version, suite, block size, both salt pairs,
nonce, tweak, KDF mode, KDF input mode, master width and password model. Both
MACs cover the same magic, header length, header and the entire ciphertext, and
both tags are compared in full and without short-circuiting before any plaintext
reaches the ZPAQ pipe.

The v11 reader accepts only `t=4`, `p=4` and a zero memory field. Deviating
header values are rejected before the KDF, so a manipulated archive can force
neither weaker nor higher Argon2 cost — and because the cost is not in the header
at all, there is no field to manipulate. The native adapter enforces its own
bounds a second time, independently, and requires that the entire Argon2 matrix
be locked against paging; if that lock fails the KDF aborts rather than accepting
swappable memory. After the KDF the matrix is zeroed before it is unlocked and
freed.

---

## Using it

The window has three tabs.

**Archive** — select or drop files and folders, choose a target, enable
encryption and pick an option. Suggested archive and output names always get at
least a `(1)`. Before encrypting, the current combination of archive path, suite
and both factors must be printed or deliberately exported as a test PDF.

**Delete original files** — optional, and gated on proof. The archive is
extracted again into a private directory and compared with the originals byte for
byte, in both directions: every original must appear in the archive, and the
archive must contain nothing else. Immediately before anything is deleted, two
things are re-checked. The archive is identified again by length and SHA-512, so
a swap between verification and deletion is caught. And every original is read
again and compared against what was verified — same set, same lengths, same
modification times, same digests, and no file that has appeared since. Any
difference at all and nothing is deleted.

Deletion then names each verified file individually. It is deliberately not
`Directory.Delete(recursive: true)`: that call deletes whatever it finds, which
is not necessarily what was verified, and the difference would be a file that was
never archived. Folders are removed afterwards only if they are empty.

**Extract** — drop a `.zpaq` or `.kzpaq`. The suite is shown from the not-yet
authenticated header first and is authenticated by both MACs before any
plaintext is written. Extraction only ever goes into a new or empty folder. A
`.kzpaq` with neither a valid container header nor usable KPAR2 data is refused
outright and never handed to the native parser as plain ZPAQ.

**Cryptographic erase** — analyse a valid encrypted v11 container, then destroy
the reconstructable recovery sidecar first and afterwards corrupt and delete the
container itself, through the same exclusive file handle. The button refuses
until the SSD/APFS limitation is explicitly acknowledged.

A successful archive or extraction clears the associated password and factor
fields; both panels also have a manual **Clear secrets** button. Failed archive
runs remove partial archives, dual manifests and recovery leftovers; failed or
cancelled extractions remove their partial output folder.

Language, the last selected suite and the ZPAQ compression level are stored as
strictly validated convenience settings in the user profile, capped at 64 bytes,
falling back to English / the default suite / level 1 on anything invalid.
Passwords, factors, salt and nonce are never stored there. On extraction the
authenticated archive header alone determines the suite; the remembered GUI
selection has no influence on it.

---

## Password model

Extraction requires all three values:

1. A user password of 24 to 128 characters.
2. Factor A: 128 hex characters = 64 bytes = 512 bits.
3. Factor B: 128 hex characters = 64 bytes = 512 bits.

The header stores none of them. It stores only public, necessary parameters:
salt, nonce, tweak, suite and the Argon2id profile. The optional hint is also
public, must not contain password material, and is shown explicitly as
unauthenticated header text until the MAC check succeeds.

### User-password policy

- at least 24 and at most 128 characters
- at least 3 character groups
- at least 12 distinct characters
- at least 12 characters outside `0-9`, `A-F`, `a-f`
- no contiguous hex run of 8 or more characters
- not equal to factor A or B, and A and B must differ from each other
- at least 128 bits by a conservative local estimate

The estimate caps the assumed alphabet and penalises repetition, sequences,
keyboard patterns and known words. It is a pessimistic policy, not a proof of
entropy for human passwords.

### The four credentials

Each suite has separate domains for A and B. `LP` means every field — domain,
UTF-8 passphrase, ASCII PIN and normalised ASCII hex factor — gets an explicit
32-bit length prefix:

```text
Q_S = SHA3-512(LP(domain_A, pass, pin, A)) || SHA3-512(LP(domain_B, pass, pin, B))
Q_K = Skein-MAC-1024-1024(key = A || B, pers = domain, msg = LP(pass, pin))
```

The two paths use the credentials differently on purpose. In `Q_S` the factors
are hashed alongside the passphrase and PIN; in `Q_K` they *are* the MAC key and
the passphrase and PIN are the message. Neither path can be computed from the
other's output.

`Q_S` and `Q_K` go into their own Argon2id branch untruncated, each with its own
512-bit salt. The app compiles the unmodified PHC Argon2 reference sources; tests
compare the native adapter against the PHC CLI, and the v11 branch additionally
against Bouncy Castle's independent Argon2id implementation.

Every intermediate buffer — the encoding targets, the length frames, both
credential hashes, every one-call Argon2id copy and both round masters — is
locked against paging before its first write and zeroed while still locked. Each
Argon2id call receives a fresh copy, because the native side clears what it is
given; this is what an earlier revision got wrong.

The Skein-MAC is Bouncy Castle's `SkeinMac` with Skein's own key and
personalisation parameters, not `Skein1024(key || message)`. HKDF-Expand is
Bouncy Castle's `HkdfBytesGenerator` with `SkipExtractParameters`, not a
hand-rolled HMAC chain. Both were verified against independent second
implementations before being used for anything.

A salt prevents precomputed tables for identical password material. It does not
make a weak user password strong on its own; the two independent factors and the
memory-hard KDF are what carry the protection here.

---

## Randomness, salt, nonce and tweak

Nine separate pools collect mouse samples: A1, A2, B1, B2, the SHA3 salt, the
Skein salt, and three nonce parts. A 1024-bit factor is drawn from two pools laid
end to end — A = A1 ‖ A2 — which is defence in depth, not a claim that either
pool holds 512 bits of real entropy. Each pool needs at least **1024 samples**
before archive entropy can be produced; with round-robin distribution that is at
least 9216 mouse events per epoch, and the nine counters differ by at most one.

The interface shows all nine counters. It groups A1/A2 and B1/B2 visually, but
there are two user factors, not four.

That count is not a claim of 512 bits of physical mouse entropy. Security may
already rest on the operating-system CSPRNG alone; the mouse data is additional
diversity. Every output is the XOR of two independent things:

- `SecRandomCopyBytes` as the primary CSPRNG
- a domain-separated SHA3-512 expansion of the relevant mouse pool

The factors, both salts and all three nonce parts are generated together and
atomically from one epoch, each from its own pool. Afterwards every pool is replaced, zeroed
while locked, and its counter reset to zero — so zero in that state means
*consumed*, not *insufficient*. Both salts and the full nonce stay in locked
RAM until encryption begins and are taken exactly once. If that attempt fails
after they were taken, A and B stay valid, but the retry derives fresh salts and
fresh nonces from a new epoch, so a nonce is never reused under the same key.

Each round carries a 1024-bit salt pair — 512 bits for the SHA3 branch and 512
for the Skein branch — and the two are refused if they are ever equal. Paranoia
carries two such pairs. The public 16-byte Threefish tweak is derived
deterministically and domain-separated from the nonce and stored in the
authenticated header. Salt, nonce and tweak do not need to be secret.

---

## Key sheets

Before encrypting, the current combination of archive path, suite and both
factors must be printed or deliberately exported as a test PDF.

- Physical printing without a file is the default path.
- Obvious virtual PDF/XPS/fax printers are blocked.
- Page order: factor A, a genuinely blank separator page carrying the
  installation instructions, factor B.
- Each secret page names the suite, the device name, the archive path, exactly
  one 1024-bit factor in 32 groups of eight hex characters, a blank handwritten
  field for the user password, and that factor's QR code twice.
- The PIN is deliberately **not** on the sheet, and the sheet says so. The
  handwriting field for the passphrase is already a compromise; a sheet carrying
  the passphrase, the PIN and a factor would hold three of the four credentials
  at once.
- A and B are meant to be stored separately and offline.
- **Save test PDF** deliberately writes both factors to the chosen volume
  permanently and is not a safe default path.

`QR-Scanner.app` from the same package reads the codes back. Printer spoolers,
drivers and printers can create their own temporary data outside the app.

---

## Streaming and parallelism

ZPAQ lives under `external/zpaq`, Kalyna under `external/Kalyna-reference`, the
official Skein 1.3 / Threefish source under `external/Skein-reference`, and
Crypto++ 8.9.0 under `external/cryptopp`.

The adapted ZPAQ `--pipe` interface carries the unencrypted ZPAQ archive
directly in RAM between ZPAQ and the container service; no unencrypted
intermediate archive is ever written to disk. The final container is written
under a random name as already-encrypted ciphertext, flushed, and then moved
atomically onto the target name without overwriting.

On extraction the local ZPAQ adaptation rejects absolute paths, `..`, ambiguous
trailing dots and spaces, and reserved device names, so archive members cannot
escape the empty target folder by path traversal. Extraction happens in a random
hidden sibling folder and is installed by directory rename only after success.

Direct file inputs are pinned for the whole ZPAQ call with a handle that cannot
be renamed or deleted from under them; symlink aliases are refused. Archive
targets may neither equal an input nor lie inside a directory tree being read.
The native ZPAQ JIT is disabled, and model and index sizes have hard limits.

The extractor works in a single forward pass and does not buffer the whole
decrypted archive. Its memory needs are set by one ZPAQ block, the 16 MiB
container buffers and process metadata — not by archive size.

`native/kalyna_ref_export.c` and `native/threefish_ref_export.c` split large CTR
calls into disjoint block and counter ranges across workers that claim chunks
from a shared atomic counter. Workers write into disjoint output ranges, so the
output stays bit-identical to the serial CTR path. Both MACs are logically
sequential over the resulting ciphertext and are updated in one shared streaming
pass.

The Threefish adapter uses the 80 rounds, rotations and key schedule of the
official `Skein1024_Process_Block` reference unchanged, removing only the Skein
UBI feed-forward to obtain the raw Threefish block.

CTR authenticates nothing by itself. Tamper protection comes from HMAC-SHA3-512
with a 64-byte key and tag together with Skein's native keyed mode with a
128-byte key and tag. Each MAC key is derived from its own role context in the
same schedule the cipher keys use — not carved out of a shared buffer, and not
derivable from any cipher key.

Unencrypted `.zpaq` archives instead get mandatory `<archive>.sha3` and
`<archive>.skein` sidecars. These detect corruption but, without a private
signing key, are not protection against an active attacker who replaces the
archive and both sidecars.

---

## Bit-error correction

Every archive gets a KPAR2-v4 sidecar
`<archive>.kpar2`:

- Reed-Solomon `RS(20,3)`: 20 data plus 3 parity shards, 15 percent overhead
- separate parity regions for header and archive body
- 4096-byte aligned archive shards with dual SHA3-512 and Skein-1024 digests
- eight spatially separated, themselves dual-hashed 4096-byte locators — four at
  the start, four at the end; at least five identical valid copies are required
- a metadata region of exactly 4096-byte blocks, itself protected stripe-wise
  with `RS(20,3)`; the canonical manifest, both certificates, suite, salt,
  Argon2id profile and all shard digests live inside it

Single bits and entirely unreadable 4 KiB blocks are repairable as long as they
affect at most three data shards per stripe. Block-oriented reads treat I/O
errors reported by the file system as erasures.

For **encrypted archives** the KPAR2 manifest is always dual-authenticated:
HMAC-SHA3-512 and Skein-1024 keyed mode use their own recovery keys, derived
domain-separated from the archive MAC keys and a random archive ID. Wrong
password factors or a swapped KPAR2 file are refused before any repair candidate
is produced. Every suite in the catalogue is covered — an earlier release
validated the locator's suite id against a hard-coded range that admitted only
the first two, which meant most suites produced an archive the app would encrypt
and then refuse to protect.

KPAR2 is at **v4** and nothing older is read. Its bootstrap is the container's:
it stores every salt pair the container uses, one per round, and runs exactly the
same derivation the container runs, both Paranoia rounds included. An earlier
development format stored a single 64-byte salt and derived the recovery MAC
parents with one Argon2id round even for Paranoia, which handed anyone holding
both key-sheet factors a cheaper offline oracle for the passphrase through the
recovery file than through the container it protects. The certification keys are
still not the container's keys: they come from their own role purposes in the
same schedule. They simply cost the same to attack.

v4 additionally binds the container version into the authenticated recovery
context — both into the recovery-key derivation and into the certification
prefix — so the unkeyed version field in the locator cannot select a different
key derivation. Since only container version 11 exists, any other value is
refused outright.

The Argon2id cost fields are gone from the locator and manifest, and are
rejected if present. The memory cost is derived from the credentials, and
publishing it beside the salt would undo that.

For **unencrypted archives** the same SHA3 and Skein values are explicitly
unkeyed error-detection values. A repair is therefore always written to a new,
conflict-free file name and the damaged original is left untouched.

The separate **emergency mode** skips KPAR2 metadata authentication, always
writes a new file and never modifies the original. For an encrypted archive all
all four credentials are still required and the finished candidate must pass
the container's own two MACs. There is no automatic fallback from the normal
mode into emergency mode.

---

## Integrity and signing

Every executable in the package carries two independent signatures: Apple's, and
a detached pair of RSA-PSS/SHA-512 (RSA-4096) and ML-DSA-87 (NIST FIPS 204).
**Both** must verify; there is no OR fallback. Seventeen Mach-O files are
covered:

- `Keep Vault`, `Keep Vault Launcher`, `Keep Vault Supervisor`
- `zpaq`, `argon2`
- `libargon2_ref`, `libkalyna_ref`, `libthreefish_ref`, `libaes_ref`,
  `libmars_ref`, `libshacal2_ref`, `libchachapoly_ref`
- `libAvaloniaNative`, `libHarfBuzzSharp`, `libSkiaSharp`
- `Keep Vault Release Verifier`
- `QR-Scanner`

The signing targets are enumerated from the bundle rather than listed by hand,
and both the launcher and the standalone verifier refuse any Mach-O in the tree
that has no signature. A hand-written list only ever covers what somebody
remembered to add: the three Avalonia and Skia libraries were once signed by
Apple and left out of the dual signature, running inside the process that holds
the archive keys on Apple's signature alone — the single layer this app is built
not to depend on.

Two signatures cannot live inside the bundle they cover and are therefore
published beside it:

- the launcher's, because codesign writes the bundle seal into the launcher
  itself, so a signature over its own bytes would invalidate itself;
- the scanner's, because Apple's seal covers `Contents/Resources` and a file
  added there afterwards would break the seal it sits under.

Keep Vault verifies `QR-Scanner.app` against the same pinned keys at every start
and reports the result in the security log. The scanner reads the two secret
factors off the printed sheets and cannot vouch for itself — a replaced app
would simply claim to be fine. A failure is loud but does not stop Keep Vault:
the scanner is a separate program whose code Keep Vault never loads.

Both public keys are pinned three times each, and all six fingerprints must
match exactly:

- SHA-256
- SHA3-512
- Skein-1024

Multiple hashes add no security bits; they avoid a single hash or provider
dependency in key identification. macOS validates only the Apple signature;
ML-DSA-87 is checked by the launcher, by the app, and by the standalone
verifier. This is a hybrid application signature, not a dual X.509 certificate.
ML-KEM-1024 from FIPS 203 is a KEM and cannot sign software, which is why
ML-DSA-87 from FIPS 204 provides the post-quantum half.

The imported `pq-crystals/dilithium` reference sources are pinned to commit
`d35ba3fe5449bee3e6d43e1f296c3ca818bd36be`, and the native build requires
matching SHA-256, SHA3-512 and Skein-1024 source manifests for exactly the 21
included reference files.

### Protecting the signing keys

A hybrid signature is one decision: it counts only when RSA-PSS and ML-DSA-87
both verify. Both halves therefore sit under the same 32-byte wrapping key, and
one confirmation covers the certificate as a whole rather than two covering
halves of it.

Both are AES-256-GCM envelopes; the wrapping key lives in the login Keychain in
an item created with no trusted application, so **every read prompts**. Four
prompts for an app build, two for the portable one — and a fifth or a third is a
use nobody started. Answer *Allow*, never *Always Allow*: the latter writes the
asking binary into the item's access list and the prompt stops, which is the
whole property this provides.

`tools/Protect-HybridKeys-macOS.sh` performs the migration. It wraps and unwraps
through the signer's own code, so the two directions cannot drift apart, and it
verifies the round trip before keeping anything — an envelope only the writer
can open is worth nothing, and that failure surfaces after the original has been
deleted. It deletes nothing itself.

Encryption at rest stops the files from being useful once they leave the
machine: a Time Machine backup, a cloned disk, a tar of the home directory. It
does not stop malware running as the same user, which can ask the Keychain the
way the signer does. What raises that bar is the prompt.

A root-owned rollback anchor at
`/Library/Application Support/Keep Vault/minimum-version` records the lowest
acceptable build number, so a user-level attacker cannot reinstate an older,
weaker release.

---

## Build from source

Requires Xcode command-line tools and the pinned .NET 10 SDK. Release signing
needs your own RSA-4096 code-signing key and an ML-DSA-87 key pair; the paths are
configurable through `KEEPVAULT_HYBRID_PFX` and `KEEPVAULT_MLDSA_PRIVATE_KEY`.

```sh
./tools/Build-Native-macOS.sh          # reference ciphers, Argon2, ZPAQ
./QrCodeScanner/tools/Build-QrScanner-macOS.sh --version 4.0.2 --build-number 6
./tools/Build-KeepVault-macOS.sh --version 4.0.2 --build-number 6
./tools/Build-Portable-macOS.sh        # portable folder and ZIP
./tools/Install-KeepVault-macOS.sh     # verify and install to /Applications
./tools/Verify-KeepVault-macOS.sh      # check an installed or built bundle
./tools/Protect-HybridKeys-macOS.sh    # put both signing keys behind one prompt
```

The QR scanner and Keep Vault must be built with the same marketing version and
build number. The portable release gate requires the scanner, checks both
bundle identifiers and rejects a missing or mismatched companion before signing
the package.

The build compiles all six fingerprints in, signs the app and every native file,
then produces SHA3-512 and Skein-1024 manifests plus a `.khsig` for each release
artifact. Its final gate runs the shipped verifier against the ZIP, the app and
the whole package folder, so a release cannot be published unless its own tool
accepts it.

---

## Tests

```sh
./tools/Stage-TestNatives-macOS.sh
cd KeepVaultMac.Tests
dotnet run -c Release -- --full
```

Twenty-five comprehensive groups, on top of thirteen smoke tests. `--only <text>`
narrows a run to one group while fixing it.

The suite covers macOS process hardening; signed native trust and tamper
rejection; hybrid-signature coverage of every Mach-O in the built bundle; the
companion scanner check including corrupted, modified and missing signatures;
SHA3, Skein, Kalyna and Threefish reference vectors; ML-DSA-87 interoperability
against the compiled reference adapter in both directions; randomised
differential testing against every reference library; the fixed Argon2id profile
against PHC and Bouncy Castle; ZPAQ levels, streaming, traversal and a malformed
corpus; v11 round-trips and manipulation rejection; that the outer cascade layer
alone reveals nothing; two-round derivation from one pool consumption; per-chunk
nonces across a multi-chunk archive; salt and nonce for every single-round suite;
MARS and SHACAL-2 published vectors; KPAR2 repair, authentication,
transplantation rejection and coverage of every catalogued suite; cryptographic
erase ordering and hard-link refusal; verified original deletion including
the pre-deletion re-check of the originals; and the GUI
driven through Avalonia's headless backend.

---

## Security boundaries

- Sensitive managed buffers are zeroed and locked against paging. A lock failure
  aborts the operation. The same applies to the entire native 1 GiB Argon2
  matrix.
- The app runs with the hardened runtime and no entitlements, so library
  validation is active. It is signed with a local Apple Development identity and
  is **not notarized**; Gatekeeper will refuse it on another Mac until it is
  signed with a Developer ID certificate and notarized.
- Capture protection is best effort. It cannot block every screen-recording
  tool, remote-desktop configuration or hardware camera.
- Passwords exist temporarily as managed strings. Pagefile, hibernation,
  debuggers, malware holding the user's own privileges, and hardware or timing
  attacks cannot be fully excluded by a .NET desktop application.
- Memory locking covers only the buffers explicitly locked. CPU registers,
  native worker stacks and the internal state of operating-system crypto
  providers cannot be reliably locked or zeroed from application level.
- Threefish and ChaCha20 use ARX operations without secret tables. The Kalyna,
  AES, MARS and SHACAL-2 references are table-based and offer no provable
  protection against cache side channels on a compromised shared system.
- A 1024-bit Threefish key and a 1024-bit Skein tag do not mean the whole
  construction has 1024 bits of security. KDF, password material, ciphers, both
  MACs and the implementation jointly bound the real strength; security bits do
  not add up. Neither does layering six ciphers make the cascade six times
  stronger — it means an attacker must break every layer, not that the strengths
  sum.
- Dual unkeyed hashes are not a digital signature. The release manifests gain
  active forgery resistance only from their mandatory RSA-PSS / ML-DSA `.khsig`
  signatures and from both private keys being protected.
- The hybrid code signature stays forgery-resistant against a cryptographically
  relevant quantum attacker only if ML-DSA-87, its implementation and the pin
  anchored outside the package hold. RSA-4096 alone is not post-quantum secure.
  The AND construction does, however, permit no fallback to RSA when only RSA is
  broken by Shor.
- `.khsig` has no RFC-3161 timestamp or revocation status of its own. Long-term
  release archiving must handle key compromise and pin rotation organisationally.
- The current signing keys live in a local key store, not an HSM. A public
  release needs two separately protected signing keys and an independently
  distributed verifier.
- A self-check cannot force a completely replaced application bootstrap to run
  its own checking code. The launcher, its cdhash pins and the rollback anchor
  raise the bar; they do not remove this class of local startup attack.
- KPAR2 offers authenticity against an attacker only for encrypted archives and
  only after both domain-separated recovery MACs verify. The unencrypted profile
  and emergency mode offer error correction only.
- `KPAR2` is an app-specific format and is not compatible with standard PAR2
  tooling. At 1 TB, 15 percent redundancy needs roughly 150 GiB of sidecar
  storage and several full read/write passes.
- Per-file overwriting guarantees no physical erasure on SSDs. Real ATA/NVMe
  Secure Erase and Crypto Erase are whole-drive firmware actions.
- Cloud versioning, backups, snapshots and existing PDF or print-spooler files
  can still contain deleted archives or key sheets.
- ZPAQ is a large native C++ parser and does not currently run in a separate
  sandbox. Path tests, a deterministic mutation corpus and process limits reduce
  the risk but replace neither continuous fuzzing nor an independent audit of the
  parser.
- A physical 1 TB end-to-end test, a formal security proof and an independent
  external cryptographic audit have not been carried out.

---

Sources: [Kalyna reference](https://github.com/Roman-Oliynykov/Kalyna-reference),
[PHC Argon2](https://github.com/P-H-C/phc-winner-argon2),
[ZPAQ](https://github.com/zpaq/zpaq),
[Crypto++](https://github.com/weidai11/cryptopp),
[FIPS 202 / SHA-3](https://csrc.nist.gov/pubs/fips/202/final),
[FIPS 204 / ML-DSA](https://csrc.nist.gov/pubs/fips/204/final),
[pq-crystals/dilithium](https://github.com/pq-crystals/dilithium),
[Threefish / Skein authors](https://www.schneier.com/academic/skein/threefish/),
[Skein 1.3 paper](https://www.schneier.com/wp-content/uploads/2015/01/skein.pdf),
[RFC 8439 / ChaCha20-Poly1305](https://www.rfc-editor.org/rfc/rfc8439).
