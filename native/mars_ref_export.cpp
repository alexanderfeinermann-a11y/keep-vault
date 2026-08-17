/*
 * Native adapter for MARS-448 in CTR mode.
 *
 * MARS is the innermost-but-one layer of the v9 paranoia cascade. It has no
 * reference implementation of its own in this repository, so it comes from the
 * vendored Crypto++ release; see external/VENDOR-PROVENANCE.md.
 *
 * Build together with the Crypto++ objects into mars_ref.dll / libmars_ref.dylib.
 */
#include "mars.h"

#include "cryptopp_ctr_common.hpp"

/* MARS accepts 128 to 448 bits. The cascade uses the longest, which is what
   the exported name states so a caller cannot silently pass a shorter key. */
#define MARS_KEY_BYTES 56
#define MARS_BLOCK_BYTES 16

static_assert(
    CryptoPP::MARS::BLOCKSIZE == MARS_BLOCK_BYTES,
    "MARS block size changed; the container's nonce layout depends on it.");

static_assert(
    MARS_KEY_BYTES >= CryptoPP::MARS::MIN_KEYLENGTH
        && MARS_KEY_BYTES <= CryptoPP::MARS::MAX_KEYLENGTH,
    "MARS-448 is outside the key range this build of Crypto++ accepts.");

extern "C" KEEPVAULT_EXPORT int mars_448_ctr_xcrypt(
    const std::uint8_t key[MARS_KEY_BYTES],
    const std::uint8_t nonce[MARS_BLOCK_BYTES],
    const std::uint8_t* input,
    std::uint8_t* output,
    std::size_t length)
{
    return keepvault::xcrypt_ctr<CryptoPP::MARS::Encryption>(
        key, MARS_KEY_BYTES, nonce, input, output, length);
}

/*
 * Encrypts a single block with no counter around it.
 *
 * Only the tests use this, to compare against published vectors and against a
 * second implementation. Keeping it out of the CTR path means the vector check
 * exercises the cipher itself rather than the mode wrapped around it.
 */
extern "C" KEEPVAULT_EXPORT int mars_encrypt_block(
    const std::uint8_t* key,
    std::size_t key_length,
    const std::uint8_t input[MARS_BLOCK_BYTES],
    std::uint8_t output[MARS_BLOCK_BYTES])
{
    if (key == nullptr || input == nullptr || output == nullptr) {
        return 1;
    }

    if (key_length < CryptoPP::MARS::MIN_KEYLENGTH
        || key_length > CryptoPP::MARS::MAX_KEYLENGTH) {
        return 2;
    }

    CryptoPP::MARS::Encryption cipher;
    cipher.SetKey(key, key_length);
    cipher.ProcessBlock(input, output);
    return 0;
}
