/*
 * Native adapter for SHACAL-2 with a 512-bit key, in CTR mode.
 *
 * SHACAL-2 is the third layer of the v9 paranoia cascade. Like MARS it has no
 * reference implementation of its own here and comes from the vendored Crypto++
 * release; see external/VENDOR-PROVENANCE.md.
 *
 * Note the block width: SHACAL-2 works on 256-bit blocks, twice AES's and half
 * Kalyna's. The counter therefore spans 32 bytes, not 16, and the container's
 * nonce split has to account for that.
 */
#include "shacal2.h"

#include "cryptopp_ctr_common.hpp"

#define SHACAL2_KEY_BYTES 64
#define SHACAL2_BLOCK_BYTES 32

static_assert(
    CryptoPP::SHACAL2::BLOCKSIZE == SHACAL2_BLOCK_BYTES,
    "SHACAL-2 block size changed; the container's nonce layout depends on it.");

static_assert(
    SHACAL2_KEY_BYTES >= CryptoPP::SHACAL2::MIN_KEYLENGTH
        && SHACAL2_KEY_BYTES <= CryptoPP::SHACAL2::MAX_KEYLENGTH,
    "SHACAL-2-512 is outside the key range this build of Crypto++ accepts.");

extern "C" KEEPVAULT_EXPORT int shacal2_512_ctr_xcrypt(
    const std::uint8_t key[SHACAL2_KEY_BYTES],
    const std::uint8_t nonce[SHACAL2_BLOCK_BYTES],
    const std::uint8_t* input,
    std::uint8_t* output,
    std::size_t length)
{
    return keepvault::xcrypt_ctr<CryptoPP::SHACAL2::Encryption>(
        key, SHACAL2_KEY_BYTES, nonce, input, output, length);
}

/*
 * Encrypts a single block, for the published-vector checks in the tests.
 */
extern "C" KEEPVAULT_EXPORT int shacal2_encrypt_block(
    const std::uint8_t* key,
    std::size_t key_length,
    const std::uint8_t input[SHACAL2_BLOCK_BYTES],
    std::uint8_t output[SHACAL2_BLOCK_BYTES])
{
    if (key == nullptr || input == nullptr || output == nullptr) {
        return 1;
    }

    if (key_length < CryptoPP::SHACAL2::MIN_KEYLENGTH
        || key_length > CryptoPP::SHACAL2::MAX_KEYLENGTH) {
        return 2;
    }

    CryptoPP::SHACAL2::Encryption cipher;
    cipher.SetKey(key, key_length);
    cipher.ProcessBlock(input, output);
    return 0;
}
