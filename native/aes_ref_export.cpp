/*
 * Native adapter for AES-256 in CTR mode.
 *
 * AES is the innermost layer of the v9 paranoia cascade, and the only one with
 * a hardware path. That path is not here: the app uses the platform's AES,
 * which reaches AES-NI on Intel and the crypto extensions on Apple silicon,
 * and falls back to this adapter when the platform implementation is missing
 * or refuses to load.
 *
 * So this is deliberately the slow one. It exists to be a reference — an
 * independent implementation the hardware path can be checked against, and a
 * way to finish a decryption on a machine where the fast path is unavailable.
 * Crypto++'s assembly paths are switched off for the same reason the other two
 * adapters switch them off: one flag set for the whole archive, and no
 * hardware acceleration to lose in a fallback that is not meant to be fast.
 */
#include "rijndael.h"

#include "cryptopp_ctr_common.hpp"

#define AES_KEY_BYTES 32
#define AES_BLOCK_BYTES 16

static_assert(
    CryptoPP::Rijndael::BLOCKSIZE == AES_BLOCK_BYTES,
    "AES block size changed; the container's nonce layout depends on it.");

static_assert(
    AES_KEY_BYTES <= CryptoPP::Rijndael::MAX_KEYLENGTH,
    "AES-256 is outside the key range this build of Crypto++ accepts.");

extern "C" KEEPVAULT_EXPORT int aes_256_ctr_xcrypt(
    const std::uint8_t key[AES_KEY_BYTES],
    const std::uint8_t nonce[AES_BLOCK_BYTES],
    const std::uint8_t* input,
    std::uint8_t* output,
    std::size_t length)
{
    return keepvault::xcrypt_ctr<CryptoPP::Rijndael::Encryption>(
        key, AES_KEY_BYTES, nonce, input, output, length);
}

/*
 * One block, no counter, for the published-vector checks and for comparing the
 * platform's AES against this one.
 */
extern "C" KEEPVAULT_EXPORT int aes_encrypt_block(
    const std::uint8_t* key,
    std::size_t key_length,
    const std::uint8_t input[AES_BLOCK_BYTES],
    std::uint8_t output[AES_BLOCK_BYTES])
{
    if (key == nullptr || input == nullptr || output == nullptr) {
        return 1;
    }

    if (key_length != 16 && key_length != 24 && key_length != 32) {
        return 2;
    }

    CryptoPP::Rijndael::Encryption cipher;
    cipher.SetKey(key, key_length);
    cipher.ProcessBlock(input, output);
    return 0;
}
