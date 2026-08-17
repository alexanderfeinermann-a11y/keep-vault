/*
 * Native adapter for ChaCha20-Poly1305 (RFC 8439).
 *
 * The outermost layer of the v9 paranoia cascade, and the only one that is not
 * a block cipher in CTR mode. It authenticates as well as encrypts, so it does
 * not fit the shared CTR driver: it needs a nonce of its own width, produces a
 * tag, and on decryption either returns the plaintext or refuses.
 *
 * Poly1305 is additional to, not a replacement for, the container's existing
 * HMAC-SHA3-512 and Skein-MAC-1024. It authenticates the outermost ciphertext
 * as that layer sees it; the other two authenticate the container.
 *
 * Deliberately not parallelised. Poly1305 is a single pass over the ciphertext
 * with a carry chain, so splitting it means recombining polynomial evaluations,
 * and the wrong recombination produces a tag that is merely different rather
 * than obviously broken. The layer beneath it is already parallel, and this one
 * runs at the speed of one core over data that has been through five ciphers.
 */
#include "chachapoly.h"

#include "cryptopp_ctr_common.hpp"

#define CHACHAPOLY_KEY_BYTES 32
#define CHACHAPOLY_NONCE_BYTES 12
#define CHACHAPOLY_TAG_BYTES 16

/*
 * Encrypts and authenticates in one pass.
 *
 * The tag is written separately rather than appended, so the caller decides
 * where it lives and the ciphertext keeps the length of the plaintext.
 */
extern "C" KEEPVAULT_EXPORT int chacha20poly1305_encrypt(
    const std::uint8_t key[CHACHAPOLY_KEY_BYTES],
    const std::uint8_t nonce[CHACHAPOLY_NONCE_BYTES],
    const std::uint8_t* associated_data,
    std::size_t associated_length,
    const std::uint8_t* plaintext,
    std::uint8_t* ciphertext,
    std::size_t length,
    std::uint8_t tag[CHACHAPOLY_TAG_BYTES])
{
    if (key == nullptr || nonce == nullptr || tag == nullptr) {
        return 1;
    }

    if (length != 0 && (plaintext == nullptr || ciphertext == nullptr)) {
        return 1;
    }

    if (associated_length != 0 && associated_data == nullptr) {
        return 1;
    }

    try {
        CryptoPP::ChaCha20Poly1305::Encryption encryption;
        encryption.SetKeyWithIV(key, CHACHAPOLY_KEY_BYTES, nonce, CHACHAPOLY_NONCE_BYTES);
        encryption.EncryptAndAuthenticate(
            ciphertext,
            tag,
            CHACHAPOLY_TAG_BYTES,
            nonce,
            CHACHAPOLY_NONCE_BYTES,
            associated_data,
            associated_length,
            plaintext,
            length);
        return 0;
    } catch (...) {
        return 5;
    }
}

/*
 * Verifies and decrypts.
 *
 * Returns 6 when the tag does not match, and writes nothing the caller should
 * use in that case. Crypto++ clears the output buffer itself on failure; the
 * return value is what the caller must act on, because a decryption that
 * ignores the tag is a decryption with no authentication at all.
 */
extern "C" KEEPVAULT_EXPORT int chacha20poly1305_decrypt(
    const std::uint8_t key[CHACHAPOLY_KEY_BYTES],
    const std::uint8_t nonce[CHACHAPOLY_NONCE_BYTES],
    const std::uint8_t* associated_data,
    std::size_t associated_length,
    const std::uint8_t* ciphertext,
    std::uint8_t* plaintext,
    std::size_t length,
    const std::uint8_t tag[CHACHAPOLY_TAG_BYTES])
{
    if (key == nullptr || nonce == nullptr || tag == nullptr) {
        return 1;
    }

    if (length != 0 && (ciphertext == nullptr || plaintext == nullptr)) {
        return 1;
    }

    if (associated_length != 0 && associated_data == nullptr) {
        return 1;
    }

    try {
        CryptoPP::ChaCha20Poly1305::Decryption decryption;
        decryption.SetKeyWithIV(key, CHACHAPOLY_KEY_BYTES, nonce, CHACHAPOLY_NONCE_BYTES);
        const bool authentic = decryption.DecryptAndVerify(
            plaintext,
            tag,
            CHACHAPOLY_TAG_BYTES,
            nonce,
            CHACHAPOLY_NONCE_BYTES,
            associated_data,
            associated_length,
            ciphertext,
            length);
        return authentic ? 0 : 6;
    } catch (...) {
        return 5;
    }
}
