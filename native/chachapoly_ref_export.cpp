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

/*
 * Raw ChaCha20, and Poly1305 over a whole stream.
 *
 * The cascade cannot use the AEAD above for its outer layer. The container
 * encrypts in 16 MiB chunks and authenticates the finished ciphertext, so an
 * AEAD applied per chunk would produce a tag per chunk that says nothing about
 * the order those chunks appear in — dropping or swapping two of them would
 * leave every tag valid. Poly1305 is therefore run once over the entire
 * ciphertext, beside the container's HMAC-SHA3-512 and Skein-MAC-1024, where it
 * covers ordering and length as well as content.
 *
 * That needs the two halves separately: ChaCha20 as a keystream generator the
 * chunk loop can position by block, and Poly1305 as something that can be fed
 * incrementally.
 */
#include "chacha.h"
#include "poly1305.h"

/*
 * Encrypts or decrypts, starting at an explicit block counter.
 *
 * ChaChaTLS, not ChaCha: Crypto++ carries both Bernstein's original with its
 * 8-byte nonce and the IETF form from RFC 8439 with a 12-byte nonce and a
 * 32-bit block counter. The container uses the IETF form, and the two produce
 * different keystreams from the same inputs.
 *
 * The counter is what lets a chunk be processed on its own: the caller passes
 * the block index the chunk begins at, so the keystream lines up with the
 * position in the stream rather than restarting per call.
 */
extern "C" KEEPVAULT_EXPORT int chacha20_xcrypt(
    const std::uint8_t key[CHACHAPOLY_KEY_BYTES],
    const std::uint8_t nonce[CHACHAPOLY_NONCE_BYTES],
    std::uint32_t block_counter,
    const std::uint8_t* input,
    std::uint8_t* output,
    std::size_t length)
{
    if (key == nullptr || nonce == nullptr) {
        return 1;
    }

    if (length != 0 && (input == nullptr || output == nullptr)) {
        return 1;
    }

    try {
        // The initial block counter is not part of the IV. Crypto++ reads it
        // from an "InitialBlock" parameter at SetKey time and puts it in
        // state[12]; the 12-byte nonce goes to state[13..15], exactly as
        // RFC 8439 section 2.3 lays the state out. Building a 16-byte
        // counter||nonce IV instead — which is what an earlier version of this
        // function did — produces a different keystream that matches neither
        // the RFC nor this file's own AEAD.
        CryptoPP::ChaChaTLS::Encryption cipher;
        cipher.SetKeyWithIV(
            key,
            CHACHAPOLY_KEY_BYTES,
            nonce,
            CHACHAPOLY_NONCE_BYTES);
        cipher.SetKey(
            key,
            CHACHAPOLY_KEY_BYTES,
            CryptoPP::MakeParameters(
                "InitialBlock", static_cast<CryptoPP::word64>(block_counter))
                (CryptoPP::Name::IV(),
                 CryptoPP::ConstByteArrayParameter(nonce, CHACHAPOLY_NONCE_BYTES)));
        cipher.ProcessData(output, input, length);
        return 0;
    } catch (...) {
        return 5;
    }
}

/*
 * Poly1305 over a stream, in three calls.
 *
 * This is the RFC 8439 form, which takes the 32-byte one-time key r||s
 * directly, rather than Bernstein's original AES-keyed variant.
 *
 * The one-time key is the caller's to supply and must never be reused with a
 * different message: Poly1305 is a one-time authenticator, and two messages
 * under one key hand an attacker the ability to forge a third. The container
 * derives it per archive from the Argon2id output.
 */
extern "C" KEEPVAULT_EXPORT void* poly1305_create(const std::uint8_t key[32])
{
    if (key == nullptr) {
        return nullptr;
    }

    try {
        auto* mac = new CryptoPP::Poly1305TLS();
        mac->SetKey(key, 32);
        return mac;
    } catch (...) {
        return nullptr;
    }
}

extern "C" KEEPVAULT_EXPORT int poly1305_update(void* handle, const std::uint8_t* data, std::size_t length)
{
    if (handle == nullptr || (length != 0 && data == nullptr)) {
        return 1;
    }

    try {
        static_cast<CryptoPP::Poly1305TLS*>(handle)->Update(data, length);
        return 0;
    } catch (...) {
        return 5;
    }
}

extern "C" KEEPVAULT_EXPORT int poly1305_final(void* handle, std::uint8_t tag[CHACHAPOLY_TAG_BYTES])
{
    if (handle == nullptr || tag == nullptr) {
        return 1;
    }

    try {
        static_cast<CryptoPP::Poly1305TLS*>(handle)->Final(tag);
        return 0;
    } catch (...) {
        return 5;
    }
}

extern "C" KEEPVAULT_EXPORT void poly1305_destroy(void* handle)
{
    delete static_cast<CryptoPP::Poly1305TLS*>(handle);
}
