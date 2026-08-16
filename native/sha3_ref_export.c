/*
 * SHA3-512 adapter for the official FIPS 202 reference source.
 *
 * The app computes SHA3-512 and HMAC-SHA3-512 with Bouncy Castle, because
 * Apple's CryptoKit backend does not expose SHA3 through .NET on macOS. That
 * makes Bouncy Castle a load-bearing cryptographic dependency, and a
 * dependency of that weight is not taken on trust: this adapter exposes the
 * reference implementation shipped with the ML-DSA sources so the two can be
 * compared directly, over fixed known-answer vectors and over randomised
 * inputs that cross the 72-byte rate boundary of SHA3-512.
 *
 * It is a verification aid only and is never shipped inside the app bundle.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../external/ML-DSA-reference/ref/fips202.h"

#if defined(_WIN32)
#define SHA3_REF_EXPORT __declspec(dllexport)
#else
#define SHA3_REF_EXPORT __attribute__((visibility("default")))
#endif

#define SHA3_512_DIGEST_BYTES 64

/* SHA3-512 absorbs 1600 - 2*512 bits per permutation. HMAC needs the block
   size, and stating it here lets the caller assert that the library it uses in
   production agrees. */
#define SHA3_512_RATE_BYTES 72

SHA3_REF_EXPORT int sha3_512_reference_hash(
    const uint8_t* message,
    size_t message_length,
    uint8_t* digest,
    size_t digest_length)
{
    if (digest == NULL || digest_length != SHA3_512_DIGEST_BYTES) {
        return -1;
    }

    if (message == NULL && message_length != 0) {
        return -2;
    }

    /* The reference refuses a NULL pointer even for an empty message. */
    static const uint8_t empty = 0;
    sha3_512(digest, message == NULL ? &empty : message, message_length);
    return 0;
}

SHA3_REF_EXPORT size_t sha3_512_reference_rate(void)
{
    return SHA3_512_RATE_BYTES;
}

/*
 * HMAC-SHA3-512 built strictly from the reference hash, per FIPS 198-1.
 *
 * The production side gets HMAC from Bouncy Castle, whose block size comes
 * from its own digest metadata. Recomputing it here from the reference means a
 * disagreement about the rate — the single most likely way an HMAC-SHA3
 * implementation goes subtly wrong — shows up as a mismatch instead of
 * silently producing tags that only that one library can reproduce.
 */
SHA3_REF_EXPORT int hmac_sha3_512_reference(
    const uint8_t* key,
    size_t key_length,
    const uint8_t* message,
    size_t message_length,
    uint8_t* tag,
    size_t tag_length)
{
    uint8_t padded_key[SHA3_512_RATE_BYTES];
    uint8_t inner_pad[SHA3_512_RATE_BYTES];
    uint8_t outer_pad[SHA3_512_RATE_BYTES];
    uint8_t inner_digest[SHA3_512_DIGEST_BYTES];
    uint8_t* inner_input = NULL;
    uint8_t outer_input[SHA3_512_RATE_BYTES + SHA3_512_DIGEST_BYTES];
    int result = -1;

    if (tag == NULL || tag_length != SHA3_512_DIGEST_BYTES) {
        return -1;
    }

    if ((key == NULL && key_length != 0) || (message == NULL && message_length != 0)) {
        return -2;
    }

    memset(padded_key, 0, sizeof(padded_key));
    if (key_length > SHA3_512_RATE_BYTES) {
        if (sha3_512_reference_hash(key, key_length, padded_key, SHA3_512_DIGEST_BYTES) != 0) {
            return -3;
        }
    } else if (key_length != 0) {
        memcpy(padded_key, key, key_length);
    }

    for (size_t index = 0; index < SHA3_512_RATE_BYTES; ++index) {
        inner_pad[index] = (uint8_t)(padded_key[index] ^ 0x36);
        outer_pad[index] = (uint8_t)(padded_key[index] ^ 0x5C);
    }

    if (message_length > SIZE_MAX - SHA3_512_RATE_BYTES) {
        goto cleanup;
    }

    inner_input = (uint8_t*)malloc(SHA3_512_RATE_BYTES + message_length);
    if (inner_input == NULL) {
        goto cleanup;
    }

    memcpy(inner_input, inner_pad, SHA3_512_RATE_BYTES);
    if (message_length != 0) {
        memcpy(inner_input + SHA3_512_RATE_BYTES, message, message_length);
    }

    if (sha3_512_reference_hash(
            inner_input,
            SHA3_512_RATE_BYTES + message_length,
            inner_digest,
            SHA3_512_DIGEST_BYTES) != 0) {
        goto cleanup;
    }

    memcpy(outer_input, outer_pad, SHA3_512_RATE_BYTES);
    memcpy(outer_input + SHA3_512_RATE_BYTES, inner_digest, SHA3_512_DIGEST_BYTES);
    if (sha3_512_reference_hash(outer_input, sizeof(outer_input), tag, SHA3_512_DIGEST_BYTES) != 0) {
        goto cleanup;
    }

    result = 0;

cleanup:
    if (inner_input != NULL) {
        memset(inner_input, 0, SHA3_512_RATE_BYTES + message_length);
        free(inner_input);
    }

    memset(padded_key, 0, sizeof(padded_key));
    memset(inner_pad, 0, sizeof(inner_pad));
    memset(outer_pad, 0, sizeof(outer_pad));
    memset(inner_digest, 0, sizeof(inner_digest));
    memset(outer_input, 0, sizeof(outer_input));
    return result;
}
