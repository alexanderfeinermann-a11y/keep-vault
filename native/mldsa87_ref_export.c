/*
 * Platform adapter for the official pq-crystals Dilithium reference source.
 * DILITHIUM_MODE=5 is the ML-DSA-87 parameter set standardized by FIPS 204.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#elif defined(__APPLE__)
#include <Security/SecRandom.h>
#else
#error "A reviewed operating-system CSPRNG adapter is required for this platform."
#endif
#include "../external/ML-DSA-reference/ref/sign.h"
#include "../external/ML-DSA-reference/ref/params.h"

#if defined(_WIN32)
#define MLDSA_EXPORT __declspec(dllexport)
#else
#define MLDSA_EXPORT __attribute__((visibility("default")))
#endif

static void secure_zero(void* pointer, size_t length)
{
    volatile uint8_t* bytes = (volatile uint8_t*)pointer;
    while (length-- != 0) {
        *bytes++ = 0;
    }
}

void randombytes(uint8_t* output, size_t length)
{
#if defined(_WIN32)
    while (length != 0) {
        ULONG chunk = length > 0xFFFFFFFFu ? 0xFFFFFFFFu : (ULONG)length;
        NTSTATUS status = BCryptGenRandom(
            NULL,
            output,
            chunk,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (!BCRYPT_SUCCESS(status)) {
            if (output != NULL) {
                secure_zero(output, length);
            }

            abort();
        }

        output += chunk;
        length -= chunk;
    }
#else
    if ((output == NULL && length != 0)
        || SecRandomCopyBytes(kSecRandomDefault, length, output) != errSecSuccess) {
        if (output != NULL) {
            secure_zero(output, length);
        }

        abort();
    }
#endif
}

MLDSA_EXPORT int mldsa87_keypair(
    uint8_t* public_key,
    size_t public_key_length,
    uint8_t* private_key,
    size_t private_key_length)
{
    if (public_key == NULL
        || private_key == NULL
        || public_key_length != CRYPTO_PUBLICKEYBYTES
        || private_key_length != CRYPTO_SECRETKEYBYTES) {
        return 1;
    }

    return crypto_sign_keypair(public_key, private_key) == 0 ? 0 : 2;
}

MLDSA_EXPORT int mldsa87_sign(
    uint8_t* signature,
    size_t signature_capacity,
    size_t* signature_length,
    const uint8_t* message,
    size_t message_length,
    const uint8_t* context,
    size_t context_length,
    const uint8_t* private_key,
    size_t private_key_length)
{
    if (signature == NULL
        || signature_length == NULL
        || (message == NULL && message_length != 0)
        || (context == NULL && context_length != 0)
        || context_length > 255
        || private_key == NULL
        || private_key_length != CRYPTO_SECRETKEYBYTES
        || signature_capacity < CRYPTO_BYTES) {
        return 1;
    }

    size_t actual_length = 0;
    int result = crypto_sign_signature(
        signature,
        &actual_length,
        message,
        message_length,
        context,
        context_length,
        private_key);
    if (result != 0 || actual_length != CRYPTO_BYTES) {
        secure_zero(signature, signature_capacity);
        *signature_length = 0;
        return 2;
    }

    *signature_length = actual_length;
    return 0;
}

MLDSA_EXPORT int mldsa87_verify(
    const uint8_t* signature,
    size_t signature_length,
    const uint8_t* message,
    size_t message_length,
    const uint8_t* context,
    size_t context_length,
    const uint8_t* public_key,
    size_t public_key_length)
{
    if (signature == NULL
        || signature_length != CRYPTO_BYTES
        || (message == NULL && message_length != 0)
        || (context == NULL && context_length != 0)
        || context_length > 255
        || public_key == NULL
        || public_key_length != CRYPTO_PUBLICKEYBYTES) {
        return 1;
    }

    return crypto_sign_verify(
        signature,
        signature_length,
        message,
        message_length,
        context,
        context_length,
        public_key) == 0 ? 0 : 2;
}

MLDSA_EXPORT const char* mldsa87_reference_commit(void)
{
    return "pq-crystals/dilithium@d35ba3fe5449bee3e6d43e1f296c3ca818bd36be";
}
