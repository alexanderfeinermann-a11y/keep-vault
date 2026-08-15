#include <CommonCrypto/CommonDigest.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MLDSA87_PUBLIC_KEY_BYTES 2592U
#define MLDSA87_PRIVATE_KEY_BYTES 4896U
#define MLDSA87_SIGNATURE_BYTES 4627U

typedef int (*kalyna_ctr_fn)(
    const uint8_t[64],
    const uint8_t[64],
    const uint8_t*,
    uint8_t*,
    size_t);
typedef int (*threefish_block_fn)(
    const uint8_t[128],
    const uint8_t[16],
    const uint8_t[128],
    uint8_t[128]);
typedef int (*skein_hash_fn)(const uint8_t*, size_t, uint8_t[128]);
typedef int (*mldsa_keypair_fn)(uint8_t*, size_t, uint8_t*, size_t);
typedef int (*mldsa_sign_fn)(
    uint8_t*,
    size_t,
    size_t*,
    const uint8_t*,
    size_t,
    const uint8_t*,
    size_t,
    const uint8_t*,
    size_t);
typedef int (*mldsa_verify_fn)(
    const uint8_t*,
    size_t,
    const uint8_t*,
    size_t,
    const uint8_t*,
    size_t,
    const uint8_t*,
    size_t);
typedef const char* (*mldsa_commit_fn)(void);
typedef int (*argon2_hash_fn)(
    uint32_t,
    uint32_t,
    uint32_t,
    uint8_t*,
    uint32_t,
    uint8_t*,
    uint32_t,
    uint8_t*,
    uint32_t);

_Noreturn static void fail(const char* message)
{
    fprintf(stderr, "Native KAT failed: %s\n", message);
    exit(1);
}

static void secure_zero(void* pointer, size_t length)
{
    (void)memset_s(pointer, length, 0, length);
}

static void require_equal(
    const uint8_t* expected,
    const uint8_t* actual,
    size_t length,
    const char* message)
{
    uint8_t difference = 0;
    for (size_t index = 0; index < length; ++index) {
        difference |= (uint8_t)(expected[index] ^ actual[index]);
    }
    if (difference != 0) {
        fail(message);
    }
}

static uint8_t hex_nibble(char value)
{
    if (value >= '0' && value <= '9') {
        return (uint8_t)(value - '0');
    }
    if (value >= 'a' && value <= 'f') {
        return (uint8_t)(value - 'a' + 10);
    }
    if (value >= 'A' && value <= 'F') {
        return (uint8_t)(value - 'A' + 10);
    }
    fail("an embedded hexadecimal vector is malformed");
}

static void decode_hex(const char* encoded, uint8_t* output, size_t output_length)
{
    if (strlen(encoded) != output_length * 2U) {
        fail("an embedded hexadecimal vector has the wrong length");
    }
    for (size_t index = 0; index < output_length; ++index) {
        output[index] = (uint8_t)((hex_nibble(encoded[index * 2U]) << 4U)
            | hex_nibble(encoded[index * 2U + 1U]));
    }
}

static void* open_library(const char* directory, const char* name)
{
    size_t required = strlen(directory) + strlen(name) + 2U;
    char* path = calloc(required, 1U);
    if (path == NULL) {
        fail("memory allocation failed while resolving a KAT library");
    }
    int written = snprintf(path, required, "%s/%s", directory, name);
    if (written < 0 || (size_t)written >= required) {
        free(path);
        fail("a KAT library path is too long");
    }
    void* handle = dlopen(path, RTLD_LOCAL | RTLD_NOW);
    if (handle == NULL) {
        fprintf(stderr, "Native KAT could not load %s: %s\n", path, dlerror());
        free(path);
        exit(1);
    }
    free(path);
    return handle;
}

static void load_symbol(void* handle, const char* name, void* destination, size_t destination_size)
{
    void* symbol = dlsym(handle, name);
    if (symbol == NULL || destination_size != sizeof(symbol)) {
        fprintf(stderr, "Native KAT could not resolve %s: %s\n", name, dlerror());
        exit(1);
    }
    memcpy(destination, &symbol, sizeof(symbol));
}

static void run_kalyna_kat(const char* directory)
{
    static const uint64_t expected_words[8] = {
        UINT64_C(0x6a351c811be3264a), UINT64_C(0x1a239605cad61da6),
        UINT64_C(0xa1f347aa5483ba67), UINT64_C(0xb856eb20c3ee1d3e),
        UINT64_C(0x66ab5b1717f4d095), UINT64_C(0x6cc815bb34f1d62f),
        UINT64_C(0xb7fe6e85266a90cb), UINT64_C(0xd9d90d947264bcc5),
    };
    uint8_t key[64];
    uint8_t nonce[64];
    uint8_t input[64] = {0};
    uint8_t output[64] = {0};
    for (size_t index = 0; index < sizeof(key); ++index) {
        key[index] = (uint8_t)index;
        nonce[index] = (uint8_t)(index + 0x40U);
    }

    void* handle = open_library(directory, "libkalyna_ref.dylib");
    kalyna_ctr_fn xcrypt = NULL;
    load_symbol(handle, "kalyna_512_512_ctr_xcrypt", &xcrypt, sizeof(xcrypt));
    if (xcrypt(key, nonce, input, output, sizeof(output)) != 0) {
        fail("Kalyna-512/512 CTR adapter returned an error");
    }
    require_equal(
        (const uint8_t*)expected_words,
        output,
        sizeof(output),
        "Kalyna-512/512 official CTR vector mismatch");
    secure_zero(key, sizeof(key));
    secure_zero(nonce, sizeof(nonce));
    secure_zero(output, sizeof(output));
    if (dlclose(handle) != 0) {
        fail("Kalyna KAT library could not be closed");
    }
}

static void run_threefish_and_skein_kats(const char* directory)
{
    static const uint64_t expected_threefish_words[16] = {
        UINT64_C(0x04B3053D0A3D5CF0), UINT64_C(0x0136E0D1C7DD85F7),
        UINT64_C(0x067B212F6EA78A5C), UINT64_C(0x0DA9C10B4C54E1C6),
        UINT64_C(0x0F4EC27394CBACF0), UINT64_C(0x32437F0568EA4FD5),
        UINT64_C(0xCFF56D1D7654B49C), UINT64_C(0xA2D5FB14369B2E7B),
        UINT64_C(0x540306B460472E0B), UINT64_C(0x71C18254BCEA820D),
        UINT64_C(0xC36B4068BEAF32C8), UINT64_C(0xFA4329597A360095),
        UINT64_C(0xC4A36C28434A5B9A), UINT64_C(0xD54331444B1046CF),
        UINT64_C(0xDF11834830B2A460), UINT64_C(0x1E39E8DFE1F7EE4F),
    };
    static const char expected_skein_hex[] =
        "E62C05802EA0152407CDD8787FDA9E35703DE862A4FBC119CFF8590AFE79250B"
        "CCC8B3FAF1BD2422AB5C0D263FB2F8AFB3F796F048000381531B6F00D85161BC"
        "0FFF4BEF2486B1EBCD3773FABF50AD4AD5639AF9040E3F29C6C931301BF79832"
        "E9DA09857E831E82EF8B4691C235656515D437D2BDA33BCEC001C67FFDE15BA8";
    uint8_t zero_key[128] = {0};
    uint8_t zero_tweak[16] = {0};
    uint8_t zero_input[128] = {0};
    uint8_t block_output[128] = {0};
    uint8_t skein_output[128] = {0};
    uint8_t expected_skein[128] = {0};
    const uint8_t skein_message[1] = {0xFF};
    decode_hex(expected_skein_hex, expected_skein, sizeof(expected_skein));

    void* handle = open_library(directory, "libthreefish_ref.dylib");
    threefish_block_fn encrypt_block = NULL;
    skein_hash_fn hash = NULL;
    load_symbol(handle, "threefish_1024_encrypt_block", &encrypt_block, sizeof(encrypt_block));
    load_symbol(handle, "skein_1024_hash", &hash, sizeof(hash));
    if (encrypt_block(zero_key, zero_tweak, zero_input, block_output) != 0) {
        fail("Threefish-1024 adapter returned an error");
    }
    require_equal(
        (const uint8_t*)expected_threefish_words,
        block_output,
        sizeof(block_output),
        "Threefish-1024 official zero vector mismatch");
    if (hash(skein_message, sizeof(skein_message), skein_output) != 0) {
        fail("Skein-1024 adapter returned an error");
    }
    require_equal(expected_skein, skein_output, sizeof(skein_output), "Skein-1024 official 8-bit KAT mismatch");
    secure_zero(block_output, sizeof(block_output));
    secure_zero(skein_output, sizeof(skein_output));
    secure_zero(expected_skein, sizeof(expected_skein));
    if (dlclose(handle) != 0) {
        fail("Threefish/Skein KAT library could not be closed");
    }
}

static void run_mldsa_self_test(const char* directory)
{
    static const char expected_commit[] =
        "pq-crystals/dilithium@d35ba3fe5449bee3e6d43e1f296c3ca818bd36be";
    static const uint8_t message[] = "Keep Vault ML-DSA-87 per-slice self-test";
    static const uint8_t context[] = "KeepVault/KAT/v1";
    uint8_t* public_key = calloc(MLDSA87_PUBLIC_KEY_BYTES, 1U);
    uint8_t* private_key = calloc(MLDSA87_PRIVATE_KEY_BYTES, 1U);
    uint8_t* signature = calloc(MLDSA87_SIGNATURE_BYTES, 1U);
    uint8_t* second_signature = calloc(MLDSA87_SIGNATURE_BYTES, 1U);
    if (public_key == NULL || private_key == NULL || signature == NULL || second_signature == NULL) {
        fail("ML-DSA-87 self-test allocation failed");
    }

    void* handle = open_library(directory, "libmldsa87_ref.dylib");
    mldsa_keypair_fn keypair = NULL;
    mldsa_sign_fn sign = NULL;
    mldsa_verify_fn verify = NULL;
    mldsa_commit_fn commit = NULL;
    load_symbol(handle, "mldsa87_keypair", &keypair, sizeof(keypair));
    load_symbol(handle, "mldsa87_sign", &sign, sizeof(sign));
    load_symbol(handle, "mldsa87_verify", &verify, sizeof(verify));
    load_symbol(handle, "mldsa87_reference_commit", &commit, sizeof(commit));
    if (commit() == NULL || strcmp(commit(), expected_commit) != 0) {
        fail("ML-DSA-87 reference revision mismatch");
    }
    if (keypair(public_key, MLDSA87_PUBLIC_KEY_BYTES, private_key, MLDSA87_PRIVATE_KEY_BYTES) != 0) {
        fail("ML-DSA-87 key generation failed");
    }
    size_t signature_length = 0;
    if (sign(
            signature,
            MLDSA87_SIGNATURE_BYTES,
            &signature_length,
            message,
            sizeof(message) - 1U,
            context,
            sizeof(context) - 1U,
            private_key,
            MLDSA87_PRIVATE_KEY_BYTES) != 0
        || signature_length != MLDSA87_SIGNATURE_BYTES) {
        fail("ML-DSA-87 signing failed");
    }
    if (verify(
            signature,
            signature_length,
            message,
            sizeof(message) - 1U,
            context,
            sizeof(context) - 1U,
            public_key,
            MLDSA87_PUBLIC_KEY_BYTES) != 0) {
        fail("ML-DSA-87 verification failed");
    }
    uint8_t changed_message[sizeof(message) - 1U];
    memcpy(changed_message, message, sizeof(changed_message));
    changed_message[0] ^= 0x80U;
    if (verify(
            signature,
            signature_length,
            changed_message,
            sizeof(changed_message),
            context,
            sizeof(context) - 1U,
            public_key,
            MLDSA87_PUBLIC_KEY_BYTES) == 0) {
        fail("ML-DSA-87 accepted a changed message");
    }
    signature[MLDSA87_SIGNATURE_BYTES / 2U] ^= 1U;
    if (verify(
            signature,
            signature_length,
            message,
            sizeof(message) - 1U,
            context,
            sizeof(context) - 1U,
            public_key,
            MLDSA87_PUBLIC_KEY_BYTES) == 0) {
        fail("ML-DSA-87 accepted a changed signature");
    }
    signature[MLDSA87_SIGNATURE_BYTES / 2U] ^= 1U;
    size_t second_length = 0;
    if (sign(
            second_signature,
            MLDSA87_SIGNATURE_BYTES,
            &second_length,
            message,
            sizeof(message) - 1U,
            context,
            sizeof(context) - 1U,
            private_key,
            MLDSA87_PRIVATE_KEY_BYTES) != 0
        || second_length != MLDSA87_SIGNATURE_BYTES
        || memcmp(signature, second_signature, MLDSA87_SIGNATURE_BYTES) == 0) {
        fail("ML-DSA-87 randomized signing self-test failed");
    }

    secure_zero(public_key, MLDSA87_PUBLIC_KEY_BYTES);
    secure_zero(private_key, MLDSA87_PRIVATE_KEY_BYTES);
    secure_zero(signature, MLDSA87_SIGNATURE_BYTES);
    secure_zero(second_signature, MLDSA87_SIGNATURE_BYTES);
    free(public_key);
    free(private_key);
    free(signature);
    free(second_signature);
    if (dlclose(handle) != 0) {
        fail("ML-DSA-87 self-test library could not be closed");
    }
}

static void run_argon2_policy_kat(const char* directory)
{
    static const char expected_hex[] =
        "EA1770676778A3197837EC64A7BBD78163F7C8986909089B86941A9AF473187A"
        "EDE081B1ADD1A54D041B3C2D950168B1069B7450B5DBC1F2AB215D1841FE8FFE";
    uint8_t password[] = "KeepVault-Native-KAT-Argon2id-1GiB-2026";
    uint8_t salt[] = "0123456789abcdef0123456789abcdef";
    uint8_t output[64] = {0};
    uint8_t expected[64] = {0};
    decode_hex(expected_hex, expected, sizeof(expected));

    void* handle = open_library(directory, "libargon2_ref.dylib");
    argon2_hash_fn hash = NULL;
    load_symbol(handle, "phc_argon2id_hash_raw", &hash, sizeof(hash));
    if (hash(
            4U,
            1048576U,
            4U,
            password,
            (uint32_t)(sizeof(password) - 1U),
            salt,
            (uint32_t)(sizeof(salt) - 1U),
            output,
            (uint32_t)sizeof(output)) != 0) {
        fail("the enforced Argon2id 1-GiB/4/4 adapter profile failed");
    }
    require_equal(expected, output, sizeof(output), "Argon2id 1-GiB/4/4 policy KAT mismatch");

    memset(output, 0xA5, sizeof(output));
    if (hash(
            4U,
            65536U,
            4U,
            password,
            (uint32_t)(sizeof(password) - 1U),
            salt,
            (uint32_t)(sizeof(salt) - 1U),
            output,
            (uint32_t)sizeof(output)) == 0) {
        fail("Argon2id adapter accepted a weakened memory profile");
    }
    for (size_t index = 0; index < sizeof(output); ++index) {
        if (output[index] != 0xA5U) {
            fail("Argon2id adapter modified output after rejecting a weakened profile");
        }
    }
    secure_zero(password, sizeof(password));
    secure_zero(salt, sizeof(salt));
    secure_zero(output, sizeof(output));
    secure_zero(expected, sizeof(expected));
    if (dlclose(handle) != 0) {
        fail("Argon2id KAT library could not be closed");
    }
}

int main(int argument_count, char** arguments)
{
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "Keep Vault native KAT vectors require a reviewed little-endian target."
#endif
    if (argument_count != 2 || arguments[1][0] == '\0') {
        fprintf(stderr, "Usage: %s /absolute/native/slice/directory\n", arguments[0]);
        return 64;
    }
    run_kalyna_kat(arguments[1]);
    run_threefish_and_skein_kats(arguments[1]);
    run_mldsa_self_test(arguments[1]);
    run_argon2_policy_kat(arguments[1]);
    puts("Native per-slice cryptographic KATs passed.");
    return 0;
}
