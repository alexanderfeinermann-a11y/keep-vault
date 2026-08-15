/*
 * Threefish-1024 adapter for the official Skein 1.3 reference source.
 *
 * skein_block.c implements Threefish followed by Skein's UBI feed-forward.
 * XORing the input block with that result exposes the raw Threefish block
 * cipher without changing the reference rounds, rotations, or key schedule.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32)
#include <windows.h>
#else
#include <errno.h>
#include <pthread.h>
#include <sys/mman.h>
#include <unistd.h>
#endif
#include "../external/Skein-reference/NIST/CD/Reference_Implementation/skein.h"
#include "../external/Skein-reference/NIST/CD/Reference_Implementation/skein_port.h"

#if defined(_WIN32)
#define THREEFISH_EXPORT __declspec(dllexport)
#else
#define THREEFISH_EXPORT __attribute__((visibility("default")))
#endif
#define THREEFISH_BLOCK_BYTES 128
#define THREEFISH_TWEAK_BYTES 16
/* CTR mode splits into independent block ranges, so the ciphertext is
   identical no matter how many workers process it. The cap therefore only
   bounds the stack-allocated job tables and lets the counter mode scale across
   every logical processor, hyperthreads included. */
#define THREEFISH_MAX_THREADS 64
#define THREEFISH_PARALLEL_THRESHOLD_BYTES (8 * 1024 * 1024)
#define THREEFISH_MIN_BYTES_PER_THREAD (1024 * 1024)
#define SKEIN1024_DIGEST_BYTES 128
#define SKEIN1024_MAC_KEY_BYTES 128

void Skein1024_Process_Block(
    Skein1024_Ctxt_t* ctx,
    const u08b_t* block,
    size_t block_count,
    size_t byte_count_add);

static void secure_zero(void* pointer, size_t length)
{
#if defined(_WIN32)
    SecureZeroMemory(pointer, length);
#elif defined(__APPLE__)
    (void)memset_s(pointer, length, 0, length);
#else
    volatile uint8_t* bytes = (volatile uint8_t*)pointer;
    while (length-- != 0) {
        *bytes++ = 0;
    }
#endif
}

typedef struct skein1024_stream_state {
    Skein1024_Ctxt_t context;
    int finalized;
    int locked;
} skein1024_stream_state;

static skein1024_stream_state* create_skein_state(
    const uint8_t* key,
    size_t key_length)
{
    if ((key == NULL && key_length != 0)
        || (key != NULL && key_length != SKEIN1024_MAC_KEY_BYTES)) {
        return NULL;
    }

#if defined(_WIN32)
    skein1024_stream_state* state = (skein1024_stream_state*)VirtualAlloc(
        NULL,
        sizeof(skein1024_stream_state),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);
#else
    skein1024_stream_state* state = (skein1024_stream_state*)mmap(
        NULL,
        sizeof(skein1024_stream_state),
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANON,
        -1,
        0);
    if (state == MAP_FAILED) {
        state = NULL;
    }
#endif
    if (state == NULL) {
        return NULL;
    }

    memset(state, 0, sizeof(*state));
#if defined(_WIN32)
    state->locked = VirtualLock(state, sizeof(*state)) != 0;
#else
    state->locked = mlock(state, sizeof(*state)) == 0;
#endif
    if (key != NULL && !state->locked) {
        secure_zero(state, sizeof(*state));
#if defined(_WIN32)
        VirtualFree(state, 0, MEM_RELEASE);
#else
        (void)munmap(state, sizeof(*state));
#endif
        return NULL;
    }

    int result = key == NULL
        ? Skein1024_Init(&state->context, 1024)
        : Skein1024_InitExt(
            &state->context,
            1024,
            SKEIN_CFG_TREE_INFO_SEQUENTIAL,
            key,
            key_length);
    if (result != SKEIN_SUCCESS) {
        int was_locked = state->locked;
        secure_zero(state, sizeof(*state));
        if (was_locked) {
#if defined(_WIN32)
            VirtualUnlock(state, sizeof(*state));
#else
            (void)munlock(state, sizeof(*state));
#endif
        }

#if defined(_WIN32)
        VirtualFree(state, 0, MEM_RELEASE);
#else
        (void)munmap(state, sizeof(*state));
#endif
        return NULL;
    }

    return state;
}

THREEFISH_EXPORT void* skein_1024_create(void)
{
    return create_skein_state(NULL, 0);
}

THREEFISH_EXPORT void* skein_1024_mac_create(
    const uint8_t key[SKEIN1024_MAC_KEY_BYTES],
    size_t key_length)
{
    return create_skein_state(key, key_length);
}

THREEFISH_EXPORT int skein_1024_update(
    void* handle,
    const uint8_t* input,
    size_t length)
{
    skein1024_stream_state* state = (skein1024_stream_state*)handle;
    if (state == NULL || state->finalized || (input == NULL && length != 0)) {
        return 1;
    }

    return Skein1024_Update(&state->context, input, length) == SKEIN_SUCCESS
        ? 0
        : 2;
}

THREEFISH_EXPORT int skein_1024_final(
    void* handle,
    uint8_t output[SKEIN1024_DIGEST_BYTES],
    size_t output_length)
{
    skein1024_stream_state* state = (skein1024_stream_state*)handle;
    if (state == NULL
        || state->finalized
        || output == NULL
        || output_length != SKEIN1024_DIGEST_BYTES) {
        return 1;
    }

    int result = Skein1024_Final(&state->context, output);
    secure_zero(&state->context, sizeof(state->context));
    state->finalized = 1;
    return result == SKEIN_SUCCESS ? 0 : 2;
}

THREEFISH_EXPORT void skein_1024_destroy(void* handle)
{
    skein1024_stream_state* state = (skein1024_stream_state*)handle;
    if (state == NULL) {
        return;
    }

    int was_locked = state->locked;
    secure_zero(state, sizeof(*state));
    if (was_locked) {
#if defined(_WIN32)
        VirtualUnlock(state, sizeof(*state));
#else
        (void)munlock(state, sizeof(*state));
#endif
    }

#if defined(_WIN32)
    VirtualFree(state, 0, MEM_RELEASE);
#else
    (void)munmap(state, sizeof(*state));
#endif
}

THREEFISH_EXPORT int skein_1024_hash(
    const uint8_t* input,
    size_t length,
    uint8_t output[SKEIN1024_DIGEST_BYTES])
{
    if ((input == NULL && length != 0) || output == NULL) {
        return 1;
    }

    skein1024_stream_state* state = create_skein_state(NULL, 0);
    if (state == NULL) {
        return 3;
    }

    int result = skein_1024_update(state, input, length);
    if (result == 0) {
        result = skein_1024_final(state, output, SKEIN1024_DIGEST_BYTES);
    }

    skein_1024_destroy(state);
    return result;
}

THREEFISH_EXPORT int skein_1024_mac(
    const uint8_t key[SKEIN1024_MAC_KEY_BYTES],
    size_t key_length,
    const uint8_t* input,
    size_t length,
    uint8_t output[SKEIN1024_DIGEST_BYTES])
{
    if (key == NULL
        || key_length != SKEIN1024_MAC_KEY_BYTES
        || (input == NULL && length != 0)
        || output == NULL) {
        return 1;
    }

    skein1024_stream_state* state = create_skein_state(key, key_length);
    if (state == NULL) {
        return 3;
    }

    int result = skein_1024_update(state, input, length);
    if (result == 0) {
        result = skein_1024_final(state, output, SKEIN1024_DIGEST_BYTES);
    }

    skein_1024_destroy(state);
    return result;
}

static int increment_counter(uint8_t counter[THREEFISH_BLOCK_BYTES])
{
    for (int index = THREEFISH_BLOCK_BYTES - 1; index >= 0; --index) {
        counter[index]++;
        if (counter[index] != 0) {
            return 0;
        }
    }

    return 1;
}

static int add_counter_blocks(
    uint8_t counter[THREEFISH_BLOCK_BYTES],
    uint64_t blocks)
{
    uint64_t carry = blocks;
    for (int index = THREEFISH_BLOCK_BYTES - 1; index >= 0 && carry != 0; --index) {
        uint64_t sum = (uint64_t)counter[index] + (carry & 0xffu);
        counter[index] = (uint8_t)sum;
        carry = (carry >> 8) + (sum >> 8);
    }

    return carry != 0;
}

static void encrypt_block_reference(
    const uint8_t key[THREEFISH_BLOCK_BYTES],
    const uint8_t tweak[THREEFISH_TWEAK_BYTES],
    const uint8_t input[THREEFISH_BLOCK_BYTES],
    uint8_t output[THREEFISH_BLOCK_BYTES])
{
    Skein1024_Ctxt_t context;
    uint8_t ubi_output[THREEFISH_BLOCK_BYTES];

    memset(&context, 0, sizeof(context));
    memset(ubi_output, 0, sizeof(ubi_output));
    context.h.hashBitLen = 1024;
    Skein_Get64_LSB_First(context.X, key, SKEIN1024_STATE_WORDS);
    Skein_Get64_LSB_First(context.h.T, tweak, SKEIN_MODIFIER_WORDS);
    Skein1024_Process_Block(&context, input, 1, 0);
    Skein_Put64_LSB_First(ubi_output, context.X, THREEFISH_BLOCK_BYTES);

    for (size_t index = 0; index < THREEFISH_BLOCK_BYTES; ++index) {
        output[index] = ubi_output[index] ^ input[index];
    }

    secure_zero(ubi_output, sizeof(ubi_output));
    secure_zero(&context, sizeof(context));
}

static int xcrypt_ctr_range(
    const uint8_t key[THREEFISH_BLOCK_BYTES],
    const uint8_t tweak[THREEFISH_TWEAK_BYTES],
    const uint8_t nonce[THREEFISH_BLOCK_BYTES],
    const uint8_t* input,
    uint8_t* output,
    size_t length,
    size_t start_block,
    size_t block_count)
{
    uint8_t counter[THREEFISH_BLOCK_BYTES];
    uint8_t stream[THREEFISH_BLOCK_BYTES];
    int result = 0;

    if (block_count == 0) {
        return 0;
    }

    memcpy(counter, nonce, sizeof(counter));
    memset(stream, 0, sizeof(stream));
    if (add_counter_blocks(counter, (uint64_t)start_block)) {
        result = 4;
        goto cleanup;
    }

    size_t end_block = start_block + block_count;
    if (end_block < start_block) {
        result = 4;
        goto cleanup;
    }

    for (size_t block_index = start_block; block_index < end_block; ++block_index) {
        size_t offset = block_index * THREEFISH_BLOCK_BYTES;
        size_t remaining = length - offset;
        size_t block_length = remaining < THREEFISH_BLOCK_BYTES
            ? remaining
            : THREEFISH_BLOCK_BYTES;
        encrypt_block_reference(key, tweak, counter, stream);
        for (size_t index = 0; index < block_length; ++index) {
            output[offset + index] = input[offset + index] ^ stream[index];
        }

        secure_zero(stream, sizeof(stream));
        if (block_index + 1 < end_block && increment_counter(counter)) {
            result = 4;
            goto cleanup;
        }
    }

cleanup:
    secure_zero(counter, sizeof(counter));
    secure_zero(stream, sizeof(stream));
    return result;
}

typedef struct threefish_ctr_job {
    const uint8_t* key;
    const uint8_t* tweak;
    const uint8_t* nonce;
    const uint8_t* input;
    uint8_t* output;
    size_t length;
    size_t start_block;
    size_t block_count;
    int result;
} threefish_ctr_job;

#if defined(_WIN32)
static DWORD WINAPI threefish_ctr_worker(LPVOID parameter)
#else
static void* threefish_ctr_worker(void* parameter)
#endif
{
    threefish_ctr_job* job = (threefish_ctr_job*)parameter;
    job->result = xcrypt_ctr_range(
        job->key,
        job->tweak,
        job->nonce,
        job->input,
        job->output,
        job->length,
        job->start_block,
        job->block_count);
#if defined(_WIN32)
    return 0;
#else
    return NULL;
#endif
}

static size_t configured_thread_limit(void)
{
    const char* configured = getenv("THREEFISH_CTR_THREADS");
    if (configured != NULL && configured[0] != '\0') {
        long parsed = strtol(configured, NULL, 10);
        if (parsed > 0) {
            return parsed > THREEFISH_MAX_THREADS
                ? THREEFISH_MAX_THREADS
                : (size_t)parsed;
        }
    }

#if defined(_WIN32)
    DWORD processors = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
#else
    long processors = sysconf(_SC_NPROCESSORS_ONLN);
#endif
    if (processors <= 0) {
        processors = 1;
    }

    return processors > THREEFISH_MAX_THREADS
        ? THREEFISH_MAX_THREADS
        : (size_t)processors;
}

static size_t choose_thread_count(size_t length, size_t total_blocks)
{
    if (length < THREEFISH_PARALLEL_THRESHOLD_BYTES || total_blocks < 2) {
        return 1;
    }

    size_t threads = configured_thread_limit();
    if (threads < 1) {
        threads = 1;
    }

    /* Keep every worker on a substantial contiguous range so that a wide
       machine does not spend more on thread setup and cache traffic than the
       split saves. */
    size_t useful_threads = length / THREEFISH_MIN_BYTES_PER_THREAD;
    if (useful_threads < 1) {
        useful_threads = 1;
    }
    if (threads > useful_threads) {
        threads = useful_threads;
    }

    if (threads > total_blocks) {
        threads = total_blocks;
    }

    return threads;
}

THREEFISH_EXPORT int threefish_1024_encrypt_block(
    const uint8_t key[THREEFISH_BLOCK_BYTES],
    const uint8_t tweak[THREEFISH_TWEAK_BYTES],
    const uint8_t input[THREEFISH_BLOCK_BYTES],
    uint8_t output[THREEFISH_BLOCK_BYTES])
{
    if (key == NULL || tweak == NULL || input == NULL || output == NULL) {
        return 1;
    }

    encrypt_block_reference(key, tweak, input, output);
    return 0;
}

THREEFISH_EXPORT int threefish_1024_ctr_xcrypt(
    const uint8_t key[THREEFISH_BLOCK_BYTES],
    const uint8_t tweak[THREEFISH_TWEAK_BYTES],
    const uint8_t nonce[THREEFISH_BLOCK_BYTES],
    const uint8_t* input,
    uint8_t* output,
    size_t length)
{
    if (key == NULL || tweak == NULL || nonce == NULL || input == NULL || output == NULL) {
        return 1;
    }

    if (length > SIZE_MAX - (THREEFISH_BLOCK_BYTES - 1)) {
        return 4;
    }

    size_t total_blocks = (length + THREEFISH_BLOCK_BYTES - 1) / THREEFISH_BLOCK_BYTES;
    if (total_blocks == 0) {
        return 0;
    }

    size_t thread_count = choose_thread_count(length, total_blocks);
    if (thread_count > 1) {
#if defined(_WIN32)
        HANDLE handles[THREEFISH_MAX_THREADS];
#else
        pthread_t handles[THREEFISH_MAX_THREADS];
        int started[THREEFISH_MAX_THREADS];
#endif
        threefish_ctr_job jobs[THREEFISH_MAX_THREADS];
        size_t base_blocks = total_blocks / thread_count;
        size_t extra_blocks = total_blocks % thread_count;
        size_t start_block = 0;
        memset(handles, 0, sizeof(handles));
#if !defined(_WIN32)
        memset(started, 0, sizeof(started));
#endif
        memset(jobs, 0, sizeof(jobs));

        for (size_t index = 0; index < thread_count; ++index) {
            size_t block_count = base_blocks + (index < extra_blocks ? 1 : 0);
            jobs[index].key = key;
            jobs[index].tweak = tweak;
            jobs[index].nonce = nonce;
            jobs[index].input = input;
            jobs[index].output = output;
            jobs[index].length = length;
            jobs[index].start_block = start_block;
            jobs[index].block_count = block_count;
#if defined(_WIN32)
            handles[index] = CreateThread(NULL, 0, threefish_ctr_worker, &jobs[index], 0, NULL);
            if (handles[index] == NULL) {
                for (size_t previous = 0; previous < index; ++previous) {
                    WaitForSingleObject(handles[previous], INFINITE);
                    CloseHandle(handles[previous]);
                }

                secure_zero(jobs, sizeof(jobs));
                secure_zero(handles, sizeof(handles));
                return 3;
            }
#else
            if (pthread_create(&handles[index], NULL, threefish_ctr_worker, &jobs[index]) != 0) {
                for (size_t previous = 0; previous < index; ++previous) {
                    if (started[previous]) {
                        (void)pthread_join(handles[previous], NULL);
                    }
                }

                secure_zero(jobs, sizeof(jobs));
                secure_zero(handles, sizeof(handles));
                secure_zero(started, sizeof(started));
                return 3;
            }
            started[index] = 1;
#endif

            start_block += block_count;
        }

        int result = 0;
#if defined(_WIN32)
        DWORD wait_result = WaitForMultipleObjects((DWORD)thread_count, handles, TRUE, INFINITE);
        if (wait_result == WAIT_FAILED) {
            result = 3;
            for (size_t index = 0; index < thread_count; ++index) {
                WaitForSingleObject(handles[index], INFINITE);
            }
        }
#endif

        for (size_t index = 0; index < thread_count; ++index) {
#if defined(_WIN32)
            CloseHandle(handles[index]);
#else
            if (started[index] && pthread_join(handles[index], NULL) != 0 && result == 0) {
                result = 3;
            }
#endif
            if (jobs[index].result != 0 && result == 0) {
                result = jobs[index].result;
            }
        }

        secure_zero(jobs, sizeof(jobs));
        secure_zero(handles, sizeof(handles));
#if !defined(_WIN32)
        secure_zero(started, sizeof(started));
#endif
        return result;
    }

    return xcrypt_ctr_range(key, tweak, nonce, input, output, length, 0, total_blocks);
}
