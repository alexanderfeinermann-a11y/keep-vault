/*
 * Native adapter expected by the WPF app.
 *
 * Build this file together with the Roman-Oliynykov/Kalyna-reference sources
 * into kalyna_ref.dll and place that DLL next to KalynaArchiver.exe.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "../external/Kalyna-reference/kalyna.h"

#if defined(_WIN32)
#include <windows.h>
#define KALYNA_EXPORT __declspec(dllexport)
#else
#include <pthread.h>
#include <unistd.h>
#define KALYNA_EXPORT __attribute__((visibility("default")))
#endif

#define KALYNA_BLOCK_BYTES 64
#define KALYNA_MAX_THREADS 4
#define KALYNA_PARALLEL_THRESHOLD_BYTES (8 * 1024 * 1024)

static int increment_counter(uint8_t counter[64])
{
    for (int i = 63; i >= 0; --i) {
        counter[i]++;
        if (counter[i] != 0) {
            return 0;
        }
    }

    return 1;
}

static int add_counter_blocks(uint8_t counter[64], uint64_t blocks)
{
    uint64_t carry = blocks;
    for (int i = 63; i >= 0 && carry != 0; --i) {
        uint64_t sum = (uint64_t)counter[i] + (carry & 0xffu);
        counter[i] = (uint8_t)sum;
        carry = (carry >> 8) + (sum >> 8);
    }

    return carry != 0;
}

static void secure_zero(void* ptr, size_t length)
{
    volatile uint8_t* p = (volatile uint8_t*)ptr;
    while (length--) {
        *p++ = 0;
    }
}

static void wipe_kalyna(kalyna_t* ctx)
{
    if (ctx == NULL) {
        return;
    }

    if (ctx->state != NULL) {
        secure_zero(ctx->state, ctx->nb * sizeof(uint64_t));
    }

    if (ctx->round_keys != NULL) {
        for (size_t i = 0; i < ctx->nr + 1; ++i) {
            if (ctx->round_keys[i] != NULL) {
                secure_zero(ctx->round_keys[i], ctx->nb * sizeof(uint64_t));
            }
        }
    }
}

static int xcrypt_ctr_range(
    const uint8_t key[64],
    const uint8_t nonce[64],
    const uint8_t* input,
    uint8_t* output,
    size_t length,
    size_t start_block,
    size_t block_count)
{
    kalyna_t* ctx = NULL;
    uint64_t key_words[8];
    uint64_t counter_words[8];
    uint64_t stream_words[8];
    uint8_t counter[64];
    uint8_t stream[64];
    int result = 0;

    if (block_count == 0) {
        return 0;
    }

    if (start_block > UINT64_MAX) {
        return 4;
    }

    ctx = KalynaInit(512, 512);
    if (ctx == NULL) {
        return 2;
    }

    memcpy(key_words, key, sizeof(key_words));
    memcpy(counter, nonce, sizeof(counter));
    if (add_counter_blocks(counter, (uint64_t)start_block)) {
        result = 4;
        goto cleanup;
    }

    KalynaKeyExpand(key_words, ctx);

    size_t end_block = start_block + block_count;
    if (end_block < start_block) {
        result = 4;
        goto cleanup;
    }

    for (size_t block_index = start_block; block_index < end_block; ++block_index) {
        size_t offset = block_index * KALYNA_BLOCK_BYTES;
        size_t remaining = length - offset;
        size_t block = remaining < KALYNA_BLOCK_BYTES ? remaining : KALYNA_BLOCK_BYTES;
        memcpy(counter_words, counter, sizeof(counter_words));
        KalynaEncipher(counter_words, ctx, stream_words);
        memcpy(stream, stream_words, sizeof(stream));
        for (size_t i = 0; i < block; ++i) {
            output[offset + i] = input[offset + i] ^ stream[i];
        }

        if (block_index + 1 < end_block && increment_counter(counter)) {
            result = 4;
            goto cleanup;
        }
    }

cleanup:
    wipe_kalyna(ctx);
    secure_zero(key_words, sizeof(key_words));
    secure_zero(counter_words, sizeof(counter_words));
    secure_zero(stream_words, sizeof(stream_words));
    secure_zero(counter, sizeof(counter));
    secure_zero(stream, sizeof(stream));
    KalynaDelete(ctx);
    return result;
}

typedef struct kalyna_ctr_job {
    const uint8_t* key;
    const uint8_t* nonce;
    const uint8_t* input;
    uint8_t* output;
    size_t length;
    size_t start_block;
    size_t block_count;
    int result;
} kalyna_ctr_job;

#if defined(_WIN32)
static DWORD WINAPI kalyna_ctr_worker(LPVOID parameter)
#else
static void* kalyna_ctr_worker(void* parameter)
#endif
{
    kalyna_ctr_job* job = (kalyna_ctr_job*)parameter;
    job->result = xcrypt_ctr_range(
        job->key,
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
    const char* configured = getenv("KALYNA_CTR_THREADS");
    if (configured != NULL && configured[0] != '\0') {
        long parsed = strtol(configured, NULL, 10);
        if (parsed > 0) {
            return parsed > KALYNA_MAX_THREADS ? KALYNA_MAX_THREADS : (size_t)parsed;
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

    return processors > KALYNA_MAX_THREADS ? KALYNA_MAX_THREADS : (size_t)processors;
}

static size_t choose_thread_count(size_t length, size_t total_blocks)
{
    if (length < KALYNA_PARALLEL_THRESHOLD_BYTES || total_blocks < 2) {
        return 1;
    }

    size_t threads = configured_thread_limit();
    if (threads < 1) {
        threads = 1;
    }

    if (threads > total_blocks) {
        threads = total_blocks;
    }

    return threads;
}

KALYNA_EXPORT int kalyna_512_512_ctr_xcrypt(
    const uint8_t key[64],
    const uint8_t nonce[64],
    const uint8_t* input,
    uint8_t* output,
    size_t length)
{
    if (key == NULL || nonce == NULL || input == NULL || output == NULL) {
        return 1;
    }

    if (length > SIZE_MAX - (KALYNA_BLOCK_BYTES - 1)) {
        return 4;
    }

    size_t total_blocks = (length + KALYNA_BLOCK_BYTES - 1) / KALYNA_BLOCK_BYTES;

    if (total_blocks == 0) {
        return 0;
    }

    size_t thread_count = choose_thread_count(length, total_blocks);
    if (thread_count > 1) {
#if defined(_WIN32)
        HANDLE handles[KALYNA_MAX_THREADS];
#else
        pthread_t handles[KALYNA_MAX_THREADS];
        int started[KALYNA_MAX_THREADS];
#endif
        kalyna_ctr_job jobs[KALYNA_MAX_THREADS];
        size_t base_blocks = total_blocks / thread_count;
        size_t extra_blocks = total_blocks % thread_count;
        size_t start_block = 0;
        memset(handles, 0, sizeof(handles));
#if !defined(_WIN32)
        memset(started, 0, sizeof(started));
#endif
        memset(jobs, 0, sizeof(jobs));

        for (size_t i = 0; i < thread_count; ++i) {
            size_t block_count = base_blocks + (i < extra_blocks ? 1 : 0);
            jobs[i].key = key;
            jobs[i].nonce = nonce;
            jobs[i].input = input;
            jobs[i].output = output;
            jobs[i].length = length;
            jobs[i].start_block = start_block;
            jobs[i].block_count = block_count;
#if defined(_WIN32)
            handles[i] = CreateThread(NULL, 0, kalyna_ctr_worker, &jobs[i], 0, NULL);
            if (handles[i] == NULL) {
                for (size_t j = 0; j < i; ++j) {
                    WaitForSingleObject(handles[j], INFINITE);
                    CloseHandle(handles[j]);
                }
                secure_zero(jobs, sizeof(jobs));
                return 3;
            }
#else
            if (pthread_create(&handles[i], NULL, kalyna_ctr_worker, &jobs[i]) != 0) {
                for (size_t j = 0; j < i; ++j) {
                    if (started[j]) {
                        (void)pthread_join(handles[j], NULL);
                    }
                }
                secure_zero(jobs, sizeof(jobs));
                secure_zero(handles, sizeof(handles));
                secure_zero(started, sizeof(started));
                return 3;
            }
            started[i] = 1;
#endif

            start_block += block_count;
        }

        int result = 0;
#if defined(_WIN32)
        DWORD wait_result = WaitForMultipleObjects((DWORD)thread_count, handles, TRUE, INFINITE);
        if (wait_result == WAIT_FAILED) {
            result = 3;
            for (size_t i = 0; i < thread_count; ++i) {
                WaitForSingleObject(handles[i], INFINITE);
            }
        }
#endif

        for (size_t i = 0; i < thread_count; ++i) {
#if defined(_WIN32)
            CloseHandle(handles[i]);
#else
            if (started[i] && pthread_join(handles[i], NULL) != 0 && result == 0) {
                result = 3;
            }
#endif
            if (jobs[i].result != 0 && result == 0) {
                result = jobs[i].result;
            }
        }

        secure_zero(jobs, sizeof(jobs));
        secure_zero(handles, sizeof(handles));
#if !defined(_WIN32)
        secure_zero(started, sizeof(started));
#endif
        return result;
    }

    return xcrypt_ctr_range(key, nonce, input, output, length, 0, total_blocks);
}
