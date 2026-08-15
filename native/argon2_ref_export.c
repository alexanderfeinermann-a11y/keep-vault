/*
 * Native PHC Argon2id adapter expected by the WPF app.
 *
 * Build this file together with the phc-winner-argon2 reference sources into
 * argon2_ref.dll and place that DLL next to KalynaArchiver.exe.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#if defined(_WIN32)
#include <windows.h>
#else
#include <errno.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>
#endif
#include "../external/phc-winner-argon2/include/argon2.h"

#if defined(_WIN32)
#define ARGON2_REF_EXPORT __declspec(dllexport)
#else
#define ARGON2_REF_EXPORT __attribute__((visibility("default")))
#endif

#define KZPAQ_ARGON2_MEMORY_KIB 1048576U
#define KZPAQ_ARGON2_ITERATIONS 4U
#define KZPAQ_ARGON2_PARALLELISM 4U

#if defined(_WIN32)
static SRWLOCK argon2_call_lock = SRWLOCK_INIT;
static __declspec(thread) DWORD last_memory_lock_error = ERROR_SUCCESS;
#else
static pthread_mutex_t argon2_call_lock = PTHREAD_MUTEX_INITIALIZER;
static _Thread_local uint32_t last_memory_lock_error = 0;

static void secure_zero_memory(void* pointer, size_t length)
{
#if defined(__APPLE__)
    (void)memset_s(pointer, length, 0, length);
#else
    volatile uint8_t* bytes = (volatile uint8_t*)pointer;
    while (length-- != 0) {
        *bytes++ = 0;
    }
#endif
}
#endif

static int locked_allocator(uint8_t** memory, size_t bytes_to_allocate)
{
    if (memory == NULL || bytes_to_allocate == 0) {
        return ARGON2_MEMORY_ALLOCATION_ERROR;
    }

#if defined(_WIN32)
    *memory = (uint8_t*)VirtualAlloc(NULL, bytes_to_allocate, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (*memory == NULL) {
        last_memory_lock_error = GetLastError();
        return ARGON2_MEMORY_ALLOCATION_ERROR;
    }

    if (!VirtualLock(*memory, bytes_to_allocate)) {
        DWORD lock_error = GetLastError();
        SecureZeroMemory(*memory, bytes_to_allocate);
        (void)VirtualFree(*memory, 0, MEM_RELEASE);
        *memory = NULL;
        last_memory_lock_error = lock_error;
        return ARGON2_MEMORY_ALLOCATION_ERROR;
    }

    last_memory_lock_error = ERROR_SUCCESS;
#else
    *memory = (uint8_t*)mmap(
        NULL,
        bytes_to_allocate,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANON,
        -1,
        0);
    if (*memory == MAP_FAILED) {
        *memory = NULL;
        last_memory_lock_error = (uint32_t)errno;
        return ARGON2_MEMORY_ALLOCATION_ERROR;
    }

    if (mlock(*memory, bytes_to_allocate) != 0) {
        int lock_error = errno;
        secure_zero_memory(*memory, bytes_to_allocate);
        (void)munmap(*memory, bytes_to_allocate);
        *memory = NULL;
        last_memory_lock_error = (uint32_t)lock_error;
        return ARGON2_MEMORY_ALLOCATION_ERROR;
    }

    last_memory_lock_error = 0;
#endif
    return ARGON2_OK;
}

static void locked_deallocator(uint8_t* memory, size_t bytes_to_allocate)
{
    if (memory == NULL) {
        return;
    }

#if defined(_WIN32)
    SecureZeroMemory(memory, bytes_to_allocate);
    (void)VirtualUnlock(memory, bytes_to_allocate);
    (void)VirtualFree(memory, 0, MEM_RELEASE);
#else
    secure_zero_memory(memory, bytes_to_allocate);
    (void)munlock(memory, bytes_to_allocate);
    (void)munmap(memory, bytes_to_allocate);
#endif
}

#if defined(_WIN32)
static BOOL prepare_working_set(
    size_t argon2_bytes,
    SIZE_T* previous_minimum,
    SIZE_T* previous_maximum,
    BOOL* previous_sizes_available)
{
    const SIZE_T minimum_margin = (SIZE_T)64 * 1024 * 1024;
    const SIZE_T maximum_margin = (SIZE_T)256 * 1024 * 1024;
    HANDLE process = GetCurrentProcess();
    SIZE_T requested_minimum;
    SIZE_T requested_maximum;

    *previous_sizes_available = GetProcessWorkingSetSize(
        process,
        previous_minimum,
        previous_maximum);

    if (argon2_bytes > SIZE_MAX - maximum_margin) {
        last_memory_lock_error = ERROR_ARITHMETIC_OVERFLOW;
        return FALSE;
    }

    requested_minimum = (SIZE_T)argon2_bytes + minimum_margin;
    requested_maximum = (SIZE_T)argon2_bytes + maximum_margin;
    if (*previous_sizes_available) {
        if (*previous_minimum > requested_minimum) {
            requested_minimum = *previous_minimum;
        }
        if (*previous_maximum > requested_maximum) {
            requested_maximum = *previous_maximum;
        }
    }

    /*
     * Windows limits VirtualLock to slightly less than the process minimum
     * working set. Raising the quota before Argon2 runs lets the full 1 GiB
     * matrix be pinned. Never lower a larger reservation made by the managed
     * secure-memory coordinator while entering the native adapter.
     */
    if (!SetProcessWorkingSetSize(process, requested_minimum, requested_maximum)) {
        last_memory_lock_error = GetLastError();
        return FALSE;
    }

    return TRUE;
}

static void restore_working_set(
    SIZE_T previous_minimum,
    SIZE_T previous_maximum,
    BOOL previous_sizes_available)
{
    if (previous_sizes_available) {
        (void)SetProcessWorkingSetSize(
            GetCurrentProcess(),
            previous_minimum,
            previous_maximum);
    }
}
#else
static int prepare_working_set(size_t argon2_bytes)
{
    struct rlimit limit;
    if (getrlimit(RLIMIT_MEMLOCK, &limit) != 0) {
        last_memory_lock_error = (uint32_t)errno;
        return 0;
    }

    if (limit.rlim_cur != RLIM_INFINITY && limit.rlim_cur < (rlim_t)argon2_bytes) {
        last_memory_lock_error = (uint32_t)ENOMEM;
        return 0;
    }

    return 1;
}
#endif

ARGON2_REF_EXPORT int phc_argon2id_hash_raw(
    uint32_t t_cost,
    uint32_t m_cost,
    uint32_t parallelism,
    uint8_t* password,
    uint32_t password_len,
    uint8_t* salt,
    uint32_t salt_len,
    uint8_t* output,
    uint32_t output_len)
{
#if defined(_WIN32)
    SIZE_T previous_minimum = 0;
    SIZE_T previous_maximum = 0;
    BOOL previous_sizes_available = FALSE;
#endif
    size_t argon2_bytes;
    int result;

#if defined(_WIN32)
    last_memory_lock_error = ERROR_SUCCESS;
#else
    last_memory_lock_error = 0;
#endif
    if (password == NULL || salt == NULL || output == NULL) {
        return ARGON2_INCORRECT_PARAMETER;
    }

    if (t_cost != KZPAQ_ARGON2_ITERATIONS ||
        m_cost != KZPAQ_ARGON2_MEMORY_KIB ||
        parallelism != KZPAQ_ARGON2_PARALLELISM) {
        return ARGON2_INCORRECT_PARAMETER;
    }

    if (m_cost > SIZE_MAX / 1024) {
        return ARGON2_MEMORY_TOO_MUCH;
    }

    argon2_bytes = (size_t)m_cost * 1024;
#if defined(_WIN32)
    AcquireSRWLockExclusive(&argon2_call_lock);
    if (!prepare_working_set(
            argon2_bytes,
            &previous_minimum,
            &previous_maximum,
            &previous_sizes_available)) {
        ReleaseSRWLockExclusive(&argon2_call_lock);
        return ARGON2_MEMORY_ALLOCATION_ERROR;
    }
#else
    if (pthread_mutex_lock(&argon2_call_lock) != 0) {
        last_memory_lock_error = (uint32_t)EDEADLK;
        return ARGON2_MEMORY_ALLOCATION_ERROR;
    }
    if (!prepare_working_set(argon2_bytes)) {
        (void)pthread_mutex_unlock(&argon2_call_lock);
        return ARGON2_MEMORY_ALLOCATION_ERROR;
    }
#endif

    argon2_context context;
    memset(&context, 0, sizeof(context));
    context.out = output;
    context.outlen = output_len;
    context.pwd = password;
    context.pwdlen = password_len;
    context.salt = salt;
    context.saltlen = salt_len;
    context.t_cost = t_cost;
    context.m_cost = m_cost;
    context.lanes = parallelism;
    context.threads = parallelism;
    context.version = ARGON2_VERSION_NUMBER;
    context.allocate_cbk = locked_allocator;
    context.free_cbk = locked_deallocator;
    context.flags = ARGON2_FLAG_CLEAR_PASSWORD;

    result = argon2id_ctx(&context);
#if defined(_WIN32)
    restore_working_set(previous_minimum, previous_maximum, previous_sizes_available);
    ReleaseSRWLockExclusive(&argon2_call_lock);
#else
    (void)pthread_mutex_unlock(&argon2_call_lock);
#endif
    return result;
}

ARGON2_REF_EXPORT const char* phc_argon2_error_message(int error_code)
{
    return argon2_error_message(error_code);
}

ARGON2_REF_EXPORT uint32_t phc_argon2_last_memory_lock_error(void)
{
    return (uint32_t)last_memory_lock_error;
}
