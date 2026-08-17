/*
 * Shared CTR driver for the Crypto++-backed block ciphers.
 *
 * The Kalyna and Threefish adapters each carry their own copy of this logic in
 * C, with a #ifdef ladder for Windows and pthreads. These two are C++ because
 * Crypto++ is, so they can use the standard library's threads instead and share
 * one implementation. The behaviour is deliberately identical to the C
 * adapters: same counter arithmetic, same claimed-chunk work queue, same
 * ciphertext regardless of how many threads run.
 */
#ifndef KEEPVAULT_CRYPTOPP_CTR_COMMON_HPP
#define KEEPVAULT_CRYPTOPP_CTR_COMMON_HPP

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <thread>
#include <vector>

#if defined(_WIN32)
#define KEEPVAULT_EXPORT __declspec(dllexport)
#else
#define KEEPVAULT_EXPORT __attribute__((visibility("default")))
#endif

namespace keepvault {

/* Below this the thread hand-off costs more than it saves. */
constexpr std::size_t kParallelThresholdBytes = 1024u * 1024u;

/* 256 KiB of work per claim for a 64-byte block: one atomic claim disappears
   into the work it buys, and the tail stays short. Expressed in blocks so the
   claim is the same size in bytes whatever the cipher's block width is. */
constexpr std::size_t kChunkBytes = 256u * 1024u;

constexpr std::size_t kMaxThreads = 64;

inline void secure_zero(void* pointer, std::size_t length) noexcept
{
    volatile unsigned char* target = static_cast<volatile unsigned char*>(pointer);
    while (length-- > 0) {
        *target++ = 0;
    }
}

/*
 * Adds a block count to a big-endian counter that spans the whole nonce.
 *
 * The counter is the nonce, so it is as wide as the cipher's block. Carrying
 * across the entire width rather than a trailing field is what lets a worker
 * jump straight to the block it claimed without walking there.
 */
inline void add_counter_blocks(
    std::uint8_t* counter,
    std::size_t counter_length,
    std::uint64_t blocks) noexcept
{
    std::size_t index = counter_length;
    std::uint64_t carry = blocks;
    while (index-- > 0 && carry != 0) {
        std::uint64_t sum = static_cast<std::uint64_t>(counter[index]) + (carry & 0xFFu);
        counter[index] = static_cast<std::uint8_t>(sum & 0xFFu);
        carry >>= 8;
        carry += sum >> 8;
    }
}

/*
 * Encrypts or decrypts one range of blocks under a freshly keyed cipher.
 *
 * CTR is its own inverse, so this one path serves both directions. Each worker
 * keys its own cipher instance: Crypto++ block ciphers hold an expanded key
 * schedule and are not safe to share across threads.
 */
template <typename Encryption>
inline void xcrypt_ctr_range(
    const std::uint8_t* key,
    std::size_t key_length,
    const std::uint8_t* nonce,
    const std::uint8_t* input,
    std::uint8_t* output,
    std::size_t length,
    std::size_t first_block)
{
    constexpr std::size_t block_bytes = Encryption::BLOCKSIZE;

    Encryption cipher;
    cipher.SetKey(key, key_length);

    std::uint8_t counter[block_bytes];
    std::uint8_t keystream[block_bytes];
    std::memcpy(counter, nonce, block_bytes);
    add_counter_blocks(counter, block_bytes, static_cast<std::uint64_t>(first_block));

    std::size_t offset = 0;
    while (offset < length) {
        cipher.ProcessBlock(counter, keystream);

        const std::size_t remaining = length - offset;
        const std::size_t count = remaining < block_bytes ? remaining : block_bytes;
        for (std::size_t i = 0; i < count; ++i) {
            output[offset + i] = static_cast<std::uint8_t>(input[offset + i] ^ keystream[i]);
        }

        offset += count;
        add_counter_blocks(counter, block_bytes, 1u);
    }

    secure_zero(counter, sizeof(counter));
    secure_zero(keystream, sizeof(keystream));
}

/*
 * Drives a whole buffer, on one thread or several.
 *
 * Work is claimed in chunks rather than split once up front. Apple silicon
 * pairs fast performance cores with slower efficiency ones, and an even split
 * lets the slow half decide when the operation finishes; a claimed-chunk queue
 * lets each core take what it can carry. Because every chunk is keyed to its
 * absolute block index, the output does not depend on how the chunks were
 * distributed.
 */
template <typename Encryption>
inline int xcrypt_ctr(
    const std::uint8_t* key,
    std::size_t key_length,
    const std::uint8_t* nonce,
    const std::uint8_t* input,
    std::uint8_t* output,
    std::size_t length)
{
    constexpr std::size_t block_bytes = Encryption::BLOCKSIZE;

    if (key == nullptr || nonce == nullptr || input == nullptr || output == nullptr) {
        return 1;
    }

    if (length == 0) {
        return 0;
    }

    if (length > SIZE_MAX - (block_bytes - 1)) {
        return 4;
    }

    const std::size_t total_blocks = (length + block_bytes - 1) / block_bytes;
    const std::size_t chunk_blocks = kChunkBytes / block_bytes;

    std::size_t thread_count = 1;
    if (length >= kParallelThresholdBytes) {
        const unsigned hardware = std::thread::hardware_concurrency();
        thread_count = hardware == 0 ? 1 : static_cast<std::size_t>(hardware);
        const std::size_t chunks = (total_blocks + chunk_blocks - 1) / chunk_blocks;
        if (thread_count > chunks) {
            thread_count = chunks;
        }
        if (thread_count > kMaxThreads) {
            thread_count = kMaxThreads;
        }
        if (thread_count == 0) {
            thread_count = 1;
        }
    }

    if (thread_count <= 1) {
        xcrypt_ctr_range<Encryption>(key, key_length, nonce, input, output, length, 0);
        return 0;
    }

    std::atomic<std::size_t> next_chunk{0};
    std::atomic<int> failure{0};

    auto worker = [&]() noexcept {
        try {
            for (;;) {
                const std::size_t chunk = next_chunk.fetch_add(1, std::memory_order_relaxed);
                const std::size_t first_block = chunk * chunk_blocks;
                if (first_block >= total_blocks) {
                    return;
                }

                const std::size_t offset = first_block * block_bytes;
                const std::size_t span = chunk_blocks * block_bytes;
                const std::size_t remaining = length - offset;
                const std::size_t count = remaining < span ? remaining : span;

                xcrypt_ctr_range<Encryption>(
                    key, key_length, nonce, input + offset, output + offset, count, first_block);
            }
        } catch (...) {
            // A worker that threw must not unwind out of a thread, and it must
            // not leave the caller believing the buffer was processed.
            failure.store(3, std::memory_order_relaxed);
        }
    };

    std::vector<std::thread> threads;
    threads.reserve(thread_count - 1);
    try {
        for (std::size_t i = 1; i < thread_count; ++i) {
            threads.emplace_back(worker);
        }
    } catch (...) {
        // Fewer threads than hoped is not an error; this one runs the rest.
        failure.store(0, std::memory_order_relaxed);
    }

    worker();

    for (std::thread& thread : threads) {
        if (thread.joinable()) {
            thread.join();
        }
    }

    return failure.load(std::memory_order_relaxed);
}

}  // namespace keepvault

#endif
