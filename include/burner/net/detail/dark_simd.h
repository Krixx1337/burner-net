#pragma once

#include "burner/net/detail/dark_hash_utils.h"

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <string>

#if defined(__aarch64__) || defined(_M_ARM64) || defined(__ARM_NEON)
#include <arm_neon.h>
#define BURNER_DARK_HAS_NEON 1
#else
#define BURNER_DARK_HAS_NEON 0
#endif

#if defined(__SSE2__) || (defined(_MSC_VER) && (defined(_M_X64) || (_M_IX86_FP >= 2)))
#include <emmintrin.h>
#define BURNER_DARK_HAS_SSE2 1
#else
#define BURNER_DARK_HAS_SSE2 0
#endif

namespace burner::net::detail {

[[nodiscard]] constexpr std::uint64_t dark_string_seed_base() noexcept {
    return fnv1a<std::uint64_t>(std::string_view{__TIME__, sizeof(__TIME__) - 1u});
}

[[nodiscard]] constexpr std::uint32_t dark_word_key(std::size_t index, std::uint64_t seed) noexcept {
    const std::uint64_t mixed = split_mix64(
        seed + (static_cast<std::uint64_t>(index + 1u) * split_mix_increment));
    return static_cast<std::uint32_t>(mixed ^ (mixed >> 32));
}

#if BURNER_DARK_HAS_NEON
static inline void dark_restore_neon_block(std::uint32_t* words, const std::uint32_t* keys) noexcept {
    const uint32x4_t encoded = vld1q_u32(words);
    const uint32x4_t key = vld1q_u32(keys);
    const uint32x4_t step1 = veorq_u32(encoded, key);
    const uint32x4_t step2 = vaddq_u32(step1, vshlq_n_u32(key, 4));
    const uint32x4_t step3 = vsubq_u32(step2, vshlq_n_u32(key, 4));
    const uint32x4_t step4 = vaddq_u32(step3, vshrq_n_u32(key, 5));
    const uint32x4_t plain = vsubq_u32(step4, vshrq_n_u32(key, 5));
    vst1q_u32(words, plain);
}
#endif

#if BURNER_DARK_HAS_SSE2
static inline void dark_restore_sse2_block(std::uint32_t* words, const std::uint32_t* keys) noexcept {
    const __m128i encoded = _mm_loadu_si128(reinterpret_cast<const __m128i*>(words));
    const __m128i key = _mm_loadu_si128(reinterpret_cast<const __m128i*>(keys));
    const __m128i step1 = _mm_xor_si128(encoded, key);
    const __m128i step2 = _mm_add_epi32(step1, _mm_slli_epi32(key, 4));
    const __m128i step3 = _mm_sub_epi32(step2, _mm_slli_epi32(key, 4));
    const __m128i step4 = _mm_add_epi32(step3, _mm_srli_epi32(key, 5));
    const __m128i plain = _mm_sub_epi32(step4, _mm_srli_epi32(key, 5));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(words), plain);
}
#endif

static inline void dark_restore_scalar_block(std::uint32_t* words, const std::uint32_t* keys, std::size_t count) noexcept {
    for (std::size_t i = 0; i < count; ++i) {
        const std::uint32_t key = keys[i];
        const std::uint32_t step1 = words[i] ^ key;
        const std::uint32_t step2 = step1 + (key << 4);
        const std::uint32_t step3 = step2 - (key << 4);
        const std::uint32_t step4 = step3 + (key >> 5);
        words[i] = step4 - (key >> 5);
    }
}

template <std::size_t N, std::uint64_t Seed>
class DarkLiteral {
public:
    static constexpr std::size_t word_count = (N + 3u) / 4u;

    consteval explicit DarkLiteral(const char (&value)[N]) {
        for (std::size_t word_index = 0; word_index < word_count; ++word_index) {
            std::uint32_t plain = 0;
            for (std::size_t lane = 0; lane < 4; ++lane) {
                const std::size_t char_index = word_index * 4u + lane;
                const std::uint32_t byte = char_index < N
                    ? static_cast<std::uint8_t>(value[char_index])
                    : 0u;
                plain |= byte << (lane * 8u);
            }
            masked_words_[word_index] = plain ^ dark_word_key(word_index, Seed);
        }
    }

    [[nodiscard]] std::string resolve() const {
        auto words = masked_words_;
        std::array<std::uint32_t, word_count> keys{};
        for (std::size_t i = 0; i < word_count; ++i) {
            keys[i] = dark_word_key(i, Seed);
        }

        std::size_t index = 0;
        for (; index + 4u <= word_count; index += 4u) {
#if BURNER_DARK_HAS_NEON
            dark_restore_neon_block(words.data() + index, keys.data() + index);
#elif BURNER_DARK_HAS_SSE2
            dark_restore_sse2_block(words.data() + index, keys.data() + index);
#else
            dark_restore_scalar_block(words.data() + index, keys.data() + index, 4u);
#endif
        }

        if (index < word_count) {
            dark_restore_scalar_block(words.data() + index, keys.data() + index, word_count - index);
        }

        std::string result(N - 1u, '\0');
        for (std::size_t i = 0; i + 1u < N; ++i) {
            const std::uint32_t word = words[i / 4u];
            result[i] = static_cast<char>((word >> ((i % 4u) * 8u)) & 0xFFu);
        }
        return result;
    }

private:
    std::array<std::uint32_t, word_count> masked_words_{};
};

} // namespace burner::net::detail
