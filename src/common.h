#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <array>
#include <stdexcept>

using Bytes = std::vector<uint8_t>;

inline uint32_t rotl32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }
inline uint32_t rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

// xorshift-based deterministic RNG so every experiment is reproducible.
class Rng {
public:
    explicit Rng(uint64_t seed = 0x9E3779B97F4A7C15ULL) : s_(seed ? seed : 1) {}
    uint64_t next64() {
        uint64_t x = s_;
        x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
        s_ = x;
        return x * 2685821657736338717ULL;
    }
    uint32_t next32() { return static_cast<uint32_t>(next64() >> 32); }
    uint64_t below(uint64_t n) { return n ? next64() % n : 0; }
    // uniform in (0,1)
    double uniform() { return (next64() >> 11) * (1.0 / 9007199254740992.0); }
    double normal() {
        // Box-Muller
        double u1 = uniform(); if (u1 < 1e-300) u1 = 1e-300;
        double u2 = uniform();
        return std::sqrt(-2.0 * std::log(u1)) * std::cos(6.283185307179586 * u2);
    }
    void fill(uint8_t* p, size_t n) {
        for (size_t i = 0; i < n; ++i) p[i] = static_cast<uint8_t>(next64() >> 24);
    }
    void seed(uint64_t s) { s_ = s ? s : 1; }
private:
    uint64_t s_;
};

inline int hamming_bits(const Bytes& a, const Bytes& b) {
    if (a.size() != b.size()) throw std::runtime_error("hamming size mismatch");
    int d = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        uint8_t x = a[i] ^ b[i];
        while (x) { ++d; x &= static_cast<uint8_t>(x - 1); }
    }
    return d;
}

inline int popcount8(uint8_t x) {
    int c = 0; while (x) { ++c; x = static_cast<uint8_t>(x & (x - 1)); } return c;
}

inline Bytes to_bytes(const std::string& s) { return Bytes(s.begin(), s.end()); }
inline std::string to_hex(const uint8_t* p, size_t n) {
    static const char* H = "0123456789abcdef";
    std::string out; out.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) { out.push_back(H[p[i] >> 4]); out.push_back(H[p[i] & 15]); }
    return out;
}
inline std::string to_hex(const Bytes& b) { return to_hex(b.data(), b.size()); }
