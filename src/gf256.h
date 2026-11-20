#pragma once
#include "common.h"
#include <stdexcept>

// GF(2^8) with primitive polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11d), alpha = 2.
struct GF256 {
    uint8_t exp[512];
    uint8_t logt[256];

    GF256() {
        int x = 1;
        for (int i = 0; i < 255; ++i) {
            exp[i] = static_cast<uint8_t>(x);
            logt[x] = static_cast<uint8_t>(i);
            x <<= 1;
            if (x & 0x100) x ^= 0x11d;
        }
        for (int i = 255; i < 512; ++i) exp[i] = exp[i - 255];
        logt[0] = 0; // unused
    }
    uint8_t mul(uint8_t a, uint8_t b) const {
        if (!a || !b) return 0;
        return exp[logt[a] + logt[b]];
    }
    uint8_t div(uint8_t a, uint8_t b) const {
        if (!b) throw std::runtime_error("GF div by zero");
        if (!a) return 0;
        return exp[logt[a] + 255 - logt[b]];
    }
    uint8_t inv(uint8_t a) const {
        if (!a) throw std::runtime_error("GF inv of zero");
        return exp[255 - logt[a]];
    }
    uint8_t pow(uint8_t a, int e) const {
        if (e == 0) return 1;
        if (!a) return 0;
        int m = (logt[a] * (e % 255)) % 255;
        if (m < 0) m += 255;
        return exp[m];
    }
};

inline const GF256& gf() {
    static GF256 g;
    return g;
}
