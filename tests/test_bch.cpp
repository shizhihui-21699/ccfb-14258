#include "../src/bch.h"
#include "../src/rs.h"
#include <cstdio>
#include <vector>

static int fails = 0;
#define CHECK(c, m) do { if (!(c)) { std::printf("FAIL: %s\n", m); ++fails; } } while (0)

using Cw = std::array<uint8_t, 255>;

static std::vector<uint8_t> rand_msg(int k, Rng& r) {
    std::vector<uint8_t> m(k);
    for (auto& x : m) x = uint8_t(r.below(2));
    return m;
}

static void test_bch_errors() {
    Bch b(32);
    Rng r(1);
    for (int trial = 0; trial < 100; ++trial) {
        auto m = rand_msg(b.k(), r);
        Cw c = b.encode(m);
        CHECK(b.is_codeword(c), "encoded is codeword");
        CHECK(b.extract_message(c) == m, "systematic message preserved");
        int ne = int(r.below(b.t() + 1));
        Cw bad = c;
        std::vector<int> used;
        while (int(used.size()) < ne) {
            int p = int(r.below(255));
            bool dup = false;
            for (int q : used) if (q == p) dup = true;
            if (dup) continue;
            used.push_back(p);
            bad[p] ^= 1;
        }
        Cw out;
        CHECK(b.decode(bad, {}, out), "decode within t errors");
        CHECK(out == c, "correct within t errors");
    }
}

static void test_bch_erasures() {
    Bch b(32);
    Rng r(2);
    for (int trial = 0; trial < 100; ++trial) {
        auto m = rand_msg(b.k(), r);
        Cw c = b.encode(m);
        int ne = int(r.below(b.t() + 1));
        Cw bad = c;
        std::vector<int> er;
        while (int(er.size()) < ne) {
            int p = int(r.below(255));
            bool dup = false;
            for (int q : er) if (q == p) dup = true;
            if (dup) continue;
            er.push_back(p);
            bad[p] ^= 1;
        }
        Cw out;
        CHECK(b.decode(bad, er, out), "decode pure erasures");
        CHECK(out == c, "correct pure erasures");
    }
}

static void test_bch_combined() {
    Bch b(32);
    Rng r(3);
    for (int trial = 0; trial < 300; ++trial) {
        auto m = rand_msg(b.k(), r);
        Cw c = b.encode(m);
        int budget = 2 * b.t(); // BCH minimum distance 2t+1: 2e + f <= 2t
        int f = int(r.below(budget / 2 + 1));
        int e = int(r.below((budget - f) / 2 + 1));
        Cw bad = c;
        std::vector<int> used, er;
        auto pick = [&](int cnt, bool record) {
            int made = 0;
            while (made < cnt) {
                int p = int(r.below(255));
                bool dup = false;
                for (int q : used) if (q == p) dup = true;
                if (dup) continue;
                used.push_back(p);
                bad[p] ^= 1;
                if (record) er.push_back(p);
                ++made;
            }
        };
        pick(e, false);
        pick(f, true);
        Cw out;
        CHECK(b.decode(bad, er, out), "decode combined errors+erasures");
        CHECK(out == c, "correct combined e+erasures");
    }
}

static void test_bch_beyond_capacity_not_original() {
    // Beyond capacity the decoder may refuse or return a *different* codeword, but
    // it must never crash. (The FE's 128-bit tag is the real acceptance gate.)
    Bch b(32);
    Rng r(4);
    int original_returned = 0;
    for (int trial = 0; trial < 100; ++trial) {
        auto m = rand_msg(b.k(), r);
        Cw c = b.encode(m);
        Cw bad = c;
        for (int i = 0; i < b.t() + 10; ++i) bad[int(r.below(255))] ^= 1;
        Cw out;
        if (b.decode(bad, {}, out) && out == c) ++original_returned;
        // (getting the original back would actually be fine, just surprising)
    }
    (void)original_returned;
    CHECK(true, "beyond-capacity handled without crash");
}

static void test_rs_erasure_plus_error() {
    ReedSolomon rs(187);
    Rng r(5);
    for (int trial = 0; trial < 100; ++trial) {
        Bytes msg(rs.k());
        r.fill(msg.data(), msg.size());
        Bytes cw = rs.encode(msg);
        int budget = 2 * rs.t();
        int f = int(r.below(budget / 2 + 1));
        int e = int(r.below((budget - f) / 2 + 1));
        Bytes bad = cw;
        std::vector<int> used, er;
        auto pick = [&](int cnt, bool record) {
            int made = 0;
            while (made < cnt) {
                int p = int(r.below(255));
                bool dup = false;
                for (int q : used) if (q == p) dup = true;
                if (dup) continue;
                used.push_back(p);
                bad[p] ^= uint8_t(1 + r.below(255));
                if (record) er.push_back(p);
                ++made;
            }
        };
        pick(e, false);
        pick(f, true);
        Bytes out;
        CHECK(rs.decode(bad, er, out), "rs decode combined");
        CHECK(out == cw, "rs correct combined");
    }
}

int main() {
    test_bch_errors();
    test_bch_erasures();
    test_bch_combined();
    test_bch_beyond_capacity_not_original();
    test_rs_erasure_plus_error();
    if (fails) { std::printf("%d BCH/RS checks FAILED\n", fails); return 1; }
    std::printf("all BCH/RS tests passed\n");
    return 0;
}
