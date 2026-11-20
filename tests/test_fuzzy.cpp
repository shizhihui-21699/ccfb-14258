#include "../src/fuzzy_extractor.h"
#include "../src/device.h"
#include <cstdio>
#include <string>

static int fails = 0;
#define CHECK(c, m) do { if (!(c)) { std::printf("FAIL: %s\n", m); ++fails; } } while (0)

static Bytes make_kraw(int n) {
    Rng r(12345);
    Bytes k(n);
    r.fill(k.data(), k.size());
    return k;
}

static void test_bch_params() {
    Bch b(32);
    CHECK(b.n() == 255, "bch n");
    CHECK(b.k() == 47, "bch k for t=32");
    CHECK(b.parity() == 208, "bch parity");
    // every t in a range produces a usable (n,k) with k>0
    for (int t = 1; t <= 46; ++t) {
        Bch bb(t);
        CHECK(bb.k() > 0 && bb.k() < 255, "bch k range");
        CHECK(bb.n() - bb.k() == bb.parity(), "bch parity identity");
    }
}

static void test_fe_roundtrip() {
    FeParams p;
    PufChip chip(777);
    FuzzyExtractor fe(p);
    Bytes kraw = make_kraw(256);
    FeHelper h = fe.enroll(chip, 42, kraw);
    CHECK(h.blocks >= 1, "fe enrolled at least one block");
    CHECK(h.stable_idx.size() == size_t(h.blocks * 255), "stable idx size");
    // Nominal reproduction must succeed and use zero extra erasures.
    auto a = average_reads(chip, 25, 3.3, 0, 8);
    FeKey k = fe.reproduce(a, h);
    CHECK(k.ok, "fe reproduce at nominal");
    CHECK(k.extra_erasures_used == 0, "fe nominal needs no runtime erasures");
    // Key is deterministic given the helper.
    FeKey k2 = fe.reproduce(a, h);
    CHECK(k2.ok && k2.key == k.key, "fe key stable");
}

static void test_fe_is_device_bound() {
    PufChip a(777), b(778);
    FuzzyExtractor fe;
    Bytes kraw = make_kraw(256);
    FeHelper h = fe.enroll(a, 42, kraw);
    auto reads = average_reads(b, 25, 3.3, 0, 8);
    FeKey k = fe.reproduce(reads, h);
    CHECK(!k.ok, "foreign chip cannot reproduce key");
}

static void test_fe_extreme_temperature() {
    PufChip chip(777);
    FuzzyExtractor fe;
    Bytes kraw = make_kraw(256);
    FeHelper h = fe.enroll(chip, 42, kraw);
    for (double T : {-40.0, 0.0, 85.0, 125.0}) {
        auto a = average_reads(chip, T, 3.3, 0, 8);
        FeKey k = fe.reproduce(a, h);
        char msg[64];
        std::snprintf(msg, sizeof msg, "fe reproduce at %.0f C", T);
        CHECK(k.ok, msg);
    }
}

static void test_fe_aging() {
    PufChip chip(777);
    FuzzyExtractor fe;
    Bytes kraw = make_kraw(256);
    FeHelper h = fe.enroll(chip, 42, kraw);
    for (double age : {0.0, 5.0, 10.0, 20.0}) {
        auto a = average_reads(chip, 25, 3.3, age, 8);
        FeKey k = fe.reproduce(a, h);
        char msg[64];
        std::snprintf(msg, sizeof msg, "fe reproduce at age %.0f y", age);
        CHECK(k.ok, msg);
    }
}

static void test_fe_helper_tamper_rejected() {
    PufChip chip(777);
    FuzzyExtractor fe;
    Bytes kraw = make_kraw(256);
    FeHelper h = fe.enroll(chip, 42, kraw);
    auto a = average_reads(chip, 25, 3.3, 0, 8);
    FeKey good = fe.reproduce(a, h);
    CHECK(good.ok, "baseline ok");
    Rng r(1);
    int accepted_wrong = 0;
    for (int i = 0; i < 200; ++i) {
        FeHelper t = h;
        t.bits[r.below(t.bits.size())] ^= 1;
        FeKey k = fe.reproduce(a, t);
        if (k.ok && k.key != good.key) ++accepted_wrong;
    }
    CHECK(accepted_wrong == 0, "tampered helper never yields a different accepted key");
}

static void test_device_clone_rejected() {
    Device d(7, 777);
    Rng trng(99);
    Bytes cred = to_bytes("DOOR-KEY");
    FlashImage img = d.provision(cred, trng);
    CHECK(d.unlock(img, 25, 3.3, 0).status == UnlockStatus::Ok, "device unlocks locally");

    // A clone = same flash image on foreign silicon.
    Device foreign(7, 888);
    FlashImage copied = img;
    auto r = foreign.unlock(copied, 25, 3.3, 0);
    CHECK(r.status != UnlockStatus::Ok, "clone rejected");
    CHECK(r.credential.empty(), "clone learns no credential");
}

static void test_device_credential_tamper() {
    Device d(7, 777);
    Rng trng(99);
    Bytes cred = to_bytes("DOOR-KEY");
    FlashImage img = d.provision(cred, trng);
    FlashImage t = img;
    t.cred.ct[0] ^= 1;
    // Fresh device instance with same silicon seed (same chip).
    Device d2(7, 777);
    auto r = d2.unlock(t, 25, 3.3, 0);
    CHECK(r.status != UnlockStatus::Ok, "ciphertext tamper rejected");
}

static void test_device_lockout() {
    Device d(7, 777);
    Rng trng(99);
    Bytes cred = to_bytes("DOOR-KEY");
    FlashImage img = d.provision(cred, trng);
    int attempts = 0;
    for (int i = 0; i < 200; ++i) {
        Device::tamper_helper_bit(img, size_t(i) * 13 + 1);
        auto r = d.unlock(img, 25, 3.3, 0);
        if (r.status == UnlockStatus::LockedOut) break;
        ++attempts;
    }
    CHECK(attempts < 200, "ratchet locks out brute-force tampering");
    auto r = d.unlock(img, 25, 3.3, 0);
    CHECK(r.status == UnlockStatus::LockedOut, "stays locked out");
}

int main() {
    test_bch_params();
    test_fe_roundtrip();
    test_fe_is_device_bound();
    test_fe_extreme_temperature();
    test_fe_aging();
    test_fe_helper_tamper_rejected();
    test_device_clone_rejected();
    test_device_credential_tamper();
    test_device_lockout();
    if (fails) { std::printf("%d FE/device checks FAILED\n", fails); return 1; }
    std::printf("all fuzzy-extractor/device tests passed\n");
    return 0;
}
