#include "../src/device.h"
#include "../src/fuzzy_extractor.h"
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>
#include <memory>

// ---------------------------------------------------------------------------
// Experiment driver. All results are printed as CSV lines prefixed with "CSV,"
// plus human-readable context. The report generator consumes the CSV.
//
// All PUF physics is simulated (src/puf.h). No real silicon was measured.
// ---------------------------------------------------------------------------

struct Stat {
    int ok = 0, total = 0;
    double rate() const { return total ? double(ok) / total : 0.0; }
    void add(bool v) { ++total; ok += v ? 1 : 0; }
};

static std::unique_ptr<Device> g_dev;
static FlashImage g_img;
static Bytes g_cred;

// Provision one deterministic chip with the given FE params.
static void setup(int chip_seed, FeParams p) {
    g_cred = to_bytes("DOOR-HMAC-KEY:9f2c1e7b4a");
    g_dev = std::make_unique<Device>(7, uint64_t(chip_seed), PufSpec(), p);
    Rng trng(uint64_t(0xABCD0000 + chip_seed));
    g_img = g_dev->provision(g_cred, trng, UnlockMode::Ratchet);
}

static bool try_unlock(double T, double V, double age) {
    auto r = g_dev->unlock(g_img, T, V, age);
    return r.status == UnlockStatus::Ok && r.credential == g_cred;
}

// ---------------------------------------------------------------------------
static void run_temps() {
    setup(101, FeParams());
    std::printf("# TEMPERATURE / VOLTAGE\n");
    std::printf("# device: blocks=%d stable_cells=%d secret_bits=%d t=%d\n",
                g_img.helper.blocks, g_img.helper.cells_used,
                g_img.helper.blocks * g_dev->fe().bch_k(), g_dev->fe().bch_t());

    std::printf("# --- temperature sweep at 3.3 V, 10 attempts each ---\n");
    for (double T : {-40.0, -20.0, 0.0, 25.0, 45.0, 65.0, 85.0, 105.0, 125.0}) {
        Stat s;
        for (int i = 0; i < 10; ++i) s.add(try_unlock(T, 3.3, 0));
        std::printf("CSV,temp,%.1f,%.3f,%d,%d\n", T, s.rate(), s.ok, s.total);
        std::printf("  T=%6.1f C : %3d/%2d = %5.1f%%\n", T, s.ok, s.total, 100 * s.rate());
    }

    std::printf("# --- voltage sweep at 25 C, 10 attempts each ---\n");
    for (double V : {2.6, 2.8, 3.0, 3.3, 3.6, 3.8}) {
        Stat s;
        for (int i = 0; i < 10; ++i) s.add(try_unlock(25, V, 0));
        std::printf("CSV,volt,%.2f,%.3f,%d,%d\n", V, s.rate(), s.ok, s.total);
        std::printf("  V=%.2f V : %3d/%2d = %5.1f%%\n", V, s.ok, s.total, 100 * s.rate());
    }

    std::printf("# --- joint hot + low voltage, 10 attempts each ---\n");
    for (double T : {65.0, 85.0, 105.0})
        for (double V : {2.8, 3.0}) {
            Stat s;
            for (int i = 0; i < 10; ++i) s.add(try_unlock(T, V, 0));
            std::printf("CSV,joint,%.1f,%.2f,%.3f\n", T, V, s.rate());
            std::printf("  T=%5.1f C V=%.2f : %3d/%2d\n", T, V, s.ok, s.total);
        }
}

// ---------------------------------------------------------------------------
static void run_aging() {
    setup(101, FeParams());
    std::printf("# AGING\n");
    std::printf("# --- age sweep at 25 C ---\n");
    for (double a : {0.0, 1.0, 2.0, 3.0, 5.0, 7.0, 10.0, 15.0, 20.0}) {
        Stat s;
        for (int i = 0; i < 10; ++i) s.add(try_unlock(25, 3.3, a));
        std::printf("CSV,age,%.1f,%.3f,%d,%d\n", a, s.rate(), s.ok, s.total);
        std::printf("  age=%4.1f y : %3d/%2d = %5.1f%%\n", a, s.ok, s.total, 100 * s.rate());
    }
    std::printf("# --- aging x temperature grid (3 attempts per cell) ---\n");
    for (double a : {0.0, 5.0, 10.0, 15.0}) {
        for (double T : {-20.0, 25.0, 70.0, 85.0, 105.0}) {
            Stat s;
            for (int i = 0; i < 3; ++i) s.add(try_unlock(T, 3.3, a));
            std::printf("CSV,age_temp,%.0f,%.0f,%.3f\n", a, T, s.rate());
            std::printf("  age=%4.0f y T=%6.1f C : %d/%d\n", a, T, s.ok, s.total);
        }
    }
}

// ---------------------------------------------------------------------------
static void run_attacks() {
    std::printf("# ATTACKS\n");
    setup(101, FeParams());

    // A. Cloning: same flash image, different silicon, across many foreign chips.
    {
        Stat accepted;
        int n = 50;
        for (int i = 0; i < n; ++i) {
            Device foreign(7, uint64_t(90000 + i), PufSpec());
            FlashImage img = g_img;              // attacker copied the whole flash
            auto r = foreign.unlock(img, 25, 3.3, 0);
            accepted.add(r.status == UnlockStatus::Ok);
        }
        std::printf("CSV,clone_accept,%.4f,%d,%d\n", accepted.rate(), accepted.ok, accepted.total);
        std::printf("  clone attempts: %d/%d accepted (credential recovered)\n", accepted.ok, accepted.total);
    }

    // B. Helper tampering: flip helper payload bits, watch for false accepts.
    {
        Stat accepted;
        int n = 500;
        Rng rng(555);
        for (int i = 0; i < n; ++i) {
            FlashImage img = g_img;
            size_t off = rng.below(img.helper.bits.size());
            Device::tamper_helper_bit(img, off);
            auto r = g_dev->unlock(img, 25, 3.3, 0);
            accepted.add(r.status == UnlockStatus::Ok && r.credential == g_cred);
        }
        std::printf("CSV,tamper_false_accept,%.4f,%d,%d\n", accepted.rate(), accepted.ok, accepted.total);
        std::printf("  single-bit helper tampering: %d/%d unlocked with the true credential\n",
                    accepted.ok, accepted.total);
    }

    // C. Oracle: repeatedly tamper, count failures, verify lockout in Ratchet mode.
    {
        FlashImage img = g_img;
        int attempts_before_lock = 0;
        for (int i = 0; i < 1000; ++i) {
            Device::tamper_helper_bit(img, size_t(i) * 7 + 3);
            auto r = g_dev->unlock(img, 25, 3.3, 0);
            if (r.status == UnlockStatus::LockedOut) break;
            ++attempts_before_lock;
        }
        std::printf("CSV,lockout_attempts,%d\n", attempts_before_lock);
        std::printf("  ratchet lockout after %d tamper attempts (threshold %u)\n",
                    attempts_before_lock, img.lockout_threshold);
    }

    // D. Offline key-guess: attacker has helper + tag but no PUF. Security is
    //    min(K_raw entropy, 128-bit tag). Report the design's K_raw length.
    {
        int bits = g_img.helper.blocks * g_dev->fe().bch_k();
        std::printf("CSV,offline_guess_bits,%d\n", bits);
        std::printf("  offline key-guess work bound: 2^%d (K_raw) vs 2^128 tag, "
                    "so 2^%d work\n", bits, std::min(bits, 128));
    }

    // E. Wrong-credential integrity: corrupt the stored ciphertext.
    {
        FlashImage img = g_img;
        img.cred.ct[0] ^= 1;
        auto r = g_dev->unlock(img, 25, 3.3, 0);
        std::printf("CSV,ct_tamper_detected,%d\n", r.status != UnlockStatus::Ok);
        std::printf("  ciphertext tamper detected: %s\n",
                    r.status != UnlockStatus::Ok ? "yes" : "NO (BUG)");
    }
}

// ---------------------------------------------------------------------------
static void run_sweep() {
    std::printf("# DESIGN SWEEP (secret bits vs reliability)\n");
    std::printf("# columns: t,k,blocks,secret_bits,T85,age10_25C,age10_T85,age20_T125\n");
    for (int t : {12, 16, 20, 24, 28, 32, 40, 46}) {
        FeParams p; p.bch_t = t;
        int blocks = 0, kbits = 0;
        Stat s_t85, s_a10, s_a10t85, s_a20t125;
        int N = 20;
        for (int cid = 0; cid < N; ++cid) {
            Device dev(7, uint64_t(3000 + cid), PufSpec(), p);
            Rng trng(uint64_t(4000 + cid));
            Bytes cred = to_bytes("cred");
            FlashImage img;
            try { img = dev.provision(cred, trng); } catch (...) { blocks = -1; break; }
            blocks = img.helper.blocks;
            kbits = dev.fe().bch_k();
            auto test = [&](double T, double age) {
                auto r = dev.unlock(img, T, 3.3, age);
                return r.status == UnlockStatus::Ok;
            };
            s_t85.add(test(85, 0));
            s_a10.add(test(25, 10));
            s_a10t85.add(test(85, 10));
            s_a20t125.add(test(125, 20));
        }
        if (blocks < 0) { std::printf("CSV,sweep,%d,enroll_fail\n", t); continue; }
        std::printf("CSV,sweep,%d,%d,%d,%d,%.3f,%.3f,%.3f,%.3f\n",
                    t, kbits, blocks, blocks * kbits,
                    s_t85.rate(), s_a10.rate(), s_a10t85.rate(), s_a20t125.rate());
        std::printf("  t=%2d k=%3d blocks=%d secret=%4d bits | T85 %3.0f%% age10 %3.0f%% "
                    "age10+T85 %3.0f%% age20+T125 %3.0f%%\n",
                    t, kbits, blocks, blocks * kbits,
                    100 * s_t85.rate(), 100 * s_a10.rate(),
                    100 * s_a10t85.rate(), 100 * s_a20t125.rate());
    }
}

// ---------------------------------------------------------------------------
// Boundary probe: for each t, find the temperature and age at which the unlock
// success rate over a small multi-chip population drops below 50%.

static void run_bounds() {
    std::printf("# RELIABILITY BOUNDS (enrolled new, multi-chip, 50%% success crossing)\n");
    std::printf("# columns: t,secret_bits,enrolled_chips,max_temp_C,max_age_y\n");
    const int chips = 8, trials = 3;
    for (int t : {12, 16, 20, 24, 28, 32, 40}) {
        FeParams p; p.bch_t = t;
        FuzzyExtractor fe(p);
        int kbits = fe.bch_k();

        // Provision one fresh population (enrolled at age 0, 25 C).
        std::vector<std::pair<std::unique_ptr<Device>, FlashImage>> pop;
        for (int cid = 0; cid < chips; ++cid) {
            auto dev = std::make_unique<Device>(7, uint64_t(5000 + cid), PufSpec(), p);
            Rng trng(uint64_t(6000 + cid));
            Bytes cred = to_bytes("cred");
            FlashImage img;
            try { img = dev->provision(cred, trng); } catch (...) { continue; }
            pop.emplace_back(std::move(dev), std::move(img));
        }
        if (pop.empty()) { std::printf("CSV,bounds,%d,0,0,-1000,-1\n", t); continue; }
        int blocks = pop.front().second.helper.blocks;
        int secret = blocks * kbits;

        auto rate = [&](double T, double age) {
            Stat s;
            for (auto& [dev, img] : pop)
                for (int k = 0; k < trials; ++k) {
                    FlashImage local = img;   // don't let the fail counter latch
                    s.add(dev->unlock(local, T, 3.3, age).status == UnlockStatus::Ok);
                }
            return s.rate();
        };
        // Max temperature at nominal age 0 (extrapolation stress to 175 C).
        double maxT = -1000;
        for (double T = 25; T <= 175; T += 15) {
            if (rate(T, 0) >= 0.5) maxT = T; else break;
        }
        // Max age at 25 C.
        double maxAge = 0;
        for (double a = 5; a <= 60; a += 5) {
            if (rate(25, a) >= 0.5) maxAge = a; else break;
        }
        std::printf("CSV,bounds,%d,%d,%zu,%.0f,%.0f\n", t, secret, pop.size(), maxT, maxAge);
        std::printf("  t=%2d secret=%4d bits | chips=%zu | max T=%.0f C | max age=%.0f y\n",
                    t, secret, pop.size(), maxT, maxAge);
    }
}

// ---------------------------------------------------------------------------
// Extreme boundaries, well beyond the accessory-lock envelope: where does the
// default t=32 design actually stop working?
static void run_extremes() {
    std::printf("# EXTREME BOUNDARIES (t=32, beyond rated envelope)\n");
    FeParams p;
    Device dev(7, 777, PufSpec(), p);
    Rng trng(99);
    Bytes cred = to_bytes("c");
    FlashImage img = dev.provision(cred, trng);
    for (double T : {-80.0, -60.0, -40.0, 0.0, 125.0, 150.0, 175.0, 200.0, 225.0}) {
        int ok = 0;
        for (int i = 0; i < 10; ++i) { FlashImage local = img; ok += dev.unlock(local, T, 3.3, 0).status == UnlockStatus::Ok; }
        std::printf("CSV,extreme_temp,%.0f,%.2f\n", T, ok / 10.0);
        std::printf("  T=%6.0f C : %d/10\n", T, ok);
    }
    for (double a : {10.0, 20.0, 30.0, 40.0, 50.0, 60.0}) {
        int ok = 0;
        for (int i = 0; i < 10; ++i) { FlashImage local = img; ok += dev.unlock(local, 25, 3.3, a).status == UnlockStatus::Ok; }
        std::printf("CSV,extreme_age,%.0f,%.2f\n", a, ok / 10.0);
        std::printf("  age=%4.0f y : %d/10\n", a, ok);
    }
}

// ---------------------------------------------------------------------------
// Spec-envelope test: the accessory-lock operating envelope is -20..70 C,
// 2.9..3.5 V, 10 years. Sweep the whole grid across many chips per design point.
static void run_envelope() {
    std::printf("# SPEC ENVELOPE: -20..70 C x 2.9..3.5 V x 0..10 y, 30 chips x 10 trials/cell\n");
    std::printf("# columns: t,secret_bits,success_rate,total\n");
    const int chips = 30, trials = 10;
    int deficit_design = 0;
    for (int t : {20, 24, 28, 32}) {
        FeParams p; p.bch_t = t;
        int ok = 0, tot = 0, secret = 0;
        for (int cid = 0; cid < chips; ++cid) {
            Device dev(7, uint64_t(9000 + cid), PufSpec(), p);
            Rng trng(uint64_t(9500 + cid));
            Bytes cred = to_bytes("c");
            FlashImage img;
            try { img = dev.provision(cred, trng); } catch (...) { continue; }
            secret = img.helper.blocks * dev.fe().bch_k();
            for (double T : {-20.0, 0.0, 25.0, 45.0, 70.0})
                for (double V : {2.9, 3.3, 3.5})
                    for (double a : {0.0, 5.0, 10.0})
                        for (int k = 0; k < trials; ++k) {
                            FlashImage local = img;
                            ok += dev.unlock(local, T, V, a).status == UnlockStatus::Ok;
                            ++tot;
                        }
        }
        std::printf("CSV,envelope,%d,%d,%.5f,%d\n", t, secret, tot ? double(ok) / tot : 0.0, tot);
        std::printf("  t=%2d secret=%4d bits | spec-envelope success = %6.3f%% (%d/%d)\n",
                    t, secret, tot ? 100.0 * ok / tot : 0.0, ok, tot);
        if (tot && ok != tot) ++deficit_design;
        (void)deficit_design;
    }
}

// ---------------------------------------------------------------------------
// Diagnostics behind the design rationale: (a) inter-chip distance, (b) how
// completely the factory-calibrated volatile set predicts later runtime errors,
// (c) per-block hard-decision error counts for the naive design.
static void run_diagnostics() {
    std::printf("# DIAGNOSTICS\n");

    // (0) same-condition single-read flip rate
    {
        PufChip c(777);
        auto b1 = PufChip::bits(average_reads(c, 25, 3.3, 0, 1));
        int flips = 0, pairs = 5;
        for (int t = 0; t < pairs; ++t) {
            auto b2 = PufChip::bits(average_reads(c, 25, 3.3, 0, 1));
            for (size_t i = 0; i < b1.size(); ++i) flips += b1[i] ^ b2[i];
        }
        double rate = double(flips) / (pairs * b1.size());
        std::printf("CSV,read_flip_rate,%.4f\n", rate);
        std::printf("  same-condition single-read flip rate = %.2f%%\n", 100 * rate);
    }

    // (a) mean inter-chip Hamming distance of the ideal fingerprints
    {
        double tot = 0; int pairs = 0;
        for (int i = 0; i < 20; ++i)
            for (int j = i + 1; j < 20; ++j) {
                PufChip a(uint64_t(1000 + i)), b(uint64_t(1000 + j));
                auto ia = a.ideal(), ib = b.ideal();
                int d = 0;
                for (size_t k = 0; k < ia.size(); ++k) d += ((ia[k] > 0) != (ib[k] > 0));
                tot += 100.0 * d / ia.size();
                ++pairs;
            }
        std::printf("CSV,interchip_hd,%.2f,%d\n", tot / pairs, pairs);
        std::printf("  mean inter-chip HD = %.2f%% over %d pairs\n", tot / pairs, pairs);
    }

    // (b) volatile-set recall
    {
        PufChip chip(777);
        auto ref = average_reads(chip, 25, 3.3, 0, 32);
        auto rb = FuzzyExtractor::threshold_bits(ref, 0.0);
        std::vector<uint8_t> vol(2048, 0);
        for (double T : {-20.0, 0.0, 25.0, 50.0, 75.0, 100.0})
            for (double V : {2.7, 3.0, 3.3, 3.6}) {
                auto x = average_reads(chip, T, V, 0, 6);
                auto bx = FuzzyExtractor::threshold_bits(x, 0.0);
                for (int i = 0; i < 2048; ++i) if (bx[i] != rb[i]) vol[i] = 1;
            }
        int nvol = 0;
        for (int i = 0; i < 2048; ++i) nvol += vol[i];
        std::printf("CSV,volatile_fraction,%.3f\n", double(nvol) / 2048);
        std::printf("  volatile set = %d/2048 = %.1f%%\n", nvol, 100.0 * nvol / 2048);
        for (double T : {0.0, 25.0, 45.0, 65.0, 85.0, 105.0, 125.0}) {
            auto x = average_reads(chip, T, 3.3, 0, 8);
            auto bx = FuzzyExtractor::threshold_bits(x, 0.0);
            int err = 0, hit = 0;
            for (int i = 0; i < 2048; ++i) if (bx[i] ^ rb[i]) { ++err; if (vol[i]) ++hit; }
            double rec = err ? double(hit) / err : 1.0;
            std::printf("CSV,volatile_recall,%.0f,%.3f,%d,%d\n", T, rec, hit, err);
            std::printf("  T=%5.0f err=%3d in-volatile=%3d (%.0f%% recall)\n", T, err, hit, 100 * rec);
        }
    }

    // (c) naive per-block hard-decision error counts
    {
        FeParams p; p.select_stable = false;
        PufChip chip(777);
        FuzzyExtractor fe(p);
        Rng r(1); Bytes k(256); r.fill(k.data(), k.size());
        auto h = fe.enroll(chip, 42, k);
        auto ref0 = average_reads(chip, 25, 3.3, 0, 32);
        auto rb = FuzzyExtractor::threshold_bits(ref0, h.threshold);
        std::printf("# naive blocks=%d t=%d\n", h.blocks, fe.bch_t());
        for (double T : {25.0, 85.0, 105.0, 125.0}) {
            auto a = average_reads(chip, T, 3.3, 0, 8);
            auto rr = FuzzyExtractor::threshold_bits(a, h.threshold);
            std::vector<int> per;
            for (int b = 0; b < h.blocks; ++b) {
                int e = 0;
                for (int i = 0; i < 255; ++i) { int idx = h.stable_idx[b * 255 + i]; e += rr[idx] ^ rb[idx]; }
                per.push_back(e);
            }
            std::sort(per.begin(), per.end());
            std::printf("CSV,naive_block_err,%.0f,%d,%d,%d\n", T, per.front(), per[per.size() / 2], per.back());
            std::printf("  T=%5.0f naive errors/block min=%2d med=%2d max=%2d\n",
                        T, per.front(), per[per.size() / 2], per.back());
        }
    }
}

// ---------------------------------------------------------------------------
// Baseline comparison: naive fuzzy extractor (all cells, no stability selection)
// vs the proposed stable-subset design, over the same conditions and chips.
static void run_baseline() {
    std::printf("# BASELINE vs STABLE-SUBSET (8 chips x 5 trials per cell)\n");
    std::printf("# columns: design,t,secret_bits,T85,age10_25C,age20_25C,age10_T85\n");
    const int chips = 8, trials = 5;
    for (int t : {20, 32}) {
        for (int mode = 0; mode < 2; ++mode) {
            const char* name = mode ? "stable" : "naive";
            FeParams p; p.bch_t = t; p.select_stable = (mode == 1);
            int secret = 0;
            Stat s85, a10, a20, a10t85;
            for (int cid = 0; cid < chips; ++cid) {
                Device dev(7, uint64_t(7000 + cid), PufSpec(), p);
                Rng trng(uint64_t(8000 + cid));
                Bytes cred = to_bytes("cred");
                FlashImage img;
                try { img = dev.provision(cred, trng); } catch (...) { continue; }
                secret = img.helper.blocks * dev.fe().bch_k();
                auto test = [&](double T, double age) {
                    FlashImage local = img;
                    return dev.unlock(local, T, 3.3, age).status == UnlockStatus::Ok;
                };
                for (int k = 0; k < trials; ++k) {
                    s85.add(test(85, 0));
                    a10.add(test(25, 10));
                    a20.add(test(25, 20));
                    a10t85.add(test(85, 10));
                }
            }
            std::printf("CSV,baseline,%s,%d,%d,%.3f,%.3f,%.3f,%.3f\n",
                        name, t, secret, s85.rate(), a10.rate(), a20.rate(),
                        a10t85.rate());
            std::printf("  %-6s t=%2d secret=%4d bits | T85 %5.1f%% | age10 %5.1f%% | "
                        "age20 %5.1f%% | age10+T85 %5.1f%%\n",
                        name, t, secret, 100 * s85.rate(), 100 * a10.rate(),
                        100 * a20.rate(), 100 * a10t85.rate());
        }
    }
}

// ---------------------------------------------------------------------------
int main(int argc, char** argv) {
    std::string cmd = argc > 1 ? argv[1] : "all";
    if (cmd == "temps") run_temps();
    else if (cmd == "aging") run_aging();
    else if (cmd == "attacks") run_attacks();
    else if (cmd == "sweep") run_sweep();
    else if (cmd == "bounds") run_bounds();
    else if (cmd == "baseline") run_baseline();
    else if (cmd == "envelope") run_envelope();
    else if (cmd == "extremes") run_extremes();
    else if (cmd == "diagnostics") run_diagnostics();
    else if (cmd == "all") { run_temps(); run_aging(); run_attacks(); run_sweep(); run_bounds(); run_baseline(); run_envelope(); run_extremes(); run_diagnostics(); }
    else { std::printf("usage: %s [temps|aging|attacks|sweep|bounds|baseline|all]\n", argv[0]); return 1; }
    return 0;
}
