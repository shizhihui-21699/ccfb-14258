#pragma once
#include "common.h"
#include "crypto.h"
#include "bch.h"
#include "puf.h"
#include <algorithm>
#include <cmath>
#include <memory>

// ---------------------------------------------------------------------------
// Stable-subset fuzzy extractor over a binary BCH(255,k,t) code.
//
// Empirically (see tests/), a silicon PUF's errors are dominated by *systematic*
// condition drift, not random noise: ~25% of cells flip together when the board
// heats/cools or the rail sags, and those cells are the same ones every time.
// Two designs follow from that:
//
//  (A) Erasure marking: send every volatile cell to the decoder as an erasure.
//      An erasure costs 1 parity symbol, an undetected error costs 2, so this
//      roughly doubles the budget per volatile cell - but the volatile set
//      (~25% -> ~64 of 255 per block) alone nearly exhausts 2t, leaving no margin
//      for aging.
//
//  (B) Stable-subset extraction (this implementation): discard volatile cells at
//      enrollment and build the codewords only from cells that never flipped on
//      the factory calibration grid. The parity budget is then spent entirely on
//      aging drift, not on temperature. Capacity drops (fewer usable cells), but
//      every surviving bit is one that has been *observed* to be stable.
//
// The public descriptor records: the threshold, the stable-cell index map, and
// the code-offset helper. The secret RNG seed K_raw makes the derived key uniform
// even though PUF bits are biased; the 128-bit tag is what gates acceptance, so a
// wrong candidate is rejected regardless of what the algebraic decoder claims.
// ---------------------------------------------------------------------------

struct FeParams {
    int cells = 2048;
    int bch_t = 32;              // BCH(255, k, t), k = 47
    int reads = 8;
    // factory calibration grid (within the device's rated envelope)
    std::vector<double> cal_temps = {-20, 0, 25, 50, 75, 100};
    std::vector<double> cal_volts = {2.7, 3.0, 3.3, 3.6};
    int cal_reads = 6;
    int cal_aging_years = 0;
    // When false, skip stability selection and use the first cells of the array
    // (baseline "naive" design, used only to quantify what selection buys).
    bool select_stable = true;
    // runtime: additional erasures among *stable* cells, least reliable first
    std::vector<int> extra_erasures = {0, 8, 16, 24, 32, 40, 48};
    int tag_len = 16;
    uint32_t version = 3;
};

struct FeHelper {
    uint32_t version = 0;
    uint32_t device_id = 0;
    int bch_t = 0;
    int blocks = 0;
    int cells_used = 0;         // = blocks * 255, count of stable cells used
    double threshold = 0.0;
    std::vector<int> stable_idx; // positions (into the physical array) of used cells
    Bytes bits;                  // 0/1 per used cell: codeword XOR reference bit
    Bytes tag;

    int usable_secret_bits(int bch_k) const { return blocks * bch_k; }

    Bytes core_digest() const {
        Sha256 h;
        uint8_t hdr[28];
        size_t p = 0;
        auto put32 = [&](uint32_t v) {
            hdr[p++] = uint8_t(v); hdr[p++] = uint8_t(v >> 8);
            hdr[p++] = uint8_t(v >> 16); hdr[p++] = uint8_t(v >> 24);
        };
        put32(version); put32(device_id); put32(uint32_t(bch_t));
        put32(uint32_t(blocks)); put32(uint32_t(cells_used));
        uint64_t tb; std::memcpy(&tb, &threshold, 8);
        for (int i = 0; i < 8; ++i) hdr[p++] = uint8_t(tb >> (8 * i));
        h.update(hdr, p);
        for (int idx : stable_idx) {
            uint8_t b4[4] = {uint8_t(idx), uint8_t(idx >> 8), uint8_t(idx >> 16), uint8_t(idx >> 24)};
            h.update(b4, 4);
        }
        h.update(bits);
        return h.final();
    }
};

struct FeKey {
    Bytes key;
    int extra_erasures_used = -1;
    bool ok = false;
};

class FuzzyExtractor {
public:
    explicit FuzzyExtractor(FeParams p = FeParams()) : p_(std::move(p)) {
        bch_ = std::make_unique<Bch>(p_.bch_t);
        kbits_ = bch_->k();
    }

    const FeParams& params() const { return p_; }
    int bch_k() const { return kbits_; }
    int bch_t() const { return bch_->t(); }
    int message_bytes(int blocks) const { return (blocks * kbits_ + 7) / 8; }

    static Bytes threshold_bits(const std::vector<double>& v, double thr) {
        Bytes b(v.size());
        for (size_t i = 0; i < v.size(); ++i) b[i] = v[i] > thr ? 1 : 0;
        return b;
    }
    static double median(std::vector<double> v) {
        if (v.empty()) return 0.0;
        std::nth_element(v.begin(), v.begin() + v.size() / 2, v.end());
        return v[v.size() / 2];
    }

    // Factory enrollment.
    FeHelper enroll(PufChip& chip, uint32_t device_id, const Bytes& kraw) const {
        FeHelper h;
        h.version = p_.version;
        h.device_id = device_id;
        h.bch_t = p_.bch_t;
        int N = p_.cells;

        std::vector<double> ref = average_reads(chip, 25.0, 3.3, p_.cal_aging_years, p_.reads * 2);
        h.threshold = median(ref);
        Bytes refbits = threshold_bits(ref, h.threshold);

        // Volatile = flips anywhere on the calibration grid; stable = the rest.
        std::vector<uint8_t> volatile_(N, 0);
        for (double T : p_.cal_temps)
            for (double V : p_.cal_volts) {
                std::vector<double> a = average_reads(chip, T, V, p_.cal_aging_years, p_.cal_reads);
                Bytes b = threshold_bits(a, h.threshold);
                for (int i = 0; i < N; ++i) if (b[i] != refbits[i]) volatile_[i] = 1;
            }
        std::vector<int> stable;
        if (p_.select_stable) {
            for (int i = 0; i < N; ++i) if (!volatile_[i]) stable.push_back(i);
        } else {
            for (int i = 0; i < N; ++i) stable.push_back(i); // naive: use the raw array
        }

        int blocks = static_cast<int>(stable.size()) / 255;
        if (blocks < 1) throw std::runtime_error("FE enroll: not enough stable cells");
        if (static_cast<int>(kraw.size()) * 8 < blocks * kbits_)
            throw std::runtime_error("FE enroll: not enough key material");
        h.blocks = blocks;
        h.cells_used = blocks * 255;
        h.stable_idx.assign(stable.begin(), stable.begin() + h.cells_used);

        h.bits.assign(h.cells_used, 0);
        // Normalize K_raw to exactly blocks*kbits_ bits: zero the unused high bits
        // of the final partial byte so enrollment and reproduction agree on them.
        Bytes k = kraw;
        int used_bits = h.blocks * kbits_;
        int full = used_bits / 8, rem = used_bits % 8;
        int klen = full + (rem ? 1 : 0);
        if (rem && full < static_cast<int>(k.size()))
            k[full] &= uint8_t((1u << rem) - 1);
        // Truncate to exactly the recovered length so enrollment and reproduction
        // derive the key from the same byte string.
        k.resize(klen);
        std::vector<uint8_t> msg(kbits_);
        for (int b = 0; b < blocks; ++b) {
            for (int i = 0; i < kbits_; ++i) {
                int bit = b * kbits_ + i;
                msg[i] = (k[bit / 8] >> (bit % 8)) & 1;
            }
            auto cw = bch_->encode(msg);
            for (int i = 0; i < 255; ++i) {
                int idx = h.stable_idx[b * 255 + i];
                h.bits[b * 255 + i] = uint8_t(cw[i] ^ refbits[idx]);
            }
        }
        Bytes digest = h.core_digest();
        Bytes key = hkdf(k, digest, to_bytes("fe-key"), 32);
        h.tag = hmac_sha256(key, to_bytes("fe-verify"));
        h.tag.resize(p_.tag_len);
        secure_wipe(key);
        secure_wipe(k);
        return h;
    }

    // Derive the vault key during enrollment, matching what reproduce() computes.
    Bytes enrollment_key(const FeHelper& h, const Bytes& kraw) const {
        int used_bits = h.blocks * kbits_;
        int full = used_bits / 8, rem = used_bits % 8;
        int klen = full + (rem ? 1 : 0);
        Bytes k(kraw.begin(), kraw.begin() + std::min<size_t>(klen, kraw.size()));
        k.resize(klen, 0);
        if (rem && full < static_cast<int>(k.size())) k[full] &= uint8_t((1u << rem) - 1);
        Bytes digest = h.core_digest();
        Bytes key = hkdf(k, digest, to_bytes("fe-key"), 32);
        secure_wipe(k);
        return key;
    }

    FeKey reproduce(const std::vector<double>& analog, const FeHelper& h) const {
        FeKey out;
        if (h.version != p_.version || h.bch_t != p_.bch_t || h.blocks < 1) return out;
        if (static_cast<int>(h.bits.size()) != h.blocks * 255) return out;
        if (static_cast<int>(h.stable_idx.size()) != h.blocks * 255) return out;
        // stable_idx indexes the physical array; reject a short read instead of
        // indexing out of bounds.
        for (int idx : h.stable_idx)
            if (idx < 0 || idx >= static_cast<int>(analog.size())) return out;
        Bytes digest = h.core_digest();
        for (int extra : p_.extra_erasures) {
            Bytes kraw;
            if (!decode_all(analog, h, extra, kraw)) continue;
            Bytes key = hkdf(kraw, digest, to_bytes("fe-key"), 32);
            Bytes tag = hmac_sha256(key, to_bytes("fe-verify"));
            tag.resize(p_.tag_len);
            if (ct_equal(tag, h.tag)) {
                out.key = key; out.extra_erasures_used = extra; out.ok = true;
                return out;
            }
            secure_wipe(key);
        }
        return out;
    }

    int decodable_blocks(const std::vector<double>& analog, const FeHelper& h, int extra) const {
        if (static_cast<int>(h.bits.size()) != h.blocks * 255) return 0;
        if (static_cast<int>(h.stable_idx.size()) != h.blocks * 255) return 0;
        for (int idx : h.stable_idx)
            if (idx < 0 || idx >= static_cast<int>(analog.size())) return 0;
        Bytes r = threshold_bits(analog, h.threshold);
        int good = 0;
        for (int b = 0; b < h.blocks; ++b) {
            auto er = erasures_for_block(analog, h, b, extra);
            std::array<uint8_t, 255> cw{}, dec;
            for (int i = 0; i < 255; ++i) {
                int idx = h.stable_idx[b * 255 + i];
                cw[i] = uint8_t(r[idx] ^ h.bits[b * 255 + i]);
            }
            if (bch_->decode(cw, er, dec)) ++good;
        }
        return good;
    }

private:
    std::vector<int> erasures_for_block(const std::vector<double>& analog, const FeHelper& h,
                                        int b, int extra) const {
        std::vector<int> out;
        if (extra <= 0) return out;
        std::vector<std::pair<double, int>> rel;
        rel.reserve(255);
        for (int i = 0; i < 255; ++i) {
            int idx = h.stable_idx[b * 255 + i];
            rel.emplace_back(std::fabs(analog[idx] - h.threshold), i);
        }
        int take = std::min<int>(extra, 255);
        std::partial_sort(rel.begin(), rel.begin() + take, rel.end());
        for (int j = 0; j < take; ++j) out.push_back(rel[j].second);
        return out;
    }

    bool decode_all(const std::vector<double>& analog, const FeHelper& h, int extra,
                    Bytes& kraw) const {
        Bytes r = threshold_bits(analog, h.threshold);
        Bytes out;
        out.reserve(h.blocks * kbits_);
        for (int b = 0; b < h.blocks; ++b) {
            auto er = erasures_for_block(analog, h, b, extra);
            std::array<uint8_t, 255> cw{}, dec;
            for (int i = 0; i < 255; ++i) {
                int idx = h.stable_idx[b * 255 + i];
                cw[i] = uint8_t(r[idx] ^ h.bits[b * 255 + i]);
            }
            if (!bch_->decode(cw, er, dec)) return false;
            auto msg = bch_->extract_message(dec);
            out.insert(out.end(), msg.begin(), msg.end());
        }
        kraw.assign((out.size() + 7) / 8, 0);
        for (size_t i = 0; i < out.size(); ++i) kraw[i / 8] |= uint8_t(out[i] << (i % 8));
        return true;
    }

    FeParams p_;
    std::unique_ptr<Bch> bch_;
    int kbits_ = 0;
};
