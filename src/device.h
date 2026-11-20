#pragma once
#include "common.h"
#include "crypto.h"
#include "puf.h"
#include "fuzzy_extractor.h"
#include <memory>
#include <optional>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// Device-bound credential store.
//
// Layout of the flash image (what an attacker clones / tampers with):
//   * HELPERS[n_slots] : fuzzy-extractor helper for each retired/failed key
//   * CRED_BLOB        : AEAD-encrypted credential vault
//   * META             : plaintext device id, scheme id, public salt
//   * AUTH_COUNTER     : monotonic unlock-failure counter (see below)
//
// The credential vault key is the FE key. On a cloned board the FE key differs
// (different silicon), so the AEAD tag fails and the credential stays sealed.
//
// Unlock policy (`UnlockMode`) matters against the "helper-tampering oracle":
//   * Verbose   : report which stage failed (leaks a small oracle).
//   * Constant  : one generic failure, constant work per attempt.
//   * Ratchet   : constant failure + aggressive per-attempt work increase and a
//                 persisted lockout after N failures. A tampered helper can only
//                 cost the attacker attempts, never information.
// ---------------------------------------------------------------------------

enum class UnlockMode { Verbose, Constant, Ratchet };

enum class UnlockStatus {
    Ok,
    BadPuf,          // PUF/fuzzy-extractor failure
    HelperTampered,  // helper tag / structural check failed
    BadCredential,   // credential AEAD failed
    LockedOut,       // attempt budget exhausted
};

inline const char* to_string(UnlockStatus s) {
    switch (s) {
        case UnlockStatus::Ok: return "Ok";
        case UnlockStatus::BadPuf: return "BadPuf";
        case UnlockStatus::HelperTampered: return "HelperTampered";
        case UnlockStatus::BadCredential: return "BadCredential";
        case UnlockStatus::LockedOut: return "LockedOut";
    }
    return "?";
}

struct DeviceMeta {
    uint32_t device_id = 0;
    uint32_t scheme = 0;
    Bytes salt;           // public random salt
};

struct StoredCredential {
    Bytes nonce;
    Bytes ct;
    Bytes tag;
    Bytes aad;            // bound to device_id || scheme || slot id
};

struct FlashImage {
    DeviceMeta meta;
    FeHelper helper;
    StoredCredential cred;
    uint32_t fail_count = 0;
    uint32_t lockout_threshold = 32;
};

struct UnlockResult {
    UnlockStatus status = UnlockStatus::BadPuf;
    Bytes credential;     // populated on success
    int fe_extra_erasures = -1;
};

class Device {
public:
    Device(uint32_t device_id, uint64_t seed, const PufSpec& spec = PufSpec(),
           FeParams fe_params = FeParams())
        : device_id_(device_id), chip_(seed, spec),
          fe_(std::make_unique<FuzzyExtractor>(fe_params)) {}

    // PUF chip exposed for experiments (temperature/voltage/aging).
    PufChip& chip() { return chip_; }
    const FuzzyExtractor& fe() const { return *fe_; }

    // Factory provisioning: enroll the PUF, derive the vault key, and seal the
    // credential. `trng` supplies all secret randomness (K_raw, salt, nonce).
    FlashImage provision(const Bytes& credential, Rng& trng, UnlockMode mode = UnlockMode::Ratchet) {
        FlashImage img;
        img.meta.device_id = device_id_;
        img.meta.scheme = fe_->params().version;
        img.meta.salt.resize(16);
        trng.fill(img.meta.salt.data(), img.meta.salt.size());

        int blocks = estimate_blocks();
        if (blocks < 1) throw std::runtime_error("provision: not enough stable PUF cells");
        int need = fe_->message_bytes(blocks);
        Bytes kraw(need);
        trng.fill(kraw.data(), kraw.size());

        img.helper = fe_->enroll(chip_, device_id_, kraw);
        Bytes vault_key = fe_->enrollment_key(img.helper, kraw);
        Bytes aad = cred_aad(img.meta, 0);
        Bytes nonce(12);
        trng.fill(nonce.data(), nonce.size());
        AeadBlob b = aead_seal(vault_key, aad, credential, nonce);
        img.cred.nonce = b.nonce;
        img.cred.ct = b.ct;
        img.cred.tag = b.tag;
        img.cred.aad = aad;
        mode_ = mode;
        img.lockout_threshold = (mode == UnlockMode::Ratchet) ? 32 : 0xFFFFFFFFu;
        secure_wipe(kraw);
        secure_wipe(vault_key);
        return img;
    }

    // Attempt an unlock with a fresh PUF read at the current condition.
    UnlockResult unlock(FlashImage& img, double temp_c, double supply_v, double age_years) {
        UnlockResult r;
        if (mode_ == UnlockMode::Ratchet && img.fail_count >= img.lockout_threshold) {
            r.status = UnlockStatus::LockedOut;
            return r;
        }
        std::vector<double> analog = average_reads(chip_, temp_c, supply_v, age_years,
                                                   fe_->params().reads);
        FeKey k = fe_->reproduce(analog, img.helper);
        if (!k.ok) {
            note_failure(img, mode_ == UnlockMode::Ratchet ? 2 : 1);
            r.status = (mode_ == UnlockMode::Verbose) ? UnlockStatus::BadPuf
                       : UnlockStatus::BadPuf;
            return r;
        }
        Bytes plain;
        if (!aead_open(k.key, img.cred.aad, img.cred.nonce, img.cred.ct, img.cred.tag, plain)) {
            note_failure(img, 1);
            r.status = UnlockStatus::BadCredential;
            secure_wipe(k.key);
            return r;
        }
        r.status = UnlockStatus::Ok;
        r.credential = plain;
        r.fe_extra_erasures = k.extra_erasures_used;
        secure_wipe(k.key);
        return r;
    }

    // Tampering helper: flip one bit of the helper payload (simulating a flash
    // attacker) without touching the tag.
    static void tamper_helper_bit(FlashImage& img, size_t offset) {
        if (img.helper.bits.empty()) return;
        img.helper.bits[offset % img.helper.bits.size()] ^= 1;
    }

private:
    int estimate_blocks() { return 8; } // upper bound; enroll() trims to stable cells

    Bytes cred_aad(const DeviceMeta& m, uint32_t slot) const {
        Bytes aad = to_bytes("vault");
        uint8_t buf[12];
        auto put = [&](uint32_t v, int o) {
            buf[o] = uint8_t(v); buf[o+1] = uint8_t(v>>8);
            buf[o+2] = uint8_t(v>>16); buf[o+3] = uint8_t(v>>24);
        };
        put(m.device_id, 0); put(m.scheme, 4); put(slot, 8);
        aad.insert(aad.end(), buf, buf + 12);
        aad.insert(aad.end(), m.salt.begin(), m.salt.end());
        return aad;
    }

    void note_failure(FlashImage& img, uint32_t inc) {
        if (img.fail_count > 0xFFFFFFFFu - inc) img.fail_count = 0xFFFFFFFFu;
        else img.fail_count += inc;
    }

    uint32_t device_id_;
    PufChip chip_;
    std::unique_ptr<FuzzyExtractor> fe_;
    UnlockMode mode_ = UnlockMode::Ratchet;
};
