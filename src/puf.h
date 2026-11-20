#pragma once
#include "common.h"
#include <cmath>
#include <vector>

// ---------------------------------------------------------------------------
// SRAM power-up PUF simulator.
//
// Physically, each SRAM cell settles to the bit dictated by the threshold
// mismatch of its two cross-coupled inverters.  The mismatch delta_i is fixed at
// manufacture (the "fingerprint").  What changes with operating conditions is the
// *bias* added on top: the two inverters' temperature and supply sensitivities
// differ per cell, so a cell with a small delta can flip when hot/cold, while a
// cell with a large delta never flips.  Read-to-read noise at a fixed condition is
// small compared with these systematic shifts.
//
//   v_i(T,V,age) = delta_i * gain(age)
//                + tcoef_i * (T - 25)          [per-cell temperature sensitivity]
//                + vcoef_i * (V - 3.3)         [per-cell supply sensitivity]
//                + common(T,V)                 [array-wide bias]
//                + read_noise(T,V,age)         [small, per read]
//
// Aging (NBTI/HCI + charge trapping) is modelled as:
//   * mismatch shrink        delta_i *= (1 - shrink*dt)
//   * random-walk drift      delta_i += N(0, drift_sigma^2 * dt)
//   * permanent flips        with prob stuck_rate*dt the cell's settled value flips
//   * read noise growth      sigma *= (1 + age_noise*dt)
//
// Values are in units of the mismatch spread; sign(v_i) is the stored bit.
// ---------------------------------------------------------------------------

struct PufSpec {
    int cells = 2048;

    double mismatch_sigma = 1.0;

    // per-degree / per-volt sensitivity spread
    double tcoef_sigma = 0.0045;   // shift std at |dT| = 100 C is 0.45
    double vcoef_sigma = 0.12;     // shift std at |dV| = 1.0 V is 0.12

    double sigma0 = 0.020;         // nominal per-read noise
    double rts_prob = 0.0015;      // sparse random-telegraph-noise cells per read
    double rts_sigma = 1.2;

    // aging
    double age_shrink = 0.012;     // fraction of mismatch lost per year
    double age_drift = 0.050;      // random-walk std per sqrt(year)
    double age_stuck = 0.0008;     // permanent flip probability per year
    double age_noise = 0.030;      // multiplicative read-noise growth per year
};

class PufChip {
public:
    PufChip(uint64_t seed, const PufSpec& spec = PufSpec()) : spec_(spec), rng_(seed) {
        const int n = spec_.cells;
        delta_.resize(n);
        tcoef_.resize(n);
        vcoef_.resize(n);
        for (int i = 0; i < n; ++i) {
            delta_[i] = spec_.mismatch_sigma * rng_.normal();
            tcoef_[i] = spec_.tcoef_sigma * rng_.normal();
            vcoef_[i] = spec_.vcoef_sigma * rng_.normal();
        }
    }

    int cells() const { return spec_.cells; }
    const PufSpec& spec() const { return spec_; }
    const std::vector<double>& ideal() const { return delta_; }

    double noise_sigma(double temp_c, double supply_v, double age) const {
        double dT = std::fabs(temp_c - 25.0);
        double dV = supply_v - 3.3;
        // read noise grows slowly with temperature; undervoltage hurts more than over
        double fT = 1.0 + 0.000045 * dT * dT;                  // 85C -> 1.27, -40C -> 1.30
        double fV = 1.0 + (dV < 0 ? 1.5 * (-dV) : 0.3 * dV);   // 2.6V -> 2.05, 3.8V -> 1.15
        double fA = 1.0 + spec_.age_noise * age;
        return spec_.sigma0 * fT * fV * fA;
    }

    // Read all cells. `out[i]` is the analog settle value.
    void read(double temp_c, double supply_v, double age, std::vector<double>& out) {
        apply_aging(age);
        const int n = spec_.cells;
        out.resize(n);
        double dT = temp_c - 25.0;
        double dV = supply_v - 3.3;
        // array-wide bias: hot/cold and undervoltage push the whole array slightly
        double common = 0.0009 * dT + 0.020 * dV
                      + 0.0015 * (dT > 0 ? dT : 0.0); // hot side slightly stronger
        double sigma = noise_sigma(temp_c, supply_v, age);
        double p_rts = spec_.rts_prob * (1.0 + 0.06 * std::fabs(dT) + 0.6 * (dV < 0 ? -dV : 0));
        for (int i = 0; i < n; ++i) {
            double v = delta_[i]
                     + tcoef_[i] * dT
                     + vcoef_[i] * dV
                     + common
                     + sigma * rng_.normal();
            if (rng_.uniform() < p_rts) v += spec_.rts_sigma * rng_.normal();
            out[i] = v;
        }
    }

    // Advance the physical aging state to `years` (monotone). Calling with the same
    // age twice is a no-op, so experiments can read repeatedly at one age.
    void apply_aging(double years) {
        if (years <= aged_to_ + 1e-12) return;
        double dt = years - aged_to_;
        for (int i = 0; i < spec_.cells; ++i) {
            delta_[i] *= (1.0 - spec_.age_shrink * dt);
            delta_[i] += spec_.age_drift * std::sqrt(dt) * rng_.normal();
            if (rng_.uniform() < spec_.age_stuck * dt) delta_[i] = -delta_[i];
            // clamp so the model stays physical (no runaway)
            if (delta_[i] > 4.0) delta_[i] = 4.0;
            if (delta_[i] < -4.0) delta_[i] = -4.0;
        }
        aged_to_ = years;
    }
    double aged_to() const { return aged_to_; }

    static std::vector<uint8_t> bits(const std::vector<double>& v) {
        std::vector<uint8_t> b(v.size());
        for (size_t i = 0; i < v.size(); ++i) b[i] = v[i] > 0 ? 1 : 0;
        return b;
    }

private:
    PufSpec spec_;
    Rng rng_;
    std::vector<double> delta_, tcoef_, vcoef_;
    double aged_to_ = 0.0;
};

// Average several reads at one condition -> (mean value per cell). This is what a
// real device does to suppress read noise and to obtain a soft reliability metric.
inline std::vector<double> average_reads(PufChip& chip, double t, double v, double age, int reads) {
    std::vector<double> acc, tmp;
    chip.read(t, v, age, acc);
    for (int r = 1; r < reads; ++r) {
        chip.read(t, v, age, tmp);
        for (size_t i = 0; i < acc.size(); ++i) acc[i] += tmp[i];
    }
    double inv = 1.0 / reads;
    for (double& x : acc) x *= inv;
    return acc;
}
