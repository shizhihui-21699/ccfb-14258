#pragma once
#include "common.h"
#include "gf256.h"
#include <array>
#include <algorithm>

// Binary BCH code over GF(2^8): length n = 255, designed distance 2t+1.
// A codeword is 255 bits; we represent it as std::array<uint8_t,255> of 0/1 values,
// index i = coefficient of x^i (LSB-first). Systematic form: the k = 255 - deg(g)
// message bits sit in the *high* positions c[deg(g) .. 254].
//
// Erasures are per bit, which is exactly what a PUF's per-cell soft information gives.
class Bch {
public:
    explicit Bch(int t) : t_(t), n_(255) {
        if (t < 1 || t > 60) throw std::runtime_error("BCH t out of range");
        const GF256& G = gf();
        // generator = product of distinct minimal polynomials m_i(x), i odd in [1, 2t]
        std::vector<int> used;
        gen_.assign(1, 1); // ascending coefficients, GF(2) values
        for (int i = 1; i <= 2 * t_; i += 2) {
            bool seen = false;
            for (int u : used) if (u == i) seen = true;
            if (seen) continue;
            std::vector<int> conj;
            int e = i;
            for (int j = 0; j < 8; ++j) {
                conj.push_back(e);
                e = (e * 2) % 255;
            }
            std::sort(conj.begin(), conj.end());
            conj.erase(std::unique(conj.begin(), conj.end()), conj.end());
            // minimal polynomial = prod (x + alpha^c) over conjugates; multiply over GF(256)
            std::vector<uint8_t> mp(1, 1);
            for (int c : conj) {
                uint8_t root = G.exp[c % 255];
                std::vector<uint8_t> nm(mp.size() + 1, 0);
                for (size_t q = 0; q < mp.size(); ++q) {
                    nm[q + 1] ^= mp[q];
                    nm[q] ^= G.mul(mp[q], root);
                }
                mp.swap(nm);
            }
            // coefficients must be 0/1
            for (uint8_t v : mp) if (v > 1) throw std::runtime_error("BCH: non-binary minimal polynomial");
            // gen *= mp over GF(2)
            std::vector<int> ng(gen_.size() + mp.size() - 1, 0);
            for (size_t a = 0; a < gen_.size(); ++a)
                for (size_t b = 0; b < mp.size(); ++b)
                    ng[a + b] ^= (gen_[a] & mp[b]) & 1;
            gen_.assign(ng.begin(), ng.end());
            used.insert(used.end(), conj.begin(), conj.end());
        }
        // strip leading zeros
        while (gen_.size() > 1 && gen_.back() == 0) gen_.pop_back();
        deg_ = static_cast<int>(gen_.size()) - 1;
        k_ = n_ - deg_;
        if (k_ < 24) throw std::runtime_error("BCH: message too short for this t");
    }

    int t() const { return t_; }
    int n() const { return n_; }
    int k() const { return k_; }
    int parity() const { return deg_; }
    const std::vector<int>& gen() const { return gen_; }

    // message: k bits (values 0/1), index 0 = highest message coefficient? We accept
    // `msg` as k bits LSB-first of the message polynomial m(x) (deg < k).
    std::array<uint8_t, 255> encode(const std::vector<uint8_t>& msg) const {
        if (static_cast<int>(msg.size()) != k_) throw std::runtime_error("BCH encode: bad msg len");
        std::array<uint8_t, 255> c{};
        // c(x) = m(x) * x^deg + (m(x)*x^deg mod g(x)); place message in high positions.
        for (int i = 0; i < k_; ++i) c[deg_ + i] = msg[i] & 1;
        // remainder via LFSR
        std::vector<uint8_t> sr(deg_, 0);
        for (int i = k_ - 1; i >= 0; --i) {
            uint8_t fb = static_cast<uint8_t>((msg[i] & 1) ^ sr[deg_ - 1]);
            for (int j = deg_ - 1; j >= 1; --j)
                sr[j] = static_cast<uint8_t>(sr[j - 1] ^ (fb & gen_[j]));
            sr[0] = static_cast<uint8_t>(fb & gen_[0]);
        }
        for (int i = 0; i < deg_; ++i) c[i] = sr[i];
        return c;
    }

    std::vector<uint8_t> extract_message(const std::array<uint8_t, 255>& c) const {
        std::vector<uint8_t> m(k_);
        for (int i = 0; i < k_; ++i) m[i] = c[deg_ + i];
        return m;
    }

    bool is_codeword(const std::array<uint8_t, 255>& c) const {
        const GF256& G = gf();
        for (int j = 1; j <= 2 * t_; ++j) {
            uint8_t acc = 0, xp = 1, a = G.exp[j % 255];
            for (int i = 0; i < n_; ++i) {
                if (c[i]) acc ^= xp;
                xp = G.mul(xp, a);
            }
            if (acc) return false;
        }
        return true;
    }

    // Decode with up to t errors, or (errors,erasures) with 2e+f <= 2t.
    bool decode(const std::array<uint8_t, 255>& in, const std::vector<int>& erasures,
                std::array<uint8_t, 255>& out) const {
        // fast path: an already-valid codeword needs no correction
        std::vector<uint8_t> S(2 * t_ + 1, 0);
        if (syndromes(in, S)) { out = in; return true; } // all syndromes zero
        // build erasure locator
        std::vector<int> pos = erasures;
        std::sort(pos.begin(), pos.end());
        pos.erase(std::unique(pos.begin(), pos.end()), pos.end());
        for (int p : pos) if (p < 0 || p >= n_) return false;
        int E = static_cast<int>(pos.size());
        if (E > 2 * t_) return false;
        const GF256& G = gf();
        std::vector<uint8_t> Le(1, 1);
        for (int p : pos) {
            uint8_t X = G.exp[p % 255];
            std::vector<uint8_t> nle(Le.size() + 1, 0);
            for (size_t i = 0; i < Le.size(); ++i) {
                nle[i] ^= Le[i];
                nle[i + 1] ^= G.mul(Le[i], X);
            }
            Le.swap(nle);
        }
        int N = 2 * t_ - E;
        std::vector<uint8_t> T(N + 1, 0);
        for (int j = 1; j <= N; ++j) {
            uint8_t acc = 0;
            for (int i = 0; i <= E; ++i) {
                int idx = j + E - i;
                if (idx >= 1 && idx <= 2 * t_) acc ^= G.mul(Le[i], S[idx]);
            }
            T[j] = acc;
        }
        // Berlekamp-Massey
        std::vector<uint8_t> Lam(1, 1), B(1, 1);
        int L = 0, m = 1;
        uint8_t b = 1;
        for (int n = 1; n <= N; ++n) {
            uint8_t d = T[n];
            for (int i = 1; i <= L && i < static_cast<int>(Lam.size()); ++i)
                if (n - i >= 1) d ^= G.mul(Lam[i], T[n - i]);
            if (d == 0) { ++m; continue; }
            uint8_t coef = G.div(d, b);
            std::vector<uint8_t> Tmp = Lam;
            if (Lam.size() < B.size() + m) Lam.resize(B.size() + m, 0);
            for (size_t i = 0; i < B.size(); ++i) Lam[i + m] ^= G.mul(coef, B[i]);
            if (2 * L <= n - 1) { L = n - L; B = Tmp; b = d; m = 1; }
            else ++m;
        }
        if (2 * L + E > 2 * t_) return false;
        std::vector<uint8_t> Ltot(Lam.size() + Le.size() - 1, 0);
        for (size_t i = 0; i < Lam.size(); ++i)
            for (size_t j = 0; j < Le.size(); ++j)
                Ltot[i + j] ^= G.mul(Lam[i], Le[j]);
        while (Ltot.size() > 1 && Ltot.back() == 0) Ltot.pop_back();
        int deg = static_cast<int>(Ltot.size()) - 1;
        std::vector<int> found;
        for (int p = 0; p < n_; ++p) {
            uint8_t xinv = (p == 0) ? 1 : G.exp[(255 - (p % 255)) % 255];
            uint8_t xp = 1, acc = 0;
            for (size_t i = 0; i < Ltot.size(); ++i) { acc ^= G.mul(Ltot[i], xp); xp = G.mul(xp, xinv); }
            if (acc == 0) found.push_back(p);
        }
        if (static_cast<int>(found.size()) != deg) return false;
        int M = static_cast<int>(found.size());
        if (M == 0) return false;
        // Solve the error magnitudes from S_1..S_M. A root contributed by an erasure
        // locator may be a position that did NOT actually flip; its solved magnitude
        // is then 0, so we must not blindly flip every root.
        std::vector<std::vector<uint8_t>> A(M, std::vector<uint8_t>(M + 1, 0));
        for (int r = 0; r < M; ++r) {
            for (int c2 = 0; c2 < M; ++c2) {
                uint8_t X = G.exp[found[c2] % 255];
                A[r][c2] = G.pow(X, r + 1);
            }
            A[r][M] = S[r + 1];
        }
        for (int col = 0; col < M; ++col) {
            int piv = -1;
            for (int r = col; r < M; ++r) if (A[r][col]) { piv = r; break; }
            if (piv < 0) return false;
            std::swap(A[piv], A[col]);
            uint8_t invp = G.inv(A[col][col]);
            for (int c2 = col; c2 <= M; ++c2) A[col][c2] = G.mul(A[col][c2], invp);
            for (int r = 0; r < M; ++r) {
                if (r == col || !A[r][col]) continue;
                uint8_t f = A[r][col];
                for (int c2 = col; c2 <= M; ++c2) A[r][c2] ^= G.mul(f, A[col][c2]);
            }
        }
        out = in;
        for (int k2 = 0; k2 < M; ++k2) {
            uint8_t mag = A[k2][M];
            if (mag == 0) continue;
            if (mag != 1) return false; // binary code: error magnitude must be 1
            out[found[k2]] ^= 1;
        }
        return is_codeword(out);
    }

private:
    // returns true if all syndromes are zero
    bool syndromes(const std::array<uint8_t, 255>& c, std::vector<uint8_t>& S) const {
        const GF256& G = gf();
        bool zero = true;
        for (int j = 1; j <= 2 * t_; ++j) {
            uint8_t acc = 0, xp = 1, a = G.exp[j % 255];
            for (int i = 0; i < n_; ++i) {
                if (c[i]) acc ^= xp;
                xp = G.mul(xp, a);
            }
            S[j] = acc;
            if (acc) zero = false;
        }
        return zero;
    }

    int t_, n_, k_, deg_;
    std::vector<int> gen_;
};
