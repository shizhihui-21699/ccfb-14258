#pragma once
#include "common.h"
#include "gf256.h"
#include <algorithm>

// Systematic Reed-Solomon over GF(256), narrow-sense: n = 255, roots alpha^1..alpha^(2t).
// Codeword coefficients are stored LSB-first: c[i] is the coefficient of x^i.
// The k message symbols occupy c[2t .. 254]; the 2t parity symbols occupy c[0 .. 2t-1].
// Supports combined errors + erasures (Forney syndromes + Berlekamp-Massey + Chien + Forney
// magnitudes solved as a linear system).
class ReedSolomon {
public:
    explicit ReedSolomon(int k) : k_(k), t_((255 - k) / 2), n_(255) {
        if (k < 1 || k > 255 || (255 - k) % 2 != 0)
            throw std::runtime_error("invalid RS(255,k)");
        const GF256& G = gf();
        std::vector<uint8_t> g(1, 1); // ascending coefficients of g(x)
        for (int j = 1; j <= 2 * t_; ++j) {
            uint8_t root = G.exp[j];
            std::vector<uint8_t> ng(g.size() + 1, 0);
            for (size_t i = 0; i < g.size(); ++i) {
                ng[i + 1] ^= g[i];
                ng[i] ^= G.mul(g[i], root);
            }
            g.swap(ng);
        }
        gen_ = g;
    }

    int k() const { return k_; }
    int t() const { return t_; }
    int n() const { return n_; }
    int parity() const { return 2 * t_; }

    Bytes encode(const Bytes& msg) const {
        if (static_cast<int>(msg.size()) != k_) throw std::runtime_error("RS encode: bad msg length");
        const GF256& G = gf();
        // LFSR synthetic division of msg(x)*x^{2t} by monic g(x)
        std::vector<uint8_t> sr(2 * t_, 0);
        for (int i = k_ - 1; i >= 0; --i) {
            uint8_t fb = static_cast<uint8_t>(msg[i] ^ sr[2 * t_ - 1]);
            for (int j = 2 * t_ - 1; j >= 1; --j)
                sr[j] = static_cast<uint8_t>(sr[j - 1] ^ G.mul(fb, gen_[j]));
            sr[0] = G.mul(fb, gen_[0]);
        }
        Bytes c(n_, 0);
        for (int i = 0; i < 2 * t_; ++i) c[i] = sr[i];
        for (int i = 0; i < k_; ++i) c[2 * t_ + i] = msg[i];
        return c;
    }

    Bytes extract_message(const Bytes& cw) const {
        if (static_cast<int>(cw.size()) != n_) throw std::runtime_error("RS: bad cw length");
        return Bytes(cw.begin() + 2 * t_, cw.end());
    }

    std::vector<uint8_t> syndromes(const Bytes& cw) const {
        const GF256& G = gf();
        std::vector<uint8_t> S(2 * t_ + 1, 0);
        for (int j = 1; j <= 2 * t_; ++j) {
            uint8_t acc = 0, xp = 1, a = G.exp[j % 255];
            for (int i = 0; i < n_; ++i) { acc ^= G.mul(cw[i], xp); xp = G.mul(xp, a); }
            S[j] = acc;
        }
        return S;
    }

    bool is_codeword(const Bytes& cw) const {
        const GF256& G = gf();
        for (int j = 1; j <= 2 * t_; ++j) {
            uint8_t acc = 0, xp = 1, a = G.exp[j % 255];
            for (int i = 0; i < n_; ++i) { acc ^= G.mul(cw[i], xp); xp = G.mul(xp, a); }
            if (acc) return false;
        }
        return true;
    }

    // erasure_pos: byte indices in [0,255). On success fills out with the corrected codeword.
    // A returned codeword is guaranteed to be *a* codeword, not necessarily the original one
    // (that residual risk is what the fuzzy-extractor's tag check catches).
    bool decode(const Bytes& in, const std::vector<int>& erasure_pos, Bytes& out) const {
        if (static_cast<int>(in.size()) != n_) return false;
        const GF256& G = gf();
        std::vector<uint8_t> S = syndromes(in);
        bool clean = true;
        for (int j = 1; j <= 2 * t_; ++j) if (S[j]) { clean = false; break; }
        if (clean) { out = in; return true; }

        std::vector<int> pos = erasure_pos;
        std::sort(pos.begin(), pos.end());
        pos.erase(std::unique(pos.begin(), pos.end()), pos.end());
        for (int p : pos) if (p < 0 || p >= n_) return false;
        int E = static_cast<int>(pos.size());
        if (E > 2 * t_) return false;

        // erasure locator Lambda_e(x) = prod (1 - X x), X = alpha^p, ascending coeffs
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
        // Forney syndromes T_j = sum_{i=0..E} Le[i]*S_{j+E-i}
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
        // Berlekamp-Massey over T_1..T_N (ascending convention, n = 1..N)
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
            if (2 * L <= n - 1) {
                L = n - L;
                B = Tmp;
                b = d;
                m = 1;
            } else {
                ++m;
            }
        }
        if (2 * L + E > 2 * t_) return false;
        // full locator = Lam * Le
        std::vector<uint8_t> Ltot(Lam.size() + Le.size() - 1, 0);
        for (size_t i = 0; i < Lam.size(); ++i)
            for (size_t j2 = 0; j2 < Le.size(); ++j2)
                Ltot[i + j2] ^= G.mul(Lam[i], Le[j2]);
        while (Ltot.size() > 1 && Ltot.back() == 0) Ltot.pop_back();
        int deg = static_cast<int>(Ltot.size()) - 1;
        // Chien search: root at x = alpha^{-p}
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
        // solve magnitudes from S_1..S_M:  sum_k e_k X_k^r = S_r
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
        Bytes cw = in;
        for (int k2 = 0; k2 < M; ++k2) cw[found[k2]] ^= A[k2][M];
        if (!is_codeword(cw)) return false;
        out = cw;
        return true;
    }

private:
    int k_, t_, n_;
    std::vector<uint8_t> gen_;
};
