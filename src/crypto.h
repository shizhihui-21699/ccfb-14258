#pragma once
#include "common.h"
#include <cstring>

// ---- SHA-256 (FIPS 180-4) ----
struct Sha256 {
    uint32_t h[8];
    uint64_t len = 0;
    uint8_t buf[64];
    size_t buflen = 0;

    Sha256() { reset(); }
    void reset() {
        static const uint32_t IV[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                                       0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
        std::memcpy(h, IV, sizeof(h)); len = 0; buflen = 0;
    }
    static void compress(uint32_t st[8], const uint8_t blk[64]) {
        static const uint32_t K[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
        uint32_t w[64];
        for (int i = 0; i < 16; ++i)
            w[i] = (uint32_t(blk[i*4])<<24)|(uint32_t(blk[i*4+1])<<16)|(uint32_t(blk[i*4+2])<<8)|uint32_t(blk[i*4+3]);
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = rotr32(w[i-15],7) ^ rotr32(w[i-15],18) ^ (w[i-15] >> 3);
            uint32_t s1 = rotr32(w[i-2],17) ^ rotr32(w[i-2],19) ^ (w[i-2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        uint32_t a=st[0],b=st[1],c=st[2],d=st[3],e=st[4],f=st[5],g=st[6],hh=st[7];
        for (int i = 0; i < 64; ++i) {
            uint32_t S1 = rotr32(e,6) ^ rotr32(e,11) ^ rotr32(e,25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t t1 = hh + S1 + ch + K[i] + w[i];
            uint32_t S0 = rotr32(a,2) ^ rotr32(a,13) ^ rotr32(a,22);
            uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + mj;
            hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        st[0]+=a; st[1]+=b; st[2]+=c; st[3]+=d; st[4]+=e; st[5]+=f; st[6]+=g; st[7]+=hh;
    }
    void update(const uint8_t* p, size_t n) {
        len += n;
        while (n) {
            size_t take = 64 - buflen; if (take > n) take = n;
            std::memcpy(buf + buflen, p, take);
            buflen += take; p += take; n -= take;
            if (buflen == 64) { compress(h, buf); buflen = 0; }
        }
    }
    void update(const Bytes& b) { update(b.data(), b.size()); }
    void update(const std::string& s) { update(reinterpret_cast<const uint8_t*>(s.data()), s.size()); }
    Bytes final() {
        uint64_t bitlen = len * 8;
        uint8_t pad = 0x80;
        update(&pad, 1);
        uint8_t zero = 0;
        while (buflen != 56) update(&zero, 1);
        uint8_t lb[8];
        for (int i = 0; i < 8; ++i) lb[i] = uint8_t(bitlen >> (56 - 8*i));
        update(lb, 8);
        Bytes out(32);
        for (int i = 0; i < 8; ++i) {
            out[i*4] = uint8_t(h[i]>>24); out[i*4+1] = uint8_t(h[i]>>16);
            out[i*4+2] = uint8_t(h[i]>>8); out[i*4+3] = uint8_t(h[i]);
        }
        return out;
    }
};

inline Bytes sha256(const Bytes& data) { Sha256 s; s.update(data); return s.final(); }
inline Bytes sha256(const std::string& data) { Sha256 s; s.update(data); return s.final(); }

inline Bytes hmac_sha256(const Bytes& key, const Bytes& msg) {
    Bytes k = key.size() > 64 ? sha256(key) : key;
    k.resize(64, 0);
    Bytes ipad(64), opad(64);
    for (int i = 0; i < 64; ++i) { ipad[i] = k[i] ^ 0x36; opad[i] = k[i] ^ 0x5c; }
    Sha256 inner; inner.update(ipad); inner.update(msg); Bytes ih = inner.final();
    Sha256 outer; outer.update(opad); outer.update(ih); return outer.final();
}

// HKDF-SHA256 (RFC 5869)
inline Bytes hkdf_extract(const Bytes& salt, const Bytes& ikm) {
    return hmac_sha256(salt, ikm);
}
inline Bytes hkdf_expand(const Bytes& prk, const Bytes& info, size_t outlen) {
    Bytes out; Bytes t; uint8_t ctr = 1;
    while (out.size() < outlen) {
        Bytes m = t; m.insert(m.end(), info.begin(), info.end()); m.push_back(ctr++);
        t = hmac_sha256(prk, m);
        out.insert(out.end(), t.begin(), t.end());
    }
    out.resize(outlen);
    return out;
}
inline Bytes hkdf(const Bytes& ikm, const Bytes& salt, const Bytes& info, size_t outlen) {
    return hkdf_expand(hkdf_extract(salt, ikm), info, outlen);
}

// constant-time compare
inline bool ct_equal(const Bytes& a, const Bytes& b) {
    if (a.size() != b.size()) return false;
    uint8_t d = 0;
    for (size_t i = 0; i < a.size(); ++i) d |= a[i] ^ b[i];
    return d == 0;
}
inline void secure_wipe(Bytes& b) { volatile uint8_t* p = b.data(); for (size_t i = 0; i < b.size(); ++i) p[i] = 0; }

// ---- ChaCha20 (RFC 8439) ----
inline uint32_t load32_le(const uint8_t* p) {
    return uint32_t(p[0]) | (uint32_t(p[1])<<8) | (uint32_t(p[2])<<16) | (uint32_t(p[3])<<24);
}
inline void store32_le(uint8_t* p, uint32_t v) {
    p[0]=uint8_t(v); p[1]=uint8_t(v>>8); p[2]=uint8_t(v>>16); p[3]=uint8_t(v>>24);
}
inline void chacha_qr(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
    a += b; d ^= a; d = rotl32(d,16);
    c += d; b ^= c; b = rotl32(b,12);
    a += b; d ^= a; d = rotl32(d,8);
    c += d; b ^= c; b = rotl32(b,7);
}
inline void chacha_block(const uint32_t in[16], uint8_t out[64]) {
    uint32_t x[16]; std::memcpy(x, in, sizeof(x));
    for (int i = 0; i < 10; ++i) {
        chacha_qr(x[0],x[4],x[8],x[12]); chacha_qr(x[1],x[5],x[9],x[13]);
        chacha_qr(x[2],x[6],x[10],x[14]); chacha_qr(x[3],x[7],x[11],x[15]);
        chacha_qr(x[0],x[5],x[10],x[15]); chacha_qr(x[1],x[6],x[11],x[12]);
        chacha_qr(x[2],x[7],x[8],x[13]); chacha_qr(x[3],x[4],x[9],x[14]);
    }
    for (int i = 0; i < 16; ++i) store32_le(out + i*4, x[i] + in[i]);
}
inline void chacha20_init(uint32_t st[16], const uint8_t key[32], const uint8_t nonce[12], uint32_t ctr) {
    st[0]=0x61707865; st[1]=0x3320646e; st[2]=0x79622d32; st[3]=0x6b206574;
    for (int i = 0; i < 8; ++i) st[4+i] = load32_le(key + i*4);
    st[12] = ctr;
    for (int i = 0; i < 3; ++i) st[13+i] = load32_le(nonce + i*4);
}
inline Bytes chacha20(const Bytes& key32, const Bytes& nonce12, const Bytes& data, uint32_t ctr = 1) {
    if (key32.size() != 32) throw std::runtime_error("chacha key must be 32 bytes");
    if (nonce12.size() != 12) throw std::runtime_error("chacha nonce must be 12 bytes");
    uint32_t st[16]; chacha20_init(st, key32.data(), nonce12.data(), ctr);
    Bytes out(data.size());
    uint8_t blk[64];
    for (size_t off = 0; off < data.size(); off += 64) {
        chacha_block(st, blk);
        st[12]++;
        size_t n = std::min<size_t>(64, data.size() - off);
        for (size_t i = 0; i < n; ++i) out[off+i] = data[off+i] ^ blk[i];
    }
    return out;
}

// AEAD: encrypt-then-MAC (ChaCha20 + HMAC-SHA256 over nonce||aad||ct)
struct AeadBlob { Bytes nonce; Bytes ct; Bytes tag; };

inline AeadBlob aead_seal(const Bytes& key, const Bytes& aad, const Bytes& plaintext, const Bytes& nonce12) {
    if (key.size() != 32) throw std::runtime_error("aead key must be 32 bytes");
    if (nonce12.size() != 12) throw std::runtime_error("aead nonce must be 12 bytes");
    Bytes ek = hkdf(key, Bytes(0), to_bytes("aead-enc"), 32);
    Bytes mk = hkdf(key, Bytes(0), to_bytes("aead-mac"), 32);
    AeadBlob out;
    out.nonce = nonce12;
    out.ct = chacha20(ek, nonce12, plaintext, 1);
    Bytes macin; macin.reserve(12 + aad.size() + out.ct.size() + 8);
    macin.insert(macin.end(), nonce12.begin(), nonce12.end());
    uint8_t al[8];
    for (int i = 0; i < 8; ++i) al[i] = uint8_t(uint64_t(aad.size()) >> (56 - 8*i));
    macin.insert(macin.end(), al, al + 8);
    macin.insert(macin.end(), aad.begin(), aad.end());
    macin.insert(macin.end(), out.ct.begin(), out.ct.end());
    Bytes full = hmac_sha256(mk, macin);
    out.tag.assign(full.begin(), full.begin() + 16);
    secure_wipe(ek); secure_wipe(mk);
    return out;
}

inline bool aead_open(const Bytes& key, const Bytes& aad, const Bytes& nonce12, const Bytes& ct,
                      const Bytes& tag, Bytes& plaintext_out) {
    if (key.size() != 32 || nonce12.size() != 12 || tag.size() != 16) return false;
    Bytes ek = hkdf(key, Bytes(0), to_bytes("aead-enc"), 32);
    Bytes mk = hkdf(key, Bytes(0), to_bytes("aead-mac"), 32);
    Bytes macin; macin.reserve(12 + aad.size() + ct.size() + 8);
    macin.insert(macin.end(), nonce12.begin(), nonce12.end());
    uint8_t al[8];
    for (int i = 0; i < 8; ++i) al[i] = uint8_t(uint64_t(aad.size()) >> (56 - 8*i));
    macin.insert(macin.end(), al, al + 8);
    macin.insert(macin.end(), aad.begin(), aad.end());
    macin.insert(macin.end(), ct.begin(), ct.end());
    Bytes full = hmac_sha256(mk, macin);
    Bytes expect(full.begin(), full.begin() + 16);
    bool ok = ct_equal(expect, tag);
    if (ok) plaintext_out = chacha20(ek, nonce12, ct, 1);
    secure_wipe(ek); secure_wipe(mk);
    return ok;
}
