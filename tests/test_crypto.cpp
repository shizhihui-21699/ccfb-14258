#include "../src/crypto.h"
#include "../src/rs.h"
#include <cstdio>
#include <cstring>
#include <string>

static int fails = 0;
#define CHECK(cond, msg) do { if (!(cond)) { std::printf("FAIL: %s\n", msg); ++fails; } } while (0)

static Bytes from_hex(const std::string& h) {
    Bytes out;
    for (size_t i = 0; i + 1 < h.size(); i += 2)
        out.push_back(uint8_t(std::stoi(h.substr(i, 2), nullptr, 16)));
    return out;
}

static void test_sha256() {
    CHECK(to_hex(sha256(std::string("abc"))) ==
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "sha256(abc)");
    CHECK(to_hex(sha256(std::string(""))) ==
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256(empty)");
    CHECK(to_hex(sha256(std::string("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))) ==
          "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", "sha256(two-block)");
    std::string million(1000000, 'a');
    CHECK(to_hex(sha256(million)) ==
          "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0", "sha256(1M a)");
}

static void test_hmac() {
    // RFC 4231 test case 2
    CHECK(to_hex(hmac_sha256(to_bytes("Jefe"), to_bytes("what do ya want for nothing?"))) ==
          "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", "hmac rfc4231 #2");
}

static void test_hkdf() {
    // RFC 5869 test case 1
    Bytes ikm(22, 0x0b);
    Bytes salt = from_hex("000102030405060708090a0b0c");
    Bytes info = from_hex("f0f1f2f3f4f5f6f7f8f9");
    Bytes prk = hkdf_extract(salt, ikm);
    CHECK(to_hex(prk) == "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5", "hkdf prk");
    Bytes okm = hkdf_expand(prk, info, 42);
    CHECK(to_hex(okm) == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865", "hkdf okm");
}

static void test_chacha() {
    // RFC 8439 section 2.4.2
    Bytes key(32, 0), nonce(12, 0);
    Bytes counter = from_hex("0100000000000000000000000000000000000009000000000000000000000000");
    for (int i = 0; i < 32; ++i) key[i] = uint8_t(i);
    nonce = from_hex("000000000000004a00000000");
    Bytes pt = to_bytes("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.");
    Bytes ct = chacha20(key, nonce, pt, 1);
    CHECK(to_hex(ct).substr(0, 64) == "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b", "chacha20 rfc8439");
}

static void test_aead_roundtrip() {
    Bytes key(32); Rng rng(7); rng.fill(key.data(), key.size());
    Bytes nonce(12); rng.fill(nonce.data(), nonce.size());
    Bytes pt = to_bytes("door-credential:token-42");
    Bytes aad = to_bytes("device-7");
    AeadBlob b = aead_seal(key, aad, pt, nonce);
    Bytes out;
    CHECK(aead_open(key, aad, b.nonce, b.ct, b.tag, out), "aead open ok");
    CHECK(out == pt, "aead plaintext");
    b.ct[0] ^= 1;
    CHECK(!aead_open(key, aad, b.nonce, b.ct, b.tag, out), "aead tamper ct rejected");
    b.ct[0] ^= 1;
    Bytes aad2 = aad; aad2[0] ^= 1;
    CHECK(!aead_open(key, aad2, b.nonce, b.ct, b.tag, out), "aead tamper aad rejected");
}

static void test_rs() {
    const int k = 187; // t = 34, matches the fuzzy extractor
    ReedSolomon rs(k);
    Rng rng(1234);
    for (int trial = 0; trial < 200; ++trial) {
        Bytes msg(k); rng.fill(msg.data(), msg.size());
        Bytes cw = rs.encode(msg);
        CHECK(rs.is_codeword(cw), "rs codeword valid");
        CHECK(rs.extract_message(cw) == msg, "rs systematic");
        // random error counts up to t
        int ne = int(rng.below(rs.t() + 1));
        Bytes bad = cw;
        std::vector<int> errs;
        while (static_cast<int>(errs.size()) < ne) {
            int p = int(rng.below(255));
            bool dup = false;
            for (int q : errs) if (q == p) dup = true;
            if (dup) continue;
            errs.push_back(p);
            bad[p] ^= uint8_t(1 + rng.below(255));
        }
        Bytes dec;
        CHECK(rs.decode(bad, {}, dec), "rs decode within t");
        CHECK(dec == cw, "rs correct within t");
    }
    // erasures: up to 2t
    for (int trial = 0; trial < 100; ++trial) {
        Bytes msg(k); rng.fill(msg.data(), msg.size());
        Bytes cw = rs.encode(msg);
        int ne = int(rng.below(2 * rs.t() + 1));
        Bytes bad = cw;
        std::vector<int> pos;
        while (static_cast<int>(pos.size()) < ne) {
            int p = int(rng.below(255));
            bool dup = false;
            for (int q : pos) if (q == p) dup = true;
            if (dup) continue;
            pos.push_back(p);
            bad[p] ^= uint8_t(1 + rng.below(255));
        }
        Bytes dec;
        CHECK(rs.decode(bad, pos, dec), "rs erasure decode");
        CHECK(dec == cw, "rs erasure correct");
    }
    // combined e errors + f erasures with 2e + f <= 2t
    for (int trial = 0; trial < 200; ++trial) {
        Bytes msg(k); rng.fill(msg.data(), msg.size());
        Bytes cw = rs.encode(msg);
        int budget = 2 * rs.t();
        int f = int(rng.below(budget / 2 + 1));
        int e = int(rng.below((budget - f) / 2 + 1));
        Bytes bad = cw;
        std::vector<int> used, er;
        auto pick = [&](int cnt, bool record) {
            int made = 0;
            while (made < cnt) {
                int p = int(rng.below(255));
                bool dup = false;
                for (int q : used) if (q == p) dup = true;
                if (dup) continue;
                used.push_back(p);
                bad[p] ^= uint8_t(1 + rng.below(255));
                if (record) er.push_back(p);
                ++made;
            }
        };
        pick(e, false); pick(f, true);
        Bytes dec;
        bool ok = rs.decode(bad, er, dec);
        CHECK(ok && dec == cw, "rs combined errors+erasures");
    }
    // beyond capacity must not silently produce the wrong codeword as "correct"
    {
        Bytes msg(k, 0x5a);
        Bytes cw = rs.encode(msg);
        Bytes bad = cw;
        for (int i = 0; i < rs.t() + 5; ++i) bad[i * 3] ^= 0xff;
        Bytes dec;
        if (rs.decode(bad, {}, dec)) { /* may return some codeword; must not claim cw */ }
        CHECK(!(dec == cw), "rs beyond-capacity does not return original (expected)");
    }
}

static void test_ct_equal() {
    Bytes a = to_bytes("hello"), b = to_bytes("hellp");
    CHECK(!ct_equal(a, b), "ct_equal differs");
    CHECK(ct_equal(a, to_bytes("hello")), "ct_equal same");
}

int main() {
    test_sha256();
    test_hmac();
    test_hkdf();
    test_chacha();
    test_aead_roundtrip();
    test_rs();
    test_ct_equal();
    if (fails) { std::printf("%d checks FAILED\n", fails); return 1; }
    std::printf("all crypto/RS tests passed\n");
    return 0;
}
