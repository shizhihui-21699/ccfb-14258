# Device-Bound Credential Storage via SRAM PUF

A C++20 reference implementation of device binding for an access-control board:
credentials are encrypted under a key derived from each chip's manufacturing
fingerprint (a power-up SRAM PUF). Copying the flash image onto another board
yields a key that does not decrypt.

The hard parts handled here:

- **Noisy fingerprints** — read-to-read bit flips, amplified by temperature and
  supply variation. Solved with a BCH-based code-offset fuzzy extractor plus a
  *factory-calibrated stable-cell subset* (the key idea).
- **Aging drift** — the mismatch fingerprint shrinks and drifts over the device
  lifetime. The stable-subset design leaves enough error-correction budget to
  absorb it; the reliability margin is quantified per design point.
- **Tamperable helper data** — the error-correction helper stored in flash can be
  read and modified by an attacker. Acceptance is gated by a 128-bit MAC, so a
  tampered helper only ever produces rejections, and a ratchet failure counter
  bounds online probing.

See **[`report/REPORT.md`](report/REPORT.md)** for the full analysis (Chinese),
and **[`report/tables.md`](report/tables.md)** for the generated result tables.

## Quick start

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
./build/demo
```

`demo` walks through provisioning, genuine unlocks across temperature, a clone
attack, and helper tampering.

## Reproduce the experiments

```bash
./build/experiments all > results/experiments.log
python3 -I tools/make_report.py         # regenerates report/tables.md
```

Sub-commands: `temps`, `aging`, `attacks`, `sweep`, `bounds`, `baseline`,
`envelope`, `extremes`.

## Layout

| Path | Contents |
|---|---|
| `src/crypto.h` | SHA-256, HMAC-SHA256, HKDF, ChaCha20, AEAD (RFC-vector tested) |
| `src/gf256.h`, `src/bch.h`, `src/rs.h` | GF(2^8), BCH(255,k,t), Reed-Solomon with combined error+erasure decoding |
| `src/puf.h` | Simulated SRAM PUF: mismatch, temperature/supply sensitivity, aging, noise |
| `src/fuzzy_extractor.h` | Code-offset fuzzy extractor + stable-cell selection |
| `src/device.h` | Credential vault, unlock policy (verbose/constant/ratchet) |
| `tools/` | Demo, experiment driver, report generator |
| `tests/` | Crypto, BCH/RS, fuzzy-extractor/device tests |

## Honest scope

All PUF physics is **simulated** (`src/puf.h`); no real silicon was measured.
Parameters are chosen to match published SRAM-PUF magnitudes, but they do not
represent any specific process. The results validate the algorithm and its
robustness trends; real deployment requires characterization on the target
process. Full limitations are listed in section 7 of `report/REPORT.md`.
