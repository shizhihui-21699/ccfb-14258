#include "../src/device.h"
#include <cstdio>

// End-to-end walkthrough of the device-binding scheme. Run with: ./build/demo
int main() {
    std::printf("=== Device-bound credential storage demo ===\n\n");

    const Bytes credential = to_bytes("DOOR-HMAC-KEY:9f2c1e7b4a (never leaves sealed flash)");
    Rng trng(0xC0FFEE);

    // 1. Factory provisioning on a genuine board.
    Device genuine(/*device_id=*/7, /*silicon seed=*/777);
    FlashImage flash = genuine.provision(credential, trng);
    const FuzzyExtractor& fe = genuine.fe();
    std::printf("Provisioned device 7:\n");
    std::printf("  BCH(%d,%d,%d), %d blocks, %d stable cells used, %d-bit secret\n",
                255, fe.bch_k(), fe.bch_t(), flash.helper.blocks,
                flash.helper.cells_used, flash.helper.blocks * fe.bch_k());

    // 2. Normal unlocks over the operating envelope.
    std::printf("\nGenuine board unlocks:\n");
    for (double T : {-20.0, 25.0, 70.0, 85.0, 105.0}) {
        FlashImage local = flash;
        auto r = genuine.unlock(local, T, 3.3, 0);
        std::printf("  %6.0f C -> %-11s credential %s\n", T, to_string(r.status),
                    r.credential == credential ? "recovered" : "-");
    }

    // 3. The attack: copy the whole flash image onto a different board.
    std::printf("\nAttack: flash copied to a different chip:\n");
    Device clone(7, 888);
    FlashImage copied = flash;
    auto r = clone.unlock(copied, 25, 3.3, 0);
    std::printf("  clone -> %-11s credential %s\n", to_string(r.status),
                r.credential.empty() ? "NOT recovered" : "RECOVERED (!!)");

    // 4. The attack: tamper with the helper data to probe the decoder.
    std::printf("\nAttack: helper-data tampering (ratchet mode):\n");
    FlashImage tampered = flash;
    int locked_at = -1;
    for (int i = 0; i < 100; ++i) {
        Device::tamper_helper_bit(tampered, size_t(i) * 31 + 7);
        auto rr = genuine.unlock(tampered, 25, 3.3, 0);
        if (rr.status == UnlockStatus::LockedOut) { locked_at = i + 1; break; }
    }
    std::printf("  locked out after %d tampering attempts\n", locked_at);

    std::printf("\nDone.\n");
    return 0;
}
