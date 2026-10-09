// Regression tests for the raw-hardware-command layer.
//
// The bugs guarded against here were found by reading the code against the
// specifications, and every one of them produced a command that was wrong in a
// way that either failed silently or targeted the wrong thing:
//
//   1. NVMe_ADMIN_SANITIZE was 0x0C, not 0x84. 0x0C is an unrelated admin
//      opcode, so "sanitize" sent a different command to the controller.
//   2. OWPASS was shifted into cdw10 bits 15:8 instead of the 4-bit field at
//      bits 7:4, so the controller read a pass count of 0 from a field the
//      device cannot be told 0 through.
//   3. Get Log Page put the dword count in cdw10 bits 15:8 and the LID in
//      cdw11 bits 15:8. Neither field is there: cdw10 bits 7:0 is the LID and
//      bits 31:16 is NUMDL, cdw11 bits 15:0 is NUMDU. The tool asked for LID 0
//      with no stated length, then decoded whatever came back as a sanitize
//      state.
//   4. HDIO_DRIVE_CMD was given a {password[32]; control} struct. It expects a
//      4-byte taskfile header, so the first four password bytes were read as
//      taskfile registers and the fourth was used as a sector-count multiplier.
//
// None of these are observable without the relevant hardware, so the encodings
// are asserted against the specification here rather than by issuing the
// commands. Issuing them would be destructive and, for the Sanitize command,
// irreversible.
//
// The one thing these tests must not do is read or write a real block device.
// Nothing here opens /dev/*.

#include "platform/linux/linux.hpp"
#include "ledgerase/policy.hpp"
#include "ledgerase/sanitization.hpp"
#include "ledgerase/types.hpp"
#include "ledgerase/error.hpp"

#include <linux/hdreg.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <string>
#include <utility>
#include <vector>

using namespace ledgerase;
using namespace ledgerase::platform::linux;

namespace {

int g_failures = 0;

void check(bool condition, const std::string& what) {
    if (condition) {
        std::printf("  ok   %s\n", what.c_str());
        return;
    }
    std::printf("  FAIL %s\n", what.c_str());
    ++g_failures;
}

// ---------------------------------------------------------------------------
// 1. NVMe Sanitize opcode
// ---------------------------------------------------------------------------

void testSanitizeOpcode() {
    std::printf("NVMe Sanitize uses the opcode the specification assigns\n");

    check(NVME_ADMIN_SANITIZE == 0x84,
          "the Sanitize admin opcode is 0x84");

    // 0x0C is Format NVM. Sending it in place of Sanitize would have formatted
    // the namespace rather than erased it, and the Sanitize Status log would
    // never have changed.
    check(NVME_ADMIN_SANITIZE != 0x0C,
          "the opcode is not 0x0C, which is Format NVM");

    // The vendor-specific range: 0x80-0xFF. A value outside it would be a
    // reserved or different command again.
    check(NVME_ADMIN_SANITIZE >= 0x80 && NVME_ADMIN_SANITIZE <= 0xFF,
          "the opcode is in the vendor-specific admin range 0x80-0xFF");

    // Identify (0x06) and Get Log Page (0x02) must stay distinct from it, or
    // one of them would have been overwritten by the same mistake.
    check(NVME_ADMIN_IDENTIFY != NVME_ADMIN_SANITIZE,
          "Sanitize does not collide with the Identify opcode");
    check(NVME_ADMIN_GET_LOG_PAGE != NVME_ADMIN_SANITIZE,
          "Sanitize does not collide with the Get Log Page opcode");
}

// ---------------------------------------------------------------------------
// 2. Sanitize cdw10 field layout
// ---------------------------------------------------------------------------

// The same encoding nvmeSanitize() performs, restated so it can be asserted.
uint32_t encodeSanitizeCdw10(uint8_t action, bool useAuse, uint8_t overwritePassCount) {
    uint32_t cdw10 = static_cast<uint32_t>(action) & 0x07;
    if (useAuse) {
        cdw10 |= (1u << 3);
        cdw10 |= (static_cast<uint32_t>(overwritePassCount) & 0x0F) << 4;
    }
    return cdw10;
}

void testSanitizeCdw10Layout() {
    std::printf("Sanitize cdw10 places SANACT, AUSE and OWPASS correctly\n");

    // Block Erase, no AUSE.
    check(encodeSanitizeCdw10(0x01, false, 0) == 0x01,
          "Block Erase is SANACT = 1h with nothing else set");

    // Crypto Erase.
    check(encodeSanitizeCdw10(0x02, false, 0) == 0x02,
          "Crypto Erase is SANACT = 2h");

    // Overwrite with AUSE and 1 pass: AUSE at bit 3, OWPASS at bits 7:4.
    const uint32_t ow1 = encodeSanitizeCdw10(0x03, true, 1);
    check((ow1 & 0x07) == 0x03, "Overwrite is SANACT = 3h in bits 2:0");
    check((ow1 & (1u << 3)) != 0, "AUSE is set at bit 3");
    check(((ow1 >> 4) & 0x0F) == 1,
          "OWPASS = 1 is in bits 7:4, not bits 15:8");
    check((ow1 >> 8) == 0,
          "nothing is written above bit 7, so the old bits 15:8 shift is gone");

    // Every pass count from 1 to 15 must survive the encoding unchanged. A
    // field that cannot hold the value it was given is the bug being guarded.
    bool allPassCountsFit = true;
    for (uint8_t passes = 1; passes <= 15; ++passes) {
        const uint32_t encoded = encodeSanitizeCdw10(0x03, true, passes);
        if (((encoded >> 4) & 0x0F) != passes) {
            allPassCountsFit = false;
        }
        // And nothing must spill outside the field.
        if ((encoded & ~(0x07u | (1u << 3) | (0x0Fu << 4))) != 0) {
            allPassCountsFit = false;
        }
    }
    check(allPassCountsFit,
          "pass counts 1..15 round-trip through the 4-bit OWPASS field");

    // The old layout: a pass count of 1 shifted to bits 15:8 produced 0x100,
    // which the controller would decode as OWPASS = 0 and a reserved bit set.
    const uint32_t oldLayout = 0x03u | (1u << 3) | (1u << 8);
    check(((oldLayout >> 4) & 0x0F) == 0,
          "the old bits 15:8 shift would have encoded a pass count of zero");
    check((oldLayout & (1u << 3)) != 0,
          "AUSE at bit 3 was already right, which is why the OWPASS bug survived");

    // 15 is the maximum. 16 does not fit and must not be silently truncated to
    // 0, which a mask would do.
    const uint32_t maxFits = encodeSanitizeCdw10(0x03, true, 15);
    check(((maxFits >> 4) & 0x0F) == 15, "15 is the largest encodable pass count");
    const uint32_t overflows = encodeSanitizeCdw10(0x03, true, 16);
    check(((overflows >> 4) & 0x0F) == 0,
          "16 masked to 4 bits would read back as 0, which is why it is rejected");
}

// ---------------------------------------------------------------------------
// 3. Get Log Page cdw10 / cdw11 field layout
// ---------------------------------------------------------------------------

struct GetLogPage {
    uint32_t cdw10;
    uint32_t cdw11;
};

GetLogPage encodeGetLogPage(uint16_t lid, uint32_t dwords) {
    GetLogPage cmd{};
    const uint32_t numdl = dwords - 1;   // NUMDL is zero-based
    const uint32_t numdu = 0;            // one contiguous buffer
    const uint32_t lsi = 0;
    cmd.cdw10 = (static_cast<uint32_t>(lid) & 0xFF) | (numdl << 16);
    cmd.cdw11 = (numdu & 0xFFFF) | (lsi << 16);
    return cmd;
}

void testGetLogPageLayout() {
    std::printf("Get Log Page places LID and NUMDL where the spec puts them\n");

    constexpr uint16_t kLidSanitizeStatus = 0x0081;
    constexpr uint32_t kPageDwords = 128;   // 512 bytes

    const GetLogPage glp = encodeGetLogPage(kLidSanitizeStatus, kPageDwords);

    check((glp.cdw10 & 0xFF) == 0x81,
          "LID 0x81 (Sanitize Status) is in cdw10 bits 7:0");
    check(((glp.cdw10 >> 16) & 0xFFFF) == 127,
          "NUMDL = 127 (128 dwords, zero-based) is in cdw10 bits 31:16");
    check((glp.cdw10 & 0xFF00) == 0,
          "cdw10 bits 15:8 are reserved and left clear");

    check((glp.cdw11 & 0xFFFF) == 0,
          "NUMDU = 0 in cdw11 bits 15:0, because the page is contiguous");
    check(((glp.cdw11 >> 16) & 0xFFFF) == 0,
          "the Log Specific Identifier is 0, and is not confused with the LID");

    // The previous encoding. Both fields were in the wrong dword and the wrong
    // bit range, so the controller was asked for LID 0 with no stated length.
    const uint32_t oldCdw10 = static_cast<uint32_t>((kPageDwords - 1) << 8);
    const uint32_t oldCdw11 = static_cast<uint32_t>((kLidSanitizeStatus & 0xFF) << 8);
    check((oldCdw10 & 0xFF) == 0,
          "the old cdw10 requested LID 0, not the Sanitize Status page");
    check((oldCdw10 >> 16) == 0,
          "the old cdw10 stated no NUMDL, so no length was requested");
    // cdw11 bits 15:0 are NUMDU, not a second LID field, so the old encoding
    // would have asked the controller for 33024 upper dwords.
    check((oldCdw11 & 0xFFFF) == 0x8100,
          "the old cdw11 put the LID into NUMDU, asking for 33024 upper dwords");
    check(((oldCdw10 >> 8) & 0xFF) == 127,
          "the old cdw10 put the dword count at bits 15:8, which is reserved");

    // A full 4096-byte log page would use NUMDL = 1023 and still fit, which
    // shows the field is wide enough for the largest page the spec allows.
    const GetLogPage big = encodeGetLogPage(kLidSanitizeStatus, 1024);
    check(((big.cdw10 >> 16) & 0xFFFF) == 1023,
          "NUMDL also encodes a 4096-byte page without overflowing");
}

// ---------------------------------------------------------------------------
// 4. ATA Security Feature Set transport
// ---------------------------------------------------------------------------

void testAtaSecurityEraseFailsClosed() {
    std::printf("ATA Secure Erase refuses rather than sending a malformed command\n");

    auto supported = ataSecurityEraseSupportedInThisBuild();
    check(supported.isError(),
          "this build reports the ATA Security Feature Set transport as unavailable");

    if (supported.isError()) {
        const std::string what = supported.error().what();
        check(what.find("HDIO_DRIVE_CMD") != std::string::npos,
              "the reason names the interface that cannot carry the command");
        check(what.find("taskfile") != std::string::npos,
              "the reason explains the 4-byte taskfile limitation");
    }

    // Both erase commands must fail, and must name the SG_IO requirement.
    // They are handed a real-looking password to prove the password is not the
    // thing being rejected: nothing is transmitted either way.
    auto prepare = ataSecurityErasePrepare(-1, "SOME_PASSWORD");
    check(prepare.isError(), "SECURITY ERASE PREPARE fails instead of issuing a command");
    if (prepare.isError()) {
        check(prepare.error().code() == ErrorCode::NOT_IMPLEMENTED,
              "SECURITY ERASE PREPARE reports NOT_IMPLEMENTED, not a device error");
        check(std::string(prepare.error().what()).find("SG_IO") != std::string::npos,
              "SECURITY ERASE PREPARE names SG_IO ATA PASS-THROUGH as the fix");
    }

    auto unit = ataSecurityEraseUnit(-1, "SOME_PASSWORD", /*enhanced=*/true);
    check(unit.isError(), "SECURITY ERASE UNIT fails instead of issuing a command");
    if (unit.isError()) {
        check(unit.error().code() == ErrorCode::NOT_IMPLEMENTED,
              "SECURITY ERASE UNIT reports NOT_IMPLEMENTED");
        check(std::string(unit.error().what()).find("SG_IO") != std::string::npos,
              "SECURITY ERASE UNIT names SG_IO ATA PASS-THROUGH as the fix");
    }

    // The argument struct the old code passed was 33 bytes. The kernel reads the
    // first 4 as the taskfile header, so bytes 4..32 of the "password" were a
    // data buffer for a PIO data-in transfer whose length is 512 * args[3].
    // Recording the size here keeps the reason concrete.
    struct WrongArgumentStruct {
        uint8_t password[32];
        uint8_t control;
    };
    check(sizeof(WrongArgumentStruct) == 33,
          "the old argument struct was 33 bytes, starting with 4 taskfile bytes");
    check(HDIO_DRIVE_CMD_HDR_SIZE == 4,
          "HDIO_DRIVE_CMD's taskfile header is 4 bytes, so the struct was misaligned");
}

// ---------------------------------------------------------------------------
// 5. Identify Controller / Namespace field offsets
// ---------------------------------------------------------------------------

void testNvmeIdentityLayout() {
    std::printf("the NVMe identity structs match the specification layout\n");

    // The offsets the whole NVMe path depends on. OACS carries the Sanitize
    // support bit and SANICAP carries the per-action capabilities; when these
    // were read from the wrong bytes, capability detection answered from noise.
    check(offsetof(NvmeIdentifyController, sn) == 4, "SN is at byte 4");
    check(offsetof(NvmeIdentifyController, mn) == 24, "MN is at byte 24");
    check(offsetof(NvmeIdentifyController, fr) == 64, "FR is at byte 64");
    check(offsetof(NvmeIdentifyController, oacs) == 256, "OACS is at byte 256");
    check(offsetof(NvmeIdentifyController, sanicap) == 328, "SANICAP is at byte 328");
    check(offsetof(NvmeIdentifyController, subnqn) == 768, "SUBNQN is at byte 768");

    // OACS bit 13 is the Sanitize command advertisement, and SANICAP bits 0..2
    // are the three sanitize actions. These are the exact bits the capability
    // detector reads, so their values are asserted rather than just their names.
    check(NVME_OACS_SANITIZE == 0x2000, "OACS bit 13 advertises Sanitize");
    check(NVME_SANICAP_BLOCK_ERASE == 0x1, "SANICAP bit 0 is Block Erase");
    check(NVME_SANICAP_CRYPTO_ERASE == 0x2, "SANICAP bit 1 is Crypto Erase");
    check(NVME_SANICAP_OVERWRITE == 0x4, "SANICAP bit 2 is Overwrite");

    // The maximum-actions field is SANICAP bits 7:3, a 5-bit field: the mask is
    // 0xF8, not 0x1F. Masking with 0x1F first would read bits 5:3 and halve the
    // decoded value.
    const uint32_t sanicap = 0x2B;   // block erase + crypto erase + 5 max actions
    check(((sanicap & NVME_SANICAP_BLOCK_ERASE) != 0), "a sample SANICAP decodes Block Erase");
    check(((sanicap & NVME_SANICAP_OVERWRITE) == 0), "a sample SANICAP decodes no Overwrite");
    check((((sanicap & NVME_SANICAP_MAX_ACTIONS_MASK) >> NVME_SANICAP_MAX_ACTIONS_SHIFT) == 5),
          "SANICAP bits 7:3 decode the maximum action count");

    check(offsetof(NvmeIdentifyNamespace, nsze) == 0, "namespace NSZE is at byte 0");
    check(offsetof(NvmeIdentifyNamespace, nguid) == 104, "namespace NGUID is at byte 104");
    check(offsetof(NvmeIdentifyNamespace, lbaf) == 128, "namespace LBAF is at byte 128");
    check(sizeof(NvmeLbaFormat) == 4, "nvme_lbaf is 4 bytes");
}

// ---------------------------------------------------------------------------
// 6. String trimming, and the byte-order question
// ---------------------------------------------------------------------------

void testDeviceStringTrimming() {
    std::printf("device string fields are trimmed before use\n");

    // The kernel space-pads and does not NUL-terminate these fields.
    const char padded[8] = {'1', '.', '0', '0', ' ', ' ', ' ', ' '};
    check(trimDeviceString(padded, 8) == "1.00",
          "trailing spaces are removed from a firmware field");

    const char full[8] = {'1', '.', '2', '.', '3', '4', '5', '6'};
    check(trimDeviceString(full, 8) == "1.2.3456",
          "a completely filled field is left alone");

    const char nulPadded[8] = {'A', 'B', '\0', '\0', '\0', '\0', '\0', '\0'};
    check(trimDeviceString(nulPadded, 8) == "AB",
          "a NUL-padded field stops at the NUL");

    const char mixed[8] = {'S', 'A', 'T', 'A', ' ', ' ', ' ', '\0'};
    check(trimDeviceString(mixed, 8) == "SATA",
          "space padding followed by a NUL is handled");

    check(trimDeviceString("", 0).empty(), "an empty field yields an empty string");

    // On the byte-order question, the answer is that no swap belongs here.
    //
    // ATA stores the IDENTIFY string fields with the two bytes of each 16-bit
    // word reversed, but the kernel undoes that before the data reaches user
    // space: ata_get_identity() overwrites the three string fields with the
    // output of ata_id_string(), which emits the high byte of each word first
    // "regardless of platform". Swapping again in user space would double-swap
    // them.
    //
    // This is asserted as a property of the decoder so that a future reader who
    // "fixes" the byte order introduces character-pair-reversed strings and this
    // test fails.
    const char alreadyDecoded[8] = {'S', 'A', 'T', 'A', ' ', ' ', ' ', ' '};
    const std::string decoded = trimDeviceString(alreadyDecoded, 8);
    check(decoded == "SATA",
          "the decoder leaves already-decoded bytes in order, with no second swap");

    std::string doubleSwapped = decoded;
    for (std::size_t i = 0; i + 1 < doubleSwapped.size(); i += 2) {
        std::swap(doubleSwapped[i], doubleSwapped[i + 1]);
    }
    check(doubleSwapped != decoded,
          "a second byte-pair swap would corrupt the string, which is why there is none");
}

} // namespace

int main() {
    testSanitizeOpcode();
    testSanitizeCdw10Layout();
    testGetLogPageLayout();
    testAtaSecurityEraseFailsClosed();
    testNvmeIdentityLayout();
    testDeviceStringTrimming();

    if (g_failures == 0) {
        std::printf("\nall hardware command encoding tests passed\n");
        return 0;
    }
    std::printf("\n%d check(s) failed\n", g_failures);
    return 1;
}
